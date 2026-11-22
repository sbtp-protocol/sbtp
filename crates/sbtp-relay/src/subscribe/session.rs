//! One subscription connection (ADR 0054 rules 6 to 8, 17, 20, 23, 26 and 31 to 33).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};
use tokio::time::{Instant, sleep_until, timeout};

use super::proto::{self, Bad, ClientMsg};
use super::{Conn, Hub, Out, lock, metrics};
use crate::client::{ClientKey, Slot};
use crate::limiter::Limiter;
use crate::server::RequestClass;

/// What a session holds until it ends: its slots of rules 25 to 28, and the end signal the
/// connection task waits for before it gives back its `max_connections` permit (rule 27).
pub(super) struct Guards {
    pub _total: OwnedSemaphorePermit,
    pub _client: Option<Slot>,
    pub _group: Option<Slot>,
    pub _done: oneshot::Sender<()>,
}

pub(super) struct Session {
    pub hub: Arc<Hub>,
    pub socket: WebSocket,
    pub key: Option<ClientKey>,
    pub limiter: Arc<Limiter>,
    pub stopping: watch::Receiver<bool>,
    pub guards: Guards,
}

/// How a session ends.
enum End {
    /// The relay closes with this code.
    Close(u16),
    /// The client closed, with this code if any.
    Peer(Option<u16>),
    /// The transport failed or is stuck: dropped without a close frame.
    Drop,
}

/// The time allowed to send the close frame.
const CLOSE_GRACE: Duration = Duration::from_secs(1);

pub(super) async fn run(s: Session) {
    let Session {
        hub,
        mut socket,
        key,
        limiter,
        mut stopping,
        guards,
    } = s;
    let _open = metrics::Open::new();
    let (id, conn) = hub.add_conn();
    let end = drive(&hub, id, &conn, &mut socket, key, &limiter, &mut stopping).await;
    hub.remove_conn(id, &conn);
    match end {
        End::Close(code) => {
            let frame = CloseFrame {
                code,
                reason: "".into(),
            };
            let _ = timeout(CLOSE_GRACE, socket.send(Message::Close(Some(frame)))).await;
            metrics::closed(Some(code));
        }
        End::Peer(code) => metrics::closed(code),
        End::Drop => metrics::closed(None),
    }
    drop(socket);
    drop(guards);
}

/// The entry count of a delivery frame (rule 9).
fn entries_of(frame: &[u8]) -> u64 {
    let c = usize::from(frame.get(6).copied().unwrap_or(0));
    frame
        .get(7 + c..9 + c)
        .and_then(|n| <[u8; 2]>::try_from(n).ok())
        .map_or(0, |n| u64::from(u16::from_be_bytes(n)))
}

/// Rules 7 and 10 (relay side): a failed read, by its cause.
fn read_failed(e: axum::Error) -> End {
    match e.into_inner().downcast::<tungstenite::Error>().map(|e| *e) {
        Ok(tungstenite::Error::Capacity(_)) => End::Close(1009),
        Ok(tungstenite::Error::Utf8(_)) => End::Close(1007),
        Ok(tungstenite::Error::Protocol(_)) => End::Close(1002),
        _ => End::Drop,
    }
}

/// Security review 2026-11-22, M-1: the deadlines that end a connection whatever its queue holds,
/// checked at the top of every turn of the loop and raced against every send, so that a client
/// that reads slowly under steady traffic is still closed: `ws_max_age_ms` and `idle_timeout_ms`
/// (rule 33), and `slow_at`, 2 × `tick_ms` after the queue overflowed (rule 20). Liveness (rule
/// 32) is judged only while the queue is empty, when the session reads: a pong cannot be read
/// while a send is in progress.
fn ending(age_at: Instant, idle_at: Option<Instant>, slow_at: Option<Instant>) -> Instant {
    [Some(age_at), idle_at, slow_at]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or(age_at)
}

/// The close of [`ending`] due at `now`, if any.
fn ended(
    now: Instant,
    age_at: Instant,
    idle_at: Option<Instant>,
    slow_at: Option<Instant>,
) -> Option<End> {
    if now >= age_at || idle_at.is_some_and(|t| t <= now) {
        // Rule 33.
        return Some(End::Close(1000));
    }
    if slow_at.is_some_and(|t| t <= now) {
        // Rule 20: the subscriptions keep overflowing.
        return Some(End::Close(1008));
    }
    None
}

#[allow(clippy::too_many_lines)] // One loop for the whole life of the connection.
async fn drive(
    hub: &Hub,
    id: u64,
    conn: &Conn,
    socket: &mut WebSocket,
    key: Option<ClientKey>,
    limiter: &Limiter,
    stopping: &mut watch::Receiver<bool>,
) -> End {
    let lim = hub.limits;
    let born = Instant::now();
    let age_at = born + lim.max_age;
    let mut ping_at = born + lim.ping;
    let mut pong_due: Option<Instant> = None;
    // Rule 33: no open subscription for `idle_timeout_ms`.
    let mut idle_at = Some(born + lim.idle);
    let mut sent = false;
    loop {
        if *stopping.borrow() {
            // Rule 23.
            return End::Close(1001);
        }
        let (can_read, slow_at) = {
            let q = lock(&conn.q);
            (q.can_read(), q.overflow_since.map(|t| t + 2 * lim.ping))
        };
        if let Some(end) = ended(Instant::now(), age_at, idle_at, slow_at) {
            return end;
        }
        let ending = ending(age_at, idle_at, slow_at);
        // The queue, one item at a time; its bytes stay counted until it is written.
        let item = lock(&conn.q).out.pop_front();
        if let Some(out) = item {
            let len = out.cost();
            let (msg, entries) = match out {
                Out::Text(t) => (Message::Text(t.into()), None),
                Out::Binary(b) => {
                    let n = entries_of(&b);
                    (Message::Binary(b.into()), Some(n))
                }
            };
            // Rule 20: a client that does not read for 2 × `tick_ms` is dropped. M-1: a deadline
            // that ends the connection interrupts the send; the next turn closes.
            let r = tokio::select! {
                biased;
                _ = stopping.changed() => return End::Drop,
                () = sleep_until(ending) => None,
                r = timeout(2 * lim.ping, socket.send(msg)) => Some(r),
            };
            lock(&conn.q).release(len);
            match r {
                None => {}
                Some(Ok(Ok(()))) => {
                    sent = true;
                    if let Some(n) = entries {
                        metrics::sent(1, n);
                    }
                }
                Some(Ok(Err(_)) | Err(_)) => return End::Drop,
            }
            continue;
        }
        let wake = [Some(ping_at), Some(ending), pong_due]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(ending);
        tokio::select! {
            biased;
            _ = stopping.changed() => return End::Close(1001),
            () = conn.wake.notified() => {}
            m = socket.recv(), if can_read => {
                let m = match m {
                    None => return End::Drop,
                    Some(Err(e)) => return read_failed(e),
                    Some(Ok(m)) => m,
                };
                // Rule 32: any frame shows the client is alive.
                pong_due = None;
                match m {
                    Message::Text(t) => {
                        if let Some(end) =
                            message(hub, id, conn, t.as_str(), key, limiter, &mut idle_at)
                        {
                            return end;
                        }
                    }
                    // Rule 6.
                    Message::Binary(_) => return End::Close(1003),
                    Message::Close(f) => return End::Peer(f.map(|f| f.code)),
                    Message::Ping(_) | Message::Pong(_) => {}
                }
            }
            () = sleep_until(wake) => {
                let now = Instant::now();
                if pong_due.is_some_and(|t| t <= now) {
                    // Rule 32.
                    return End::Close(1001);
                }
                if now >= ping_at {
                    // Rule 31: a ping, and a `tick` when nothing else was sent.
                    // Security review 2026-11-22, L-3: raced against shutdown like an item
                    // send, so that a client that does not read cannot hold the drain.
                    let ping = timeout(2 * lim.ping, socket.send(Message::Ping(Vec::new().into())));
                    let r = tokio::select! {
                        biased;
                        _ = stopping.changed() => return End::Drop,
                        r = ping => r,
                    };
                    if !matches!(r, Ok(Ok(()))) {
                        return End::Drop;
                    }
                    pong_due = Some(now + lim.ping);
                    if !sent {
                        let mut q = lock(&conn.q);
                        if !q.gap_pending() {
                            let tick = proto::tick(&hub.cursor(q.next));
                            q.push(Out::Text(tick));
                        }
                    }
                    sent = false;
                    ping_at = now + lim.ping;
                }
                // The deadlines of [`ending`] are acted on at the next turn.
            }
        }
    }
}

/// One client text message (rule 7); `Some` when it ends the connection.
fn message(
    hub: &Hub,
    id: u64,
    conn: &Conn,
    text: &str,
    key: Option<ClientKey>,
    limiter: &Limiter,
    idle_at: &mut Option<Instant>,
) -> Option<End> {
    // The caller read this message only with the reply reserve free (L-1): the reply fits.
    let reply = |m: String| {
        lock(&conn.q).push_reply(Out::Text(m));
        conn.wake.notify_one();
    };
    let invalid = |sub, m| reply(proto::error(sub, "InvalidParameter", None, m));
    match proto::parse(text) {
        Err(Bad::NotObject) => return Some(End::Close(1007)),
        Err(Bad::Invalid { sub, message }) => invalid(sub, message),
        Ok(ClientMsg::Subscribe {
            sub,
            filter,
            fields,
        }) => {
            // Rule 26: the tokens first, before the message is checked further.
            if let Some(k) = key
                && let Err(retry_after) =
                    limiter.take_tokens(k, RequestClass::Query, filter.tokens())
            {
                reply(proto::error(
                    Some(sub),
                    "RateLimited",
                    Some(retry_after),
                    "no query tokens left for this subscription",
                ));
                return None;
            }
            let (duplicate, full) = {
                let q = lock(&conn.q);
                (
                    q.subs.contains_key(&sub),
                    q.subs.len() >= hub.limits.max_subscriptions,
                )
            };
            if duplicate {
                invalid(Some(sub), "sub is already open on this connection");
            } else if full {
                invalid(Some(sub), "max_subscriptions reached on this connection");
            } else if hub.subscribe(id, conn, sub, filter, fields) {
                *idle_at = None;
                conn.wake.notify_one();
            }
        }
        Ok(ClientMsg::Unsubscribe { sub }) => {
            if hub.unsubscribe(id, conn, sub) {
                if lock(&conn.q).subs.is_empty() {
                    *idle_at = Some(Instant::now() + hub.limits.idle);
                }
                conn.wake.notify_one();
            } else {
                invalid(Some(sub), "sub is not open on this connection");
            }
        }
    }
    None
}
