//! `GET /sbtp/v1/subscribe` (SPEC §6): catch-up from the store paced by TCP flow control, then
//! live blocks through a bounded queue.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::http::{StatusCode, Uri};
use sbtp_core::BlockId;
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::task::{JoinHandle, spawn_blocking};
use tokio::time::{Instant, interval_at, sleep_until, timeout};

use crate::http::{Reply, check_position, error, params, rate_limited};
use crate::store::Page;
use crate::{ClientKey, Live, MAX_SUBSCRIPTIONS_PER_IP, Relay};

/// Catch-up page: few enough bytes that hundreds of subscribers stay within a lean memory budget.
const PAGE_LEN: usize = 128;
const PAGE_BYTES: usize = 256 << 10;
/// A client sends nothing but pongs and a close frame.
const MAX_CLIENT_MESSAGE: usize = 1024;
/// `Retry-After` of a client over its subscription cap: a subscription lasts minutes, not seconds.
const RETRY_SECONDS: u64 = 10;

/// spec §6 close codes.
const NORMAL: u16 = 1000;
const GOING_AWAY: u16 = 1001;
const UNSUPPORTED: u16 = 1003;
const RELAY_ERROR: u16 = 1011;
const TOO_SLOW: u16 = 4000;

pub async fn subscribe(
    State(relay): State<Arc<Relay>>,
    Extension(key): Extension<ClientKey>,
    uri: Uri,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Reply {
    let invalid = || error(StatusCode::BAD_REQUEST, "InvalidParameter");
    let p = params(&uri, &["since", "parent"])?;
    // spec §6: `since` is required; a malformed upgrade is `InvalidParameter` too.
    let since = p.since.ok_or_else(invalid)?;
    let upgrade = upgrade.map_err(|_| invalid())?;
    check_position(&relay, since)?;
    let max = MAX_SUBSCRIPTIONS_PER_IP.saturating_mul(relay.factor(key));
    let client = relay
        .subscriptions
        .acquire(key, max)
        .ok_or_else(|| rate_limited(RETRY_SECONDS))?;
    let slot = Arc::clone(&relay.subscription_slots)
        .try_acquire_owned()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Unavailable"))?;
    let upgrade = upgrade
        .max_message_size(MAX_CLIENT_MESSAGE)
        .max_frame_size(MAX_CLIENT_MESSAGE);
    Ok(upgrade.on_upgrade(move |socket| async move {
        let feed = Feed {
            relay,
            parent: p.parent,
            last: since,
            buffer: VecDeque::new(),
            rx: None,
            live: false,
            read: None,
        };
        session(socket, feed).await;
        drop((client, slot));
    }))
}

/// The frames of one subscription, in position order.
struct Feed {
    relay: Arc<Relay>,
    parent: Option<BlockId>,
    /// The greatest position examined so far; every later frame is above it.
    last: u64,
    buffer: VecDeque<Bytes>,
    rx: Option<broadcast::Receiver<Live>>,
    /// Caught up: frames now come from the live queue.
    live: bool,
    /// The catch-up read in flight, kept across a cancelled `next` instead of respawned.
    read: Option<JoinHandle<Result<Page, redb::Error>>>,
}

impl Feed {
    /// The next frame, or the close code that ends the subscription. Cancel-safe for `select!`:
    /// a client frame or a ping tick leaves the pending read in `read`, polled again next call.
    async fn next(&mut self) -> Result<Bytes, u16> {
        loop {
            if let Some(frame) = self.buffer.pop_front() {
                return Ok(frame);
            }
            if let (true, Some(rx)) = (self.live, self.rx.as_mut()) {
                let item = match rx.recv().await {
                    Ok(item) => item,
                    // spec §6: a live consumer that falls a whole queue behind is too slow.
                    Err(RecvError::Lagged(_)) => return Err(TOO_SLOW),
                    Err(RecvError::Closed) => return Err(GOING_AWAY),
                };
                if item.position <= self.last {
                    continue;
                }
                self.last = item.position;
                let block = sbtp_core::parse(item.frame.get(8..).unwrap_or_default());
                // spec §6: a denied block is never sent.
                let deny = self.relay.store.deny();
                if block.is_ok_and(|b| {
                    self.parent.is_none_or(|p| b.parents().contains(&p))
                        && deny.check(&item.id, b.pubkey()).is_none()
                }) {
                    return Ok(item.frame);
                }
                continue;
            }
            let (relay, parent, since) = (Arc::clone(&self.relay), self.parent, self.last);
            let page = move || relay.store.page(parent, since, PAGE_LEN, Some(PAGE_BYTES));
            let page = self.read.get_or_insert_with(|| spawn_blocking(page)).await;
            self.read = None;
            let Ok(Ok(page)) = page else {
                tracing::error!("store error during catch-up");
                return Err(RELAY_ERROR);
            };
            self.last = page.since;
            let frames = page.items.into_iter().filter_map(|item| item.frame);
            self.buffer.extend(frames.map(Bytes::from));
            // Caught up: listen to the live queue, read the store once more for blocks committed
            // in between, then go live. A page that is not the last one means a burst: drop the
            // queue and keep catching up from the store.
            match (page.more, self.rx.is_some()) {
                (false, false) => self.rx = Some(self.relay.live.subscribe()),
                (false, true) => self.live = true,
                (true, _) => self.rx = None,
            }
        }
    }
}

async fn session(mut socket: WebSocket, mut feed: Feed) {
    let l = feed.relay.config.clone();
    let mut stop = feed.relay.stop.clone();
    let start = Instant::now();
    let deadline = start.checked_add(l.max_age).unwrap_or(start);
    // A zero period would panic.
    let period = l.idle_timeout.checked_div(3).unwrap_or_default();
    let mut ping = interval_at(start, period.max(Duration::from_millis(10)));
    let mut last_heard = Instant::now();
    // A send with no progress for this long means a dead peer, not a slow one.
    let stall = l.idle_timeout;
    let code = loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break GOING_AWAY,
            () = sleep_until(deadline) => break NORMAL,
            message = socket.recv() => match message {
                Some(Ok(Message::Pong(_) | Message::Ping(_))) => last_heard = Instant::now(),
                Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                // spec §6: no data frames from the client.
                Some(Ok(Message::Text(_) | Message::Binary(_))) => break UNSUPPORTED,
            },
            _ = ping.tick() => {
                if last_heard.elapsed() >= l.idle_timeout {
                    break NORMAL;
                }
                if !matches!(timeout(stall, socket.send(Message::Ping(Bytes::new()))).await, Ok(Ok(()))) {
                    return;
                }
            }
            next = feed.next() => match next {
                Ok(frame) => match timeout(stall, socket.send(Message::Binary(frame))).await {
                    Ok(Ok(())) => {}
                    // spec §6: catch-up is never closed for slowness, only a live consumer.
                    Err(_) if feed.live => break TOO_SLOW,
                    _ => return,
                },
                Err(code) => break code,
            },
        }
    };
    let close = Message::Close(Some(CloseFrame {
        code,
        reason: "".into(),
    }));
    // Wait for the client's close (RFC 6455 §7.1.1): dropping a socket with unread pongs would
    // reset the connection and discard the frames and the close code still in flight.
    let _ = timeout(Duration::from_secs(5), async {
        socket.send(close).await?;
        while socket.recv().await.transpose()?.is_some() {}
        Ok::<_, axum::Error>(())
    })
    .await;
}
