//! Relay subscriptions over WebSocket (ADR 0054; core spec §4, `GET /sbtp/v1/subscribe`;
//! `architecture.md` §2, "Subscriptions"). On only with `ws_enabled`.
//!
//! - **Fan-out** (rule 34). The index writer thread, right after the commit of a block that
//!   takes a new position (`201`, replication, re-acceptance after expiry), offers it to a queue of
//!   [`FANOUT_QUEUE`] entries with `try_send`: the writer never waits, and the queue order is
//!   the store order. A full queue drops the entry and records its position; the fan-out task
//!   then gives every open subscription a `gap` (cause `fanout`). The task matches each entry
//!   against a table keyed by parent and the relay-wide subscriptions: no index or block read.
//!   A block the deny list refuses at that time is never offered (rule 42).
//! - **Per connection** (rules 18, 29). A queue of at most [`WS_SEND_BYTES`] bytes, the frame
//!   being sent included. A delivery that does not fit is dropped with every later one of its
//!   subscription until a `gap` fits; the `gap` carries the cursor of the last frame queued for
//!   that subscription, or its `start`.
//! - **Session** (rules 6 to 8, 14, 17, 20, 23, 26, 31 to 33): one task per connection reads the
//!   client's messages, only while its queue has room for a control message, sends the queue,
//!   pings and ticks, and closes on idle, age, liveness, a slow consumer and shutdown.
//! - **Privacy** (rules 36 and 37): the state lives in memory only, and nothing of a client
//!   message (a parent, a cursor, a `sub`) reaches a log or a metric label.

pub mod metrics;
pub mod proto;
mod session;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use axum::extract::Request;
use axum::extract::ws::WebSocketUpgrade;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use sbtp_core::BlockId;
use tokio::sync::{Notify, Semaphore, mpsc, oneshot, watch};

use crate::client::{ClientKey, Counts};
use crate::config::Settings;
use crate::error::ApiError;
use crate::index::Position;
use crate::limiter::Limiter;
use crate::query::encode_cursor;
use crate::server::RequestClient;
use proto::{Filter, Item};

/// The route (rule 1).
pub const PATH: &str = "/sbtp/v1/subscribe";
/// Rule 29: the bytes queued for sending on one connection, the frame in progress included.
pub const WS_SEND_BYTES: usize = 65_536;
/// Rule 34: the entries between the index writer and the fan-out.
pub const FANOUT_QUEUE: usize = 256;
/// Rule 29: the codec's read buffer.
pub const WS_READ_BUFFER: usize = 8_192;
/// Rule 29: what one subscription connection holds besides the connection itself: the read
/// buffer, the largest client message and the send queue.
pub const CONNECTION_BYTES: u64 =
    (WS_READ_BUFFER + proto::MAX_CLIENT_MESSAGE + WS_SEND_BYTES) as u64;
/// Rule 35: the estimate per subscription (32 parent entries of 128 bytes, 1,088 bytes of state).
pub const EST_SUBSCRIPTION: u64 = 5_184;
/// Rule 35: the estimate per fan-out queue entry.
pub const EST_FANOUT_ENTRY: u64 = 320;
/// Rule 35: the estimate per network group count.
pub const EST_GROUP_COUNT: u64 = 128;
/// Rule 25, step 6: the least `Retry-After` of a `429`.
const REFUSED_RETRY_AFTER_S: u64 = 30;
/// The fan-out entries taken from the queue at once.
const FANOUT_BATCH: usize = 64;

/// A block that took a new position, as the fan-out needs it (rule 34): from the header in hand,
/// nothing read again.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Its position.
    pub at: Position,
    /// Its `block_id`.
    pub id: BlockId,
    /// Its Parents Hashes, in header order (0 to 8).
    pub parents: Vec<BlockId>,
    /// Its length in bytes.
    pub len: u32,
}

/// The settings of the function (rule 30).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// `ws_max_connections`.
    pub max_connections: u32,
    /// `ws_max_connections_per_client`.
    pub per_client: u32,
    /// `⌈ws_max_connections × ws_group_share_pct / 100⌉` (rule 28).
    pub per_group: u32,
    /// `ws_max_subscriptions`.
    pub max_subscriptions: usize,
    /// `ws_ping_interval_ms`, also `/info` `tick_ms`.
    pub ping: Duration,
    /// `idle_timeout_ms` (rule 33).
    pub idle: Duration,
    /// `ws_max_age_ms`.
    pub max_age: Duration,
    /// `shed_retry_after_s`, the `Retry-After` of the `503`.
    pub shed_retry_after_s: u64,
    /// `client_ipv6_prefix` (rule 28).
    pub ipv6_prefix: u8,
}

impl Limits {
    fn of(s: &Settings) -> Self {
        let n = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
        Self {
            max_connections: n(s.ws_max_connections),
            per_client: n(s.ws_max_connections_per_client),
            per_group: n(s
                .ws_max_connections
                .saturating_mul(s.ws_group_share_pct)
                .div_ceil(100)),
            max_subscriptions: usize::try_from(s.ws_max_subscriptions).unwrap_or(1),
            ping: Duration::from_millis(s.ws_ping_interval_ms),
            idle: Duration::from_millis(s.idle_timeout_ms),
            max_age: Duration::from_millis(s.ws_max_age_ms),
            shed_retry_after_s: s.shed_retry_after_s,
            ipv6_prefix: u8::try_from(s.client_ipv6_prefix).unwrap_or(64),
        }
    }
}

/// The `/info` member `subscribe` (rule 5), when the function is on.
#[must_use]
pub fn info_member(s: &Settings) -> Option<serde_json::Value> {
    s.ws_enabled.then(|| {
        serde_json::json!({
            "versions": [1],
            "max_subscriptions": s.ws_max_subscriptions,
            "tick_ms": s.ws_ping_interval_ms,
        })
    })
}

/// What a connection task of the server shares with the upgrade handler of its requests: the
/// stop signal, the token buckets, and the end of the session once upgraded, so that the
/// connection keeps its `max_connections` permit for the session's whole life (rule 27).
#[derive(Debug)]
pub struct Link {
    stopping: watch::Receiver<bool>,
    limiter: Arc<Limiter>,
    session: Mutex<Option<oneshot::Receiver<()>>>,
}

impl Link {
    /// A link for one connection.
    #[must_use]
    pub fn new(stopping: watch::Receiver<bool>, limiter: Arc<Limiter>) -> Arc<Self> {
        Arc::new(Self {
            stopping,
            limiter,
            session: Mutex::new(None),
        })
    }

    /// The end of the session of an upgraded connection, once.
    pub fn take_session(&self) -> Option<oneshot::Receiver<()>> {
        lock(&self.session).take()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One subscription of a connection.
#[derive(Debug)]
struct Sub {
    filter: Filter,
    fields: bool,
    /// The cursor of the last frame queued for it, or `start` (rule 18).
    cursor: String,
    /// Deliveries were dropped; a `gap` is owed before any later frame.
    gap: bool,
}

/// What a connection queues for sending.
#[derive(Debug)]
enum Out {
    Text(String),
    Binary(Vec<u8>),
}

/// Security review 2026-11-22, L-6: what one queued item takes beyond its heap bytes, charged in
/// the queue bound so that the bound counts memory, not payload: two slots of the `VecDeque` (its
/// ring buffer grows by doubling and keeps its capacity) and [`ALLOC_SLACK`]. With it, a queue of
/// one-entry frames of 81 bytes holds fewer than half the items it held when only payload was
/// counted (about 800), and its memory stays within [`WS_SEND_BYTES`], so the per-connection term
/// of rule 29 is unchanged.
const ITEM_OVERHEAD: usize = 2 * std::mem::size_of::<Out>() + ALLOC_SLACK;
/// The allocator's header and size rounding of one heap allocation: at most 24 bytes for the
/// glibc allocator of the relay's image (an 8-byte header, rounded up to 16).
const ALLOC_SLACK: usize = 32;

impl Out {
    /// What the item is charged in the queue bound: its heap capacity and [`ITEM_OVERHEAD`].
    fn cost(&self) -> usize {
        ITEM_OVERHEAD
            + match self {
                Self::Text(t) => t.capacity(),
                Self::Binary(b) => b.capacity(),
            }
    }

    /// Gives back spare capacity, so that the item is charged its length.
    fn shrink(&mut self) {
        match self {
            Self::Text(t) => t.shrink_to_fit(),
            Self::Binary(b) => b.shrink_to_fit(),
        }
    }
}

/// The send queue and subscriptions of one connection (rules 18 and 29).
#[derive(Debug, Default)]
struct Queue {
    out: VecDeque<Out>,
    /// Queued bytes, the frame being sent included, each item charged [`Out::cost`].
    bytes: usize,
    subs: HashMap<u32, Sub>,
    /// The gap after the last position evaluated for this connection (rule 31).
    next: Position,
    /// When a delivery was first dropped since the queue was last empty with no gap owed (rule
    /// 20).
    overflow_since: Option<tokio::time::Instant>,
}

impl Queue {
    fn room(&self) -> usize {
        WS_SEND_BYTES.saturating_sub(self.bytes)
    }

    fn push(&mut self, mut out: Out) -> bool {
        out.shrink();
        let cost = out.cost();
        if cost > self.room() {
            return false;
        }
        self.bytes += cost;
        self.out.push_back(out);
        true
    }

    /// Queues the `gap` of every subscription that owes one, while they fit.
    fn flush_gaps(&mut self) {
        let mut owed: Vec<u32> = self
            .subs
            .iter()
            .filter(|(_, s)| s.gap)
            .map(|(k, _)| *k)
            .collect();
        owed.sort_unstable();
        for k in owed {
            let Some(s) = self.subs.get(&k) else { continue };
            if !self.push(Out::Text(proto::gap(k, &s.cursor))) {
                return;
            }
            if let Some(s) = self.subs.get_mut(&k) {
                s.gap = false;
            }
        }
    }

    /// The item charged `len` bytes was written (or given up): its bytes leave the queue, owed gaps are
    /// queued while they fit, and the slow-consumer clock of rule 20 stops once the queue is
    /// empty with no gap owed. Security review 2026-11-22, M-1: a client that reads slowly under
    /// steady traffic never empties its queue, though it flushes a gap now and then; its clock
    /// keeps running and it is closed with 1008.
    fn release(&mut self, len: usize) {
        self.bytes = self.bytes.saturating_sub(len);
        self.flush_gaps();
        if self.out.is_empty() && !self.gap_pending() {
            self.overflow_since = None;
        }
    }

    /// Rule 18: the frames of `sub`, each with the cursor after its last entry.
    fn deliver(&mut self, sub: u32, frames: Vec<(Vec<u8>, String, u64)>) {
        for (frame, cursor, entries) in frames {
            let Some(s) = self.subs.get(&sub) else { return };
            if s.gap {
                let gap = proto::gap(sub, &s.cursor);
                if !self.push(Out::Text(gap)) {
                    continue;
                }
                if let Some(s) = self.subs.get_mut(&sub) {
                    s.gap = false;
                }
            }
            if self.push(Out::Binary(frame)) {
                if let Some(s) = self.subs.get_mut(&sub) {
                    s.cursor = cursor;
                }
                metrics::queued(entries);
            } else {
                if let Some(s) = self.subs.get_mut(&sub) {
                    s.gap = true;
                }
                self.overflow_since
                    .get_or_insert_with(tokio::time::Instant::now);
                metrics::gap(metrics::GapCause::Queue);
            }
        }
    }

    fn gap_pending(&self) -> bool {
        self.subs.values().any(|s| s.gap)
    }
}

/// One subscription connection, shared by its session and the fan-out.
#[derive(Debug)]
struct Conn {
    q: Mutex<Queue>,
    wake: Notify,
}

/// Where a subscription is registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Target {
    conn: u64,
    sub: u32,
}

/// The table keyed by parent and the relay-wide subscriptions (rule 34).
#[derive(Debug, Default)]
struct Registry {
    /// The gap after the last position evaluated for delivery (rule 14).
    next: Position,
    next_conn: u64,
    conns: HashMap<u64, Arc<Conn>>,
    /// Per parent, the subscriptions that list it and its bit in their mask.
    by_parent: HashMap<BlockId, Vec<(Target, u8)>>,
    all: Vec<Target>,
}

impl Registry {
    fn remove(&mut self, t: Target, filter: &Filter) {
        match filter {
            Filter::All => self.all.retain(|x| *x != t),
            Filter::Parents(ps) => {
                for p in ps {
                    if let Some(v) = self.by_parent.get_mut(p) {
                        v.retain(|(x, _)| *x != t);
                        if v.is_empty() {
                            self.by_parent.remove(p);
                        }
                    }
                }
            }
        }
    }
}

/// The admission counts of rule 25, step 6, and rules 27 and 28.
#[derive(Debug)]
struct Admission {
    total: Arc<Semaphore>,
    /// Pinning the limiter (rule 27), made at the first upgrade, when the limiter is known.
    per_client: OnceLock<Arc<Counts>>,
    groups: Arc<Counts>,
}

/// The subscriptions of a relay.
pub struct Hub {
    limits: Limits,
    tx: mpsc::Sender<Entry>,
    rx: Mutex<Option<mpsc::Receiver<Entry>>>,
    started: AtomicBool,
    /// The newest position the writer could not queue, until the fan-out turns it into gaps.
    dropped: Mutex<Option<Position>>,
    reg: Mutex<Registry>,
    epoch: Box<dyn Fn() -> u64 + Send + Sync>,
    admission: Admission,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Hub {
    /// The hub of `s`, `None` with `ws_enabled = false` (rule 30). `head` is the gap after the
    /// newest position at start-up; `epoch` gives the index epoch of the cursors.
    #[must_use]
    pub fn new(
        s: &Settings,
        head: Position,
        epoch: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Option<Arc<Self>> {
        if !s.ws_enabled {
            return None;
        }
        let limits = Limits::of(s);
        let (tx, rx) = mpsc::channel(FANOUT_QUEUE);
        metrics::set_on();
        Some(Arc::new(Self {
            limits,
            tx,
            rx: Mutex::new(Some(rx)),
            started: AtomicBool::new(false),
            dropped: Mutex::new(None),
            reg: Mutex::new(Registry {
                next: head,
                ..Registry::default()
            }),
            epoch: Box::new(epoch),
            admission: Admission {
                total: Arc::new(Semaphore::new(limits.max_connections as usize)),
                per_client: OnceLock::new(),
                groups: Counts::new(limits.per_group),
            },
        }))
    }

    /// Rule 34, on the index writer thread right after the commit: offers `e`, never waiting.
    pub fn offer(&self, e: Entry) {
        if let Err(mpsc::error::TrySendError::Full(e) | mpsc::error::TrySendError::Closed(e)) =
            self.tx.try_send(e)
        {
            let mut d = lock(&self.dropped);
            if d.is_none_or(|p| p < e.at) {
                *d = Some(e.at);
            }
        }
    }

    /// Starts the fan-out task once; called from inside the runtime at start-up, before the
    /// relay listens (security review 2026-11-22, L-2).
    pub fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(rx) = lock(&self.rx).take() else {
            return;
        };
        tokio::spawn(fanout(Arc::clone(self), rx));
    }

    /// Tests: the entries offered and not yet taken by the fan-out task.
    #[cfg(test)]
    pub(crate) fn drain_offered(&self) -> Vec<BlockId> {
        let mut out = Vec::new();
        if let Some(rx) = lock(&self.rx).as_mut() {
            while let Ok(e) = rx.try_recv() {
                out.push(e.id);
            }
        }
        out
    }

    fn cursor(&self, at: Position) -> String {
        encode_cursor((self.epoch)(), at)
    }

    /// Rule 34: one batch of entries, in store order.
    fn evaluate(&self, batch: &[Entry]) {
        let mut reg = lock(&self.reg);
        // A full writer queue: every open subscription gets a gap, and the dropped positions
        // are before any later `start`.
        if let Some(p) = lock(&self.dropped).take() {
            reg.next = reg.next.max(p.next());
            for c in reg.conns.values() {
                let mut q = lock(&c.q);
                let n = q.subs.len() as u64;
                for s in q.subs.values_mut() {
                    s.gap = true;
                }
                if n > 0 {
                    q.overflow_since
                        .get_or_insert_with(tokio::time::Instant::now);
                    metrics::gaps(metrics::GapCause::Fanout, n);
                }
                q.flush_gaps();
                c.wake.notify_one();
            }
        }
        // Per subscription, the entries it matches, with their mask.
        let mut matched: HashMap<Target, Vec<(usize, u32)>> = HashMap::new();
        for (i, e) in batch.iter().enumerate() {
            for t in &reg.all {
                matched.entry(*t).or_default().push((i, 0));
            }
            for p in &e.parents {
                let Some(subs) = reg.by_parent.get(p) else {
                    continue;
                };
                for (t, bit) in subs {
                    let v = matched.entry(*t).or_default();
                    match v.last_mut() {
                        Some((j, m)) if *j == i => *m |= 1 << bit,
                        _ => v.push((i, 1 << bit)),
                    }
                }
            }
            if e.at >= reg.next {
                reg.next = e.at.next();
            }
        }
        let next = reg.next;
        let mut by_conn: HashMap<u64, Vec<(u32, Matched)>> = HashMap::new();
        for (t, v) in matched {
            by_conn.entry(t.conn).or_default().push((t.sub, v));
        }
        for (id, c) in &reg.conns {
            let mut q = lock(&c.q);
            q.next = next;
            if let Some(subs) = by_conn.remove(id) {
                for (sub, entries) in subs {
                    let Some(s) = q.subs.get(&sub) else { continue };
                    let frames = self.frames(sub, s, batch, &entries);
                    q.deliver(sub, frames);
                }
                c.wake.notify_one();
            }
        }
    }

    /// The delivery frames of `sub` for `entries` of `batch`, each within [`proto::MAX_FRAME`],
    /// with the cursor after its last entry and its entry count.
    fn frames(
        &self,
        sub: u32,
        s: &Sub,
        batch: &[Entry],
        entries: &[(usize, u32)],
    ) -> Vec<(Vec<u8>, String, u64)> {
        let parents = matches!(s.filter, Filter::Parents(_));
        let mut out = Vec::new();
        let mut items: Vec<Item<'_>> = Vec::new();
        let mut size = 0usize;
        let mut last = None;
        let mut flush = |items: &mut Vec<Item<'_>>, last: Option<Position>| {
            if let Some(at) = last {
                let cursor = self.cursor(at.next());
                if let Some(f) = proto::delivery(sub, &cursor, items) {
                    out.push((f, cursor, items.len() as u64));
                }
            }
            items.clear();
        };
        for (i, mask) in entries {
            let Some(e) = batch.get(*i) else { continue };
            let item = Item {
                id: &e.id,
                mask: parents.then_some(*mask),
                fields: s.fields.then_some((e.parents.as_slice(), e.len)),
            };
            // The cursor is 40 characters (`encode_cursor`).
            if size + item.len() + proto::header_len(40) > proto::MAX_FRAME {
                flush(&mut items, last);
                size = 0;
            }
            size += item.len();
            items.push(item);
            last = Some(e.at);
        }
        flush(&mut items, last);
        out
    }

    fn add_conn(&self) -> (u64, Arc<Conn>) {
        let mut reg = lock(&self.reg);
        reg.next_conn += 1;
        let id = reg.next_conn;
        let c = Arc::new(Conn {
            q: Mutex::new(Queue {
                next: reg.next,
                ..Queue::default()
            }),
            wake: Notify::new(),
        });
        reg.conns.insert(id, Arc::clone(&c));
        (id, c)
    }

    fn remove_conn(&self, id: u64, c: &Conn) {
        let mut reg = lock(&self.reg);
        let subs = std::mem::take(&mut lock(&c.q).subs);
        for (sub, s) in subs {
            reg.remove(Target { conn: id, sub }, &s.filter);
            metrics::subscription_closed(&s.filter);
        }
        reg.conns.remove(&id);
    }

    /// Rule 14: registers `sub` and queues `subscribed`, in one step, so that `subscribed`
    /// precedes every frame of it. The caller checked that a control message fits.
    fn subscribe(&self, id: u64, c: &Conn, sub: u32, filter: Filter, fields: bool) {
        let mut reg = lock(&self.reg);
        let start = self.cursor(reg.next);
        let t = Target { conn: id, sub };
        match &filter {
            Filter::All => reg.all.push(t),
            Filter::Parents(ps) => {
                for (bit, p) in ps.iter().enumerate() {
                    let bit = u8::try_from(bit).unwrap_or(u8::MAX);
                    reg.by_parent.entry(*p).or_default().push((t, bit));
                }
            }
        }
        metrics::subscription_opened(&filter);
        let mut q = lock(&c.q);
        q.push(Out::Text(proto::subscribed(sub, &start)));
        q.subs.insert(
            sub,
            Sub {
                filter,
                fields,
                cursor: start,
                gap: false,
            },
        );
    }

    /// Rule 17: removes `sub` and queues `unsubscribed`; `false` when it is not open.
    fn unsubscribe(&self, id: u64, c: &Conn, sub: u32) -> bool {
        let mut reg = lock(&self.reg);
        let mut q = lock(&c.q);
        let Some(s) = q.subs.remove(&sub) else {
            return false;
        };
        reg.remove(Target { conn: id, sub }, &s.filter);
        metrics::subscription_closed(&s.filter);
        q.push(Out::Text(proto::unsubscribed(sub)));
        true
    }
}

/// The entries of a batch one subscription matches: index in the batch, match mask.
type Matched = Vec<(usize, u32)>;

/// The fan-out task (rule 34), until the writer side is gone.
async fn fanout(hub: Arc<Hub>, mut rx: mpsc::Receiver<Entry>) {
    let mut batch = Vec::with_capacity(FANOUT_BATCH);
    while rx.recv_many(&mut batch, FANOUT_BATCH).await > 0 {
        hub.evaluate(&batch);
        batch.clear();
    }
}

fn bad_request(msg: &'static str) -> Response {
    ApiError::invalid_parameter()
        .with_message(msg)
        .into_response()
}

fn has_token(h: &HeaderMap, name: header::HeaderName, token: &str) -> bool {
    h.get_all(name).iter().any(|v| {
        v.to_str()
            .is_ok_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    })
}

/// `GET /sbtp/v1/subscribe` (rules 1, 2 and 25): the head checks, step 6 of the admission, then
/// `101` with the subprotocol selected and the session started.
pub async fn upgrade(
    axum::extract::State(hub): axum::extract::State<Arc<Hub>>,
    req: Request,
) -> Response {
    // Rule 1.
    if req.uri().query().is_some() {
        return bad_request("this route takes no query string");
    }
    let headers = req.headers();
    // Rule 2: a valid upgrade (RFC 6455 §4.2.1); the library's own checks give other
    // statuses and bodies, so the relay checks first.
    if !has_token(headers, header::UPGRADE, "websocket")
        || !has_token(headers, header::CONNECTION, "upgrade")
        || headers.get(header::SEC_WEBSOCKET_KEY).is_none()
    {
        return bad_request("not a WebSocket upgrade");
    }
    if headers
        .get(header::SEC_WEBSOCKET_VERSION)
        .map(HeaderValue::as_bytes)
        != Some(b"13")
    {
        let mut r = bad_request("Sec-WebSocket-Version must be 13");
        r.headers_mut().insert(
            header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );
        return r;
    }
    if !has_token(headers, header::SEC_WEBSOCKET_PROTOCOL, proto::SUBPROTOCOL) {
        return bad_request("the subprotocol sbtp.subscribe.v1 must be offered");
    }
    let Some(link) = req.extensions().get::<Arc<Link>>().cloned() else {
        return ApiError::internal().into_response();
    };
    let key = req.extensions().get::<RequestClient>().and_then(|c| c.key);
    // Step 6: per client and per group (a key in `rate_limit_exempt` skips both), then the
    // total.
    let adm = &hub.admission;
    let refused = |r: crate::metrics::Refused| {
        crate::metrics::refused(r);
        ApiError::rate_limited(REFUSED_RETRY_AFTER_S).into_response()
    };
    let (client_slot, group_slot) = match key {
        None => (None, None),
        Some(client) => {
            let per_client = adm
                .per_client
                .get_or_init(|| Counts::pinning(hub.limits.per_client, Arc::clone(&link.limiter)));
            let Some(slot) = per_client.try_acquire(client) else {
                return refused(crate::metrics::Refused::WsClient);
            };
            let group = group_of(client, hub.limits.ipv6_prefix).map(|g| adm.groups.try_acquire(g));
            match group {
                Some(None) => return refused(crate::metrics::Refused::WsGroup),
                Some(Some(g)) => (Some(slot), Some(g)),
                None => (Some(slot), None),
            }
        }
    };
    let Ok(total) = Arc::clone(&adm.total).try_acquire_owned() else {
        crate::metrics::refused(crate::metrics::Refused::WsFull);
        return ApiError::unavailable(hub.limits.shed_retry_after_s).into_response();
    };
    let (mut parts, _) = req.into_parts();
    let Ok(ws) = WebSocketUpgrade::from_request_parts(&mut parts, &()).await else {
        return bad_request("not a WebSocket upgrade");
    };
    let (done, ended) = oneshot::channel();
    *lock(&link.session) = Some(ended);
    let guards = session::Guards {
        _total: total,
        _client: client_slot,
        _group: group_slot,
        _done: done,
    };
    let stopping = link.stopping.clone();
    let limiter = Arc::clone(&link.limiter);
    // Rule 29: every size of the codec set explicitly.
    ws.read_buffer_size(WS_READ_BUFFER)
        .write_buffer_size(0)
        .max_write_buffer_size(proto::MAX_FRAME + 64)
        .max_message_size(proto::MAX_CLIENT_MESSAGE)
        .max_frame_size(proto::MAX_CLIENT_MESSAGE)
        .protocols([proto::SUBPROTOCOL])
        .on_upgrade(move |socket| {
            session::run(session::Session {
                hub,
                socket,
                key,
                limiter,
                stopping,
                guards,
            })
        })
}

use axum::extract::FromRequestParts as _;

/// Rule 28: the network group of a client key: its IPv6 /48 or its IPv4 /24. A level not
/// shorter than the key is skipped (security review 2026-11-22, L-8): with
/// `client_ipv6_prefix = 48` an IPv6 key has no group, so only its per-client bound applies.
fn group_of(k: ClientKey, ipv6_prefix: u8) -> Option<ClientKey> {
    k.groups(ipv6_prefix)
        .into_iter()
        .flatten()
        .find(|g| matches!(g.prefix(), 24 | 48) && g.prefix() < k.prefix())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn at(ms: u64) -> Position {
        Position::at(ms)
    }

    fn entry(ms: u64, id: u8, parents: &[u8]) -> Entry {
        Entry {
            at: at(ms),
            id: BlockId([id; 32]),
            parents: parents.iter().map(|p| BlockId([*p; 32])).collect(),
            len: 200,
        }
    }

    fn hub() -> Arc<Hub> {
        let s = crate::config::Settings::load(
            Vec::<std::ffi::OsString>::new(),
            [("SBTP_RELAY_WS_ENABLED".into(), "true".into())],
        )
        .unwrap();
        Hub::new(&s, at(1), || 7).unwrap()
    }

    fn drain(c: &Conn) -> Vec<Out> {
        let mut q = lock(&c.q);
        q.bytes = 0;
        q.out.drain(..).collect()
    }

    fn texts(out: &[Out]) -> Vec<String> {
        out.iter()
            .filter_map(|o| match o {
                Out::Text(t) => Some(t.clone()),
                Out::Binary(_) => None,
            })
            .collect()
    }

    /// ADR 0054 rules 11, 14, 16: `subscribed` first with the gap after the last evaluated
    /// position; parent matches with their mask, once per subscription; `all` sees every block;
    /// nothing from before `start`.
    #[test]
    fn matching_and_order() {
        let h = hub();
        let (id, c) = h.add_conn();
        h.evaluate(&[entry(5, 1, &[])]);
        h.subscribe(
            id,
            &c,
            1,
            Filter::Parents(vec![BlockId([9; 32]), BlockId([8; 32])]),
            false,
        );
        h.subscribe(id, &c, 2, Filter::All, true);
        let first = drain(&c);
        assert_eq!(
            texts(&first)[0],
            proto::subscribed(1, &encode_cursor(7, at(5).next()))
        );
        h.evaluate(&[entry(6, 2, &[8, 9]), entry(7, 3, &[3]), entry(8, 4, &[9])]);
        let out = drain(&c);
        let frames: Vec<&Vec<u8>> = out
            .iter()
            .filter_map(|o| match o {
                Out::Binary(b) => Some(b),
                Out::Text(_) => None,
            })
            .collect();
        assert_eq!(frames.len(), 2);
        let parents = frames.iter().find(|f| f[4] == 1).unwrap();
        // Two entries (2 and 4), the first matching both parents (mask 0b11).
        assert_eq!(parents[5], proto::FLAG_MASK);
        assert_eq!(&parents[7 + 40..9 + 40], &[0, 2]);
        assert_eq!(&parents[9 + 40 + 32..9 + 40 + 36], &[0, 0, 0, 3]);
        let all = frames.iter().find(|f| f[4] == 2).unwrap();
        assert_eq!(all[5], proto::FLAG_FIELDS);
        assert_eq!(&all[7 + 40..9 + 40], &[0, 3]);
        assert_eq!(
            &all[7..47],
            encode_cursor(7, at(8).next()).as_bytes(),
            "cursor after the last entry"
        );
    }

    /// ADR 0054 rule 18: a delivery that does not fit is dropped with the later ones until a
    /// `gap` fits; the `gap` carries the cursor of the last frame queued; the queue never holds
    /// more than `WS_SEND_BYTES`.
    #[test]
    fn overflow_becomes_one_gap() {
        let h = hub();
        let (id, c) = h.add_conn();
        h.subscribe(id, &c, 3, Filter::All, true);
        drain(&c);
        let big: Vec<Entry> = (0..64)
            .map(|n| entry(10 + n, 1, &[1, 2, 3, 4, 5, 6, 7, 8]))
            .collect();
        let mut queued_cursor = None;
        for round in 0..10u64 {
            let batch: Vec<Entry> = big
                .iter()
                .map(|e| Entry {
                    at: at(e.at.received_at + round * 100),
                    ..e.clone()
                })
                .collect();
            h.evaluate(&batch);
            let q = lock(&c.q);
            assert!(q.bytes <= WS_SEND_BYTES);
            if q.subs[&3].gap && queued_cursor.is_none() {
                queued_cursor = Some(q.subs[&3].cursor.clone());
            }
        }
        let cursor = queued_cursor.unwrap();
        drain(&c);
        h.evaluate(&[entry(5_000, 9, &[])]);
        let out = drain(&c);
        assert_eq!(texts(&out), [proto::gap(3, &cursor)], "the gap first");
        assert!(
            matches!(out.last(), Some(Out::Binary(_))),
            "then live delivery"
        );
        assert!(!lock(&c.q).gap_pending());
    }

    /// Security review 2026-11-22, L-6: a queue filled with the smallest delivery frames stays
    /// within `WS_SEND_BYTES` of memory: its ring buffer, and each item's heap allocation with
    /// the allocator's header and rounding (8 bytes, to 16).
    #[test]
    fn the_queue_bound_counts_memory() {
        assert!(ITEM_OVERHEAD >= 2 * std::mem::size_of::<Out>() + 24);
        let item = Item {
            id: &BlockId([1; 32]),
            mask: None,
            fields: None,
        };
        let frame = proto::delivery(1, &"c".repeat(40), &[item]).unwrap();
        assert_eq!(frame.len(), 81);
        let mut q = Queue::default();
        while q.push(Out::Binary(frame.clone())) {}
        let heap: usize = q
            .out
            .iter()
            .map(|o| match o {
                Out::Text(t) => t.capacity(),
                Out::Binary(b) => b.capacity(),
            })
            .map(|c| (c + 8).next_multiple_of(16))
            .sum();
        let memory = q.out.capacity() * std::mem::size_of::<Out>() + heap;
        assert!(
            memory <= WS_SEND_BYTES,
            "{memory} bytes for {} items",
            q.out.len()
        );
        assert!(q.bytes <= WS_SEND_BYTES);
    }

    /// ADR 0054 rule 34: a full writer queue gives every open subscription a gap, and later
    /// starts are after the dropped positions.
    #[test]
    fn fanout_overflow_gaps_every_subscription() {
        let h = hub();
        let (id, c) = h.add_conn();
        h.subscribe(id, &c, 1, Filter::All, false);
        drain(&c);
        for n in 0..=FANOUT_QUEUE as u64 {
            h.offer(entry(100 + n, 1, &[]));
        }
        assert!(lock(&h.dropped).is_some());
        h.evaluate(&[]);
        assert_eq!(texts(&drain(&c)).len(), 1);
        assert!(lock(&h.reg).next > at(100 + FANOUT_QUEUE as u64));
    }

    /// ADR 0054 rule 17: no frame of a `sub` after `unsubscribed`; an unknown `sub` is refused.
    #[test]
    fn unsubscribe_stops_delivery() {
        let h = hub();
        let (id, c) = h.add_conn();
        h.subscribe(id, &c, 4, Filter::All, false);
        assert!(h.unsubscribe(id, &c, 4));
        assert!(!h.unsubscribe(id, &c, 4));
        drain(&c);
        h.evaluate(&[entry(50, 1, &[])]);
        assert!(drain(&c).is_empty());
        h.remove_conn(id, &c);
        assert!(lock(&h.reg).conns.is_empty());
    }

    /// ADR 0054 rule 28: the group of a key.
    #[test]
    fn groups() {
        let p = crate::client::ClientPolicy::from_settings(
            &crate::config::Settings::load(
                Vec::<std::ffi::OsString>::new(),
                Vec::<(std::ffi::OsString, std::ffi::OsString)>::new(),
            )
            .unwrap(),
        );
        let v4 = p.key("192.0.2.7".parse().unwrap()).unwrap();
        assert_eq!(group_of(v4, 64).unwrap().prefix(), 24);
        let v6 = p.key("2001:db8:1:2::7".parse().unwrap()).unwrap();
        assert_eq!(group_of(v6, 64).unwrap().prefix(), 48);
        // L-8: with `client_ipv6_prefix = 48` the /48 is the key itself, a level not shorter
        // than the key: no group.
        let p48 = crate::client::ClientPolicy::from_settings(
            &crate::config::Settings::load(
                Vec::<std::ffi::OsString>::new(),
                [("SBTP_RELAY_CLIENT_IPV6_PREFIX".into(), "48".into())],
            )
            .unwrap(),
        );
        let v6 = p48.key("2001:db8:1:2::7".parse().unwrap()).unwrap();
        assert_eq!(v6.prefix(), 48);
        assert!(group_of(v6, 48).is_none());
        let v4 = p48.key("192.0.2.7".parse().unwrap()).unwrap();
        assert_eq!(group_of(v4, 48).unwrap().prefix(), 24);
    }
}
