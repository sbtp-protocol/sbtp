//! Archive copy to S3-compatible object storage (ADR 0050 rules 1 to 14 and 22 to 29), feature
//! `object-store`, on only when `mirror_endpoint` is set.
//!
//! The uploader walks the relay's own index by position from a durable cursor (`meta` keys
//! [`CURSOR_AT`] and [`CURSOR_N`]), reading [`PAGE`] positions at a time. Each block of a
//! page is read through the read path of ADR 0023 and sent as a conditional `PUT` signed with
//! Signature Version 4 (`If-None-Match: *`) by one of `mirror_max_in_flight` lanes, each with its own
//! connection, from a window of at most [`WINDOW`] positions. The cursor moves, durably, to the
//! lowest position not yet done: uploaded, already there (`412`), no longer held, or damaged. A
//! retryable failure retries the same block after back-off while the other lanes go on; a
//! configuration error backs off at the maximum and never skips a block. The
//! relay never sends anything but `PUT` to the bucket, plus the `GET` of the public URL after a
//! `412` (rule 9).
//!
//! Nothing here is on the request path: a client `PUT` never waits for the bucket (rule 7).

pub mod sigv4;

use std::collections::VecDeque;
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, Request, StatusCode, header};
use sbtp_core::BlockId;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use zeroize::Zeroizing;

use crate::blocks::{Copied, Relay};
use crate::config::{ConfigError, Settings, UrlStyle};
use crate::index::{Position, RedbIndex};
use crate::log::{self, Event, Throttle, Value};
use crate::peers::PeerUrl;
use crate::replication::http::{BLOCK_CEILING, Client, Conn, Fail};
use crate::replication::metrics::Failed;
use crate::store;
use sigv4::{Credentials, Signing};

/// Positions per page of the index walk (rule 7).
pub const PAGE: usize = 64;
/// `meta` keys of the cursor: the next position to copy (rule 7).
pub const CURSOR_AT: &str = "mirror_cursor";
/// The tie-breaker part of the cursor.
pub const CURSOR_N: &str = "mirror_cursor_n";
/// `meta` key of the digest of the last `/info` object written (rule 3).
pub const INFO_DIGEST: &str = "mirror_info_digest";
/// How often a caught-up uploader looks at the index again. Short: an index read is cheap, and
/// the lag of a quiet relay stays a few seconds.
const IDLE: Duration = Duration::from_secs(2);
/// The retry delay after a local refusal (no read permit, an index queue full, an I/O error).
const LOCAL_RETRY: Duration = Duration::from_secs(1);
/// The most positions counted for `mirror_lag_blocks`: the count walks the index, so a backlog
/// larger than this reads as this value. Recounted at most every [`LAG_EVERY`].
const LAG_CAP: u64 = 1_000_000;
const LAG_EVERY: Duration = Duration::from_secs(30);

/// The object-store bodies (ADR 0050 rule 8, rule 3).
const BLOCK_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const INFO_CACHE_CONTROL: &str = "public, max-age=3600";

/// Counters and gauges (ADR 0050 rule 29). Labels are fixed names; none carries a URL, a key
/// or a client.
pub mod metrics {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    /// The `status` label of `mirror_failed_total`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Class {
        /// A `3xx`.
        Redirect,
        /// A `4xx` (`409` and `429` included).
        Client,
        /// A `5xx` or a status outside 100 to 599.
        Server,
        /// No response: connection, TLS, timeout, broken exchange.
        Network,
    }

    impl Class {
        /// The label value.
        #[must_use]
        pub fn name(self) -> &'static str {
            match self {
                Self::Redirect => "3xx",
                Self::Client => "4xx",
                Self::Server => "5xx",
                Self::Network => "network",
            }
        }
    }

    const UPLOADED: usize = 0;
    const EXISTING: usize = 1;
    const MISSED: usize = 2;
    const DAMAGED: usize = 3;
    const POISONED: usize = 4;
    const LAG_BLOCKS: usize = 5;
    const LAG_MS: usize = 6;
    const DENIED: usize = 7;
    const UNVERIFIED: usize = 8;
    const FAILED: usize = 9;
    static C: [AtomicU64; FAILED + 4] = [const { AtomicU64::new(0) }; FAILED + 4];
    /// Whether the archive copy runs, for the `stats` line.
    static ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    fn add(i: usize) {
        if let Some(c) = C.get(i) {
            c.fetch_add(1, Relaxed);
        }
    }
    fn get(i: usize) -> u64 {
        C.get(i).map_or(0, |c| c.load(Relaxed))
    }
    fn set(i: usize, v: u64) {
        if let Some(c) = C.get(i) {
            c.store(v, Relaxed);
        }
    }

    pub(super) fn uploaded() {
        add(UPLOADED);
    }
    pub(super) fn existing() {
        add(EXISTING);
    }
    pub(super) fn missed() {
        add(MISSED);
    }
    pub(super) fn damaged() {
        add(DAMAGED);
    }
    pub(super) fn poisoned() {
        add(POISONED);
    }
    pub(super) fn denied() {
        add(DENIED);
    }
    pub(super) fn unverified() {
        add(UNVERIFIED);
    }
    pub(super) fn set_on() {
        ON.store(true, Relaxed);
    }
    pub(super) fn failed(c: Class) {
        add(FAILED + c as usize);
    }
    pub(super) fn set_lag(blocks: Option<u64>, ms: u64) {
        if let Some(b) = blocks {
            set(LAG_BLOCKS, b);
        }
        set(LAG_MS, ms);
    }

    /// `mirror_uploaded_total`.
    #[must_use]
    pub fn uploaded_total() -> u64 {
        get(UPLOADED)
    }
    /// `mirror_existing_total`.
    #[must_use]
    pub fn existing_total() -> u64 {
        get(EXISTING)
    }
    /// `mirror_missed_total`.
    #[must_use]
    pub fn missed_total() -> u64 {
        get(MISSED)
    }
    /// `mirror_damaged_total`.
    #[must_use]
    pub fn damaged_total() -> u64 {
        get(DAMAGED)
    }
    /// `mirror_poisoned_total`.
    #[must_use]
    pub fn poisoned_total() -> u64 {
        get(POISONED)
    }
    /// `mirror_denied_total` (ADR 0052 rule 18).
    #[must_use]
    pub fn denied_total() -> u64 {
        get(DENIED)
    }
    /// `mirror_unverified_total` (mirror review L-4): the check after a `412` did not get a
    /// `200` from the public URL, so nothing says the object is there.
    #[must_use]
    pub fn unverified_total() -> u64 {
        get(UNVERIFIED)
    }
    /// `mirror_failed_total{status}`.
    #[must_use]
    pub fn failed_total(c: Class) -> u64 {
        get(FAILED + c as usize)
    }
    /// The `mirror_lag_blocks` and `mirror_lag_ms` gauges.
    #[must_use]
    pub fn lag() -> (u64, u64) {
        (get(LAG_BLOCKS), get(LAG_MS))
    }

    /// Mirror review L-4: the fields of the `stats` line while the archive copy runs, until
    /// `/metrics` serves them; none otherwise.
    #[must_use]
    pub fn stats() -> Vec<(&'static str, u64)> {
        if !ON.load(Relaxed) {
            return Vec::new();
        }
        let failed = [
            Class::Redirect,
            Class::Client,
            Class::Server,
            Class::Network,
        ]
        .into_iter()
        .map(failed_total)
        .fold(0, u64::saturating_add);
        vec![
            ("mirror_uploaded", uploaded_total()),
            ("mirror_existing", existing_total()),
            ("mirror_failed", failed),
            ("mirror_missed", missed_total()),
            ("mirror_damaged", damaged_total()),
            ("mirror_poisoned", poisoned_total()),
            ("mirror_denied", denied_total()),
            ("mirror_unverified", unverified_total()),
            ("mirror_lag_blocks", get(LAG_BLOCKS)),
            ("mirror_lag_ms", get(LAG_MS)),
        ]
    }
}

use metrics::Class;

/// Rule 22: the variable named by a `*_ref` setting, from the start-up environment. `None`
/// when it is unset or empty. The value is never part of an error.
fn credential(
    env: &[(std::ffi::OsString, std::ffi::OsString)],
    name: &str,
) -> Option<Zeroizing<String>> {
    env.iter()
        .find(|(k, _)| k.to_str() == Some(name))
        .and_then(|(_, v)| v.to_str())
        .filter(|v| !v.is_empty())
        .map(|v| Zeroizing::new(v.to_owned()))
}

/// Where the objects go.
struct Target {
    /// The URL the requests connect to: the endpoint, or `{bucket}.{endpoint host}` with
    /// `mirror_url_style = virtual`.
    url: PeerUrl,
    /// The path of `{mirror_prefix}sbtp/v1/` under `url`, with the bucket for path style.
    base: String,
    region: String,
}

impl Target {
    fn new(s: &Settings, endpoint: &PeerUrl) -> Result<Self, ConfigError> {
        let (url, base) = match s.mirror_url_style {
            UrlStyle::Path => (
                endpoint.clone(),
                format!(
                    "{}/{}/{}sbtp/v1/",
                    endpoint.path(),
                    s.mirror_bucket,
                    s.mirror_prefix
                ),
            ),
            UrlStyle::Virtual => {
                let scheme = if endpoint.is_https() { "https" } else { "http" };
                let url = PeerUrl::parse(&format!(
                    "{scheme}://{}.{}{}",
                    s.mirror_bucket,
                    endpoint.authority(),
                    endpoint.path()
                ))
                .map_err(|reason| ConfigError::Invalid {
                    setting: "mirror_url_style",
                    reason: format!("virtual-hosted style: {reason}"),
                })?;
                let base = format!("{}/{}sbtp/v1/", url.path(), s.mirror_prefix);
                (url, base)
            }
        };
        Ok(Self {
            url,
            base,
            region: s.mirror_region.clone(),
        })
    }

    fn block_path(&self, id: &BlockId) -> String {
        format!("{}block/{}", self.base, store::hex(id))
    }

    fn info_path(&self) -> String {
        format!("{}info", self.base)
    }
}

/// The settings the lanes use.
#[derive(Clone, Copy)]
struct Cfg {
    in_flight: usize,
    max_backoff: Duration,
}

/// The archive copy, prepared at start-up before anything is opened.
pub struct Mirror {
    target: Target,
    creds: Credentials,
    client: Client,
    public: Option<PeerUrl>,
    /// The `/info` object (rule 3), `None` with `mirror_info = false`.
    info: Option<Bytes>,
    cfg: Cfg,
}

impl Mirror {
    /// `None` when `mirror_endpoint` is empty. Reads the credentials from `env` (rule 22) and
    /// loads the trust roots once when the endpoint or the public URL is `https` (rule 23).
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when a referenced variable is unset or empty, no trust root loads, or the
    /// virtual-hosted URL is not valid. No error repeats a credential.
    pub fn prepare(
        s: &Settings,
        env: &[(std::ffi::OsString, std::ffi::OsString)],
    ) -> Result<Option<Self>, ConfigError> {
        let Some(endpoint) = s.mirror_endpoint.as_ref().filter(|_| s.mirror_on()) else {
            return Ok(None);
        };
        let missing = |setting| ConfigError::Invalid {
            setting,
            reason: "the environment variable it names is unset or empty (ADR 0050 rule 22)".into(),
        };
        let creds = Credentials {
            access_key: credential(env, &s.mirror_access_key_ref)
                .ok_or_else(|| missing("mirror_access_key_ref"))?,
            secret_key: credential(env, &s.mirror_secret_key_ref)
                .ok_or_else(|| missing("mirror_secret_key_ref"))?,
            session_token: match &s.mirror_session_token_ref {
                Some(name) => {
                    Some(credential(env, name).ok_or_else(|| missing("mirror_session_token_ref"))?)
                }
                None => None,
            },
        };
        let target = Target::new(s, endpoint)?;
        let https =
            target.url.is_https() || s.mirror_public_url.as_ref().is_some_and(PeerUrl::is_https);
        let tls = if https {
            Some(Arc::new(crate::replication::client_config(
                s,
                "mirror_endpoint",
            )?))
        } else {
            None
        };
        let info = s.mirror_info.then(|| Bytes::from(info_body(s)));
        Ok(Some(Self {
            target,
            creds,
            client: Client::new(
                tls,
                s.mirror_allow_private,
                Duration::from_millis(s.mirror_request_timeout_ms),
            ),
            public: s.mirror_public_url.clone(),
            info,
            cfg: Cfg {
                in_flight: usize::try_from(s.mirror_max_in_flight).unwrap_or(1).max(1),
                max_backoff: Duration::from_secs(s.mirror_max_backoff_s),
            },
        }))
    }

    /// The start-up line `mirror` (ADR 0050 rule 29), written after the `setting` lines.
    pub fn announce(&self, s: &Settings) {
        log::emit(
            Event::Mirror,
            &[
                ("in_flight", Value::Int(s.mirror_max_in_flight)),
                ("info", Value::Bool(self.info.is_some())),
                ("verify", Value::Bool(s.mirror_public_url.is_some())),
            ],
        );
    }

    /// Starts the uploader. The task ends when `stop` turns `true`, or if it panics: the caller
    /// then stops the relay (ADR 0018 rule 37).
    #[must_use]
    pub fn spawn(
        self,
        relay: Arc<Relay<RedbIndex>>,
        stop: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        metrics::set_on();
        let shared = Arc::new(Shared {
            relay,
            m: self,
            jitter: AtomicU64::new(0),
        });
        tokio::spawn(async move {
            let mut stop = stop;
            tokio::select! {
                () = shared.walk() => {}
                _ = stop.wait_for(|s| *s) => {}
            }
        })
    }
}

/// Rule 3: the `/info` object of the read-only relay URL.
fn info_body(s: &Settings) -> String {
    serde_json::json!({
        // ADR 0045: `D_NET`, the blocks a client can expect.
        "min_pow_difficulty": sbtp_core::NETWORK_POW_DIFFICULTY,
        "max_future_ms": s.max_future_ms,
        "block_versions": [sbtp_core::layout::VERSION_V1],
        // Rule 11: a bucket is an archive.
        "block_ttl_ms": null,
        "demand_eviction": false,
        "read_only": true,
    })
    .to_string()
}

/// The outcome of one `PUT` to the bucket (rule 9).
enum Put {
    /// `2xx`.
    Done,
    /// `412`: the key exists.
    Exists,
    /// `409`, `429`, `5xx`, no response: retried with back-off.
    Retry(Class),
    /// Another `4xx` or a `3xx`: retried at the maximum back-off.
    Refused(Class),
}

/// How far ahead of the cursor the lanes may get, in positions: four pages. It bounds the
/// uploader's own state (one [`Slot`] each, about 24 KiB) and what a restart sends again (`412`,
/// cheap). With rule 9's exponential back-off, the block with the longest run of failures holds
/// the cursor, so a larger window copies more meanwhile; four pages copied a store failing one
/// `PUT` in three about 1.5 times faster than two in a simulation of the lanes.
pub const WINDOW: usize = 4 * PAGE;

/// One position of the window.
struct Slot {
    at: Position,
    id: BlockId,
    /// Retryable failures so far, for the back-off of rule 9.
    failures: u32,
    turn: Turn,
}

#[derive(Clone, Copy)]
enum Turn {
    /// Waiting for a lane, not before this instant.
    Ready(Instant),
    /// In a lane.
    Busy,
    /// Uploaded, already there, no longer held or damaged.
    Done,
}

/// The result of one attempt at a block.
enum Attempt {
    Done,
    /// Try again after `delay`; `failure` counts towards the exponential back-off.
    Wait {
        delay: Duration,
        failure: bool,
    },
}

struct Shared {
    relay: Arc<Relay<RedbIndex>>,
    m: Mirror,
    jitter: AtomicU64,
}

impl Shared {
    /// The walk of rule 7. Never returns; the caller stops it.
    ///
    /// The lanes take blocks from a window of at most [`WINDOW`] positions starting at the
    /// cursor, refilled a page at a time. A block that fails waits out its back-off in the
    /// window, not in a lane, so the other lanes keep copying: with a page barrier and lanes
    /// asleep in back-off, a store failing one `PUT` in three held the copy at 7 blocks/s. The
    /// cursor is the lowest position not yet done, so it never passes a block that is not done.
    async fn walk(self: &Arc<Self>) {
        let mut cursor = self.load_cursor().await;
        // Where the next page read starts: just after the last position in the window.
        let mut next = cursor;
        let mut window: VecDeque<Slot> = VecDeque::with_capacity(WINDOW);
        // The sequence number of `window[0]`: a lane's result finds its slot by it.
        let mut base = 0u64;
        let mut idle: Vec<Option<Conn>> = (0..self.m.cfg.in_flight).map(|_| None).collect();
        let mut lanes = JoinSet::new();
        let mut unsaved = 0usize;
        let mut read_at = Instant::now();
        let mut info_due = self.info_due().await;
        let mut info_failures = 0u32;
        let mut info_at = Instant::now();
        let mut counted: Option<Instant> = None;
        loop {
            // Rule 3: a failure is retried after back-off; blocks do not wait for it.
            if info_due
                && Instant::now() >= info_at
                && let Some(conn) = idle.last_mut()
            {
                match self.put_info(conn).await {
                    Ok(()) => info_due = false,
                    Err(delay) => {
                        info_failures = info_failures.saturating_add(1);
                        info_at =
                            Instant::now() + delay.unwrap_or_else(|| self.backoff(info_failures));
                    }
                }
            }
            let room = window.len() + PAGE <= WINDOW;
            if room && Instant::now() >= read_at {
                read_at = self.refill(&mut window, &mut next).await;
            }
            self.update_lag(window.front().map(|s| s.at), cursor, &mut counted)
                .await;
            // Hand every block whose turn has come to an idle lane.
            let now = Instant::now();
            let mut wake = room.then_some(read_at);
            for (seq, slot) in (base..).zip(window.iter_mut()) {
                let Turn::Ready(due) = slot.turn else {
                    continue;
                };
                if due > now {
                    wake = Some(wake.map_or(due, |w| w.min(due)));
                } else if let Some(mut conn) = idle.pop() {
                    slot.turn = Turn::Busy;
                    let (me, at, id, failures) =
                        (Arc::clone(self), slot.at, slot.id, slot.failures);
                    lanes.spawn(async move {
                        let r = me.attempt(&mut conn, at, id, failures).await;
                        (seq, conn, r)
                    });
                }
            }
            let wake = wake.unwrap_or(now + IDLE).max(now);
            tokio::select! {
                Some(done) = lanes.join_next() => {
                    // A lane that panicked is a bug: the relay stops (ADR 0018 rule 37). Lanes
                    // are never aborted, so no other error occurs while the walk runs.
                    let (seq, conn, r) = match done {
                        Ok(v) => v,
                        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                        Err(_) => continue,
                    };
                    idle.push(conn);
                    let slot = seq
                        .checked_sub(base)
                        .and_then(|i| usize::try_from(i).ok())
                        .and_then(|i| window.get_mut(i));
                    if let Some(slot) = slot {
                        slot.turn = match r {
                            Attempt::Done => Turn::Done,
                            Attempt::Wait { delay, failure } => {
                                slot.failures = slot.failures.saturating_add(u32::from(failure));
                                Turn::Ready(Instant::now() + delay)
                            }
                        };
                    }
                }
                () = tokio::time::sleep_until(wake.into()) => {}
            }
            let before = base;
            while window.front().is_some_and(|s| matches!(s.turn, Turn::Done)) {
                window.pop_front();
                base += 1;
            }
            if base > before {
                cursor = window.front().map_or(next, |s| s.at);
                unsaved += usize::try_from(base - before).unwrap_or(PAGE);
                // About once per page, as before, and when the window drains.
                if unsaved >= PAGE || window.is_empty() {
                    self.save_cursor(cursor).await;
                    unsaved = 0;
                }
            }
        }
    }

    /// The `mirror_lag_*` gauges: from the oldest position not yet done; the block count is
    /// recounted at most every [`LAG_EVERY`].
    async fn update_lag(
        &self,
        front: Option<Position>,
        cursor: Position,
        counted: &mut Option<Instant>,
    ) {
        let Some(front) = front else {
            metrics::set_lag(Some(0), 0);
            *counted = None;
            return;
        };
        let blocks = if counted.is_none_or(|t| t.elapsed() >= LAG_EVERY) {
            *counted = Some(Instant::now());
            self.relay
                .index()
                .read(move |i| i.count_from(cursor, LAG_CAP).ok())
                .await
                .ok()
                .flatten()
        } else {
            None
        };
        let now = (self.relay.clock())();
        metrics::set_lag(blocks, now.saturating_sub(front.received_at));
    }

    /// Appends the page at `next` to the window and moves `next` past it; returns when the
    /// next read may happen: now after a page, after [`IDLE`] when caught up, after
    /// [`LOCAL_RETRY`] on a local failure.
    async fn refill(&self, window: &mut VecDeque<Slot>, next: &mut Position) -> Instant {
        let Some(page) = self.read_page(*next).await else {
            return Instant::now() + LOCAL_RETRY;
        };
        let now = Instant::now();
        if page.entries.is_empty() {
            return now + IDLE;
        }
        *next = page.next;
        window.extend(page.entries.into_iter().map(|(at, id)| Slot {
            at,
            id,
            failures: 0,
            turn: Turn::Ready(now),
        }));
        now
    }

    /// The next page of the index from `from`; `None` on a local failure.
    async fn read_page(&self, from: Position) -> Option<crate::index::Page> {
        let page = self
            .relay
            .index()
            .read(move |i| {
                use crate::index::IndexBackend as _;
                i.query(None, from, PAGE)
            })
            .await
            .ok()?;
        self.relay.index().record_read(&page);
        page.ok()
    }

    /// One attempt at a block (rule 9).
    async fn attempt(
        &self,
        conn: &mut Option<Conn>,
        at: Position,
        id: BlockId,
        failures: u32,
    ) -> Attempt {
        // ADR 0043: an expired position is not held.
        if self.relay.is_expired(at) {
            metrics::missed();
            return Attempt::Done;
        }
        // Read again on every attempt: a block waiting out its back-off holds no bytes.
        let bytes = match self.relay.read_for_copy(id).await {
            Copied::Bytes(b) => b,
            Copied::Absent => {
                metrics::missed();
                return Attempt::Done;
            }
            Copied::Damaged => {
                metrics::damaged();
                return Attempt::Done;
            }
            // ADR 0052 rule 18: not uploaded, done, so that the cursor passes it.
            Copied::Denied(m) => {
                metrics::denied();
                crate::metrics::denied(crate::metrics::DenyRoute::Mirror, m.is_key(), 1);
                return Attempt::Done;
            }
            Copied::Retry => {
                return Attempt::Wait {
                    delay: LOCAL_RETRY,
                    failure: false,
                };
            }
        };
        let (class, delay, failure) = match self.put_block(conn, &id, &bytes).await {
            Put::Done => {
                metrics::uploaded();
                return Attempt::Done;
            }
            Put::Exists => {
                metrics::existing();
                self.verify(&id).await;
                return Attempt::Done;
            }
            Put::Retry(c) => (c, self.backoff(failures.saturating_add(1)), true),
            Put::Refused(c) => (c, self.m.cfg.max_backoff, false),
        };
        metrics::failed(class);
        log_failed(class, delay);
        Attempt::Wait { delay, failure }
    }

    /// Rule 9, after a `412`: the object at the public URL, validated once. Only bytes that
    /// fail validation count as poisoning; a failed fetch proves nothing and is not retried.
    async fn verify(&self, id: &BlockId) {
        let Some(public) = &self.m.public else {
            return;
        };
        let mut conn = None;
        let path = format!("/sbtp/v1/block/{}", store::hex(id));
        let Ok(reply) = self
            .m
            .client
            .get(&mut conn, public, &path, BLOCK_CEILING)
            .await
        else {
            metrics::unverified();
            return;
        };
        if reply.status != StatusCode::OK {
            // Mirror review L-4: a store that claims to hold an object it does not serve.
            metrics::unverified();
            return;
        }
        if store::full_validation(&reply.body, id).is_err() {
            static LOG: Throttle = Throttle::new();
            metrics::poisoned();
            let hex = store::hex(id);
            log::throttled(
                &LOG,
                Event::MirrorPoisoned,
                &[("block", Value::Str(&hex))],
                None,
            );
        }
    }

    /// Exponential back-off with jitter, from 1 second to `mirror_max_backoff_s` (rule 9).
    fn backoff(&self, failures: u32) -> Duration {
        let exp = Duration::from_secs(1u64 << failures.saturating_sub(1).min(20))
            .min(self.m.cfg.max_backoff);
        // Uniform in [exp / 2, exp].
        let half = u64::try_from(exp.as_millis() / 2)
            .unwrap_or(u64::MAX)
            .max(1);
        let n = self.jitter.fetch_add(1, Ordering::Relaxed);
        Duration::from_millis(half + RandomState::new().hash_one(n) % (half + 1))
    }

    async fn put_block(&self, conn: &mut Option<Conn>, id: &BlockId, bytes: &Bytes) -> Put {
        let path = self.m.target.block_path(id);
        self.put(
            conn,
            &path,
            bytes.clone(),
            "application/octet-stream",
            BLOCK_CACHE_CONTROL,
            true,
        )
        .await
    }

    /// Rule 3: writes the `/info` object, then records its digest. `Err` holds the delay of a
    /// configuration error (`None`: back off exponentially).
    async fn put_info(&self, conn: &mut Option<Conn>) -> Result<(), Option<Duration>> {
        let Some(body) = self.m.info.clone() else {
            return Ok(());
        };
        let path = self.m.target.info_path();
        let digest = self.info_digest();
        let (class, delay) = match self
            .put(
                conn,
                &path,
                body,
                "application/json",
                INFO_CACHE_CONTROL,
                false,
            )
            .await
        {
            Put::Done => {
                let index = self.relay.index().clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let r =
                        index.write_blocking(move |i| i.set_meta_values(&[(INFO_DIGEST, digest)]));
                    if let Ok(r) = &r {
                        index.record_write(r);
                    }
                })
                .await;
                return Ok(());
            }
            // Not sent with `If-None-Match`: a `412` is not a defined answer.
            Put::Exists => (Class::Client, None),
            Put::Retry(c) => (c, None),
            Put::Refused(c) => (c, Some(self.m.cfg.max_backoff)),
        };
        metrics::failed(class);
        log_failed(class, delay.unwrap_or(LOCAL_RETRY));
        Err(delay)
    }

    /// The digest of the `/info` object and of where it goes: a change of either rewrites it.
    fn info_digest(&self) -> u64 {
        let mut h = blake3::Hasher::new();
        h.update(self.m.target.url.as_str().as_bytes());
        h.update(b"\n");
        h.update(self.m.target.info_path().as_bytes());
        h.update(b"\n");
        h.update(self.m.info.as_deref().unwrap_or_default());
        let mut first = [0u8; 8];
        first.copy_from_slice(h.finalize().as_bytes().get(..8).unwrap_or(&[0; 8]));
        u64::from_be_bytes(first)
    }

    /// Whether the `/info` object needs writing (rule 3). An index that cannot be read writes it.
    async fn info_due(&self) -> bool {
        if self.m.info.is_none() {
            return false;
        }
        let digest = self.info_digest();
        let stored = self
            .relay
            .index()
            .read(|i| i.meta_values([INFO_DIGEST]))
            .await;
        !matches!(stored, Ok(Ok([Some(d)])) if d == digest)
    }

    async fn load_cursor(&self) -> Position {
        loop {
            match self
                .relay
                .index()
                .read(|i| i.meta_values([CURSOR_AT, CURSOR_N]))
                .await
            {
                Ok(Ok([at, n])) => {
                    return Position {
                        received_at: at.unwrap_or(0),
                        n: n.and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
                    };
                }
                _ => tokio::time::sleep(LOCAL_RETRY).await,
            }
        }
    }

    /// Records the cursor on the index writer thread. A failure keeps it in memory only: after a
    /// restart the page is copied again, and `412` makes that cheap.
    async fn save_cursor(&self, c: Position) {
        let index = self.relay.index().clone();
        let _ = tokio::task::spawn_blocking(move || {
            let r = index.write_blocking(move |i| {
                i.set_meta_values(&[(CURSOR_AT, c.received_at), (CURSOR_N, u64::from(c.n))])
            });
            if let Ok(r) = &r {
                index.record_write(r);
            }
        })
        .await;
    }

    /// One signed `PUT` (rules 8 and 9). Only the status is read.
    async fn put(
        &self,
        conn: &mut Option<Conn>,
        path: &str,
        body: Bytes,
        content_type: &'static str,
        cache_control: &'static str,
        create_only: bool,
    ) -> Put {
        let Some(req) = self.request(path, body, content_type, cache_control, create_only) else {
            return Put::Refused(Class::Client);
        };
        match self
            .m
            .client
            .send_discard(conn, &self.m.target.url, req)
            .await
        {
            Ok(status) => classify(status),
            Err(Fail {
                kind: Failed::Address,
                ..
            }) => Put::Refused(Class::Network),
            Err(_) => Put::Retry(Class::Network),
        }
    }

    fn request(
        &self,
        path: &str,
        body: Bytes,
        content_type: &'static str,
        cache_control: &'static str,
        create_only: bool,
    ) -> Option<Request<Body>> {
        let hash = sigv4::sha256_hex(&body);
        let date = sigv4::amz_date((self.relay.clock())());
        let host = self.m.target.url.authority();
        let mut signed: Vec<(&str, &str)> = vec![
            ("cache-control", cache_control),
            ("content-type", content_type),
            ("host", host),
            ("x-amz-content-sha256", &hash),
            ("x-amz-date", &date),
        ];
        if create_only {
            signed.push(("if-none-match", "*"));
        }
        if let Some(t) = &self.m.creds.session_token {
            signed.push(("x-amz-security-token", t.as_str()));
        }
        let auth = Zeroizing::new(sigv4::authorization(
            &Signing {
                method: "PUT",
                path,
                headers: &signed,
                payload_hash: &hash,
                amz_date: &date,
                region: &self.m.target.region,
            },
            &self.m.creds,
        ));
        let mut b = Request::put(sigv4::encode_path(path))
            .header(header::CONTENT_LENGTH, body.len())
            .header(header::USER_AGENT, HeaderValue::from_static("sbtp-relay"));
        for (n, v) in &signed {
            let Ok(mut v) = HeaderValue::from_str(v) else {
                return None;
            };
            // Mirror review L-2: the session token, like `Authorization`, is sensitive.
            v.set_sensitive(*n == "x-amz-security-token");
            b = b.header(*n, v);
        }
        let mut auth = HeaderValue::from_str(&auth).ok()?;
        auth.set_sensitive(true);
        b.header(header::AUTHORIZATION, auth)
            .body(Body::from(body))
            .ok()
    }
}

/// Rule 9.
fn classify(status: StatusCode) -> Put {
    match status.as_u16() {
        200..=299 => Put::Done,
        412 => Put::Exists,
        409 | 429 => Put::Retry(Class::Client),
        300..=399 => Put::Refused(Class::Redirect),
        400..=499 => Put::Refused(Class::Client),
        _ => Put::Retry(Class::Server),
    }
}

/// `mirror_failed`, rate-capped: the status class and the delay only; no URL, key or response
/// body is ever logged (rule 23).
fn log_failed(class: Class, delay: Duration) {
    static LOG: Throttle = Throttle::new();
    log::throttled(
        &LOG,
        Event::MirrorFailed,
        &[
            ("status", Value::Str(class.name())),
            (
                "delay_ms",
                Value::Int(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)),
            ),
        ],
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR 0054 rules 5 and 43: the read-only URL of the bucket has no subscription route, so
    /// its `/info` never publishes `subscribe`, whatever `ws_enabled` says.
    #[test]
    #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
    fn the_read_only_info_has_no_subscribe_member() {
        let s = Settings::load(
            Vec::<std::ffi::OsString>::new(),
            [("SBTP_RELAY_WS_ENABLED".into(), "true".into())],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&info_body(&s)).unwrap();
        assert_eq!(v["read_only"], true);
        assert!(v.get("subscribe").is_none());
    }

    /// The window's share of the memory bound (`EST_MIRROR_WINDOW` in `config.rs`) counts 96
    /// bytes per slot.
    #[test]
    fn slot_size() {
        assert!(size_of::<Slot>() <= 96, "{}", size_of::<Slot>());
    }

    #[test]
    fn statuses() {
        assert!(matches!(classify(StatusCode::OK), Put::Done));
        assert!(matches!(
            classify(StatusCode::PRECONDITION_FAILED),
            Put::Exists
        ));
        assert!(matches!(
            classify(StatusCode::CONFLICT),
            Put::Retry(Class::Client)
        ));
        assert!(matches!(
            classify(StatusCode::TOO_MANY_REQUESTS),
            Put::Retry(Class::Client)
        ));
        assert!(matches!(
            classify(StatusCode::SERVICE_UNAVAILABLE),
            Put::Retry(Class::Server)
        ));
        assert!(matches!(
            classify(StatusCode::FORBIDDEN),
            Put::Refused(Class::Client)
        ));
        assert!(matches!(
            classify(StatusCode::FOUND),
            Put::Refused(Class::Redirect)
        ));
    }
}
