//! Pull replication (ADR 0048 rules 4 to 19), feature `replication`, on only when `peers` is not
//! empty.
//!
//! The relay is a client of each peer its operator lists. `replication_max_in_flight` workers
//! share the peers: each takes the next ready peer in round robin order for one **turn** (one
//! `/query` page, at most [`TURN_FETCHES`] block fetches), so that one peer cannot take another's
//! share (rule 10). In a turn the worker:
//!
//! 1. stops at once while the store is above the high-water mark (rule 13);
//! 2. asks the peer for one page of `/query?limit=1000&since=&cursor=`, at most one per peer and
//!    per [`QUERY_INTERVAL`];
//! 3. skips, without fetching, each identifier below `min_pow_difficulty` and each one held and
//!    not expired (rule 6);
//! 4. fetches the others with `GET /sbtp/v1/block/{id}` and `Sbtp-Replication: 1`, within the
//!    block and byte budgets, and stores each through the `PUT` pipeline with R1
//!    ([`Relay::store_replicated`]);
//! 5. records the page's cursor durably once every identifier of the page was handled
//!    ([`cursor`], rule 8).
//!
//! A turn that ends inside a page keeps the last identifier it handled in memory and lists the
//! same page again next turn: the identifiers before it are not handled twice, and after a
//! restart the held check makes the second walk cheap. A failed request backs the peer off
//! (rule 11): `Retry-After` when the peer sent one, else exponentially with jitter from 1 second
//! to `replication_max_backoff_s`. Nothing a peer sends adds a peer or a URL (rule 5).

pub mod cursor;
pub mod http;
pub mod metrics;

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use sbtp_core::BlockId;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::blocks::{Relay, Replicated};
use crate::config::{ConfigError, Settings};
use crate::index::{IndexBackend, IndexError};
use crate::log::{self, Event, Throttle, Value};
use crate::peers::{PeerUrl, ReplicationStart};
use crate::store;
use cursor::{CursorStore, Walk, valid_cursor};
use http::{BLOCK_CEILING, Client, Fail, QUERY_CEILING, fail};
use metrics::{Failed, Skip};

/// The `limit` of each `/query` (rule 15: one `/query` per page of up to 1,000 identifiers).
pub const QUERY_LIMIT: usize = 1_000;
/// Block fetches of one turn, after which the next peer has its turn (rule 10).
pub const TURN_FETCHES: usize = 64;
/// Rule 7: invalid blocks in one round after which the round ends and the peer backs off.
pub const MAX_INVALID: usize = 16;
/// The least time between two `/query` of one peer: 60 per minute at most, under the `query`
/// allowance of a `small` peer (300 per minute, burst 20; rule 11).
pub const QUERY_INTERVAL: Duration = Duration::from_secs(1);
/// How often a paused replication looks at the store again (rule 13).
const PAUSE_RECHECK: Duration = Duration::from_secs(5);
/// The retry delay after a local refusal or failure (rule 12): no permit, an index queue full.
const LOCAL_RETRY: Duration = Duration::from_secs(1);
/// Held checks per index job.
const HELD_CHUNK: usize = 64;
/// The longest wait for a peer, whatever its `Retry-After` (Instant arithmetic stays bounded).
const MAX_WAIT: Duration = Duration::from_secs(30 * 86_400);

/// The settings the workers use.
#[derive(Clone, Copy, Debug)]
struct Cfg {
    min_pow: u32,
    poll: Duration,
    max_backoff: Duration,
    margin_ms: u64,
    start: ReplicationStart,
    in_flight: usize,
    /// Rule 13: `demand_high_water_pct` of `max_store_bytes`, 90 % without demand eviction.
    high_water: u64,
}

/// Replication, prepared at start-up before anything is opened.
pub struct Replication {
    peers: Vec<PeerUrl>,
    client: Client,
    cfg: Cfg,
    blocks_per_min: u64,
    bytes_per_hour: u64,
}

impl Replication {
    /// Rule 3 and rule 19: `None` when `peers` is empty. Loads the trust roots once when a peer
    /// is `https`: `peer_ca_file` when set, else the operating system store.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when no trust root can be loaded, or the TLS client cannot be built.
    pub fn prepare(s: &Settings) -> Result<Option<Self>, ConfigError> {
        if !s.replication_on() {
            return Ok(None);
        }
        let tls = if s.peers.iter().any(PeerUrl::is_https) {
            Some(Arc::new(client_config(s, "peers")?))
        } else {
            None
        };
        let pct = if s.demand_eviction {
            s.demand_high_water_pct
        } else {
            90
        };
        let high_water = u64::try_from(u128::from(s.max_store_bytes) * u128::from(pct) / 100)
            .unwrap_or(u64::MAX);
        let peers = u64::try_from(s.peers.len()).unwrap_or(u64::MAX);
        log::emit(
            Event::Replication,
            &[
                ("peers", Value::Int(peers)),
                ("start", Value::Str(s.replication_start.name())),
                ("in_flight", Value::Int(s.replication_max_in_flight)),
            ],
        );
        Ok(Some(Self {
            peers: s.peers.clone(),
            client: Client::new(
                tls,
                s.replication_allow_private,
                Duration::from_millis(s.replication_request_timeout_ms),
            ),
            cfg: Cfg {
                min_pow: s.min_pow_difficulty,
                poll: Duration::from_millis(s.replication_poll_ms),
                max_backoff: Duration::from_secs(s.replication_max_backoff_s),
                margin_ms: s.replication_resync_margin_ms,
                start: s.replication_start,
                in_flight: usize::try_from(s.replication_max_in_flight).unwrap_or(1),
                high_water,
            },
            blocks_per_min: s.replication_blocks_per_min,
            bytes_per_hour: s.replication_bytes_per_hour,
        }))
    }

    /// Starts the workers. The task returned ends when `stop` turns `true`, or as soon as a
    /// worker ends otherwise (a panic): the caller then stops the relay (ADR 0018 rule 37).
    #[must_use]
    pub fn spawn<I>(self, relay: Arc<Relay<I>>, stop: watch::Receiver<bool>) -> JoinHandle<()>
    where
        I: IndexBackend<Error = IndexError> + CursorStore + 'static,
    {
        let now = Instant::now();
        let slots = self
            .peers
            .into_iter()
            .map(|url| Slot {
                url,
                next_at: now,
                work: Some(Work::default()),
            })
            .collect();
        let blocks_cap = (self.blocks_per_min / 10).max(1);
        let bytes_cap = (self.bytes_per_hour / 60)
            .max(u64::try_from(BLOCK_CEILING + QUERY_CEILING).unwrap_or(u64::MAX));
        let shared = Arc::new(Shared {
            relay,
            client: self.client,
            cfg: self.cfg,
            sched: Mutex::new(Sched { next: 0, slots }),
            blocks: Bucket::new(self.blocks_per_min, 60_000, blocks_cap),
            bytes: Bucket::new(self.bytes_per_hour, 3_600_000, bytes_cap),
            jitter: AtomicU64::new(0),
        });
        tokio::spawn(async move {
            shared.retain().await;
            let mut workers = JoinSet::new();
            for _ in 0..shared.cfg.in_flight {
                workers.spawn(worker(Arc::clone(&shared), stop.clone()));
            }
            // The first worker that ends ends replication: at a stop every worker ends.
            let _ = workers.join_next().await;
            workers.abort_all();
            while workers.join_next().await.is_some() {}
        })
    }
}

/// The largest trust file read.
const MAX_TRUST_FILE: u64 = 4 << 20;

/// The certificates of a PEM file, read up to [`MAX_TRUST_FILE`] bytes.
fn read_pem(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    use std::io::Read as _;
    let mut pem = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_TRUST_FILE + 1).read_to_end(&mut pem))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if u64::try_from(pem.len()).unwrap_or(u64::MAX) > MAX_TRUST_FILE {
        return Err(format!("{}: larger than 4 MiB", path.display()));
    }
    CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("{}: not a PEM file of certificates", path.display()))
}

/// Rule 19: rustls, `ring`, TLS 1.3 only, the roots of `peer_ca_file` or of the operating
/// system, hostname verification by the `WebPKI` verifier, no resumption, ALPN `http/1.1`.
/// `user` names the setting that needs it in errors (`peers`, or `mirror_endpoint` for the
/// archive copy of ADR 0050 rule 23).
pub(crate) fn client_config(
    s: &Settings,
    user: &'static str,
) -> Result<rustls::ClientConfig, ConfigError> {
    let (setting, certs) = if let Some(path) = &s.peer_ca_file {
        let certs = read_pem(path).map_err(|reason| ConfigError::Invalid {
            setting: "peer_ca_file",
            reason,
        })?;
        ("peer_ca_file", certs)
    } else {
        // `rustls-native-certs`: `SSL_CERT_FILE` or `SSL_CERT_DIR` when set, else the platform
        // store (openssl-probe's file locations on Linux, Security.framework on macOS). Errors on
        // single certificates are ignored; what matters is that some root loads.
        (user, rustls_native_certs::load_native_certs().certs)
    };
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(ConfigError::Invalid {
            setting,
            reason: "no trust root could be loaded for the https URLs from peer_ca_file or \
                     the operating system bundle (ADR 0048 rule 19)"
                .into(),
        });
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ConfigError::Invalid {
            setting: user,
            reason: "the TLS client could not be built".into(),
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// What a worker carries through a peer's turn.
#[derive(Debug, Default)]
struct Work {
    /// `None` until read from the cursor table.
    walk: Option<Walk>,
    /// The last identifier handled in the current page.
    resume_after: Option<BlockId>,
    /// Failed requests in a row (rule 11).
    failures: u32,
    last_query: Option<Instant>,
}

struct Slot {
    url: PeerUrl,
    next_at: Instant,
    /// `None` while a worker holds the peer.
    work: Option<Work>,
}

struct Sched {
    next: usize,
    slots: Vec<Slot>,
}

struct Shared<I> {
    relay: Arc<Relay<I>>,
    client: Client,
    cfg: Cfg,
    sched: Mutex<Sched>,
    blocks: Bucket,
    bytes: Bucket,
    jitter: AtomicU64,
}

/// The outcome of one block fetch.
enum Fetched {
    /// Stored, held, `404` or P1: the identifier is handled.
    Handled,
    /// Failed validation: handled, and counted toward [`MAX_INVALID`].
    Invalid,
    /// Not stored for a local reason: the turn ends, the identifier is not handled.
    Retry(Duration),
    /// A failed request: the peer backs off.
    Failed(Fail),
}

/// One peer page of `/query`, checked (ADR 0029).
struct Page {
    ids: Vec<BlockId>,
    cursor: String,
    more: bool,
}

async fn worker<I>(shared: Arc<Shared<I>>, mut stop: watch::Receiver<bool>)
where
    I: IndexBackend<Error = IndexError> + CursorStore + 'static,
{
    loop {
        if *stop.borrow() {
            return;
        }
        match shared.pick() {
            Ok((peer, url, work)) => {
                let turned = tokio::select! {
                    r = shared.turn(peer, &url, work) => Some(r),
                    _ = stop.changed() => None,
                };
                let Some((work, next_at)) = turned else {
                    return;
                };
                shared.put_back(peer, work, next_at);
            }
            Err(at) => {
                let at = at.min(Instant::now() + LOCAL_RETRY);
                tokio::select! {
                    () = tokio::time::sleep_until(at.into()) => {}
                    _ = stop.changed() => return,
                }
            }
        }
    }
}

impl<I: IndexBackend<Error = IndexError> + CursorStore + 'static> Shared<I> {
    fn sched(&self) -> std::sync::MutexGuard<'_, Sched> {
        self.sched.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The next ready peer in round robin order, taken from its slot; else the earliest time a
    /// peer is ready.
    fn pick(&self) -> Result<(usize, PeerUrl, Work), Instant> {
        let now = Instant::now();
        let mut s = self.sched();
        let n = s.slots.len();
        let first = s.next;
        for k in 0..n {
            let i = (first + k) % n;
            if let Some(slot) = s.slots.get_mut(i)
                && slot.next_at <= now
                && let Some(work) = slot.work.take()
            {
                let url = slot.url.clone();
                s.next = (i + 1) % n;
                return Ok((i, url, work));
            }
        }
        Err(s
            .slots
            .iter()
            .filter(|s| s.work.is_some())
            .map(|s| s.next_at)
            .min()
            .unwrap_or(now + LOCAL_RETRY))
    }

    fn put_back(&self, peer: usize, work: Work, next_at: Instant) {
        if let Some(slot) = self.sched().slots.get_mut(peer) {
            slot.work = Some(work);
            slot.next_at = next_at;
        }
    }

    /// Rule 8: the rows of peers no longer configured are removed at start-up.
    async fn retain(&self) {
        let keep: Vec<String> = self
            .sched()
            .slots
            .iter()
            .map(|s| s.url.as_str().to_owned())
            .collect();
        let index = self.relay.index().clone();
        let _ = tokio::task::spawn_blocking(move || {
            index.write_blocking(move |i| i.retain_walks(&keep))
        })
        .await;
    }

    /// Rule 13.
    fn over_high_water(&self) -> bool {
        let over = self.relay.store().admission_total() > self.cfg.high_water;
        if over {
            static LOG: Throttle = Throttle::new();
            metrics::set_paused(true);
            log::throttled(
                &LOG,
                Event::ReplicationPaused,
                &[("high_water_bytes", Value::Int(self.cfg.high_water))],
                None,
            );
        } else {
            metrics::set_paused(false);
        }
        over
    }

    /// One turn of `peer` (see the module documentation). Returns the work and when the peer is
    /// ready again.
    async fn turn(&self, peer: usize, url: &PeerUrl, mut w: Work) -> (Work, Instant) {
        let now = Instant::now();
        if self.over_high_water() {
            return (w, now + PAUSE_RECHECK);
        }
        let walk = match w.walk.take() {
            Some(walk) => walk,
            None => match self.load_walk(url).await {
                Some(walk) => walk,
                None => return (w, now + LOCAL_RETRY),
            },
        };
        w.walk = Some(walk);
        if let Some(t) = w.last_query
            && now < t + QUERY_INTERVAL
        {
            return (w, t + QUERY_INTERVAL);
        }
        if let Err(wait) = self.bytes.ready() {
            return (w, now + wait);
        }
        w.last_query = Some(now);
        let mut conn = None;
        let path = query_path(w.walk.as_ref());
        let reply = match self.client.get(&mut conn, url, &path, QUERY_CEILING).await {
            Ok(r) => r,
            Err(f) => return self.back_off(peer, w, f),
        };
        self.read(peer, reply.body.len());
        let page = match reply.status {
            StatusCode::OK => parse_page(&reply.body),
            StatusCode::BAD_REQUEST if is_invalid_cursor(&reply.body) => {
                self.reset(peer, url, &mut w).await;
                return (w, Instant::now());
            }
            _ => None,
        };
        drop(reply);
        let Some(page) = page else {
            return self.back_off(peer, w, fail(Failed::Invalid));
        };
        w.failures = 0;
        let start = w
            .resume_after
            .and_then(|r| page.ids.iter().position(|id| *id == r))
            .map_or(0, |p| p + 1);
        let mut fetched = 0;
        let mut invalid = 0;
        for chunk in page.ids.get(start..).unwrap_or_default().chunks(HELD_CHUNK) {
            let Some(held) = self.held(chunk).await else {
                return (w, Instant::now() + LOCAL_RETRY);
            };
            for (id, held) in chunk.iter().zip(held) {
                // Rule 6: the proof of work depends on the identifier alone; never re-mined.
                if id.leading_zero_bits() < self.cfg.min_pow {
                    metrics::skipped(peer, Skip::Pow);
                    w.resume_after = Some(*id);
                    continue;
                }
                if held {
                    metrics::skipped(peer, Skip::Held);
                    w.resume_after = Some(*id);
                    continue;
                }
                let now = Instant::now();
                if fetched >= TURN_FETCHES {
                    return (w, now);
                }
                if self.over_high_water() {
                    return (w, now + PAUSE_RECHECK);
                }
                if let Err(wait) = self.blocks.take().and_then(|()| self.bytes.ready()) {
                    return (w, now + wait);
                }
                fetched += 1;
                match self.fetch(peer, url, &mut conn, id).await {
                    Fetched::Handled => {}
                    Fetched::Invalid => {
                        invalid += 1;
                        if invalid >= MAX_INVALID {
                            w.resume_after = Some(*id);
                            return self.back_off(peer, w, fail(Failed::InvalidBlocks));
                        }
                    }
                    // The block was not stored; the walk does not skip it.
                    Fetched::Retry(d) => return (w, now + d),
                    Fetched::Failed(f) => return self.back_off(peer, w, f),
                }
                w.resume_after = Some(*id);
            }
        }
        self.page_done(url, w, page).await
    }

    /// Rule 8: every identifier of `page` is handled; its cursor is recorded. A caught-up walk
    /// (`more = false`) waits `replication_poll_ms` (rule 10).
    async fn page_done(&self, url: &PeerUrl, mut w: Work, page: Page) -> (Work, Instant) {
        if let Some(walk) = w.walk.as_mut() {
            walk.cursor = Some(page.cursor);
            walk.last_page_ms = (self.relay.clock())();
        }
        w.resume_after = None;
        self.save_walk(url, w.walk.clone()).await;
        let next = if page.more {
            Instant::now()
        } else {
            Instant::now() + self.cfg.poll
        };
        (w, next)
    }

    /// Fetches `id` from the peer and stores it (rules 4, 7, 12 and 13).
    async fn fetch(
        &self,
        peer: usize,
        url: &PeerUrl,
        conn: &mut Option<http::Conn>,
        id: &BlockId,
    ) -> Fetched {
        let path = format!("/sbtp/v1/block/{}", store::hex(id));
        let reply = match self.client.get(conn, url, &path, BLOCK_CEILING).await {
            Ok(r) => r,
            Err(f) => return Fetched::Failed(f),
        };
        self.read(peer, reply.body.len());
        if reply.status == StatusCode::NOT_FOUND {
            metrics::skipped(peer, Skip::NotFound);
            return Fetched::Handled;
        }
        if !reply.status.is_success() {
            return Fetched::Failed(fail(Failed::Client));
        }
        match self.relay.store_replicated(reply.body, *id).await {
            Replicated::New => metrics::stored(peer),
            Replicated::Known => metrics::skipped(peer, Skip::Held),
            Replicated::Future => metrics::skipped(peer, Skip::Future),
            Replicated::Invalid => {
                metrics::skipped(peer, Skip::Invalid);
                return Fetched::Invalid;
            }
            // Rule 13.
            Replicated::Full => return Fetched::Retry(PAUSE_RECHECK),
            // Rule 12: retried in the next round.
            Replicated::Busy | Replicated::Internal => return Fetched::Retry(LOCAL_RETRY),
        }
        Fetched::Handled
    }

    fn read(&self, peer: usize, n: usize) {
        let n = u64::try_from(n).unwrap_or(u64::MAX);
        self.bytes.charge(n);
        metrics::bytes(peer, n);
    }

    /// Rule 11: `Retry-After` when given (at least 1 second), else exponential back-off with
    /// jitter from 1 second to `replication_max_backoff_s`. The peer is never given up.
    fn back_off(&self, peer: usize, mut w: Work, f: Fail) -> (Work, Instant) {
        static LOG: Throttle = Throttle::new();
        metrics::failed(peer, f.kind);
        w.failures = w.failures.saturating_add(1);
        let delay = if let Some(s) = f.retry_after {
            Duration::from_secs(s.max(1)).min(MAX_WAIT)
        } else {
            let exp =
                Duration::from_secs(1u64 << (w.failures - 1).min(20)).min(self.cfg.max_backoff);
            // Uniform in [exp / 2, exp].
            let half = u64::try_from(exp.as_millis() / 2)
                .unwrap_or(u64::MAX)
                .max(1);
            let n = self.jitter.fetch_add(1, Ordering::Relaxed);
            Duration::from_millis(half + RandomState::new().hash_one(n) % (half + 1))
        };
        let p = u64::try_from(peer).unwrap_or(u64::MAX);
        log::throttled(
            &LOG,
            Event::ReplicationPeerBackoff,
            &[
                ("peer", Value::Int(p)),
                ("status", Value::Str(f.kind.name())),
                (
                    "delay_ms",
                    Value::Int(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)),
                ),
            ],
            None,
        );
        let now = Instant::now();
        (
            w,
            now.checked_add(delay).unwrap_or(now + self.cfg.max_backoff),
        )
    }

    /// Rule 9: `InvalidCursor`, a new index epoch of the peer. The cursor is dropped and the walk
    /// starts again from its last complete page, minus `replication_resync_margin_ms`.
    async fn reset(&self, peer: usize, url: &PeerUrl, w: &mut Work) {
        static LOG: Throttle = Throttle::new();
        metrics::cursor_reset(peer);
        log::throttled(
            &LOG,
            Event::ReplicationCursorReset,
            &[("peer", Value::Int(u64::try_from(peer).unwrap_or(u64::MAX)))],
            None,
        );
        if let Some(walk) = w.walk.as_mut() {
            walk.cursor = None;
            if walk.last_page_ms > 0 {
                walk.since = Some(walk.last_page_ms.saturating_sub(self.cfg.margin_ms));
            }
        }
        w.resume_after = None;
        self.save_walk(url, w.walk.clone()).await;
    }

    /// The walk of `url` from the cursor table, or a new one (rule 9), recorded at once so that
    /// the time the peer was first seen survives a restart. `None` when the index refused.
    async fn load_walk(&self, url: &PeerUrl) -> Option<Walk> {
        let key = url.as_str().to_owned();
        let found = self
            .relay
            .index()
            .read(move |i| i.load_walk(&key))
            .await
            .ok()?;
        if let Ok(Some(walk)) = found {
            return Some(walk);
        }
        found.ok()?;
        let walk = Walk {
            since: match self.cfg.start {
                ReplicationStart::Now => {
                    Some((self.relay.clock())().saturating_sub(self.cfg.margin_ms))
                }
                ReplicationStart::All => None,
            },
            cursor: None,
            last_page_ms: 0,
        };
        self.save_walk(url, Some(walk.clone())).await;
        Some(walk)
    }

    /// Records `walk` on the index writer thread. A failure keeps the walk in memory only: the
    /// next start walks again from the last recorded page (rule 8).
    async fn save_walk(&self, url: &PeerUrl, walk: Option<Walk>) {
        let Some(walk) = walk else { return };
        let key = url.as_str().to_owned();
        let index = self.relay.index().clone();
        let _ = tokio::task::spawn_blocking(move || {
            let r = index.write_blocking(move |i| i.save_walk(&key, &walk));
            if let Ok(r) = &r {
                index.record_write(r);
            }
        })
        .await;
    }

    /// Rule 6, one index job per chunk: whether each identifier is held and not expired. A
    /// failed lookup reads as not held (the storage step decides); `None` when the reader queue
    /// refused the job.
    async fn held(&self, ids: &[BlockId]) -> Option<Vec<bool>> {
        let ids = ids.to_vec();
        let found = self
            .relay
            .index()
            .read(move |i| ids.iter().map(|id| i.contains(id)).collect::<Vec<_>>())
            .await
            .ok()?;
        Some(
            found
                .into_iter()
                .map(|r| {
                    self.relay.index().record_read(&r);
                    matches!(r, Ok(Some(at)) if !self.relay.is_expired(at))
                })
                .collect(),
        )
    }
}

/// The path and query of the next page of a walk.
fn query_path(walk: Option<&Walk>) -> String {
    use std::fmt::Write as _;
    let mut p = format!("/sbtp/v1/query?limit={QUERY_LIMIT}");
    if let Some(since) = walk.and_then(|w| w.since) {
        let _ = write!(p, "&since={since}");
    }
    if let Some(c) = walk.and_then(|w| w.cursor.as_deref())
        && valid_cursor(c)
    {
        p.push_str("&cursor=");
        p.push_str(c);
    }
    p
}

/// A `/query` body (core spec §4 and "Client bounds"): an object with `block_ids` (at most
/// [`QUERY_LIMIT`] distinct identifiers of 64 lowercase hexadecimal characters), `cursor` (the
/// cursor syntax) and `more` (a boolean). Other members are ignored. `None`: a failed request.
fn parse_page(body: &[u8]) -> Option<Page> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let o = v.as_object()?;
    let list = o.get("block_ids")?.as_array()?;
    if list.len() > QUERY_LIMIT {
        return None;
    }
    let ids = list
        .iter()
        .map(|i| i.as_str().and_then(store::parse_hex_id))
        .collect::<Option<Vec<BlockId>>>()?;
    let cursor = o.get("cursor")?.as_str()?;
    let more = o.get("more")?.as_bool()?;
    if !valid_cursor(cursor) {
        return None;
    }
    let mut sorted: Vec<&BlockId> = ids.iter().collect();
    sorted.sort_unstable_by_key(|id| id.as_bytes());
    if sorted.windows(2).any(|w| matches!(w, [a, b] if a == b)) {
        return None;
    }
    let cursor = cursor.to_owned();
    drop(sorted);
    Some(Page { ids, cursor, more })
}

/// Whether an error body names `InvalidCursor` (core spec §4, "Errors").
fn is_invalid_cursor(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(serde_json::Value::as_str)
        == Some("InvalidCursor")
}

/// A token bucket in integers: the level is kept in tokens × `period_ms`, so that a refill of
/// `rate` tokens per `period_ms` adds `rate` units per millisecond. The level may go below zero
/// after a charge (bytes are charged once read); nothing is taken until it is positive again.
struct Bucket {
    state: Mutex<(i128, Instant)>,
    rate: i128,
    period: i128,
    cap: i128,
}

impl Bucket {
    fn new(rate: u64, period_ms: u64, capacity: u64) -> Self {
        let period = i128::from(period_ms.max(1));
        let cap = i128::from(capacity) * period;
        Self {
            state: Mutex::new((cap, Instant::now())),
            rate: i128::from(rate.max(1)),
            period,
            cap,
        }
    }

    fn level(&self) -> std::sync::MutexGuard<'_, (i128, Instant)> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        let elapsed = i128::try_from(now.duration_since(s.1).as_millis()).unwrap_or(i128::MAX);
        if elapsed > 0 {
            s.0 =
                s.0.saturating_add(elapsed.saturating_mul(self.rate))
                    .min(self.cap);
            s.1 = now;
        }
        s
    }

    /// The wait until the level reaches `units`.
    fn wait(&self, level: i128, units: i128) -> Duration {
        let ms = (units - level).max(0) / self.rate + 1;
        Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX))
    }

    /// Takes one token, or the wait until one is there.
    fn take(&self) -> Result<(), Duration> {
        let mut s = self.level();
        if s.0 >= self.period {
            s.0 -= self.period;
            Ok(())
        } else {
            Err(self.wait(s.0, self.period))
        }
    }

    /// `Ok` when the level is positive.
    fn ready(&self) -> Result<(), Duration> {
        let s = self.level();
        if s.0 > 0 {
            Ok(())
        } else {
            Err(self.wait(s.0, 1))
        }
    }

    /// Charges `n` tokens.
    fn charge(&self, n: u64) {
        let mut s = self.level();
        s.0 =
            s.0.saturating_sub(i128::from(n).saturating_mul(self.period));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn page_shapes() {
        let id = |b: char| b.to_string().repeat(64);
        let ok = format!(
            r#"{{"block_ids":["{}","{}"],"cursor":"k_1","more":true,"x":[1]}}"#,
            id('a'),
            id('b')
        );
        let p = parse_page(ok.as_bytes()).unwrap();
        assert_eq!(p.ids.len(), 2);
        assert!(p.more);
        assert_eq!(p.cursor, "k_1");
        for bad in [
            "[]".to_owned(),
            r#"{"block_ids":[],"cursor":"","more":false}"#.to_owned(),
            r#"{"block_ids":[],"cursor":"a b","more":false}"#.to_owned(),
            r#"{"block_ids":[],"cursor":"a","more":"no"}"#.to_owned(),
            r#"{"block_ids":["AB"],"cursor":"a","more":false}"#.to_owned(),
            format!(
                r#"{{"block_ids":["{}"],"cursor":"a","more":false}}"#,
                "A".repeat(64)
            ),
            format!(
                r#"{{"block_ids":["{0}","{0}"],"cursor":"a","more":false}}"#,
                id('c')
            ),
            format!(
                r#"{{"block_ids":[{}],"cursor":"a","more":false}}"#,
                (0..=QUERY_LIMIT)
                    .map(|n| format!("\"{n:064x}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ] {
            assert!(parse_page(bad.as_bytes()).is_none(), "{bad}");
        }
        assert!(is_invalid_cursor(br#"{"error":"InvalidCursor"}"#));
        assert!(!is_invalid_cursor(br#"{"error":"InvalidParameter"}"#));
        assert!(!is_invalid_cursor(b"nope"));
    }

    #[test]
    fn query_paths() {
        assert_eq!(query_path(None), "/sbtp/v1/query?limit=1000");
        let w = Walk {
            since: Some(5),
            cursor: Some("abc".into()),
            last_page_ms: 0,
        };
        assert_eq!(
            query_path(Some(&w)),
            "/sbtp/v1/query?limit=1000&since=5&cursor=abc"
        );
    }

    #[test]
    fn bucket_takes_waits_and_refills() {
        let b = Bucket::new(600, 60_000, 2);
        assert!(b.take().is_ok());
        assert!(b.take().is_ok());
        let wait = b.take().unwrap_err();
        assert!(wait <= Duration::from_millis(101), "{wait:?}");
        let bytes = Bucket::new(3_600_000, 3_600_000, 10);
        assert!(bytes.ready().is_ok());
        bytes.charge(1_000);
        let wait = bytes.ready().unwrap_err();
        assert!(wait >= Duration::from_millis(900), "{wait:?}");
    }
}
