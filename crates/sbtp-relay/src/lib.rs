//! # sbtp-relay
//!
//! The SBTP v1 dumb relay (`SPEC.md` §5 to §7): it checks the layer 0 envelope with `sbtp-core`,
//! stores blocks in receipt order and serves them over HTTP and WebSocket. It never reads a
//! payload. TLS is left to a reverse proxy, which also bounds slow or idle request heads: the
//! relay listens on loopback by default and is exposed only through one.

// A handler's early exit is its response; boxing every `Err(Response)` would buy nothing.
#![allow(clippy::result_large_err)]

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderName;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast, watch};

mod http;
mod limits;
mod store;
mod subscribe;

pub use limits::ClientKey;
use limits::{Counter, DenyList, RateLimiter};

/// Relay configuration. The operator sets it through the `SBTP_*` variables of
/// [`Config::from_env`]; the remaining fields are internal limits that only tests change.
#[derive(Clone)]
pub struct Config {
    /// Directory of the store (`relay.redb`) and of the deny list (`deny.txt`).
    pub data_dir: PathBuf,
    /// spec §4 C1 on `PUT`, published in `/info`.
    pub min_pow_difficulty: u32,
    /// spec §7 global disk quota, in bytes of store file.
    pub max_store_bytes: u64,
    /// Header holding the client address, set by the reverse proxy (its last entry is used).
    /// `None`: the TCP peer address is the client.
    pub client_ip_header: Option<HeaderName>,
    /// spec §7: listed client addresses, given `LISTED_FACTOR` times the per-client limits.
    pub listed: HashSet<ClientKey>,
    /// spec §7 body read timeout (`408`); 64 KiB arrives in 10 s even over a poor link.
    pub body_timeout: Duration,
    /// Per-client requests per second, and the burst a client may save up.
    pub rate_per_sec: f64,
    /// See `rate_per_sec`.
    pub rate_burst: f64,
    /// Global requests in flight, `503` above: each may hold one block in memory.
    pub max_requests: usize,
    /// Global `/subscribe` connections (`503`); each may hold a 256 KiB catch-up page.
    pub max_subscriptions: usize,
    /// spec §6 bounded live queue, in blocks, shared by all subscribers.
    pub live_queue: usize,
    /// A subscriber silent (not even a pong) this long is closed with `1000`; pinged at a third.
    pub idle_timeout: Duration,
    /// spec §6 maximum connection age, closed with `1000`.
    pub max_age: Duration,
    /// How often the deny list file is checked for changes.
    pub deny_reload: Duration,
}

/// spec §4 P1 margin; 5 minutes absorbs ordinary clock skew.
const MAX_FUTURE_MS: u64 = 300_000;
/// spec §5 `/query` cap; 1,000 ids and positions fit in about 90 KB of the 128 KiB cap.
const MAX_QUERY_LIMIT: u32 = 1000;
/// spec §6 per-client `/subscribe` connections, published in `/info`.
const MAX_SUBSCRIPTIONS_PER_IP: u32 = 4;
/// spec §7 per-client concurrency: requests in flight (what stays visible behind a proxy).
const REQUESTS_PER_CLIENT: u32 = 8;
/// Multiplier of the per-client limits for listed addresses (spec §7), e.g. a gateway.
const LISTED_FACTOR: u32 = 16;
/// `PUT` bytes per second and burst per client, apart from the request rate: 50 maximum-size
/// `PUT`s per second filled the 8 GiB quota in 43 minutes; at 32 KiB/s it takes 3 days.
const PUT_BYTES_PER_SEC: f64 = 32_768.0;
const PUT_BYTES_BURST: f64 = 4_194_304.0;
/// The same budget per IPv6 /48 ([`ClientKey::wide`]), this many times one client's: ISPs
/// that assign /56s put up to 256 customers in one /48.
const WIDE: f64 = 8.0;

impl Config {
    /// Defaults with the store in `data_dir`.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            min_pow_difficulty: 16,
            max_store_bytes: 8 << 30,
            client_ip_header: None,
            listed: HashSet::new(),
            body_timeout: Duration::from_secs(10),
            rate_per_sec: 50.0,
            rate_burst: 200.0,
            max_requests: 256,
            max_subscriptions: 256,
            live_queue: 128,
            idle_timeout: Duration::from_secs(60),
            max_age: Duration::from_secs(3600),
            deny_reload: Duration::from_secs(2),
        }
    }

    /// Reads `SBTP_DATA_DIR`, `SBTP_MIN_POW_DIFFICULTY`, `SBTP_MAX_STORE_BYTES`,
    /// `SBTP_CLIENT_IP_HEADER` and `SBTP_LISTED_ADDRESSES` (comma-separated IP addresses).
    ///
    /// # Errors
    ///
    /// The name of a variable that does not parse.
    pub fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let data_dir = var("SBTP_DATA_DIR").unwrap_or_else(|| "data".into());
        let mut config = Self::new(data_dir.into());
        if let Some(v) = var("SBTP_MIN_POW_DIFFICULTY") {
            let d = v.parse().ok().filter(|d| *d <= 256);
            config.min_pow_difficulty = d.ok_or("SBTP_MIN_POW_DIFFICULTY")?;
        }
        if let Some(v) = var("SBTP_MAX_STORE_BYTES") {
            config.max_store_bytes = v.parse().map_err(|_| "SBTP_MAX_STORE_BYTES")?;
        }
        if let Some(v) = var("SBTP_CLIENT_IP_HEADER") {
            config.client_ip_header = Some(v.parse().map_err(|_| "SBTP_CLIENT_IP_HEADER")?);
        }
        for a in var("SBTP_LISTED_ADDRESSES")
            .unwrap_or_default()
            .split_terminator(',')
        {
            let ip: IpAddr = a.trim().parse().map_err(|_| "SBTP_LISTED_ADDRESSES")?;
            config.listed.insert(ip.into());
        }
        Ok(config)
    }
}

/// A newly stored block, as sent to live subscribers.
#[derive(Clone)]
struct Live {
    position: u64,
    id: [u8; 32],
    /// `position ‖ block` (spec §6).
    frame: axum::body::Bytes,
}

/// Shared relay state.
struct Relay {
    config: Config,
    store: store::Store,
    live: broadcast::Sender<Live>,
    rate: RateLimiter,
    put_bytes: RateLimiter,
    put_bytes_wide: RateLimiter,
    requests: Counter,
    request_slots: Semaphore,
    subscriptions: Counter,
    subscription_slots: Arc<Semaphore>,
    stop: watch::Receiver<bool>,
}

impl Relay {
    /// Limit multiplier of a client: listed addresses get more (spec §7).
    fn factor(&self, key: ClientKey) -> u32 {
        self.config.listed.get(&key).map_or(1, |_| LISTED_FACTOR)
    }
}

/// Opens the store and serves `listener` until `shutdown` completes.
///
/// # Errors
///
/// The deny list exists but cannot be read or parsed (starting without it would serve every
/// denied block again), the store cannot be opened, or the listener fails.
pub async fn run(
    listener: TcpListener,
    config: Config,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let deny_path = config.data_dir.join("deny.txt");
    let deny = DenyList::load(&deny_path).map_err(|e| format!("deny.txt: {e}"))?;
    let store = store::Store::open(&config.data_dir, deny)?;
    // Without the header behind a proxy, every client shares one set of limits; with it on a
    // public address, any client can claim any address. Both go unnoticed otherwise.
    let header = config.client_ip_header.is_some();
    if header != listener.local_addr()?.ip().is_loopback() {
        let why = "client addresses unreliable: SBTP_CLIENT_IP_HEADER with a public listener, \
                   or a loopback listener without it (deploy/README.md)";
        tracing::warn!(header, why);
    }
    let (stop_tx, stop) = watch::channel(false);
    let relay = Arc::new(Relay {
        store,
        live: broadcast::channel(config.live_queue.max(1)).0,
        rate: RateLimiter::new(config.rate_per_sec, config.rate_burst),
        put_bytes: RateLimiter::new(PUT_BYTES_PER_SEC, PUT_BYTES_BURST),
        put_bytes_wide: RateLimiter::new(PUT_BYTES_PER_SEC * WIDE, PUT_BYTES_BURST * WIDE),
        requests: Counter::default(),
        request_slots: Semaphore::new(config.max_requests),
        subscriptions: Counter::default(),
        subscription_slots: Arc::new(Semaphore::new(config.max_subscriptions)),
        stop,
        config,
    });
    let (relay_id, min_pow) = (&relay.store.relay_id, relay.config.min_pow_difficulty);
    tracing::info!(relay_id, min_pow, "relay started");
    let watcher = tokio::spawn(limits::watch_deny_list(
        deny_path,
        relay.config.deny_reload,
        Arc::downgrade(&relay),
    ));
    let app = http::router(Arc::clone(&relay));
    let served = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        tracing::info!("relay stopping");
        // spec §6: subscribers are closed with `1001`.
        let _ = stop_tx.send(true);
    })
    .await;
    watcher.abort();
    // Upgraded connections are not waited for by axum: give subscribers a moment to close.
    let all = u32::try_from(relay.config.max_subscriptions).unwrap_or(u32::MAX);
    let closed = relay.subscription_slots.acquire_many(all);
    let _ = tokio::time::timeout(Duration::from_secs(1), closed).await;
    Ok(served?)
}
