//! Survival guards (SPEC §7): client keys, rate limit, concurrency counters, deny list.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use sbtp_core::BlockId;

use crate::Relay;

/// spec §7: the client address of the limits. An IPv6 /64 is one address; an IPv4-mapped IPv6
/// address is its IPv4 address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientKey(IpAddr);

impl From<IpAddr> for ClientKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self(IpAddr::V4(v4)),
                None => Self(IpAddr::V6((v6.to_bits() & !u128::from(u64::MAX)).into())),
            },
            v4 @ IpAddr::V4(_) => Self(v4),
        }
    }
}

impl ClientKey {
    /// The IPv6 /48 of the aggregate `PUT` budget (IPv4 unchanged): a /48 is the largest
    /// common assignment to one site, so one allocation is one budget, not 65,536 /64 clients.
    #[must_use]
    pub fn wide(self) -> Self {
        match self.0 {
            IpAddr::V6(v6) => Self(IpAddr::V6((v6.to_bits() & !(u128::MAX >> 48)).into())),
            v4 @ IpAddr::V4(_) => Self(v4),
        }
    }
}

/// Bound on remembered clients, so that a spray of addresses cannot grow memory without limit.
const MAX_TRACKED: usize = 65_536;

/// Per-client token bucket.
pub struct RateLimiter {
    buckets: Mutex<HashMap<ClientKey, (f64, Instant)>>,
    per_sec: f64,
    burst: f64,
}

impl RateLimiter {
    /// `per_sec` tokens per second, at most `burst` saved up.
    pub fn new(per_sec: f64, burst: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            per_sec,
            burst,
        }
    }

    /// Takes `cost` tokens, rates scaled by `factor` for listed clients. `Err(seconds)` to wait
    /// otherwise.
    pub fn check(&self, key: ClientKey, factor: f64, cost: f64) -> Result<(), u64> {
        let now = Instant::now();
        let (rate, burst) = (self.per_sec * factor, self.burst * factor);
        let mut map = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= MAX_TRACKED && !map.contains_key(&key) {
            // A client idle long enough to refill its bucket is the same as a forgotten one.
            map.retain(|_, (_, at)| now.duration_since(*at).as_secs_f64() * rate < burst);
            if map.len() >= MAX_TRACKED {
                return Err(1);
            }
        }
        let (tokens, at) = map.entry(key).or_insert((burst, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * rate).min(burst);
        *at = now;
        if *tokens >= cost {
            *tokens -= cost;
            Ok(())
        } else {
            // Whole seconds until `cost` is back, at least 1 (SPEC §7: `Retry-After` in seconds).
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Err(((cost - *tokens) / rate).ceil().max(1.0) as u64)
        }
    }
}

/// Concurrent uses per client (requests, subscriptions); a guard releases one on drop.
#[derive(Default)]
pub struct Counter(Arc<Mutex<HashMap<ClientKey, u32>>>);

impl Counter {
    /// One more use by `key`, unless it already has `max`.
    pub fn acquire(&self, key: ClientKey, max: u32) -> Option<CounterGuard> {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = map.entry(key).or_insert(0);
        if *count >= max {
            return None;
        }
        *count = count.saturating_add(1);
        Some(CounterGuard(Arc::clone(&self.0), key))
    }
}

/// Releases one use on drop; the entry goes at zero, so the map holds only live clients.
pub struct CounterGuard(Arc<Mutex<HashMap<ClientKey, u32>>>, ClientKey);

impl Drop for CounterGuard {
    fn drop(&mut self) {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = map.get_mut(&self.1) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.1);
            }
        }
    }
}

/// The operator deny list (SPEC §7): lines `block <block_id>` or `key <public key hex>`; `#`
/// starts a comment.
#[derive(Default)]
pub struct DenyList {
    blocks: HashSet<[u8; 32]>,
    keys: HashSet<[u8; 32]>,
}

impl DenyList {
    /// Parses the file; any malformed line rejects the whole file, so a typo never lifts a denial.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            other => other.map_err(|e| e.to_string())?,
        };
        let mut list = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let bad = || format!("line {}: expected `block|key <hex>`", n.saturating_add(1));
            let (kind, hex) = line.split_once(char::is_whitespace).ok_or_else(bad)?;
            let bytes = hex.trim().parse::<BlockId>().map_err(|_| bad())?.0;
            match kind {
                "block" => list.blocks.insert(bytes),
                "key" => list.keys.insert(bytes),
                _ => return Err(bad()),
            };
        }
        Ok(list)
    }

    /// The SPEC §5 error name when the block `id` signed by `key` is denied.
    pub fn check(&self, id: &[u8; 32], key: &[u8; 32]) -> Option<&'static str> {
        if self.blocks.contains(id) {
            Some("Denied")
        } else {
            self.keys.contains(key).then_some("DeniedKey")
        }
    }
}

/// Reloads the deny list when the file's modification time or length changes.
pub async fn watch_deny_list(path: std::path::PathBuf, every: Duration, relay: Weak<Relay>) {
    let stamp = |p: &Path| {
        std::fs::metadata(p)
            .ok()
            .map(|m| (m.modified().ok(), m.len()))
    };
    let mut seen = stamp(&path);
    let mut tick = tokio::time::interval(every);
    loop {
        tick.tick().await;
        let now = stamp(&path);
        if now == seen {
            continue;
        }
        seen = now;
        let list = match DenyList::load(&path) {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(error = %e, "deny list rejected, previous list kept");
                continue;
            }
        };
        let Some(relay) = relay.upgrade() else { return };
        // `set_deny` scans the log back to the last served block: off the async workers.
        let done = tokio::task::spawn_blocking(move || relay.store.set_deny(list)).await;
        tracing::info!(ok = matches!(done, Ok(Ok(()))), "deny list reloaded");
    }
}
