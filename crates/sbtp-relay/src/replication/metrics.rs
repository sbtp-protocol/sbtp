//! Replication counters (ADR 0048, "Metrics"; ADR 0021 rules 39 to 42). The `peer` label is the
//! position of the peer in `peers` (at most 256), never its URL; every other label comes from a
//! fixed set in this file. Fixed-size tables of atomic integers, as in [`crate::metrics`].

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// The largest `replication_max_peers`.
pub const MAX_PEERS: usize = 256;

/// The `reason` label of `replication_skipped_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// Held, not expired (rule 6), or found held at the storage step.
    Held,
    /// Fewer leading zero bits than `min_pow_difficulty`; never fetched (rule 6).
    Pow,
    /// Failed validation (rule 7).
    Invalid,
    /// `404` (rule 7).
    NotFound,
    /// Failed P1 (rule 7).
    Future,
}

impl Skip {
    /// Every reason, in label order.
    pub const ALL: [Self; 5] = [
        Self::Held,
        Self::Pow,
        Self::Invalid,
        Self::NotFound,
        Self::Future,
    ];

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Pow => "pow",
            Self::Invalid => "invalid",
            Self::NotFound => "not_found",
            Self::Future => "future",
        }
    }
}

/// The `status` label of `replication_requests_failed_total`: a status class or a fixed name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failed {
    /// A `3xx` (ADR 0030): never followed.
    Redirect,
    /// `429`.
    RateLimited,
    /// `502`, `503` or `504` (handled alike, core spec §4).
    Unavailable,
    /// Another `4xx`.
    Client,
    /// Another `5xx`, or a status outside 100 to 599.
    Server,
    /// No connection: DNS, TCP or refused addresses (rule 14).
    Connect,
    /// Every resolved address is refused by rule 14.
    Address,
    /// The TLS handshake or certificate verification failed.
    Tls,
    /// `replication_request_timeout_ms` passed.
    Timeout,
    /// A body over its ceiling (ADR 0029).
    TooLarge,
    /// A response that is not what the interface defines (ADR 0029), or a broken connection.
    Invalid,
    /// 16 invalid blocks in one round (rule 7).
    InvalidBlocks,
}

impl Failed {
    /// Every value, in label order.
    pub const ALL: [Self; 12] = [
        Self::Redirect,
        Self::RateLimited,
        Self::Unavailable,
        Self::Client,
        Self::Server,
        Self::Connect,
        Self::Address,
        Self::Tls,
        Self::Timeout,
        Self::TooLarge,
        Self::Invalid,
        Self::InvalidBlocks,
    ];

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Redirect => "3xx",
            Self::RateLimited => "429",
            Self::Unavailable => "503",
            Self::Client => "4xx",
            Self::Server => "5xx",
            Self::Connect => "connect",
            Self::Address => "address_refused",
            Self::Tls => "tls",
            Self::Timeout => "timeout",
            Self::TooLarge => "too_large",
            Self::Invalid => "invalid_response",
            Self::InvalidBlocks => "invalid_blocks",
        }
    }
}

const STORED: usize = 0;
const BYTES: usize = 1;
const RESETS: usize = 2;
const SKIPPED: usize = 3;
const FAILED: usize = SKIPPED + Skip::ALL.len();
const COUNTERS: usize = FAILED + Failed::ALL.len();

static PEERS: [[AtomicU64; COUNTERS]; MAX_PEERS] =
    [const { [const { AtomicU64::new(0) }; COUNTERS] }; MAX_PEERS];
static PAUSED: AtomicU64 = AtomicU64::new(0);

fn add(peer: usize, counter: usize, n: u64) {
    if let Some(c) = PEERS.get(peer).and_then(|p| p.get(counter)) {
        c.fetch_add(n, Relaxed);
    }
}

fn get(peer: usize, counter: usize) -> u64 {
    PEERS
        .get(peer)
        .and_then(|p| p.get(counter))
        .map_or(0, |c| c.load(Relaxed))
}

/// `replication_blocks_stored_total{peer}`.
pub fn stored(peer: usize) {
    add(peer, STORED, 1);
}

/// Counts bytes read from a peer (`replication_bytes_total`): block and `/query` bodies.
pub fn bytes(peer: usize, n: u64) {
    add(peer, BYTES, n);
}

/// `replication_skipped_total{peer,reason}`.
pub fn skipped(peer: usize, r: Skip) {
    add(peer, SKIPPED + r as usize, 1);
}

/// `replication_requests_failed_total{peer,status}`.
pub fn failed(peer: usize, f: Failed) {
    add(peer, FAILED + f as usize, 1);
}

/// `replication_cursor_resets_total{peer}`.
pub fn cursor_reset(peer: usize) {
    add(peer, RESETS, 1);
}

/// The `replication_paused` gauge.
pub fn set_paused(on: bool) {
    PAUSED.store(u64::from(on), Relaxed);
}

/// `replication_paused`.
#[must_use]
pub fn paused() -> bool {
    PAUSED.load(Relaxed) == 1
}

/// `replication_blocks_stored_total{peer}`.
#[must_use]
pub fn stored_total(peer: usize) -> u64 {
    get(peer, STORED)
}

/// `replication_bytes_total{peer}`.
#[must_use]
pub fn bytes_total(peer: usize) -> u64 {
    get(peer, BYTES)
}

/// `replication_skipped_total{peer,reason}`.
#[must_use]
pub fn skipped_total(peer: usize, r: Skip) -> u64 {
    get(peer, SKIPPED + r as usize)
}

/// `replication_requests_failed_total{peer,status}`.
#[must_use]
pub fn failed_total(peer: usize, f: Failed) -> u64 {
    get(peer, FAILED + f as usize)
}

/// `replication_cursor_resets_total{peer}`.
#[must_use]
pub fn cursor_resets_total(peer: usize) -> u64 {
    get(peer, RESETS)
}
