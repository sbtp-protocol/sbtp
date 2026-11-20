//! Counters (ADR 0021 rules 39 to 42): fixed-size tables of atomic integers. Every label value
//! comes from a fixed set in this file; none holds a client key, an address, a `block_id` or
//! anything a client chose, so the number of series is fixed at build time.
//!
//! Milestone 1b keeps the counters of what exists today. The others of rule 41 are marked
//! `HOOK(1c-b)` (sweeper, disk watermark, `/metrics`).

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use axum::http::StatusCode;

/// The `route` label: a template, never the path received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// `PUT /sbtp/v1/block`.
    Block,
    /// `GET /sbtp/v1/block/{id}`.
    BlockId,
    /// `GET /sbtp/v1/query`.
    Query,
    /// `GET /sbtp/v1/info`.
    Info,
    /// Any other path (`404`).
    Other,
}

impl Route {
    /// Every route, in order.
    pub const ALL: [Self; 5] = [
        Self::Block,
        Self::BlockId,
        Self::Query,
        Self::Info,
        Self::Other,
    ];

    /// The label value.
    #[must_use]
    pub fn template(self) -> &'static str {
        match self {
            Self::Block => "/sbtp/v1/block",
            Self::BlockId => "/sbtp/v1/block/{id}",
            Self::Query => "/sbtp/v1/query",
            Self::Info => "/sbtp/v1/info",
            Self::Other => "other",
        }
    }

    /// The route of a request, from the path template axum matched (`None` for the fallback).
    #[must_use]
    pub fn of(matched: Option<&str>) -> Self {
        match matched {
            Some("/sbtp/v1/block") => Self::Block,
            Some(p) if p.starts_with("/sbtp/v1/block/") => Self::BlockId,
            Some("/sbtp/v1/query") => Self::Query,
            Some("/sbtp/v1/info") => Self::Info,
            _ => Self::Other,
        }
    }
}

/// The `status` and `reason` labels of `http_refused_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// `429`, over `max_connections_per_client` requests in flight (ADR 0019 rule 30).
    InFlight,
    /// `503`, no response within `request_timeout_ms` (ADR 0018 rule 25).
    RequestTimeout,
    /// `429`, over `put_max_in_flight_per_client` (ADR 0018 rules 18 and 29).
    PutInFlight,
    /// `503`, the `PUT` queue is full or the wait passed `queue_timeout_ms` (ADR 0018 rule 30).
    PutQueue,
    /// `503`, the block read queue is full or the wait passed `queue_timeout_ms`.
    BlockQueue,
    /// `503`, the index reader queue is full or the wait passed `queue_timeout_ms` for a
    /// `/query` page (ADR 0018 rules 12, 13 and 30), or the index writer refused an insert while
    /// the relay stops (clarification M4). A refused repair lookup of a `PUT` is not a refusal:
    /// it is counted in `index_repairs_deferred_total` (clarification M1).
    IndexQueue,
    /// `429`, the `block` token bucket is empty (ADR 0018 rules 21 and 29).
    BlockRate,
    /// `429`, the `query` token bucket is empty.
    QueryRate,
    /// `429`, the `put` token bucket is empty.
    PutRate,
}

impl Refused {
    const ALL: [Self; 9] = [
        Self::InFlight,
        Self::RequestTimeout,
        Self::PutInFlight,
        Self::PutQueue,
        Self::BlockQueue,
        Self::IndexQueue,
        Self::BlockRate,
        Self::QueryRate,
        Self::PutRate,
    ];

    /// The HTTP status.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::InFlight
            | Self::PutInFlight
            | Self::BlockRate
            | Self::QueryRate
            | Self::PutRate => 429,
            Self::RequestTimeout | Self::PutQueue | Self::BlockQueue | Self::IndexQueue => 503,
        }
    }

    /// The `reason` label, also the `class` or `reason` field of the log event.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::RequestTimeout => "request_timeout",
            Self::PutInFlight => "put_in_flight",
            Self::PutQueue => "put_queue",
            Self::BlockQueue => "block_queue",
            Self::IndexQueue => "index_queue",
            Self::BlockRate => "block",
            Self::QueryRate => "query",
            Self::PutRate => "put",
        }
    }
}

/// The `class` label of `accept_errors_total` (ADR 0020).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptClass {
    /// An error that pauses the accept loop.
    Backoff,
    /// An error of one pending connection.
    Transient,
}

impl AcceptClass {
    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Backoff => "backoff",
            Self::Transient => "transient",
        }
    }
}

/// The `op` label of `index_write_errors_total` (ADR 0021 rule 37).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexOp {
    /// An insert (the `PUT` handler and the reconciliation).
    Insert,
    /// A removal (HOOK(1c-b): the sweeper).
    Remove,
    /// A durable commit.
    Flush,
}

impl IndexOp {
    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Remove => "remove",
            Self::Flush => "flush",
        }
    }
}

/// The `op` label of `index_read_errors_total` and of the event `index_read_failed` (ADR 0021
/// clarifications X1 and X3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexReadOp {
    /// The page of `/query`.
    Query,
}

impl IndexReadOp {
    /// The number of operations.
    pub const COUNT: usize = 1;

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Query => "query",
        }
    }
}

/// The `op` label of `store_errors_total`: the step of a block-store operation that failed for
/// a cause other than space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreOp {
    /// Reading a stored file.
    Read,
    /// Writing a new file: temporary file, shard directory, link.
    Write,
    /// `fsync` of the shard directory after the link (the file is left as an orphan).
    Sync,
    /// Moving a damaged file to the quarantine area (ADR 0023 rules 7 and 14).
    Quarantine,
    /// Deleting a quarantined file (ADR 0023 rules 6 and 14).
    Purge,
}

impl StoreOp {
    /// The number of operations.
    pub const COUNT: usize = 5;

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Sync => "sync",
            Self::Quarantine => "quarantine",
            Self::Purge => "purge",
        }
    }
}

const fn zeros<const N: usize>() -> [AtomicU64; N] {
    [const { AtomicU64::new(0) }; N]
}

/// `http_requests_total{route, class}`; classes `2xx`, `4xx`, `5xx`.
static REQUESTS: [[AtomicU64; 3]; 5] = [const { zeros() }; 5];
/// `http_refused_total{status, reason}`.
static REFUSED: [AtomicU64; Refused::ALL.len()] = zeros();
/// `accept_errors_total{class}`.
static ACCEPT_ERRORS: [AtomicU64; 2] = zeros();
/// `index_write_errors_total{op}`.
static INDEX_WRITE_ERRORS: [AtomicU64; 3] = zeros();
/// `index_read_errors_total{op}` (ADR 0021 clarification X3).
static INDEX_READ_ERRORS: [AtomicU64; IndexReadOp::COUNT] = zeros();
/// `store_errors_total{op}`.
static STORE_ERRORS: [AtomicU64; StoreOp::COUNT] = zeros();
/// `panics_total`.
static PANICS: AtomicU64 = AtomicU64::new(0);
/// `connections_open`.
static CONNECTIONS_OPEN: AtomicU64 = AtomicU64::new(0);
/// Connections closed at accept for `max_connections_per_client` (ADR 0019 rule 29).
static CONNECTIONS_REFUSED: AtomicU64 = AtomicU64::new(0);
/// `blocks_accepted_total{result}`.
static ACCEPTED: [AtomicU64; 2] = zeros();
/// `blocks_rejected_total{error}`, one slot per name of [`REJECTIONS`].
static REJECTED: [AtomicU64; REJECTIONS.len()] = zeros();
/// `storage_full_total{reason}`, one slot per [`StorageFull`].
static STORAGE_FULL: [AtomicU64; 3] = zeros();
/// `store_bytes` and `index_bytes` gauges, set by the store.
static STORE_BYTES: AtomicU64 = AtomicU64::new(0);
static INDEX_BYTES: AtomicU64 = AtomicU64::new(0);
/// `store_quarantined_total{reason}`, one slot per [`Damage`] (ADR 0023 rule 14).
static STORE_QUARANTINED: [AtomicU64; 3] = zeros();
/// `store_replaced_total` (ADR 0023 rule 14).
static STORE_REPLACED: AtomicU64 = AtomicU64::new(0);
/// `index_repairs_deferred_total` (ADR 0018 clarification M1, ADR 0021 clarification X5).
static INDEX_REPAIRS_DEFERRED: AtomicU64 = AtomicU64::new(0);
/// `quarantine_files` gauge (ADR 0023 rule 14), set by the store.
static QUARANTINE_FILES: AtomicU64 = AtomicU64::new(0);
// HOOK(1c-b): `storage_full_total` reasons `disk`, `inodes`, `read_only`; `sweeps_total`, `sweep_removed_blocks_total`,
// `sweep_duration_ms_total`, `sweep_last_duration_ms`, `index_bytes`, `store_bytes`,
// `store_max_bytes`, `disk_free_bytes`, `disk_state`, `build_info`; `log_lines_total{level}` and
// `log_lines_dropped_total{event, cause}` (kept by the logger, `log::Logger::dropped`).

/// The `error` label values of `blocks_rejected_total`: the block rejection names of ADR 0012
/// rule 17, in its order.
pub const REJECTIONS: [&str; 12] = [
    "TooShort",
    "TooLong",
    "BadMagic",
    "UnsupportedVersion",
    "TooManyParents",
    "Truncated",
    "TrailingBytes",
    "DuplicateParent",
    "TimestampTooFarInFuture",
    "InsufficientPow",
    "InvalidPublicKey",
    "InvalidSignature",
];

/// The `result` label of `blocks_accepted_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// `201`.
    New,
    /// `200`.
    Known,
}

/// The `reason` label of `storage_full_total` (ADR 0021 rule 7) that milestone 1b produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageFull {
    /// `max_store_bytes` reached.
    Quota,
    /// The operating system reported no space (`ENOSPC`).
    Enospc,
    /// A file-system quota was reached (`EDQUOT`, security review L-1).
    Edquot,
}

impl StorageFull {
    /// The label value, also the `reason` field of `storage_full`.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Quota => "quota",
            Self::Enospc => "enospc",
            Self::Edquot => "edquot",
        }
    }
}

/// Counts an accepted block.
pub fn accepted(a: Accepted) {
    if let Some(n) = ACCEPTED.get(a as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// Counts a rejected block by its error name; a name outside [`REJECTIONS`] is not counted.
pub fn rejected(name: &str) {
    if let Some(n) = REJECTIONS
        .iter()
        .position(|r| *r == name)
        .and_then(|i| REJECTED.get(i))
    {
        n.fetch_add(1, Relaxed);
    }
}

/// Rejections with `name` since start-up.
#[must_use]
pub fn rejected_total(name: &str) -> u64 {
    REJECTIONS
        .iter()
        .position(|r| *r == name)
        .and_then(|i| REJECTED.get(i))
        .map_or(0, |n| n.load(Relaxed))
}

/// Accepted blocks with `a` since start-up.
#[must_use]
pub fn accepted_total(a: Accepted) -> u64 {
    ACCEPTED.get(a as usize).map_or(0, |n| n.load(Relaxed))
}

/// Counts a `507`.
pub fn storage_full(r: StorageFull) {
    if let Some(n) = STORAGE_FULL.get(r as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// `507`s with `r` since start-up.
#[must_use]
pub fn storage_full_total(r: StorageFull) -> u64 {
    STORAGE_FULL.get(r as usize).map_or(0, |n| n.load(Relaxed))
}

/// Sets the `store_bytes` and `index_bytes` gauges.
pub fn set_store_bytes(store: u64, index: u64) {
    STORE_BYTES.store(store, Relaxed);
    INDEX_BYTES.store(index, Relaxed);
}

/// Why a stored file failed full validation (ADR 0023 rules 1 and 14): the `reason` label of
/// `store_quarantined_total` and the `reason` field of `block_quarantined`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Damage {
    /// F1 to F9 (spec §2.2).
    Parse,
    /// R1 against the file name.
    Id,
    /// C2 or C3.
    Signature,
}

impl Damage {
    /// Every reason, in label order.
    pub const ALL: [Self; 3] = [Self::Parse, Self::Id, Self::Signature];

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Id => "id",
            Self::Signature => "signature",
        }
    }
}

/// Counts a file moved to quarantine (files moved, not requests: ADR 0023 rule 14).
pub fn store_quarantined(d: Damage) {
    if let Some(n) = STORE_QUARANTINED.get(d as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// Files moved to quarantine for `d` since start-up.
#[must_use]
pub fn store_quarantined_total(d: Damage) -> u64 {
    STORE_QUARANTINED
        .get(d as usize)
        .map_or(0, |n| n.load(Relaxed))
}

/// Counts a `PUT` of a held block whose repair lookup the index reader queue refused, answered
/// `200` without repair (ADR 0018 clarification M1, ADR 0021 clarification X5).
pub fn index_repair_deferred() {
    INDEX_REPAIRS_DEFERRED.fetch_add(1, Relaxed);
}

/// `index_repairs_deferred_total` since start-up.
#[must_use]
pub fn index_repairs_deferred_total() -> u64 {
    INDEX_REPAIRS_DEFERRED.load(Relaxed)
}

/// Counts a damaged file replaced by a `PUT` (ADR 0023 rules 8 and 14).
pub fn store_replaced() {
    STORE_REPLACED.fetch_add(1, Relaxed);
}

/// Damaged files replaced since start-up.
#[must_use]
pub fn store_replaced_total() -> u64 {
    STORE_REPLACED.load(Relaxed)
}

/// Sets the `quarantine_files` gauge.
pub fn set_quarantine_files(n: u64) {
    QUARANTINE_FILES.store(n, Relaxed);
}

/// The `quarantine_files` gauge.
#[must_use]
pub fn quarantine_files() -> u64 {
    QUARANTINE_FILES.load(Relaxed)
}

/// Counts the response of a request on `route` with `status`. Statuses outside `2xx`, `4xx` and
/// `5xx` are not counted: the only other one the relay sends is the `304` of a conditional
/// `GET /block`, and the classes of ADR 0021 rule 41 have no `3xx`.
pub fn request(route: Route, status: StatusCode) {
    let class = match status.as_u16() {
        200..=299 => 0,
        400..=499 => 1,
        500..=599 => 2,
        _ => return,
    };
    if let Some(n) = REQUESTS.get(route as usize).and_then(|r| r.get(class)) {
        n.fetch_add(1, Relaxed);
    }
}

/// Counts a refusal.
pub fn refused(r: Refused) {
    if let Some(n) = REFUSED.get(r as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// Counts a failed `accept`.
pub fn accept_error(c: AcceptClass) {
    if let Some(n) = ACCEPT_ERRORS.get(c as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// Counts a failed index write.
pub fn index_write_error(op: IndexOp) {
    if let Some(n) = INDEX_WRITE_ERRORS.get(op as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// Counts a failed index read that a request needed, logged or suppressed (ADR 0021
/// clarification X3).
pub fn index_read_error(op: IndexReadOp) {
    if let Some(n) = INDEX_READ_ERRORS.get(op as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// Failed index reads `op` since start-up.
#[must_use]
pub fn index_read_errors_total(op: IndexReadOp) -> u64 {
    INDEX_READ_ERRORS
        .get(op as usize)
        .map_or(0, |n| n.load(Relaxed))
}

/// Counts a failed block-store operation.
pub fn store_error(op: StoreOp) {
    if let Some(n) = STORE_ERRORS.get(op as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// Failed block-store operations `op` since start-up.
#[must_use]
pub fn store_errors_total(op: StoreOp) -> u64 {
    STORE_ERRORS.get(op as usize).map_or(0, |n| n.load(Relaxed))
}

/// Counts a panic: once, by the `500` path for a caught request panic, by the panic hook for
/// any other.
pub fn panicked() {
    PANICS.fetch_add(1, Relaxed);
}

/// Panics since start-up.
#[must_use]
pub fn panics() -> u64 {
    PANICS.load(Relaxed)
}

/// Counts a connection closed at accept for the per-client bound.
pub fn connection_refused() {
    CONNECTIONS_REFUSED.fetch_add(1, Relaxed);
}

/// One open connection, counted in `connections_open` until it is dropped. Owned by the
/// connection task, so that every way out of the task releases it.
#[derive(Debug)]
pub struct OpenConnection(());

impl OpenConnection {
    /// Counts one more open connection.
    #[must_use]
    pub fn new() -> Self {
        CONNECTIONS_OPEN.fetch_add(1, Relaxed);
        Self(())
    }
}

impl Default for OpenConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        CONNECTIONS_OPEN.fetch_sub(1, Relaxed);
    }
}

/// Refusals for `r` since start-up.
#[must_use]
pub fn refused_total(r: Refused) -> u64 {
    REFUSED.get(r as usize).map_or(0, |n| n.load(Relaxed))
}

/// The counters of the `stats` line (rule 42), totals since start-up, in a fixed order. The
/// logger appends `log_dropped`.
#[must_use]
pub fn snapshot() -> Vec<(&'static str, u64)> {
    let sum = |a: &[AtomicU64]| {
        a.iter()
            .map(|n| n.load(Relaxed))
            .fold(0, u64::saturating_add)
    };
    let class = |c: usize| {
        REQUESTS
            .iter()
            .filter_map(|r| r.get(c))
            .map(|n| n.load(Relaxed))
            .fold(0, u64::saturating_add)
    };
    let status = |s: u16| {
        Refused::ALL
            .iter()
            .filter(|r| r.status() == s)
            .map(|r| refused_total(*r))
            .fold(0, u64::saturating_add)
    };
    vec![
        ("requests_2xx", class(0)),
        ("requests_4xx", class(1)),
        ("requests_5xx", class(2)),
        ("refused_429", status(429)),
        ("refused_503", status(503)),
        ("refused_507", sum(&STORAGE_FULL)),
        ("blocks_new", accepted_total(Accepted::New)),
        ("blocks_known", accepted_total(Accepted::Known)),
        ("blocks_rejected", sum(&REJECTED)),
        ("store_bytes", STORE_BYTES.load(Relaxed)),
        ("index_bytes", INDEX_BYTES.load(Relaxed)),
        ("store_quarantined", sum(&STORE_QUARANTINED)),
        ("store_replaced", STORE_REPLACED.load(Relaxed)),
        ("quarantine_files", QUARANTINE_FILES.load(Relaxed)),
        // HOOK(1c-b): `disk_free_bytes`, `disk_state`.
        ("accept_errors", sum(&ACCEPT_ERRORS)),
        ("index_write_errors", sum(&INDEX_WRITE_ERRORS)),
        ("index_read_errors", sum(&INDEX_READ_ERRORS)),
        (
            "index_repairs_deferred",
            INDEX_REPAIRS_DEFERRED.load(Relaxed),
        ),
        ("store_errors", sum(&STORE_ERRORS)),
        ("panics", PANICS.load(Relaxed)),
        ("connections_open", CONNECTIONS_OPEN.load(Relaxed)),
        ("connections_refused", CONNECTIONS_REFUSED.load(Relaxed)),
    ]
}
