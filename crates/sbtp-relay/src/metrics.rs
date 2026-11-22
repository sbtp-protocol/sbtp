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
    /// `POST /sbtp/v1/blocks` (ADR 0051).
    Blocks,
    /// Any other path (`404`).
    Other,
}

impl Route {
    /// Every route, in order.
    pub const ALL: [Self; 6] = [
        Self::Block,
        Self::BlockId,
        Self::Query,
        Self::Info,
        Self::Blocks,
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
            Self::Blocks => "/sbtp/v1/blocks",
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
            Some("/sbtp/v1/blocks") => Self::Blocks,
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
    /// A removal (the sweeper).
    Remove,
    /// A durable commit.
    Flush,
    /// A flush of the demand set, or the demand of a `PUT` answered `200` (ADR 0046 rules 12 and 14).
    Demand,
}

impl IndexOp {
    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Remove => "remove",
            Self::Flush => "flush",
            Self::Demand => "demand",
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
static REQUESTS: [[AtomicU64; 3]; Route::ALL.len()] = [const { zeros() }; Route::ALL.len()];
/// `http_refused_total{status, reason}`.
static REFUSED: [AtomicU64; Refused::ALL.len()] = zeros();
/// `accept_errors_total{class}`.
static ACCEPT_ERRORS: [AtomicU64; 2] = zeros();
/// `index_write_errors_total{op}`.
static INDEX_WRITE_ERRORS: [AtomicU64; 4] = zeros();
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
/// `sweeps_total`, `sweep_removed_blocks_total`, `sweep_duration_ms_total` (ADR 0021 rule 41).
static SWEEPS: AtomicU64 = AtomicU64::new(0);
static SWEEP_REMOVED: AtomicU64 = AtomicU64::new(0);
static SWEEP_DURATION_MS: AtomicU64 = AtomicU64::new(0);
/// `sweep_last_duration_ms` gauge.
static SWEEP_LAST_DURATION_MS: AtomicU64 = AtomicU64::new(0);
/// `sweep_failures_total`: runs that stopped on an error (`sweep_failed`, or `index_write_failed`
/// with `op=remove`). Not in the table of rule 41, added so that a failing sweeper shows in the
/// counters, not only in throttled lines.
static SWEEP_FAILURES: AtomicU64 = AtomicU64::new(0);
/// ADR 0046 rule 29: demand eviction counters and gauges.
static DEMAND_EVICTED_BLOCKS: AtomicU64 = AtomicU64::new(0);
static DEMAND_EVICTED_BYTES: AtomicU64 = AtomicU64::new(0);
static DEMAND_RUNS: AtomicU64 = AtomicU64::new(0);
static DEMAND_STUCK: AtomicU64 = AtomicU64::new(0);
static DEMAND_FLUSHES: AtomicU64 = AtomicU64::new(0);
static DEMAND_FLUSH_UPDATES: AtomicU64 = AtomicU64::new(0);
static DEMAND_LOST: AtomicU64 = AtomicU64::new(0);
static DEMAND_SUSPENDED: AtomicU64 = AtomicU64::new(0);
static DEMAND_TOUCH_ENTRIES: AtomicU64 = AtomicU64::new(0);
static DEMAND_COLDEST_MS: AtomicU64 = AtomicU64::new(0);
/// `block_not_modified_total`: `304` answers of `/block`.
static BLOCK_NOT_MODIFIED: AtomicU64 = AtomicU64::new(0);

// ADR 0049 rule 16.
static INGEST_BYTES: AtomicU64 = AtomicU64::new(0);
static INGEST_CAPPED: AtomicU64 = AtomicU64::new(0);
static INGEST_GROUP_LIMITED: [AtomicU64; 3] = zeros();
static INGEST_GROUP_UNCHECKED: AtomicU64 = AtomicU64::new(0);
static INGEST_CAP_ACTIVE: AtomicU64 = AtomicU64::new(0);
static INGEST_BUCKET_BYTES: AtomicU64 = AtomicU64::new(0);
static INGEST_GROUP_ENTRIES: AtomicU64 = AtomicU64::new(0);
// HOOK(1c-b): `storage_full_total` reasons `disk`, `inodes`, `read_only`; `store_max_bytes`,
// `disk_free_bytes`, `disk_state`, `build_info`; `log_lines_total{level}` and
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

/// Counts one sweeper run that removed `removed` index entries in `duration_ms`.
pub fn sweep_done(removed: u64, duration_ms: u64) {
    SWEEPS.fetch_add(1, Relaxed);
    SWEEP_REMOVED.fetch_add(removed, Relaxed);
    SWEEP_DURATION_MS.fetch_add(duration_ms, Relaxed);
    SWEEP_LAST_DURATION_MS.store(duration_ms, Relaxed);
}

/// Counts a sweeper run that stopped on an error.
pub fn sweep_failed() {
    SWEEP_FAILURES.fetch_add(1, Relaxed);
}

/// `(sweeps_total, sweep_removed_blocks_total, sweep_failures_total)` since start-up.
#[must_use]
pub fn sweep_totals() -> (u64, u64, u64) {
    (
        SWEEPS.load(Relaxed),
        SWEEP_REMOVED.load(Relaxed),
        SWEEP_FAILURES.load(Relaxed),
    )
}

/// Counts one demand eviction run that deleted `blocks` blocks of `bytes` bytes (ADR 0046 rule
/// 29).
pub fn demand_run(blocks: u64, bytes: u64) {
    DEMAND_RUNS.fetch_add(1, Relaxed);
    DEMAND_EVICTED_BLOCKS.fetch_add(blocks, Relaxed);
    DEMAND_EVICTED_BYTES.fetch_add(bytes, Relaxed);
}

/// Counts a demand eviction run that found no candidate above the low-water mark.
pub fn demand_stuck() {
    DEMAND_STUCK.fetch_add(1, Relaxed);
}

/// Counts one flush of the demand set that updated `updates` index entries.
pub fn demand_flush(updates: u64) {
    DEMAND_FLUSHES.fetch_add(1, Relaxed);
    DEMAND_FLUSH_UPDATES.fetch_add(updates, Relaxed);
}

/// Counts `n` lost demands (ADR 0046 rule 13).
pub fn demand_lost(n: u64) {
    DEMAND_LOST.fetch_add(n, Relaxed);
}

/// Sets the `demand_suspended` gauge.
pub fn set_demand_suspended(on: bool) {
    DEMAND_SUSPENDED.store(u64::from(on), Relaxed);
}

/// Sets the `demand_touch_entries` gauge.
pub fn set_demand_touch_entries(n: u64) {
    DEMAND_TOUCH_ENTRIES.store(n, Relaxed);
}

/// Sets the `demand_coldest_ms` gauge (0 when there is no block).
pub fn set_demand_coldest_ms(ms: u64) {
    DEMAND_COLDEST_MS.store(ms, Relaxed);
}

/// Counts a `304` of `/block`.
pub fn block_not_modified() {
    BLOCK_NOT_MODIFIED.fetch_add(1, Relaxed);
}

/// Why the body of a batch (`POST /sbtp/v1/blocks`, ADR 0051 rule 3) ended before its last
/// record: the `reason` label of `batch_cut_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchEnd {
    /// The next record would bring the body above 1,048,576 bytes (rule 4).
    Ceiling,
    /// The time budget of the response was spent.
    Budget,
    /// The block read queue refused the next record.
    Busy,
    /// The next record could not be read (an I/O error).
    Failed,
}

impl BatchEnd {
    const ALL: [Self; 4] = [Self::Ceiling, Self::Budget, Self::Busy, Self::Failed];

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Ceiling => "ceiling",
            Self::Budget => "budget",
            Self::Busy => "busy",
            Self::Failed => "failed",
        }
    }
}

/// `batch_requests_total`: batches answered `200`.
static BATCH_REQUESTS: AtomicU64 = AtomicU64::new(0);
/// `batch_records_total{result}`: `served`, `missing`.
static BATCH_RECORDS: [AtomicU64; 2] = zeros();
/// `batch_cut_total{reason}`.
static BATCH_CUT: [AtomicU64; BatchEnd::ALL.len()] = zeros();

/// Counts a batch whose identifiers were accepted.
pub fn batch_request() {
    BATCH_REQUESTS.fetch_add(1, Relaxed);
}

/// Counts one record of a batch: a block (`served`) or `length = 0` (`missing`).
pub fn batch_record(served: bool) {
    if let Some(n) = BATCH_RECORDS.get(usize::from(!served)) {
        n.fetch_add(1, Relaxed);
    }
}

/// Counts a batch body ended early (rule 3).
pub fn batch_end(why: BatchEnd) {
    if let Some(n) = BATCH_CUT.get(why as usize) {
        n.fetch_add(1, Relaxed);
    }
}

/// The batch counters, by name (tests, `/metrics` later).
#[must_use]
pub fn batch_snapshot() -> Vec<(String, u64)> {
    let mut out = vec![
        (
            "batch_requests_total".to_owned(),
            BATCH_REQUESTS.load(Relaxed),
        ),
        (
            "batch_records_total{result=\"served\"}".to_owned(),
            BATCH_RECORDS.first().map_or(0, |n| n.load(Relaxed)),
        ),
        (
            "batch_records_total{result=\"missing\"}".to_owned(),
            BATCH_RECORDS.get(1).map_or(0, |n| n.load(Relaxed)),
        ),
    ];
    for e in BatchEnd::ALL {
        out.push((
            format!("batch_cut_total{{reason=\"{}\"}}", e.name()),
            BATCH_CUT.get(e as usize).map_or(0, |n| n.load(Relaxed)),
        ));
    }
    out
}

/// The demand counters and gauges, by their ADR 0046 rule 29 names (tests, `/metrics` later).
#[must_use]
pub fn demand_snapshot() -> [(&'static str, u64); 11] {
    [
        (
            "demand_evicted_blocks_total",
            DEMAND_EVICTED_BLOCKS.load(Relaxed),
        ),
        (
            "demand_evicted_bytes_total",
            DEMAND_EVICTED_BYTES.load(Relaxed),
        ),
        ("demand_runs_total", DEMAND_RUNS.load(Relaxed)),
        ("demand_stuck_total", DEMAND_STUCK.load(Relaxed)),
        ("demand_flushes_total", DEMAND_FLUSHES.load(Relaxed)),
        (
            "demand_flush_updates_total",
            DEMAND_FLUSH_UPDATES.load(Relaxed),
        ),
        ("demand_lost_total", DEMAND_LOST.load(Relaxed)),
        ("demand_suspended", DEMAND_SUSPENDED.load(Relaxed)),
        ("demand_touch_entries", DEMAND_TOUCH_ENTRIES.load(Relaxed)),
        ("demand_coldest_ms", DEMAND_COLDEST_MS.load(Relaxed)),
        ("block_not_modified_total", BLOCK_NOT_MODIFIED.load(Relaxed)),
    ]
}

/// Counts `bytes` charged to the global bucket of ADR 0049 rule 6, and sets the
/// `ingest_bucket_bytes` gauge to `level` (0 at or below zero).
pub fn ingest_bytes(bytes: u64, level: u64) {
    INGEST_BYTES.fetch_add(bytes, Relaxed);
    INGEST_BUCKET_BYTES.store(level, Relaxed);
}

/// Counts a `503` of the global cap (ADR 0049 rule 6).
pub fn ingest_capped() {
    INGEST_CAPPED.fetch_add(1, Relaxed);
}

/// Counts a `429` of a group budget (ADR 0049 rule 4).
pub fn ingest_group_limited(level: crate::ingest::GroupLevel) {
    let i = crate::ingest::GroupLevel::ALL
        .iter()
        .position(|l| *l == level)
        .unwrap_or(0);
    if let Some(n) = INGEST_GROUP_LIMITED.get(i) {
        n.fetch_add(1, Relaxed);
    }
}

/// Counts a `PUT` with a group not checked because the group table is full (ADR 0049 rule 5).
pub fn ingest_group_unchecked() {
    INGEST_GROUP_UNCHECKED.fetch_add(1, Relaxed);
}

/// Sets the `ingest_cap_active` and `ingest_bucket_bytes` gauges.
pub fn set_ingest_cap(active: bool, level: u64) {
    INGEST_CAP_ACTIVE.store(u64::from(active), Relaxed);
    INGEST_BUCKET_BYTES.store(level, Relaxed);
}

/// Sets the `ingest_group_entries` gauge.
pub fn set_ingest_group_entries(n: u64) {
    INGEST_GROUP_ENTRIES.store(n, Relaxed);
}

/// The ingest counters and gauges, by their ADR 0049 rule 16 names (tests, `/metrics` later).
/// `ingest_group_limited_total` is one series per `level`, in the order of
/// [`crate::ingest::GroupLevel::ALL`].
#[must_use]
pub fn ingest_snapshot() -> [(&'static str, u64); 9] {
    let [l56, l48, l24] = &INGEST_GROUP_LIMITED;
    [
        ("ingest_bytes_total", INGEST_BYTES.load(Relaxed)),
        ("ingest_capped_total", INGEST_CAPPED.load(Relaxed)),
        (
            "ingest_group_limited_total{level=\"v6_56\"}",
            l56.load(Relaxed),
        ),
        (
            "ingest_group_limited_total{level=\"v6_48\"}",
            l48.load(Relaxed),
        ),
        (
            "ingest_group_limited_total{level=\"v4_24\"}",
            l24.load(Relaxed),
        ),
        (
            "ingest_group_unchecked_total",
            INGEST_GROUP_UNCHECKED.load(Relaxed),
        ),
        ("ingest_cap_active", INGEST_CAP_ACTIVE.load(Relaxed)),
        ("ingest_bucket_bytes", INGEST_BUCKET_BYTES.load(Relaxed)),
        ("ingest_group_entries", INGEST_GROUP_ENTRIES.load(Relaxed)),
    ]
}

/// The `route` label of `denied_total` (ADR 0052 rule 20).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyRoute {
    /// `PUT /sbtp/v1/block`.
    Put,
    /// `GET` or `HEAD /sbtp/v1/block/{id}`.
    Get,
    /// A record of `POST /sbtp/v1/blocks`.
    Batch,
    /// An identifier left out of a `/query` page.
    Query,
    /// A block replication skipped or discarded (ADR 0048).
    Replication,
    /// A read-through fetch (ADR 0050 rules 15 to 19).
    Fallback,
    /// A block the archive copy did not upload (ADR 0050).
    Mirror,
}

impl DenyRoute {
    /// Every route, in label order.
    pub const ALL: [Self; 7] = [
        Self::Put,
        Self::Get,
        Self::Batch,
        Self::Query,
        Self::Replication,
        Self::Fallback,
        Self::Mirror,
    ];

    /// The label value.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Put => "put",
            Self::Get => "get",
            Self::Batch => "batch",
            Self::Query => "query",
            Self::Replication => "replication",
            Self::Fallback => "fallback",
            Self::Mirror => "mirror",
        }
    }
}

/// `denied_total{route, match}`: `route` major, `match` (`block`, `key`) minor.
static DENIED: [AtomicU64; 14] = zeros();
/// `deny_entries{kind}`: `block`, `key`.
static DENY_ENTRIES: [AtomicU64; 2] = zeros();
/// `deny_marking_pending`.
static DENY_MARKING_PENDING: AtomicU64 = AtomicU64::new(0);

/// Counts `n` denied blocks on `route` (ADR 0052 rule 20); `key` is a match by public key.
/// Never a client tag, never a `block_id`.
pub fn denied(route: DenyRoute, key: bool, n: u64) {
    if let Some(c) = DENIED.get(route as usize * 2 + usize::from(key)) {
        c.fetch_add(n, Relaxed);
    }
}

/// `denied_total{route, match}` since start-up.
#[must_use]
pub fn denied_total(route: DenyRoute, key: bool) -> u64 {
    DENIED
        .get(route as usize * 2 + usize::from(key))
        .map_or(0, |n| n.load(Relaxed))
}

/// Sets the `deny_entries` gauges.
pub fn set_deny_entries(blocks: u64, keys: u64) {
    let [b, k] = &DENY_ENTRIES;
    b.store(blocks, Relaxed);
    k.store(keys, Relaxed);
}

/// Sets the `deny_marking_pending` gauge.
pub fn set_deny_marking_pending(n: u64) {
    DENY_MARKING_PENDING.store(n, Relaxed);
}

/// The deny list counters and gauges, by their ADR 0052 rule 20 names (tests, `/metrics` later).
#[must_use]
pub fn deny_snapshot() -> Vec<(String, u64)> {
    let mut out = Vec::with_capacity(DENIED.len() + 3);
    for r in DenyRoute::ALL {
        for (key, m) in [(false, "block"), (true, "key")] {
            out.push((
                format!("denied_total{{route=\"{}\",match=\"{m}\"}}", r.name()),
                denied_total(r, key),
            ));
        }
    }
    let [b, k] = &DENY_ENTRIES;
    out.push(("deny_entries{kind=\"block\"}".to_owned(), b.load(Relaxed)));
    out.push(("deny_entries{kind=\"key\"}".to_owned(), k.load(Relaxed)));
    out.push((
        "deny_marking_pending".to_owned(),
        DENY_MARKING_PENDING.load(Relaxed),
    ));
    out
}

/// `demand_lost_total` since start-up.
#[must_use]
pub fn demand_lost_total() -> u64 {
    DEMAND_LOST.load(Relaxed)
}

/// `block_not_modified_total` since start-up.
#[must_use]
pub fn block_not_modified_total() -> u64 {
    BLOCK_NOT_MODIFIED.load(Relaxed)
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
    #[allow(unused_mut)] // Extended in the `object-store` build.
    let mut v = vec![
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
        ("sweeps", SWEEPS.load(Relaxed)),
        ("sweep_removed", SWEEP_REMOVED.load(Relaxed)),
        ("sweep_failures", SWEEP_FAILURES.load(Relaxed)),
        ("demand_evicted", DEMAND_EVICTED_BLOCKS.load(Relaxed)),
        ("demand_lost", DEMAND_LOST.load(Relaxed)),
        ("demand_suspended", DEMAND_SUSPENDED.load(Relaxed)),
        ("not_modified", BLOCK_NOT_MODIFIED.load(Relaxed)),
        ("ingest_capped", INGEST_CAPPED.load(Relaxed)),
        // ADR 0052 rule 20: every route and match together.
        ("denied", sum(&DENIED)),
        ("deny_marking_pending", DENY_MARKING_PENDING.load(Relaxed)),
        ("ingest_group_limited", sum(&INGEST_GROUP_LIMITED)),
        (
            "ingest_group_unchecked",
            INGEST_GROUP_UNCHECKED.load(Relaxed),
        ),
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
    ];
    // Mirror review L-4: the archive copy's counters, while it runs.
    #[cfg(feature = "object-store")]
    v.extend(crate::mirror::metrics::stats());
    v
}
