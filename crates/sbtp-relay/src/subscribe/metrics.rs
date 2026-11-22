//! The counters of ADR 0054 rule 38, labels from fixed sets only. Until `/metrics` exists they
//! are on the `stats` line, while the function is on.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

use super::proto::Filter;

/// The `cause` label of `ws_gaps_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GapCause {
    /// The connection's send queue was full (rule 18).
    Queue,
    /// The fan-out queue was full (rule 34).
    Fanout,
}

/// The `code` label values of `ws_closed_total`, in order.
pub const CLOSE_CODES: [&str; 9] = [
    "1000", "1001", "1002", "1003", "1007", "1008", "1009", "1011", "none",
];

static ON: AtomicBool = AtomicBool::new(false);
static CONNECTIONS_OPEN: AtomicU64 = AtomicU64::new(0);
static SUBS_PARENTS: AtomicU64 = AtomicU64::new(0);
static SUBS_ALL: AtomicU64 = AtomicU64::new(0);
static FRAMES_SENT: AtomicU64 = AtomicU64::new(0);
static ENTRIES_SENT: AtomicU64 = AtomicU64::new(0);
static ENTRIES_QUEUED: AtomicU64 = AtomicU64::new(0);
static GAPS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static CLOSED: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];

pub(super) fn set_on() {
    ON.store(true, Relaxed);
}

pub(super) fn subscription_opened(f: &Filter) {
    subs(f).fetch_add(1, Relaxed);
}

pub(super) fn subscription_closed(f: &Filter) {
    subs(f).fetch_sub(1, Relaxed);
}

fn subs(f: &Filter) -> &'static AtomicU64 {
    match f {
        Filter::Parents(_) => &SUBS_PARENTS,
        Filter::All => &SUBS_ALL,
    }
}

pub(super) fn gap(cause: GapCause) {
    gaps(cause, 1);
}

pub(super) fn gaps(cause: GapCause, n: u64) {
    if let Some(c) = GAPS.get(cause as usize) {
        c.fetch_add(n, Relaxed);
    }
}

pub(super) fn queued(entries: u64) {
    ENTRIES_QUEUED.fetch_add(entries, Relaxed);
}

pub(super) fn sent(frames: u64, entries: u64) {
    FRAMES_SENT.fetch_add(frames, Relaxed);
    ENTRIES_SENT.fetch_add(entries, Relaxed);
}

pub(super) fn closed(code: Option<u16>) {
    let label = code.map(|c| c.to_string());
    let i = CLOSE_CODES
        .iter()
        .position(|c| Some(*c) == label.as_deref())
        .unwrap_or(CLOSE_CODES.len() - 1);
    if let Some(n) = CLOSED.get(i) {
        n.fetch_add(1, Relaxed);
    }
}

/// An open subscription connection, counted in `ws_connections_open` while it lives.
#[derive(Debug)]
pub(super) struct Open(());

impl Open {
    pub(super) fn new() -> Self {
        CONNECTIONS_OPEN.fetch_add(1, Relaxed);
        Self(())
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        CONNECTIONS_OPEN.fetch_sub(1, Relaxed);
    }
}

/// `ws_connections_open`.
#[must_use]
pub fn connections_open() -> u64 {
    CONNECTIONS_OPEN.load(Relaxed)
}

/// `ws_subscriptions_open{kind}`: (`parents`, `all`).
#[must_use]
pub fn subscriptions_open() -> (u64, u64) {
    (SUBS_PARENTS.load(Relaxed), SUBS_ALL.load(Relaxed))
}

/// `ws_gaps_total{cause}`.
#[must_use]
pub fn gaps_total(cause: GapCause) -> u64 {
    GAPS.get(cause as usize).map_or(0, |n| n.load(Relaxed))
}

/// `ws_closed_total{code}`, `code` one of [`CLOSE_CODES`].
#[must_use]
pub fn closed_total(code: &str) -> u64 {
    CLOSE_CODES
        .iter()
        .position(|c| *c == code)
        .and_then(|i| CLOSED.get(i))
        .map_or(0, |n| n.load(Relaxed))
}

/// `ws_frames_sent_total` and `ws_entries_sent_total`.
#[must_use]
pub fn sent_total() -> (u64, u64) {
    (FRAMES_SENT.load(Relaxed), ENTRIES_SENT.load(Relaxed))
}

/// The fields of the `stats` line, with `ws_enabled`; none otherwise.
#[must_use]
pub fn stats() -> Vec<(&'static str, u64)> {
    if !ON.load(Relaxed) {
        return Vec::new();
    }
    let (parents, all) = subscriptions_open();
    let closed = CLOSED
        .iter()
        .map(|n| n.load(Relaxed))
        .fold(0, u64::saturating_add);
    vec![
        ("ws_connections_open", connections_open()),
        ("ws_subscriptions_parents", parents),
        ("ws_subscriptions_all", all),
        ("ws_frames_sent", FRAMES_SENT.load(Relaxed)),
        ("ws_entries_sent", ENTRIES_SENT.load(Relaxed)),
        ("ws_gaps_queue", gaps_total(GapCause::Queue)),
        ("ws_gaps_fanout", gaps_total(GapCause::Fanout)),
        ("ws_closed", closed),
    ]
}
