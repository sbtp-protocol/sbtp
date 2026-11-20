//! The `/query` walk (spec §4 `GET /sbtp/v1/query`; ADR 0012 rules 9 to 13 and clarifications K1,
//! K2; ADR 0024 rule 8), kept apart from HTTP so that its restart and back-off rules are tested
//! against a scripted relay.
//!
//! - `400 InvalidCursor`: the walk starts again without a cursor, keeping its filters, and the
//!   rejected cursor is never sent again. Identifiers already emitted are not emitted twice.
//! - `400 InvalidParameter`, and every other refusal: the walk stops. It is never restarted.
//! - `500`, `502`, `503`, `504`, `429`: the walk keeps its cursor and repeats the request after
//!   `Retry-After`, or after an exponential back-off with jitter from 1 second.

use std::collections::HashSet;
use std::fmt::Write;
use std::time::Duration;

use sbtp_core::BlockId;

use crate::fail::Fail;

/// Longest cursor (spec §4 `/query`, ADR 0012 rule 5).
pub const MAX_CURSOR_LEN: usize = 128;

/// Whether `cursor` is within the syntax of ADR 0012 rule 5: 1 to 128 characters of
/// `A-Z a-z 0-9 - _`. A relay MUST issue cursors within it (clarification K1).
pub fn is_cursor_syntax(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAX_CURSOR_LEN
        && cursor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The filters of a walk. They are kept unchanged across a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// `parent`: only children of this block.
    pub parent: Option<BlockId>,
    /// `since`: only blocks the relay stored at or after this time (ms, relay clock).
    pub since: Option<u64>,
    /// `limit`: page size asked for; the relay may lower it, never raise it.
    pub limit: Option<u32>,
}

/// One `200` page of `/query`, already checked (identifiers, cursor syntax, page size).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// `block_ids`, in the relay's order.
    pub block_ids: Vec<BlockId>,
    /// `cursor`, within the syntax of [`is_cursor_syntax`].
    pub cursor: String,
    /// `more`.
    pub more: bool,
}

/// Why a page could not be read.
#[derive(Debug)]
pub enum PageError {
    /// `400` with the error `InvalidCursor`.
    InvalidCursor,
    /// A transient refusal: the same request may be repeated later.
    Transient {
        /// HTTP status.
        status: u16,
        /// `Retry-After` in seconds, when the relay sent one.
        retry_after: Option<u64>,
        /// What to report if the walk gives up.
        fail: Fail,
    },
    /// Anything else, `InvalidParameter` included: the walk stops.
    Fatal(Fail),
}

/// Where pages come from: the relay over HTTP, or a script in the tests.
pub trait PageSource {
    /// `GET /sbtp/v1/query` with `filter` and, if given, `cursor`.
    ///
    /// # Errors
    ///
    /// See [`PageError`].
    fn page(&mut self, filter: &Filter, cursor: Option<&str>) -> Result<Page, PageError>;
}

/// Bounds of one walk.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Transient failures in a row on one page before the walk gives up.
    pub max_retries: u32,
    /// Restarts after `InvalidCursor` within one walk before it gives up (a relay that rejects
    /// every cursor it issued would otherwise loop for ever).
    pub max_restarts: u32,
    /// Longest `Retry-After` obeyed; a longer one ends the walk instead of a silent wait.
    pub max_retry_after: Duration,
    /// Cap of the exponential back-off before jitter.
    pub backoff_cap: Duration,
    /// Pages in a row that bring no new identifier before the walk stops, when no restart
    /// happened. An honest relay never sends such pages outside a restart (ADR 0012 rule 10); a
    /// hostile one could otherwise keep the walk busy for ever (security review 2026-11-19 query,
    /// L-2). After a restart, `seen / page size` more pages are allowed: the relay re-serves what
    /// was already printed.
    pub max_idle_pages: u64,
    /// Most distinct identifiers remembered for deduplication (security review 2026-11-19 query,
    /// L-3). About 50 MB at 1,000,000. The walk stops, with a resume cursor, past this bound.
    pub max_seen: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_retries: 6,
            max_restarts: 3,
            max_retry_after: Duration::from_secs(300),
            backoff_cap: Duration::from_secs(60),
            max_idle_pages: 16,
            max_seen: MAX_SEEN,
        }
    }
}

/// Default of [`Policy::max_seen`].
pub const MAX_SEEN: usize = 1_000_000;

/// Default `limit` of `/query` (ADR 0012 rule 5).
const DEFAULT_QUERY_LIMIT: usize = 100;
/// Largest page of `/query` (ADR 0012 rule 8: `max_query_limit` is at most 1,000).
const MAX_PAGE_IDS: usize = 1000;

/// The most identifiers a page may hold: the `limit` asked for (default 100), which a relay may
/// lower but never raise, and never more than 1,000 (ADR 0012 rules 5 and 8).
pub fn page_limit(filter: &Filter) -> usize {
    filter
        .limit
        .and_then(|l| usize::try_from(l).ok())
        .unwrap_or(DEFAULT_QUERY_LIMIT)
        .min(MAX_PAGE_IDS)
}

/// What the walk reports while it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A `block_id` not emitted before by this walker.
    Id(&'a BlockId),
    /// `InvalidCursor`: the walk starts again without a cursor.
    Restart {
        /// Nothing was emitted by this walker yet (a rejected starting `--cursor`): identifiers
        /// printed by an earlier run will be emitted again.
        first_output: bool,
    },
    /// A transient failure: the walk waits `delay`, then repeats the request with the same cursor.
    Wait {
        /// HTTP status of the failure.
        status: u16,
        /// How long the walk waits.
        delay: Duration,
        /// Whether `delay` comes from `Retry-After`.
        retry_after: bool,
    },
}

/// Counts of one call to [`Walker::walk`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// `200` pages read.
    pub pages: u64,
    /// Identifiers emitted (new to this walker).
    pub new_ids: u64,
    /// Restarts after `InvalidCursor`.
    pub restarts: u32,
}

/// A walk over one relay. Keeps the cursor and the identifiers already emitted between calls to
/// [`Walker::walk`], so that polling with `--follow` emits each `block_id` once.
pub struct Walker<S> {
    source: S,
    filter: Filter,
    cursor: Option<String>,
    seen: HashSet<BlockId>,
    policy: Policy,
}

impl<S: PageSource> Walker<S> {
    /// A walk from `cursor` (a cursor of this relay, or `None` for the start).
    pub fn new(source: S, filter: Filter, cursor: Option<String>, policy: Policy) -> Self {
        Self {
            source,
            filter,
            cursor,
            seen: HashSet::new(),
            policy,
        }
    }

    /// The cursor to resume from: the last one the relay returned, or the starting one.
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    /// Emits the new identifiers of a `200` page and moves the cursor past it. Returns whether
    /// the page held an identifier not emitted before.
    fn take_page(
        &mut self,
        page: Page,
        summary: &mut Summary,
        on: &mut dyn FnMut(Event<'_>) -> Result<(), Fail>,
    ) -> Result<bool, Fail> {
        summary.pages = summary.pages.saturating_add(1);
        if page.more
            && page.block_ids.is_empty()
            && self.cursor.as_deref() == Some(page.cursor.as_str())
        {
            // An empty page that says `more` and hands back the same cursor would repeat for
            // ever.
            return Err(Fail::failed(
                "the relay's /query made no progress (an empty page with `more` and an unchanged \
                 cursor)",
            ));
        }
        let mut fresh = false;
        for id in &page.block_ids {
            // spec §4 `/query`: a client MUST deduplicate by block_id.
            if self.seen.insert(*id) {
                fresh = true;
                summary.new_ids = summary.new_ids.saturating_add(1);
                on(Event::Id(id))?;
            }
        }
        self.cursor = Some(page.cursor);
        // Checked on every page, the last included, so that `--follow` polls are bounded too.
        if self.seen.len() > self.policy.max_seen {
            // The whole page was printed: the cursor resumes right after it.
            return Err(Fail::failed(format!(
                "more than {} distinct block_ids in one run, the most this client remembers to \
                 avoid printing one twice; narrow the listing with `--parent` or `--since`",
                self.policy.max_seen
            )));
        }
        Ok(fresh)
    }

    /// Reads pages until the relay answers `more: false` (ADR 0012 rule 12).
    ///
    /// `sleep` waits, `random` gives the jitter, `on` receives the events; an error from `on`
    /// stops the walk and is returned.
    ///
    /// # Errors
    ///
    /// A fatal refusal, too many transient failures or restarts, a `Retry-After` above the policy,
    /// a relay that makes no progress, or an error from `on`.
    pub fn walk(
        &mut self,
        sleep: &mut dyn FnMut(Duration),
        random: &mut dyn FnMut() -> u64,
        on: &mut dyn FnMut(Event<'_>) -> Result<(), Fail>,
    ) -> Result<Summary, Fail> {
        let mut summary = Summary::default();
        let mut retries = 0u32;
        // Pages in a row with no new identifier, and how many are tolerated (L-2).
        let mut idle = 0u64;
        let mut idle_allowed = self.policy.max_idle_pages;
        loop {
            match self.source.page(&self.filter, self.cursor.as_deref()) {
                Ok(page) => {
                    retries = 0;
                    let more = page.more;
                    let fresh = self.take_page(page, &mut summary, on)?;
                    if !more {
                        return Ok(summary);
                    }
                    idle = if fresh { 0 } else { idle.saturating_add(1) };
                    if idle > idle_allowed {
                        return Err(Fail::failed(format!(
                            "the relay's /query made no progress: {idle} pages in a row with \
                             `more` and no block_id not already printed"
                        )));
                    }
                }
                Err(PageError::InvalidCursor) => {
                    if self.cursor.is_none() {
                        return Err(Fail::refused(
                            "the relay answered InvalidCursor to a request without a cursor",
                        ));
                    }
                    // ADR 0024 rule 8: the rejected cursor is never sent again, nor offered for a
                    // resume (security review 2026-11-19 query, L-1).
                    self.cursor = None;
                    if summary.restarts >= self.policy.max_restarts {
                        return Err(Fail::refused(format!(
                            "the relay rejected the walk's cursor {} times (InvalidCursor); \
                             giving up",
                            summary.restarts.saturating_add(1)
                        )));
                    }
                    // Start again without a cursor; the filters are kept; deduplication hides
                    // what this process already emitted.
                    summary.restarts = summary.restarts.saturating_add(1);
                    retries = 0;
                    idle = 0;
                    let pages_to_replay = u64::try_from(self.seen.len() / page_limit(&self.filter))
                        .unwrap_or(u64::MAX);
                    idle_allowed = self.policy.max_idle_pages.saturating_add(pages_to_replay);
                    on(Event::Restart {
                        first_output: self.seen.is_empty(),
                    })?;
                }
                Err(PageError::Transient {
                    status,
                    retry_after,
                    mut fail,
                }) => {
                    if retries >= self.policy.max_retries {
                        let _ = write!(
                            fail.message,
                            "\nGave up after {} attempts on this page.",
                            retries.saturating_add(1)
                        );
                        return Err(fail);
                    }
                    let delay = match retry_after {
                        Some(seconds) => {
                            let delay = Duration::from_secs(seconds);
                            if delay > self.policy.max_retry_after {
                                let _ = write!(
                                    fail.message,
                                    "\nThe relay asks to wait {seconds} seconds; not waiting \
                                     that long."
                                );
                                return Err(fail);
                            }
                            delay
                        }
                        None => backoff(retries, self.policy.backoff_cap, random()),
                    };
                    retries = retries.saturating_add(1);
                    // ADR 0012 K2: a 500 invalidates no cursor; the same request is repeated.
                    on(Event::Wait {
                        status,
                        delay,
                        retry_after: retry_after.is_some(),
                    })?;
                    sleep(delay);
                }
                Err(PageError::Fatal(fail)) => return Err(fail),
            }
        }
    }
}

/// Exponential back-off with jitter, from 1 second (spec §4 "Admission control"): a base of
/// `2^attempt` seconds capped at `cap`, plus a random part of up to half the base. Never under
/// 1 second.
pub fn backoff(attempt: u32, cap: Duration, random: u64) -> Duration {
    let cap_ms = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX).max(1000);
    let base_ms = 1000u64.saturating_mul(1u64 << attempt.min(30)).min(cap_ms);
    let jitter_ms = random % (base_ms / 2 + 1);
    Duration::from_millis(base_ms.saturating_add(jitter_ms))
}

/// A random `u64` for the jitter, from the standard library's per-process random hash keys: no
/// extra dependency, and the jitter needs no cryptographic quality.
pub fn jitter_source() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::from(d.subsec_nanos()) ^ d.as_secs()),
    );
    hasher.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use std::collections::VecDeque;

    use super::*;

    /// One scripted answer.
    enum Answer {
        Page(&'static [u8], &'static str, bool),
        InvalidCursor,
        InvalidParameter,
        Status(u16, Option<u64>),
    }

    /// A relay that plays `answers` in order and records each request's cursor.
    struct Script {
        answers: VecDeque<Answer>,
        requests: Vec<(Filter, Option<String>)>,
    }

    fn script(answers: Vec<Answer>) -> Script {
        Script {
            answers: answers.into(),
            requests: Vec::new(),
        }
    }

    fn id(n: u8) -> BlockId {
        BlockId::from_bytes([n; 32])
    }

    impl PageSource for &mut Script {
        fn page(&mut self, filter: &Filter, cursor: Option<&str>) -> Result<Page, PageError> {
            self.requests
                .push((filter.clone(), cursor.map(str::to_owned)));
            match self
                .answers
                .pop_front()
                .expect("more requests than scripted")
            {
                Answer::Page(ids, cursor, more) => Ok(Page {
                    block_ids: ids.iter().map(|n| id(*n)).collect(),
                    cursor: cursor.to_owned(),
                    more,
                }),
                Answer::InvalidCursor => Err(PageError::InvalidCursor),
                Answer::InvalidParameter => Err(PageError::Fatal(Fail::refused(
                    "400 Bad Request: InvalidParameter",
                ))),
                Answer::Status(status, retry_after) => Err(PageError::Transient {
                    status,
                    retry_after,
                    fail: Fail::refused(format!("status {status}")),
                }),
            }
        }
    }

    /// What a walk did: emitted ids, restarts, waits, sleeps.
    #[derive(Default)]
    struct Run {
        ids: Vec<BlockId>,
        restarts: u32,
        first_output: Vec<bool>,
        waits: Vec<(u16, bool)>,
        sleeps: Vec<Duration>,
    }

    fn filter() -> Filter {
        Filter {
            parent: Some(id(0xaa)),
            since: Some(5),
            limit: Some(2),
        }
    }

    fn run(
        s: &mut Script,
        cursor: Option<&str>,
        policy: Policy,
    ) -> (Result<Summary, Fail>, Run, Option<String>) {
        let mut r = Run::default();
        let mut sleeps = Vec::new();
        let mut walker = Walker::new(s, filter(), cursor.map(str::to_owned), policy);
        let result = walker.walk(&mut |d| sleeps.push(d), &mut || 0, &mut |e| {
            match e {
                Event::Id(i) => r.ids.push(*i),
                Event::Restart { first_output } => {
                    r.restarts += 1;
                    r.first_output.push(first_output);
                }
                Event::Wait {
                    status,
                    retry_after,
                    ..
                } => r.waits.push((status, retry_after)),
            }
            Ok(())
        });
        r.sleeps = sleeps;
        let cursor = walker.cursor().map(str::to_owned);
        (result, r, cursor)
    }

    fn cursors(s: &Script) -> Vec<Option<&str>> {
        s.requests.iter().map(|(_, c)| c.as_deref()).collect()
    }

    #[test]
    fn walks_pages_with_the_returned_cursor() {
        let mut s = script(vec![
            Answer::Page(&[1, 2], "c1", true),
            Answer::Page(&[3], "c2", false),
        ]);
        let (result, r, cursor) = run(&mut s, None, Policy::default());
        let summary = result.unwrap();
        assert_eq!(r.ids, [id(1), id(2), id(3)]);
        assert_eq!(summary.pages, 2);
        assert_eq!(summary.new_ids, 3);
        assert_eq!(cursors(&s), [None, Some("c1")]);
        assert_eq!(cursor.as_deref(), Some("c2"));
        assert!(s.requests.iter().all(|(f, _)| *f == filter()));
    }

    /// ADR 0024 rule 8: `InvalidCursor` in the middle of a walk restarts it without a cursor, with
    /// the same filters; the rejected cursor is never sent again; ids are emitted once.
    #[test]
    fn invalid_cursor_mid_walk_restarts_without_cursor_and_deduplicates() {
        let mut s = script(vec![
            Answer::Page(&[1, 2], "c1", true),
            Answer::InvalidCursor,
            Answer::Page(&[1, 2], "n1", true),
            Answer::Page(&[3], "n2", false),
        ]);
        let (result, r, cursor) = run(&mut s, None, Policy::default());
        let summary = result.unwrap();
        assert_eq!(summary.restarts, 1);
        assert_eq!(r.restarts, 1);
        assert_eq!(r.first_output, [false]);
        assert_eq!(r.ids, [id(1), id(2), id(3)]);
        assert_eq!(cursors(&s), [None, Some("c1"), None, Some("n1")]);
        assert_eq!(cursor.as_deref(), Some("n2"));
        assert!(s.requests.iter().all(|(f, _)| *f == filter()));
        assert_eq!(r.sleeps, Vec::<Duration>::new());
    }

    /// A starting cursor (`--cursor`) the relay no longer recognises also restarts the walk.
    #[test]
    fn invalid_starting_cursor_restarts() {
        let mut s = script(vec![Answer::InvalidCursor, Answer::Page(&[7], "n1", false)]);
        let (result, r, _) = run(&mut s, Some("stale"), Policy::default());
        assert_eq!(result.unwrap().restarts, 1);
        assert_eq!(r.ids, [id(7)]);
        assert_eq!(cursors(&s), [Some("stale"), None]);
        // I-1: nothing printed yet by this walker; earlier runs' ids come again.
        assert_eq!(r.first_output, [true]);
    }

    #[test]
    fn invalid_cursor_without_a_cursor_is_a_relay_fault() {
        let mut s = script(vec![Answer::InvalidCursor]);
        let (result, r, _) = run(&mut s, None, Policy::default());
        assert!(result.unwrap_err().message.contains("without a cursor"));
        assert_eq!(r.restarts, 0);
        assert_eq!(s.requests.len(), 1);
    }

    #[test]
    fn restarts_are_bounded() {
        let mut s = script(vec![
            Answer::Page(&[1], "a", true),
            Answer::InvalidCursor,
            Answer::Page(&[1], "b", true),
            Answer::InvalidCursor,
        ]);
        let policy = Policy {
            max_restarts: 1,
            ..Policy::default()
        };
        let (result, r, cursor) = run(&mut s, None, policy);
        assert!(result.unwrap_err().message.contains("giving up"));
        assert_eq!(r.restarts, 1);
        assert_eq!(s.requests.len(), 4);
        // L-1: the rejected cursor is not offered for a resume.
        assert_eq!(cursor, None);
    }

    /// L-2: empty pages with `more` and alternating cursors stop after `max_idle_pages`.
    #[test]
    fn alternating_cursors_on_empty_pages_stop() {
        let mut answers = vec![Answer::Page(&[1], "a", true)];
        for i in 0..6 {
            answers.push(Answer::Page(&[], if i % 2 == 0 { "b" } else { "a" }, true));
        }
        let mut s = script(answers);
        let policy = Policy {
            max_idle_pages: 4,
            ..Policy::default()
        };
        let (result, r, _) = run(&mut s, None, policy);
        assert!(result.unwrap_err().message.contains("no progress"));
        assert_eq!(r.ids, [id(1)]);
        // One page with an id, then 4 idle pages tolerated, the 5th stops.
        assert_eq!(s.requests.len(), 6);
    }

    /// L-2: pages that only repeat ids already printed also stop, without a restart.
    #[test]
    fn pages_repeating_printed_ids_stop() {
        let mut answers = vec![Answer::Page(&[1, 2], "a", true)];
        let cursors = ["b", "c", "d", "e", "f"];
        for c in cursors {
            answers.push(Answer::Page(&[1, 2], c, true));
        }
        let mut s = script(answers);
        let policy = Policy {
            max_idle_pages: 3,
            ..Policy::default()
        };
        let (result, r, _) = run(&mut s, None, policy);
        assert!(result.unwrap_err().message.contains("no progress"));
        assert_eq!(r.ids, [id(1), id(2)]);
        assert_eq!(s.requests.len(), 5);
    }

    /// L-2: after a restart the relay re-serves what was printed: `seen / limit` extra idle pages
    /// are tolerated before the bound applies.
    #[test]
    fn a_restart_allows_replaying_printed_pages() {
        // limit 2 (filter()), 6 ids printed: 3 replayed pages allowed on top of max_idle_pages.
        let mut s = script(vec![
            Answer::Page(&[1, 2], "a", true),
            Answer::Page(&[3, 4], "b", true),
            Answer::Page(&[5, 6], "c", true),
            Answer::InvalidCursor,
            Answer::Page(&[1, 2], "n1", true),
            Answer::Page(&[3, 4], "n2", true),
            Answer::Page(&[5, 6], "n3", true),
            Answer::Page(&[7], "n4", false),
        ]);
        let policy = Policy {
            max_idle_pages: 0,
            ..Policy::default()
        };
        let (result, r, _) = run(&mut s, None, policy);
        assert_eq!(result.unwrap().restarts, 1);
        assert_eq!(r.ids, [1, 2, 3, 4, 5, 6, 7].map(id));
    }

    /// L-3: the deduplication set is bounded; past it the walk stops with the page's cursor.
    #[test]
    fn the_dedup_set_is_bounded() {
        let mut s = script(vec![
            Answer::Page(&[1, 2], "a", true),
            Answer::Page(&[3, 4], "b", true),
            Answer::Page(&[5, 6], "c", false),
        ]);
        let policy = Policy {
            max_seen: 3,
            ..Policy::default()
        };
        let (result, r, cursor) = run(&mut s, None, policy);
        assert!(result.unwrap_err().message.contains("more than 3 distinct"));
        assert_eq!(r.ids, [1, 2, 3, 4].map(id));
        assert_eq!(cursor.as_deref(), Some("b"));
        assert_eq!(s.requests.len(), 2);

        // A final page (`more: false`) past the bound stops too, so `--follow` polls are bounded.
        let mut s = script(vec![Answer::Page(&[1, 2, 3, 4], "a", false)]);
        let policy = Policy {
            max_seen: 3,
            ..Policy::default()
        };
        let mut walker = Walker::new(
            &mut s,
            Filter {
                limit: Some(4),
                ..Filter::default()
            },
            None,
            policy,
        );
        let result = walker.walk(&mut |_| {}, &mut || 0, &mut |_| Ok(()));
        assert!(result.is_err());
    }

    /// ADR 0012 K1: `InvalidParameter` stops the walk; no restart, no repeat.
    #[test]
    fn invalid_parameter_stops_without_restart_or_retry() {
        let mut s = script(vec![
            Answer::Page(&[1], "c1", true),
            Answer::InvalidParameter,
        ]);
        let (result, r, cursor) = run(&mut s, None, Policy::default());
        assert!(result.unwrap_err().message.contains("InvalidParameter"));
        assert_eq!(r.restarts, 0);
        assert!(r.waits.is_empty() && r.sleeps.is_empty());
        assert_eq!(cursors(&s), [None, Some("c1")]);
        // The last good cursor is kept for the report.
        assert_eq!(cursor.as_deref(), Some("c1"));
    }

    /// ADR 0012 K2: a `500` keeps the cursor and backs off exponentially from 1 second.
    #[test]
    fn server_error_keeps_the_cursor_and_backs_off() {
        let mut s = script(vec![
            Answer::Page(&[1], "c1", true),
            Answer::Status(500, None),
            Answer::Status(500, None),
            Answer::Status(500, None),
            Answer::Page(&[2], "c2", false),
        ]);
        let (result, r, _) = run(&mut s, None, Policy::default());
        let summary = result.unwrap();
        assert_eq!(summary.restarts, 0);
        assert_eq!(r.ids, [id(1), id(2)]);
        assert_eq!(
            cursors(&s),
            [None, Some("c1"), Some("c1"), Some("c1"), Some("c1")]
        );
        assert_eq!(r.waits, [(500, false), (500, false), (500, false)]);
        // Jitter source fixed at 0: exactly 1, 2, 4 seconds.
        assert_eq!(
            r.sleeps,
            [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4)
            ]
        );
    }

    #[test]
    fn retries_are_bounded_and_the_cursor_is_kept() {
        let mut s = script(vec![
            Answer::Page(&[1], "c1", true),
            Answer::Status(500, None),
            Answer::Status(500, None),
            Answer::Status(500, None),
        ]);
        let policy = Policy {
            max_retries: 2,
            ..Policy::default()
        };
        let (result, r, cursor) = run(&mut s, None, policy);
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Gave up after 3 attempts")
        );
        assert_eq!(r.sleeps.len(), 2);
        assert_eq!(r.restarts, 0);
        assert_eq!(cursor.as_deref(), Some("c1"));
    }

    /// spec §4 "Admission control": `Retry-After` is obeyed exactly (429, 503); too long a wait
    /// ends the walk instead.
    #[test]
    fn retry_after_is_obeyed_and_bounded() {
        let mut s = script(vec![
            Answer::Status(429, Some(3)),
            Answer::Status(503, Some(7)),
            Answer::Page(&[1], "c1", false),
        ]);
        let (result, r, _) = run(&mut s, None, Policy::default());
        result.unwrap();
        assert_eq!(r.waits, [(429, true), (503, true)]);
        assert_eq!(r.sleeps, [Duration::from_secs(3), Duration::from_secs(7)]);

        let mut s = script(vec![Answer::Status(503, Some(301))]);
        let (result, r, _) = run(&mut s, None, Policy::default());
        assert!(result.unwrap_err().message.contains("not waiting"));
        assert_eq!(r.sleeps, Vec::<Duration>::new());
    }

    #[test]
    fn an_empty_page_without_progress_stops() {
        let mut s = script(vec![
            Answer::Page(&[1], "c1", true),
            Answer::Page(&[], "c1", true),
        ]);
        let (result, _, _) = run(&mut s, None, Policy::default());
        assert!(result.unwrap_err().message.contains("no progress"));
    }

    /// `--follow`: a second walk resumes from the last cursor and emits only new ids.
    #[test]
    fn a_second_walk_resumes_and_emits_only_new_ids() {
        let mut s = script(vec![
            Answer::Page(&[1, 2], "c1", false),
            Answer::Page(&[2, 3], "c2", false),
        ]);
        let mut ids = Vec::new();
        let mut walker = Walker::new(&mut s, filter(), None, Policy::default());
        for _ in 0..2 {
            walker
                .walk(&mut |_| {}, &mut || 0, &mut |e| {
                    if let Event::Id(i) = e {
                        ids.push(*i);
                    }
                    Ok(())
                })
                .unwrap();
        }
        drop(walker);
        assert_eq!(ids, [id(1), id(2), id(3)]);
        assert_eq!(cursors(&s), [None, Some("c1")]);
    }

    #[test]
    fn an_event_error_stops_the_walk() {
        let mut s = script(vec![Answer::Page(&[1, 2], "c1", true)]);
        let mut walker = Walker::new(&mut s, filter(), None, Policy::default());
        let result = walker.walk(&mut |_| {}, &mut || 0, &mut |_| Err(Fail::failed("closed")));
        assert_eq!(result.unwrap_err().message, "closed");
    }

    #[test]
    fn backoff_grows_from_one_second_with_bounded_jitter() {
        let cap = Duration::from_secs(60);
        assert_eq!(backoff(0, cap, 0), Duration::from_secs(1));
        assert_eq!(backoff(1, cap, 0), Duration::from_secs(2));
        assert_eq!(backoff(10, cap, 0), Duration::from_secs(60));
        assert_eq!(backoff(u32::MAX, cap, 0), Duration::from_secs(60));
        for r in [1, 499, 500, 501, u64::MAX] {
            let d = backoff(0, cap, r);
            assert!(
                d >= Duration::from_secs(1) && d <= Duration::from_millis(1500),
                "{d:?}"
            );
            let d = backoff(9, cap, r);
            assert!(d >= cap && d <= Duration::from_secs(90), "{d:?}");
        }
    }

    #[test]
    fn cursor_syntax() {
        assert!(is_cursor_syntax("k3_Zr0AAAAEAAAAq"));
        assert!(is_cursor_syntax("-"));
        assert!(is_cursor_syntax(&"a".repeat(128)));
        assert!(!is_cursor_syntax(""));
        assert!(!is_cursor_syntax(&"a".repeat(129)));
        assert!(!is_cursor_syntax("a+b"));
        assert!(!is_cursor_syntax("a=b"));
        assert!(!is_cursor_syntax("é"));
    }
}
