//! `GET /sbtp/v1/query?parent=&since=&limit=&cursor=` (spec §4; ADR 0012 rules 5 to 15 and 32;
//! ADR 0013 rules 3, 5 and 14; ADR 0018 rules 12 to 14 and 30; ADR 0024).
//!
//! The query string is read as received, not percent-decoded: every accepted value is plain
//! ASCII from a fixed set, so a `%` or a `+` is malformed. Nothing a client sent is logged.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Uri, header};
use axum::response::{IntoResponse, Response};
use sbtp_core::BlockId;

use crate::config::Settings;
use crate::error::ApiError;
use crate::index::{IndexBackend, MAX_QUERY_LIMIT, Page, Position};
use crate::log::{self, Event, Throttle, Value};
use crate::metrics::{self, IndexReadOp, Refused};
use crate::pool::IndexHandle;
use crate::store::{decode_hex, encode_hex, parse_hex_id, push_hex};

/// ADR 0012 rule 5: `limit` when the request has none.
pub const DEFAULT_LIMIT: u64 = 100;

/// ADR 0012 rule 5: the length bound of a `cursor`.
const MAX_CURSOR_CHARS: usize = 128;

/// Length of the cursors this relay issues: 20 bytes in lowercase hexadecimal.
#[cfg(test)]
const CURSOR_CHARS: usize = 40;

/// Why a `/query` request was refused with `400`, one variant per rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// ADR 0012 rule 5: a parameter that is not one of the four, or a pair without `=`.
    UnknownParameter,
    /// ADR 0012 rule 5: a parameter given twice.
    RepeatedParameter,
    /// ADR 0012 rules 4 and 5: `parent` is not 64 lowercase hexadecimal characters.
    MalformedParent,
    /// ADR 0012 rule 5: `since` is not a decimal u64 written with digits only.
    MalformedSince,
    /// ADR 0012 rules 5 and 8: `limit` is not a decimal integer of at least 1.
    MalformedLimit,
    /// ADR 0012 rule 5: `cursor` is not 1 to 128 characters of `A-Z a-z 0-9 - _`.
    MalformedCursor,
    /// ADR 0012 rule 9, ADR 0013 rule 5, ADR 0024 rule 7: a well-formed cursor this relay did not
    /// issue for its current index epoch.
    UnrecognisedCursor,
}

impl QueryError {
    /// The `400` response of this error (ADR 0012 rule 17).
    #[must_use]
    pub fn to_api(self) -> ApiError {
        let invalid = ApiError::invalid_parameter;
        match self {
            Self::UnknownParameter => invalid().with_message(
                "unknown query parameter; the parameters are parent, since, limit and cursor",
            ),
            Self::RepeatedParameter => invalid().with_message("a query parameter is repeated"),
            Self::MalformedParent => {
                invalid().with_message("parent must be 64 lowercase hexadecimal characters")
            }
            Self::MalformedSince => {
                invalid().with_message("since must be a decimal u64 in Unix milliseconds")
            }
            Self::MalformedLimit => invalid().with_message("limit must be a decimal integer >= 1"),
            Self::MalformedCursor => invalid()
                .with_message("cursor must be 1 to 128 characters of A-Z, a-z, 0-9, - and _"),
            Self::UnrecognisedCursor => ApiError::invalid_cursor(),
        }
    }
}

/// The parameters of one request, syntax checked; the cursor is not decoded yet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params<'a> {
    /// `parent`.
    pub parent: Option<BlockId>,
    /// `since`, Unix milliseconds of the relay clock (ADR 0012 rule 7).
    pub since: Option<u64>,
    /// `limit`, at least 1; a value past `u64::MAX` saturates (it is lowered anyway, rule 8).
    pub limit: Option<u64>,
    /// `cursor`, as received.
    pub cursor: Option<&'a str>,
}

/// Parses a raw query string (ADR 0012 rule 5). An absent or empty query has no parameter.
///
/// # Errors
///
/// The [`QueryError`] of the first pair that fails.
pub fn parse_params(query: Option<&str>) -> Result<Params<'_>, QueryError> {
    let mut p = Params::default();
    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return Ok(p);
    };
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or(QueryError::UnknownParameter)?;
        match name {
            "parent" => set(
                &mut p.parent,
                parse_hex_id(value).ok_or(QueryError::MalformedParent)?,
            )?,
            "since" => set(
                &mut p.since,
                digits(value)
                    .and_then(|d| d.parse().ok())
                    .ok_or(QueryError::MalformedSince)?,
            )?,
            "limit" => set(&mut p.limit, parse_limit(value)?)?,
            "cursor" => {
                let ok = (1..=MAX_CURSOR_CHARS).contains(&value.len())
                    && value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
                if !ok {
                    return Err(QueryError::MalformedCursor);
                }
                set(&mut p.cursor, value)?;
            }
            _ => return Err(QueryError::UnknownParameter),
        }
    }
    Ok(p)
}

fn set<T>(slot: &mut Option<T>, value: T) -> Result<(), QueryError> {
    if slot.is_some() {
        return Err(QueryError::RepeatedParameter);
    }
    *slot = Some(value);
    Ok(())
}

/// `s` if it is one or more ASCII digits.
fn digits(s: &str) -> Option<&str> {
    (!s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())).then_some(s)
}

/// ADR 0012 rules 5 and 8: digits only, at least 1; `0` is an error, a value too large for a u64
/// is still a valid integer and saturates (it is lowered to `max_query_limit`).
fn parse_limit(s: &str) -> Result<u64, QueryError> {
    let d = digits(s).ok_or(QueryError::MalformedLimit)?;
    let significant = d.trim_start_matches('0');
    if significant.is_empty() {
        return Err(QueryError::MalformedLimit);
    }
    Ok(significant.parse().unwrap_or(u64::MAX))
}

/// The cursor of position `at` under `epoch` (ADR 0013 rule 5): epoch (8 bytes), `received_at`
/// (8 bytes) and `n` (4 bytes), big-endian, in lowercase hexadecimal. Opaque to clients (ADR 0012
/// rule 9).
#[must_use]
pub fn encode_cursor(epoch: u64, at: Position) -> String {
    encode_hex(&cursor_bytes(epoch, at))
}

fn cursor_bytes(epoch: u64, at: Position) -> [u8; 20] {
    let mut raw = [0u8; 20];
    let (e, rest) = raw.split_at_mut(8);
    let (r, n) = rest.split_at_mut(8);
    e.copy_from_slice(&epoch.to_be_bytes());
    r.copy_from_slice(&at.received_at.to_be_bytes());
    n.copy_from_slice(&at.n.to_be_bytes());
    raw
}

/// The body of one page (ADR 0012 rule 10: exactly `block_ids`, `cursor` and `more`), written
/// into one buffer of its exact size: no intermediate string per identifier or JSON value (code
/// review finding 7 of milestone 1c-a). Every value is hexadecimal or a boolean, so nothing needs
/// escaping.
#[must_use]
pub fn page_body(epoch: u64, page: &Page) -> Vec<u8> {
    const HEAD: &[u8] = br#"{"block_ids":["#;
    const MID: &[u8] = br#"],"cursor":""#;
    let tail: &[u8] = if page.more {
        br#"","more":true}"#
    } else {
        br#"","more":false}"#
    };
    // Each identifier is 64 characters in quotes, with a comma between two.
    let ids = page.entries.len().saturating_mul(67).saturating_sub(1);
    let mut out = Vec::with_capacity(HEAD.len() + ids + MID.len() + 40 + tail.len());
    out.extend_from_slice(HEAD);
    for (k, (_, id)) in page.entries.iter().enumerate() {
        if k > 0 {
            out.push(b',');
        }
        out.push(b'"');
        push_hex(&mut out, id.as_bytes());
        out.push(b'"');
    }
    out.extend_from_slice(MID);
    push_hex(&mut out, &cursor_bytes(epoch, page.next));
    out.extend_from_slice(tail);
    out
}

/// The position of a cursor issued by [`encode_cursor`] under `epoch`.
///
/// # Errors
///
/// [`QueryError::UnrecognisedCursor`]: another length, a character outside lowercase hexadecimal,
/// or another epoch (another relay, a rebuilt index, a new epoch after an unclean shutdown).
pub fn decode_cursor(s: &str, epoch: u64) -> Result<Position, QueryError> {
    let bad = QueryError::UnrecognisedCursor;
    let raw = decode_hex::<20>(s).ok_or(bad)?;
    let (e, rest) = raw.split_first_chunk::<8>().ok_or(bad)?;
    let (r, n) = rest.split_first_chunk::<8>().ok_or(bad)?;
    let n: [u8; 4] = n.try_into().map_err(|_| bad)?;
    if u64::from_be_bytes(*e) != epoch {
        return Err(bad);
    }
    Ok(Position {
        received_at: u64::from_be_bytes(*r),
        n: u32::from_be_bytes(n),
    })
}

/// ADR 0013 rules 12 and 14: the first position that is not expired at `now_ms`. A block expires
/// when `received_at + block_ttl_ms ≤ now`, so the first live position has
/// `received_at = now − block_ttl_ms + 1`. Without eviction by age nothing expires.
// HOOK(1c-b): the sweeper uses the same bound, and the benchmark-only expiry bound `B` of ADR 0017
// rule 4 replaces `now − block_ttl_ms` here (first live position `B + 1`).
#[must_use]
pub fn expiry_floor(block_ttl_ms: Option<u64>, now_ms: u64) -> Position {
    match block_ttl_ms.and_then(|ttl| now_ms.checked_sub(ttl)) {
        Some(bound) => Position::at(bound.saturating_add(1)),
        None => Position::default(),
    }
}

/// A failed page read (ADR 0021 clarifications X1 and X3): counted at every occurrence, logged
/// as `index_read_failed` with `op=query` and the `errno` under the failure when there is one,
/// throttled per `op` (rule 8). No `block_id`, query parameter or cursor (rules 10 and 12).
fn index_read_failed<I: IndexBackend>(e: &I::Error) {
    static QUERY_LOG: Throttle = Throttle::new();
    let op = IndexReadOp::Query;
    metrics::index_read_error(op);
    let mut fields = vec![("op", Value::Str(op.name()))];
    if let Some(n) = I::io_error(e).and_then(log::errno) {
        fields.push(("errno", Value::Int(n)));
    }
    log::throttled(&QUERY_LOG, Event::IndexReadFailed, &fields, None);
}

/// The state of the `/query` route.
pub struct QueryState<I> {
    /// ADR 0018 rules 9 to 13: each page is one job of the index reader threads.
    index: IndexHandle<I>,
    max_limit: u64,
    block_ttl_ms: Option<u64>,
    retry_after_s: u64,
    /// The relay clock in Unix milliseconds ([`log::unix_ms`]; a test clock in unit tests).
    clock: fn() -> u64,
}

impl<I: IndexBackend + 'static> QueryState<I> {
    /// The `/query` state over `index`.
    #[must_use]
    pub fn new(s: &Settings, index: IndexHandle<I>) -> Self {
        Self {
            index,
            max_limit: s.max_query_limit,
            block_ttl_ms: s.block_ttl_ms,
            retry_after_s: s.shed_retry_after_s,
            clock: log::unix_ms,
        }
    }
}

/// `GET /sbtp/v1/query` (spec §4). Order: parameters (`400 InvalidParameter`), cursor (`400
/// InvalidCursor`), then one job of the index reader threads (`503 Unavailable` when the queue
/// is full or the wait expires). The `query` token bucket of ADR 0018 rule 21 was taken at
/// admission (`server::admit`). No match is `200` with an empty list, never `404` (ADR 0012
/// rule 11).
pub async fn query<I: IndexBackend + 'static>(
    State(q): State<Arc<QueryState<I>>>,
    uri: Uri,
) -> Response {
    static SHED_LOG: Throttle = Throttle::new();
    let p = match parse_params(uri.query()) {
        Ok(p) => p,
        Err(e) => return e.to_api().into_response(),
    };
    // ADR 0013 rule 5: the epoch changes only during the start-up walk, before the relay listens.
    let epoch = q.index.epoch();
    let cursor = match p.cursor.map(|c| decode_cursor(c, epoch)).transpose() {
        Ok(c) => c,
        Err(e) => return e.to_api().into_response(),
    };
    // ADR 0012 rule 9: the later of `since` and the cursor.
    let start = p
        .since
        .map_or_else(Position::default, Position::at)
        .max(cursor.unwrap_or_default());
    // ADR 0012 rule 8: lowered to `max_query_limit`, not an error; the index clamps again (ADR
    // 0018 rule 14).
    let limit = p.limit.unwrap_or(DEFAULT_LIMIT).min(q.max_limit);
    let limit = usize::try_from(limit).unwrap_or(MAX_QUERY_LIMIT);
    let parent = p.parent;
    let (ttl, clock) = (q.block_ttl_ms, q.clock);
    let page = q
        .index
        .read(move |index| {
            // ADR 0013 rule 14 (security review L-1): the expiry bound is read when the page is
            // built, after the wait in the reader queue, not when the request arrived.
            let from = start.max(expiry_floor(ttl, clock()));
            index.query(parent.as_ref(), from, limit)
        })
        .await;
    if let Ok(r) = &page {
        q.index.record_read(r); // ADR 0018 rule 37
    }
    let page = match page {
        Ok(Ok(page)) => page,
        // ADR 0012 clarification K2, ADR 0021 clarifications X1, X3 and X4: a read failure of
        // the index is `500` with no detail; it changes no state (no epoch change, no shedding),
        // so every cursor stays valid.
        Ok(Err(e)) => {
            index_read_failed::<I>(&e);
            return ApiError::internal().into_response();
        }
        Err(_) => {
            let r = Refused::IndexQueue;
            metrics::refused(r);
            log::throttled(
                &SHED_LOG,
                Event::Shed,
                &[("reason", Value::Str(r.reason()))],
                None,
            );
            return ApiError::unavailable(q.retry_after_s).into_response();
        }
    };
    let body = page_body(epoch, &page);
    let mut r = Response::new(Body::from(body));
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // ADR 0012 rule 32.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    const H: &str = "abababababababababababababababababababababababababababababababab";

    fn parse(q: &str) -> Result<Params<'_>, QueryError> {
        parse_params(Some(q))
    }

    #[test]
    fn parameters_are_parsed() {
        assert_eq!(parse_params(None), Ok(Params::default()));
        assert_eq!(parse(""), Ok(Params::default()));
        let q = format!("parent={H}&since=17&limit=007&cursor=a-Z_9");
        let p = parse(&q).unwrap();
        assert_eq!(p.parent, parse_hex_id(H));
        assert_eq!(
            (p.since, p.limit, p.cursor),
            (Some(17), Some(7), Some("a-Z_9"))
        );
        assert_eq!(
            parse("limit=99999999999999999999999").unwrap().limit,
            Some(u64::MAX),
            "rule 8: lowered, not an error"
        );
        assert_eq!(parse("since=0").unwrap().since, Some(0));
    }

    #[test]
    fn unknown_parameter() {
        for q in [
            "foo=1",
            "Limit=5",
            "limit",
            "&limit=5",
            "limit=5&",
            "parent%3D=1",
        ] {
            assert_eq!(parse(q), Err(QueryError::UnknownParameter), "{q}");
        }
    }

    #[test]
    fn repeated_parameter() {
        for q in ["limit=1&limit=1", "since=1&since=2", "cursor=a&cursor=a"] {
            assert_eq!(parse(q), Err(QueryError::RepeatedParameter), "{q}");
        }
        let p = format!("parent={H}&parent={H}");
        assert_eq!(parse(&p), Err(QueryError::RepeatedParameter));
    }

    #[test]
    fn malformed_parent() {
        let upper = H.to_ascii_uppercase();
        let short = &H[..62];
        let pct = format!("%61{}", &H[1..]);
        for v in ["", upper.as_str(), short, pct.as_str()] {
            let q = format!("parent={v}");
            assert_eq!(parse(&q), Err(QueryError::MalformedParent), "{q}");
        }
    }

    #[test]
    fn malformed_since() {
        for q in [
            "since=",
            "since=-1",
            "since=+1",
            "since=1.0",
            "since=18446744073709551616",
        ] {
            assert_eq!(parse(q), Err(QueryError::MalformedSince), "{q}");
        }
        assert_eq!(
            parse("since=18446744073709551615").unwrap().since,
            Some(u64::MAX)
        );
    }

    #[test]
    fn malformed_limit() {
        for q in [
            "limit=",
            "limit=0",
            "limit=000",
            "limit=-1",
            "limit=+5",
            "limit=1e3",
        ] {
            assert_eq!(parse(q), Err(QueryError::MalformedLimit), "{q}");
        }
    }

    #[test]
    fn malformed_cursor() {
        let long = "a".repeat(129);
        for v in ["", "a b", "a+b", "a%2Fb", "a.b", "a=b", long.as_str()] {
            let q = format!("cursor={v}");
            assert_eq!(parse(&q), Err(QueryError::MalformedCursor), "{q}");
        }
        assert!(parse(&format!("cursor={}", "a".repeat(128))).is_ok());
    }

    #[test]
    fn cursor_round_trip_and_unrecognised() {
        let at = Position {
            received_at: 0x0102_0304_0506_0708,
            n: 0x0a0b_0c0d,
        };
        let c = encode_cursor(7, at);
        assert_eq!(c.len(), CURSOR_CHARS);
        assert!(parse(&format!("cursor={c}")).is_ok(), "within rule 5");
        assert_eq!(decode_cursor(&c, 7), Ok(at));
        let bad = QueryError::UnrecognisedCursor;
        assert_eq!(decode_cursor(&c, 8), Err(bad), "another epoch (ADR 0024)");
        assert_eq!(decode_cursor(&c[..39], 7), Err(bad), "length");
        assert_eq!(decode_cursor(&format!("{c}0"), 7), Err(bad), "length");
        assert_eq!(decode_cursor(&c.to_ascii_uppercase(), 7), Err(bad));
        assert_eq!(decode_cursor(&"_".repeat(40), 7), Err(bad));
        assert_eq!(bad.to_api().name(), "InvalidCursor");
        assert_eq!(bad.to_api().status(), 400);
    }

    #[test]
    fn every_syntax_error_is_invalid_parameter() {
        for e in [
            QueryError::UnknownParameter,
            QueryError::RepeatedParameter,
            QueryError::MalformedParent,
            QueryError::MalformedSince,
            QueryError::MalformedLimit,
            QueryError::MalformedCursor,
        ] {
            let a = e.to_api();
            assert_eq!((a.status().as_u16(), a.name()), (400, "InvalidParameter"));
        }
    }

    /// Security review L-1: the expiry bound is read once a reader thread runs the job. A block
    /// that expires while its request waits for the only reader is not listed. Deterministic: the
    /// test occupies the reader, waits until the request is queued, then moves the test clock past
    /// the expiry and releases the reader. The control run does not move the clock.
    #[tokio::test]
    async fn expiry_is_read_after_the_permit_wait() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NOW: AtomicU64 = AtomicU64::new(0);
        fn clock() -> u64 {
            NOW.load(Ordering::SeqCst)
        }
        let ttl = 60_000;
        for expire_while_queued in [false, true] {
            let dir = std::env::temp_dir().join(format!(
                "sbtp-query-l1-{}-{expire_while_queued}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let index =
                Arc::new(crate::index::RedbIndex::open(&dir.join("index.redb"), 1 << 20).unwrap());
            let id = BlockId([3; 32]);
            index
                .insert(&id, 100, &[], 1_000, crate::index::FileState::Created)
                .unwrap();
            let env = [
                ("SBTP_RELAY_BLOCK_TTL_MS", ttl.to_string()),
                ("SBTP_RELAY_INDEX_MAX_READERS", "1".to_owned()),
                ("SBTP_RELAY_INDEX_MAX_QUEUE", "1".to_owned()),
                ("SBTP_RELAY_QUEUE_TIMEOUT_MS", "10000".to_owned()),
            ]
            .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)));
            let s = Settings::load(Vec::<std::ffi::OsString>::new(), env).unwrap();
            let pool = crate::pool::IndexPool::start(&index, &s).unwrap();
            let mut state = QueryState::new(&s, pool.handle());
            state.clock = clock;
            let q = Arc::new(state);
            // Live: `1_000 + ttl > now`.
            NOW.store(1_000 + ttl - 1, Ordering::SeqCst);
            let (release, held) = std::sync::mpsc::channel::<()>();
            let busy = tokio::spawn({
                let h = pool.handle();
                async move { h.read(move |_| held.recv().is_ok()).await }
            });
            while q.index.running() == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            let request = tokio::spawn(query(
                State(Arc::clone(&q)),
                Uri::from_static("/sbtp/v1/query"),
            ));
            while q.index.queued() == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            if expire_while_queued {
                NOW.store(1_000 + ttl, Ordering::SeqCst);
            }
            drop(release);
            assert_eq!(busy.await.unwrap(), Ok(false));
            let r = request.await.unwrap();
            assert_eq!(r.status(), 200);
            let body = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let listed = !v["block_ids"].as_array().unwrap().is_empty();
            assert_eq!(listed, !expire_while_queued, "{v}");
        }
    }

    /// Code review finding 7: the body written into one buffer is the JSON of ADR 0012 rule 10,
    /// with no reallocation.
    #[test]
    fn page_body_is_the_json_of_rule_10() {
        let at = |n| Position { received_at: 77, n };
        for (entries, more) in [
            (Vec::new(), false),
            (vec![(at(0), BlockId([0xab; 32]))], true),
            (
                vec![(at(0), BlockId([1; 32])), (at(1), BlockId([0xfe; 32]))],
                false,
            ),
        ] {
            let page = Page {
                next: at(9),
                entries,
                more,
            };
            let body = page_body(5, &page);
            assert_eq!(body.len(), body.capacity(), "sized exactly");
            let ids: Vec<String> = page.entries.iter().map(|(_, id)| id.to_string()).collect();
            let expected = serde_json::json!({
                "block_ids": ids,
                "cursor": encode_cursor(5, page.next),
                "more": more,
            });
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                expected
            );
            assert_eq!(body, expected.to_string().into_bytes());
        }
    }

    /// ADR 0013 rules 12 and 14: expired iff `received_at + ttl ≤ now`.
    #[test]
    fn expiry_floor_is_the_first_live_position() {
        assert_eq!(expiry_floor(None, 5_000), Position::default());
        assert_eq!(expiry_floor(Some(1_000), 5_000), Position::at(4_001));
        assert_eq!(expiry_floor(Some(5_000), 5_000), Position::at(1));
        assert_eq!(expiry_floor(Some(6_000), 5_000), Position::default());
        assert_eq!(
            expiry_floor(Some(1), u64::MAX),
            Position::at(u64::MAX),
            "no overflow"
        );
    }
}
