//! The HTTP client side of the relay interface (spec §4): `GET /sbtp/v1/info`,
//! `PUT /sbtp/v1/block`, `GET /sbtp/v1/block/{block_id}` and `GET /sbtp/v1/query`.
//!
//! Everything a relay sends is untrusted: bodies are read up to a fixed limit, text is escaped
//! before it reaches the terminal, and a block is returned as raw bytes that the caller MUST
//! validate with `sbtp-core` (spec §3.4) before using them.

use std::time::Duration;

use sbtp_core::BlockId;
use sbtp_core::layout::MAX_BLOCK_LEN;
use ureq::Agent;
use ureq::http::{Response, StatusCode};

use crate::fail::{Fail, untrusted};
use crate::walk::{Filter, Page, PageError, PageSource, is_cursor_syntax, page_limit};

/// Deadline of one request, connection included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest JSON body read (`/info`, error bodies).
const MAX_JSON_LEN: u64 = 16 * 1024;
/// Largest `/query` body read: ADR 0012 rule 14 bounds a page under 70 KiB.
const MAX_QUERY_LEN: u64 = 128 * 1024;
/// Longest relay text shown to the user (spec §4 "Errors": `message` is at most 200 characters).
const MAX_SHOWN_CHARS: usize = 200;

/// A relay at a base URL such as `http://127.0.0.1:8080`.
pub struct Relay {
    base: String,
    agent: Agent,
}

/// The members of `GET /sbtp/v1/info` the CLI uses.
#[derive(Debug, Clone, Copy)]
pub struct Info {
    /// `min_pow_difficulty`, 0 to 256.
    pub min_pow_difficulty: u32,
    /// `max_future_ms`.
    pub max_future_ms: u64,
}

/// A successful `PUT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// `201 Created`: the relay stored the block.
    Created,
    /// `200 OK`: the relay already held this `block_id`.
    AlreadyStored,
}

impl Relay {
    /// Checks `url` and prepares a client. Only `http://` is supported by this build.
    ///
    /// # Errors
    ///
    /// A usage [`Fail`] for an unsupported or malformed URL.
    pub fn new(url: &str) -> Result<Self, Fail> {
        let base = url.trim_end_matches('/');
        if base.starts_with("https://") {
            return Err(Fail::usage(
                "this build of cli-demo has no TLS support: use an `http://` URL, for example a \
                 local relay (`http://127.0.0.1:8080`) or an SSH tunnel to a remote one",
            ));
        }
        let Some(rest) = base.strip_prefix("http://") else {
            return Err(Fail::usage(format!(
                "`--relay {}`: expected a URL starting with `http://`",
                untrusted(url, 100)
            )));
        };
        let host = rest.split('/').next().unwrap_or_default();
        if host.is_empty()
            || host.contains('@')
            || rest.contains(['?', '#'])
            || rest.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(Fail::usage(format!(
                "`--relay {}`: expected `http://host[:port][/path]` with no user name, query or \
                 fragment",
                untrusted(url, 100)
            )));
        }
        let agent: Agent = Agent::config_builder()
            // Status codes are decided here (spec §4 "Errors": status code first).
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            // A relay never redirects; a 3xx is reported, not followed.
            .max_redirects(0)
            // Explicit: no proxy taken from the environment.
            .proxy(None)
            .user_agent(concat!("sbtp-cli-demo/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self {
            base: base.to_owned(),
            agent,
        })
    }

    /// The base URL, without a trailing `/`.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// `GET /sbtp/v1/info` (spec §4). Members other than `min_pow_difficulty` and `max_future_ms`
    /// are ignored.
    ///
    /// # Errors
    ///
    /// A network failure, an error status, or a body without valid `min_pow_difficulty` and
    /// `max_future_ms`.
    pub fn info(&self) -> Result<Info, Fail> {
        let url = format!("{}/sbtp/v1/info", self.base);
        let mut response = self.agent.get(&url).call().map_err(|e| self.network(&e))?;
        if response.status() != StatusCode::OK {
            return Err(self.refusal("GET /sbtp/v1/info", &mut response));
        }
        let body = read_limited(&mut response, MAX_JSON_LEN).map_err(|e| self.network(&e))?;
        parse_info(&body)
    }

    /// `PUT /sbtp/v1/block` with `block` as the body (spec §4). `200` and `201` are the same
    /// success (spec §4); the variant only says which one the relay sent.
    ///
    /// # Errors
    ///
    /// A network failure, or the relay's error status with its `{error, message}` body.
    pub fn put_block(&self, block: &[u8]) -> Result<Stored, Fail> {
        let url = format!("{}/sbtp/v1/block", self.base);
        let mut response = self
            .agent
            .put(&url)
            .content_type("application/octet-stream")
            .send(block)
            .map_err(|e| self.network(&e))?;
        match response.status() {
            StatusCode::CREATED => Ok(Stored::Created),
            StatusCode::OK => Ok(Stored::AlreadyStored),
            _ => Err(self.refusal("PUT /sbtp/v1/block", &mut response)),
        }
    }

    /// `GET /sbtp/v1/block/{block_id}` (spec §4). Returns the raw, **unverified** bytes: the
    /// caller MUST validate them against `id` (spec §3.4) before any use.
    ///
    /// # Errors
    ///
    /// A network failure, the relay's error status, or a body longer than `MAX_BLOCK_LEN`.
    pub fn get_block(&self, id: &BlockId) -> Result<Vec<u8>, Fail> {
        // spec §4: a block_id in a path is 64 lowercase hexadecimal characters (`Display`).
        let url = format!("{}/sbtp/v1/block/{id}", self.base);
        let mut response = self.agent.get(&url).call().map_err(|e| self.network(&e))?;
        if response.status() != StatusCode::OK {
            let what = format!("GET /sbtp/v1/block/{id}");
            let mut fail = self.refusal(&what, &mut response);
            if response.status() == StatusCode::NOT_FOUND {
                // spec §4: a relay MAY evict; a 404 does not mean the block does not exist.
                fail.message.push_str(
                    "\nThe relay does not hold this block. It may never have received it, or \
                     may have evicted it.",
                );
            }
            return Err(fail);
        }
        read_limited(&mut response, MAX_BLOCK_LEN as u64).map_err(|e| match e {
            ureq::Error::BodyExceedsLimit(_) => Fail::invalid(format!(
                "the relay sent more than {MAX_BLOCK_LEN} bytes for {id}: not a block (TooLong)"
            )),
            e => self.network(&e),
        })
    }

    fn network(&self, e: &ureq::Error) -> Fail {
        let hint = match e {
            ureq::Error::ConnectionFailed | ureq::Error::Io(_) | ureq::Error::HostNotFound => {
                "\nIs a relay running at this address?"
            }
            ureq::Error::Timeout(_) => "\nThe relay did not answer in time.",
            _ => "",
        };
        Fail::failed(format!(
            "request to relay {} failed: {}{hint}",
            self.base,
            untrusted(&e.to_string(), MAX_SHOWN_CHARS)
        ))
    }

    /// The message for an error status: status line, then the relay's `{error, message}` body
    /// if it has one (spec §4 "Errors": a client accepts a missing or unparseable body).
    fn refusal(&self, what: &str, response: &mut Response<ureq::Body>) -> Fail {
        let body = read_limited(response, MAX_JSON_LEN).ok();
        self.refusal_text(what, response, body.as_deref())
    }

    /// [`Relay::refusal`] with the error body already read.
    fn refusal_text(
        &self,
        what: &str,
        response: &Response<ureq::Body>,
        body: Option<&[u8]>,
    ) -> Fail {
        let status = response.status();
        let mut text = format!(
            "relay {} answered {what} with {} {}",
            self.base,
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        );
        if let Some(body) = body.and_then(error_body) {
            text.push_str(": ");
            text.push_str(&body);
        }
        if let Some(after) = retry_after_text(response) {
            // spec §4 "Admission control": a client MUST NOT repeat before Retry-After.
            text.push_str("\nRetry after ");
            text.push_str(&untrusted(after, 20));
            text.push_str(" seconds, not before.");
        }
        if status.is_redirection() {
            text.push_str("\nA relay does not redirect: check the URL.");
        }
        Fail::refused(text)
    }

    /// `GET /sbtp/v1/query` (spec §4): one page, checked, or the classified failure.
    fn query_page(&self, filter: &Filter, cursor: Option<&str>) -> Result<Page, PageError> {
        let url = query_url(&self.base, filter, cursor);
        let mut response = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| PageError::Fatal(self.network(&e)))?;
        let status = response.status();
        if status == StatusCode::OK {
            let body = read_limited(&mut response, MAX_QUERY_LEN).map_err(|e| {
                PageError::Fatal(match e {
                    ureq::Error::BodyExceedsLimit(_) => Fail::failed(
                        "the relay's /query page is larger than 128 KiB; a valid page is under \
                         70 KiB",
                    ),
                    e => self.network(&e),
                })
            })?;
            return parse_page(&body, page_limit(filter)).map_err(PageError::Fatal);
        }
        let body = read_limited(&mut response, MAX_JSON_LEN).ok();
        let name = body.as_deref().and_then(error_name);
        let fail = self.refusal_text("GET /sbtp/v1/query", &response, body.as_deref());
        // A Retry-After that is not visible ASCII is present all the same (L-4).
        let retry_after = response
            .headers()
            .get("retry-after")
            .map(|v| v.to_str().unwrap_or(""));
        Err(classify(
            status.as_u16(),
            name.as_deref(),
            retry_after,
            fail,
        ))
    }
}

impl PageSource for &Relay {
    fn page(&mut self, filter: &Filter, cursor: Option<&str>) -> Result<Page, PageError> {
        self.query_page(filter, cursor)
    }
}

/// The `Retry-After` header as text, if present.
fn retry_after_text(response: &Response<ureq::Body>) -> Option<&str> {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
}

/// The URL of one `/query` request. Every value is URL-safe as is: a `block_id` is lowercase
/// hexadecimal (spec §4), numbers are decimal and a cursor is within `A-Z a-z 0-9 - _`.
fn query_url(base: &str, filter: &Filter, cursor: Option<&str>) -> String {
    let mut params: Vec<String> = Vec::new();
    if let Some(parent) = &filter.parent {
        params.push(format!("parent={parent}"));
    }
    if let Some(since) = filter.since {
        params.push(format!("since={since}"));
    }
    if let Some(limit) = filter.limit {
        params.push(format!("limit={limit}"));
    }
    if let Some(cursor) = cursor {
        params.push(format!("cursor={cursor}"));
    }
    let mut url = format!("{base}/sbtp/v1/query");
    if !params.is_empty() {
        url.push('?');
        url.push_str(&params.join("&"));
    }
    url
}

/// How the walk treats a `/query` failure. The status decides first, the error name refines
/// (spec §4 "Errors"):
/// - `400` `InvalidCursor`: restart without a cursor (ADR 0024 rule 8);
/// - `400` with any other name, `InvalidParameter` included, or with no readable name: stop
///   (ADR 0012 clarification K1);
/// - `429`, `500`, `502`, `503`, `504`: repeat later with the same cursor (ADR 0012 clarification
///   K2, spec §4 "Admission control"; `502` and `504` come from a reverse proxy);
/// - anything else: stop.
fn classify(status: u16, name: Option<&str>, retry_after: Option<&str>, fail: Fail) -> PageError {
    match (status, name) {
        (400, Some("InvalidCursor")) => PageError::InvalidCursor,
        (429 | 500 | 502 | 503 | 504, _) => match retry_after {
            None => PageError::Transient {
                status,
                retry_after: None,
                fail,
            },
            // The delay-seconds form (ADR 0012 rule 29).
            Some(text) => {
                if let Ok(seconds) = text.trim().parse::<u64>() {
                    PageError::Transient {
                        status,
                        retry_after: Some(seconds),
                        fail,
                    }
                } else {
                    // Present but not read (an HTTP-date, a fraction, an overflow): a client
                    // MUST NOT repeat before it has elapsed (spec §4 "Admission control", ADR
                    // 0012 rule 30), and a back-off could repeat early, so the walk stops
                    // (security review 2026-11-19 query, L-4). `refusal_text` shows the value.
                    let mut fail = fail;
                    fail.message.push_str(
                        "\nThis Retry-After is not a number of seconds; not repeating the \
                         request before it has elapsed.",
                    );
                    PageError::Fatal(fail)
                }
            }
        },
        _ => PageError::Fatal(fail),
    }
}

/// A `/query` page (spec §4): `block_ids` (at most `limit` lowercase `block_id` values), `cursor`
/// (ADR 0012 rule 5 syntax, clarification K1) and `more`. Unknown members are ignored.
fn parse_page(body: &[u8], limit: usize) -> Result<Page, Fail> {
    let bad = |what: &str| Fail::failed(format!("the relay's /query page is invalid: {what}"));
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| bad("not a JSON object"))?;
    let ids = value
        .get("block_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| bad("`block_ids` is not an array"))?;
    if ids.len() > limit {
        return Err(bad(&format!(
            "{} identifiers for a limit of {limit}",
            ids.len()
        )));
    }
    let block_ids = ids
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|t| t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                .and_then(crate::hex::block_id)
                .ok_or_else(|| bad("an identifier is not 64 lowercase hexadecimal characters"))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let cursor = value
        .get("cursor")
        .and_then(serde_json::Value::as_str)
        .filter(|c| is_cursor_syntax(c))
        .ok_or_else(|| bad("`cursor` is missing or not 1 to 128 characters of `A-Za-z0-9-_`"))?
        .to_owned();
    let more = value
        .get("more")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| bad("`more` is not a boolean"))?;
    Ok(Page {
        block_ids,
        cursor,
        more,
    })
}

/// The `error` member of an error body, as sent: compared, never shown.
fn error_name(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("error")?.as_str().map(str::to_owned)
}

/// Reads the body if it is at most `max` bytes; `BodyExceedsLimit` otherwise.
///
/// ureq 3.5.1's body limit fails on the read that would observe the end of the body once `limit`
/// bytes are in (security review 2026-11-19, M-1): a body of exactly `limit` bytes is refused. The
/// limit is therefore `max + 1`, and the length is decided here.
fn read_limited(response: &mut Response<ureq::Body>, max: u64) -> Result<Vec<u8>, ureq::Error> {
    let body = response
        .body_mut()
        .with_config()
        .limit(max.saturating_add(1))
        .read_to_vec()?;
    if body.len() as u64 > max {
        return Err(ureq::Error::BodyExceedsLimit(max));
    }
    Ok(body)
}

/// `error` and, if present, `message` of an error body, escaped for the terminal.
fn error_body(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let error = value.get("error")?.as_str()?;
    let mut text = untrusted(error, 64);
    if let Some(message) = value.get("message").and_then(serde_json::Value::as_str) {
        text.push_str(" (");
        text.push_str(&untrusted(message, MAX_SHOWN_CHARS));
        text.push(')');
    }
    Some(text)
}

/// The members of `/info` the CLI needs (spec §4: a client MUST accept the absence of the others
/// and ignore unknown members).
fn parse_info(body: &[u8]) -> Result<Info, Fail> {
    let bad = |what: &str| Fail::failed(format!("the relay's /sbtp/v1/info is invalid: {what}"));
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| bad("not a JSON object"))?;
    let min_pow_difficulty = value
        .get("min_pow_difficulty")
        .and_then(serde_json::Value::as_u64)
        .filter(|d| *d <= u64::from(sbtp_core::MAX_DIFFICULTY))
        .and_then(|d| u32::try_from(d).ok())
        .ok_or_else(|| bad("`min_pow_difficulty` is not an integer from 0 to 256"))?;
    let max_future_ms = value
        .get("max_future_ms")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| bad("`max_future_ms` is not a non-negative integer"))?;
    Ok(Info {
        min_pow_difficulty,
        max_future_ms,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            Relay::new("http://127.0.0.1:8080/").unwrap().base(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            Relay::new("http://relay.test/prefix").unwrap().base(),
            "http://relay.test/prefix"
        );
        for bad in [
            "https://relay.test",
            "relay.test",
            "http://",
            "http://user@relay.test",
            "http://relay.test/?x=1",
            "http://relay.test/#x",
            "http://relay test",
        ] {
            assert!(Relay::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn info_members() {
        let i = parse_info(br#"{"min_pow_difficulty":16,"max_future_ms":300000,"x":[1]}"#).unwrap();
        assert_eq!(i.min_pow_difficulty, 16);
        assert_eq!(i.max_future_ms, 300_000);
        assert!(parse_info(br#"{"min_pow_difficulty":257,"max_future_ms":1}"#).is_err());
        assert!(parse_info(br#"{"min_pow_difficulty":-1,"max_future_ms":1}"#).is_err());
        assert!(parse_info(br#"{"max_future_ms":1}"#).is_err());
        assert!(parse_info(br#"{"min_pow_difficulty":16}"#).is_err());
        assert!(parse_info(b"not json").is_err());
    }

    #[test]
    fn error_bodies() {
        assert_eq!(
            error_body(br#"{"error":"InsufficientPow","message":"too easy","extra":1}"#).unwrap(),
            "InsufficientPow (too easy)"
        );
        assert_eq!(error_body(br#"{"error":"NotFound"}"#).unwrap(), "NotFound");
        assert_eq!(
            error_body(br#"{"error":"X\u001b[2J"}"#).unwrap(),
            "X\\u{1b}[2J"
        );
        assert!(error_body(b"<html>proxy</html>").is_none());
        assert!(error_body(br#"{"message":"no error member"}"#).is_none());
    }

    #[test]
    fn query_urls() {
        let mut f = Filter::default();
        assert_eq!(query_url("http://r", &f, None), "http://r/sbtp/v1/query");
        f.parent = Some(BlockId::from_bytes([0xab; 32]));
        f.since = Some(17);
        f.limit = Some(2);
        assert_eq!(
            query_url("http://r", &f, Some("k3_Z-0")),
            format!(
                "http://r/sbtp/v1/query?parent={}&since=17&limit=2&cursor=k3_Z-0",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn query_pages() {
        let id = "0a".repeat(32);
        let page = parse_page(
            format!(r#"{{"block_ids":["{id}"],"cursor":"c_1-x","more":true,"x":0}}"#).as_bytes(),
            1,
        )
        .unwrap();
        assert_eq!(page.block_ids, [BlockId::from_bytes([0x0a; 32])]);
        assert_eq!(page.cursor, "c_1-x");
        assert!(page.more);
        let empty = parse_page(br#"{"block_ids":[],"cursor":"c","more":false}"#, 100).unwrap();
        assert!(empty.block_ids.is_empty() && !empty.more);

        let upper = "0A".repeat(32);
        for bad in [
            // More identifiers than the limit asked for.
            format!(r#"{{"block_ids":["{id}","{id}"],"cursor":"c","more":true}}"#),
            // Uppercase, short, not a string.
            format!(r#"{{"block_ids":["{upper}"],"cursor":"c","more":true}}"#),
            r#"{"block_ids":["0a"],"cursor":"c","more":true}"#.to_owned(),
            r#"{"block_ids":[1],"cursor":"c","more":true}"#.to_owned(),
            // Cursor outside the syntax, or missing; `more` missing.
            r#"{"block_ids":[],"cursor":"a+b","more":true}"#.to_owned(),
            r#"{"block_ids":[],"cursor":"","more":true}"#.to_owned(),
            format!(
                r#"{{"block_ids":[],"cursor":"{}","more":true}}"#,
                "a".repeat(129)
            ),
            r#"{"block_ids":[],"more":true}"#.to_owned(),
            r#"{"block_ids":[],"cursor":"c"}"#.to_owned(),
            r#"{"cursor":"c","more":false}"#.to_owned(),
            "not json".to_owned(),
        ] {
            assert!(parse_page(bad.as_bytes(), 1).is_err(), "{bad}");
        }
    }

    #[test]
    fn page_limits() {
        let mut f = Filter::default();
        assert_eq!(page_limit(&f), 100);
        f.limit = Some(5);
        assert_eq!(page_limit(&f), 5);
        f.limit = Some(u32::MAX);
        assert_eq!(page_limit(&f), 1000);
    }

    /// ADR 0024 rule 8 and ADR 0012 clarifications K1, K2.
    #[test]
    fn query_failures_are_classified() {
        let fail = || Fail::refused("x");
        assert!(matches!(
            classify(400, Some("InvalidCursor"), None, fail()),
            PageError::InvalidCursor
        ));
        for (status, name) in [
            (400, Some("InvalidParameter")),
            (400, None),
            (400, Some("invalidcursor")),
            (404, Some("InvalidCursor")),
            (403, None),
            (501, None),
        ] {
            assert!(
                matches!(classify(status, name, None, fail()), PageError::Fatal(_)),
                "{status} {name:?}"
            );
        }
        for status in [429, 500, 502, 503, 504] {
            assert!(matches!(
                classify(status, Some("Internal"), None, fail()),
                PageError::Transient {
                    retry_after: None,
                    ..
                }
            ));
        }
        assert!(matches!(
            classify(503, None, Some("12"), fail()),
            PageError::Transient {
                retry_after: Some(12),
                ..
            }
        ));
        // L-4: present but unreadable (HTTP-date, fraction, overflow, not text): stop, never an
        // early repeat through the back-off.
        for unread in [
            "Wed, 21 Oct 2026 07:28:00 GMT",
            "1.5",
            "18446744073709551616",
            "-1",
            "",
        ] {
            match classify(429, None, Some(unread), fail()) {
                PageError::Fatal(f) => assert!(f.message.contains("not a number of seconds")),
                other => panic!("{unread:?}: {other:?}"),
            }
        }
    }
}
