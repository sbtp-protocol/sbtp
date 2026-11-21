//! The HTTP client side of the relay interface (spec §4): `GET /sbtp/v1/info`,
//! `PUT /sbtp/v1/block`, `GET /sbtp/v1/block/{block_id}`, `GET /sbtp/v1/query`, and the read API
//! of ADR 0051: `POST /sbtp/v1/blocks`, `order`, `fields=parents`, `head` and several `parent`.
//! The ADR 0051 forms are sent only to a relay whose `/info` says `read_api >= 2` (rule 31): the
//! commands check [`Info::read_api`] first.
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
use crate::walk::{
    Filter, Group, GroupEntry, GroupSource, Hint, Page, PageError, PageSource, is_cursor_syntax,
    page_limit,
};

/// Deadline of one request, connection included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest JSON body read (`/info`, error bodies).
const MAX_JSON_LEN: u64 = 16 * 1024;
/// Largest `/query` body read: ADR 0012 rule 14 bounds a page under 70 KiB.
const MAX_QUERY_LEN: u64 = 128 * 1024;
/// Longest relay text shown to the user (spec §4 "Errors": `message` is at most 200 characters).
const MAX_SHOWN_CHARS: usize = 200;
/// Body ceiling of `POST /sbtp/v1/blocks` (ADR 0051 rule 4).
pub const MAX_BATCH_BODY: u64 = 1_048_576;
/// Identifiers in one `POST /sbtp/v1/blocks` (ADR 0051 rule 1).
pub const MAX_BATCH_IDS: usize = 256;
/// `read_api` from which ADR 0051 applies (rule 31).
pub const READ_API: u32 = 2;

/// The records of one `POST /sbtp/v1/blocks` answer (ADR 0051 rules 2, 3, 6): one per requested
/// identifier of a prefix of the request, in request order, each the raw **unverified** bytes, or
/// `None` for `length = 0` (not served).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Batch {
    /// The complete records.
    pub records: Vec<Option<Vec<u8>>>,
    /// The body ended inside a record: a failed request for the rest (rule 6); the complete
    /// records before it may be used, each checked on its own.
    pub truncated: bool,
}

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
    /// `read_api` (ADR 0051 rule 31): 1 when absent, or when not a positive integer.
    pub read_api: u32,
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

    /// `POST /sbtp/v1/blocks` (ADR 0051 rules 1 to 6), for a relay with `read_api >= 2` only:
    /// 1 to 256 distinct identifiers. Returns the records of a prefix of `ids`, raw and
    /// **unverified**: the caller MUST validate each against the identifier at its position (R1 and
    /// full validation, spec §3.4) before any use, and asks again for the rest (rule 3).
    ///
    /// # Errors
    ///
    /// A network failure, the relay's error status, a body over 1 MiB, or a failed request by
    /// [`parse_records`].
    pub fn post_blocks(&self, ids: &[BlockId]) -> Result<Batch, Fail> {
        if ids.is_empty() || ids.len() > MAX_BATCH_IDS {
            return Err(Fail::failed(format!(
                "internal error: a batch of {} identifiers",
                ids.len()
            )));
        }
        let body: Vec<u8> = ids.iter().flat_map(|id| *id.as_bytes()).collect();
        let url = format!("{}/sbtp/v1/blocks", self.base);
        let mut response = self
            .agent
            .post(&url)
            .content_type("application/octet-stream")
            .send(&body[..])
            .map_err(|e| self.network(&e))?;
        if response.status() != StatusCode::OK {
            return Err(self.refusal("POST /sbtp/v1/blocks", &mut response));
        }
        let bytes = read_limited(&mut response, MAX_BATCH_BODY).map_err(|e| match e {
            ureq::Error::BodyExceedsLimit(_) => Fail::failed(format!(
                "relay {} sent a POST /sbtp/v1/blocks body above 1 MiB (ADR 0051 rule 4)",
                self.base
            )),
            e => self.network(&e),
        })?;
        parse_records(&bytes, ids.len()).map_err(|why| {
            Fail::failed(format!(
                "relay {} sent an invalid POST /sbtp/v1/blocks body: {why}",
                self.base
            ))
        })
    }

    /// Grouped `GET /sbtp/v1/query` (ADR 0051 rules 21 to 24), for a relay with `read_api >= 2`
    /// only: 2 to 32 distinct parents, each with its own cursor. One parent uses the plain form.
    fn query_group(
        &self,
        parents: &[(BlockId, Option<String>)],
        filter: &Filter,
    ) -> Result<Group, PageError> {
        if let [(parent, cursor)] = parents {
            let single = Filter {
                parent: Some(*parent),
                fields: false,
                ..filter.clone()
            };
            let page = self.query_page(&single, cursor.as_deref())?;
            let head = page.head.ok_or_else(|| {
                PageError::Fatal(Fail::failed(
                    "the relay's /query page has no head, though its /info says read_api 2",
                ))
            })?;
            return Ok(Group {
                entries: vec![GroupEntry {
                    parent: *parent,
                    block_ids: page.block_ids,
                    cursor: page.cursor,
                    more: page.more,
                }],
                head,
            });
        }
        let url = group_url(&self.base, parents, filter);
        let body = self.query_body(&url)?;
        let requested: Vec<BlockId> = parents.iter().map(|(p, _)| *p).collect();
        parse_group(&body, &requested, page_limit(filter)).map_err(PageError::Fatal)
    }

    /// One `/query` request: the `200` body, or the classified failure.
    fn query_body(&self, url: &str) -> Result<Vec<u8>, PageError> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| PageError::Fatal(self.network(&e)))?;
        let status = response.status();
        if status == StatusCode::OK {
            return read_limited(&mut response, MAX_QUERY_LEN).map_err(|e| {
                PageError::Fatal(match e {
                    ureq::Error::BodyExceedsLimit(_) => Fail::failed(
                        "the relay's /query page is larger than 128 KiB, the ceiling of a valid \
                         page (ADR 0029, ADR 0051 rules 14 and 24)",
                    ),
                    e => self.network(&e),
                })
            });
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
        let body = self.query_body(&url)?;
        parse_page(&body, page_limit(filter), filter.fields).map_err(PageError::Fatal)
    }
}

impl PageSource for &Relay {
    fn page(&mut self, filter: &Filter, cursor: Option<&str>) -> Result<Page, PageError> {
        self.query_page(filter, cursor)
    }
}

impl GroupSource for &Relay {
    fn group(
        &mut self,
        parents: &[(BlockId, Option<String>)],
        filter: &Filter,
    ) -> Result<Group, PageError> {
        self.query_group(parents, filter)
    }
}

/// `since`, `limit` and `order` of a `/query` request, in that order (ADR 0051: `order` only when
/// `desc`, so that a request without it is the one an older relay understands).
fn common_params(filter: &Filter, params: &mut Vec<String>) {
    if let Some(since) = filter.since {
        params.push(format!("since={since}"));
    }
    if let Some(limit) = filter.limit {
        params.push(format!("limit={limit}"));
    }
    if filter.desc {
        params.push("order=desc".to_owned());
    }
}

/// The URL of a grouped `/query` (ADR 0051 rule 21): `parent=<id>` or `parent=<id>.<cursor>` per
/// parent; `.` is outside the cursor alphabet and needs no percent-encoding.
fn group_url(base: &str, parents: &[(BlockId, Option<String>)], filter: &Filter) -> String {
    let mut params: Vec<String> = parents
        .iter()
        .map(|(p, c)| match c {
            Some(c) => format!("parent={p}.{c}"),
            None => format!("parent={p}"),
        })
        .collect();
    common_params(filter, &mut params);
    format!("{base}/sbtp/v1/query?{}", params.join("&"))
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
    common_params(filter, &mut params);
    if filter.fields {
        params.push("fields=parents".to_owned());
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

/// The error of an invalid `/query` page.
fn bad_page(what: &str) -> Fail {
    Fail::failed(format!("the relay's /query page is invalid: {what}"))
}

/// One `block_id` string of a relay: exactly 64 lowercase hexadecimal characters (spec §4).
fn wire_id(v: &serde_json::Value) -> Result<BlockId, Fail> {
    v.as_str()
        .filter(|t| t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .and_then(crate::hex::block_id)
        .ok_or_else(|| bad_page("an identifier is not 64 lowercase hexadecimal characters"))
}

/// `block_ids` (at most `limit`), `cursor` and `more` of a page or of a grouped entry.
fn page_members(
    value: &serde_json::Value,
    limit: usize,
) -> Result<(Vec<BlockId>, String, bool), Fail> {
    let ids = value
        .get("block_ids")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| bad_page("`block_ids` is not an array"))?;
    if ids.len() > limit {
        return Err(bad_page(&format!(
            "{} identifiers for a limit of {limit}",
            ids.len()
        )));
    }
    let block_ids = ids.iter().map(wire_id).collect::<Result<Vec<_>, Fail>>()?;
    let cursor = value
        .get("cursor")
        .and_then(serde_json::Value::as_str)
        .filter(|c| is_cursor_syntax(c))
        .ok_or_else(|| bad_page("`cursor` is missing or not 1 to 128 characters of `A-Za-z0-9-_`"))?
        .to_owned();
    let more = value
        .get("more")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| bad_page("`more` is not a boolean"))?;
    Ok((block_ids, cursor, more))
}

/// `head` (ADR 0051 rule 18): `None` when absent (a relay before `read_api` 2); a member that is
/// not a cursor makes the response a failed request.
fn page_head(value: &serde_json::Value) -> Result<Option<String>, Fail> {
    match value.get("head") {
        None => Ok(None),
        Some(h) => h
            .as_str()
            .filter(|c| is_cursor_syntax(c))
            .map(|c| Some(c.to_owned()))
            .ok_or_else(|| bad_page("`head` is not a cursor")),
    }
}

/// The `parents` and `lens` members of `fields=parents` (ADR 0051 rule 13), aligned with `n`
/// identifiers.
fn page_hints(value: &serde_json::Value, n: usize) -> Result<Vec<Hint>, Fail> {
    let parents = value
        .get("parents")
        .and_then(serde_json::Value::as_array)
        .filter(|a| a.len() == n);
    let lens = value
        .get("lens")
        .and_then(serde_json::Value::as_array)
        .filter(|a| a.len() == n);
    let (Some(parents), Some(lens)) = (parents, lens) else {
        return Err(bad_page(
            "with fields=parents, `parents` and `lens` are not arrays aligned with `block_ids`",
        ));
    };
    parents
        .iter()
        .zip(lens)
        .map(|(p, l)| {
            let p = p
                .as_array()
                .filter(|a| a.len() <= usize::from(sbtp_core::layout::MAX_PARENTS))
                .ok_or_else(|| bad_page("a `parents` entry is not an array of at most 8"))?;
            let len = l
                .as_u64()
                .filter(|l| (1..=MAX_BLOCK_LEN as u64).contains(l))
                .and_then(|l| u32::try_from(l).ok())
                .ok_or_else(|| bad_page("a `lens` entry is not a block length"))?;
            Ok(Hint {
                parents: p.iter().map(wire_id).collect::<Result<Vec<_>, Fail>>()?,
                len,
            })
        })
        .collect()
}

/// A `/query` page (spec §4): `block_ids` (at most `limit` lowercase `block_id` values), `cursor`
/// (ADR 0012 rule 5 syntax, clarification K1) and `more`; `head` when sent; with `fields`, the
/// hints of ADR 0051 rule 13. Unknown members are ignored.
fn parse_page(body: &[u8], limit: usize, fields: bool) -> Result<Page, Fail> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| bad_page("not a JSON object"))?;
    let (block_ids, cursor, more) = page_members(&value, limit)?;
    let head = page_head(&value)?;
    let hints = if fields {
        Some(page_hints(&value, block_ids.len())?)
    } else {
        None
    };
    Ok(Page {
        block_ids,
        cursor,
        more,
        head,
        hints,
    })
}

/// A grouped `/query` response (ADR 0051 rule 24) for `requested`: one entry per parent, in
/// request order, each at most `limit` identifiers, at most `max(N, 1000)` in all (rule 23), and
/// `head`.
fn parse_group(body: &[u8], requested: &[BlockId], limit: usize) -> Result<Group, Fail> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| bad_page("not a JSON object"))?;
    let list = value
        .get("parents")
        .and_then(serde_json::Value::as_array)
        .filter(|a| a.len() == requested.len())
        .ok_or_else(|| bad_page("`parents` is not one entry per parent requested"))?;
    let mut entries = Vec::with_capacity(list.len());
    let mut total = 0usize;
    for (entry, want) in list.iter().zip(requested) {
        let parent = entry
            .get("parent")
            .ok_or_else(|| bad_page("an entry has no `parent`"))
            .and_then(wire_id)?;
        if parent != *want {
            return Err(bad_page(
                "an entry does not match the parent requested at its position",
            ));
        }
        let (block_ids, cursor, more) = page_members(entry, limit)?;
        total = total.saturating_add(block_ids.len());
        entries.push(GroupEntry {
            parent,
            block_ids,
            cursor,
            more,
        });
    }
    if total > requested.len().max(1000) {
        return Err(bad_page(
            "more identifiers in all than ADR 0051 rule 23 allows",
        ));
    }
    let head = page_head(&value)?.ok_or_else(|| bad_page("a grouped response has no `head`"))?;
    Ok(Group { entries, head })
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
    // ADR 0051 rule 31: absent reads as 1; anything that is not a positive integer too, so that
    // the new forms go only to a relay that clearly announces them.
    let read_api = value
        .get("read_api")
        .and_then(serde_json::Value::as_u64)
        .filter(|v| *v >= 1)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(1);
    Ok(Info {
        min_pow_difficulty,
        max_future_ms,
        read_api,
    })
}

/// The records of a `POST /sbtp/v1/blocks` body for `count` requested identifiers (ADR 0051 rules
/// 2, 3, 6). A length above `MAX_BLOCK_LEN`, more records than identifiers, or no record at all
/// makes the response a failed request (`Err`); a body ending inside a record or a length gives the
/// complete records before it with `truncated`.
///
/// # Errors
///
/// The reason the response is a failed request, for the user.
pub fn parse_records(body: &[u8], count: usize) -> Result<Batch, String> {
    let mut batch = Batch::default();
    let mut rest = body;
    while !rest.is_empty() {
        if batch.records.len() >= count {
            return Err("more records than identifiers requested".to_owned());
        }
        let (Some(len), Some(after)) = (rest.get(..4), rest.get(4..)) else {
            batch.truncated = true;
            return Ok(batch);
        };
        let mut be = [0u8; 4];
        be.copy_from_slice(len);
        let len = u32::from_be_bytes(be);
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if len > MAX_BLOCK_LEN {
            return Err(format!(
                "a record of {len} bytes, above the largest block ({MAX_BLOCK_LEN})"
            ));
        }
        let (Some(record), Some(next)) = (after.get(..len), after.get(len..)) else {
            batch.truncated = true;
            return Ok(batch);
        };
        batch.records.push(if len == 0 {
            None
        } else {
            Some(record.to_vec())
        });
        rest = next;
    }
    if batch.records.is_empty() {
        return Err("a 200 answer with no record".to_owned());
    }
    Ok(batch)
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
            false,
        )
        .unwrap();
        assert_eq!(page.block_ids, [BlockId::from_bytes([0x0a; 32])]);
        assert_eq!(page.cursor, "c_1-x");
        assert!(page.more);
        assert_eq!(page.head, None);
        let empty =
            parse_page(br#"{"block_ids":[],"cursor":"c","more":false}"#, 100, false).unwrap();
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
            assert!(parse_page(bad.as_bytes(), 1, false).is_err(), "{bad}");
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
        // ADR 0051 rule 14.
        f.fields = true;
        assert_eq!(page_limit(&f), 200);
    }

    /// ADR 0051 rule 31: absent or malformed `read_api` reads as 1.
    #[test]
    fn info_read_api() {
        let info = |extra: &str| {
            parse_info(format!(r#"{{"min_pow_difficulty":8,"max_future_ms":1{extra}}}"#).as_bytes())
                .unwrap()
                .read_api
        };
        assert_eq!(info(""), 1);
        assert_eq!(info(r#","read_api":2"#), 2);
        for bad in [
            r#","read_api":"2""#,
            r#","read_api":0"#,
            r#","read_api":-2"#,
            r#","read_api":2.5"#,
        ] {
            assert_eq!(info(bad), 1, "{bad}");
        }
    }

    /// ADR 0051 rules 2, 3, 6: framing, length 0, prefix, truncation, a length above the ceiling,
    /// more records than identifiers, an empty `200`.
    #[test]
    fn batch_records() {
        let rec = |b: &[u8]| {
            let mut v = u32::try_from(b.len()).unwrap().to_be_bytes().to_vec();
            v.extend_from_slice(b);
            v
        };
        let body = [rec(b"abc"), rec(b""), rec(b"z")].concat();
        let batch = parse_records(&body, 3).unwrap();
        assert_eq!(
            batch.records,
            [Some(b"abc".to_vec()), None, Some(b"z".to_vec())]
        );
        assert!(!batch.truncated);
        // A prefix.
        assert_eq!(parse_records(&rec(b"abc"), 3).unwrap().records.len(), 1);
        // Truncated inside a record, and inside a length: the complete records are kept.
        let two = [rec(b"abc"), rec(b"de")].concat();
        for cut in [two.len() - 1, 7 + 2] {
            let b = parse_records(two.get(..cut).unwrap(), 2).unwrap();
            assert_eq!(b.records, [Some(b"abc".to_vec())]);
            assert!(b.truncated);
        }
        // A length above MAX_BLOCK_LEN fails the whole response.
        let mut over = rec(b"abc");
        over.extend_from_slice(&u32::try_from(MAX_BLOCK_LEN + 1).unwrap().to_be_bytes());
        assert!(
            parse_records(&over, 2)
                .unwrap_err()
                .contains("above the largest block")
        );
        let max = rec(&vec![0u8; MAX_BLOCK_LEN]);
        assert_eq!(parse_records(&max, 1).unwrap().records.len(), 1);
        assert!(parse_records(&two, 1).unwrap_err().contains("more records"));
        assert!(parse_records(b"", 1).unwrap_err().contains("no record"));
    }

    /// ADR 0051 rules 13, 14, 18, 21, 24: URLs, hints, head, grouped responses.
    #[test]
    fn read_api_pages() {
        let (a, b) = (
            BlockId::from_bytes([0xa1; 32]),
            BlockId::from_bytes([0xb2; 32]),
        );
        let f = Filter {
            limit: Some(2),
            desc: true,
            ..Filter::default()
        };
        assert_eq!(
            group_url("http://r", &[(a, Some("c1".to_owned())), (b, None)], &f),
            format!("http://r/sbtp/v1/query?parent={a}.c1&parent={b}&limit=2&order=desc")
        );
        let wide = Filter {
            fields: true,
            ..Filter::default()
        };
        assert_eq!(
            query_url("http://r", &wide, Some("c")),
            "http://r/sbtp/v1/query?fields=parents&cursor=c"
        );

        let page = parse_page(
            format!(r#"{{"block_ids":["{a}"],"cursor":"c","more":false,"head":"h1","parents":[["{b}"]],"lens":[300]}}"#)
                .as_bytes(),
            10,
            true,
        )
        .unwrap();
        assert_eq!(page.head.as_deref(), Some("h1"));
        assert_eq!(
            page.hints.unwrap(),
            [Hint {
                parents: vec![b],
                len: 300
            }]
        );
        for bad in [
            format!(r#""parents":[["{b}"]]"#),
            r#""parents":[],"lens":[]"#.to_owned(),
            format!(r#""parents":[["{b}"]],"lens":[0]"#),
            format!(r#""parents":[["{b}"]],"lens":[65910]"#),
            format!(
                r#""parents":[[{}]],"lens":[1]"#,
                vec![format!("\"{b}\""); 9].join(",")
            ),
            r#""parents":[["B2"]],"lens":[1]"#.to_owned(),
        ] {
            let body = format!(r#"{{"block_ids":["{a}"],"cursor":"c","more":false,{bad}}}"#);
            assert!(parse_page(body.as_bytes(), 10, true).is_err(), "{bad}");
        }
        assert!(
            parse_page(
                br#"{"block_ids":[],"cursor":"c","more":false,"head":"a/b"}"#,
                1,
                false
            )
            .is_err()
        );

        let entry = |p: &BlockId, ids: &str| {
            format!(r#"{{"parent":"{p}","block_ids":[{ids}],"cursor":"c","more":false}}"#)
        };
        let ok = format!(
            r#"{{"parents":[{},{}],"head":"h"}}"#,
            entry(&a, &format!("\"{b}\"")),
            entry(&b, "")
        );
        let g = parse_group(ok.as_bytes(), &[a, b], 10).unwrap();
        assert_eq!(g.head, "h");
        assert_eq!(g.entries.len(), 2);
        assert_eq!(g.entries.first().unwrap().block_ids, [b]);
        for bad in [
            format!(
                r#"{{"parents":[{},{}],"head":"h"}}"#,
                entry(&b, ""),
                entry(&a, "")
            ),
            format!(r#"{{"parents":[{}],"head":"h"}}"#, entry(&a, "")),
            format!(r#"{{"parents":[{},{}]}}"#, entry(&a, ""), entry(&b, "")),
            format!(
                r#"{{"parents":[{},{}],"head":"h"}}"#,
                entry(&a, &format!("\"{b}\",\"{a}\",\"{b}\"")),
                entry(&b, "")
            ),
        ] {
            assert!(parse_group(bad.as_bytes(), &[a, b], 2).is_err(), "{bad}");
        }
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
