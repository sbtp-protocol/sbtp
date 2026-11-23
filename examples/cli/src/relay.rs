//! The relay routes used here: `/info`, `PUT` and `GET` of a block (SPEC §5, §7). Responses are
//! untrusted: bodies are read up to a fixed size, the status decides, and relay text reaches the
//! terminal only as an error name reduced to letters and digits.

use std::time::Duration;

use sbtp_core::{BlockId, MAX_BLOCK_LEN};
use serde_json::Value;
use ureq::Agent;

/// Attempts of one request on `429`, `502`, `503` or `504` before the status is reported.
const ATTEMPTS: u32 = 6;
/// A longer `Retry-After` is reported rather than waited for.
const MAX_WAIT: Duration = Duration::from_secs(300);
/// Largest difficulty mined: a relay asking for more would keep the CLI busy for days.
const MAX_MINED_DIFFICULTY: u64 = 32;
/// Largest JSON body read: `/info` and error bodies.
const MAX_JSON: u64 = 16_384;

pub struct Relay {
    agent: Agent,
    base: String,
}

impl Relay {
    pub fn new(url: &str) -> Self {
        let agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            // spec §5: a client MUST NOT follow a redirect.
            .max_redirects(0)
            .proxy(None)
            .build()
            .into();
        let base = url.trim_end_matches('/').to_owned();
        Self { agent, base }
    }

    /// Sends a request (a `PUT` of `block`, or a `GET`) and returns the status and the body.
    /// spec §7: `429`, `502`, `503` and `504` are retried, never before `Retry-After`, and without
    /// it with exponential back-off and jitter from 1 second.
    fn fetch(&self, path: &str, block: Option<&[u8]>, max: u64) -> Result<(u16, Vec<u8>), String> {
        let (url, agent) = (format!("{}{path}", self.base), &self.agent);
        let (mut backoff, mut attempt) = (Duration::from_secs(1), 1);
        let mut reply = loop {
            let reply = match block {
                Some(b) => agent
                    .put(&url)
                    .content_type("application/octet-stream")
                    .send(b),
                None => agent.get(&url).call(),
            };
            let reply = reply.map_err(|e| format!("relay unreachable: {e}"))?;
            let status = reply.status().as_u16();
            let after = reply
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok());
            let jitter = 1.0 + f64::from(getrandom::u32().unwrap_or(0)) / f64::from(u32::MAX);
            let after = after
                .and_then(|v| v.trim().parse().ok())
                .map(Duration::from_secs);
            let wait = after.unwrap_or_else(|| backoff.mul_f64(jitter));
            if !matches!(status, 429 | 502..=504) || attempt >= ATTEMPTS || wait > MAX_WAIT {
                break reply;
            }
            eprintln!(
                "relay answered {status}; retrying in {:.0} s",
                wait.as_secs_f32().ceil()
            );
            std::thread::sleep(wait);
            (backoff, attempt) = (backoff.saturating_mul(2), attempt.saturating_add(1));
        };
        let status = reply.status().as_u16();
        // ureq refuses a body of exactly its limit, hence `+ 1`.
        let body = reply
            .body_mut()
            .with_config()
            .limit(max.saturating_add(1))
            .read_to_vec();
        match body {
            Ok(body) if body.len() as u64 <= max => Ok((status, body)),
            // spec §5: an error body may be missing or unparseable (a proxy may answer).
            _ if status != 200 => Ok((status, Vec::new())),
            _ => Err("relay response unreadable or too large".into()),
        }
    }

    /// `min_pow_difficulty` from `/info`, which an author SHOULD read before mining (spec §5).
    pub fn min_pow_difficulty(&self) -> Result<u32, String> {
        let (status, body) = self.fetch("/sbtp/v1/info", None, MAX_JSON)?;
        if status != 200 {
            return Err(format!("/info: {}", refused(status, &body)));
        }
        let info: Option<Value> = serde_json::from_slice(&body).ok();
        let pow = info.and_then(|i| i.get("min_pow_difficulty")?.as_u64());
        let pow = pow
            .filter(|d| *d <= MAX_MINED_DIFFICULTY)
            .and_then(|d| u32::try_from(d).ok());
        pow.ok_or_else(|| "/info has no min_pow_difficulty of at most 32".into())
    }

    /// `PUT` a block; spec §5: `200` and `201` are the same success.
    pub fn put(&self, block: &[u8]) -> Result<&'static str, String> {
        match self.fetch("/sbtp/v1/block", Some(block), MAX_JSON)? {
            (201, _) => Ok("stored"),
            (200, _) => Ok("already-stored"),
            // spec §7: never resent automatically; no proof the block is invalid elsewhere.
            (451, body) => Err(format!(
                "{}: this relay's operator denies it",
                refused(451, &body)
            )),
            (status, body) => Err(format!("PUT refused: {}", refused(status, &body))),
        }
    }

    /// The bytes served for `id`, not validated yet: the caller runs SPEC §4 on them.
    pub fn block(&self, id: &BlockId) -> Result<Vec<u8>, String> {
        match self.fetch(&format!("/sbtp/v1/block/{id}"), None, MAX_BLOCK_LEN as u64)? {
            (200, bytes) => Ok(bytes),
            (status, body) => Err(format!("GET {id}: {}", refused(status, &body))),
        }
    }
}

/// The status and, when the body has one, the error name reduced to letters and digits.
fn refused(status: u16, body: &[u8]) -> String {
    let body = serde_json::from_slice::<Value>(body).ok();
    let name = body
        .as_ref()
        .and_then(|b| b.get("error")?.as_str())
        .unwrap_or_default();
    let name: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(64)
        .collect();
    format!("{status} {name}").trim_end().to_owned()
}
