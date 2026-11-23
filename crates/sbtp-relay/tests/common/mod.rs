//! Test harness: a relay on a loopback port with a temporary store, a raw HTTP/1.1 client and a
//! block builder. Keys come from public seeds only.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]
#![allow(
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use sbtp_core::{BlockId, SigningKey, UnsignedBlock};
use sbtp_relay::Config;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Proof of work used by the tests: cheap to mine in a debug build.
pub const TEST_POW: u32 = 8;

pub struct Relay {
    pub addr: SocketAddr,
    pub dir: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

/// A config with test-friendly values; `dir` holds the store.
pub fn config(dir: &TempDir) -> Config {
    let mut c = Config::new(dir.path().to_path_buf());
    c.min_pow_difficulty = TEST_POW;
    c.deny_reload = Duration::from_millis(50);
    c
}

impl Relay {
    pub async fn start(config: Config) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dir = config.data_dir.clone();
        let (stop, rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            sbtp_relay::run(listener, config, shutdown)
                .await
                .map_err(|e| e.to_string())
                .unwrap();
        });
        Self {
            addr,
            dir,
            stop: Some(stop),
            task: Some(task),
        }
    }

    /// Stops the relay and waits for it to release the store.
    pub async fn stop(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap();
    }

    pub async fn request(&self, method: &str, path: &str, body: &[u8]) -> Response {
        self.raw(method, path, &[], body).await
    }

    pub async fn get(&self, path: &str) -> Response {
        self.request("GET", path, &[]).await
    }

    pub async fn put(&self, block: &[u8]) -> Response {
        self.request("PUT", "/sbtp/v1/block", block).await
    }

    /// Sends a request with a correct `Content-Length` and extra headers.
    pub async fn raw(&self, method: &str, path: &str, headers: &[&str], body: &[u8]) -> Response {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: relay\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for h in headers {
            head.push_str(h);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(body);
        self.send_raw(&bytes).await
    }

    /// Writes `bytes` as they are and reads the whole response.
    pub async fn send_raw(&self, bytes: &[u8]) -> Response {
        let mut tcp = TcpStream::connect(self.addr).await.unwrap();
        tcp.write_all(bytes).await.unwrap();
        read_response(&mut tcp).await
    }

    pub async fn info(&self) -> HashMap<String, String> {
        let r = self.get("/sbtp/v1/info").await;
        assert_eq!(r.status, 200);
        parse_flat_json(&r.text())
    }

    pub fn ws_url(&self, query: &str) -> String {
        format!("ws://{}/sbtp/v1/subscribe?{query}", self.addr)
    }

    pub fn write_deny(&self, text: &str) {
        std::fs::write(self.dir.join("deny.txt"), text).unwrap();
    }
}

pub async fn read_response(tcp: &mut TcpStream) -> Response {
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut raw)).await;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Response {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// The `error` member of a spec §5 error body, checking its headers.
    pub fn error(&self) -> String {
        assert_eq!(
            self.header("content-type"),
            Some("application/json"),
            "{self:?}"
        );
        assert_eq!(self.header("cache-control"), Some("no-store"));
        parse_flat_json(&self.text())["error"].clone()
    }
}

/// Members of a JSON object whose values are strings, numbers, booleans or arrays of strings
/// (arrays are returned joined with commas, without quotes). Enough for the relay's bodies.
pub fn parse_flat_json(text: &str) -> HashMap<String, String> {
    let inner = text
        .trim()
        .strip_prefix('{')
        .unwrap()
        .strip_suffix('}')
        .unwrap();
    let mut out = HashMap::new();
    let mut rest = inner;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let end = after.find('"').unwrap();
        let key = after[..end].to_string();
        let value_part = after[end + 1..]
            .trim_start()
            .strip_prefix(':')
            .unwrap()
            .trim_start();
        let (value, next) = if let Some(arr) = value_part.strip_prefix('[') {
            let close = arr.find(']').unwrap();
            (arr[..close].replace('"', ""), &arr[close + 1..])
        } else if let Some(s) = value_part.strip_prefix('"') {
            let close = s.find('"').unwrap();
            (s[..close].to_string(), &s[close + 1..])
        } else {
            let close = value_part.find([',', '}']).unwrap_or(value_part.len());
            (value_part[..close].trim().to_string(), &value_part[close..])
        };
        out.insert(key, value);
        rest = next.trim_start().strip_prefix(',').unwrap_or(next);
    }
    out
}

/// A deterministic test key from a public seed.
pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A signed block mined at `difficulty`.
pub fn block_with(
    key: &SigningKey,
    parents: &[BlockId],
    payload: &[u8],
    timestamp: u64,
    difficulty: u32,
) -> (BlockId, Vec<u8>) {
    let mut unsigned = UnsignedBlock {
        timestamp,
        nonce: 0,
        pubkey: key.verifying_key().to_bytes(),
        parents,
        payload,
    };
    let id = unsigned.mine(difficulty, u64::MAX).unwrap();
    (id, unsigned.sign(key).unwrap())
}

/// A valid block at [`TEST_POW`] with the given parents and payload.
pub fn block(parents: &[BlockId], payload: &[u8]) -> (BlockId, Vec<u8>) {
    block_with(&key(1), parents, payload, now_ms(), TEST_POW)
}
