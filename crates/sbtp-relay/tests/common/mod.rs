//! Helpers shared by the integration tests: settings from test environments, a server on a real
//! loopback socket, and a raw HTTP/1.1 client (so that the tests control every byte and timing).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use axum::Router;
use sbtp_relay::blocks::Relay;
use sbtp_relay::config::Settings;
use sbtp_relay::index::{IndexBackend, RedbIndex};
use sbtp_relay::pool::IndexPool;
use sbtp_relay::server::{ConnLimits, serve};
use sbtp_relay::store::{Store, reconcile};

/// A fresh, empty directory under Cargo's integration-test temporary directory.
pub fn tmp_dir(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// `SBTP_RELAY_<NAME>` pairs as an environment.
pub fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs
        .iter()
        .map(|(k, v)| (format!("SBTP_RELAY_{k}").into(), (*v).into()))
        .collect()
}

/// Settings from `pairs`, with `MIN_POW_DIFFICULTY = 16` unless given. Every test client comes
/// from `127.0.0.1` and shares one client key, so the `block` and `put` bursts are raised to the
/// top of their range unless given: a test of the token buckets sets its own rates.
pub fn settings(pairs: &[(&str, &str)]) -> Settings {
    let mut e = env(pairs);
    for (k, v) in [
        ("MIN_POW_DIFFICULTY", "16"),
        ("RATE_BLOCK_BURST", "1000000"),
        ("RATE_PUT_BURST", "1000000"),
    ] {
        if !pairs.iter().any(|(p, _)| *p == k) {
            e.extend(env(&[(k, v)]));
        }
    }
    Settings::load(Vec::<OsString>::new(), e).unwrap()
}

/// The relay's accept loop and middleware on `127.0.0.1:0`, with the production routes plus
/// `extra`, on its own runtime, over a store and an index in `data`. Stopped (graceful shutdown)
/// on drop; the index is closed once the thread has ended.
pub struct TestServer {
    pub addr: SocketAddr,
    pub data: PathBuf,
    stop: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    thread: Option<JoinHandle<()>>,
    /// The index threads, stopped once the server thread has ended.
    pool: Option<Box<dyn Send + Sync>>,
    /// One sweeper run (`sweep::sweep_once` with a batch of 1,000) over the server's relay; the
    /// test server runs no sweeper task of its own.
    sweeper: Box<dyn Fn() -> Option<u64> + Send + Sync>,
    /// The whole marking pass of the deny list (ADR 0052), batches of 2 blocks.
    marker: Box<dyn Fn() -> bool + Send + Sync>,
    /// The deny list, loaded from `deny_file` when set; its reload task runs on the server.
    pub deny: std::sync::Arc<sbtp_relay::deny::Deny>,
}

impl TestServer {
    /// On a fresh data directory.
    pub fn start(settings: &Settings, extra: Router) -> Self {
        Self::start_in(settings, extra, &tmp_dir("server"))
    }

    /// On `data`, opened and reconciled as at start-up (ADR 0013 rule 9).
    pub fn start_in(settings: &Settings, extra: Router, data: &std::path::Path) -> Self {
        std::fs::create_dir_all(data).unwrap();
        let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
        Self::start_with(settings, extra, data, std::sync::Arc::new(index))
    }

    /// On `data`, with `index` (opened on `data/index.redb`) as the index backend.
    pub fn start_with<I: IndexBackend + 'static>(
        settings: &Settings,
        extra: Router,
        data: &std::path::Path,
        index: std::sync::Arc<I>,
    ) -> Self {
        Self::start_full(settings, extra, data, index, sbtp_relay::log::unix_ms)
    }

    /// On a fresh data directory, with `clock` as the relay clock (P1, `received_at`, expiry).
    pub fn start_clocked(settings: &Settings, clock: fn() -> u64) -> Self {
        let data = tmp_dir("server");
        std::fs::create_dir_all(&data).unwrap();
        let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
        Self::start_full(
            settings,
            Router::new(),
            &data,
            std::sync::Arc::new(index),
            clock,
        )
    }

    fn start_full<I: IndexBackend + 'static>(
        settings: &Settings,
        extra: Router,
        data: &std::path::Path,
        index: std::sync::Arc<I>,
        clock: fn() -> u64,
    ) -> Self {
        std::fs::create_dir_all(data).unwrap();
        let index_file = data.join("index.redb");
        let store = Store::open(data, index_file, settings.max_store_bytes).unwrap();
        index.configure_demand(settings.demand_epoch_ms).unwrap();
        reconcile(&store, &*index).unwrap();
        let pool = IndexPool::start(&index, settings).unwrap();
        drop(index); // Held by the index threads from here on.
        let deny = std::sync::Arc::new(sbtp_relay::deny::Deny::open(settings).unwrap());
        let relay = std::sync::Arc::new(
            Relay::new(settings, store, pool.handle())
                .unwrap()
                .with_clock(clock)
                .with_deny(std::sync::Arc::clone(&deny)),
        );
        let swept = std::sync::Arc::clone(&relay);
        let sweeper = Box::new(move || sbtp_relay::sweep::sweep_once(&swept, 1_000));
        let walked = std::sync::Arc::clone(&relay);
        let marker = Box::new(move || sbtp_relay::deny::mark_all(&walked, 2));
        let denied = std::sync::Arc::clone(&relay);
        let app = sbtp_relay::api::layered(
            sbtp_relay::api::routes(settings, relay).merge(extra),
            settings,
        );
        let limits = ConnLimits::from_settings(settings).unwrap();
        let (stop, stopped) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                // ADR 0052 rule 4: the reload task, as `sbtp_relay::run` starts it.
                let (deny_stop, deny_stopped) = tokio::sync::watch::channel(false);
                let task = denied
                    .deny()
                    .enabled()
                    .then(|| tokio::spawn(sbtp_relay::deny::run(denied, 2, deny_stopped)));
                serve(listener, app, limits, stopped).await.unwrap();
                let _ = deny_stop.send(true);
                if let Some(t) = task {
                    let _ = t.await;
                }
            });
        });
        Self {
            addr: addr_rx.recv().unwrap(),
            data: data.to_path_buf(),
            stop: Some(stop),
            thread: Some(thread),
            pool: Some(Box::new(pool)),
            sweeper,
            marker,
            deny,
        }
    }

    pub fn connect(&self) -> TcpStream {
        connect(self.addr)
    }

    /// One sweeper run; the number of index entries removed, `None` on a failure.
    pub fn sweep(&self) -> Option<u64> {
        (self.sweeper)()
    }

    /// The whole marking pass of the deny list; `false` on a failure.
    pub fn mark(&self) -> bool {
        (self.marker)()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        drop(self.pool.take());
    }
}

pub fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

/// A parsed HTTP response.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// Sends `raw` and reads one response.
pub fn exchange(s: &mut TcpStream, raw: &str) -> Response {
    s.write_all(raw.as_bytes()).unwrap();
    read_response(s).unwrap()
}

/// `GET path` with keep-alive and optional extra header lines (each ending in `\r\n`).
pub fn get(s: &mut TcpStream, path: &str, extra: &str) -> Response {
    exchange(
        s,
        &format!("GET {path} HTTP/1.1\r\nHost: relay.test\r\n{extra}\r\n"),
    )
}

/// Reads one response (body by `Content-Length`, or none).
pub fn read_response(s: &mut TcpStream) -> std::io::Result<Response> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.trim().to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .map_or(0, |(_, v)| v.parse().unwrap());
    let mut body = buf[head_end + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    if chunked {
        return read_chunked(s, body).map(|body| Response {
            status,
            headers,
            body,
        });
    }
    while body.len() < len {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Decodes a chunked body (no trailers), starting with the bytes `buf` already read. A body
/// that ends before its last chunk is `UnexpectedEof`.
fn read_chunked(s: &mut TcpStream, mut buf: Vec<u8>) -> std::io::Result<Vec<u8>> {
    let mut chunk = [0u8; 16_384];
    let mut more = |buf: &mut Vec<u8>| -> std::io::Result<()> {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
        Ok(())
    };
    let mut body = Vec::new();
    let mut at = 0;
    loop {
        let line_end = loop {
            if let Some(i) = buf[at..].windows(2).position(|w| w == b"\r\n") {
                break at + i;
            }
            more(&mut buf)?;
        };
        let size_text = std::str::from_utf8(&buf[at..line_end]).unwrap();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16).unwrap();
        let start = line_end + 2;
        while buf.len() < start + size + 2 {
            more(&mut buf)?;
        }
        if size == 0 {
            return Ok(body);
        }
        body.extend_from_slice(&buf[start..start + size]);
        at = start + size + 2;
    }
}

/// The wall clock in Unix milliseconds.
pub fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A valid block of a test key with `payload` and `parents`, difficulty 0, timestamped now.
pub fn signed_block(payload: &[u8], parents: &[sbtp_core::BlockId]) -> Vec<u8> {
    let k = sbtp_core::SigningKey::from_bytes(&[9; 32]);
    sbtp_core::BlockBuilder::for_key(&k)
        .timestamp(now_ms())
        .parents(parents)
        .payload(payload)
        .build(&k, 0)
        .unwrap()
}

/// `PUT /sbtp/v1/block` of `body` with keep-alive.
pub fn put_block(s: &mut TcpStream, body: &[u8]) -> Response {
    s.write_all(
        format!(
            "PUT /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    s.write_all(body).unwrap();
    read_response(s).unwrap()
}

/// Whether the server has closed `s`: a read returns end of file or a reset.
pub fn is_closed(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 1];
    match s.read(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
        ),
    }
}
