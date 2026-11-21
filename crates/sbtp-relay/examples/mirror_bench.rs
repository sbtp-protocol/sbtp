//! Benchmark of the archive copy (ADR 0050 stage 1) and of replication (ADR 0048). Not shipped.
//!
//! ```text
//! mirror_bench run --relay <sbtp-relay binary> --work <dir> [options]   # one run
//! mirror_bench sigv4 [--iters N] [--body BYTES]                          # signing CPU cost
//! ```
//!
//! `run` follows the subject rules of ADR 0017 (rules 1 to 3): the relay binary runs as its own
//! process, blocks enter through `PUT /sbtp/v1/block` and leave through `GET /sbtp/v1/block/{id}`
//! over loopback HTTP, and this process is the load generator; its own memory is not measured.
//! The figures are informative, never the ADR 0013 gate.
//!
//! One run: start the relay (and, with `--replica`, a second relay that replicates with it), wait
//! one second at idle, `PUT` `--blocks` blocks from `--clients` keep-alive connections (paced at
//! `--rate` blocks per second, or as fast as the relay answers), `GET` `--gets` of them back, then
//! wait until the archive copy (and the replica) hold every block. The relay's resident size is
//! sampled every 100 ms. Every result is a `RESULT name=value` line on standard output.
//!
//! `--backlog` (with `--mirror fake`) measures the uploader alone: a relay without the archive
//! copy stores the blocks, then restarts with it on the same data directory, and the run times
//! how fast the whole set reaches the fake store. `--replica` starts a second relay; the two are
//! each other's peer (`REPLICATION_POLL_MS = 1000`, no replication rate bound) and the run waits
//! until the second one serves every block.
//!
//! `--mirror` selects the archive copy:
//! - `off`: no `mirror_endpoint`;
//! - `fake`: an S3-compatible server in this process, on loopback, path style, bucket `bench`,
//!   region `us-east-1`. It checks every signature, honours `If-None-Match: *`, records when
//!   each object arrives, and adds `--s3-latency-ms` to every answer. `--s3-fail-after-s` and
//!   `--s3-fail-for-s` answer `--s3-fail-status` to every block `PUT` during that window
//!   (seconds from the first client `PUT`); `--s3-fail-every N` fails every Nth block `PUT`.
//!   Its credentials are random per run and live only in this process and the relay's
//!   environment;
//! - `remote`: a real endpoint. See "Remote runs" below.
//!
//! **Remote runs.** `--target minio` or `--target s3` selects the environment variables
//! `SBTP_MIRROR_BENCH_MINIO_*` or `SBTP_MIRROR_BENCH_S3_*`: `_ENDPOINT`, `_ACCESS_KEY_ID` and
//! `_SECRET_ACCESS_KEY`. The credentials are read only from these variables, by name: the relay
//! gets the variable names in `mirror_access_key_ref` and `mirror_secret_key_ref` and the
//! variables themselves in its environment; this tool uses them only to sign `HEAD` probes. No
//! value, and not the endpoint, is ever printed. `--bucket`, `--region`, `--url-style`,
//! `--prefix` and `--allow-private` are the relay settings of the same names. The bucket `PUT`s
//! are bounded: `--blocks` may not exceed `--max-puts` (default 200) and the client `PUT`s are
//! paced at most at `--max-rate` blocks per second (default 10). Each block is one bucket `PUT`
//! plus retries, and the `/info` object is one more. The lag is measured by signed `HEAD`
//! probes of every `--probe-every`th block (default 10), at most `--max-heads` (default 1,000).
//!
//! **Test key.** Blocks are signed with the key derived from the public seed
//! `sbtp-relay-mirror-bench-public-key`: a published constant, not a secret, never to be trusted
//! outside this benchmark.
//!
//! **Work directory.** `--work` is deleted and recreated only if it is absent, empty, or holds the
//! marker file `.mirror_bench-work` this tool writes; anything else is refused.

// Bench-only tool; plain indexing and lossy casts in statistics are acceptable here (they stay
// forbidden in the relay). It prints its results on purpose.
#![allow(
    missing_docs,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::hash::{BuildHasher, RandomState};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sbtp_core::{BlockBuilder, SigningKey};
use sbtp_relay::mirror::sigv4::{self, Credentials, Signing};
use zeroize::Zeroizing;

type R<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const MARKER: &str = ".mirror_bench-work";
const BUCKET: &str = "bench";
const REGION: &str = "us-east-1";
/// Hard defaults of the remote bounds.
const DEFAULT_MAX_PUTS: u64 = 200;
const DEFAULT_MAX_RATE: f64 = 10.0;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("run") => Opts::parse(&args[1..]).and_then(|o| run(&o)),
        Some("sigv4") => Opts::parse(&args[1..]).and_then(|o| sigv4_cost(&o)),
        _ => Err("usage: mirror_bench run|sigv4 [options] (see the file's documentation)".into()),
    };
    if let Err(e) = res {
        eprintln!("mirror_bench: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------------------------
// Options

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Off,
    Fake,
    Remote,
}

struct Opts {
    flags: HashMap<String, String>,
}

impl Opts {
    fn parse(args: &[String]) -> R<Self> {
        let mut flags = HashMap::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let Some(name) = a.strip_prefix("--") else {
                return Err(format!("unexpected argument {a:?}").into());
            };
            // Switches without a value.
            if matches!(name, "replica" | "allow-private" | "no-verify" | "backlog") {
                flags.insert(name.to_owned(), "true".to_owned());
                continue;
            }
            let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
            flags.insert(name.to_owned(), v.clone());
        }
        Ok(Self { flags })
    }

    fn str(&self, k: &str) -> Option<&str> {
        self.flags.get(k).map(String::as_str)
    }

    fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> R<T> {
        match self.str(k) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("--{k}: not a number").into()),
        }
    }

    fn on(&self, k: &str) -> bool {
        self.str(k) == Some("true")
    }
}

// ---------------------------------------------------------------------------------------------
// Small helpers

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A random lowercase hexadecimal string of `n` bytes (std only; no key-shaped literal).
fn random_hex(n: usize) -> String {
    use std::fmt::Write as _;
    (0..n).fold(String::with_capacity(2 * n), |mut s, i| {
        let _ = write!(s, "{:02x}", RandomState::new().hash_one(i) as u8);
        s
    })
}

/// A free loopback port (bound, then released: a small race, acceptable for a bench).
fn free_port() -> R<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn prepare_work(dir: &Path) -> R<()> {
    if dir.exists() {
        let empty = std::fs::read_dir(dir)?.next().is_none();
        if !empty && !dir.join(MARKER).exists() {
            return Err(format!(
                "{}: not empty and not a mirror_bench work directory",
                dir.display()
            )
            .into());
        }
        std::fs::remove_dir_all(dir)?;
    }
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(MARKER), b"")?;
    Ok(())
}

/// Latency statistics in microseconds.
fn stats(name: &str, mut us: Vec<u64>, wall: Duration) {
    if us.is_empty() {
        println!("RESULT {name}_count=0");
        return;
    }
    us.sort_unstable();
    let p = |q: f64| us[((us.len() - 1) as f64 * q).round() as usize];
    let secs = wall.as_secs_f64().max(1e-9);
    println!(
        "RESULT {name}_count={} {name}_per_s={:.0} {name}_p50_ms={:.3} {name}_p99_ms={:.3} \
         {name}_max_ms={:.3}",
        us.len(),
        us.len() as f64 / secs,
        p(0.50) as f64 / 1e3,
        p(0.99) as f64 / 1e3,
        us[us.len() - 1] as f64 / 1e3
    );
}

fn quantiles_ms(name: &str, mut ms: Vec<u64>) {
    if ms.is_empty() {
        println!("RESULT {name}_count=0");
        return;
    }
    ms.sort_unstable();
    let p = |q: f64| ms[((ms.len() - 1) as f64 * q).round() as usize];
    println!(
        "RESULT {name}_count={} {name}_p50_ms={} {name}_p99_ms={} {name}_max_ms={}",
        ms.len(),
        p(0.50),
        p(0.99),
        ms[ms.len() - 1]
    );
}

// ---------------------------------------------------------------------------------------------
// Raw HTTP/1.1 client (the generator controls every byte; no extra dependency)

struct Reply {
    status: u16,
    close: bool,
}

fn read_reply(s: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<Reply> {
    buf.clear();
    let mut chunk = [0u8; 16_384];
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
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or(std::io::ErrorKind::InvalidData)?;
    let mut len = 0usize;
    let mut close = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("content-length") {
                len = v.parse().map_err(|_| std::io::ErrorKind::InvalidData)?;
            } else if k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close") {
                close = true;
            }
        }
    }
    let mut have = buf.len() - head_end - 4;
    while have < len {
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        have += n;
    }
    Ok(Reply { status, close })
}

/// One keep-alive connection that reconnects after a close or an error.
struct Conn {
    addr: SocketAddr,
    s: Option<TcpStream>,
    buf: Vec<u8>,
}

impl Conn {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            s: None,
            buf: Vec::with_capacity(4096),
        }
    }

    fn exchange(&mut self, head: &[u8], body: &[u8]) -> std::io::Result<u16> {
        if self.s.is_none() {
            let s = TcpStream::connect(self.addr)?;
            s.set_nodelay(true)?;
            s.set_read_timeout(Some(Duration::from_secs(30)))?;
            self.s = Some(s);
        }
        let s = self.s.as_mut().ok_or(std::io::ErrorKind::NotConnected)?;
        let r = s
            .write_all(head)
            .and_then(|()| s.write_all(body))
            .and_then(|()| read_reply(s, &mut self.buf));
        match r {
            Ok(r) => {
                if r.close {
                    self.s = None;
                }
                Ok(r.status)
            }
            Err(e) => {
                self.s = None;
                Err(e)
            }
        }
    }

    /// Retries once on a fresh connection: the server may close an idle or old connection
    /// (`max_requests_per_connection`, `max_connection_age_ms`) between two requests.
    fn request(&mut self, head: &[u8], body: &[u8]) -> std::io::Result<u16> {
        match self.exchange(head, body) {
            Ok(s) => Ok(s),
            Err(_) => self.exchange(head, body),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fake S3-compatible store

struct Fake {
    latency: Duration,
    fail_status: u16,
    /// The failure window, in milliseconds from `t0`.
    fail_from: u64,
    fail_to: u64,
    fail_every: u64,
    verify: bool,
    creds: Credentials,
    /// `now_ms()` of the first client `PUT`, 0 before it.
    t0: AtomicU64,
    block_puts: AtomicU64,
    failed: AtomicU64,
    exists: AtomicU64,
    bad_sig: AtomicU64,
    requests: AtomicU64,
    /// Block key (hex id) to arrival instant and size.
    arrived: Mutex<HashMap<String, (Instant, usize)>>,
    info: AtomicBool,
}

impl Fake {
    fn start(self: &Arc<Self>) -> R<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let me = Arc::clone(&me);
                std::thread::spawn(move || me.serve(s));
            }
        });
        Ok(addr)
    }

    fn in_window(&self) -> bool {
        let t0 = self.t0.load(Ordering::Relaxed);
        if t0 == 0 || self.fail_to <= self.fail_from {
            return false;
        }
        let t = now_ms().saturating_sub(t0);
        (self.fail_from..self.fail_to).contains(&t)
    }

    fn serve(&self, mut s: TcpStream) {
        let _ = s.set_nodelay(true);
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 65_536];
        loop {
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i;
                }
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let mut lines = head.split("\r\n");
            let mut first = lines.next().unwrap_or_default().split(' ');
            let method = first.next().unwrap_or_default().to_owned();
            let path = first.next().unwrap_or_default().to_owned();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                .collect();
            let header = |n: &str| {
                headers
                    .iter()
                    .find(|(k, _)| k == n)
                    .map(|(_, v)| v.as_str())
            };
            let len: usize = header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            while buf.len() < head_end + 4 + len {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let body = &buf[head_end + 4..head_end + 4 + len];
            self.requests.fetch_add(1, Ordering::Relaxed);
            let block = path
                .strip_prefix(&format!("/{BUCKET}/sbtp/v1/block/"))
                .map(str::to_owned);
            let status = if method != "PUT" {
                405
            } else if self.verify && !self.signature_ok(&method, &path, &headers, body) {
                self.bad_sig.fetch_add(1, Ordering::Relaxed);
                403
            } else if let Some(id) = block {
                let n = self.block_puts.fetch_add(1, Ordering::Relaxed) + 1;
                if self.in_window() || (self.fail_every > 0 && n.is_multiple_of(self.fail_every)) {
                    self.failed.fetch_add(1, Ordering::Relaxed);
                    self.fail_status
                } else {
                    let mut a = lock(&self.arrived);
                    if header("if-none-match") == Some("*") && a.contains_key(&id) {
                        self.exists.fetch_add(1, Ordering::Relaxed);
                        412
                    } else {
                        a.insert(id, (Instant::now(), len));
                        200
                    }
                }
            } else {
                self.info.store(true, Ordering::Relaxed);
                200
            };
            buf.drain(..head_end + 4 + len);
            if !self.latency.is_zero() {
                std::thread::sleep(self.latency);
            }
            let out = format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n");
            if s.write_all(out.as_bytes()).is_err() {
                return;
            }
        }
    }

    fn signature_ok(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> bool {
        let h = |n: &str| {
            headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.as_str())
        };
        let (Some(auth), Some(date), Some(hash)) = (
            h("authorization"),
            h("x-amz-date"),
            h("x-amz-content-sha256"),
        ) else {
            return false;
        };
        let Some(names) = auth
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|s| s.split(',').next())
        else {
            return false;
        };
        let signed: Vec<(&str, &str)> = names.split(';').map(|n| (n, h(n).unwrap_or(""))).collect();
        let expected = sigv4::authorization(
            &Signing {
                method,
                path,
                headers: &signed,
                payload_hash: hash,
                amz_date: date,
                region: REGION,
            },
            &self.creds,
        );
        hash == sigv4::sha256_hex(body) && expected == auth
    }
}

// ---------------------------------------------------------------------------------------------
// The relay process

struct Relay {
    child: Child,
    addr: SocketAddr,
    log_lines: Arc<AtomicU64>,
    mirror_failed_lines: Arc<AtomicU64>,
    last_lines: Arc<Mutex<Vec<String>>>,
}

impl Relay {
    /// Starts `bin` with `env` only (plus `PATH` and the TLS trust variables) and waits for its
    /// `listening` line.
    fn start(bin: &Path, env: &[(String, OsString)]) -> R<Self> {
        let mut cmd = Command::new(bin);
        cmd.env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for k in ["PATH", "SSL_CERT_FILE", "SSL_CERT_DIR"] {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn()?;
        let stderr = child.stderr.take().ok_or("no stderr")?;
        let (tx, rx) = mpsc::channel::<String>();
        let log_lines = Arc::new(AtomicU64::new(0));
        let mirror_failed_lines = Arc::new(AtomicU64::new(0));
        let last_lines = Arc::new(Mutex::new(Vec::new()));
        {
            let (n, f, last) = (
                Arc::clone(&log_lines),
                Arc::clone(&mirror_failed_lines),
                Arc::clone(&last_lines),
            );
            std::thread::spawn(move || {
                let mut tx = Some(tx);
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    n.fetch_add(1, Ordering::Relaxed);
                    // The relay logs `key=value` lines (ADR 0021).
                    if line.contains(" event=mirror_failed") {
                        f.fetch_add(1, Ordering::Relaxed);
                    }
                    if line.contains(" event=listening ")
                        && let Some(addr) = line
                            .split(" addr=")
                            .nth(1)
                            .and_then(|r| r.split_whitespace().next())
                        && let Some(t) = tx.take()
                    {
                        let _ = t.send(addr.to_owned());
                    }
                    let mut l = lock(&last);
                    if l.len() >= 20 {
                        l.remove(0);
                    }
                    l.push(line);
                }
            });
        }
        let Ok(addr) = rx.recv_timeout(Duration::from_secs(60)) else {
            let _ = child.kill();
            let lines = lock(&last_lines).join("\n");
            return Err(format!("the relay did not start; its last lines:\n{lines}").into());
        };
        let addr = addr.parse()?;
        Ok(Self {
            child,
            addr,
            log_lines,
            mirror_failed_lines,
            last_lines,
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// `SIGTERM`, then waits for the exit (ADR 0018: the relay drains and closes its index).
    fn stop(mut self) -> R<i32> {
        Command::new("kill")
            .args(["-TERM", &self.pid().to_string()])
            .status()?;
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(st) = self.child.try_wait()? {
                return Ok(st.code().unwrap_or(-1));
            }
            if Instant::now() > end {
                let _ = self.child.kill();
                return Err("the relay did not stop within 30 s of SIGTERM".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Resident size (KiB) and cumulative CPU time (ms) of `pid`, from `ps` (macOS and Linux).
fn ps(pid: u32) -> Option<(u64, u64)> {
    let out = Command::new("ps")
        .args(["-o", "rss=,time=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut it = s.split_whitespace();
    let rss = it.next()?.parse().ok()?;
    Some((rss, parse_cpu(it.next()?)?))
}

/// `[[dd-]hh:]mm:ss[.cc]` to milliseconds.
fn parse_cpu(t: &str) -> Option<u64> {
    let (days, rest) = match t.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, t),
    };
    let mut secs = 0f64;
    for part in rest.split(':') {
        secs = secs * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(days * 86_400_000 + (secs * 1000.0) as u64)
}

/// Linux only: `VmHWM` in KiB, the exact peak.
fn vm_hwm(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
}

/// Samples the resident size every 100 ms; `phase` labels the samples.
struct Sampler {
    phase: Arc<AtomicUsize>,
    peaks: Arc<Mutex<Vec<u64>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

const PHASES: [&str; 5] = ["idle", "put", "get", "drain", "end"];

impl Sampler {
    fn start(pid: u32) -> Self {
        let phase = Arc::new(AtomicUsize::new(0));
        let peaks = Arc::new(Mutex::new(vec![0; PHASES.len()]));
        let stop = Arc::new(AtomicBool::new(false));
        let (p, k, s) = (Arc::clone(&phase), Arc::clone(&peaks), Arc::clone(&stop));
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                if let Some((rss, _)) = ps(pid) {
                    let mut k = lock(&k);
                    let i = p.load(Ordering::Relaxed).min(PHASES.len() - 1);
                    k[i] = k[i].max(rss);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self {
            phase,
            peaks,
            stop,
            thread: Some(thread),
        }
    }

    fn enter(&self, i: usize) {
        self.phase.store(i, Ordering::Relaxed);
    }

    fn finish(mut self) -> Vec<u64> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        lock(&self.peaks).clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Blocks

/// A generated block and its hexadecimal id, by index.
type Slot = Option<(Vec<u8>, String)>;
/// Latencies, acknowledgement instants, status counts, errors.
type Acc = (Vec<u64>, Vec<Option<Instant>>, HashMap<u16, u64>, u64);

struct Blocks {
    bytes: Vec<Vec<u8>>,
    ids: Vec<String>,
}

fn generate(n: usize, payload: usize, pow: u32) -> R<Blocks> {
    // Public seed (see the file's documentation): not a secret.
    let seed = *blake3::hash(b"sbtp-relay-mirror-bench-public-key").as_bytes();
    let threads = std::thread::available_parallelism().map_or(4, usize::from);
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Slot>> = Mutex::new(vec![None; n]);
    let run = RandomState::new().hash_one(now_ms());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| -> R<()> {
                let key = SigningKey::from_bytes(&seed);
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        return Ok(());
                    }
                    // Deterministic per run and block, distinct across runs (fresh ids, so a
                    // remote bucket never answers `412` for a block of an earlier run).
                    let mut body = vec![0u8; payload];
                    let mut h = blake3::Hasher::new();
                    h.update(&run.to_le_bytes());
                    h.update(&(i as u64).to_le_bytes());
                    h.finalize_xof().fill(&mut body);
                    let block = BlockBuilder::for_key(&key)
                        .timestamp(now_ms())
                        .payload(&body)
                        .build(&key, pow)
                        .map_err(|e| format!("build: {e:?}"))?;
                    let id = sbtp_core::parse(&block)
                        .map_err(|e| format!("parse: {e:?}"))?
                        .block_id();
                    lock(&out)[i] = Some((block, sbtp_relay::store::hex(&id)));
                }
            });
        }
    });
    let mut bytes = Vec::with_capacity(n);
    let mut ids = Vec::with_capacity(n);
    for (b, id) in out
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .into_iter()
        .flatten()
    {
        bytes.push(b);
        ids.push(id);
    }
    if bytes.len() != n {
        return Err("block generation failed".into());
    }
    Ok(Blocks { bytes, ids })
}

// ---------------------------------------------------------------------------------------------
// Load phases

struct PutOut {
    latencies: Vec<u64>,
    acked: Vec<Option<Instant>>,
    statuses: HashMap<u16, u64>,
    errors: u64,
    wall: Duration,
}

fn put_phase(addr: SocketAddr, blocks: &Blocks, clients: usize, rate: f64) -> PutOut {
    let n = blocks.bytes.len();
    let next = AtomicUsize::new(0);
    let start = Instant::now();
    let results: Mutex<Acc> = Mutex::new((Vec::with_capacity(n), vec![None; n], HashMap::new(), 0));
    std::thread::scope(|sc| {
        for _ in 0..clients {
            sc.spawn(|| {
                let mut c = Conn::new(addr);
                let mut lat = Vec::new();
                let mut acks = Vec::new();
                let mut st: HashMap<u16, u64> = HashMap::new();
                let mut errors = 0;
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    if rate > 0.0 {
                        // Global pacing: block `i` is due at `i / rate` seconds.
                        let due = start + Duration::from_secs_f64(i as f64 / rate);
                        if let Some(w) = due.checked_duration_since(Instant::now()) {
                            std::thread::sleep(w);
                        }
                    }
                    let body = &blocks.bytes[i];
                    let head = format!(
                        "PUT /sbtp/v1/block HTTP/1.1\r\nHost: relay.bench\r\n\
                         Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let t = Instant::now();
                    match c.request(head.as_bytes(), body) {
                        Ok(s) => {
                            let done = Instant::now();
                            lat.push((done - t).as_micros() as u64);
                            *st.entry(s).or_default() += 1;
                            if s == 201 || s == 200 {
                                acks.push((i, done));
                            }
                        }
                        Err(_) => errors += 1,
                    }
                }
                let mut r = lock(&results);
                r.0.extend(lat);
                for (i, t) in acks {
                    r.1[i] = Some(t);
                }
                for (k, v) in st {
                    *r.2.entry(k).or_default() += v;
                }
                r.3 += errors;
            });
        }
    });
    let wall = start.elapsed();
    let (latencies, acked, statuses, errors) =
        results.into_inner().unwrap_or_else(PoisonError::into_inner);
    PutOut {
        latencies,
        acked,
        statuses,
        errors,
        wall,
    }
}

fn get_phase(
    addr: SocketAddr,
    ids: &[String],
    clients: usize,
    gets: usize,
) -> (Vec<u64>, Duration, u64) {
    let next = AtomicUsize::new(0);
    let start = Instant::now();
    let out: Mutex<(Vec<u64>, u64)> = Mutex::new((Vec::with_capacity(gets), 0));
    std::thread::scope(|sc| {
        for _ in 0..clients {
            sc.spawn(|| {
                let mut c = Conn::new(addr);
                let mut lat = Vec::new();
                let mut bad = 0;
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= gets {
                        break;
                    }
                    // A spread over the whole set, not only the most recent (cached) blocks.
                    let id = &ids[(i * 7919) % ids.len()];
                    let head =
                        format!("GET /sbtp/v1/block/{id} HTTP/1.1\r\nHost: relay.bench\r\n\r\n");
                    let t = Instant::now();
                    match c.request(head.as_bytes(), &[]) {
                        Ok(200) => lat.push(t.elapsed().as_micros() as u64),
                        _ => bad += 1,
                    }
                }
                let mut o = lock(&out);
                o.0.extend(lat);
                o.1 += bad;
            });
        }
    });
    let wall = start.elapsed();
    let (lat, bad) = out.into_inner().unwrap_or_else(PoisonError::into_inner);
    (lat, wall, bad)
}

/// Waits until `addr` serves every id (one pass after another); the time it took.
fn wait_replica(addr: SocketAddr, ids: &[String], limit: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut missing: Vec<&String> = ids.iter().collect();
    let mut c = Conn::new(addr);
    while !missing.is_empty() {
        if start.elapsed() > limit {
            return None;
        }
        missing.retain(|id| {
            let head = format!("GET /sbtp/v1/block/{id} HTTP/1.1\r\nHost: relay.bench\r\n\r\n");
            !matches!(c.request(head.as_bytes(), &[]), Ok(200))
        });
        if !missing.is_empty() {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    Some(start.elapsed())
}

// ---------------------------------------------------------------------------------------------
// Remote probes

struct Remote {
    prefix: &'static str,
    endpoint: String,
    bucket: String,
    region: String,
    url_style: String,
    key_prefix: String,
    allow_private: bool,
}

impl Remote {
    fn var(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.prefix)
    }

    fn creds(&self) -> R<Credentials> {
        let get = |n: String| -> R<Zeroizing<String>> {
            std::env::var(&n)
                .ok()
                .filter(|v| !v.is_empty())
                .map(Zeroizing::new)
                .ok_or_else(|| format!("{n} is unset or empty").into())
        };
        Ok(Credentials {
            access_key: get(self.var("ACCESS_KEY_ID"))?,
            secret_key: get(self.var("SECRET_ACCESS_KEY"))?,
            session_token: None,
        })
    }
}

/// Signed `HEAD` probes of `(index, ack)` pairs from `rx`, in order, every 250 ms until the
/// object exists; returns the lag of each probe in milliseconds.
fn probe_remote(
    remote: &Remote,
    ids: &[String],
    rx: &mpsc::Receiver<(usize, Instant)>,
    max_heads: u64,
    limit: Duration,
) -> R<(Vec<u64>, u64)> {
    use axum::body::Body;
    use axum::http::Request;
    use sbtp_relay::peers::PeerUrl;
    use sbtp_relay::replication::http::Client;

    let creds = remote.creds()?;
    let endpoint = PeerUrl::parse(&remote.endpoint).map_err(|_| "the endpoint is not a URL")?;
    let (url, base) = if remote.url_style == "virtual" {
        let scheme = if endpoint.is_https() { "https" } else { "http" };
        let url = PeerUrl::parse(&format!(
            "{scheme}://{}.{}{}",
            remote.bucket,
            endpoint.authority(),
            endpoint.path()
        ))
        .map_err(|_| "virtual-hosted URL")?;
        let base = format!("{}/{}sbtp/v1/block/", url.path(), remote.key_prefix);
        (url, base)
    } else {
        let base = format!(
            "{}/{}/{}sbtp/v1/block/",
            endpoint.path(),
            remote.bucket,
            remote.key_prefix
        );
        (endpoint, base)
    };
    let settings = sbtp_relay::config::Settings::load(Vec::<OsString>::new(), Vec::new())?;
    let tls = if url.is_https() {
        Some(Arc::new(sbtp_relay::replication::client_config(
            &settings,
            "mirror_endpoint",
        )?))
    } else {
        None
    };
    let client = Client::new(tls, remote.allow_private, Duration::from_secs(30));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let empty = sigv4::sha256_hex(b"");
    let mut heads = 0u64;
    let mut lags = Vec::new();
    rt.block_on(async {
        let mut conn = None;
        while let Ok((i, ack)) = rx.recv() {
            let path = format!("{base}{}", ids[i]);
            loop {
                if heads >= max_heads || ack.elapsed() > limit {
                    return;
                }
                heads += 1;
                let date = sigv4::amz_date(now_ms());
                let host = url.authority();
                let signed = [
                    ("host", host),
                    ("x-amz-content-sha256", empty.as_str()),
                    ("x-amz-date", date.as_str()),
                ];
                let auth = Zeroizing::new(sigv4::authorization(
                    &Signing {
                        method: "HEAD",
                        path: &path,
                        headers: &signed,
                        payload_hash: &empty,
                        amz_date: &date,
                        region: &remote.region,
                    },
                    &creds,
                ));
                let mut b = Request::head(sigv4::encode_path(&path));
                for (n, v) in signed {
                    b = b.header(n, v);
                }
                let Ok(mut av) = axum::http::HeaderValue::from_str(&auth) else {
                    return;
                };
                av.set_sensitive(true);
                let Ok(req) = b.header("authorization", av).body(Body::empty()) else {
                    return;
                };
                if let Ok(s) = client.send_discard(&mut conn, &url, req).await
                    && s.as_u16() == 200
                {
                    lags.push(ack.elapsed().as_millis() as u64);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    });
    Ok((lags, heads))
}

// ---------------------------------------------------------------------------------------------
// One run

fn relay_env(data: &Path, pow: u32, extra: &[(&str, String)]) -> Vec<(String, OsString)> {
    let mut e: Vec<(String, OsString)> = vec![
        ("DATA_DIR".into(), data.as_os_str().to_owned()),
        ("LISTEN".into(), "127.0.0.1:0".into()),
        ("LOG_LEVEL".into(), "info".into()),
        ("MIN_POW_DIFFICULTY".into(), pow.to_string().into()),
        // Every generator connection comes from 127.0.0.1, one client key: the per-client
        // rates and the ingest quota are lifted so that they do not throttle the measure. The
        // per-client in-flight bound is raised to the relay-wide one, as if the clients were
        // distinct. Every other setting is the `small` profile.
        ("RATE_BLOCK_PER_MIN".into(), "1000000".into()),
        ("RATE_BLOCK_BURST".into(), "1000000".into()),
        ("RATE_PUT_PER_MIN".into(), "1000000".into()),
        ("RATE_PUT_BURST".into(), "1000000".into()),
        ("INGEST_BYTES_PER_HOUR".into(), "0".into()),
        ("PUT_MAX_IN_FLIGHT_PER_CLIENT".into(), "4".into()),
    ];
    for (k, v) in extra {
        e.retain(|(n, _)| n != k);
        e.push(((*k).to_owned(), v.into()));
    }
    e.into_iter()
        .map(|(k, v)| (format!("SBTP_RELAY_{k}"), v))
        .collect()
}

fn run(o: &Opts) -> R<()> {
    let bin = PathBuf::from(o.str("relay").ok_or("--relay <binary> is required")?);
    let work = PathBuf::from(o.str("work").ok_or("--work <dir> is required")?);
    let mode = match o.str("mirror").unwrap_or("off") {
        "off" => Mode::Off,
        "fake" => Mode::Fake,
        "remote" => Mode::Remote,
        _ => return Err("--mirror off|fake|remote".into()),
    };
    let n: usize = o.num("blocks", 5_000)?;
    let payload: usize = o.num("payload", 1_024)?;
    let clients: usize = o.num("clients", 4)?;
    let mut rate: f64 = o.num("rate", 0.0)?;
    let gets: usize = o.num("gets", n)?;
    let pow: u32 = o.num("pow", 0)?;
    let in_flight: u64 = o.num("in-flight", 1)?;
    let drain_limit = Duration::from_secs(o.num("drain-timeout-s", 300)?);
    if n == 0 || clients == 0 {
        return Err("--blocks and --clients must be positive".into());
    }

    let remote = if mode == Mode::Remote {
        let prefix = match o.str("target") {
            Some("minio") => "SBTP_MIRROR_BENCH_MINIO_",
            Some("s3") => "SBTP_MIRROR_BENCH_S3_",
            _ => return Err("--mirror remote needs --target minio|s3".into()),
        };
        let max_puts: u64 = o.num("max-puts", DEFAULT_MAX_PUTS)?;
        let max_rate: f64 = o.num("max-rate", DEFAULT_MAX_RATE)?;
        if n as u64 > max_puts {
            return Err(format!("--blocks {n} is above --max-puts {max_puts}").into());
        }
        if max_rate.is_nan() || max_rate <= 0.0 {
            return Err("--max-rate must be positive".into());
        }
        rate = if rate > 0.0 {
            rate.min(max_rate)
        } else {
            max_rate
        };
        let endpoint_var = format!("{prefix}ENDPOINT");
        let endpoint = std::env::var(&endpoint_var)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{endpoint_var} is unset or empty"))?;
        Some(Remote {
            prefix,
            endpoint,
            bucket: o.str("bucket").ok_or("--bucket is required")?.to_owned(),
            region: o.str("region").unwrap_or(REGION).to_owned(),
            url_style: o.str("url-style").unwrap_or("path").to_owned(),
            key_prefix: o.str("prefix").unwrap_or("").to_owned(),
            allow_private: o.on("allow-private"),
        })
    } else {
        None
    };

    prepare_work(&work)?;
    eprintln!("generating {n} blocks of {payload} payload bytes (difficulty {pow})");
    let blocks = generate(n, payload, pow)?;
    let bytes_total: usize = blocks.bytes.iter().map(Vec::len).sum();

    // The archive copy's settings.
    let mut extra: Vec<(&str, String)> = Vec::new();
    let mut fake: Option<Arc<Fake>> = None;
    let mut secret_env: Vec<(String, OsString)> = Vec::new();
    match mode {
        Mode::Off => {}
        Mode::Fake => {
            let f = Arc::new(Fake {
                latency: Duration::from_millis(o.num("s3-latency-ms", 0)?),
                fail_status: o.num("s3-fail-status", 503)?,
                fail_from: o.num::<u64>("s3-fail-after-s", 0)? * 1_000,
                fail_to: (o.num::<u64>("s3-fail-after-s", 0)?
                    + o.num::<u64>("s3-fail-for-s", 0)?)
                    * 1_000,
                fail_every: o.num("s3-fail-every", 0)?,
                verify: !o.on("no-verify"),
                creds: Credentials {
                    access_key: Zeroizing::new(random_hex(10)),
                    secret_key: Zeroizing::new(random_hex(20)),
                    session_token: None,
                },
                t0: AtomicU64::new(0),
                block_puts: AtomicU64::new(0),
                failed: AtomicU64::new(0),
                exists: AtomicU64::new(0),
                bad_sig: AtomicU64::new(0),
                requests: AtomicU64::new(0),
                arrived: Mutex::new(HashMap::new()),
                info: AtomicBool::new(false),
            });
            let addr = f.start()?;
            extra.push(("MIRROR_ENDPOINT", format!("http://{addr}")));
            extra.push(("MIRROR_BUCKET", BUCKET.into()));
            extra.push(("MIRROR_REGION", REGION.into()));
            extra.push((
                "MIRROR_ACCESS_KEY_REF",
                "SBTP_MIRROR_BENCH_FAKE_ACCESS_KEY_ID".into(),
            ));
            extra.push((
                "MIRROR_SECRET_KEY_REF",
                "SBTP_MIRROR_BENCH_FAKE_SECRET_ACCESS_KEY".into(),
            ));
            secret_env.push((
                "SBTP_MIRROR_BENCH_FAKE_ACCESS_KEY_ID".into(),
                f.creds.access_key.as_str().into(),
            ));
            secret_env.push((
                "SBTP_MIRROR_BENCH_FAKE_SECRET_ACCESS_KEY".into(),
                f.creds.secret_key.as_str().into(),
            ));
            fake = Some(f);
        }
        Mode::Remote => {
            let r = remote.as_ref().ok_or("remote")?;
            extra.push(("MIRROR_ENDPOINT", r.endpoint.clone()));
            extra.push(("MIRROR_BUCKET", r.bucket.clone()));
            extra.push(("MIRROR_REGION", r.region.clone()));
            extra.push(("MIRROR_URL_STYLE", r.url_style.clone()));
            extra.push(("MIRROR_PREFIX", r.key_prefix.clone()));
            extra.push(("MIRROR_ACCESS_KEY_REF", r.var("ACCESS_KEY_ID")));
            extra.push(("MIRROR_SECRET_KEY_REF", r.var("SECRET_ACCESS_KEY")));
            if r.allow_private {
                extra.push(("MIRROR_ALLOW_PRIVATE", "true".into()));
            }
            // The relay reads the two variables by name from its environment (rule 22).
            for suffix in ["ACCESS_KEY_ID", "SECRET_ACCESS_KEY"] {
                let k = r.var(suffix);
                let v = std::env::var_os(&k).ok_or_else(|| format!("{k} is unset"))?;
                secret_env.push((k, v));
            }
        }
    }
    if mode != Mode::Off {
        extra.push(("MIRROR_MAX_IN_FLIGHT", in_flight.to_string()));
    }

    // Replication: a second relay B, peers of each other, both polling every second without a
    // rate bound, so that the measured relay A serves (and makes) as many replication requests
    // as it can.
    let replica = o.on("replica");
    let (port_a, port_b) = (free_port()?, free_port()?);
    if replica {
        extra.push(("LISTEN", format!("127.0.0.1:{port_a}")));
        extra.push(("PEERS", format!("http://127.0.0.1:{port_b}")));
        for (k, v) in [
            ("REPLICATION_POLL_MS", "1000"),
            ("REPLICATION_BLOCKS_PER_MIN", "1000000"),
            ("REPLICATION_BYTES_PER_HOUR", "1099511627776"),
        ] {
            extra.push((k, v.into()));
        }
    }
    let mut env_a = relay_env(&work.join("a"), pow, &extra);
    env_a.extend(secret_env);
    if o.on("backlog") {
        let f = fake.as_ref().ok_or("--backlog needs --mirror fake")?;
        return drain_backlog(&bin, &work, pow, &env_a, &blocks, clients, f, drain_limit);
    }
    let relay = Relay::start(&bin, &env_a)?;
    let b = if replica {
        let b_extra = [
            ("LISTEN", format!("127.0.0.1:{port_b}")),
            ("PEERS", format!("http://127.0.0.1:{port_a}")),
            ("REPLICATION_POLL_MS", "1000".into()),
            ("REPLICATION_BLOCKS_PER_MIN", "1000000".into()),
            ("REPLICATION_BYTES_PER_HOUR", "1099511627776".into()),
        ];
        Some(Relay::start(
            &bin,
            &relay_env(&work.join("b"), pow, &b_extra),
        )?)
    } else {
        None
    };
    let pid = relay.pid();
    let sampler = Sampler::start(pid);
    std::thread::sleep(Duration::from_secs(1));
    let idle = ps(pid).map_or(0, |(r, _)| r);
    let cpu0 = ps(pid).map_or(0, |(_, c)| c);

    // Remote lag probes run beside the load.
    let (probe_tx, probe_rx) = mpsc::channel::<(usize, Instant)>();
    let probe_every: usize = o.num("probe-every", 10)?;
    let max_heads: u64 = o.num("max-heads", 1_000)?;

    sampler.enter(1);
    if let Some(f) = &fake {
        f.t0.store(now_ms(), Ordering::Relaxed);
    }
    let put_start = Instant::now();
    let probes = std::thread::scope(|sc| -> R<Option<(Vec<u64>, u64)>> {
        let handle = remote.as_ref().map(|r| {
            let ids = &blocks.ids;
            sc.spawn(move || probe_remote(r, ids, &probe_rx, max_heads, drain_limit))
        });
        let put = put_phase(relay.addr, &blocks, clients, rate);
        let cpu_put = ps(pid).map_or(0, |(_, c)| c);
        stats("put", put.latencies.clone(), put.wall);
        let mut st: Vec<_> = put.statuses.iter().collect();
        st.sort();
        println!(
            "RESULT put_statuses={} put_errors={} put_wall_s={:.2} relay_cpu_put_ms={}",
            st.iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(","),
            put.errors,
            put.wall.as_secs_f64(),
            cpu_put.saturating_sub(cpu0)
        );
        if remote.is_some() {
            for (i, a) in put.acked.iter().enumerate() {
                if let Some(t) = a
                    && i % probe_every.max(1) == probe_every.max(1) - 1
                {
                    let _ = probe_tx.send((i, *t));
                }
            }
        }
        drop(probe_tx);

        sampler.enter(2);
        let (glat, gwall, gbad) = get_phase(relay.addr, &blocks.ids, clients, gets);
        stats("get", glat, gwall);
        println!("RESULT get_not_200={gbad}");

        sampler.enter(3);
        if let Some(f) = &fake {
            let end = Instant::now() + drain_limit;
            while lock(&f.arrived).len() < n && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(50));
            }
            let arrived = lock(&f.arrived);
            let mut lags = Vec::with_capacity(n);
            let (mut first, mut last) = (None::<Instant>, None::<Instant>);
            let mut copied_bytes = 0usize;
            for (i, id) in blocks.ids.iter().enumerate() {
                if let (Some((t, len)), Some(a)) = (arrived.get(id), put.acked[i]) {
                    lags.push(t.saturating_duration_since(a).as_millis() as u64);
                    first = Some(first.map_or(*t, |f: Instant| f.min(*t)));
                    last = Some(last.map_or(*t, |l: Instant| l.max(*t)));
                    copied_bytes += len;
                }
            }
            quantiles_ms("mirror_lag", lags);
            if let (Some(f0), Some(l)) = (first, last) {
                let span = (l - f0).as_secs_f64().max(1e-9);
                println!(
                    "RESULT mirror_copied={} mirror_blocks_per_s={:.0} mirror_mb_per_s={:.2} \
                     mirror_done_after_put_s={:.2} mirror_drained_s_after_last_ack={:.2}",
                    arrived.len(),
                    arrived.len() as f64 / span,
                    copied_bytes as f64 / span / 1e6,
                    (l - put_start).as_secs_f64(),
                    put.acked
                        .iter()
                        .flatten()
                        .max()
                        .map_or(0.0, |a| l.saturating_duration_since(*a).as_secs_f64())
                );
            }
            println!(
                "RESULT s3_requests={} s3_block_puts={} s3_injected_failures={} s3_412={} \
                 s3_bad_signatures={} s3_info_written={}",
                f.requests.load(Ordering::Relaxed),
                f.block_puts.load(Ordering::Relaxed),
                f.failed.load(Ordering::Relaxed),
                f.exists.load(Ordering::Relaxed),
                f.bad_sig.load(Ordering::Relaxed),
                f.info.load(Ordering::Relaxed)
            );
        }
        if let Some(b) = &b {
            match wait_replica(b.addr, &blocks.ids, drain_limit) {
                Some(d) => println!("RESULT replica_complete_after_get_s={:.2}", d.as_secs_f64()),
                None => println!("RESULT replica_complete_after_get_s=timeout"),
            }
        }
        let probes = match handle {
            Some(h) => Some(h.join().map_err(|_| "probe thread panicked")??),
            None => None,
        };
        Ok(probes)
    })?;
    if let Some((lags, heads)) = probes {
        quantiles_ms("remote_lag", lags);
        println!("RESULT remote_heads={heads}");
    }
    sampler.enter(4);
    std::thread::sleep(Duration::from_millis(300));
    let cpu_end = ps(pid).map_or(0, |(_, c)| c);
    let hwm = vm_hwm(pid);
    let peaks = sampler.finish();
    println!(
        "RESULT rss_idle_kib={idle} {} relay_cpu_total_ms={} vm_hwm_kib={} blocks={n} \
         block_bytes={bytes_total} mirror={} in_flight={in_flight} replica={replica}",
        PHASES
            .iter()
            .zip(&peaks)
            .map(|(p, k)| format!("rss_peak_{p}_kib={k}"))
            .collect::<Vec<_>>()
            .join(" "),
        cpu_end.saturating_sub(cpu0),
        hwm.map_or_else(|| "n/a".into(), |h| h.to_string()),
        o.str("mirror").unwrap_or("off"),
    );
    let lines = relay.log_lines.load(Ordering::Relaxed);
    let failed_lines = relay.mirror_failed_lines.load(Ordering::Relaxed);
    let tail = lock(&relay.last_lines).clone();
    let code = relay.stop()?;
    if let Some(b) = b {
        let _ = b.stop();
    }
    println!("RESULT relay_log_lines={lines} relay_mirror_failed_lines={failed_lines} exit={code}");
    if code != 0 {
        eprintln!("relay exit {code}; last lines:\n{}", tail.join("\n"));
    }
    Ok(())
}

/// `--backlog`: the blocks are first stored by a relay without the archive copy, which then
/// restarts with it on the same data directory. The uploader starts with the whole set to copy,
/// so the rate it drains at is its own, not the ingest rate.
#[allow(clippy::too_many_arguments)]
fn drain_backlog(
    bin: &Path,
    work: &Path,
    pow: u32,
    env: &[(String, OsString)],
    blocks: &Blocks,
    clients: usize,
    f: &Fake,
    limit: Duration,
) -> R<()> {
    let n = blocks.ids.len();
    let plain = Relay::start(bin, &relay_env(&work.join("a"), pow, &[]))?;
    let put = put_phase(plain.addr, blocks, clients, 0.0);
    if put.statuses.get(&201) != Some(&(n as u64)) {
        return Err("backlog: not every block was accepted".into());
    }
    plain.stop()?;
    let start = Instant::now();
    let relay = Relay::start(bin, env)?;
    let pid = relay.pid();
    let cpu0 = ps(pid).map_or(0, |(_, c)| c);
    let sampler = Sampler::start(pid);
    sampler.enter(3);
    f.t0.store(now_ms(), Ordering::Relaxed);
    let end = Instant::now() + limit;
    while lock(&f.arrived).len() < n && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    let cpu = ps(pid).map_or(0, |(_, c)| c).saturating_sub(cpu0);
    let peaks = sampler.finish();
    let arrived = lock(&f.arrived);
    let first = arrived.values().map(|(t, _)| *t).min();
    let last = arrived.values().map(|(t, _)| *t).max();
    let bytes: usize = arrived.values().map(|(_, l)| *l).sum();
    if let (Some(a), Some(b)) = (first, last) {
        let span = (b - a).as_secs_f64().max(1e-9);
        println!(
            "RESULT backlog_copied={} backlog_blocks_per_s={:.0} backlog_mb_per_s={:.2} \
             backlog_done_s_after_start={:.2} relay_cpu_drain_ms={cpu} rss_peak_drain_kib={} \
             s3_block_puts={} s3_injected_failures={} s3_bad_signatures={}",
            arrived.len(),
            arrived.len() as f64 / span,
            bytes as f64 / span / 1e6,
            (b - start).as_secs_f64(),
            peaks[3],
            f.block_puts.load(Ordering::Relaxed),
            f.failed.load(Ordering::Relaxed),
            f.bad_sig.load(Ordering::Relaxed),
        );
    }
    drop(arrived);
    let code = relay.stop()?;
    println!("RESULT exit={code}");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Signing cost

fn sigv4_cost(o: &Opts) -> R<()> {
    use std::hint::black_box;
    let iters: u32 = o.num("iters", 20_000)?;
    let body_len: usize = o.num("body", 1_024)?;
    let mut body = vec![0u8; body_len];
    blake3::Hasher::new().finalize_xof().fill(&mut body);
    let creds = Credentials {
        access_key: Zeroizing::new(random_hex(10)),
        secret_key: Zeroizing::new(random_hex(20)),
        session_token: None,
    };
    let date = sigv4::amz_date(now_ms());
    let path = format!("/{BUCKET}/sbtp/v1/block/{}", "ab".repeat(32));

    let t = Instant::now();
    for _ in 0..iters {
        black_box(sigv4::sha256_hex(black_box(&body)));
    }
    let hash_ns = t.elapsed().as_nanos() as f64 / f64::from(iters);

    let hash = sigv4::sha256_hex(&body);
    let t = Instant::now();
    for _ in 0..iters {
        // The headers the uploader signs for a block (`mirror/mod.rs`, `request`).
        let headers = [
            ("cache-control", "public, max-age=31536000, immutable"),
            ("content-type", "application/octet-stream"),
            ("host", "127.0.0.1:9000"),
            ("x-amz-content-sha256", hash.as_str()),
            ("x-amz-date", date.as_str()),
            ("if-none-match", "*"),
        ];
        black_box(sigv4::authorization(
            &Signing {
                method: "PUT",
                path: black_box(&path),
                headers: &headers,
                payload_hash: &hash,
                amz_date: &date,
                region: REGION,
            },
            &creds,
        ));
    }
    let sign_ns = t.elapsed().as_nanos() as f64 / f64::from(iters);
    println!(
        "RESULT sigv4_body_bytes={body_len} sha256_payload_us={:.2} authorization_us={:.2} \
         total_per_put_us={:.2} iters={iters}",
        hash_ns / 1e3,
        sign_ns / 1e3,
        (hash_ns + sign_ns) / 1e3
    );
    Ok(())
}
