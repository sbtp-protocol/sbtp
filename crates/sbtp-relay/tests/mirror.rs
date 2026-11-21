//! Archive copy to object storage (ADR 0050 rules 1 to 14, 22, 27 and 28), end to end: real
//! relays started with `sbtp_relay::run` on loopback, and a fake S3-compatible server written
//! here that checks every signature, honours `If-None-Match: *` and records every request.
//!
//! The tests run one at a time ([`SERIAL`]): the mirror counters are process wide, so each test
//! reads them as differences.
#![cfg(feature = "object-store")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod common;

use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use common::{connect, env, put_block, signed_block, tmp_dir};
use sbtp_relay::StartError;
use sbtp_relay::config::{ConfigError, Settings};
use sbtp_relay::mirror::metrics::{self, Class};
use sbtp_relay::mirror::sigv4::{Credentials, Signing, authorization, sha256_hex};
use zeroize::Zeroizing;

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Test credentials: not keys of any account.
const ACCESS: &str = "TESTACCESSKEY";
const SECRET: &str = "test-secret-not-a-key";

fn creds() -> Credentials {
    Credentials {
        access_key: Zeroizing::new(ACCESS.into()),
        secret_key: Zeroizing::new(SECRET.into()),
        session_token: None,
    }
}

/// One request the fake store received.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    signed: bool,
}

impl Seen {
    fn header(&self, n: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct State {
    objects: HashMap<String, Vec<u8>>,
    seen: Vec<Seen>,
    /// Statuses answered, in order, to the next `PUT`s under `/archive/sbtp/v1/block/`.
    script: VecDeque<u16>,
    /// When not 0, every `fail_every`th block `PUT` (signed, not scripted) is answered `503`.
    fail_every: usize,
    block_puts: usize,
}

/// A fake S3-compatible server (path style, bucket `archive`, region `us-east-1`).
struct S3 {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl S3 {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let st = Arc::clone(&shared);
                std::thread::spawn(move || serve(s, &st));
            }
        });
        Self { addr, state }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.state().objects.get(key).cloned()
    }

    fn puts_of(&self, key: &str) -> usize {
        self.state()
            .seen
            .iter()
            .filter(|s| s.method == "PUT" && s.path == key)
            .count()
    }
}

fn block_key(id: &str) -> String {
    format!("/archive/sbtp/v1/block/{id}")
}

/// Checks the request's Signature Version 4 `Authorization` against the headers it carries and its body.
fn signature_ok(r: &Seen) -> bool {
    let (Some(auth), Some(date), Some(hash)) = (
        r.header("authorization"),
        r.header("x-amz-date"),
        r.header("x-amz-content-sha256"),
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
    let headers: Vec<(&str, &str)> = names
        .split(';')
        .map(|n| (n, r.header(n).unwrap_or("")))
        .collect();
    let expected = authorization(
        &Signing {
            method: &r.method,
            path: &r.path,
            headers: &headers,
            payload_hash: hash,
            amz_date: date,
            region: "us-east-1",
        },
        &creds(),
    );
    hash == sha256_hex(&r.body) && expected == auth && names.contains("host")
}

fn serve(mut s: TcpStream, state: &Mutex<State>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16_384];
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
        let len: usize = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .map_or(0, |(_, v)| v.parse().unwrap());
        while buf.len() < head_end + 4 + len {
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let body = buf[head_end + 4..head_end + 4 + len].to_vec();
        buf.drain(..head_end + 4 + len);
        let mut seen = Seen {
            method,
            path,
            headers,
            body,
            signed: false,
        };
        let (status, out) = {
            let mut st = state.lock().unwrap();
            let answer = if seen.method == "GET" {
                st.objects
                    .get(&seen.path)
                    .map_or((404, Vec::new()), |b| (200, b.clone()))
            } else if seen.method != "PUT" {
                (405, Vec::new())
            } else {
                seen.signed = signature_ok(&seen);
                let scripted = if seen.path.starts_with("/archive/sbtp/v1/block/") {
                    st.script.pop_front()
                } else {
                    None
                };
                if !seen.signed {
                    (403, b"<Error>SignatureDoesNotMatch</Error>".to_vec())
                } else if let Some(code) = scripted {
                    (code, Vec::new())
                } else if seen.path.starts_with("/archive/sbtp/v1/block/") && st.fail_every > 0 && {
                    st.block_puts += 1;
                    st.block_puts.is_multiple_of(st.fail_every)
                } {
                    (503, Vec::new())
                } else if seen.header("if-none-match") == Some("*")
                    && st.objects.contains_key(&seen.path)
                {
                    (412, Vec::new())
                } else {
                    st.objects.insert(seen.path.clone(), seen.body.clone());
                    (200, Vec::new())
                }
            };
            st.seen.push(seen);
            answer
        };
        let extra = if (300..400).contains(&status) {
            "Location: http://127.0.0.1:9/elsewhere\r\n"
        } else {
            ""
        };
        let head = format!(
            "HTTP/1.1 {status} X\r\n{extra}Content-Length: {}\r\n\r\n",
            out.len()
        );
        if s.write_all(head.as_bytes()).is_err() || s.write_all(&out).is_err() {
            return;
        }
    }
}

/// A relay started by `sbtp_relay::run`, stopped (cleanly) on drop.
struct Node {
    addr: SocketAddr,
    stop: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    thread: Option<JoinHandle<Result<(), StartError>>>,
}

impl Node {
    fn try_start(
        data: &Path,
        pairs: &[(&str, &str)],
        raw: &[(&str, &str)],
    ) -> Result<Self, StartError> {
        let mut e: Vec<(OsString, OsString)> = env(&[
            ("DATA_DIR", data.to_str().unwrap()),
            ("LISTEN", "127.0.0.1:0"),
            ("RATE_PUT_BURST", "1000000"),
            ("MIN_POW_DIFFICULTY", "0"),
            ("LOG_LEVEL", "warn"),
        ]);
        e.extend(env(pairs));
        e.extend(raw.iter().map(|(k, v)| ((*k).into(), (*v).into())));
        let (stop, stopped) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            sbtp_relay::run(
                sbtp_core::self_test,
                Vec::<OsString>::new(),
                e,
                move || Ok(stopped),
                move |a| {
                    let _ = addr_tx.send(a);
                },
            )
        });
        match addr_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(addr) => Ok(Self {
                addr,
                stop: Some(stop),
                thread: Some(thread),
            }),
            Err(_) => Err(thread.join().unwrap().unwrap_err()),
        }
    }

    /// A relay copying to `s3`, with the test credentials.
    fn mirrored(data: &Path, s3: &S3, pairs: &[(&str, &str)]) -> Self {
        let url = s3.url();
        let mut all = vec![
            ("MIRROR_ENDPOINT", url.as_str()),
            ("MIRROR_BUCKET", "archive"),
        ];
        all.extend_from_slice(pairs);
        Self::try_start(
            data,
            &all,
            &[
                ("SBTP_MIRROR_ACCESS_KEY_ID", ACCESS),
                ("SBTP_MIRROR_SECRET_ACCESS_KEY", SECRET),
            ],
        )
        .unwrap()
    }

    fn put(&self, block: &[u8]) -> u16 {
        put_block(&mut connect(self.addr), block).status
    }

    fn halt(&mut self) -> Result<(), StartError> {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        self.thread.take().map_or(Ok(()), |t| t.join().unwrap())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.halt();
    }
}

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    f()
}

/// A block and its hexadecimal identifier.
fn block(payload: &[u8]) -> (String, Vec<u8>) {
    let b = signed_block(payload, &[]);
    let id = sbtp_core::parse(&b).unwrap().block_id().to_string();
    (id, b)
}

/// Rules 3, 6 to 8 and 11: every stored block is copied once, with the conditional headers and a
/// valid signature; the `/info` object says `read_only`; the cursor survives a restart, so
/// nothing is sent twice; nothing but `PUT` reaches the bucket.
#[test]
fn every_block_is_copied_once_and_the_cursor_survives_a_restart() {
    let _g = serial();
    let s3 = S3::start();
    let data = tmp_dir("mirror-copy");
    let before = metrics::uploaded_total();
    let blocks: Vec<_> = (0..3u8).map(|i| block(&[b'a', i])).collect();
    {
        let mut node = Node::mirrored(&data, &s3, &[]);
        for (_, b) in &blocks {
            assert_eq!(node.put(b), 201);
        }
        assert!(wait_until(Duration::from_secs(20), || blocks
            .iter()
            .all(|(id, _)| s3.object(&block_key(id)).is_some())));
        node.halt().unwrap();
    }
    for (id, b) in &blocks {
        assert_eq!(s3.object(&block_key(id)).as_deref(), Some(b.as_slice()));
    }
    let info: serde_json::Value =
        serde_json::from_slice(&s3.object("/archive/sbtp/v1/info").unwrap()).unwrap();
    assert_eq!(info["read_only"], true);
    assert_eq!(info["block_ttl_ms"], serde_json::Value::Null);
    assert_eq!(info["demand_eviction"], false);
    assert_eq!(info["min_pow_difficulty"], 16);
    {
        let st = s3.state();
        assert!(st.seen.iter().all(|r| r.signed && r.method == "PUT"));
        for r in st.seen.iter().filter(|r| r.path.contains("/block/")) {
            assert_eq!(r.header("if-none-match"), Some("*"));
            assert_eq!(r.header("content-type"), Some("application/octet-stream"));
            assert_eq!(
                r.header("cache-control"),
                Some("public, max-age=31536000, immutable")
            );
            assert!(r.header("authorization").unwrap().contains("if-none-match"));
        }
        let info = st.seen.iter().find(|r| r.path.ends_with("/info")).unwrap();
        assert_eq!(info.header("if-none-match"), None);
        assert_eq!(info.header("cache-control"), Some("public, max-age=3600"));
        assert_eq!(info.header("content-type"), Some("application/json"));
    }
    // A restart sends neither the copied blocks nor the unchanged `/info` object again.
    let (late_id, late) = block(b"late");
    let node = Node::mirrored(&data, &s3, &[]);
    assert_eq!(node.put(&late), 201);
    assert!(wait_until(Duration::from_secs(20), || s3
        .object(&block_key(&late_id))
        .is_some()));
    drop(node);
    for (id, _) in &blocks {
        assert_eq!(s3.puts_of(&block_key(id)), 1, "{id}");
    }
    assert_eq!(s3.puts_of("/archive/sbtp/v1/info"), 1);
    assert_eq!(metrics::uploaded_total() - before, 4);
    let _ = std::fs::remove_dir_all(&data);
}

/// Rules 9, 11 and 13: a key that exists is done (first write wins), never overwritten nor
/// deleted; with `mirror_public_url` the object is fetched once and wrong bytes count as
/// poisoning.
#[test]
fn an_existing_key_is_done_and_a_poisoned_copy_is_detected() {
    let _g = serial();
    let s3 = S3::start();
    let data = tmp_dir("mirror-poison");
    let (bad_id, bad) = block(b"poisoned");
    let (good_id, good) = block(b"honest");
    s3.state()
        .objects
        .insert(block_key(&bad_id), b"not the block".to_vec());
    let (existing, poisoned) = (metrics::existing_total(), metrics::poisoned_total());
    let public = format!("{}/archive", s3.url());
    let node = Node::mirrored(&data, &s3, &[("MIRROR_PUBLIC_URL", &public)]);
    assert_eq!(node.put(&bad), 201);
    assert_eq!(node.put(&good), 201);
    assert!(wait_until(Duration::from_secs(20), || {
        s3.object(&block_key(&good_id)).is_some() && metrics::poisoned_total() > poisoned
    }));
    drop(node);
    assert_eq!(metrics::existing_total() - existing, 1);
    assert_eq!(metrics::poisoned_total() - poisoned, 1);
    assert_eq!(
        s3.object(&block_key(&bad_id)).as_deref(),
        Some(&b"not the block"[..])
    );
    let st = s3.state();
    assert!(
        st.seen
            .iter()
            .all(|r| r.method == "PUT" || r.method == "GET")
    );
    let gets: Vec<_> = st.seen.iter().filter(|r| r.method == "GET").collect();
    assert_eq!(gets.len(), 1);
    assert_eq!(gets[0].path, block_key(&bad_id));
    drop(st);
    let _ = std::fs::remove_dir_all(&data);
}

/// Rule 9: `5xx` is retried with back-off, a refused request (`403`) and a `3xx` back off at the
/// maximum; none moves the cursor or skips the block, and no redirect is followed.
#[test]
fn failures_are_retried_and_never_skip_a_block() {
    let _g = serial();
    let s3 = S3::start();
    s3.state().script.extend([503, 409, 403, 302]);
    let data = tmp_dir("mirror-retry");
    let (server, client, redirect) = (
        metrics::failed_total(Class::Server),
        metrics::failed_total(Class::Client),
        metrics::failed_total(Class::Redirect),
    );
    let (id, b) = block(b"retried");
    let (id2, b2) = block(b"after");
    let node = Node::mirrored(&data, &s3, &[("MIRROR_MAX_BACKOFF_S", "1")]);
    assert_eq!(node.put(&b), 201);
    assert_eq!(node.put(&b2), 201);
    assert!(wait_until(Duration::from_secs(30), || {
        s3.object(&block_key(&id)).is_some() && s3.object(&block_key(&id2)).is_some()
    }));
    drop(node);
    assert_eq!(s3.object(&block_key(&id)).as_deref(), Some(b.as_slice()));
    assert_eq!(s3.object(&block_key(&id2)).as_deref(), Some(b2.as_slice()));
    assert_eq!(metrics::failed_total(Class::Server) - server, 1);
    assert_eq!(metrics::failed_total(Class::Client) - client, 2);
    assert_eq!(metrics::failed_total(Class::Redirect) - redirect, 1);
    // Four failures and one success per block, over the two blocks (the lanes take them in
    // any order); nothing was sent to the redirect target.
    assert_eq!(
        s3.puts_of(&block_key(&id)) + s3.puts_of(&block_key(&id2)),
        6
    );
    assert!(
        s3.state()
            .seen
            .iter()
            .all(|r| !r.path.contains("elsewhere"))
    );
    let _ = std::fs::remove_dir_all(&data);
}

/// Rule 9 with a store that fails one block `PUT` in three: a block in back-off waits in the
/// window, not in a lane, so the others keep going; nothing is skipped and the cursor ends past
/// every block, so a restart sends none again. The back-off is capped at 1 s so that the rate
/// measures the lanes, not the longest run of failures (with the 1-hour default, that run
/// bounds any design that never skips a block).
#[test]
fn a_failing_block_does_not_hold_the_other_lanes() {
    const N: usize = 300;
    let _g = serial();
    let s3 = S3::start();
    let data = tmp_dir("mirror-every-third");
    let blocks: Vec<_> = (0..N)
        .map(|i| block(&u32::try_from(i).unwrap().to_be_bytes()))
        .collect();
    // The backlog is stored first, by a relay without the archive copy.
    {
        let node = Node::try_start(&data, &[], &[]).unwrap();
        let mut c = connect(node.addr);
        for (_, b) in &blocks {
            assert_eq!(put_block(&mut c, b).status, 201);
        }
    }
    s3.state().fail_every = 3;
    let (missed, server) = (
        metrics::missed_total(),
        metrics::failed_total(Class::Server),
    );
    let started = Instant::now();
    let node = Node::mirrored(&data, &s3, &[("MIRROR_MAX_BACKOFF_S", "1")]);
    assert!(wait_until(Duration::from_secs(60), || blocks
        .iter()
        .all(|(id, _)| s3.object(&block_key(id)).is_some())));
    let rate = f64::from(u32::try_from(N).unwrap()) / started.elapsed().as_secs_f64();
    drop(node);
    assert!(metrics::failed_total(Class::Server) - server >= N as u64 / 3);
    assert_eq!(metrics::missed_total(), missed);
    for (id, b) in &blocks {
        assert_eq!(s3.object(&block_key(id)).as_deref(), Some(b.as_slice()));
    }
    // With the page barrier and lanes asleep in back-off, about 9 blocks/s.
    assert!(rate > 25.0, "{rate:.1} blocks/s");
    let sent = s3.state().block_puts;
    s3.state().fail_every = 0;
    let node = Node::mirrored(&data, &s3, &[]);
    std::thread::sleep(Duration::from_secs(3));
    drop(node);
    assert_eq!(s3.state().block_puts, sent);
    eprintln!("every third PUT failing: {rate:.1} blocks/s");
    let _ = std::fs::remove_dir_all(&data);
}

/// Rules 22 and 28: credentials only through named variables; a value that is not a variable
/// name is refused without being repeated; the start-up stops when a named variable is unset.
#[test]
fn settings_and_credentials_are_checked() {
    let _g = serial();
    let load = |pairs: &[(&str, &str)]| Settings::load(Vec::<OsString>::new(), env(pairs));
    let on = [
        ("MIRROR_ENDPOINT", "https://s3.example"),
        ("MIRROR_BUCKET", "archive"),
    ];
    let s = load(&on).unwrap();
    assert!(s.mirror_on());
    assert_eq!(s.mirror_access_key_ref, "SBTP_MIRROR_ACCESS_KEY_ID");
    assert_eq!(s.mirror_region, "us-east-1");
    let logged: Vec<_> = s
        .effective_values()
        .filter(|(n, _, _)| *n == "mirror_endpoint")
        .collect();
    assert_eq!(logged[0].1, "set");
    for (profile, n) in [("small", 4), ("standard", 4), ("large", 8)] {
        let s = load(&[("PROFILE", profile)]).unwrap();
        assert_eq!(s.mirror_max_in_flight, n, "{profile}");
    }
    // A value pasted in the wrong setting: shaped like a key, not one.
    let pasted = "wJalr/K7MDENG+notakey";
    for setting in ["MIRROR_SECRET_KEY_REF", "MIRROR_ACCESS_KEY_REF"] {
        for bad in [pasted, "SBTP_RELAY_X", "1ABC", "lower"] {
            let e = load(&[(setting, bad)]).unwrap_err();
            assert!(matches!(e, ConfigError::Invalid { .. }), "{e}");
            assert!(!e.to_string().contains(bad), "{e}");
        }
    }
    assert!(matches!(
        load(&[("MIRROR_ENDPOINT", "https://s3.example")]),
        Err(ConfigError::Constraint(_))
    ));
    for (k, v) in [
        ("MIRROR_ENDPOINT", "http://s3.example"),
        ("MIRROR_BUCKET", "Upper"),
        ("MIRROR_REGION", "us_east"),
        ("MIRROR_PREFIX", "no-slash"),
        ("MIRROR_PREFIX", "/lead/"),
        ("MIRROR_PREFIX", "a/../"),
        ("MIRROR_URL_STYLE", "host"),
        ("MIRROR_MAX_IN_FLIGHT", "65"),
    ] {
        assert!(load(&[(k, v)]).is_err(), "{k}={v}");
    }
    assert!(load(&[("MIRROR_PREFIX", "net/a.b_c-d/")]).is_ok());
    // A named variable that is unset stops the start-up, before anything is opened.
    let data = tmp_dir("mirror-creds");
    let e = Node::try_start(&data, &on, &[("SBTP_MIRROR_ACCESS_KEY_ID", "x")])
        .err()
        .unwrap();
    assert!(
        matches!(
            e,
            StartError::Config(ConfigError::Invalid {
                setting: "mirror_secret_key_ref",
                ..
            })
        ),
        "{e}"
    );
    assert!(!data.exists());
}

/// ADR 0052 rule 18: a held block on the deny list, by `block_id` or by key, is not uploaded;
/// it is done (counted in `mirror_denied_total`) and the blocks after it are copied.
#[test]
fn denied_blocks_are_not_uploaded() {
    let _g = serial();
    let s3 = S3::start();
    let dir = tmp_dir("mirror-deny");
    std::fs::create_dir_all(&dir).unwrap();
    let data = dir.join("data");
    let (by_id, a) = block(b"denied by id");
    let k = sbtp_core::SigningKey::from_bytes(&[31; 32]);
    let b = sbtp_core::BlockBuilder::for_key(&k)
        .timestamp(common::now_ms())
        .payload(b"denied by key")
        .build(&k, 0)
        .unwrap();
    let by_key = sbtp_core::parse(&b).unwrap().block_id().to_string();
    let key = sbtp_core::BlockId(*sbtp_core::parse(&b).unwrap().pubkey()).to_string();
    let (kept, c) = block(b"copied");
    {
        // Stored before the list exists, without the archive copy.
        let mut node = Node::try_start(&data, &[], &[]).unwrap();
        for x in [&a, &b, &c] {
            assert_eq!(node.put(x), 201);
        }
        node.halt().unwrap();
    }
    let file = dir.join("deny.txt");
    std::fs::write(&file, format!("block {by_id}\nkey {key}\n")).unwrap();
    let before = metrics::denied_total();
    let node = Node::mirrored(&data, &s3, &[("DENY_FILE", file.to_str().unwrap())]);
    assert!(wait_until(Duration::from_secs(20), || s3
        .object(&block_key(&kept))
        .is_some()));
    assert!(wait_until(
        Duration::from_secs(5),
        || metrics::denied_total() - before >= 2
    ));
    drop(node);
    assert_eq!(s3.puts_of(&block_key(&by_id)), 0);
    assert_eq!(s3.puts_of(&block_key(&by_key)), 0);
    let _ = std::fs::remove_dir_all(&dir);
}
