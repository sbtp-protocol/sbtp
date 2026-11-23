//! The `sbtp` binary against an in-process relay on loopback, a canned-response server for the
//! retry and denial paths, and the key file checks. Fixed keys come from public seeds only.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sbtp_core::{BlockId, SigningKey};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    })
}
use tempfile::TempDir;

/// The fixed test key's seed (public) and its file text.
const SEED: [u8; 32] = [7; 32];
const SEED_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn sbtp(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sbtp"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The tool may exit before reading stdin (a refused key file): a broken pipe is not a failure.
    let written = child.stdin.take().unwrap().write_all(stdin);
    if let Err(e) = written {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Runs `sbtp`, expects success and returns stdout.
fn ok(args: &[&str], stdin: &[u8]) -> String {
    let out = sbtp(args, stdin);
    assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
    text(&out.stdout)
}

/// Runs `sbtp`, expects exit status 1 and nothing on stdout, and returns stderr.
fn fails(args: &[&str], stdin: &[u8]) -> String {
    let out = sbtp(args, stdin);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{args:?}: {}",
        text(&out.stdout)
    );
    assert_eq!(text(&out.stdout), "");
    text(&out.stderr)
}

/// Writes the fixed test key to `dir/name` with `mode`.
fn write_key(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&path)
        .unwrap();
    writeln!(file, "SBTP-ED25519-SECRET-KEY-V1\n{SEED_HEX}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

/// A relay on a loopback port, with its store in a temporary directory.
struct Relay {
    url: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    _dir: TempDir,
}

impl Relay {
    fn start(deny: &str) -> Self {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("deny.txt"), deny).unwrap();
        let mut config = sbtp_relay::Config::new(dir.path().to_path_buf());
        config.min_pow_difficulty = 8;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                let shutdown = async {
                    let _ = stopped.await;
                };
                sbtp_relay::run(listener, config, shutdown)
                    .await
                    .map_err(|e| e.to_string())
                    .unwrap();
            });
        });
        let url = format!("http://{}", addr_rx.recv().unwrap());
        Self {
            url,
            stop: Some(stop),
            thread: Some(thread),
            _dir: dir,
        }
    }

    fn query(&self, query: &str) -> serde_json::Value {
        let url = format!("{}/sbtp/v1/query?{query}", self.url);
        let body = ureq::get(&url)
            .call()
            .unwrap()
            .body_mut()
            .read_to_vec()
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.thread.take().unwrap().join().unwrap();
    }
}

/// The id at the start of a `publish` line, after checking the status word.
fn published(line: &str, status: &str) -> String {
    let (id, word) = line.trim_end().split_once(' ').unwrap();
    assert_eq!(word, status, "{line}");
    assert!(id.parse::<BlockId>().is_ok(), "{line}");
    id.to_owned()
}

#[test]
fn keygen_publish_get_and_the_relay_lists_both() {
    let relay = Relay::start("");
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("key");
    let key = key.to_str().unwrap();
    ok(&["keygen", key], b"");
    let url = relay.url.as_str();

    let root = published(&ok(&["publish", url, key], b"hello"), "stored");
    let child = ok(&["publish", url, key, "--parent", &root], b"child\x1b[2J");
    let child = published(&child, "stored");

    // The summary: fields, parents, and the payload escaped (no raw escape sequence).
    let summary = ok(&["get", url, &child], b"");
    assert!(
        summary.contains(&format!("block_id  {child}\n")),
        "{summary}"
    );
    assert!(
        summary.contains(&format!("parent    {root}\n")),
        "{summary}"
    );
    assert!(
        summary.contains("payload   9 bytes: \"child\\x1b[2J\""),
        "{summary}"
    );
    assert!(!summary.contains('\x1b'));

    // `--raw`: the stored bytes, whose block_id is the one asked for.
    let raw = sbtp(&["get", url, &root, "--raw"], b"").stdout;
    let block = sbtp_core::parse(&raw).unwrap();
    assert_eq!(block.block_id().to_string(), root);
    assert_eq!(block.payload(), b"hello");

    // Both blocks were stored, in order, and the child under its parent.
    let all = relay.query("since=0");
    assert_eq!(all["block_ids"], serde_json::json!([root, child]));
    let children = relay.query(&format!("parent={root}"));
    assert_eq!(children["block_ids"], serde_json::json!([child]));

    let unknown = "00".repeat(32);
    assert!(fails(&["get", url, &unknown], b"").contains("404 NotFound"));
    let nine: Vec<String> = (1..=9u8).map(|i| format!("{i:02x}").repeat(32)).collect();
    let mut args = vec!["publish", url, key];
    for p in &nine {
        args.extend(["--parent", p.as_str()]);
    }
    assert!(fails(&args, b"x").contains("more than 8 parents"));
    assert!(fails(&["publish", url, key], &vec![0; 65_536]).contains("payload longer"));
}

#[test]
fn a_denied_key_is_reported_and_nothing_is_printed() {
    let public = SigningKey::from_bytes(&SEED).verifying_key();
    let public = hex(public.as_bytes());
    let relay = Relay::start(&format!("key {public}\n"));
    let dir = TempDir::new().unwrap();
    let key = write_key(dir.path(), "key", 0o600);
    let why = fails(&["publish", &relay.url, key.to_str().unwrap()], b"hello");
    assert!(
        why.contains("451 DeniedKey: this relay's operator denies it"),
        "{why}"
    );
}

/// A server that answers each connection with the next canned response and records when each
/// request arrived and its first line.
fn canned(responses: &'static [&'static str]) -> (String, JoinHandle<Vec<(Instant, String)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for response in responses {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let (mut first, mut length) = (String::new(), 0);
            reader.read_line(&mut first).unwrap();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
                if line == "\r\n" {
                    break;
                }
            }
            reader
                .by_ref()
                .take(length)
                .read_to_end(&mut Vec::new())
                .unwrap();
            seen.push((Instant::now(), first.trim_end().to_owned()));
            let body = response.split_once("\r\n\r\n").unwrap().1;
            let head = response.split_once("\r\n\r\n").unwrap().0;
            let reply = format!(
                "{head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            reader.into_inner().write_all(reply.as_bytes()).unwrap();
        }
        seen
    });
    (url, thread)
}

const INFO: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n\
    {\"relay_id\":\"00112233445566778899aabbccddeeff\",\"min_pow_difficulty\":0,\"max_future_ms\":300000}";

#[test]
fn retry_after_is_waited_for_before_the_put_is_repeated() {
    let (url, server) = canned(&[
        INFO,
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\n\r\n{\"error\":\"RateLimited\"}",
        "HTTP/1.1 201 Created\r\n\r\n",
    ]);
    let dir = TempDir::new().unwrap();
    let key = write_key(dir.path(), "key", 0o600);
    published(
        &ok(&["publish", &url, key.to_str().unwrap()], b"hello"),
        "stored",
    );
    let seen = server.join().unwrap();
    assert!(seen[1].1.starts_with("PUT /sbtp/v1/block ") && seen[2].1 == seen[1].1);
    assert!(seen[2].0 - seen[1].0 >= Duration::from_secs(1));
}

#[test]
fn a_451_is_not_retried_and_a_redirect_is_not_followed() {
    let (url, server) = canned(&[
        INFO,
        "HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n{\"error\":\"Denied\"}",
    ]);
    let dir = TempDir::new().unwrap();
    let key = write_key(dir.path(), "key", 0o600);
    assert!(fails(&["publish", &url, key.to_str().unwrap()], b"x").contains("451 Denied"));
    assert_eq!(server.join().unwrap().len(), 2);

    let (url, server) =
        canned(&["HTTP/1.1 301 Moved Permanently\r\nLocation: http://127.0.0.1:9/\r\n\r\n"]);
    let why = fails(&["get", &url, &"00".repeat(32)], b"");
    assert!(why.contains("301"), "{why}");
    assert_eq!(server.join().unwrap().len(), 1);
}

#[test]
fn keygen_writes_an_owner_only_file_and_never_overwrites_it() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("key");
    let out = sbtp(&["keygen", path.to_str().unwrap()], b"");
    assert!(out.status.success());
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let seed = content.lines().nth(1).unwrap();
    assert_eq!(seed.len(), 64);
    // Only the public key is printed, and it is the file's.
    let mut bytes = [0u8; 32];
    for (b, pair) in bytes.iter_mut().zip(seed.as_bytes().chunks(2)) {
        *b = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    let public = SigningKey::from_bytes(&bytes).verifying_key();
    let public = hex(public.as_bytes());
    assert_eq!(text(&out.stdout), format!("{public}\n"));
    assert!(!text(&out.stderr).contains(seed));

    let why = fails(&["keygen", path.to_str().unwrap()], b"");
    assert!(why.contains("File exists"), "{why}");
    assert_eq!(fs::read_to_string(&path).unwrap(), content);
    // A dangling symbolic link is not followed either.
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), dir.path().join("link")).unwrap();
    fails(&["keygen", dir.path().join("link").to_str().unwrap()], b"");
    assert!(!dir.path().join("elsewhere").exists());
}

#[test]
fn a_key_file_others_can_access_or_a_link_is_refused_without_quoting_it() {
    let dir = TempDir::new().unwrap();
    // The relay address is never reached: the key is checked first.
    let publish = |key: &Path| {
        fails(
            &["publish", "http://127.0.0.1:9", key.to_str().unwrap()],
            b"x",
        )
    };
    for (name, mode) in [("group", 0o640), ("world", 0o604), ("all", 0o644)] {
        let why = publish(&write_key(dir.path(), name, mode));
        assert!(why.contains("chmod 600"), "{why}");
        assert!(!why.contains(SEED_HEX), "{why}");
    }
    let target = write_key(dir.path(), "target", 0o600);
    std::os::unix::fs::symlink(&target, dir.path().join("link")).unwrap();
    assert!(publish(&dir.path().join("link")).contains("cannot read key file"));
    assert!(publish(dir.path()).contains("must be a regular file"));

    let bad = dir.path().join("bad");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&bad)
        .unwrap();
    writeln!(
        file,
        "SBTP-ED25519-SECRET-KEY-V1\n{SEED_HEX}\nextra {SEED_HEX}"
    )
    .unwrap();
    let why = publish(&bad);
    assert!(
        why.contains("is not an SBTP secret key file") && !why.contains("0707"),
        "{why}"
    );
    // A read-only owner file is fine: the failure is then the unreachable relay.
    let read_only = write_key(dir.path(), "read-only", 0o400);
    assert!(publish(&read_only).contains("relay unreachable"));
}

#[test]
fn help_and_usage_errors() {
    let help = ok(&["--help"], b"");
    assert!(help.contains("sbtp keygen KEY_FILE") && help.contains("sbtp get URL BLOCK_ID"));
    assert_eq!(ok(&[], b""), help);
    assert!(fails(&["frobnicate"], b"").contains("see `sbtp --help`"));
    assert!(fails(&["get", "http://127.0.0.1:9", "XYZ"], b"").contains("not a block id"));
    assert!(fails(&["publish", "http://127.0.0.1:9", "k", "--bogus"], b"").contains("unexpected"));
}
