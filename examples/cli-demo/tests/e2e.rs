//! End-to-end tests: the `cli-demo` binary against the real `sbtp-relay`, started in-process on a
//! loopback port, and against a fake relay that serves a wrong block.
//!
//! Keys: test keys derived from public seeds only.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;

use sbtp_core::{BlockBuilder, SigningKey};

/// Difficulty of the test relay: low, so that the tests mine in milliseconds.
const RELAY_DIFFICULTY: &str = "8";

/// A fresh, empty directory under Cargo's integration-test temporary directory.
fn tmp_dir(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "cli-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `sbtp-relay` through its production entry point (`sbtp_relay::run`: self-test, settings,
/// store, index, accept loop) on `127.0.0.1:0`. Stopped on drop.
struct TestRelay {
    url: String,
    stop: tokio::sync::mpsc::UnboundedSender<()>,
    thread: Option<JoinHandle<()>>,
}

impl TestRelay {
    fn start() -> Self {
        let data = tmp_dir("relay-data");
        let env: Vec<(OsString, OsString)> = [
            ("SBTP_RELAY_MIN_POW_DIFFICULTY", RELAY_DIFFICULTY),
            ("SBTP_RELAY_LISTEN", "127.0.0.1:0"),
            ("SBTP_RELAY_DATA_DIR", data.to_str().unwrap()),
        ]
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
        let (stop, stopped) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel::<SocketAddr>();
        let thread = std::thread::spawn(move || {
            sbtp_relay::run(
                sbtp_core::self_test,
                Vec::<OsString>::new(),
                env,
                move || Ok(stopped),
                move |addr| addr_tx.send(addr).unwrap(),
            )
            .unwrap();
        });
        let addr = addr_rx.recv().expect("the relay did not start");
        Self {
            url: format!("http://{addr}"),
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Runs the CLI binary.
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cli-demo"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

#[track_caller]
fn assert_ok(o: &Output) {
    assert!(
        o.status.success(),
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        o.status,
        stdout(o),
        stderr(o)
    );
}

#[track_caller]
fn assert_code(o: &Output, code: i32) {
    assert_eq!(
        o.status.code(),
        Some(code),
        "stdout:\n{}\nstderr:\n{}",
        stdout(o),
        stderr(o)
    );
}

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The key file of the test key with public seed `[seed; 32]`, mode 0600.
fn test_key_file(dir: &Path, seed: u8) -> (PathBuf, SigningKey) {
    use std::os::unix::fs::OpenOptionsExt;
    let key = SigningKey::from_bytes(&[seed; 32]);
    let path = dir.join(format!("test-{seed}.key"));
    let hex = hex(&[seed; 32]);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    writeln!(f, "SBTP-ED25519-SECRET-KEY-V1\n{hex}").unwrap();
    (path, key)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn keygen_writes_a_0600_file_and_prints_only_the_public_key() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir("keygen");
    let path = dir.join("alice.key");
    let o = cli(&["keygen", "--out", s(&path)]);
    assert_ok(&o);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    let secret_hex = text.lines().nth(1).unwrap();
    assert_eq!(secret_hex.len(), 64);
    let pubkey = stdout(&o);
    assert_eq!(pubkey.trim().len(), 64);
    assert!(!stdout(&o).contains(secret_hex) && !stderr(&o).contains(secret_hex));

    // `pubkey` agrees, and still prints nothing secret.
    let o = cli(&["pubkey", "--key", s(&path)]);
    assert_ok(&o);
    assert_eq!(stdout(&o), pubkey);
    assert!(!stdout(&o).contains(secret_hex) && !stderr(&o).contains(secret_hex));

    // Never overwrites.
    let o = cli(&["keygen", "--out", s(&path)]);
    assert_code(&o, 1);
    assert!(
        stderr(&o).contains("refusing to overwrite"),
        "{}",
        stderr(&o)
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
}

#[test]
fn key_file_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir("mode");
    let (path, _) = test_key_file(&dir, 3);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = cli(&["pubkey", "--key", s(&path)]);
    assert_code(&o, 1);
    assert!(stderr(&o).contains("chmod 600"), "{}", stderr(&o));
}

#[test]
fn publish_and_get_round_trip_through_the_relay() {
    let relay = TestRelay::start();
    let dir = tmp_dir("round-trip");
    let (key_path, key) = test_key_file(&dir, 42);
    let payload = dir.join("hello.txt");
    std::fs::write(&payload, b"hello, relay").unwrap();
    let block = dir.join("hello.sbtp");

    // `info`, then `mine` reading the difficulty from the relay.
    let o = cli(&["info", "--relay", &relay.url]);
    assert_ok(&o);
    assert!(stdout(&o).contains(&format!("min_pow_difficulty: {RELAY_DIFFICULTY}")));
    let o = cli(&[
        "mine",
        "--key",
        s(&key_path),
        "--payload",
        s(&payload),
        "--relay",
        &relay.url,
        "--out",
        s(&block),
    ]);
    assert_ok(&o);
    let id = stdout(&o).trim().to_owned();
    assert_eq!(id.len(), 64);
    // ADR 0045 rule 5: the relay asks for 8, the block is mined at `D_NET` = 16.
    assert!(
        stderr(&o).contains("Mined at difficulty 16"),
        "{}",
        stderr(&o)
    );
    assert!(id.starts_with("0000"), "16 leading zero bits: {id}");

    // First publish stores (201), the second finds it (200); both succeed.
    let o = cli(&["publish", "--relay", &relay.url, s(&block)]);
    assert_ok(&o);
    assert_eq!(stdout(&o).trim(), id);
    assert!(stderr(&o).contains("201 Created"), "{}", stderr(&o));
    let o = cli(&["publish", "--relay", &relay.url, s(&block)]);
    assert_ok(&o);
    assert!(stderr(&o).contains("200 OK"), "{}", stderr(&o));

    // `get` verifies and returns the same bytes and payload.
    let fetched = dir.join("fetched.sbtp");
    let fetched_payload = dir.join("fetched.txt");
    let o = cli(&[
        "get",
        "--relay",
        &relay.url,
        "--difficulty",
        RELAY_DIFFICULTY,
        "--out",
        s(&fetched),
        "--payload-out",
        s(&fetched_payload),
        &id,
    ]);
    assert_ok(&o);
    let out = stdout(&o);
    assert!(out.contains(&format!("block_id:   {id}")), "{out}");
    assert!(out.contains("\"hello, relay\""), "{out}");
    let pubkey = hex(key.verifying_key().as_bytes());
    assert!(out.contains(&pubkey), "{out}");
    assert_eq!(
        std::fs::read(&fetched).unwrap(),
        std::fs::read(&block).unwrap()
    );
    assert_eq!(std::fs::read(&fetched_payload).unwrap(), b"hello, relay");

    // A child block with the first as parent.
    let child = dir.join("child.sbtp");
    let o = cli(&[
        "mine",
        "--key",
        s(&key_path),
        "--parent",
        &id,
        "--difficulty",
        RELAY_DIFFICULTY,
        "--out",
        s(&child),
    ]);
    assert_ok(&o);
    let child_id = stdout(&o).trim().to_owned();
    assert_ok(&cli(&["publish", "--relay", &relay.url, s(&child)]));
    let o = cli(&["get", "--relay", &relay.url, &child_id]);
    assert_ok(&o);
    assert!(stdout(&o).contains(&format!("  - {id}")), "{}", stdout(&o));
    let o = cli(&["inspect", s(&child)]);
    assert_ok(&o);
    assert!(stdout(&o).contains("parents:    1"));
}

#[test]
fn relay_refusals_show_status_and_error_body() {
    let relay = TestRelay::start();
    let dir = tmp_dir("refusals");
    let (key_path, _) = test_key_file(&dir, 7);

    // A block without proof of work: valid locally, refused by the relay (C1).
    // Nonce 0 meets 8 bits with probability 1/256: take the first timestamp whose block does not.
    let weak = dir.join("weak.sbtp");
    let found = (1..=8).any(|timestamp| {
        assert_ok(&cli(&[
            "mine",
            "--key",
            s(&key_path),
            "--difficulty",
            "0",
            "--timestamp",
            &timestamp.to_string(),
            "--force",
            "--out",
            s(&weak),
        ]));
        let o = cli(&["inspect", "--difficulty", RELAY_DIFFICULTY, s(&weak)]);
        o.status.code() == Some(4) && stderr(&o).contains("InsufficientPow")
    });
    assert!(found);
    let o = cli(&["publish", "--relay", &relay.url, s(&weak)]);
    assert_code(&o, 3);
    let err = stderr(&o);
    assert!(err.contains("400 Bad Request"), "{err}");
    assert!(err.contains("InsufficientPow"), "{err}");

    // An unknown block_id: 404 NotFound, nothing written.
    let out = dir.join("missing.sbtp");
    let o = cli(&[
        "get",
        "--relay",
        &relay.url,
        "--out",
        s(&out),
        &"ab".repeat(32),
    ]);
    assert_code(&o, 3);
    assert!(
        stderr(&o).contains("404 Not Found: NotFound"),
        "{}",
        stderr(&o)
    );
    assert!(!out.exists());
}

#[test]
fn local_errors_have_distinct_exit_codes() {
    let dir = tmp_dir("local");
    let bad = dir.join("bad.sbtp");
    std::fs::write(&bad, b"not a block").unwrap();
    let o = cli(&["inspect", s(&bad)]);
    assert_code(&o, 4);
    assert!(stderr(&o).contains("TooShort"), "{}", stderr(&o));
    let o = cli(&["publish", "--relay", "http://127.0.0.1:9", s(&bad)]);
    assert_code(&o, 4);
    assert!(stderr(&o).contains("not sent"), "{}", stderr(&o));

    let o = cli(&["info", "--relay", "https://relay.example"]);
    assert_code(&o, 2);
    assert!(stderr(&o).contains("no TLS"), "{}", stderr(&o));
    assert_code(&cli(&["frobnicate"]), 2);
    assert_code(&cli(&["mine", "--nope"]), 2);
    assert_code(&cli(&[]), 2);

    // Help: global and per command, exit 0.
    let o = cli(&["--help"]);
    assert_ok(&o);
    // ADR 0026 clarification: status 4 lists both an invalid block and the local floor.
    let help = stdout(&o);
    let status_4 = help
        .split("\n    4  ")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .unwrap_or_default();
    assert!(status_4.contains("failed\n       validation"), "{help}");
    assert!(
        status_4.contains("below the local\n       floor of `get --difficulty`"),
        "{help}"
    );
    for name in [
        "keygen", "pubkey", "mine", "inspect", "publish", "get", "query", "info",
    ] {
        assert!(stdout(&o).contains(name));
        let o = cli(&[name, "--help"]);
        assert_ok(&o);
        assert!(stdout(&o).starts_with(&format!("cli-demo {name}:")));
    }

    // Nothing listens on the discard port: a network failure (1) with a hint.
    let o = cli(&["info", "--relay", "http://127.0.0.1:9"]);
    assert_code(&o, 1);
    assert!(stderr(&o).contains("Is a relay running"), "{}", stderr(&o));
}

/// A relay that answers every request with `200` and `body`, once per connection.
fn fake_relay(body: Vec<u8>, requests: usize) -> (String, JoinHandle<()>) {
    fake_server("200 OK", "application/octet-stream", "", body, requests)
}

/// A server that answers `requests` connections with `status`, `content_type`, the extra header
/// lines `extra` (each ending in `\r\n`) and `body`.
fn fake_server(
    status: &'static str,
    content_type: &'static str,
    extra: &'static str,
    body: Vec<u8>,
    requests: usize,
) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        for stream in listener.incoming().take(requests) {
            let mut stream = stream.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap() == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n{extra}\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            // The client may close early (body over its limit): write errors are expected.
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (url, thread)
}

/// Security review 2026-11-19, M-1: a block of exactly `MAX_BLOCK_LEN` bytes (8 parents, maximum
/// payload) is fetched and verified; one byte more is refused as `TooLong` before parsing, and
/// nothing is written.
#[test]
fn get_accepts_a_maximum_length_block_and_refuses_one_byte_more() {
    let dir = tmp_dir("max-len");
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let parents: Vec<sbtp_core::BlockId> = (1..=8u8)
        .map(|i| sbtp_core::BlockId::from_bytes([i; 32]))
        .collect();
    let payload = vec![b'x'; sbtp_core::layout::MAX_PAYLOAD_LEN];
    let block = BlockBuilder::for_key(&key)
        .parents(&parents)
        .payload(&payload)
        .build(&key, 0)
        .unwrap();
    assert_eq!(block.len(), sbtp_core::layout::MAX_BLOCK_LEN);
    let id = sbtp_core::parse(&block).unwrap().block_id().to_string();

    let (url, t) = fake_relay(block.clone(), 1);
    let out = dir.join("max.sbtp");
    let o = cli(&["get", "--relay", &url, "--out", s(&out), &id]);
    t.join().unwrap();
    assert_ok(&o);
    assert!(
        stdout(&o).contains("payload:    65535 bytes"),
        "{}",
        stdout(&o)
    );
    assert_eq!(std::fs::read(&out).unwrap(), block);

    let mut longer = block;
    longer.push(0);
    let (url, t) = fake_relay(longer, 1);
    let out = dir.join("longer.sbtp");
    let o = cli(&["get", "--relay", &url, "--out", s(&out), &id]);
    t.join().unwrap();
    assert_code(&o, 4);
    assert!(stderr(&o).contains("TooLong"), "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
    assert!(!out.exists());
}

/// Security review 2026-11-19, L-1 and L-4: escape sequences and bidi controls in a payload and in
/// a relay's error body never reach the terminal raw.
#[test]
fn terminal_escapes_from_payloads_and_relays_are_neutralised() {
    let raw = ['\u{1b}', '\u{9b}', '\u{7}', '\u{202e}', '\u{200b}'];
    let key = SigningKey::from_bytes(&[12u8; 32]);
    let block = BlockBuilder::for_key(&key)
        .payload("a\u{1b}[2J\u{1b}]0;owned\u{7}b\u{9b}31m\u{202e}exe.txt\u{200b}".as_bytes())
        .build(&key, 0)
        .unwrap();
    let id = sbtp_core::parse(&block).unwrap().block_id().to_string();
    let (url, t) = fake_relay(block, 1);
    let o = cli(&["get", "--relay", &url, &id]);
    t.join().unwrap();
    assert_ok(&o);
    let (out, err) = (stdout(&o), stderr(&o));
    assert!(
        out.contains("\\u{1b}[2J") && out.contains("\\u{202e}"),
        "{out}"
    );
    for c in raw {
        assert!(
            !out.contains(c) && !err.contains(c),
            "{c:?} reached the terminal"
        );
    }

    let body = br#"{"error":"Bad\u001b[31mName","message":"m\u001b]0;title\u0007\u202e!"}"#;
    let (url, t) = fake_server("400 Bad Request", "application/json", "", body.to_vec(), 1);
    let o = cli(&["get", "--relay", &url, &"ab".repeat(32)]);
    t.join().unwrap();
    assert_code(&o, 3);
    let err = stderr(&o);
    assert!(err.contains("400 Bad Request: Bad\\u{1b}[31mName"), "{err}");
    for c in raw {
        assert!(
            !stdout(&o).contains(c) && !err.contains(c),
            "{c:?} reached the terminal"
        );
    }
}

/// A redirect is reported (exit 3), not followed: following it would reach the closed port 9 and
/// exit 1.
#[test]
fn redirects_are_not_followed() {
    let (url, t) = fake_server(
        "301 Moved Permanently",
        "text/plain",
        "Location: http://127.0.0.1:9/sbtp/v1/info\r\n",
        Vec::new(),
        1,
    );
    let o = cli(&["info", "--relay", &url]);
    t.join().unwrap();
    assert_code(&o, 3);
    assert!(stderr(&o).contains("301"), "{}", stderr(&o));
    assert!(stderr(&o).contains("does not redirect"), "{}", stderr(&o));
}

/// `mine --relay` refuses a relay announcing more than 24 bits, before reading the key or hashing.
#[test]
fn mine_refuses_a_relay_difficulty_above_24() {
    let dir = tmp_dir("hostile-info");
    let (key_path, _) = test_key_file(&dir, 13);
    let body = br#"{"min_pow_difficulty":25,"max_future_ms":300000}"#.to_vec();
    let (url, t) = fake_server("200 OK", "application/json", "", body, 1);
    let out = dir.join("never.sbtp");
    let started = std::time::Instant::now();
    let o = cli(&[
        "mine",
        "--key",
        s(&key_path),
        "--relay",
        &url,
        "--out",
        s(&out),
    ]);
    t.join().unwrap();
    assert_code(&o, 3);
    assert!(stderr(&o).contains("above the 24"), "{}", stderr(&o));
    assert!(!out.exists());
    // 2^25 hashes take seconds; a refusal before mining takes milliseconds.
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

/// Key files: a symbolic link (even to a 0600 file), a group-readable file and a FIFO are refused;
/// the FIFO without blocking.
#[test]
fn key_file_symlink_group_mode_and_fifo_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir("key-kinds");
    let (path, _) = test_key_file(&dir, 14);

    let link = dir.join("link.key");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    let o = cli(&["pubkey", "--key", s(&link)]);
    assert_code(&o, 1);
    assert!(
        stderr(&o).contains("cannot open key file"),
        "{}",
        stderr(&o)
    );
    assert_ok(&cli(&["pubkey", "--key", s(&path)]));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let o = cli(&["pubkey", "--key", s(&path)]);
    assert_code(&o, 1);
    assert!(stderr(&o).contains("mode 0640"), "{}", stderr(&o));

    let fifo = dir.join("fifo.key");
    let made = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(made.success());
    let o = cli(&["pubkey", "--key", s(&fifo)]);
    assert_code(&o, 1);
    assert!(stderr(&o).contains("not a regular file"), "{}", stderr(&o));
}

/// Security review 2026-11-19, L-3: `get --out --payload-out` writes both files or neither.
#[test]
fn get_writes_both_outputs_or_neither() {
    let dir = tmp_dir("both-or-neither");
    let key = SigningKey::from_bytes(&[15u8; 32]);
    let block = BlockBuilder::for_key(&key)
        .payload(b"pair")
        .build(&key, 0)
        .unwrap();
    let id = sbtp_core::parse(&block).unwrap().block_id().to_string();
    let (out, payload_out) = (dir.join("b.sbtp"), dir.join("p.txt"));
    std::fs::write(&payload_out, b"keep").unwrap();
    let (url, t) = fake_relay(block, 1);
    let o = cli(&[
        "get",
        "--relay",
        &url,
        "--out",
        s(&out),
        "--payload-out",
        s(&payload_out),
        &id,
    ]);
    t.join().unwrap();
    assert_code(&o, 1);
    assert!(stderr(&o).contains("already exists"), "{}", stderr(&o));
    assert!(!out.exists());
    assert_eq!(std::fs::read(&payload_out).unwrap(), b"keep");
    let names: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(names.len(), 1, "a temporary file was left behind");
}

/// spec §3.4: a block served for another `block_id` is rejected (R1) and nothing is written or
/// printed; a block whose signature does not verify is rejected too (C3).
#[test]
fn get_rejects_a_wrong_or_forged_block_and_writes_nothing() {
    let dir = tmp_dir("forged");
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let valid = BlockBuilder::for_key(&key)
        .payload(b"genuine")
        .build(&key, 0)
        .unwrap();
    let valid_id = sbtp_core::parse(&valid).unwrap().block_id();

    // R1: the relay answers a request for another id with a valid block.
    let (url, t) = fake_relay(valid.clone(), 1);
    let out = dir.join("r1.sbtp");
    let o = cli(&["get", "--relay", &url, "--out", s(&out), &"cd".repeat(32)]);
    t.join().unwrap();
    assert_code(&o, 4);
    assert!(stderr(&o).contains("BlockIdMismatch"), "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
    assert!(!out.exists());

    // C3: the right id, a corrupted signature.
    let mut forged = valid;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (url, t) = fake_relay(forged, 1);
    let out = dir.join("c3.sbtp");
    let o = cli(&[
        "get",
        "--relay",
        &url,
        "--out",
        s(&out),
        &valid_id.to_string(),
    ]);
    t.join().unwrap();
    assert_code(&o, 4);
    assert!(stderr(&o).contains("InvalidSignature"), "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
    assert!(!out.exists());
}

/// ADR 0026 rule 4: a valid block below the local floor (`--difficulty`) is refused as local
/// policy, not reported as an invalid block from the relay. A block that also fails C3 is still
/// reported as invalid.
#[test]
fn get_below_the_local_floor_is_not_a_relay_fault() {
    let key = SigningKey::from_bytes(&[16u8; 32]);
    // Nonce 0, no mining: find a block with fewer than 8 leading zero bits (probability 255/256).
    let (block, id) = (0..16u64)
        .map(|t| {
            let b = BlockBuilder::for_key(&key)
                .timestamp(t)
                .payload(b"floor")
                .build(&key, 0)
                .unwrap();
            let id = sbtp_core::parse(&b).unwrap().block_id();
            (b, id)
        })
        .find(|(_, id)| id.leading_zero_bits() < 8)
        .unwrap();
    let (url, t) = fake_relay(block.clone(), 1);
    let o = cli(&["get", "--relay", &url, "--difficulty", "8", &id.to_string()]);
    t.join().unwrap();
    assert_code(&o, 4);
    let err = stderr(&o);
    assert!(err.contains("below the local floor"), "{err}");
    assert!(err.contains("not a fault of the relay"), "{err}");
    assert!(!err.contains("sent an invalid block"), "{err}");
    assert_eq!(stdout(&o), "");

    // ADR 0026 clarification: exit 4 does not say who is at fault; the same `get` without
    // `--difficulty` (`d = 0`) succeeds, which shows the first refusal was the local floor.
    let (url, t) = fake_relay(block.clone(), 1);
    let o = cli(&["get", "--relay", &url, &id.to_string()]);
    t.join().unwrap();
    assert_ok(&o);

    // The same block with a broken signature: the relay did send an invalid block.
    let mut forged = block;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let (url, t) = fake_relay(forged, 1);
    let o = cli(&["get", "--relay", &url, "--difficulty", "8", &id.to_string()]);
    t.join().unwrap();
    assert_code(&o, 4);
    let err = stderr(&o);
    assert!(err.contains("sent an invalid block"), "{err}");
    assert!(err.contains("InvalidSignature"), "{err}");

    // The help text states that the floor is local and independent of /info.
    let o = cli(&["get", "--help"]);
    assert!(
        stdout(&o).contains("Local proof-of-work floor"),
        "{}",
        stdout(&o)
    );
    assert!(
        stdout(&o).contains("independent of the relay"),
        "{}",
        stdout(&o)
    );

    // Security review 2026-11-19 query, I-2: above 256 is a usage error, before any request
    // (nothing listens on port 9: a request would exit 1).
    let o = cli(&[
        "get",
        "--relay",
        "http://127.0.0.1:9",
        "--difficulty",
        "257",
        &id.to_string(),
    ]);
    assert_code(&o, 2);
    assert!(stderr(&o).contains("the maximum is 256"), "{}", stderr(&o));
}

/// Mines and publishes a block with `parent` (if any) and `ts`; returns its `block_id`.
fn mine_and_publish(relay: &str, key: &Path, dir: &Path, parent: Option<&str>, ts: u64) -> String {
    let out = dir.join(format!("b{ts}.sbtp"));
    let ts = ts.to_string();
    let mut args = vec![
        "mine",
        "--key",
        s(key),
        "--difficulty",
        RELAY_DIFFICULTY,
        "--timestamp",
        &ts,
        "--out",
        s(&out),
    ];
    if let Some(p) = parent {
        args.extend(["--parent", p]);
    }
    let o = cli(&args);
    assert_ok(&o);
    assert_ok(&cli(&["publish", "--relay", relay, s(&out)]));
    stdout(&o).trim().to_owned()
}

/// The `cursor: <C>` line that `query` prints on standard error.
fn printed_cursor(o: &Output) -> String {
    stderr(o)
        .lines()
        .find_map(|l| l.strip_prefix("cursor: "))
        .unwrap()
        .to_owned()
}

fn sorted_lines(text: &str) -> Vec<String> {
    let mut v: Vec<String> = text.lines().map(str::to_owned).collect();
    v.sort();
    v
}

/// `query` against the real relay: a walk over several pages, a poll from the printed cursor, a
/// listing without filters, and a cursor the relay does not recognise (`InvalidCursor`, ADR 0024
/// rule 8), after which the walk starts again and still lists every child.
#[test]
fn query_walks_polls_and_restarts_on_an_unknown_cursor() {
    let relay = TestRelay::start();
    let dir = tmp_dir("query");
    let (key, _) = test_key_file(&dir, 17);
    let root = mine_and_publish(&relay.url, &key, &dir, None, 1);
    let mut children: Vec<String> = (2..=4)
        .map(|ts| mine_and_publish(&relay.url, &key, &dir, Some(&root), ts))
        .collect();
    children.sort();

    // Three children, pages of 2: two pages, every child once.
    let o = cli(&[
        "query", "--relay", &relay.url, "--parent", &root, "--limit", "2",
    ]);
    assert_ok(&o);
    assert_eq!(sorted_lines(&stdout(&o)), children);
    assert!(
        stderr(&o).contains("3 block_id(s) in 2 page(s)."),
        "{}",
        stderr(&o)
    );
    let cursor = printed_cursor(&o);

    // Poll from the cursor: only the child stored since.
    let late = mine_and_publish(&relay.url, &key, &dir, Some(&root), 5);
    let o = cli(&[
        "query", "--relay", &relay.url, "--parent", &root, "--cursor", &cursor,
    ]);
    assert_ok(&o);
    assert_eq!(stdout(&o).trim(), late);
    children.push(late);
    children.sort();

    // No filter: the root and every child.
    let o = cli(&["query", "--relay", &relay.url, "--limit", "3"]);
    assert_ok(&o);
    let mut all = children.clone();
    all.push(root.clone());
    all.sort();
    assert_eq!(sorted_lines(&stdout(&o)), all);

    // A cursor within the syntax that this relay never issued: InvalidCursor, then a full walk.
    let o = cli(&[
        "query",
        "--relay",
        &relay.url,
        "--parent",
        &root,
        "--limit",
        "2",
        "--cursor",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ]);
    assert_ok(&o);
    assert!(stderr(&o).contains("InvalidCursor"), "{}", stderr(&o));
    assert!(stderr(&o).contains("walking again"), "{}", stderr(&o));
    // I-1: a rejected starting cursor means earlier runs' identifiers come again.
    assert!(
        stderr(&o).contains("printed by earlier runs will be printed again"),
        "{}",
        stderr(&o)
    );
    assert_eq!(sorted_lines(&stdout(&o)), children);

    // A cursor outside the syntax, a zero limit, an interval without --follow: usage errors.
    let o = cli(&["query", "--relay", &relay.url, "--cursor", "a+b"]);
    assert_code(&o, 2);
    let o = cli(&["query", "--relay", &relay.url, "--limit", "0"]);
    assert_code(&o, 2);
    let o = cli(&["query", "--relay", &relay.url, "--interval", "5"]);
    assert_code(&o, 2);
}

/// A server that answers one connection per entry of `answers` (status line, JSON body) and
/// returns the request target (`/sbtp/v1/query?...`) of each request.
fn scripted_server(answers: Vec<(&'static str, String)>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        let mut targets = Vec::new();
        for (status, body) in answers {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap() == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            let target = text
                .lines()
                .next()
                .and_then(|l| l.split(' ').nth(1))
                .unwrap_or("")
                .to_owned();
            targets.push(target);
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
        targets
    });
    (url, thread)
}

fn page(ids: &[&str], cursor: &str, more: bool) -> String {
    let ids: Vec<String> = ids.iter().map(|i| format!("\"{i}\"")).collect();
    format!(
        r#"{{"block_ids":[{}],"cursor":"{cursor}","more":{more}}}"#,
        ids.join(",")
    )
}

/// ADR 0024 rule 8: after `InvalidCursor` mid-walk the next request has no cursor and the same
/// filters; an identifier sent again after the restart is printed once.
#[test]
fn query_restarts_without_the_rejected_cursor() {
    let (a, b, parent) = ("0a".repeat(32), "0b".repeat(32), "0c".repeat(32));
    let (url, t) = scripted_server(vec![
        ("200 OK", page(&[&a], "c1", true)),
        ("400 Bad Request", r#"{"error":"InvalidCursor"}"#.to_owned()),
        ("200 OK", page(&[&a, &b], "n1", false)),
    ]);
    let o = cli(&[
        "query", "--relay", &url, "--parent", &parent, "--limit", "2",
    ]);
    let targets = t.join().unwrap();
    assert_ok(&o);
    assert_eq!(stdout(&o), format!("{a}\n{b}\n"));
    let base = format!("/sbtp/v1/query?parent={parent}&limit=2");
    assert_eq!(
        targets,
        [base.clone(), format!("{base}&cursor=c1"), base.clone()]
    );
    assert!(
        stderr(&o).contains("1 restart(s) after InvalidCursor"),
        "{}",
        stderr(&o)
    );
}

/// ADR 0012 clarification K1: `InvalidParameter` stops the walk: no restart, no repeat. The last
/// good cursor is shown for a later resume.
#[test]
fn query_stops_on_invalid_parameter_without_restart() {
    let a = "0a".repeat(32);
    let (url, t) = scripted_server(vec![
        ("200 OK", page(&[&a], "c1", true)),
        (
            "400 Bad Request",
            r#"{"error":"InvalidParameter","message":"bad limit"}"#.to_owned(),
        ),
    ]);
    let o = cli(&["query", "--relay", &url]);
    let targets = t.join().unwrap();
    // A third request would find the port closed and exit 1, not 3.
    assert_code(&o, 3);
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[1], "/sbtp/v1/query?cursor=c1");
    let err = stderr(&o);
    assert!(err.contains("400 Bad Request: InvalidParameter"), "{err}");
    assert!(!err.contains("walking again"), "{err}");
    assert!(err.contains("Resume later with `--cursor c1`"), "{err}");
    assert_eq!(stdout(&o), format!("{a}\n"));
}

/// ADR 0012 clarification K2: a `500` keeps the cursor; the same request is repeated after a
/// back-off of at least 1 second.
#[test]
fn query_keeps_the_cursor_and_backs_off_after_a_server_error() {
    let (a, b) = ("0a".repeat(32), "0b".repeat(32));
    let (url, t) = scripted_server(vec![
        ("200 OK", page(&[&a], "c1", true)),
        (
            "500 Internal Server Error",
            r#"{"error":"Internal"}"#.to_owned(),
        ),
        ("200 OK", page(&[&b], "c2", false)),
    ]);
    let started = std::time::Instant::now();
    let o = cli(&["query", "--relay", &url]);
    let targets = t.join().unwrap();
    assert_ok(&o);
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    assert_eq!(stdout(&o), format!("{a}\n{b}\n"));
    assert_eq!(
        targets,
        [
            "/sbtp/v1/query",
            "/sbtp/v1/query?cursor=c1",
            "/sbtp/v1/query?cursor=c1"
        ]
    );
    let err = stderr(&o);
    assert!(err.contains("answered 500; keeping the cursor"), "{err}");
    assert!(!err.contains("walking again"), "{err}");
    assert!(err.contains("cursor: c2"), "{err}");
}

/// A loopback URL where nothing listens: the port was bound, then released.
fn dead_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

/// Several relays: one mining at the highest difficulty, publish to all in parallel, `get` with
/// failover on 404, `query` merged across relays with one cursor per relay.
#[test]
fn several_relays_publish_get_and_query() {
    let a = TestRelay::start();
    let b = TestRelay::start();
    let dir = tmp_dir("multi");
    let (key, _) = test_key_file(&dir, 23);
    let both = format!("{},{}", a.url, b.url);

    // `mine` reads both /info and mines once.
    let shared = dir.join("shared.sbtp");
    let o = cli(&[
        "mine",
        "--key",
        s(&key),
        "--relay",
        &a.url,
        "--relay",
        &b.url,
        "--out",
        s(&shared),
    ]);
    assert_ok(&o);
    assert!(
        // ADR 0045 rule 5: the relays ask for 8; the block is mined at `D_NET`.
        stderr(&o).contains("Mining at difficulty 16, the network difficulty"),
        "{}",
        stderr(&o)
    );
    let shared_id = stdout(&o).trim().to_owned();

    // Publish to both (a comma list): two 201s, the block_id once.
    let o = cli(&["publish", "--relay", &both, s(&shared)]);
    assert_ok(&o);
    assert_eq!(stdout(&o).trim(), shared_id);
    assert_eq!(
        stderr(&o).matches("201 Created").count(),
        2,
        "{}",
        stderr(&o)
    );

    // Blocks held by one relay only.
    let only_a = mine_and_publish(&a.url, &key, &dir, None, 11);
    let only_b = mine_and_publish(&b.url, &key, &dir, None, 12);

    // `get` asks a first, gets 404, then b, which serves it; the block is verified.
    let o = cli(&["get", "--relay", &a.url, "--relay", &b.url, &only_b]);
    assert_ok(&o);
    assert!(stdout(&o).contains(&format!("block_id:   {only_b}")));
    let err = stderr(&o);
    assert!(
        err.contains("404") && err.contains(&format!("Served by relay {}", b.url)),
        "{err}"
    );
    // Not held anywhere: every relay's 404, status 3.
    let o = cli(&["get", "--relay", &both, &"ee".repeat(32)]);
    assert_code(&o, 3);
    assert!(stderr(&o).contains("on any relay"), "{}", stderr(&o));
    assert!(stderr(&o).matches("404").count() >= 2, "{}", stderr(&o));

    // `query` over both: every block once, though `shared` is on both; a cursor per relay.
    let o = cli(&["query", "--relay", &both]);
    assert_ok(&o);
    let mut all = vec![shared_id.clone(), only_a.clone(), only_b.clone()];
    all.sort();
    assert_eq!(sorted_lines(&stdout(&o)), all);
    let cursors: Vec<String> = stderr(&o)
        .lines()
        .filter_map(|l| l.strip_prefix("cursor: "))
        .map(str::to_owned)
        .collect();
    assert_eq!(cursors.len(), 2, "{}", stderr(&o));
    assert!(
        cursors[0].starts_with(&format!("{}=", a.url)),
        "{cursors:?}"
    );
    assert!(
        cursors[1].starts_with(&format!("{}=", b.url)),
        "{cursors:?}"
    );

    // A poll from both cursors: only what was stored since, on whichever relay.
    let late = mine_and_publish(&b.url, &key, &dir, None, 13);
    let o = cli(&[
        "query",
        "--relay",
        &both,
        "--cursor",
        &cursors[0],
        "--cursor",
        &cursors[1],
    ]);
    assert_ok(&o);
    assert_eq!(stdout(&o).trim(), late);

    // A bare cursor with several relays, a cursor that names no relay of the list, two cursors for
    // one relay: usage errors.
    let cursor_a = cursors[0].rsplit_once('=').unwrap().1;
    for bad in [
        vec!["--cursor", cursor_a],
        vec!["--cursor", "http://127.0.0.1:1=abc"],
        vec!["--cursor", &cursors[0], "--cursor", &cursors[0]],
    ] {
        let mut args = vec!["query", "--relay", &both];
        args.extend(bad);
        assert_code(&cli(&args), 2);
    }

    // `info` on both.
    let o = cli(&["info", "--relay", &both]);
    assert_ok(&o);
    assert_eq!(stdout(&o).matches("min_pow_difficulty").count(), 2);
}

/// Publishing succeeds when one relay acknowledges; the others are named with a retry command.
/// Every relay down: status 1. A relay list is checked as a whole before anything is sent.
#[test]
fn several_relays_publish_partial_failure_and_list_checks() {
    let a = TestRelay::start();
    let dir = tmp_dir("multi-fail");
    let (key, _) = test_key_file(&dir, 24);
    let block = dir.join("b.sbtp");
    assert_ok(&cli(&[
        "mine",
        "--key",
        s(&key),
        "--difficulty",
        RELAY_DIFFICULTY,
        "--out",
        s(&block),
    ]));
    let dead = dead_relay();
    let o = cli(&["publish", "--relay", &dead, "--relay", &a.url, s(&block)]);
    assert_ok(&o);
    let err = stderr(&o);
    assert!(err.contains("Published on 1 of 2 relays"), "{err}");
    assert!(
        err.contains(&format!("cli-demo publish --relay {dead} ")),
        "{err}"
    );
    assert_eq!(stdout(&o).trim().len(), 64);

    let o = cli(&[
        "publish",
        "--relay",
        &format!("{dead},{}", dead_relay()),
        s(&block),
    ]);
    assert_code(&o, 1);
    assert!(
        stderr(&o).contains("not stored on any relay"),
        "{}",
        stderr(&o)
    );

    // `mine` with an unreachable relay among reachable ones uses the others.
    let o = cli(&[
        "mine",
        "--key",
        s(&key),
        "--relay",
        &format!("{dead},{}", a.url),
        "--out",
        s(&dir.join("m.sbtp")),
    ]);
    assert_ok(&o);

    // Empty element, https in the list, more than 8 relays: usage errors.
    let nine: Vec<String> = (1..=9).map(|p| format!("http://127.0.0.1:{p}")).collect();
    for list in [
        format!("{},", a.url),
        format!("{},https://relay.example.org", a.url),
        nine.join(","),
    ] {
        assert_code(&cli(&["publish", "--relay", &list, s(&block)]), 2);
    }
    // The same relay twice is used once.
    let o = cli(&["publish", "--relay", &format!("{0},{0}/", a.url), s(&block)]);
    assert_ok(&o);
    assert_eq!(stderr(&o).matches("200 OK").count(), 1, "{}", stderr(&o));
}

/// A hostile relay first in the list serves a wrong block: it is reported and the next relay's
/// valid block is used. Only hostile or unreachable relays: status 4, nothing written.
#[test]
fn several_relays_get_skips_a_hostile_relay() {
    let good = TestRelay::start();
    let dir = tmp_dir("multi-hostile");
    let (key, _) = test_key_file(&dir, 25);
    let id = mine_and_publish(&good.url, &key, &dir, None, 21);
    let other = SigningKey::from_bytes(&[26u8; 32]);
    let wrong = BlockBuilder::for_key(&other)
        .payload(b"not the one asked for")
        .build(&other, 0)
        .unwrap();

    let (hostile, t) = fake_relay(wrong.clone(), 1);
    let out = dir.join("got.sbtp");
    let list = format!("{hostile},{}", good.url);
    let o = cli(&["get", "--relay", &list, "--out", s(&out), &id]);
    t.join().unwrap();
    assert_ok(&o);
    let err = stderr(&o);
    assert!(
        err.contains("BlockIdMismatch") && err.contains("Served by relay"),
        "{err}"
    );
    assert!(stdout(&o).contains(&format!("block_id:   {id}")));
    assert!(out.exists());

    let (hostile, t) = fake_relay(wrong, 1);
    let out = dir.join("none.sbtp");
    let dead = dead_relay();
    let o = cli(&[
        "get",
        "--relay",
        &hostile,
        "--relay",
        &dead,
        "--out",
        s(&out),
        &id,
    ]);
    t.join().unwrap();
    assert_code(&o, 4);
    assert!(stderr(&o).contains("no valid block"), "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
    assert!(!out.exists());
}

/// A server that answers every connection with `503` and `Retry-After: 3600` until `stop` is set,
/// and returns how many requests it received.
fn busy_server() -> (
    String,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    JoinHandle<usize>,
) {
    use std::sync::atomic::AtomicBool;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut count = 0;
        while !flag.load(Ordering::Relaxed) {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            };
            stream.set_nonblocking(false).unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            count += 1;
            let body = r#"{"error":"Unavailable"}"#;
            let reply = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n\
                 Retry-After: 3600\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
        count
    });
    (url, stop, thread)
}

/// Security review 2026-11-21, M-1: under `--follow`, a relay whose walk failed (here a
/// `Retry-After` of an hour, above the 300 s maximum) is retired for the run: it is never asked
/// again, while the other relay is still polled. When the last relay fails too, the command ends.
#[test]
fn query_follow_retires_a_relay_whose_walk_failed() {
    let a = "0a".repeat(32);
    let (good, t) = scripted_server(vec![
        ("200 OK", page(&[&a], "c1", false)),
        ("200 OK", page(&[], "c1", false)),
        (
            "400 Bad Request",
            r#"{"error":"InvalidParameter"}"#.to_owned(),
        ),
    ]);
    let (busy, stop, counter) = busy_server();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cli-demo"))
        .args([
            "query",
            "--relay",
            &format!("{busy},{good}"),
            "--follow",
            "--interval",
            "1",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // Three rounds of about a second each; never more than 20 s.
    let started = std::time::Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > std::time::Duration::from_secs(20) {
            let _ = child.kill();
            panic!("query --follow did not end when every relay had failed");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let o = child.wait_with_output().unwrap();
    stop.store(true, Ordering::Relaxed);
    assert_eq!(counter.join().unwrap(), 1, "the busy relay was asked again");
    assert_eq!(t.join().unwrap().len(), 3);
    // Both refusals are relay refusals: status 3.
    assert_code(&o, 3);
    assert_eq!(stdout(&o), format!("{a}\n"));
    let err = stderr(&o);
    assert!(err.contains("not polled again in this run"), "{err}");
    assert!(err.contains("InvalidParameter"), "{err}");
}
