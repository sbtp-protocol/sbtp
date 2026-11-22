//! ADR 0052, the operator deny list, over real HTTP: `451` on `GET` and `HEAD` before any `304`
//! (rule 6), the `PUT` step after C3 with `Denied` and `DeniedKey` (rule 7), `length = 0` batch
//! records (rule 8), `/query` omissions and the marking pass (rule 9), the cache headers (rule
//! 10), `/info` (rule 11), `hide` and `purge` (rule 14), the reload rules (rule 4) and the
//! counters (rule 20). Core spec §4, "Denied blocks".
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names
)]

mod common;

use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use axum::Router;
use common::{Response, TestServer, get, put_block, read_response, settings, tmp_dir};
use sbtp_core::{BlockBuilder, BlockId, SigningKey};
use sbtp_relay::deny::Reload;
use sbtp_relay::metrics::{self, DenyRoute};

/// A relay at difficulty 0 with `deny_file` = `file`, written with `text` first.
fn start(text: &str, extra: &[(&str, &str)]) -> (TestServer, PathBuf) {
    let file = tmp_dir("deny-file");
    std::fs::create_dir_all(&file).unwrap();
    let file = file.join("deny.txt");
    std::fs::write(&file, text).unwrap();
    let path = file.to_str().unwrap().to_owned();
    let mut pairs = vec![("MIN_POW_DIFFICULTY", "0"), ("DENY_FILE", path.as_str())];
    pairs.extend_from_slice(extra);
    (TestServer::start(&settings(&pairs), Router::new()), file)
}

/// Rewrites the list and reloads it.
fn deny(relay: &TestServer, file: &Path, text: &str) {
    std::fs::write(file, text).unwrap();
    assert_eq!(relay.deny.reload(), Reload::Loaded);
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_hex(seed: u8) -> String {
    let k = key(seed);
    let bytes = BlockBuilder::for_key(&k)
        .timestamp(1)
        .payload(b"")
        .build(&k, 0)
        .unwrap();
    hex(sbtp_core::parse(&bytes).unwrap().pubkey())
}

fn hex(b: &[u8]) -> String {
    BlockId(b.try_into().unwrap()).to_string()
}

/// A valid block of key `seed`, difficulty 0, timestamped now.
fn block(seed: u8, payload: &[u8], parents: &[BlockId]) -> (Vec<u8>, BlockId) {
    let k = key(seed);
    let bytes = BlockBuilder::for_key(&k)
        .timestamp(common::now_ms())
        .parents(parents)
        .payload(payload)
        .build(&k, 0)
        .unwrap();
    let id = sbtp_core::parse(&bytes).unwrap().block_id();
    (bytes, id)
}

fn store(c: &mut TcpStream, b: &(Vec<u8>, BlockId)) {
    let r = put_block(c, &b.0);
    assert!(r.status == 201 || r.status == 200, "{}", r.status);
}

fn path(id: &BlockId) -> String {
    format!("/sbtp/v1/block/{id}")
}

/// `HEAD`: the status line and headers only (no body follows).
fn head(c: &mut TcpStream, p: &str) -> Response {
    use std::io::Read;
    c.write_all(format!("HEAD {p} HTTP/1.1\r\nHost: relay.test\r\n\r\n").as_bytes())
        .unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        assert_eq!(c.read(&mut byte).unwrap(), 1, "head cut short");
        buf.push(byte[0]);
    }
    let text = String::from_utf8(buf).unwrap();
    let mut lines = text.trim_end().split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.trim().to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    Response {
        status,
        headers,
        body: Vec::new(),
    }
}

fn batch(c: &mut TcpStream, ids: &[BlockId]) -> Vec<usize> {
    let body: Vec<u8> = ids.iter().flat_map(|id| id.0).collect();
    c.write_all(
        format!(
            "POST /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    c.write_all(&body).unwrap();
    let r = read_response(c).unwrap();
    assert_eq!(r.status, 200);
    let mut lens = Vec::new();
    let mut at = 0;
    while at < r.body.len() {
        let len = u32::from_be_bytes(r.body[at..at + 4].try_into().unwrap()) as usize;
        lens.push(len);
        at += 4 + len;
    }
    lens
}

fn listed(c: &mut TcpStream, query: &str) -> Vec<String> {
    let r = get(c, &format!("/sbtp/v1/query{query}"), "");
    assert_eq!(r.status, 200);
    r.json()["block_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

/// Rules 6 and 10: the `451` of a read, its body and headers.
fn assert_denied(r: &Response, name: &str) {
    assert_eq!(r.status, 451, "{name}");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("cdn-cache-control"), Some("no-store"));
    assert_eq!(r.header("etag"), None);
    if !r.body.is_empty() {
        let v = r.json();
        assert_eq!(v["error"], name);
        // A fixed text: no identifier, no ground.
        assert_eq!(
            v["message"],
            "the operator of this relay does not serve this block"
        );
    }
}

/// ADR 0052 rule 6: `GET` and `HEAD` get `451` for a listed `block_id`, held or not, cached or
/// not, whatever `If-None-Match` (never `304`) or `Sbtp-Replication`; a block not listed and
/// not held is still `404`.
#[test]
fn block_entry_gets_451_on_reads_before_304() {
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let b = block(1, b"denied by id", &[]);
    store(&mut c, &b);
    let etag = format!("If-None-Match: \"{}\"\r\n", b.1);
    assert_eq!(get(&mut c, &path(&b.1), &etag).status, 304);
    // Cached now: the denial must not be served from the block cache.
    assert_eq!(get(&mut c, &path(&b.1), "").status, 200);
    let unheld = BlockId([7; 32]);
    deny(&relay, &file, &format!("block {}\nblock {unheld}\n", b.1));
    let before = metrics::denied_total(DenyRoute::Get, false);
    assert_denied(&get(&mut c, &path(&b.1), ""), "Denied");
    assert_denied(&get(&mut c, &path(&b.1), &etag), "Denied");
    assert_denied(&get(&mut c, &path(&b.1), "If-None-Match: *\r\n"), "Denied");
    assert_denied(
        &get(&mut c, &path(&b.1), "Sbtp-Replication: 1\r\n"),
        "Denied",
    );
    assert_denied(&head(&mut c, &path(&b.1)), "Denied");
    assert_denied(&get(&mut c, &path(&unheld), ""), "Denied");
    assert_eq!(get(&mut c, &path(&BlockId([8; 32])), "").status, 404);
    assert!(metrics::denied_total(DenyRoute::Get, false) >= before + 6);
}

/// ADR 0052 rules 6 and 7: a listed key denies every block it signed, on reads as `Denied` (a
/// read never says the match is by key) and on `PUT` as `DeniedKey`, held or new; a listed
/// `block_id` gets `Denied` on `PUT`. Nothing is stored; another key is not affected.
#[test]
fn key_entry_denies_reads_and_puts() {
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let held = block(2, b"held, key denied later", &[]);
    store(&mut c, &held);
    let other = block(3, b"another key", &[]);
    store(&mut c, &other);
    deny(&relay, &file, &format!("key {}\n", key_hex(2)));
    assert_denied(&get(&mut c, &path(&held.1), ""), "Denied");
    assert_denied(&head(&mut c, &path(&held.1)), "Denied");
    assert_eq!(get(&mut c, &path(&other.1), "").status, 200);
    let before = metrics::denied_total(DenyRoute::Put, true);
    assert_denied(&put_block(&mut c, &held.0), "DeniedKey");
    let new = block(2, b"new block of a denied key", &[]);
    assert_denied(&put_block(&mut c, &new.0), "DeniedKey");
    assert_eq!(metrics::denied_total(DenyRoute::Put, true), before + 2);
    // Not held: the relay cannot know its key, so a read is `404` (rule 6 needs the bytes for a
    // match by key).
    assert_eq!(get(&mut c, &path(&new.1), "").status, 404);
    // Nothing was stored: lifted, the new block is not held.
    deny(&relay, &file, "");
    assert_eq!(
        get(&mut c, &path(&new.1), "").status,
        404,
        "a denied PUT stores nothing"
    );
    // A listed `block_id` wins: `Denied`, also for a key that is listed too.
    deny(
        &relay,
        &file,
        &format!("key {}\nblock {}\nblock {}\n", key_hex(2), new.1, other.1),
    );
    assert_denied(&put_block(&mut c, &new.0), "Denied");
    assert_denied(&put_block(&mut c, &other.0), "Denied");
}

/// ADR 0052 rule 7: the deny step follows C3. A denied block with a bad signature gets `422`,
/// whether it is listed by `block_id` (the identifier does not cover the signature) or by key;
/// an earlier failure gets its own answer.
#[test]
fn put_deny_step_follows_c3() {
    let (relay, file) = start("", &[("MIN_POW_DIFFICULTY", "1")]);
    let mut c = relay.connect();
    let k = key(4);
    let bytes = BlockBuilder::for_key(&k)
        .timestamp(common::now_ms())
        .payload(b"bad signature")
        .build(&k, 1)
        .unwrap();
    let b = (bytes.clone(), sbtp_core::parse(&bytes).unwrap().block_id());
    deny(
        &relay,
        &file,
        &format!("block {}\nkey {}\n", b.1, key_hex(4)),
    );
    let mut forged = b.0.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let r = put_block(&mut c, &forged);
    assert_eq!(r.status, 422);
    assert_eq!(r.json()["error"], "InvalidSignature");
    let r = put_block(&mut c, b"not a block");
    assert_eq!(r.status, 400);
    assert_denied(&put_block(&mut c, &b.0), "Denied");
}

/// ADR 0052 rules 8 and 15: a denied block is a `length = 0` record in a batch, by `block_id`
/// or by key; the others are served.
#[test]
fn batch_records_of_denied_blocks_are_empty() {
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let a = block(5, b"batch a", &[]);
    let b = block(6, b"batch b", &[]);
    let k = block(7, b"batch key", &[]);
    for x in [&a, &b, &k] {
        store(&mut c, x);
    }
    deny(
        &relay,
        &file,
        &format!("block {}\nkey {}\n", a.1, key_hex(7)),
    );
    let before = metrics::denied_total(DenyRoute::Batch, false);
    let lens = batch(&mut c, &[a.1, b.1, k.1]);
    assert_eq!(lens, [0, b.0.len(), 0]);
    assert!(metrics::denied_total(DenyRoute::Batch, false) > before);
    // A first record that is denied still gives `200`.
    assert_eq!(batch(&mut c, &[k.1, b.1]), [0, b.0.len()]);
}

/// ADR 0052 rule 9: `/query` leaves out a listed `block_id` at once, with or without `fields`
/// and `order`, and a block of a listed key once the marking pass reached it; the cursor and
/// `more` are those of the walk. A denied parent's children are still listed. Lifting a key
/// lists its blocks again.
#[test]
fn query_omits_denied_blocks() {
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let parent = block(8, b"denied parent", &[]);
    store(&mut c, &parent);
    let child = block(9, b"child", &[parent.1]);
    store(&mut c, &child);
    let keyed = block(10, b"keyed child", &[parent.1]);
    store(&mut c, &keyed);
    deny(
        &relay,
        &file,
        &format!("block {}\nkey {}\n", parent.1, key_hex(10)),
    );
    let all = listed(&mut c, "");
    assert!(!all.contains(&parent.1.to_string()), "listed by block_id");
    assert!(all.contains(&child.1.to_string()));
    assert!(relay.mark());
    for q in ["", "?order=desc", "?fields=parents"] {
        assert_eq!(listed(&mut c, q), [child.1.to_string()], "{q}");
    }
    let r = get(&mut c, "/sbtp/v1/query?fields=parents", "");
    assert_eq!(r.json()["lens"], serde_json::json!([child.0.len()]));
    assert_eq!(
        listed(&mut c, &format!("?parent={}", parent.1)),
        [child.1.to_string()]
    );
    // A page of only denied blocks: fewer than `limit`, the walk goes on.
    let r = get(&mut c, "/sbtp/v1/query?limit=1", "");
    let v = r.json();
    assert_eq!(v["block_ids"], serde_json::json!([]));
    assert_eq!(v["more"], true);
    let r = get(
        &mut c,
        &format!(
            "/sbtp/v1/query?limit=1&cursor={}",
            v["cursor"].as_str().unwrap()
        ),
        "",
    );
    assert_eq!(
        r.json()["block_ids"],
        serde_json::json!([child.1.to_string()])
    );
    // Lifted: listed again at once, at its original position.
    deny(&relay, &file, &format!("block {}\n", parent.1));
    assert_eq!(
        listed(&mut c, ""),
        [child.1.to_string(), keyed.1.to_string()]
    );
    assert!(metrics::denied_total(DenyRoute::Query, true) > 0);
}

/// ADR 0052 rule 4: a reload of an invalid or a missing file keeps the previous list whole; a
/// list in force is never emptied by a failure.
#[test]
fn invalid_or_missing_file_keeps_the_previous_list() {
    let b = block(11, b"stays denied", &[]);
    let (relay, file) = start(&format!("block {}\n", b.1), &[]);
    let mut c = relay.connect();
    assert_denied(&get(&mut c, &path(&b.1), ""), "Denied");
    for bad in [
        "block 00\n".to_owned(),
        format!("block {}\nblock {} purge\n", b.1, b.1),
        format!("#{}\n", "x".repeat(300)),
    ] {
        std::fs::write(&file, bad).unwrap();
        assert!(matches!(relay.deny.reload(), Reload::Invalid(_)));
        assert_denied(&get(&mut c, &path(&b.1), ""), "Denied");
    }
    std::fs::remove_file(&file).unwrap();
    assert!(matches!(relay.deny.reload(), Reload::Invalid(_)));
    assert_denied(&get(&mut c, &path(&b.1), ""), "Denied");
}

/// ADR 0052 rule 14, `hide`: the file and the index entries stay; lifting serves the block again
/// at its original position, with no `PUT`.
#[test]
fn lifting_a_hide_entry_serves_again() {
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let first = block(12, b"first", &[]);
    store(&mut c, &first);
    let hidden = block(13, b"hidden", &[]);
    store(&mut c, &hidden);
    let third = block(14, b"third", &[]);
    store(&mut c, &third);
    deny(&relay, &file, &format!("key {}\n", key_hex(13)));
    assert!(relay.mark());
    assert_eq!(
        listed(&mut c, ""),
        [first.1.to_string(), third.1.to_string()]
    );
    deny(&relay, &file, "# lifted\n");
    assert_eq!(get(&mut c, &path(&hidden.1), "").body, hidden.0);
    assert_eq!(
        listed(&mut c, ""),
        [
            first.1.to_string(),
            hidden.1.to_string(),
            third.1.to_string()
        ]
    );
}

/// ADR 0052 rule 14, `purge`: the marking pass deletes the block as an eviction does, by
/// `block_id` or by key; after lifting, a `PUT` stores it as a new block (`201`).
#[test]
fn purge_then_put_after_lifting_gives_201() {
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let by_id = block(15, b"purged by id", &[]);
    let by_key = block(16, b"purged by key", &[]);
    let kept = block(17, b"kept", &[]);
    for b in [&by_id, &by_key, &kept] {
        store(&mut c, b);
    }
    deny(
        &relay,
        &file,
        &format!("block {} purge\nkey {} purge\n", by_id.1, key_hex(16)),
    );
    assert!(relay.mark());
    assert_eq!(listed(&mut c, ""), [kept.1.to_string()]);
    deny(&relay, &file, "");
    for b in [&by_id, &by_key] {
        assert_eq!(get(&mut c, &path(&b.1), "").status, 404, "purged");
        assert_eq!(put_block(&mut c, &b.0).status, 201);
    }
    assert_eq!(
        listed(&mut c, ""),
        [
            kept.1.to_string(),
            by_id.1.to_string(),
            by_key.1.to_string()
        ],
        "new positions"
    );
}

/// ADR 0052 rule 11: `"deny_list": true` once `deny_file` is set, also with no entry; absent
/// otherwise.
#[test]
fn info_publishes_deny_list() {
    let (relay, _file) = start("# no entry\n", &[]);
    let mut c = relay.connect();
    let v = get(&mut c, "/sbtp/v1/info", "").json();
    assert_eq!(v["deny_list"], true);
    let plain = TestServer::start(&settings(&[]), Router::new());
    let mut c = plain.connect();
    let v = get(&mut c, "/sbtp/v1/info", "").json();
    assert!(v.get("deny_list").is_none());
}

/// ADR 0052 rule 4: a change of the file is picked up by the reload task within
/// `deny_reload_ms`, without a signal.
#[test]
fn a_changed_file_is_reloaded() {
    let (relay, file) = start("", &[("DENY_RELOAD_MS", "1000")]);
    let mut c = relay.connect();
    let b = block(18, b"polled", &[]);
    store(&mut c, &b);
    std::fs::write(&file, format!("block {}\n", b.1)).unwrap();
    let t = Instant::now();
    while get(&mut c, &path(&b.1), "").status != 451 {
        assert!(t.elapsed() < Duration::from_secs(10), "not reloaded");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// ADR 0052 rule 4: an invalid or missing file at start-up stops the start-up before anything
/// is opened, naming the setting and the line, never the line's content.
#[test]
fn invalid_file_stops_the_start_up() {
    use sbtp_relay::StartError;
    use sbtp_relay::config::ConfigError;
    use std::ffi::OsString;
    let dir = tmp_dir("deny-start");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("deny.txt");
    let secret = "a".repeat(64);
    std::fs::write(&file, format!("# ok\nblock {secret} remove\n")).unwrap();
    for f in [file.clone(), dir.join("missing.txt")] {
        let data = dir.join("data");
        let e = common::env(&[
            ("LISTEN", "127.0.0.1:0"),
            ("DATA_DIR", data.to_str().unwrap()),
            ("DENY_FILE", f.to_str().unwrap()),
        ]);
        let r = sbtp_relay::run(
            sbtp_core::self_test,
            Vec::<OsString>::new(),
            e,
            || Ok(tokio::sync::mpsc::unbounded_channel::<()>().1),
            |_| panic!("listened"),
        );
        let Err(StartError::Config(ConfigError::Invalid { setting, reason })) = r else {
            panic!("{r:?}");
        };
        assert_eq!(setting, "deny_file");
        assert!(!reason.contains(&secret), "{reason}");
        assert!(
            reason == "invalid at line 2: unknown_token" || reason == "invalid at line 0: missing",
            "{reason}"
        );
        assert!(!data.exists(), "nothing is opened");
    }
}

/// The block file of `id` under the relay's data directory (ADR 0025 rule 1).
fn block_file(relay: &TestServer, id: &BlockId) -> PathBuf {
    relay
        .data
        .join("blocks")
        .join(format!("{:02x}", id.0[31]))
        .join(format!("{id}.bin"))
}

/// Deny review L-2: a `purge` by key whose index removal did not happen (the file is gone, the
/// entries are still there, as after a refused removal or a stop) is finished by the next pass,
/// which judges the block by the key of its mark.
#[test]
fn a_purge_interrupted_after_the_deletion_is_finished() {
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let b = block(18, b"purge interrupted", &[]);
    store(&mut c, &b);
    // The mark is written before any deletion; the deletion happens, the removal does not.
    deny(&relay, &file, &format!("key {} hide\n", key_hex(18)));
    assert!(relay.mark());
    std::fs::remove_file(block_file(&relay, &b.1)).unwrap();
    deny(&relay, &file, &format!("key {} purge\n", key_hex(18)));
    assert!(relay.mark());
    deny(&relay, &file, "");
    assert!(listed(&mut c, "").is_empty(), "the entries were removed");
    assert_eq!(put_block(&mut c, &b.0).status, 201);
}

/// Deny review L-2: a `purge` whose deletion fails keeps the block's mark, so it stays out of
/// `/query`; the pass reports the failure, and a later pass finishes the purge.
#[cfg(unix)]
#[test]
fn a_failed_purge_deletion_keeps_the_block_unlisted() {
    use std::os::unix::fs::PermissionsExt as _;
    let (relay, file) = start("", &[]);
    let mut c = relay.connect();
    let b = block(19, b"purge refused", &[]);
    store(&mut c, &b);
    let shard = block_file(&relay, &b.1).parent().unwrap().to_path_buf();
    let mode = |m| std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(m)).unwrap();
    mode(0o500);
    // Root ignores the mode: nothing to test then.
    if std::fs::write(shard.join("probe"), b"").is_ok() {
        mode(0o700);
        return;
    }
    deny(&relay, &file, &format!("key {} purge\n", key_hex(19)));
    assert!(!relay.mark(), "the deletion failed");
    assert!(listed(&mut c, "").is_empty(), "marked, hence not listed");
    mode(0o700);
    assert!(relay.mark());
    deny(&relay, &file, "");
    assert_eq!(get(&mut c, &path(&b.1), "").status, 404, "purged");
    assert_eq!(listed(&mut c, ""), Vec::<String>::new());
}

/// ADR 0051 clarification B10: a request that carried cursor `C` for a listing never gets a page
/// of that listing with no identifier, `more = true` and `C` again, through runs of denied
/// blocks (by `block_id` and by key), with `limit=1`, in both orders, for one parent and for a
/// grouped request with per-parent cursors. Every walk ends with `more = false` and lists every
/// block that is not denied.
#[test]
#[allow(clippy::too_many_lines)] // Four walks of one store.
fn a_walk_always_advances_past_denied_blocks() {
    let (relay, file) = start(
        "",
        &[
            ("RATE_QUERY_BURST", "100000"),
            ("RATE_QUERY_PER_MIN", "1000000"),
        ],
    );
    let mut c = relay.connect();
    let p1 = block(20, b"parent one", &[]);
    let p2 = block(20, b"parent two", &[]);
    store(&mut c, &p1);
    store(&mut c, &p2);
    let mut kept = Vec::new();
    let mut by_id = Vec::new();
    for n in 0..9u8 {
        // Runs of three denied blocks (two by key, one by id) around each kept one.
        let parents = [p1.1, p2.1];
        let seed = if n % 3 == 2 { 22 } else { 21 };
        let b = block(seed, &[b'c', n], &parents);
        store(&mut c, &b);
        if n % 3 == 1 {
            by_id.push(b.1);
        } else if seed == 22 {
            kept.push(b.1.to_string());
        }
    }
    let list = by_id
        .iter()
        .fold(String::new(), |l, id| l + &format!("block {id}\n"));
    deny(&relay, &file, &format!("{list}key {}\n", key_hex(21)));
    assert!(relay.mark());
    let walk = |c: &mut TcpStream, base: &str| {
        let mut ids = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let q = match &cursor {
                Some(k) => format!("{base}&cursor={k}"),
                None => base.to_owned(),
            };
            let r = get(c, &format!("/sbtp/v1/query?{q}"), "");
            assert_eq!(r.status, 200, "{q}: {}", String::from_utf8_lossy(&r.body));
            let v = r.json();
            let page: Vec<String> = v["block_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i.as_str().unwrap().to_owned())
                .collect();
            let next = v["cursor"].as_str().unwrap().to_owned();
            if let Some(k) = &cursor {
                assert!(
                    !(page.is_empty() && v["more"] == true && next == *k),
                    "{q}: an empty page with more and the same cursor"
                );
            }
            ids.extend(page);
            if v["more"] == false {
                return ids;
            }
            cursor = Some(next);
        }
        panic!("{base}: the walk did not end");
    };
    let kids: Vec<String> = walk(&mut c, &format!("limit=1&parent={}", p1.1));
    assert_eq!(kids, kept);
    let mut desc = walk(&mut c, &format!("limit=1&order=desc&parent={}", p2.1));
    desc.reverse();
    assert_eq!(desc, kept);
    let all = walk(&mut c, "limit=1");
    assert_eq!(
        all,
        [&[p1.1.to_string(), p2.1.to_string()][..], &kept].concat()
    );
    // Grouped: each listing carries its own cursor; check every listing of every page.
    let mut cursors = [None::<String>, None];
    for _ in 0..100 {
        let ps: Vec<String> = [p1.1, p2.1]
            .iter()
            .zip(&cursors)
            .map(|(p, k)| match k {
                Some(k) => format!("parent={p}.{k}"),
                None => format!("parent={p}"),
            })
            .collect();
        let v = get(
            &mut c,
            &format!("/sbtp/v1/query?limit=1&{}", ps.join("&")),
            "",
        )
        .json();
        let mut done = true;
        for (i, l) in v["parents"].as_array().unwrap().iter().enumerate() {
            let next = l["cursor"].as_str().unwrap().to_owned();
            if let Some(k) = &cursors[i] {
                assert!(
                    !(l["block_ids"].as_array().unwrap().is_empty()
                        && l["more"] == true
                        && next == *k),
                    "grouped listing {i}: an empty page with more and the same cursor"
                );
            }
            done &= l["more"] == false;
            cursors[i] = Some(next);
        }
        if done {
            return;
        }
    }
    panic!("the grouped walk did not end");
}
