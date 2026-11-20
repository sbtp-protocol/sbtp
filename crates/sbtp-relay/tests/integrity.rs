//! Store integrity over real HTTP and on the store (ADR 0023): damaged files on `GET` and `PUT`,
//! the quarantine area, its lock, bound and retention, the start-up walk, `HEAD`, `Cache-Control`,
//! and the `507` of a full index (security review I-3).
//!
//! The counters are process-wide: every test here takes [`serial`], so that each can assert exact
//! counts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

use axum::Router;
use common::{
    Response, TestServer, get as http_get, now_ms as unix_ms, put_block as put, settings, tmp_dir,
};
use sbtp_core::{BlockBuilder, BlockId, SigningKey};
use sbtp_relay::index::{FileState, IndexBackend, IndexError, Page, Position, RedbIndex};
use sbtp_relay::metrics::{self, Damage};
use sbtp_relay::store::{
    QUARANTINE_MAX_FILES, QUARANTINE_RETENTION_MS, Quarantine, Reconciled, Store, TREE_CHARGE,
    cost, reconcile,
};

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn block(payload: &[u8]) -> Vec<u8> {
    let k = SigningKey::from_bytes(&[9; 32]);
    BlockBuilder::for_key(&k)
        .timestamp(unix_ms())
        .payload(payload)
        .build(&k, 0)
        .unwrap()
}

fn id_of(bytes: &[u8]) -> BlockId {
    sbtp_core::parse(bytes).unwrap().block_id()
}

fn path_of(data: &Path, id: &BlockId) -> PathBuf {
    let b = id.as_bytes();
    data.join(format!("blocks/{:02x}/{id}.bin", b[31]))
}

/// The bytes of `good` damaged so that full validation fails with `d` (ADR 0023 rule 1).
fn damaged(good: &[u8], d: Damage) -> Vec<u8> {
    let mut b = good.to_vec();
    match d {
        // Truncated: F5.
        Damage::Parse => b.truncate(100),
        // The last payload byte, just before the 64-byte signature: R1.
        Damage::Id => b[good.len() - 65] ^= 1,
        // The last signature byte: C3.
        Damage::Signature => *b.last_mut().unwrap() ^= 1,
    }
    b
}

fn get_block(s: &mut TcpStream, id: &BlockId) -> Response {
    http_get(s, &format!("/sbtp/v1/block/{id}"), "")
}

/// `HEAD`: the status line and headers only (RFC 9110 §9.3.2: no body follows).
fn head(s: &mut TcpStream, path: &str) -> (u16, Vec<(String, String)>) {
    s.write_all(format!("HEAD {path} HTTP/1.1\r\nHost: relay.test\r\n\r\n").as_bytes())
        .unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut byte).unwrap(), 1, "head cut short");
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
    (status, headers)
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// The regular files of `data/quarantine`, by name.
fn quarantined(data: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(data.join("quarantine"))
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| {
            (
                e.file_name().into_string().unwrap(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn relay_with_index(data: &Path) -> (TestServer, Arc<RedbIndex>) {
    std::fs::create_dir_all(data).unwrap();
    let index = Arc::new(RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap());
    // Room for the concurrent requests of `racing_repairs_give_one_file`.
    let s = settings(&[
        ("MIN_POW_DIFFICULTY", "0"),
        ("RATE_LIMIT_EXEMPT", "127.0.0.1/32"),
        ("PUT_MAX_IN_FLIGHT", "8"),
        ("BLOCK_MAX_READERS", "8"),
        ("MAX_BLOCKING_THREADS", "32"),
    ]);
    let relay = TestServer::start_with(&s, Router::new(), data, Arc::clone(&index));
    (relay, index)
}

/// A relay holding `good`, indexed, whose file was then damaged with `d` behind its back.
fn damaged_relay(name: &str, good: &[u8], d: Damage) -> (TestServer, Arc<RedbIndex>) {
    let data = tmp_dir(name);
    let (relay, index) = relay_with_index(&data);
    assert_eq!(put(&mut relay.connect(), good).status, 201);
    std::fs::write(path_of(&data, &id_of(good)), damaged(good, d)).unwrap();
    (relay, index)
}

/// ADR 0023 rules 10 and 14: a `GET` miss on a damaged file answers `404` with `no-store`, moves
/// the file to quarantine under its rule 4 name and counts one file, not one request.
#[test]
fn get_quarantines_a_damaged_file() {
    let _s = serial();
    for d in Damage::ALL {
        let good = block(format!("get {d:?}").as_bytes());
        let id = id_of(&good);
        let (relay, index) = damaged_relay("get-damaged", &good, d);
        let before = metrics::store_quarantined_total(d);
        let pos = index.contains(&id).unwrap();
        let mut c = relay.connect();
        let r = get_block(&mut c, &id);
        assert_eq!(
            (r.status, r.json()["error"].as_str()),
            (404, Some("NotFound")),
            "{d:?}"
        );
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert!(!path_of(&relay.data, &id).exists(), "{d:?}: moved");
        let q = quarantined(&relay.data);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].1, damaged(&good, d), "the damaged bytes are kept");
        let parts: Vec<&str> = q[0].0.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], id.to_string());
        let moved: u64 = parts[1].parse().unwrap();
        assert!(moved.abs_diff(unix_ms()) < 60_000, "Unix ms of the move");
        assert_eq!(metrics::store_quarantined_total(d), before + 1);
        assert_eq!(metrics::quarantine_files(), 1);
        // Review I-5: a second `GET` finds no file and counts nothing.
        assert_eq!(get_block(&mut c, &id).status, 404);
        assert_eq!(metrics::store_quarantined_total(d), before + 1);
        // The index entry stays: a phantom (ADR 0013 rule 8).
        assert_eq!(index.contains(&id).unwrap(), pos);
        drop(c);
        drop(relay);
    }
}

/// ADR 0023 rule 8: a valid `PUT` of a block whose stored file is damaged replaces it: `200`, the
/// index entry is kept, the damaged file is in quarantine, and the next `GET` serves the valid
/// bytes as `immutable`.
#[test]
fn put_replaces_a_damaged_file() {
    let _s = serial();
    for d in Damage::ALL {
        let good = block(format!("put {d:?}").as_bytes());
        let id = id_of(&good);
        let (relay, index) = damaged_relay("put-damaged", &good, d);
        let pos = index.contains(&id).unwrap();
        assert!(pos.is_some());
        let (replaced, moved) = (
            metrics::store_replaced_total(),
            metrics::store_quarantined_total(d),
        );
        let mut c = relay.connect();
        let r = put(&mut c, &good);
        assert_eq!(r.status, 200, "{d:?}: no new position, so not 201");
        assert_eq!(r.header("cache-control"), Some("no-store"));
        assert_eq!(std::fs::read(path_of(&relay.data, &id)).unwrap(), good);
        assert_eq!(index.contains(&id).unwrap(), pos, "rule 8.7: entry kept");
        let q = quarantined(&relay.data);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].1, damaged(&good, d));
        assert_eq!(metrics::store_replaced_total(), replaced + 1);
        assert_eq!(metrics::store_quarantined_total(d), moved + 1);
        let r = get_block(&mut c, &id);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, good);
        assert_eq!(
            r.header("cache-control"),
            Some("public, max-age=31536000, immutable")
        );
        // Rule 8.3: invalid submitted bytes change nothing.
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 4;
        assert_eq!(put(&mut c, &bad).status, 422);
        assert_eq!(std::fs::read(path_of(&relay.data, &id)).unwrap(), good);
    }
}

/// ADR 0023 rule 8.3: when the stored file is damaged and the submitted bytes fail C2 or C3, the
/// stored file is not even judged: nothing moves.
#[test]
fn invalid_put_never_moves_a_file() {
    let _s = serial();
    let good = block(b"invalid put");
    let id = id_of(&good);
    let (relay, _index) = damaged_relay("invalid-put", &good, Damage::Id);
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 4;
    let r = put(&mut relay.connect(), &bad);
    assert_eq!(
        (r.status, r.json()["error"].as_str()),
        (422, Some("InvalidSignature"))
    );
    assert_eq!(
        std::fs::read(path_of(&relay.data, &id)).unwrap(),
        damaged(&good, Damage::Id)
    );
    assert_eq!(quarantined(&relay.data).len(), 0);
}

/// ADR 0023 rule 7: concurrent repairs (`PUT`s) and `GET` misses of one damaged block move it
/// once and leave one valid file. A `PUT` that finds the name empty after a `GET` moved the file
/// takes the normal path (`201`, rule 9).
#[test]
fn racing_repairs_give_one_file() {
    let _s = serial();
    for round in 0..4u8 {
        let good = block(&[round; 300]);
        let id = id_of(&good);
        let (relay, _index) = damaged_relay("race-repair", &good, Damage::Signature);
        let moved = metrics::store_quarantined_total(Damage::Signature);
        let relay = Arc::new(relay);
        let go = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let (relay, go, good) = (Arc::clone(&relay), Arc::clone(&go), good.clone());
                std::thread::spawn(move || {
                    let mut c = relay.connect();
                    go.wait();
                    if n % 2 == 0 {
                        (true, put(&mut c, &good))
                    } else {
                        (false, get_block(&mut c, &id))
                    }
                })
            })
            .collect();
        let mut created = 0;
        for t in threads {
            let (is_put, r) = t.join().unwrap();
            match (is_put, r.status) {
                (true, 200) | (false, 404) => {}
                (true, 201) => created += 1,
                (false, 200) => assert_eq!(r.body, good, "only valid bytes are served"),
                (p, s) => panic!("put={p}: unexpected status {s}"),
            }
        }
        assert!(created <= 1);
        assert_eq!(std::fs::read(path_of(&relay.data, &id)).unwrap(), good);
        assert_eq!(quarantined(&relay.data).len(), 1, "moved once");
        assert_eq!(
            metrics::store_quarantined_total(Damage::Signature),
            moved + 1
        );
    }
}

/// ADR 0023 rule 9: a crash between the move and the `link` leaves the final name absent and the
/// index entry a phantom. The start-up walk counts the quarantined file in the quota (rule 5); the
/// next `PUT` stores the block by the normal path.
#[test]
fn crash_between_move_and_link() {
    let _s = serial();
    let good = block(b"crash between");
    let id = id_of(&good);
    let data = tmp_dir("crash-move");
    {
        let (relay, _index) = damaged_relay_in(&data, &good, Damage::Id);
        drop(relay);
    }
    {
        // The relay's move, then nothing: the process "died" before the `link`.
        let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
        let bad = damaged(&good, Damage::Id);
        assert!(matches!(store.quarantine(&id, &bad), Ok(Quarantine::Moved)));
        assert!(!path_of(&data, &id).exists());
    }
    {
        let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
        assert!(index.contains(&id).unwrap().is_some(), "a phantom");
        let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
        let rec = reconcile(&store, &index).unwrap();
        assert_eq!((rec.files, rec.quarantined, rec.purged), (0, 0, 0));
        assert_eq!(
            store.used_bytes(),
            TREE_CHARGE + cost(good.len() as u64),
            "rule 5"
        );
        assert_eq!(store.quarantine_files(), 1);
        index.close().unwrap();
    }
    let (relay, _index) = relay_with_index(&data);
    let mut c = relay.connect();
    assert_eq!(get_block(&mut c, &id).status, 404);
    assert_eq!(put(&mut c, &good).status, 201);
    assert_eq!(get_block(&mut c, &id).body, good);
}

fn damaged_relay_in(data: &Path, good: &[u8], d: Damage) -> (TestServer, Arc<RedbIndex>) {
    let (relay, index) = relay_with_index(data);
    assert_eq!(put(&mut relay.connect(), good).status, 201);
    std::fs::write(path_of(data, &id_of(good)), damaged(good, d)).unwrap();
    (relay, index)
}

/// ADR 0023 rule 6: retention of 7 days and the bound of 64, at start-up and at a move; entries
/// that are not regular files with a quarantine name are skipped and left alone; a purge releases
/// the quota cost.
#[cfg(unix)]
#[test]
fn quarantine_bound_and_retention() {
    let _s = serial();
    let data = tmp_dir("q-bound");
    std::fs::create_dir_all(data.join("quarantine")).unwrap();
    let q = data.join("quarantine");
    let hex = "cd".repeat(32);
    let now = unix_ms();
    let old = now - QUARANTINE_RETENTION_MS - 1_000;
    // 3 expired files, then 66 recent ones with increasing move times.
    for n in 0..3u64 {
        std::fs::write(q.join(format!("{hex}.{old}.{n}")), [0u8; 10]).unwrap();
    }
    for n in 0..66u64 {
        std::fs::write(
            q.join(format!("{hex}.{}.{n}", now - 100_000 + n)),
            [1u8; 10],
        )
        .unwrap();
    }
    // Skipped: a directory and a symbolic link with quarantine names, a foreign file.
    std::fs::create_dir(q.join(format!("{hex}.{old}.900"))).unwrap();
    let outside = tmp_dir("q-outside");
    std::fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, q.join(format!("{hex}.{old}.901"))).unwrap();
    std::fs::write(q.join("notes.txt"), b"operator").unwrap();

    let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
    let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
    let rec = reconcile(&store, &index).unwrap();
    assert_eq!(rec.purged, 5, "3 expired, then the 2 oldest beyond 64");
    assert_eq!(store.quarantine_files(), QUARANTINE_MAX_FILES as u64);
    assert_eq!(store.used_bytes(), TREE_CHARGE + 64 * cost(10));
    let names: Vec<String> = quarantined(&data).into_iter().map(|(n, _)| n).collect();
    assert!(
        !names.iter().any(|n| n.contains(&format!(".{old}."))),
        "expired: gone"
    );
    assert!(!names.contains(&format!("{hex}.{}.0", now - 100_000)));
    assert!(!names.contains(&format!("{hex}.{}.1", now - 100_000 + 1)));
    assert!(names.contains(&format!("{hex}.{}.2", now - 100_000 + 2)));
    assert!(names.contains(&"notes.txt".to_owned()));
    assert!(q.join(format!("{hex}.{old}.900")).is_dir());
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"outside",
        "a link is not followed"
    );

    // A move at the bound deletes the oldest first; the count stays 64.
    let good = block(b"at the bound");
    let id = id_of(&good);
    let bad = damaged(&good, Damage::Signature);
    let p = path_of(&data, &id);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, &bad).unwrap();
    let used = store.used_bytes();
    assert!(matches!(store.quarantine(&id, &bad), Ok(Quarantine::Moved)));
    assert_eq!(store.quarantine_files(), QUARANTINE_MAX_FILES as u64);
    assert_eq!(
        store.used_bytes(),
        used - cost(10),
        "the purged file is released"
    );
    let names: Vec<String> = quarantined(&data).into_iter().map(|(n, _)| n).collect();
    assert!(!names.contains(&format!("{hex}.{}.2", now - 100_000 + 2)));
    assert!(names.iter().any(|n| n.starts_with(&id.to_string())));
    // The sweeper's purge: nothing is old enough yet; at 7 days everything goes.
    assert_eq!(store.purge_quarantine(unix_ms()).unwrap(), 0);
    assert_eq!(
        store
            .purge_quarantine(unix_ms() + QUARANTINE_RETENTION_MS)
            .unwrap(),
        64
    );
    assert_eq!(store.quarantine_files(), 0);
    assert_eq!(metrics::quarantine_files(), 0);
}

/// ADR 0023 rule 7: the move happens only if the final name still holds the bytes judged
/// damaged.
#[test]
fn quarantine_moves_only_the_judged_bytes() {
    let _s = serial();
    let data = tmp_dir("q-changed");
    std::fs::create_dir_all(&data).unwrap();
    let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
    let good = block(b"changed");
    let id = id_of(&good);
    let p = path_of(&data, &id);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, &good).unwrap();
    let bad = damaged(&good, Damage::Id);
    assert!(matches!(
        store.quarantine(&id, &bad),
        Ok(Quarantine::Changed)
    ));
    assert_eq!(std::fs::read(&p).unwrap(), good);
    std::fs::remove_file(&p).unwrap();
    assert!(matches!(
        store.quarantine(&id, &bad),
        Ok(Quarantine::Changed)
    ));
    assert_eq!(quarantined(&data).len(), 0);
}

/// ADR 0023 rule 15: one walk removes temporary files, indexes valid orphans with their file
/// time, quarantines damaged orphans and does not read indexed files.
#[test]
fn startup_walk() {
    let _s = serial();
    let data = tmp_dir("walk");
    let good = block(b"valid orphan");
    let broken = block(b"damaged orphan");
    let indexed = block(b"indexed, damaged");
    {
        let (relay, _index) = relay_with_index(&data);
        assert_eq!(put(&mut relay.connect(), &indexed).status, 201);
    }
    std::fs::write(
        path_of(&data, &id_of(&indexed)),
        damaged(&indexed, Damage::Signature),
    )
    .unwrap();
    for (b, bytes) in [
        (&good, good.clone()),
        (&broken, damaged(&broken, Damage::Signature)),
    ] {
        let p = path_of(&data, &id_of(b));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
    }
    std::fs::write(data.join("tmp/left.0.tmp"), b"partial").unwrap();
    let moved = metrics::store_quarantined_total(Damage::Signature);
    let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
    let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
    let rec = reconcile(&store, &index).unwrap();
    assert_eq!(
        (rec.files, rec.orphans, rec.quarantined, rec.purged),
        (3, 1, 1, 0)
    );
    assert_eq!(std::fs::read_dir(data.join("tmp")).unwrap().count(), 0);
    assert!(index.contains(&id_of(&good)).unwrap().is_some());
    assert!(index.contains(&id_of(&broken)).unwrap().is_none());
    assert!(!path_of(&data, &id_of(&broken)).exists());
    assert!(
        path_of(&data, &id_of(&indexed)).exists(),
        "indexed: not read"
    );
    assert_eq!(
        metrics::store_quarantined_total(Damage::Signature),
        moved + 1
    );
    let all = [&good, &broken, &indexed]
        .iter()
        .map(|b| cost(b.len() as u64))
        .sum::<u64>();
    assert_eq!(
        store.used_bytes(),
        TREE_CHARGE + all,
        "tree, block files and quarantined files"
    );
    assert_eq!(reconcile(&store, &index).unwrap().orphans, 0, "idempotent");
    index.close().unwrap();
}

/// ADR 0023 rule 15: on the `PUT` path an orphan is indexed only after full validation, also when
/// the identical-bytes shortcut answers.
#[test]
fn identical_put_indexes_only_a_valid_orphan() {
    let _s = serial();
    let data = tmp_dir("orphan-put");
    let (relay, index) = relay_with_index(&data);
    let mut c = relay.connect();
    let good = block(b"orphan, valid");
    let other = block(b"orphan, damaged");
    let bad = damaged(&other, Damage::Signature);
    for (b, bytes) in [(&good, &good), (&other, &bad)] {
        let p = path_of(&data, &id_of(b));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
    }
    assert_eq!(put(&mut c, &good).status, 200);
    let pos = index.contains(&id_of(&good)).unwrap().expect("indexed");
    // Security review L-4: the wall clock, not the monotonic one.
    assert!(pos.received_at.abs_diff(unix_ms()) < 60_000, "Unix ms");
    // Owner decision (security review I-6): the identical bytes fail C3, so the `PUT` gets `422`
    // and the stored file goes to quarantine.
    let moved = metrics::store_quarantined_total(Damage::Signature);
    let r = put(&mut c, &bad);
    assert_eq!(
        (r.status, r.json()["error"].as_str()),
        (422, Some("InvalidSignature"))
    );
    assert!(
        index.contains(&id_of(&other)).unwrap().is_none(),
        "not indexed: it fails C3"
    );
    assert!(!path_of(&data, &id_of(&other)).exists(), "moved");
    assert_eq!(
        metrics::store_quarantined_total(Damage::Signature),
        moved + 1
    );
    let q = quarantined(&data);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].1, bad, "the stored bytes");
    assert_eq!(put(&mut c, &other).status, 201);
    let pos = index.contains(&id_of(&other)).unwrap().expect("indexed");
    assert!(pos.received_at.abs_diff(unix_ms()) < 60_000, "Unix ms");
}

/// Security review L-4: the `201` path indexes the block at the wall clock, in Unix ms.
#[test]
fn created_received_at_is_unix_ms() {
    let _s = serial();
    let data = tmp_dir("created-at");
    let (relay, index) = relay_with_index(&data);
    let b = block(b"created now");
    assert_eq!(put(&mut relay.connect(), &b).status, 201);
    let pos = index.contains(&id_of(&b)).unwrap().expect("indexed");
    assert!(pos.received_at.abs_diff(unix_ms()) < 60_000, "Unix ms");
}

/// Security review L-2: one unreadable orphan does not stop the start-up; it is left in place,
/// unindexed. Security review I-4: an orphan's file time in the future is capped at now.
#[test]
fn startup_walk_survives_an_unreadable_orphan() {
    use std::os::unix::fs::PermissionsExt;
    let _s = serial();
    // Root reads a mode-0000 file, which would defeat the test.
    if running_as_root() {
        return;
    }
    let data = tmp_dir("walk-unreadable");
    let (unreadable, future) = (
        block(b"unreadable orphan"),
        block(b"orphan from the future"),
    );
    {
        let (_relay, _index) = relay_with_index(&data);
    }
    for b in [&unreadable, &future] {
        let p = path_of(&data, &id_of(b));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b).unwrap();
    }
    let p = path_of(&data, &id_of(&unreadable));
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(10 * 24 * 3_600);
    std::fs::File::options()
        .write(true)
        .open(path_of(&data, &id_of(&future)))
        .unwrap()
        .set_modified(later)
        .unwrap();
    let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
    let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
    let errors = metrics::store_errors_total(metrics::StoreOp::Read);
    let rec = reconcile(&store, &index).unwrap();
    assert_eq!((rec.files, rec.orphans, rec.quarantined), (2, 1, 0));
    assert_eq!(
        metrics::store_errors_total(metrics::StoreOp::Read),
        errors + 1
    );
    assert!(index.contains(&id_of(&unreadable)).unwrap().is_none());
    assert!(p.exists(), "left in place");
    let pos = index.contains(&id_of(&future)).unwrap().expect("indexed");
    assert!(pos.received_at <= unix_ms(), "capped at now");
    assert_eq!(
        store.used_bytes(),
        TREE_CHARGE + cost(unreadable.len() as u64) + cost(future.len() as u64),
        "still counted"
    );
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    index.close().unwrap();
}

/// Whether the tests run as root, read from the owner of a file just created.
fn running_as_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    let p = tmp_dir("whoami");
    std::fs::create_dir_all(&p).unwrap();
    std::fs::metadata(&p).unwrap().uid() == 0
}

/// ADR 0023 rule 13: `HEAD` runs the `GET` pipeline: same status and headers, no body; a damaged
/// file is quarantined by it too.
#[test]
fn head_follows_get() {
    let _s = serial();
    let good = block(b"head");
    let id = id_of(&good);
    let data = tmp_dir("head");
    let (relay, _index) = relay_with_index(&data);
    let mut c = relay.connect();
    assert_eq!(put(&mut c, &good).status, 201);
    let path = format!("/sbtp/v1/block/{id}");
    for _ in 0..2 {
        // A miss, then a hit.
        let (status, h) = head(&mut c, &path);
        assert_eq!(status, 200);
        assert_eq!(
            header(&h, "cache-control"),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(header(&h, "content-type"), Some("application/octet-stream"));
    }
    let (status, h) = head(&mut c, &format!("/sbtp/v1/block/{}", "11".repeat(32)));
    assert_eq!(status, 404);
    assert_eq!(header(&h, "cache-control"), Some("no-store"));
    let other = block(b"head, damaged");
    assert_eq!(put(&mut c, &other).status, 201);
    std::fs::write(path_of(&data, &id_of(&other)), damaged(&other, Damage::Id)).unwrap();
    let (status, _) = head(&mut c, &format!("/sbtp/v1/block/{}", id_of(&other)));
    assert_eq!(status, 404);
    assert!(!path_of(&data, &id_of(&other)).exists());
    // The connection is still usable: no body was sent after the heads.
    assert_eq!(get_block(&mut c, &id).body, good);
}

/// ADR 0023 rule 17: the path without a `block_id` segment is `404` with the JSON body and
/// `no-store`.
#[test]
fn empty_id_is_not_found() {
    let _s = serial();
    let relay = TestServer::start(&settings(&[]), Router::new());
    let r = http_get(&mut relay.connect(), "/sbtp/v1/block/", "");
    assert_eq!(
        (r.status, r.json()["error"].as_str()),
        (404, Some("NotFound"))
    );
    assert_eq!(r.header("cache-control"), Some("no-store"));
}

/// An index that records the order of `renew_epoch` and `insert` calls (security review L-3).
struct Recording {
    inner: RedbIndex,
    calls: Mutex<Vec<&'static str>>,
}

impl IndexBackend for Recording {
    type Error = IndexError;

    fn open(path: &Path, cache_bytes: usize) -> Result<Self, IndexError> {
        Ok(Self {
            inner: RedbIndex::open(path, cache_bytes)?,
            calls: Mutex::new(Vec::new()),
        })
    }
    fn epoch(&self) -> u64 {
        self.inner.epoch()
    }
    fn renew_epoch(&self) -> Result<u64, IndexError> {
        self.calls.lock().unwrap().push("renew");
        self.inner.renew_epoch()
    }
    fn insert(
        &self,
        id: &BlockId,
        len: u32,
        parents: &[BlockId],
        now_ms: u64,
        state: FileState,
    ) -> Result<Option<Position>, IndexError> {
        self.calls.lock().unwrap().push("insert");
        self.inner.insert(id, len, parents, now_ms, state)
    }
    fn flush(&self) -> Result<(), IndexError> {
        self.inner.flush()
    }
    fn flush_pending(&self) -> Result<bool, IndexError> {
        self.inner.flush_pending()
    }
    fn contains(&self, id: &BlockId) -> Result<Option<Position>, IndexError> {
        self.inner.contains(id)
    }
    fn query(&self, p: Option<&BlockId>, from: Position, n: usize) -> Result<Page, IndexError> {
        self.inner.query(p, from, n)
    }
    fn expired(
        &self,
        before: Position,
        max: usize,
    ) -> Result<Vec<(Position, BlockId)>, IndexError> {
        self.inner.expired(before, max)
    }
    fn remove(&self, positions: &[Position]) -> Result<usize, IndexError> {
        self.inner.remove(positions)
    }
    fn len(&self) -> Result<u64, IndexError> {
        self.inner.len()
    }
}

/// Writes `files` (bytes under the final name of the `block_id` of each first element) and runs
/// the start-up walk over a [`Recording`] index. Returns the walk, the calls, and whether the
/// epoch changed.
fn walk_recorded(name: &str, files: &[(&[u8], Vec<u8>)]) -> (Reconciled, Vec<&'static str>, bool) {
    let data = tmp_dir(name);
    std::fs::create_dir_all(&data).unwrap();
    let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
    for (block, bytes) in files {
        std::fs::write(path_of(&data, &id_of(block)), bytes).unwrap();
    }
    let index = Recording::open(&data.join("index.redb"), 1 << 20).unwrap();
    let before = index.epoch();
    let rec = reconcile(&store, &index).unwrap();
    let calls = index.calls.lock().unwrap().clone();
    let changed = index.epoch() != before;
    (rec, calls, changed)
}

/// ADR 0024 rules 3 and 4 (security review L-3): the epoch is renewed once, before the first
/// orphan entry is written, whatever the number of orphans.
#[test]
fn epoch_is_renewed_before_the_first_orphan_insert() {
    let _serial = serial();
    let (a, b) = (block(b"orphan a"), block(b"orphan b"));
    let (rec, calls, changed) = walk_recorded("epoch-order", &[(&a, a.clone()), (&b, b.clone())]);
    assert_eq!((rec.orphans, rec.epoch_renewed, changed), (2, true, true));
    assert_eq!(calls, ["renew", "insert", "insert"]);
}

/// ADR 0024 rule 1 (security review L-3): a walk that only quarantines damaged files indexes no
/// orphan and keeps the epoch.
#[test]
fn quarantine_only_walk_keeps_the_epoch() {
    let _serial = serial();
    let bad = block(b"damaged only");
    let (rec, calls, changed) =
        walk_recorded("epoch-quarantine", &[(&bad, damaged(&bad, Damage::Id))]);
    assert_eq!((rec.orphans, rec.quarantined), (0, 1));
    assert_eq!((rec.epoch_renewed, changed), (false, false));
    assert_eq!(calls, Vec::<&str>::new());
}

/// An index whose inserts fail with the OS error `full` while it is not 0.
struct FullIndex {
    inner: RedbIndex,
    full: AtomicI32,
}

impl IndexBackend for FullIndex {
    type Error = IndexError;

    fn io_error(e: &IndexError) -> Option<&std::io::Error> {
        e.io_error()
    }
    fn open(path: &Path, cache_bytes: usize) -> Result<Self, IndexError> {
        Ok(Self {
            inner: RedbIndex::open(path, cache_bytes)?,
            full: AtomicI32::new(libc::ENOSPC),
        })
    }
    fn epoch(&self) -> u64 {
        self.inner.epoch()
    }
    fn renew_epoch(&self) -> Result<u64, IndexError> {
        self.inner.renew_epoch()
    }
    fn insert(
        &self,
        id: &BlockId,
        len: u32,
        parents: &[BlockId],
        now_ms: u64,
        state: FileState,
    ) -> Result<Option<Position>, IndexError> {
        let errno = self.full.load(Ordering::Relaxed);
        if errno != 0 {
            return Err(IndexError::from(redb::Error::Io(
                std::io::Error::from_raw_os_error(errno),
            )));
        }
        self.inner.insert(id, len, parents, now_ms, state)
    }
    fn flush(&self) -> Result<(), IndexError> {
        self.inner.flush()
    }
    fn flush_pending(&self) -> Result<bool, IndexError> {
        self.inner.flush_pending()
    }
    fn contains(&self, id: &BlockId) -> Result<Option<Position>, IndexError> {
        self.inner.contains(id)
    }
    fn query(
        &self,
        parent: Option<&BlockId>,
        from: Position,
        limit: usize,
    ) -> Result<Page, IndexError> {
        self.inner.query(parent, from, limit)
    }
    fn expired(
        &self,
        before: Position,
        max: usize,
    ) -> Result<Vec<(Position, BlockId)>, IndexError> {
        self.inner.expired(before, max)
    }
    fn remove(&self, positions: &[Position]) -> Result<usize, IndexError> {
        self.inner.remove(positions)
    }
    fn len(&self) -> Result<u64, IndexError> {
        self.inner.len()
    }
}

/// Security review I-3 and L-1: no room for the index entry (`ENOSPC` or `EDQUOT`) is a full
/// store, `507`; the file stays as an orphan, indexed by the next `PUT` once there is room.
#[test]
fn index_enospc_gives_507() {
    index_full_gives_507(libc::ENOSPC, metrics::StorageFull::Enospc);
}

#[test]
fn index_edquot_gives_507() {
    index_full_gives_507(libc::EDQUOT, metrics::StorageFull::Edquot);
}

fn index_full_gives_507(errno: i32, reason: metrics::StorageFull) {
    let _s = serial();
    let data = tmp_dir(&format!("index-full-{errno}"));
    std::fs::create_dir_all(&data).unwrap();
    let index = Arc::new(FullIndex::open(&data.join("index.redb"), 1 << 20).unwrap());
    index.full.store(errno, Ordering::Relaxed);
    let full = metrics::storage_full_total(reason);
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    let relay = TestServer::start_with(&s, Router::new(), &data, Arc::clone(&index));
    let mut c = relay.connect();
    let b = block(b"no room in the index");
    let id = id_of(&b);
    let r = put(&mut c, &b);
    assert_eq!(
        (r.status, r.json()["error"].as_str()),
        (507, Some("StorageFull"))
    );
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(
        metrics::storage_full_total(reason),
        full + 1,
        "{}",
        reason.reason()
    );
    assert!(path_of(&data, &id).exists(), "an orphan");
    assert!(index.contains(&id).unwrap().is_none());
    index.full.store(0, Ordering::Relaxed);
    assert_eq!(put(&mut c, &b).status, 200);
    assert!(index.contains(&id).unwrap().is_some(), "repaired");
}
