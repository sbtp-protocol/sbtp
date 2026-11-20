//! One shard level created at start-up, and directories in the quota (ADR 0025).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use axum::Router;
use common::{TestServer, get as http_get, put_block, settings, signed_block, tmp_dir};
use sbtp_core::BlockId;
use sbtp_relay::index::{IndexBackend, RedbIndex};
use sbtp_relay::metrics::{self, StoreOp};
use sbtp_relay::store::{Store, StoreError, TREE_CHARGE, cost, reconcile};

/// The store counters are process-wide: the tests that assert them take this lock.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn shard(data: &Path, id: &BlockId) -> PathBuf {
    data.join(format!("blocks/{:02x}", id.as_bytes()[31]))
}

/// Opens and reconciles `data` as a start does; returns the store and the walk's result.
fn open(data: &Path) -> (Store, sbtp_relay::store::Reconciled) {
    let index = RedbIndex::open(&data.join("index.redb"), 1 << 20).unwrap();
    let store = Store::open(data, data.join("index.redb"), 1 << 30).unwrap();
    let rec = reconcile(&store, &index).unwrap();
    index.close().unwrap();
    (store, rec)
}

/// Rules 3, 8, 9, 13 and 17: the first start creates the 259 directories with mode `0700`; the
/// sum is the tree charge, then `T + 4,224` with one minimum-size block; a restart creates
/// nothing and recomputes the same sum.
#[test]
fn first_start_creates_the_tree() {
    let data = tmp_dir("shards-first");
    std::fs::create_dir_all(&data).unwrap();
    let (store, rec) = open(&data);
    assert_eq!(rec.dirs_created, 259);
    assert_eq!(store.used_bytes(), TREE_CHARGE);
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
    let names: Vec<String> = std::fs::read_dir(data.join("blocks"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 256);
    for b in 0..=u8::MAX {
        let d = data.join(format!("blocks/{b:02x}"));
        assert!(std::fs::symlink_metadata(&d).unwrap().is_dir());
        assert_eq!(mode(&d), 0o700);
    }
    for d in ["blocks", "tmp", "quarantine"] {
        assert_eq!(mode(&data.join(d)), 0o700, "{d}");
    }
    let b = signed_block(b"small", &[]);
    assert!(b.len() < 4_096);
    let v = sbtp_core::validate_submitted(&b, 0).unwrap();
    store.write_new(&v).unwrap();
    assert_eq!(store.used_bytes(), TREE_CHARGE + 4_224);
    assert_eq!(cost(b.len() as u64), 4_224);
    drop(store);
    let (store, rec) = open(&data);
    assert_eq!((rec.dirs_created, rec.files), (0, 1));
    assert_eq!(
        store.used_bytes(),
        TREE_CHARGE + 4_224,
        "the walk recomputes it"
    );
}

/// Rule 4: a shard directory that is a file or a symbolic link stops the start-up; the link is
/// not followed.
#[test]
fn wrong_kind_of_shard_stops_start_up() {
    for link in [false, true] {
        let data = tmp_dir("shards-kind");
        std::fs::create_dir_all(data.join("blocks")).unwrap();
        let target = tmp_dir("shards-kind-target");
        std::fs::create_dir_all(&target).unwrap();
        let shard = data.join("blocks/7f");
        if link {
            std::os::unix::fs::symlink(&target, &shard).unwrap();
        } else {
            std::fs::write(&shard, b"not a directory").unwrap();
        }
        assert!(Store::open(&data, data.join("index.redb"), 1 << 30).is_err());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "{link}");
    }
}

/// Rules 5 and 6: a shard directory removed while the relay runs gives `500` on `PUT` (`op=write`,
/// nothing created, the reservation released, the directory not recreated) and on a `GET` miss of
/// a block in it (`op=read`, not `404`); the next start recreates it (`dirs_created = 1`).
#[test]
fn shard_removed_at_run_time() {
    let _serial = serial();
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    let held = signed_block(b"held", &[]);
    let held_id = sbtp_core::parse(&held).unwrap().block_id();
    // A new block in the same shard as `held`.
    let new = (0u32..10_000)
        .map(|i| signed_block(format!("new {i}").as_bytes(), &[]))
        .find(|b| sbtp_core::parse(b).unwrap().block_id().as_bytes()[31] == held_id.as_bytes()[31])
        .unwrap();
    let data = tmp_dir("shards-removed");
    {
        // No cache, so that the `GET` below reads the store.
        let s = settings(&[("MIN_POW_DIFFICULTY", "0"), ("BLOCK_CACHE_BYTES", "0")]);
        let relay = TestServer::start_in(&s, Router::new(), &data);
        let mut c = relay.connect();
        assert_eq!(put_block(&mut c, &held).status, 201);
        std::fs::remove_dir_all(shard(&data, &held_id)).unwrap();
        let (writes, reads) = (
            metrics::store_errors_total(StoreOp::Write),
            metrics::store_errors_total(StoreOp::Read),
        );
        let r = put_block(&mut c, &new);
        assert_eq!(
            (r.status, r.json()["error"].as_str()),
            (500, Some("Internal"))
        );
        assert!(
            metrics::store_errors_total(StoreOp::Write) > writes,
            "op=write"
        );
        assert!(!shard(&data, &held_id).exists(), "not recreated");
        let r = http_get(&mut c, &format!("/sbtp/v1/block/{held_id}"), "");
        assert_eq!(
            (r.status, r.json()["error"].as_str()),
            (500, Some("Internal"))
        );
        assert!(
            metrics::store_errors_total(StoreOp::Read) > reads,
            "op=read"
        );
        assert_eq!(std::fs::read_dir(data.join("tmp")).unwrap().count(), 0);
    }
    // On the store: the reservation is released and nothing is created.
    {
        let store = Store::open(&data, data.join("index.redb"), 1 << 30).unwrap();
        std::fs::remove_dir_all(shard(&data, &held_id)).unwrap();
        let used = store.used_bytes();
        let v = sbtp_core::validate_submitted(&new, 0).unwrap();
        assert!(matches!(store.write_new(&v), Err(StoreError::Io(_))));
        assert_eq!(store.used_bytes(), used);
        assert!(!shard(&data, &held_id).exists());
    }
    let (_, rec) = open(&data);
    assert_eq!(rec.dirs_created, 1, "rule 17");
    let relay = TestServer::start_in(&s, Router::new(), &data);
    assert_eq!(put_block(&mut relay.connect(), &new).status, 201);
}

/// Code review 1: with the quota full, a missing shard is still the I/O error of rule 6 (`500`,
/// `op=write`), not `507`.
#[test]
fn missing_shard_wins_over_a_full_quota() {
    let data = tmp_dir("shards-full");
    std::fs::create_dir_all(&data).unwrap();
    let b = signed_block(b"no room", &[]);
    let v = sbtp_core::validate_submitted(&b, 0).unwrap();
    // Room for the tree and the index reserve only.
    let quota = TREE_CHARGE + sbtp_relay::store::index_reserve(0);
    let store = Store::open(&data, data.join("index.redb"), quota).unwrap();
    assert!(matches!(store.write_new(&v), Err(StoreError::Full)));
    std::fs::remove_dir_all(shard(&data, v.block_id())).unwrap();
    assert!(matches!(store.write_new(&v), Err(StoreError::Io(_))));
    assert_eq!(store.used_bytes(), TREE_CHARGE);
}

/// Code review 2: a read error that is not a missing shard (here the final name is a
/// directory) gives `500` with `op=read` on `PUT`, and creates nothing.
#[test]
fn other_read_errors_stay_read_errors() {
    let _serial = serial();
    let s = settings(&[("MIN_POW_DIFFICULTY", "0")]);
    let relay = TestServer::start(&s, Router::new());
    let b = signed_block(b"final name is a directory", &[]);
    let id = sbtp_core::parse(&b).unwrap().block_id();
    let final_name = shard(&relay.data, &id).join(format!("{id}.bin"));
    std::fs::create_dir(&final_name).unwrap();
    let (reads, writes) = (
        metrics::store_errors_total(StoreOp::Read),
        metrics::store_errors_total(StoreOp::Write),
    );
    let r = put_block(&mut relay.connect(), &b);
    assert_eq!(
        (r.status, r.json()["error"].as_str()),
        (500, Some("Internal"))
    );
    assert!(
        metrics::store_errors_total(StoreOp::Read) > reads,
        "op=read"
    );
    assert_eq!(
        metrics::store_errors_total(StoreOp::Write),
        writes,
        "not the create path"
    );
    assert!(std::fs::symlink_metadata(&final_name).unwrap().is_dir());
}

/// Code review 3: releases never take the sum below the tree charge (ADR 0025 rule 9). A
/// quarantined file placed after the walk is not counted; purging it releases its cost.
#[test]
fn sum_never_falls_below_the_tree_charge() {
    let data = tmp_dir("shards-floor");
    std::fs::create_dir_all(&data).unwrap();
    let (store, _) = open(&data);
    assert_eq!(store.used_bytes(), TREE_CHARGE);
    let name = format!("{}.0.0", BlockId([5; 32]));
    std::fs::write(data.join("quarantine").join(name), vec![0u8; 100_000]).unwrap();
    assert_eq!(store.purge_quarantine(common::now_ms()).unwrap(), 1);
    assert_eq!(store.used_bytes(), TREE_CHARGE);
}
