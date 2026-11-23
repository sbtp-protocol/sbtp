//! End-to-end tests of the survival guards (SPEC §5 to §7): request caps, `PUT` byte budgets,
//! long denied runs, the deny list at startup and the `relay_id` of a restored store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![allow(clippy::arithmetic_side_effects, missing_docs)]

mod common;

use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use common::{Relay, TEST_POW, block, block_with, config, key, now_ms, parse_flat_json};
use sbtp_core::BlockId;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// A `PUT` whose body never comes: it holds its request slots until the body timeout.
async fn hold(relay: &Relay, header: &str) -> TcpStream {
    let mut tcp = TcpStream::connect(relay.addr).await.unwrap();
    let head =
        format!("PUT /sbtp/v1/block HTTP/1.1\r\nHost: r\r\nContent-Length: 100\r\n{header}\r\n");
    tcp.write_all(head.as_bytes()).await.unwrap();
    tcp
}

/// Repeats `GET /info` until it gets `status`: held requests are registered asynchronously.
async fn until_status(relay: &Relay, header: &[&str], status: u16) -> common::Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = relay.raw("GET", "/sbtp/v1/info", header, b"").await;
        if r.status == status || Instant::now() > deadline {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn per_client_429_and_global_503_request_caps() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.body_timeout = Duration::from_secs(60);
    (c.rate_per_sec, c.rate_burst) = (1000.0, 1000.0);
    let relay = Relay::start(c.clone()).await;
    // 7 held requests and the probe are 8, within the per-client cap.
    let mut held = Vec::new();
    for _ in 0..7 {
        held.push(hold(&relay, "").await);
    }
    assert_eq!(relay.get("/sbtp/v1/info").await.status, 200);
    held.push(hold(&relay, "").await);
    let r = until_status(&relay, &[], 429).await;
    assert_eq!((r.status, r.error()), (429, "RateLimited".into()));
    assert!(r.header("retry-after").is_some());
    drop(held);
    relay.stop().await;

    // The global cap counts every client: two clients hold both slots, a third gets `503`.
    let dir = TempDir::new().unwrap();
    c.data_dir = dir.path().to_path_buf();
    c.max_requests = 2;
    c.client_ip_header = Some("x-forwarded-for".parse().unwrap());
    let relay = Relay::start(c).await;
    let a = hold(&relay, "X-Forwarded-For: 10.0.0.1\r\n").await;
    let b = hold(&relay, "X-Forwarded-For: 10.0.0.2\r\n").await;
    let r = until_status(&relay, &["X-Forwarded-For: 10.0.0.3"], 503).await;
    assert_eq!((r.status, r.error()), (503, "Unavailable".into()));
    // Closed connections end their requests, so that the relay stops at once.
    drop((a, b));
    relay.stop().await;
}

/// Status of a 65,000-byte invalid `PUT` from `ip`: the byte budget counts invalid bodies too.
async fn put_junk(relay: &Relay, ip: &str) -> common::Response {
    let header = format!("X-Forwarded-For: {ip}");
    let body = vec![0u8; 65_000];
    relay.raw("PUT", "/sbtp/v1/block", &[&header], &body).await
}

#[tokio::test]
async fn put_byte_budget_per_client_and_per_48() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.client_ip_header = Some("x-forwarded-for".parse().unwrap());
    let relay = Relay::start(c).await;
    // One client: a burst of 4 MiB, that is 64 such bodies, then `429` with `Retry-After`.
    let mut statuses = Vec::new();
    for _ in 0..80 {
        statuses.push(put_junk(&relay, "10.0.0.1").await.status);
    }
    assert_eq!(statuses[..60], [400; 60]);
    let r = put_junk(&relay, "10.0.0.1").await;
    assert_eq!((r.status, r.error()), (429, "RateLimited".into()));
    assert!(r.header("retry-after").unwrap().parse::<u64>().unwrap() >= 1);
    // Another client is not affected.
    assert_eq!(put_junk(&relay, "10.0.0.2").await.status, 400);

    // Ten /64 clients of one /48, each within its own budget, exhaust the /48's (32 MiB).
    let mut limited = 0;
    for n in 0..10 {
        for _ in 0..62 {
            let r = put_junk(&relay, &format!("2001:db8:1:{n}::1")).await;
            limited += usize::from(r.status == 429);
        }
    }
    assert!(limited > 0, "{limited}");
    // Another /48 is not affected.
    assert_eq!(put_junk(&relay, "2001:db8:2::1").await.status, 400);
    relay.stop().await;
}

/// `(block_ids, since, more)` of a `/query` response.
async fn query(relay: &Relay, params: &str) -> (Vec<String>, String, String) {
    let r = relay.get(&format!("/sbtp/v1/query?{params}")).await;
    assert_eq!(r.status, 200, "{params}: {}", r.text());
    let j = parse_flat_json(&r.text());
    let ids = j["block_ids"].split(',').filter(|x| !x.is_empty());
    (
        ids.map(String::from).collect(),
        j["since"].clone(),
        j["more"].clone(),
    )
}

/// Waits until `GET` of `id` gives `status`: the deny list was reloaded.
async fn wait_status(relay: &Relay, id: &BlockId, status: u16) {
    for _ in 0..200 {
        if relay.get(&format!("/sbtp/v1/block/{id}")).await.status == status {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("deny list not reloaded");
}

#[tokio::test]
async fn long_denied_runs_are_examined_in_bounded_steps() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    // Position 1: `first`; 2 to 11: ten children of `first` by key 2; 12: `last`, child too.
    let (first, first_bytes) = block(&[], b"first");
    assert_eq!(relay.put(&first_bytes).await.status, 201);
    let mut run = Vec::new();
    for n in 0..10u8 {
        let (id, bytes) = block_with(&key(2), &[first], &[n], now_ms(), TEST_POW);
        assert_eq!(relay.put(&bytes).await.status, 201);
        run.push(id);
    }
    let (last, last_bytes) = block(&[first], b"last");
    assert_eq!(relay.put(&last_bytes).await.status, 201);
    let key2 = BlockId(key(2).verifying_key().to_bytes());
    relay.write_deny(&format!("key {key2}\n"));
    wait_status(&relay, &run[0], 451).await;

    // A page examines at most 4 entries per block it may list, denied ones included, and then
    // names the last one examined, so an empty page still progresses.
    let (first, last) = (first.to_string(), last.to_string());
    let s = |s: &str| s.to_string();
    let pages = [
        ("limit=1", (vec![first.clone()], s("4"), s("true"))),
        ("since=4&limit=1", (vec![], s("8"), s("true"))),
        ("since=8&limit=1", (vec![last.clone()], s("12"), s("false"))),
    ];
    for (params, page) in pages {
        assert_eq!(query(&relay, params).await, page, "{params}");
    }
    let children = query(&relay, &format!("parent={first}&limit=1")).await;
    assert_eq!(children, (vec![], s("5"), s("true")));
    let children = query(&relay, &format!("parent={first}&since=8&limit=1")).await;
    assert_eq!(children, (vec![last.clone()], s("12"), s("false")));
    // A large limit lists both in one page.
    assert_eq!(query(&relay, "limit=100").await.0, [first, last.clone()]);

    // `last_position` is kept, not scanned: a denied tail moves it back once, at the reload.
    assert_eq!(relay.info().await["last_position"], "12");
    relay.write_deny(&format!("key {key2}\nblock {last}\n"));
    wait_status(&relay, &last.parse().unwrap(), 451).await;
    assert_eq!(relay.info().await["last_position"], "1");
    relay.stop().await;
}

#[tokio::test]
async fn unreadable_or_malformed_deny_list_refuses_to_start() {
    for malformed in [true, false] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("deny.txt");
        if malformed {
            std::fs::write(&path, "block 00\n").unwrap();
        } else {
            // A directory cannot be read as a file, like a file without read permission.
            std::fs::create_dir(&path).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let started = sbtp_relay::run(listener, config(&dir), async {}).await;
        let error = started.unwrap_err().to_string();
        assert!(error.starts_with("deny.txt"), "{error}");
    }
}

fn store_file(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("relay.redb")
}

#[tokio::test]
async fn restored_store_draws_a_new_relay_id() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let (_, a) = block(&[], b"a");
    assert_eq!(relay.put(&a).await.status, 201);
    let first_id = relay.info().await["relay_id"].clone();
    relay.stop().await;
    let backup = std::fs::read(store_file(&dir)).unwrap();
    let relay = Relay::start(config(&dir)).await;
    let (_, b) = block(&[], b"b");
    assert_eq!(relay.put(&b).await.status, 201);
    relay.stop().await;

    // The file restored in place (same inode, rsync --inplace or cp over it): the sidecar saw
    // position 2, the store has 1.
    let inode = std::fs::metadata(store_file(&dir)).unwrap().ino();
    std::fs::write(store_file(&dir), &backup).unwrap();
    assert_eq!(std::fs::metadata(store_file(&dir)).unwrap().ino(), inode);
    let relay = Relay::start(config(&dir)).await;
    let info = relay.info().await;
    let second_id = info["relay_id"].clone();
    assert_ne!(second_id, first_id);
    assert_eq!(info["last_position"], "1");
    relay.stop().await;

    // A volume snapshot rolls the sidecar back too: only the operator's marker can tell.
    let sidecar = dir.path().join("relay.position");
    let snapshot = (
        std::fs::read(store_file(&dir)).unwrap(),
        std::fs::read(&sidecar).unwrap(),
    );
    let relay = Relay::start(config(&dir)).await;
    assert_eq!(relay.put(&b).await.status, 201);
    relay.stop().await;
    std::fs::write(store_file(&dir), &snapshot.0).unwrap();
    std::fs::write(&sidecar, &snapshot.1).unwrap();
    let relay = Relay::start(config(&dir)).await;
    assert_eq!(relay.info().await["relay_id"], second_id);
    relay.stop().await;
    std::fs::write(dir.path().join("restored"), b"").unwrap();
    let relay = Relay::start(config(&dir)).await;
    let third_id = relay.info().await["relay_id"].clone();
    assert_ne!(third_id, second_id);
    assert!(!dir.path().join("restored").exists());
    relay.stop().await;
    // The new id is kept from then on.
    let relay = Relay::start(config(&dir)).await;
    assert_eq!(relay.info().await["relay_id"], third_id);
    relay.stop().await;
}
