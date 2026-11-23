//! End-to-end HTTP tests of the relay (SPEC §5, §7) over loopback.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![allow(clippy::arithmetic_side_effects, missing_docs)]

mod common;

use std::time::Duration;

use common::{Relay, TEST_POW, block, block_with, config, key, now_ms, parse_flat_json};
use sbtp_core::{BlockId, UnsignedBlock};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn put_get_and_duplicate() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let (id, bytes) = block(&[], b"hello");
    let r = relay.put(&bytes).await;
    assert_eq!(r.status, 201);
    assert_eq!(
        r.header("location"),
        Some(format!("/sbtp/v1/block/{id}").as_str())
    );
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    assert_eq!(
        r.header("access-control-expose-headers"),
        Some("Location, Retry-After")
    );

    let r = relay.get(&format!("/sbtp/v1/block/{id}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, bytes);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(
        r.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));

    // spec §5: a repeated PUT is `200` and gets no new position.
    assert_eq!(relay.put(&bytes).await.status, 200);
    assert_eq!(relay.info().await["last_position"], "1");
    relay.stop().await;
}

#[tokio::test]
async fn get_errors_and_unknown_routes() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let unknown = BlockId([0xab; 32]);
    let r = relay.get(&format!("/sbtp/v1/block/{unknown}")).await;
    assert_eq!((r.status, r.error()), (404, "NotFound".into()));
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    let upper = unknown.to_string().to_uppercase();
    let r = relay.get(&format!("/sbtp/v1/block/{upper}")).await;
    assert_eq!((r.status, r.error()), (400, "InvalidParameter".into()));
    let r = relay.get("/sbtp/v1/block/abc").await;
    assert_eq!((r.status, r.error()), (400, "InvalidParameter".into()));
    let r = relay.get("/elsewhere").await;
    assert_eq!((r.status, r.error()), (404, "NotFound".into()));
    let r = relay.request("POST", "/sbtp/v1/block", b"x").await;
    assert_eq!((r.status, r.error()), (405, "MethodNotAllowed".into()));
    relay.stop().await;
}

#[tokio::test]
async fn cors_preflight() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let r = relay.request("OPTIONS", "/sbtp/v1/block", b"").await;
    assert_eq!(r.status, 204);
    assert_eq!(r.header("access-control-allow-methods"), Some("GET, PUT"));
    assert_eq!(
        r.header("access-control-allow-headers"),
        Some("content-type")
    );
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    relay.stop().await;
}

/// Encodes a block by hand, for public keys `UnsignedBlock::sign` refuses.
fn raw_block(pubkey: [u8; 32], difficulty: u32) -> Vec<u8> {
    let mut unsigned = UnsignedBlock {
        timestamp: now_ms(),
        nonce: 0,
        pubkey,
        parents: &[],
        payload: b"p",
    };
    unsigned.mine(difficulty, u64::MAX).unwrap();
    let mut out = b"SB\x01".to_vec();
    out.extend_from_slice(&unsigned.timestamp.to_be_bytes());
    out.extend_from_slice(&unsigned.nonce.to_be_bytes());
    out.extend_from_slice(&pubkey);
    out.extend_from_slice(&[0, 0, 1, b'p']);
    out.extend_from_slice(&[0; 64]);
    out
}

#[tokio::test]
async fn put_rejections_in_spec_order() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let expect = |r: common::Response, status: u16, name: &str| {
        assert_eq!((r.status, r.error()), (status, name.to_string()));
    };
    expect(relay.put(b"short").await, 400, "TooShort");
    let (_, mut bad_magic) = block(&[], b"x");
    bad_magic[0] = b'X';
    expect(relay.put(&bad_magic).await, 400, "BadMagic");

    // P1: more than 5 minutes ahead of the relay clock.
    let (_, future) = block_with(&key(1), &[], b"x", now_ms() + 600_000, TEST_POW);
    expect(relay.put(&future).await, 400, "TimestampTooFarInFuture");

    // C1: a block below the relay's difficulty.
    let weak = (0u8..=255)
        .map(|n| block_with(&key(1), &[], &[n], now_ms(), 0))
        .find(|(id, _)| id.leading_zero_bits() < TEST_POW)
        .unwrap();
    expect(relay.put(&weak.1).await, 400, "InsufficientPow");

    // C3: the signature is not covered by the block_id, so the PoW still holds.
    let (_, mut forged) = block(&[], b"x");
    let last = forged.len() - 1;
    forged[last] ^= 1;
    expect(relay.put(&forged).await, 422, "InvalidSignature");

    // C2: an all-zero key is a point of small order (V2).
    expect(
        relay.put(&raw_block([0; 32], TEST_POW)).await,
        422,
        "InvalidPublicKey",
    );
    assert_eq!(relay.info().await["last_position"], "0");
    relay.stop().await;
}

#[tokio::test]
async fn oversized_body_is_refused_before_it_is_read() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    // Only the head is sent: the relay answers without waiting for the body.
    let head = "PUT /sbtp/v1/block HTTP/1.1\r\nHost: r\r\nConnection: close\r\nContent-Length: 65910\r\n\r\n";
    let r = relay.send_raw(head.as_bytes()).await;
    assert_eq!((r.status, r.error()), (413, "BodyTooLarge".into()));

    // Without a length: chunked, cut at the limit.
    let mut chunked =
        b"PUT /sbtp/v1/block HTTP/1.1\r\nHost: r\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    chunked.extend_from_slice(format!("{:x}\r\n", 70_000).as_bytes());
    chunked.extend_from_slice(&vec![0u8; 70_000]);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    let r = relay.send_raw(&chunked).await;
    assert_eq!((r.status, r.error()), (413, "BodyTooLarge".into()));
    relay.stop().await;
}

#[tokio::test]
async fn slow_body_times_out() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.body_timeout = Duration::from_millis(200);
    let relay = Relay::start(c).await;
    let mut tcp = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    let head = "PUT /sbtp/v1/block HTTP/1.1\r\nHost: r\r\nConnection: close\r\nContent-Length: 500\r\n\r\n0123456789";
    tcp.write_all(head.as_bytes()).await.unwrap();
    let r = common::read_response(&mut tcp).await;
    assert_eq!((r.status, r.error()), (408, "RequestTimeout".into()));
    relay.stop().await;
}

#[tokio::test]
async fn rate_limit_listed_addresses_and_proxy_header() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.rate_per_sec = 0.1;
    c.rate_burst = 2.0;
    let relay = Relay::start(c.clone()).await;
    assert_eq!(relay.get("/sbtp/v1/info").await.status, 200);
    assert_eq!(relay.get("/sbtp/v1/info").await.status, 200);
    let r = relay.get("/sbtp/v1/info").await;
    assert_eq!((r.status, r.error()), (429, "RateLimited".into()));
    let retry: u64 = r.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=10).contains(&retry), "{retry}");
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    relay.stop().await;

    // A listed address gets `LISTED_FACTOR` times the burst.
    let dir = TempDir::new().unwrap();
    let mut listed = c.clone();
    listed.data_dir = dir.path().to_path_buf();
    listed
        .listed
        .insert(std::net::IpAddr::from([127, 0, 0, 1]).into());
    let relay = Relay::start(listed).await;
    for _ in 0..10 {
        assert_eq!(relay.get("/sbtp/v1/info").await.status, 200);
    }
    relay.stop().await;

    // Behind a proxy: the header's last entry is the client; an IPv6 /64 is one client.
    let dir = TempDir::new().unwrap();
    let mut proxied = c;
    proxied.data_dir = dir.path().to_path_buf();
    proxied.rate_burst = 1.0;
    proxied.client_ip_header = Some("x-forwarded-for".parse().unwrap());
    let relay = Relay::start(proxied).await;
    for (ip, status) in [
        ("10.0.0.1", 200),
        ("10.0.0.1", 429),
        ("10.0.0.2", 200),
        ("2001:db8::1", 200),
        ("2001:db8::2", 429),
        ("2001:db8:0:1::2", 200),
    ] {
        let header = format!("X-Forwarded-For: 203.0.113.9, {ip}");
        let r = relay.raw("GET", "/sbtp/v1/info", &[&header], b"").await;
        assert_eq!(r.status, status, "{ip}");
    }
    relay.stop().await;
}

#[tokio::test]
async fn info_members() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let r = relay.get("/sbtp/v1/info").await;
    assert_eq!(r.header("content-type"), Some("application/json"));
    let text = r.text();
    // spec §5: positions are decimal strings.
    assert!(text.contains("\"last_position\":\"0\""), "{text}");
    assert!(text.contains("\"block_versions\":[1]"), "{text}");
    let info = parse_flat_json(&text);
    let mut keys: Vec<_> = info.keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "block_versions",
            "last_position",
            "max_future_ms",
            "max_query_limit",
            "max_subscriptions_per_ip",
            "min_pow_difficulty",
            "relay_id"
        ]
    );
    assert_eq!(info["relay_id"].len(), 32);
    assert!(
        info["relay_id"]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(info["min_pow_difficulty"], TEST_POW.to_string());
    assert_eq!(info["max_future_ms"], "300000");
    assert_eq!(info["max_query_limit"], "1000");
    assert_eq!(info["max_subscriptions_per_ip"], "4");
    relay.stop().await;
}

#[tokio::test]
async fn default_difficulty_is_16() {
    assert_eq!(
        sbtp_relay::Config::new("unused".into()).min_pow_difficulty,
        16
    );
}

#[tokio::test]
async fn positions_persist_relay_id_and_quota() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let (a, a_bytes) = block(&[], b"a");
    assert_eq!(relay.put(&a_bytes).await.status, 201);
    let id = relay.info().await["relay_id"].clone();
    relay.stop().await;

    // Restart over the same store, over its quota: same relay_id, old blocks still `200`.
    let mut full = config(&dir);
    full.max_store_bytes = 1;
    let relay = Relay::start(full).await;
    assert_eq!(relay.info().await["relay_id"], id);
    assert_eq!(relay.put(&a_bytes).await.status, 200);
    let (_, b_bytes) = block(&[a], b"b");
    let r = relay.put(&b_bytes).await;
    assert_eq!((r.status, r.error()), (507, "StorageFull".into()));
    assert_eq!(relay.info().await["last_position"], "1");
    relay.stop().await;

    // Positions continue after a restart, never reused.
    let relay = Relay::start(config(&dir)).await;
    assert_eq!(relay.put(&b_bytes).await.status, 201);
    assert_eq!(relay.info().await["last_position"], "2");
    relay.stop().await;

    // spec §5: a copied store draws a new relay_id but keeps its positions.
    let copy = TempDir::new().unwrap();
    std::fs::copy(
        dir.path().join("relay.redb"),
        copy.path().join("relay.redb"),
    )
    .unwrap();
    let relay = Relay::start(config(&copy)).await;
    let info = relay.info().await;
    assert_ne!(info["relay_id"], id);
    assert_eq!(info["last_position"], "2");
    relay.stop().await;
}

/// `(block_ids, positions, since, more)` of a `/query` response.
async fn query(relay: &Relay, params: &str) -> (Vec<String>, Vec<String>, String, String) {
    let r = relay.get(&format!("/sbtp/v1/query?{params}")).await;
    assert_eq!(r.status, 200, "{params}: {}", r.text());
    assert_eq!(r.header("cache-control"), Some("no-store"));
    let j = parse_flat_json(&r.text());
    let list = |s: &str| {
        s.split(',')
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect()
    };
    (
        list(&j["block_ids"]),
        list(&j["positions"]),
        j["since"].clone(),
        j["more"].clone(),
    )
}

#[tokio::test]
async fn query_pages_parents_and_errors() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    assert_eq!(
        query(&relay, "").await,
        (vec![], vec![], "0".into(), "false".into())
    );
    let (root, root_bytes) = block(&[], b"root");
    relay.put(&root_bytes).await;
    let mut children = Vec::new();
    for n in 0..4u8 {
        let parents = if n % 2 == 0 { vec![root] } else { vec![] };
        let (id, bytes) = block(&parents, &[n]);
        assert_eq!(relay.put(&bytes).await.status, 201);
        children.push(id.to_string());
    }

    let page = query(&relay, "limit=2").await;
    assert_eq!(
        page,
        (
            vec![root.to_string(), children[0].clone()],
            vec!["1".into(), "2".into()],
            "2".into(),
            "true".into()
        )
    );
    let page = query(&relay, "since=2&limit=10").await;
    assert_eq!(page.0, children[1..].to_vec());
    assert_eq!(page.1, ["3", "4", "5"]);
    assert_eq!((page.2.as_str(), page.3.as_str()), ("5", "false"));
    assert_eq!(
        query(&relay, "since=5").await,
        (vec![], vec![], "5".into(), "false".into())
    );

    // Children of `root`, in position order.
    let kids = query(&relay, &format!("parent={root}")).await;
    assert_eq!(kids.0, [children[0].clone(), children[2].clone()]);
    assert_eq!(kids.1, ["2", "4"]);
    let kids = query(&relay, &format!("parent={root}&limit=1&since=2")).await;
    assert_eq!(
        (kids.1, kids.2, kids.3),
        (vec!["4".to_string()], "4".into(), "false".into())
    );
    let unknown = BlockId([9; 32]);
    assert_eq!(
        query(&relay, &format!("parent={unknown}&since=3")).await.2,
        "3"
    );
    // A value above `max_query_limit` is lowered, not refused.
    assert_eq!(
        query(&relay, "limit=99999999999999999999999").await.0.len(),
        5
    );

    let r = relay.get("/sbtp/v1/query?since=6").await;
    assert_eq!((r.status, r.error()), (400, "InvalidPosition".into()));
    for bad in [
        "since=abc",
        "since=1&since=2",
        "foo=1",
        "limit=0",
        "since=",
        "since",
        "since=-1",
        "since=18446744073709551616",
        "since=000000000000000000001",
        "parent=ABC",
        "since=%31",
    ] {
        let r = relay.get(&format!("/sbtp/v1/query?{bad}")).await;
        assert_eq!(
            (r.status, r.error()),
            (400, "InvalidParameter".into()),
            "{bad}"
        );
    }
    relay.stop().await;
}

/// Waits until `GET` of `id` gives `status`: the deny list was reloaded.
async fn wait_status(relay: &Relay, id: &BlockId, status: u16) {
    for _ in 0..100 {
        if relay.get(&format!("/sbtp/v1/block/{id}")).await.status == status {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("deny list not reloaded");
}

#[tokio::test]
async fn deny_list_reloads_without_restart() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let (a, a_bytes) = block(&[], b"a");
    let (b, b_bytes) = block_with(&key(2), &[], b"b", now_ms(), TEST_POW);
    relay.put(&a_bytes).await;
    relay.put(&b_bytes).await;

    relay.write_deny(&format!("# operator list\nblock {a}\n"));
    wait_status(&relay, &a, 451).await;
    let r = relay.get(&format!("/sbtp/v1/block/{a}")).await;
    assert_eq!(r.error(), "Denied");
    let r = relay.put(&a_bytes).await;
    assert_eq!((r.status, r.error()), (451, "Denied".into()));
    // Not listed; its position is examined (`since`) and still counts for `InvalidPosition`.
    let page = query(&relay, "limit=1").await;
    assert_eq!(
        (page.0, page.2, page.3),
        (vec![b.to_string()], "2".into(), "false".into())
    );
    assert_eq!(relay.info().await["last_position"], "2");

    // A denied key: every block of that key, stored or new.
    let key2 = BlockId(key(2).verifying_key().to_bytes());
    relay.write_deny(&format!("key {key2}\n"));
    wait_status(&relay, &a, 200).await;
    let r = relay.get(&format!("/sbtp/v1/block/{b}")).await;
    assert_eq!((r.status, r.error()), (451, "Denied".into()));
    let (_, b2) = block_with(&key(2), &[], b"b2", now_ms(), TEST_POW);
    let r = relay.put(&b2).await;
    assert_eq!((r.status, r.error()), (451, "DeniedKey".into()));
    // `last_position` skips the denied last block; `since=2` stays a valid position.
    assert_eq!(relay.info().await["last_position"], "1");
    assert_eq!(query(&relay, "since=2").await.0.len(), 0);

    // A malformed file keeps the previous list; an empty one lifts it.
    relay.write_deny("nonsense\n");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(relay.get(&format!("/sbtp/v1/block/{b}")).await.status, 451);
    relay.write_deny("");
    wait_status(&relay, &b, 200).await;
    assert_eq!(relay.info().await["last_position"], "2");
    relay.stop().await;
}
