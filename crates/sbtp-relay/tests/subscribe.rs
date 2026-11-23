//! End-to-end tests of `GET /sbtp/v1/subscribe` (SPEC §6) over loopback.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    missing_docs
)]

mod common;

use std::time::Duration;

use common::{Relay, block, config};
use futures_util::{SinkExt, StreamExt};
use sbtp_core::BlockId;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn connect(relay: &Relay, query: &str) -> Ws {
    connect_async(relay.ws_url(query)).await.unwrap().0
}

/// The HTTP status of a refused upgrade.
async fn refused(relay: &Relay, query: &str) -> u16 {
    match connect_async(relay.ws_url(query)).await {
        Err(tungstenite::Error::Http(r)) => r.status().as_u16(),
        other => panic!("upgrade not refused: {:?}", other.map(|_| ())),
    }
}

/// The next block frame as `(position, block_id)`, or the close code.
async fn next(ws: &mut Ws) -> Result<(u64, BlockId), u16> {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .unwrap();
        match message {
            Some(Ok(Message::Binary(frame))) => {
                let position = u64::from_be_bytes(frame[..8].try_into().unwrap());
                let block = sbtp_core::validate_submitted(&frame[8..], 0).unwrap();
                return Ok((position, *block.block_id()));
            }
            Some(Ok(Message::Close(frame))) => return Err(frame.map_or(0, |f| f.code.into())),
            Some(Ok(_)) => {}
            other => {
                eprintln!("unexpected {other:?}");
                return Err(1);
            }
        }
    }
}

#[tokio::test]
async fn catch_up_then_live_with_parent_filter() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let (root, root_bytes) = block(&[], b"root");
    let (a, a_bytes) = block(&[root], b"a");
    let (b, b_bytes) = block(&[], b"b");
    for bytes in [&root_bytes, &a_bytes, &b_bytes] {
        relay.put(bytes).await;
    }
    let mut all = connect(&relay, "since=0").await;
    let mut kids = connect(&relay, &format!("since=0&parent={root}")).await;
    let mut after = connect(&relay, "since=2").await;
    assert_eq!(next(&mut all).await, Ok((1, root)));
    assert_eq!(next(&mut all).await, Ok((2, a)));
    assert_eq!(next(&mut all).await, Ok((3, b)));
    assert_eq!(next(&mut kids).await, Ok((2, a)));
    assert_eq!(next(&mut after).await, Ok((3, b)));

    // Live: new blocks arrive in position order, filtered.
    let (c, c_bytes) = block(&[], b"c");
    let (d, d_bytes) = block(&[root], b"d");
    relay.put(&c_bytes).await;
    relay.put(&d_bytes).await;
    assert_eq!(next(&mut all).await, Ok((4, c)));
    assert_eq!(next(&mut all).await, Ok((5, d)));
    assert_eq!(next(&mut kids).await, Ok((5, d)));
    assert_eq!(next(&mut after).await, Ok((4, c)));

    // A denied block is never sent, live or in catch-up.
    let (e, e_bytes) = block(&[], b"e");
    relay.write_deny(&format!("block {e}\n"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(relay.put(&e_bytes).await.status, 451);
    relay.write_deny(&format!("block {c}\n"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut late = connect(&relay, "since=3").await;
    assert_eq!(next(&mut late).await, Ok((5, d)));

    // spec §6: the relay closes with `1001` when it stops.
    drop(late);
    relay.stop().await;
    assert_eq!(next(&mut all).await, Err(1001));
}

#[tokio::test]
async fn denied_key_is_skipped_in_catch_up_and_live() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let other = |payload: &[u8]| {
        common::block_with(
            &common::key(2),
            &[],
            payload,
            common::now_ms(),
            common::TEST_POW,
        )
    };
    let (a, a_bytes) = block(&[], b"a");
    let (b, b_bytes) = other(b"b");
    let (c, c_bytes) = block(&[], b"c");
    for bytes in [&a_bytes, &b_bytes, &c_bytes] {
        assert_eq!(relay.put(bytes).await.status, 201);
    }
    let key2 = BlockId(common::key(2).verifying_key().to_bytes());
    relay.write_deny(&format!("key {key2}\n"));
    for _ in 0..200 {
        if relay.get(&format!("/sbtp/v1/block/{b}")).await.status == 451 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut ws = connect(&relay, "since=0").await;
    assert_eq!(next(&mut ws).await, Ok((1, a)));
    assert_eq!(next(&mut ws).await, Ok((3, c)));
    // Live: the denied key's new block is refused and never sent; the next one arrives.
    let (_, d_bytes) = other(b"d");
    assert_eq!(relay.put(&d_bytes).await.status, 451);
    let (e, e_bytes) = block(&[], b"e");
    assert_eq!(relay.put(&e_bytes).await.status, 201);
    assert_eq!(next(&mut ws).await, Ok((4, e)));
    drop(ws);
    relay.stop().await;
}

#[tokio::test]
async fn refusals_before_the_upgrade() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.max_subscriptions = 5;
    let relay = Relay::start(c).await;
    assert_eq!(refused(&relay, "").await, 400);
    assert_eq!(refused(&relay, "since=x").await, 400);
    assert_eq!(refused(&relay, "since=0&limit=3").await, 400);
    assert_eq!(refused(&relay, "since=1").await, 400);
    let r = relay.get("/sbtp/v1/subscribe?since=0").await;
    assert_eq!((r.status, r.error()), (400, "InvalidParameter".into()));
    let r = relay.get("/sbtp/v1/subscribe?since=1").await;
    assert_eq!(r.status, 400);

    // spec §6: `max_subscriptions_per_ip` (4), then the global cap.
    let mut open = Vec::new();
    for _ in 0..4 {
        open.push(connect(&relay, "since=0").await);
    }
    assert_eq!(refused(&relay, "since=0").await, 429);
    drop(open.pop());
    tokio::time::sleep(Duration::from_millis(100)).await;
    open.push(connect(&relay, "since=0").await);
    relay.stop().await;
}

#[tokio::test]
async fn global_cap_is_503() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.max_subscriptions = 1;
    let relay = Relay::start(c).await;
    let _one = connect(&relay, "since=0").await;
    assert_eq!(refused(&relay, "since=0").await, 503);
    relay.stop().await;
}

#[tokio::test]
async fn client_data_frame_closes_with_1003() {
    let dir = TempDir::new().unwrap();
    let relay = Relay::start(config(&dir)).await;
    let mut ws = connect(&relay, "since=0").await;
    ws.send(Message::text("hello")).await.unwrap();
    assert_eq!(next(&mut ws).await, Err(1003));
    relay.stop().await;
}

#[tokio::test]
async fn idle_client_and_max_age_close_with_1000() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.idle_timeout = Duration::from_millis(300);
    let relay = Relay::start(c.clone()).await;
    // Not reading means not answering pings.
    let mut ws = connect(&relay, "since=0").await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(next(&mut ws).await, Err(1000));
    relay.stop().await;

    let dir = TempDir::new().unwrap();
    c.data_dir = dir.path().to_path_buf();
    c.idle_timeout = Duration::from_secs(30);
    c.max_age = Duration::from_millis(300);
    let relay = Relay::start(c).await;
    let mut ws = connect(&relay, "since=0").await;
    assert_eq!(next(&mut ws).await, Err(1000));
    relay.stop().await;
}

/// 60 blocks of 60 KB, about 3.6 MB: more than loopback socket buffers hold. Mined in advance
/// at difficulty 0, so that publishing them is fast.
fn big_blocks() -> Vec<Vec<u8>> {
    (0..60u8)
        .map(|n| {
            let mut payload = vec![7u8; 60_000];
            payload[0] = n;
            common::block_with(&common::key(1), &[], &payload, common::now_ms(), 0).1
        })
        .collect()
}

#[tokio::test]
async fn slow_live_consumer_is_closed_with_4000() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.live_queue = 2;
    c.min_pow_difficulty = 0;
    let relay = Relay::start(c).await;
    let blocks = big_blocks();
    let mut ws = connect(&relay, "since=0").await;
    // Let the subscription reach the live phase, then publish far more than the socket buffers
    // hold while the client does not read.
    tokio::time::sleep(Duration::from_millis(200)).await;
    for bytes in blocks {
        assert_eq!(relay.put(&bytes).await.status, 201);
    }
    let mut received = 0;
    let code = loop {
        match next(&mut ws).await {
            Ok(_) => received += 1,
            Err(code) => break code,
        }
    };
    eprintln!("received {received}, code {code}");
    assert_eq!(code, 4000);
    assert!(received < 60, "{received}");
    relay.stop().await;
}

#[tokio::test]
async fn catch_up_is_never_closed_for_slowness() {
    let dir = TempDir::new().unwrap();
    let mut c = config(&dir);
    c.live_queue = 2;
    c.min_pow_difficulty = 0;
    let relay = Relay::start(c).await;
    for bytes in big_blocks() {
        relay.put(&bytes).await;
    }
    let mut ws = connect(&relay, "since=0").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    for position in 1..=60 {
        assert_eq!(next(&mut ws).await.unwrap().0, position);
    }
    relay.stop().await;
}
