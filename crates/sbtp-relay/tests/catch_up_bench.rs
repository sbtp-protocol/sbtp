//! Catch-up throughput of one unfiltered `/subscribe` from `since=0` (SPEC §6).
//!
//! Ignored by default. Run in release:
//! `cargo test --release -p sbtp-relay --test catch_up_bench -- --ignored --nocapture`
//! (`SBTP_BENCH_BLOCKS` sets the block count, default 100,000).
//!
//! The store is seeded directly with redb, in the relay's table layout, in transactions of
//! 10,000 blocks: one fsynced `PUT` per block would make seeding take minutes and measures
//! nothing about catch-up. Blocks are realistic: signed, 256-byte payload, 1 or 2 parents.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::panic
)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    missing_docs
)]

mod common;

use std::time::Instant;

use common::{Relay, config, key, now_ms};
use futures_util::StreamExt;
use redb::{Database, TableDefinition};
use sbtp_core::{BlockId, UnsignedBlock};
use tempfile::TempDir;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const IDS: TableDefinition<[u8; 32], u64> = TableDefinition::new("ids");
const LOG: TableDefinition<u64, ([u8; 32], [u8; 32])> = TableDefinition::new("log");
const BLOCKS: TableDefinition<u64, &[u8]> = TableDefinition::new("blocks");
const CHILDREN: TableDefinition<([u8; 32], u64), ()> = TableDefinition::new("children");

fn seed(dir: &TempDir, count: u64) {
    let db = Database::create(dir.path().join("relay.redb")).unwrap();
    let signer = key(3);
    let mut ids: Vec<BlockId> = Vec::new();
    let mut position = 0u64;
    while position < count {
        let txn = db.begin_write().unwrap();
        {
            let (mut t_ids, mut log) = (txn.open_table(IDS).unwrap(), txn.open_table(LOG).unwrap());
            let mut children = txn.open_table(CHILDREN).unwrap();
            let mut blocks = txn.open_table(BLOCKS).unwrap();
            for _ in 0..10_000.min(count - position) {
                position += 1;
                let mut payload = [0u8; 256];
                payload[..8].copy_from_slice(&position.to_be_bytes());
                // One parent, or two for every third block, among the last thousand.
                let n = ids.len();
                let parents: Vec<BlockId> = match n {
                    0 => vec![BlockId([0; 32])],
                    _ if position.is_multiple_of(3) && n > 2 => vec![ids[n - 1], ids[n / 2]],
                    _ => vec![ids[n - 1 - (position as usize % n.min(1000))]],
                };
                let unsigned = UnsignedBlock {
                    timestamp: now_ms(),
                    nonce: 0,
                    pubkey: signer.verifying_key().to_bytes(),
                    parents: &parents,
                    payload: &payload,
                };
                let id = unsigned.block_id().unwrap();
                let bytes = unsigned.sign(&signer).unwrap();
                log.insert(position, (id.0, unsigned.pubkey)).unwrap();
                blocks.insert(position, bytes.as_slice()).unwrap();
                t_ids.insert(id.0, position).unwrap();
                for p in &parents {
                    children.insert((p.0, position), ()).unwrap();
                }
                ids.push(id);
            }
        }
        txn.commit().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: run in release with --ignored"]
async fn catch_up_throughput() {
    let count: u64 = std::env::var("SBTP_BENCH_BLOCKS").map_or(100_000, |v| v.parse().unwrap());
    let dir = TempDir::new().unwrap();
    let started = Instant::now();
    seed(&dir, count);
    let size = std::fs::metadata(dir.path().join("relay.redb"))
        .unwrap()
        .len();
    eprintln!(
        "seeded {count} blocks ({size} bytes) in {:?}",
        started.elapsed()
    );

    let relay = Relay::start(config(&dir)).await;
    let (mut ws, _) = connect_async(relay.ws_url("since=0")).await.unwrap();
    let started = Instant::now();
    let (mut received, mut bytes, mut last) = (0u64, 0usize, 0u64);
    while received < count {
        match ws.next().await.unwrap().unwrap() {
            Message::Binary(frame) => {
                let position = u64::from_be_bytes(frame[..8].try_into().unwrap());
                assert!(position > last);
                last = position;
                received += 1;
                bytes += frame.len();
            }
            Message::Close(c) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
    let elapsed = started.elapsed();
    eprintln!(
        "catch-up: {received} blocks, {bytes} bytes in {elapsed:?}: {:.0} blocks/s, {:.1} MB/s",
        received as f64 / elapsed.as_secs_f64(),
        bytes as f64 / elapsed.as_secs_f64() / 1e6
    );
    relay.stop().await;
}
