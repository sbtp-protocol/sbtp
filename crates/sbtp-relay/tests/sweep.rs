//! Eviction by age over real HTTP, with a controllable relay clock (ADR 0013 rules 12 to 15, ADR
//! 0043 rules 2 to 4): `/query` and `PUT` judge expiry at the same bound; a `PUT` of an expired
//! block is new again (`201`, listed again) whether or not the sweeper has run; the sweeper then
//! keeps it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};

use common::{TestServer, get as http_get, put_block as put, settings};
use sbtp_core::{BlockBuilder, SigningKey};

const TTL: u64 = 60_000;
const T0: u64 = 1_900_000_000_000;

fn block(payload: &[u8]) -> (Vec<u8>, String) {
    let k = SigningKey::from_bytes(&[8; 32]);
    let bytes = BlockBuilder::for_key(&k)
        .timestamp(T0)
        .payload(payload)
        .build(&k, 0)
        .unwrap();
    let id = sbtp_core::parse(&bytes).unwrap().block_id().to_string();
    (bytes, id)
}

fn listed(c: &mut TcpStream) -> Vec<String> {
    let r = http_get(c, "/sbtp/v1/query", "");
    assert_eq!(r.status, 200);
    r.json()["block_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

fn relay(clock: fn() -> u64) -> TestServer {
    TestServer::start_clocked(
        &settings(&[
            ("MIN_POW_DIFFICULTY", "0"),
            ("BLOCK_TTL_MS", &TTL.to_string()),
        ]),
        clock,
    )
}

/// ADR 0043: before expiry a `PUT` is `200` and the block is listed once; from the expiry
/// millisecond it is not listed, and a `PUT` is `201` with `Location` and lists it again, before
/// any sweep; a sweep afterwards keeps it.
#[test]
fn put_after_expiry_is_new_and_listed_again() {
    static NOW: AtomicU64 = AtomicU64::new(T0);
    fn now() -> u64 {
        NOW.load(Ordering::SeqCst)
    }
    let relay = relay(now);
    let mut c = relay.connect();
    let (b, id) = block(b"long-lived");
    assert_eq!(put(&mut c, &b).status, 201);
    NOW.store(T0 + TTL - 1, Ordering::SeqCst);
    assert_eq!(put(&mut c, &b).status, 200, "no renewal before expiry");
    assert_eq!(listed(&mut c), vec![id.clone()], "listed once");

    NOW.store(T0 + TTL, Ordering::SeqCst);
    assert!(listed(&mut c).is_empty(), "expired: not listed");
    let r = put(&mut c, &b);
    assert_eq!(r.status, 201, "an expired block is not held");
    assert_eq!(
        r.header("location"),
        Some(format!("/sbtp/v1/block/{id}").as_str())
    );
    assert_eq!(listed(&mut c), vec![id.clone()], "listed again");
    assert_eq!(put(&mut c, &b).status, 200, "held again");

    assert_eq!(relay.sweep(), Some(0));
    assert_eq!(listed(&mut c), vec![id.clone()]);
    assert_eq!(
        http_get(&mut c, &format!("/sbtp/v1/block/{id}"), "").status,
        200
    );
    // One TTL after the re-acceptance, the sweeper deletes it.
    NOW.store(T0 + 2 * TTL, Ordering::SeqCst);
    assert_eq!(relay.sweep(), Some(1));
    assert_eq!(
        http_get(&mut c, &format!("/sbtp/v1/block/{id}"), "").status,
        404
    );
}

/// After the sweeper deleted an expired block, a `PUT` stores it again (`201`, a new file).
#[test]
fn put_after_the_sweep_stores_a_new_file() {
    static NOW: AtomicU64 = AtomicU64::new(T0);
    fn now() -> u64 {
        NOW.load(Ordering::SeqCst)
    }
    let relay = relay(now);
    let mut c = relay.connect();
    let (b, id) = block(b"swept");
    assert_eq!(put(&mut c, &b).status, 201);
    NOW.store(T0 + TTL, Ordering::SeqCst);
    assert_eq!(relay.sweep(), Some(1));
    let path = format!("/sbtp/v1/block/{id}");
    assert_eq!(http_get(&mut c, &path, "").status, 404);
    assert_eq!(put(&mut c, &b).status, 201);
    assert_eq!(http_get(&mut c, &path, "").status, 200);
    assert_eq!(listed(&mut c), vec![id]);
}
