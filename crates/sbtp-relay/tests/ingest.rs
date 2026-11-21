//! ADR 0049 over real HTTP: the byte budget of a network group (`429` before the body, only that
//! group refused) and the global cap under disk pressure (`503` for a new block, `200` for a held
//! one, off below the low-water mark). Clients are told apart by `X-Forwarded-For` through the
//! default trusted loopback proxy. The bucket arithmetic itself is tested with an injected clock
//! in `src/ingest.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::io::Write;

use axum::Router;
use common::{Response, TestServer, now_ms, read_response, settings};
use sbtp_core::{BlockBuilder, SigningKey};

fn block(n: u32) -> Vec<u8> {
    let k = SigningKey::from_bytes(&[11; 32]);
    BlockBuilder::for_key(&k)
        .timestamp(now_ms())
        .payload(format!("ingest {n}").as_bytes())
        .build(&k, 0)
        .unwrap()
}

/// `PUT` of `body` from client address `from` through the loopback proxy.
fn put_from(relay: &TestServer, from: &str, body: &[u8]) -> Response {
    let mut c = relay.connect();
    c.write_all(
        format!(
            "PUT /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\nX-Forwarded-For: {from}\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    c.write_all(body).unwrap();
    read_response(&mut c).unwrap()
}

fn start(pairs: &[(&str, &str)]) -> TestServer {
    let mut all = vec![("MIN_POW_DIFFICULTY", "0")];
    all.extend_from_slice(pairs);
    TestServer::start(&settings(&all), Router::new())
}

/// Rules 2 to 4: with `R` = 1 MiB/h, a /24 has 262,144 bytes per hour and 21,845 bytes of
/// capacity: six small blocks (quota cost 4,224 bytes each) leave it above zero, the seventh is refused with
/// `429` and `Retry-After` before its body is read. Another /24 and an IPv6 network are served.
#[test]
fn only_the_flooding_network_gets_429() {
    let relay = start(&[("INGEST_BYTES_PER_HOUR", "1048576")]);
    let mut stored = 0;
    for n in 0..7 {
        let r = put_from(&relay, &format!("198.51.100.{}", n + 1), &block(n));
        if r.status == 201 {
            stored += 1;
        } else {
            assert_eq!(r.status, 429, "{n}");
            assert_eq!(r.json()["error"], "RateLimited");
            let s: u64 = r.header("retry-after").unwrap().parse().unwrap();
            assert!(s >= 1, "{s}");
        }
    }
    assert_eq!(stored, 6, "one /24 for 198.51.100.1 to .7");
    // Refused before the body: the head alone gets the answer.
    let mut c = relay.connect();
    c.write_all(
        b"PUT /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\nX-Forwarded-For: 198.51.100.99\r\n\
          Content-Length: 1000\r\n\r\n",
    )
    .unwrap();
    assert_eq!(read_response(&mut c).unwrap().status, 429);
    // Other networks.
    assert_eq!(put_from(&relay, "203.0.113.5", &block(100)).status, 201);
    assert_eq!(put_from(&relay, "2001:db8:5::1", &block(101)).status, 201);
}

/// Rule 6: above the low-water mark, a new block over the global cap gets `503` with
/// `Retry-After` of at most 300 s and nothing is stored; a block the relay holds still gets
/// `200`. Each `PUT` comes from another /24, so that no group budget is reached first.
#[test]
fn global_cap_above_low_water_refuses_new_blocks_only() {
    let relay = start(&[
        ("INGEST_BYTES_PER_HOUR", "1048576"),
        // The admission total of an almost empty 4 MiB store (tree charge and index reserve) is
        // above 10 %: the cap is checked from the first `PUT`.
        ("MAX_STORE_BYTES", "4194304"),
        ("DEMAND_LOW_WATER_PCT", "10"),
        ("DEMAND_HIGH_WATER_PCT", "99"),
    ]);
    // 1 MiB/h / 12 = 87,381 bytes: 21 small blocks fit, the 22nd is refused.
    let first = block(0);
    assert_eq!(put_from(&relay, "10.0.0.1", &first).status, 201);
    let mut refused = None;
    for n in 1..40 {
        let r = put_from(&relay, &format!("10.0.{n}.1"), &block(n));
        if r.status == 503 {
            refused = Some((n, r));
            break;
        }
        assert_eq!(r.status, 201, "{n}");
    }
    let (n, r) = refused.expect("the cap refused");
    assert_eq!(n, 21);
    assert_eq!(r.json()["error"], "Unavailable");
    let s: u64 = r.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=300).contains(&s), "{s}");
    // The refused block was not stored.
    let id = sbtp_core::parse(&block(n)).unwrap().block_id();
    assert_eq!(
        common::get(&mut relay.connect(), &format!("/sbtp/v1/block/{id}"), "").status,
        404
    );
    // A held block: `200`, whatever the bucket.
    assert_eq!(put_from(&relay, "10.0.200.1", &first).status, 200);
}

/// Rule 6, the self-blocking guarantee: below the low-water mark the global cap refuses nothing,
/// even with its bucket drained far below zero.
#[test]
fn global_cap_is_off_below_low_water() {
    let relay = start(&[("INGEST_BYTES_PER_HOUR", "1048576")]);
    for n in 0..40 {
        let r = put_from(&relay, &format!("10.1.{n}.1"), &block(1_000 + n));
        assert_eq!(r.status, 201, "{n}");
    }
}

/// Rule 1: an exempt address is never charged nor refused.
#[test]
fn exempt_addresses_are_not_bounded() {
    let relay = start(&[
        ("INGEST_BYTES_PER_HOUR", "1048576"),
        ("RATE_LIMIT_EXEMPT", "192.0.2.0/24"),
    ]);
    for n in 0..20 {
        assert_eq!(
            put_from(&relay, "192.0.2.10", &block(2_000 + n)).status,
            201
        );
    }
    // The other networks still have their own budget.
    assert_eq!(put_from(&relay, "198.51.100.1", &block(3_000)).status, 201);
}
