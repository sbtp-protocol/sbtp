//! ADR 0054, relay subscriptions over WebSocket, over real HTTP/1.1 and WebSocket: the route and
//! `/info` behind `ws_enabled` (rules 5 and 30), the upgrade checks (rules 1 and 2), admission
//! (rules 25 to 28), client messages and their errors (rules 7, 8 and 26), deliveries (rules 9
//! and 11 to 16), gaps (rules 18 and 19), ticks and timers (rules 31 to 33), the deny list (rule
//! 42) and shutdown (rule 23). Core spec §4, `GET /sbtp/v1/subscribe`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::type_complexity
)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use axum::Router;
use common::{Response, TestServer, exchange, get, put_block, settings};
use sbtp_core::{BlockBuilder, BlockId, SigningKey};
use sbtp_relay::subscribe::metrics as ws_metrics;
use serde_json::Value;
use tungstenite::protocol::{Role, WebSocket};
use tungstenite::{Message, protocol::frame::coding::CloseCode};

type Ws = WebSocket<TcpStream>;

/// The tests that watch the process-wide gap and close counters run one at a time.
static SLOW: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A relay at difficulty 0 with subscriptions on, and `extra` settings.
fn relay(extra: &[(&str, &str)]) -> TestServer {
    let mut pairs = vec![
        ("MIN_POW_DIFFICULTY", "0"),
        ("WS_ENABLED", "true"),
        ("RATE_PUT_PER_MIN", "1000000"),
        ("RATE_QUERY_BURST", "1000"),
        ("RATE_QUERY_PER_MIN", "1000000"),
    ];
    for e in extra {
        pairs.retain(|(k, _)| *k != e.0);
        pairs.push(*e);
    }
    TestServer::start(&settings(&pairs), Router::new())
}

const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// The head of an upgrade request with `lines` (each ending with `\r\n`).
fn upgrade_head(path: &str, lines: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: relay.test\r\n{lines}\r\n")
}

fn valid_lines() -> String {
    format!(
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: sbtp.subscribe.v1\r\n"
    )
}

/// Reads a response head byte by byte, so that no WebSocket byte after it is consumed.
fn read_head(s: &mut TcpStream) -> (u16, String) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).unwrap(), 1, "connection closed in the head");
        head.push(b[0]);
    }
    let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, head)
}

/// An open subscription connection (rules 1 and 2): `101` with the subprotocol selected.
fn open(r: &TestServer) -> Ws {
    try_open(r).unwrap_or_else(|(s, h)| panic!("{s} {h}"))
}

fn try_open(r: &TestServer) -> Result<Ws, (u16, String)> {
    let mut s = r.connect();
    s.write_all(upgrade_head("/sbtp/v1/subscribe", &valid_lines()).as_bytes())
        .unwrap();
    let (status, head) = read_head(&mut s);
    if status != 101 {
        return Err((status, head));
    }
    assert!(
        head.contains("sec-websocket-protocol: sbtp.subscribe.v1"),
        "{head}"
    );
    Ok(WebSocket::from_raw_socket(s, Role::Client, None))
}

/// The next message that is not a ping or a pong.
fn next(ws: &mut Ws) -> Message {
    loop {
        match ws.read().unwrap() {
            Message::Ping(_) | Message::Pong(_) => {}
            m => return m,
        }
    }
}

fn next_json(ws: &mut Ws) -> Value {
    match next(ws) {
        Message::Text(t) => serde_json::from_str(t.as_str()).unwrap(),
        m => panic!("{m:?}"),
    }
}

fn send(ws: &mut Ws, text: &str) {
    ws.send(Message::Text(text.into())).unwrap();
}

/// The close code the relay sent, reading until the close frame.
fn closed_with(ws: &mut Ws) -> u16 {
    loop {
        match ws.read() {
            Ok(Message::Close(Some(f))) => return u16::from(f.code),
            Ok(Message::Close(None)) => return 0,
            Ok(_) => {}
            Err(e) => panic!("no close frame: {e}"),
        }
    }
}

/// A delivery frame (rule 9), decoded: `sub`, flags, cursor, entries (`block_id`, mask).
fn delivery(b: &[u8]) -> (u32, u8, String, Vec<(BlockId, Option<u32>)>) {
    assert_eq!(b[0], 1);
    let sub = u32::from_be_bytes(b[1..5].try_into().unwrap());
    let flags = b[5];
    let c = usize::from(b[6]);
    let cursor = String::from_utf8(b[7..7 + c].to_vec()).unwrap();
    let n = u16::from_be_bytes(b[7 + c..9 + c].try_into().unwrap());
    let mut at = 9 + c;
    let mut out = Vec::new();
    for _ in 0..n {
        let id = BlockId(b[at..at + 32].try_into().unwrap());
        at += 32;
        let mask = (flags & 2 != 0).then(|| {
            let m = u32::from_be_bytes(b[at..at + 4].try_into().unwrap());
            at += 4;
            m
        });
        if flags & 1 != 0 {
            let p = usize::from(b[at]);
            at += 1 + 32 * p + 4;
        }
        out.push((id, mask));
    }
    assert_eq!(at, b.len(), "the frame ends after its last entry");
    (sub, flags, cursor, out)
}

fn next_delivery(ws: &mut Ws) -> (u32, u8, String, Vec<(BlockId, Option<u32>)>) {
    match next(ws) {
        Message::Binary(b) => delivery(&b),
        m => panic!("{m:?}"),
    }
}

/// A valid block of key `seed`, difficulty 0.
fn block(seed: u8, payload: &[u8], parents: &[BlockId]) -> (Vec<u8>, BlockId) {
    let k = SigningKey::from_bytes(&[seed; 32]);
    let bytes = BlockBuilder::for_key(&k)
        .timestamp(common::now_ms())
        .parents(parents)
        .payload(payload)
        .build(&k, 0)
        .unwrap();
    let id = sbtp_core::parse(&bytes).unwrap().block_id();
    (bytes, id)
}

fn hex(id: &BlockId) -> String {
    id.to_string()
}

fn subscribe_all(ws: &mut Ws, sub: u32) -> String {
    send(
        ws,
        &format!(r#"{{"op":"subscribe","sub":{sub},"all":true}}"#),
    );
    let m = next_json(ws);
    assert_eq!(
        (m["op"].as_str(), m["sub"].as_u64()),
        (Some("subscribed"), Some(u64::from(sub)))
    );
    m["start"].as_str().unwrap().to_owned()
}

/// Rules 5 and 30: `/info` publishes `subscribe` and the route exists only with `ws_enabled`.
#[test]
fn info_and_route_follow_ws_enabled() {
    let on = relay(&[
        ("WS_MAX_SUBSCRIPTIONS", "5"),
        ("WS_PING_INTERVAL_MS", "20000"),
    ]);
    let v = get(&mut on.connect(), "/sbtp/v1/info", "").json();
    assert_eq!(
        v["subscribe"],
        serde_json::json!({"versions": [1], "max_subscriptions": 5, "tick_ms": 20000})
    );
    assert_eq!(v["read_api"], 2);
    let off = TestServer::start(&settings(&[("MIN_POW_DIFFICULTY", "0")]), Router::new());
    let mut c = off.connect();
    assert!(
        get(&mut c, "/sbtp/v1/info", "")
            .json()
            .get("subscribe")
            .is_none()
    );
    let r = exchange(&mut c, &upgrade_head("/sbtp/v1/subscribe", &valid_lines()));
    assert_eq!(
        (r.status, r.json()["error"].as_str()),
        (404, Some("NotFound"))
    );
}

fn refused(r: &Response, status: u16, name: &str) {
    assert_eq!(r.status, status, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["error"], name);
    assert_eq!(r.header("cache-control"), Some("no-store"));
}

/// Rules 1 and 2: a query string, a missing subprotocol, an invalid upgrade get `400`; a version
/// other than 13 gets `400` with `Sec-WebSocket-Version: 13`; another method gets `405`.
#[test]
fn upgrade_head_checks() {
    let r = relay(&[]);
    let mut c = r.connect();
    let lines = valid_lines();
    let q = exchange(&mut c, &upgrade_head("/sbtp/v1/subscribe?from=x", &lines));
    refused(&q, 400, "InvalidParameter");
    let no_proto = lines.replace("Sec-WebSocket-Protocol: sbtp.subscribe.v1\r\n", "");
    refused(
        &exchange(&mut c, &upgrade_head("/sbtp/v1/subscribe", &no_proto)),
        400,
        "InvalidParameter",
    );
    let other = lines.replace("sbtp.subscribe.v1", "sbtp.subscribe.v2");
    refused(
        &exchange(&mut c, &upgrade_head("/sbtp/v1/subscribe", &other)),
        400,
        "InvalidParameter",
    );
    let v8 = lines.replace("Version: 13", "Version: 8");
    let r8 = exchange(&mut c, &upgrade_head("/sbtp/v1/subscribe", &v8));
    refused(&r8, 400, "InvalidParameter");
    assert_eq!(r8.header("sec-websocket-version"), Some("13"));
    let no_key = lines.replace(&format!("Sec-WebSocket-Key: {KEY}\r\n"), "");
    refused(
        &exchange(&mut c, &upgrade_head("/sbtp/v1/subscribe", &no_key)),
        400,
        "InvalidParameter",
    );
    refused(
        &get(&mut c, "/sbtp/v1/subscribe", ""),
        400,
        "InvalidParameter",
    );
    let post = exchange(
        &mut c,
        "POST /sbtp/v1/subscribe HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(post.status, 405);
    // Several offered subprotocols: the relay selects its own.
    let mut s = r.connect();
    let both = lines.replace("sbtp.subscribe.v1", "sbtp.subscribe.v9, sbtp.subscribe.v1");
    s.write_all(upgrade_head("/sbtp/v1/subscribe", &both).as_bytes())
        .unwrap();
    let (status, head) = read_head(&mut s);
    assert_eq!(status, 101);
    assert!(
        head.contains("sec-websocket-protocol: sbtp.subscribe.v1\r\n"),
        "{head}"
    );
}

/// Rules 12 to 16: `subscribed` with `start`, then every block stored after it, in store order,
/// with the mask of a parent subscription; nothing from before `start`, nothing for a `200`
/// re-`PUT`. Rule 9: the cursor after the last entry, walked with `/query`, lists nothing more.
#[test]
fn blocks_after_start_are_delivered() {
    let r = relay(&[]);
    let mut c = r.connect();
    let (root, root_id) = block(1, b"root", &[]);
    assert_eq!(put_block(&mut c, &root).status, 201);
    let (other, other_id) = block(1, b"other root", &[]);
    assert_eq!(put_block(&mut c, &other).status, 201);
    let mut ws = open(&r);
    send(
        &mut ws,
        &format!(
            r#"{{"op":"subscribe","sub":7,"parents":["{}","{}"]}}"#,
            hex(&other_id),
            hex(&root_id)
        ),
    );
    let m = next_json(&mut ws);
    assert_eq!(m["op"], "subscribed");
    let start = m["start"].as_str().unwrap().to_owned();
    let all_start = subscribe_all(&mut ws, 8);
    assert_eq!(start, all_start);
    // `start` is the `head` of `/query`: nothing before it is delivered.
    let q = get(&mut c, &format!("/sbtp/v1/query?cursor={start}"), "").json();
    assert_eq!(q["block_ids"], serde_json::json!([]));
    let (child, child_id) = block(2, b"child", &[root_id]);
    assert_eq!(put_block(&mut c, &child).status, 201);
    // A re-`PUT` (`200`) delivers nothing.
    assert_eq!(put_block(&mut c, &child).status, 200);
    let (unrelated, unrelated_id) = block(3, b"unrelated", &[]);
    assert_eq!(put_block(&mut c, &unrelated).status, 201);
    let mut got: Vec<(u32, Vec<(BlockId, Option<u32>)>, String)> = Vec::new();
    while got.iter().map(|g| g.1.len()).sum::<usize>() < 3 {
        let (sub, _, cursor, entries) = next_delivery(&mut ws);
        got.push((sub, entries, cursor));
    }
    let parent_entries: Vec<_> = got
        .iter()
        .filter(|g| g.0 == 7)
        .flat_map(|g| g.1.clone())
        .collect();
    assert_eq!(
        parent_entries,
        [(child_id, Some(0b10))],
        "mask bit of the second parent"
    );
    let all_entries: Vec<BlockId> = got
        .iter()
        .filter(|g| g.0 == 8)
        .flat_map(|g| g.1.iter().map(|e| e.0))
        .collect();
    assert_eq!(all_entries, [child_id, unrelated_id], "store order");
    let last_cursor = &got.iter().rfind(|g| g.0 == 8).unwrap().2;
    let q = get(&mut c, &format!("/sbtp/v1/query?cursor={last_cursor}"), "").json();
    assert_eq!(
        q["block_ids"],
        serde_json::json!([]),
        "nothing after the last cursor"
    );
    // Rule 17.
    send(&mut ws, r#"{"op":"unsubscribe","sub":7}"#);
    loop {
        match next(&mut ws) {
            Message::Text(t) => {
                let v: Value = serde_json::from_str(t.as_str()).unwrap();
                assert_eq!(
                    (v["op"].as_str(), v["sub"].as_u64()),
                    (Some("unsubscribed"), Some(7))
                );
                break;
            }
            Message::Binary(b) => assert_ne!(delivery(&b).0, 7),
            m => panic!("{m:?}"),
        }
    }
    let (late, late_id) = block(4, b"late", &[root_id]);
    assert_eq!(put_block(&mut c, &late).status, 201);
    let (sub, _, _, entries) = next_delivery(&mut ws);
    assert_eq!(
        (sub, entries),
        (8, vec![(late_id, None)]),
        "nothing more for sub 7"
    );
}

/// Rule 9: `fields` carries the Parents Hashes and the length.
#[test]
fn fields_carry_parents_and_length() {
    let r = relay(&[]);
    let mut c = r.connect();
    let mut ws = open(&r);
    send(
        &mut ws,
        r#"{"op":"subscribe","sub":1,"all":true,"fields":"parents"}"#,
    );
    assert_eq!(next_json(&mut ws)["op"], "subscribed");
    let (a, a_id) = block(5, b"a", &[]);
    let (b, b_id) = block(5, b"b", &[a_id]);
    for x in [&a, &b] {
        assert_eq!(put_block(&mut c, x).status, 201);
    }
    let mut frames = Vec::new();
    while frames.len() < 2 {
        let Message::Binary(f) = next(&mut ws) else {
            panic!()
        };
        let n = usize::from(u16::from_be_bytes([f[47], f[48]]));
        assert_eq!(f[5], 1);
        let mut at = 49;
        for _ in 0..n {
            let id = BlockId(f[at..at + 32].try_into().unwrap());
            let p = usize::from(f[at + 32]);
            let parents: Vec<BlockId> = (0..p)
                .map(|i| BlockId(f[at + 33 + 32 * i..at + 65 + 32 * i].try_into().unwrap()))
                .collect();
            let len_at = at + 33 + 32 * p;
            let len = u32::from_be_bytes(f[len_at..len_at + 4].try_into().unwrap());
            frames.push((id, parents, len));
            at = len_at + 4;
        }
    }
    assert_eq!(frames[0], (a_id, vec![], u32::try_from(a.len()).unwrap()));
    assert_eq!(
        frames[1],
        (b_id, vec![a_id], u32::try_from(b.len()).unwrap())
    );
}

/// Rules 7, 8 and 26: malformed or refused messages get `error` and the connection stays open;
/// `max_subscriptions`; no tokens gives `RateLimited` with `retry_after`, nothing registered.
#[test]
fn subscribe_errors_keep_the_connection() {
    let r = relay(&[("WS_MAX_SUBSCRIPTIONS", "2")]);
    let mut ws = open(&r);
    let id = "ab".repeat(32);
    let many: Vec<String> = (0..33)
        .map(|n| format!("\"{n:02x}{}\"", &id[2..]))
        .collect();
    for (msg, sub) in [
        (
            format!(
                r#"{{"op":"subscribe","sub":1,"parents":[{}]}}"#,
                many.join(",")
            ),
            Some(1),
        ),
        (
            format!(
                r#"{{"op":"subscribe","sub":1,"parents":["{}"]}}"#,
                id.to_uppercase()
            ),
            Some(1),
        ),
        (
            format!(r#"{{"op":"subscribe","sub":1,"parents":["{id}"],"all":true}}"#),
            Some(1),
        ),
        (
            r#"{"op":"subscribe","sub":1,"all":true,"from":"x"}"#.to_owned(),
            Some(1),
        ),
        (r#"{"op":"subscribe","sub":0,"all":true}"#.to_owned(), None),
        (r#"{"op":"unsubscribe","sub":9}"#.to_owned(), Some(9)),
        (r#"{"op":"publish","sub":1}"#.to_owned(), Some(1)),
    ] {
        send(&mut ws, &msg);
        let e = next_json(&mut ws);
        assert_eq!(
            (e["op"].as_str(), e["error"].as_str()),
            (Some("error"), Some("InvalidParameter")),
            "{msg}"
        );
        assert_eq!(e["sub"].as_u64(), sub, "{msg}");
        assert!(e["message"].as_str().unwrap().len() <= 200);
    }
    subscribe_all(&mut ws, 1);
    send(&mut ws, r#"{"op":"subscribe","sub":1,"all":true}"#);
    assert_eq!(
        next_json(&mut ws)["error"],
        "InvalidParameter",
        "duplicate sub"
    );
    subscribe_all(&mut ws, 2);
    send(&mut ws, r#"{"op":"subscribe","sub":3,"all":true}"#);
    assert_eq!(
        next_json(&mut ws)["error"],
        "InvalidParameter",
        "over max_subscriptions"
    );

    // Rule 26: `all` takes 4 tokens; a burst of 5 (one spent by the upgrade) leaves one `all`.
    let r = relay(&[("RATE_QUERY_BURST", "5"), ("RATE_QUERY_PER_MIN", "1")]);
    let mut ws = open(&r);
    subscribe_all(&mut ws, 1);
    send(&mut ws, r#"{"op":"subscribe","sub":2,"all":true}"#);
    let e = next_json(&mut ws);
    assert_eq!(
        (e["error"].as_str(), e["sub"].as_u64()),
        (Some("RateLimited"), Some(2))
    );
    assert!(e["retry_after"].as_u64().unwrap() >= 1);
    send(&mut ws, r#"{"op":"unsubscribe","sub":2}"#);
    assert_eq!(
        next_json(&mut ws)["error"],
        "InvalidParameter",
        "nothing registered"
    );
}

/// Rules 6 and 7: a binary frame closes with 1003, a text frame that is not a JSON object with
/// 1007, a message over 4,096 bytes with 1009.
#[test]
fn protocol_violations_close_the_connection() {
    let r = relay(&[]);
    let mut ws = open(&r);
    ws.send(Message::Binary(vec![1, 2, 3].into())).unwrap();
    assert_eq!(closed_with(&mut ws), 1003);
    let mut ws = open(&r);
    send(&mut ws, "[1,2]");
    assert_eq!(closed_with(&mut ws), 1007);
    let mut ws = open(&r);
    send(
        &mut ws,
        &format!(
            r#"{{"op":"subscribe","sub":1,"all":true,"x":"{}"}}"#,
            "y".repeat(4_100)
        ),
    );
    assert_eq!(closed_with(&mut ws), 1009);
    assert!(ws_metrics::closed_total("1009") >= 1);
}

/// Rules 25 to 28: the per-client bound gives `429` with `Retry-After` of at least 30 s, the
/// group share likewise, the total `503`; a closed connection gives its slot back.
#[test]
fn subscription_connection_limits() {
    let r = relay(&[
        ("WS_MAX_CONNECTIONS_PER_CLIENT", "2"),
        ("WS_MAX_CONNECTIONS", "8"),
    ]);
    let first = open(&r);
    let second = open(&r);
    let (status, head) = try_open(&r).err().unwrap();
    assert_eq!(status, 429, "{head}");
    let retry: u64 = head
        .split("retry-after: ")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry >= 30);
    drop(first);
    drop(second);
    let t = Instant::now();
    while try_open(&r).is_err() {
        assert!(t.elapsed() < Duration::from_secs(5), "slots not given back");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Rule 28: ⌈4 × 25 / 100⌉ = 1 connection for the /24 of 127.0.0.1.
    let r = relay(&[
        ("WS_MAX_CONNECTIONS", "4"),
        ("WS_MAX_CONNECTIONS_PER_CLIENT", "4"),
    ]);
    let _one = open(&r);
    assert_eq!(try_open(&r).err().unwrap().0, 429);
    // The total: an exempt client skips the per-client and group bounds, not the total.
    let r = relay(&[
        ("WS_MAX_CONNECTIONS", "1"),
        ("WS_MAX_CONNECTIONS_PER_CLIENT", "1"),
        ("RATE_LIMIT_EXEMPT", "127.0.0.0/8"),
    ]);
    let _one = open(&r);
    let (status, head) = try_open(&r).err().unwrap();
    assert_eq!(status, 503, "{head}");
    assert!(head.contains("retry-after: "));
}

/// Rule 27: an upgraded connection no longer counts in `max_connections_per_client`; ordinary
/// requests from the same client still get through.
#[test]
fn an_upgraded_connection_leaves_the_per_client_bound() {
    let r = relay(&[
        ("MAX_CONNECTIONS_PER_CLIENT", "1"),
        ("TRUSTED_PROXIES", "192.0.2.1/32"),
    ]);
    let _ws = open(&r);
    let mut c = r.connect();
    assert_eq!(get(&mut c, "/sbtp/v1/info", "").status, 200);
}

/// Rules 18 and 19, 20 and 29: a consumer that stops reading gets one `gap` instead of the
/// deliveries that do not fit, and the relay's queue never grows; the `gap` cursor, walked with
/// `/query`, lists every block it was not given. Slow clients are not kept for ever: see
/// `a_slow_reader_under_steady_traffic_gets_1008`.
#[test]
fn a_slow_consumer_gets_a_gap() {
    let _one = SLOW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = relay(&[
        ("WS_PING_INTERVAL_MS", "5000"),
        ("WS_MAX_SUBSCRIPTIONS", "32"),
    ]);
    let mut c = r.connect();
    let parents: Vec<BlockId> = (0..8u8).map(|n| BlockId([n + 1; 32])).collect();
    let mut ws = open(&r);
    let list = parents
        .iter()
        .map(|p| format!("\"{}\"", hex(p)))
        .collect::<Vec<_>>()
        .join(",");
    // 32 subscriptions of the same parents: every block makes 32 frames, so that a few hundred
    // blocks fill the socket buffers and the queue.
    for sub in 1..=32 {
        send(
            &mut ws,
            &format!(r#"{{"op":"subscribe","sub":{sub},"parents":[{list}],"fields":"parents"}}"#),
        );
        assert_eq!(next_json(&mut ws)["op"], "subscribed");
    }
    let gaps = ws_metrics::gaps_total(ws_metrics::GapCause::Queue);
    // About 360 bytes per one-entry frame, 32 frames per block.
    let mut ids = Vec::new();
    let t = Instant::now();
    let mut n = 0u32;
    while ws_metrics::gaps_total(ws_metrics::GapCause::Queue) == gaps {
        assert!(
            t.elapsed() < Duration::from_secs(8),
            "no gap after {n} blocks"
        );
        let (b, id) = block(6, &n.to_be_bytes(), &parents);
        assert_eq!(put_block(&mut c, &b).status, 201);
        ids.push(id);
        n += 1;
    }
    for i in 0..20u32 {
        let (b, id) = block(6, &(1_000_000 + i).to_be_bytes(), &parents);
        assert_eq!(put_block(&mut c, &b).status, 201);
        ids.push(id);
    }
    // Read again: deliveries, then the gap, then live deliveries.
    let mut delivered = Vec::new();
    let gap_cursor = loop {
        match next(&mut ws) {
            Message::Binary(b) => {
                let (sub, _, _, entries) = delivery(&b);
                if sub == 1 {
                    delivered.extend(entries.into_iter().map(|e| e.0));
                }
            }
            Message::Text(t) => {
                let v: Value = serde_json::from_str(t.as_str()).unwrap();
                assert_eq!(v["op"], "gap", "{v}");
                if v["sub"] == 1 {
                    break v["cursor"].as_str().unwrap().to_owned();
                }
            }
            m => panic!("{m:?}"),
        }
    };
    // Rule 19: the walk from the gap's cursor lists the rest.
    let mut cursor = gap_cursor;
    loop {
        let q = get(
            &mut c,
            &format!(
                "/sbtp/v1/query?parent={}&cursor={cursor}&limit=1000",
                hex(&parents[0])
            ),
            "",
        )
        .json();
        for id in q["block_ids"].as_array().unwrap() {
            let id = sbtp_relay::store::parse_hex_id(id.as_str().unwrap()).unwrap();
            if !delivered.contains(&id) {
                delivered.push(id);
            }
        }
        cursor = q["cursor"].as_str().unwrap().to_owned();
        if q["more"] == false {
            break;
        }
    }
    for id in &ids {
        assert!(delivered.contains(id), "missing {id}");
    }
}

/// Rule 20, security review 2026-11-22 M-1: a client that keeps reading, but more slowly than
/// steady traffic fills its queue, is closed with 1008 about 2 × `tick_ms` after the first
/// overflow, although its queue never empties and every single send completes.
#[test]
fn a_slow_reader_under_steady_traffic_gets_1008() {
    let _one = SLOW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = relay(&[
        ("WS_PING_INTERVAL_MS", "5000"),
        ("WS_MAX_SUBSCRIPTIONS", "32"),
        ("RATE_PUT_BURST", "1000000"),
        ("INGEST_BYTES_PER_HOUR", "0"),
        ("PUT_MAX_IN_FLIGHT", "8"),
        ("PUT_MAX_IN_FLIGHT_PER_CLIENT", "8"),
    ]);
    let parents: Vec<BlockId> = (0..8u8).map(|n| BlockId([n + 101; 32])).collect();
    let mut ws = open(&r);
    let list = parents
        .iter()
        .map(|p| format!("\"{}\"", hex(p)))
        .collect::<Vec<_>>()
        .join(",");
    for sub in 1..=32 {
        send(
            &mut ws,
            &format!(r#"{{"op":"subscribe","sub":{sub},"parents":[{list}],"fields":"parents"}}"#),
        );
        assert_eq!(next_json(&mut ws)["op"], "subscribed");
    }
    let closed = ws_metrics::closed_total("1008");
    // Steady traffic from four writers until told to stop, about 11 KB of frames per block, so
    // that the socket buffers fill even when the index commits slowly.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writers: Vec<_> = (0..4u32)
        .map(|w| {
            let (addr, stop, parents) = (r.addr, std::sync::Arc::clone(&stop), parents.clone());
            std::thread::spawn(move || {
                let mut n = 0u32;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    // A refused or failed `PUT` (a slow disk under the whole test suite) is
                    // not this test's concern: the writer goes on, on a new connection.
                    let mut c = common::connect(addr);
                    for _ in 0..50 {
                        let (b, _) =
                            block(9, &[w.to_be_bytes(), n.to_be_bytes()].concat(), &parents);
                        n += 1;
                        let head = format!(
                            "PUT /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\n\
                             Content-Type: application/octet-stream\r\n\
                             Content-Length: {}\r\n\r\n",
                            b.len()
                        );
                        let sent = c
                            .write_all(head.as_bytes())
                            .and_then(|()| c.write_all(&b))
                            .and_then(|()| common::read_response(&mut c));
                        if !sent.is_ok_and(|r| r.status == 201) {
                            break;
                        }
                    }
                }
            })
        })
        .collect();
    // A slow reader: one message every 50 ms, about 7 KB/s, so that the queue would take about
    // 9 s to drain even if the writer paused.
    let t = Instant::now();
    while ws_metrics::closed_total("1008") == closed {
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "a slow reader was never closed"
        );
        match ws.read() {
            Ok(Message::Close(f)) => {
                panic!("closed with {f:?} before 1008 was counted");
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("connection lost before 1008 was counted: {e}"),
        }
    }
    // 2 × `tick_ms` after the first overflow, not much later.
    assert!(t.elapsed() >= Duration::from_secs(9), "{:?}", t.elapsed());
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for w in writers {
        w.join().unwrap();
    }
    // Read what is left: the close frame, unless the relay gave up sending it to a client that
    // was still reading slowly (it then drops the connection).
    loop {
        match ws.read() {
            Ok(Message::Close(f)) => {
                assert_eq!(f.map(|f| u16::from(f.code)), Some(1008));
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

/// Rule 42: a block of a denied key is never delivered.
#[test]
fn a_denied_block_is_never_delivered() {
    let dir = common::tmp_dir("ws-deny");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("deny.txt");
    let (denied, _) = block(7, b"denied", &[]);
    let key = hex(&BlockId(*sbtp_core::parse(&denied).unwrap().pubkey()));
    std::fs::write(&file, format!("key {key}\n")).unwrap();
    let r = relay(&[("DENY_FILE", file.to_str().unwrap())]);
    let mut c = r.connect();
    let mut ws = open(&r);
    subscribe_all(&mut ws, 1);
    assert_eq!(put_block(&mut c, &denied).status, 451);
    let (kept, kept_id) = block(8, b"kept", &[]);
    assert_eq!(put_block(&mut c, &kept).status, 201);
    let (_, _, _, entries) = next_delivery(&mut ws);
    assert_eq!(entries, [(kept_id, None)]);
}

/// Rule 31: a `tick` with the cursor of the last evaluated position when nothing else was sent,
/// and pings. Rule 33: no subscription for `idle_timeout_ms` closes with 1000.
#[test]
fn ticks_and_idle_close() {
    let r = relay(&[("WS_PING_INTERVAL_MS", "5000"), ("IDLE_TIMEOUT_MS", "8000")]);
    let mut ws = open(&r);
    let start = subscribe_all(&mut ws, 1);
    let mut pinged = false;
    let tick = loop {
        match ws.read().unwrap() {
            Message::Ping(_) => pinged = true,
            Message::Text(t) => break serde_json::from_str::<Value>(t.as_str()).unwrap(),
            m => panic!("{m:?}"),
        }
    };
    assert!(pinged);
    assert_eq!(tick, serde_json::json!({"op": "tick", "cursor": start}));
    let r = relay(&[("IDLE_TIMEOUT_MS", "1000")]);
    let mut ws = open(&r);
    let t = Instant::now();
    assert_eq!(closed_with(&mut ws), 1000);
    assert!(t.elapsed() >= Duration::from_millis(900));
}

/// Rule 23: a relay that stops closes each subscription connection with 1001.
#[test]
fn shutdown_closes_with_1001() {
    let r = relay(&[]);
    let mut ws = open(&r);
    subscribe_all(&mut ws, 1);
    let stopper = std::thread::spawn(move || drop(r));
    assert_eq!(closed_with(&mut ws), u16::from(CloseCode::Away));
    stopper.join().unwrap();
}

/// Rule 32: a client that answers nothing within `ws_ping_interval_ms` after a ping (it does not
/// read, so its codec sends no pong) is closed with 1001.
#[test]
fn a_silent_client_is_closed_after_a_ping() {
    let r = relay(&[("WS_PING_INTERVAL_MS", "5000")]);
    let mut ws = open(&r);
    subscribe_all(&mut ws, 1);
    std::thread::sleep(Duration::from_millis(10_500));
    assert_eq!(closed_with(&mut ws), 1001);
}
