//! ADR 0051 over real HTTP: the batch read `POST /sbtp/v1/blocks` (framing, missing blocks,
//! the 1 MiB prefix, malformed bodies, weight at admission, `Sbtp-Replication`, CORS) and the
//! `/query` additions (`fields=parents`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::many_single_char_names
)]

mod common;

use std::io::Write;
use std::net::TcpStream;

use axum::Router;
use common::{Response, TestServer, get, put_block, read_response, settings, signed_block};
use sbtp_core::BlockId;

fn start(pairs: &[(&str, &str)]) -> TestServer {
    let mut all = vec![("MIN_POW_DIFFICULTY", "0")];
    all.extend_from_slice(pairs);
    TestServer::start(&settings(&all), Router::new())
}

/// Stores a block with `payload` and `parents`; its bytes and identifier.
fn store(c: &mut TcpStream, payload: &[u8], parents: &[BlockId]) -> (Vec<u8>, BlockId) {
    let bytes = signed_block(payload, parents);
    let id = sbtp_core::parse(&bytes).unwrap().block_id();
    let r = put_block(c, &bytes);
    assert!(r.status == 201 || r.status == 200, "{}", r.status);
    (bytes, id)
}

fn body_of(ids: &[BlockId]) -> Vec<u8> {
    ids.iter().flat_map(|id| id.0).collect()
}

/// `POST /sbtp/v1/blocks` with `body` and extra header lines.
fn batch(c: &mut TcpStream, body: &[u8], extra: &str) -> Response {
    c.write_all(
        format!(
            "POST /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\n{extra}\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    c.write_all(body).unwrap();
    read_response(c).unwrap()
}

/// The records of a batch body (rule 2); panics on a body that ends inside a record.
fn records(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let len = u32::from_be_bytes(body[at..at + 4].try_into().unwrap()) as usize;
        assert!(len <= 65_909, "rule 2");
        at += 4;
        out.push(body[at..at + len].to_vec());
        at += len;
    }
    assert_eq!(at, body.len(), "the body ends after a complete record");
    out
}

fn unknown(n: u8) -> BlockId {
    BlockId([n; 32])
}

/// Rules 1, 2 and 5: one record per identifier, in request order, the exact stored bytes, and
/// `length = 0` for a block the relay does not hold; `200`, `application/octet-stream`,
/// `no-store`; no `CDN-Cache-Control` outside replication.
#[test]
fn records_follow_the_request_order() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let (a, ida) = store(&mut c, b"batch a", &[]);
    let (b, idb) = store(&mut c, b"batch b", &[ida]);
    let ids = [idb, unknown(1), ida, unknown(2)];
    let r = batch(&mut c, &body_of(&ids), "");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/octet-stream"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("cdn-cache-control"), None);
    assert_eq!(records(&r.body), vec![b, Vec::new(), a, Vec::new()]);
    // Only unknown identifiers: still `200`, every record empty.
    let r = batch(&mut c, &body_of(&[unknown(3)]), "");
    assert_eq!((r.status, r.body.as_slice()), (200, &[0u8, 0, 0, 0][..]));
    // Rule 10: `If-None-Match` is ignored.
    let r = batch(
        &mut c,
        &body_of(&[ida]),
        &format!("If-None-Match: \"{ida}\"\r\n"),
    );
    assert_eq!(r.status, 200);
    // The connection stays usable.
    assert_eq!(get(&mut c, "/sbtp/v1/info", "").status, 200);
}

/// Rule 1: an empty body, a length that is not a multiple of 32 and a duplicate get `400`
/// `InvalidParameter`; more than 256 identifiers get `413` before the body is read; a request
/// without `Content-Length`, or chunked, gets `400` and its connection is closed.
#[test]
fn malformed_bodies_are_refused() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let (_, id) = store(&mut c, b"dup", &[]);
    for body in [
        Vec::new(),
        vec![7u8; 33],
        vec![7u8; 31],
        body_of(&[id, unknown(9), id]),
    ] {
        let r = batch(&mut c, &body, "");
        assert_eq!(r.status, 400, "{}", body.len());
        assert_eq!(r.json()["error"], "InvalidParameter");
    }
    // 257 identifiers: `413` on the head alone.
    let mut c = relay.connect();
    c.write_all(
        b"POST /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 8224\r\n\r\n",
    )
    .unwrap();
    let r = read_response(&mut c).unwrap();
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (413, "BodyTooLarge".into())
    );
    assert!(common::is_closed(&mut c));
    // Exactly 256: accepted.
    let ids: Vec<BlockId> = (0..=255u8).map(|n| BlockId([n; 32])).collect();
    let mut c = relay.connect();
    let r = batch(&mut c, &body_of(&ids), "");
    assert_eq!(r.status, 200);
    assert_eq!(records(&r.body).len(), 256);
    // No `Content-Length`.
    let mut c = relay.connect();
    c.write_all(b"POST /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\n\r\n")
        .unwrap();
    let r = read_response(&mut c).unwrap();
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (400, "InvalidParameter".into())
    );
    assert_eq!(r.header("connection"), Some("close"));
    // Chunked, with a valid identifier inside: refused before the body is read.
    let mut c = relay.connect();
    c.write_all(
        b"POST /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n",
    )
    .unwrap();
    c.write_all(&id.0).unwrap();
    c.write_all(b"\r\n0\r\n\r\n").unwrap();
    let r = read_response(&mut c).unwrap();
    assert_eq!(r.status, 400);
    assert_eq!(r.header("connection"), Some("close"));
}

/// Rules 3 and 4: the relay never starts a record that would bring the body above 1,048,576
/// bytes; the body is then a prefix of the full answer, with at least one record, and the client
/// asks again for the rest.
#[test]
fn a_full_body_stops_at_one_mebibyte() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let blocks: Vec<(Vec<u8>, BlockId)> = (0..17u8)
        .map(|n| {
            let mut payload = vec![n; 65_535];
            payload[0] = n;
            store(&mut c, &payload, &[])
        })
        .collect();
    let len = blocks[0].0.len();
    let fit = 1_048_576 / (4 + len);
    assert!(fit < 17, "the request exceeds the ceiling");
    let ids: Vec<BlockId> = blocks.iter().map(|b| b.1).collect();
    let r = batch(&mut c, &body_of(&ids), "");
    assert_eq!(r.status, 200);
    assert!(r.body.len() <= 1_048_576);
    let got = records(&r.body);
    assert_eq!(got.len(), fit);
    for (k, rec) in got.iter().enumerate() {
        assert_eq!(rec, &blocks[k].0, "a prefix of the request, in order");
    }
    // The rest, asked again.
    let r = batch(&mut c, &body_of(&ids[fit..]), "");
    let rest = records(&r.body);
    assert_eq!(rest.len(), 17 - fit);
    assert_eq!(rest[0], blocks[fit].0);
}

/// Rule 9: a copy gets `Cache-Control: no-store` and `CDN-Cache-Control: no-store`.
#[test]
fn replication_requests_are_not_cached() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let (a, ida) = store(&mut c, b"copy", &[]);
    let r = batch(&mut c, &body_of(&[ida]), "Sbtp-Replication: 1\r\n");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("cdn-cache-control"), Some("no-store"));
    assert_eq!(records(&r.body), vec![a]);
}

/// Rule 11: a preflight for `POST` from an allowed origin is answered with `POST` allowed.
#[test]
fn preflight_allows_post() {
    let relay = start(&[]);
    let mut c = relay.connect();
    let r = common::exchange(
        &mut c,
        "OPTIONS /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\nOrigin: https://app.example\r\n\
         Access-Control-Request-Method: POST\r\n\
         Access-Control-Request-Headers: content-type\r\n\r\n",
    );
    assert_eq!(r.status, 200);
    let methods = r.header("access-control-allow-methods").unwrap();
    assert!(
        methods.contains("POST") && methods.contains("PUT"),
        "{methods}"
    );
}

/// Rule 7: `⌈N / 4⌉` tokens of the `block` bucket at admission, from `Content-Length`, before
/// the body is read; 64 (capped at the burst) without `Content-Length`. With a burst of 10 and a
/// refill of 1 per minute: five batches of 8 identifiers (2 tokens each) pass, the next request
/// of the bucket gets `429`.
#[test]
fn weight_is_taken_at_admission() {
    let relay = start(&[("RATE_BLOCK_BURST", "10"), ("RATE_BLOCK_PER_MIN", "1")]);
    let mut c = relay.connect();
    let ids: Vec<BlockId> = (0..8u8).map(unknown).collect();
    for k in 0..5 {
        assert_eq!(batch(&mut c, &body_of(&ids), "").status, 200, "{k}");
    }
    let r = batch(&mut c, &body_of(&ids[..1]), "");
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (429, "RateLimited".into())
    );

    // A head without `Content-Length` takes the whole burst of a fresh client.
    let relay = start(&[("RATE_BLOCK_BURST", "10"), ("RATE_BLOCK_PER_MIN", "1")]);
    let mut c = relay.connect();
    c.write_all(b"POST /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\n\r\n")
        .unwrap();
    assert_eq!(read_response(&mut c).unwrap().status, 400);
    let mut c = relay.connect();
    assert_eq!(get(&mut c, "/sbtp/v1/info", "").status, 429);

    // A batch heavier than what is left is refused whole before its body is read.
    let relay = start(&[("RATE_BLOCK_BURST", "10"), ("RATE_BLOCK_PER_MIN", "1")]);
    let mut c = relay.connect();
    let many: Vec<BlockId> = (0..36u8).map(unknown).collect(); // 9 tokens
    assert_eq!(batch(&mut c, &body_of(&many), "").status, 200);
    let mut c = relay.connect();
    c.write_all(
        b"POST /sbtp/v1/blocks HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 256\r\n\r\n",
    )
    .unwrap();
    let r = read_response(&mut c).unwrap();
    assert_eq!(r.status, 429, "2 tokens needed, 1 left");
    let mut c = relay.connect();
    assert_eq!(
        get(&mut c, "/sbtp/v1/info", "").status,
        200,
        "the last token"
    );
}

/// Rule 7 and "Weights": the same tokens never buy more than 4 times the blocks single `GET`s
/// would, while `rate_block_burst` is at least 64 (every profile: 200 to 600). With a burst of
/// 64 and a refill of 1 per minute, single `GET`s serve 64 blocks; batches serve at most 256,
/// whatever their sizes. Below a burst of 64 the cap of rule 7 lets a batch cost the whole
/// burst only, so the ratio grows (shown last).
#[test]
fn batches_buy_at_most_four_times_the_single_gets() {
    let burst = 64usize;
    let pairs = [
        ("RATE_BLOCK_BURST", "64"),
        ("RATE_BLOCK_PER_MIN", "1"),
        ("RATE_PUT_BURST", "1000"),
        ("RATE_PUT_PER_MIN", "1000000"),
    ];
    let fresh = |pairs: &[(&str, &str)]| {
        let relay = start(pairs);
        let mut c = relay.connect();
        let ids: Vec<BlockId> = (0..300u32)
            .map(|n| store(&mut c, format!("ratio {n}").as_bytes(), &[]).1)
            .collect();
        (relay, ids)
    };
    let (relay, ids) = fresh(&pairs);
    let mut c = relay.connect();
    let mut single = 0;
    for id in &ids {
        match get(&mut c, &format!("/sbtp/v1/block/{id}"), "").status {
            200 => single += 1,
            429 => break,
            s => panic!("{s}"),
        }
    }
    assert_eq!(single, burst);
    for size in [1usize, 3, 5, 64, 255, 256] {
        let (relay, ids) = fresh(&pairs);
        let mut c = relay.connect();
        let mut served = 0;
        'outer: for _ in 0..300 {
            for chunk in ids.chunks(size) {
                let r = batch(&mut c, &body_of(chunk), "");
                if r.status == 429 {
                    break 'outer;
                }
                assert_eq!(r.status, 200);
                served += records(&r.body).iter().filter(|r| !r.is_empty()).count();
            }
        }
        assert!(
            served <= 4 * burst,
            "size {size}: {served} blocks for {burst} tokens"
        );
        assert!(served >= burst, "size {size}: {served}");
    }
    // Rule 7 caps the weight at the burst: with a burst of 16, 256 identifiers cost 16 tokens.
    let (relay, ids) = fresh(&[("RATE_BLOCK_BURST", "16"), ("RATE_BLOCK_PER_MIN", "1")]);
    let mut c = relay.connect();
    let r = batch(&mut c, &body_of(&ids[..256]), "");
    assert_eq!(records(&r.body).len(), 256);
    let mut c = relay.connect();
    assert_eq!(get(&mut c, "/sbtp/v1/info", "").status, 429);
}

/// ADR 0051 rules 13 and 14: `fields=parents` adds `parents` and `lens`, aligned with
/// `block_ids`; the page holds at most 200 entries; `fields` is refused with `parent` and with
/// any other value.
#[test]
fn fields_parents_are_aligned() {
    let relay = start(&[("RATE_PUT_BURST", "1000")]);
    let mut c = relay.connect();
    let (ra, a) = store(&mut c, b"root a", &[]);
    let (rb, b) = store(&mut c, b"root b", &[]);
    let (rc, cc) = store(&mut c, b"child", &[b, a]);
    let r = get(&mut c, "/sbtp/v1/query?fields=parents", "");
    assert_eq!(r.status, 200);
    let v = r.json();
    let ids: Vec<String> = [a, b, cc].iter().map(ToString::to_string).collect();
    assert_eq!(v["block_ids"], serde_json::json!(ids));
    assert_eq!(
        v["parents"],
        serde_json::json!([[], [], [b.to_string(), a.to_string()]]),
        "header order"
    );
    assert_eq!(v["lens"], serde_json::json!([ra.len(), rb.len(), rc.len()]));
    // Pages of the walk stay aligned.
    let r = get(&mut c, "/sbtp/v1/query?fields=parents&limit=2", "");
    let v = r.json();
    assert_eq!(v["block_ids"].as_array().unwrap().len(), 2);
    assert_eq!(v["parents"].as_array().unwrap().len(), 2);
    assert_eq!(v["lens"].as_array().unwrap().len(), 2);
    assert_eq!(v["more"], true);
    let next = format!(
        "/sbtp/v1/query?fields=parents&limit=2&cursor={}",
        v["cursor"].as_str().unwrap()
    );
    let v = get(&mut c, &next, "").json();
    assert_eq!(v["block_ids"], serde_json::json!([cc.to_string()]));
    assert_eq!(v["lens"], serde_json::json!([rc.len()]));
    // Without `fields`, no extra member.
    let v = get(&mut c, "/sbtp/v1/query", "").json();
    assert!(v.get("parents").is_none() && v.get("lens").is_none(), "{v}");
    for q in [
        format!("fields=parents&parent={a}"),
        format!("parent={a}&fields=parents"),
        "fields=lens".to_owned(),
        "fields=".to_owned(),
        "fields=parents&fields=parents".to_owned(),
    ] {
        let r = get(&mut c, &format!("/sbtp/v1/query?{q}"), "");
        assert_eq!(
            (r.status, r.json()["error"].clone()),
            (400, "InvalidParameter".into()),
            "{q}"
        );
    }
}

/// Rule 14: with `fields=parents` the page is at most 200 entries, whatever `limit`.
#[test]
fn fields_pages_are_capped_at_200() {
    let relay = start(&[("RATE_PUT_BURST", "1000")]);
    let mut c = relay.connect();
    for n in 0..205u32 {
        store(&mut c, format!("cap {n}").as_bytes(), &[]);
    }
    let v = get(&mut c, "/sbtp/v1/query?fields=parents&limit=1000", "").json();
    assert_eq!(v["block_ids"].as_array().unwrap().len(), 200);
    assert_eq!(v["lens"].as_array().unwrap().len(), 200);
    assert_eq!(v["more"], true);
    let v = get(&mut c, "/sbtp/v1/query?limit=1000", "").json();
    assert_eq!(v["block_ids"].as_array().unwrap().len(), 205);
}

/// `/query` with `query`, as JSON, asserting `200`.
fn query(c: &mut TcpStream, q: &str) -> serde_json::Value {
    let r = get(c, &format!("/sbtp/v1/query?{q}"), "");
    assert_eq!(r.status, 200, "{q}: {}", String::from_utf8_lossy(&r.body));
    r.json()
}

fn listed(v: &serde_json::Value) -> Vec<String> {
    v["block_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect()
}

fn s(v: &serde_json::Value, k: &str) -> String {
    v[k].as_str().unwrap().to_owned()
}

/// ADR 0051 rules 15 to 19: `desc` lists newest first across pages; each cursor names a gap and
/// works in both orders; `since` ends a `desc` walk; `head` is in every response and an `asc`
/// poll from it returns exactly the blocks stored since; `order` other than `asc` or `desc` is
/// `400`.
#[test]
fn desc_walks_both_ways_and_head_polls() {
    let relay = start(&[("RATE_PUT_BURST", "1000"), ("RATE_QUERY_BURST", "1000")]);
    let mut c = relay.connect();
    let (_, root) = store(&mut c, b"root", &[]);
    let kids: Vec<String> = (0..7u32)
        .map(|n| {
            // Distinct milliseconds for the `since` check.
            std::thread::sleep(std::time::Duration::from_millis(3));
            store(&mut c, format!("kid {n}").as_bytes(), &[root])
                .1
                .to_string()
        })
        .collect();
    let newest_first: Vec<String> = kids.iter().rev().cloned().collect();
    // Backward, three per page.
    let p = format!("parent={root}&order=desc&limit=3");
    let v1 = query(&mut c, &p);
    assert_eq!(listed(&v1), newest_first[..3]);
    assert_eq!(v1["more"], true);
    let v2 = query(&mut c, &format!("{p}&cursor={}", s(&v1, "cursor")));
    assert_eq!(listed(&v2), newest_first[3..6]);
    let v3 = query(&mut c, &format!("{p}&cursor={}", s(&v2, "cursor")));
    assert_eq!(listed(&v3), newest_first[6..]);
    assert_eq!(v3["more"], false);
    // The gap of page 1, forward: the blocks after it, oldest first.
    let up = query(
        &mut c,
        &format!("parent={root}&order=asc&cursor={}", s(&v1, "cursor")),
    );
    assert_eq!(listed(&up), kids[4..]);
    // An `asc` cursor, backward.
    let a = query(&mut c, &format!("parent={root}&limit=2"));
    let back = query(
        &mut c,
        &format!("parent={root}&order=desc&cursor={}", s(&a, "cursor")),
    );
    assert_eq!(listed(&back), vec![kids[1].clone(), kids[0].clone()]);
    // `head` is in every response, and the same while nothing is stored.
    let head = s(&v1, "head");
    for v in [&v2, &v3, &up, &a, &back] {
        assert_eq!(s(v, "head"), head);
    }
    let poll = query(&mut c, &format!("parent={root}&cursor={head}"));
    assert_eq!(listed(&poll), Vec::<String>::new());
    assert_eq!(poll["more"], false);
    let (_, late) = store(&mut c, b"late kid", &[root]);
    let (_, other) = store(&mut c, b"unrelated", &[]);
    let poll = query(&mut c, &format!("parent={root}&cursor={head}"));
    assert_eq!(listed(&poll), vec![late.to_string()]);
    let all = query(&mut c, &format!("cursor={head}"));
    assert_eq!(listed(&all), vec![late.to_string(), other.to_string()]);
    assert_ne!(s(&all, "head"), head, "head moved");
    let r = get(&mut c, "/sbtp/v1/query?order=up", "");
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (400, "InvalidParameter".into())
    );
}

/// ADR 0051 rule 17: with `desc`, `since` and the expiry bound end the walk with `more =
/// false`.
#[test]
fn desc_stops_at_since_and_expiry() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(1_000_000);
    fn clock() -> u64 {
        NOW.load(Ordering::SeqCst)
    }
    let s_ = settings(&[
        ("MIN_POW_DIFFICULTY", "0"),
        ("BLOCK_TTL_MS", "60000"),
        ("RATE_PUT_BURST", "1000"),
    ]);
    let relay = TestServer::start_clocked(&s_, clock);
    let mut c = relay.connect();
    let mut ids = Vec::new();
    for n in 0..5u64 {
        NOW.store(1_000_000 + n * 10_000, Ordering::SeqCst);
        let k = sbtp_core::SigningKey::from_bytes(&[4; 32]);
        let bytes = sbtp_core::BlockBuilder::for_key(&k)
            .timestamp(1)
            .payload(format!("ttl {n}").as_bytes())
            .build(&k, 0)
            .unwrap();
        assert_eq!(put_block(&mut c, &bytes).status, 201);
        ids.push(sbtp_core::parse(&bytes).unwrap().block_id().to_string());
    }
    // Now 1,040,000: nothing expired yet.
    let v = query(&mut c, "order=desc&since=1020000");
    assert_eq!(
        listed(&v),
        vec![ids[4].clone(), ids[3].clone(), ids[2].clone()]
    );
    assert_eq!(v["more"], false);
    // At 1,075,000 the blocks received at 1,000,000 and 1,010,000 are expired.
    NOW.store(1_075_000, Ordering::SeqCst);
    let v = query(&mut c, "order=desc&limit=3");
    assert_eq!(
        listed(&v),
        vec![ids[4].clone(), ids[3].clone(), ids[2].clone()]
    );
    assert_eq!(v["more"], false, "the expiry bound ends the walk");
}

/// ADR 0051 rules 21 to 28: several parents in one request, grouped in request order, each with
/// its cursor and `more`; per-parent cursors override `cursor`; the per-parent limit is lowered
/// to `max(1, ⌊max_query_limit / N⌋)`; one unrecognised cursor fails the whole request.
#[test]
fn grouped_listings_and_per_parent_more() {
    let relay = start(&[
        ("RATE_PUT_BURST", "1000"),
        ("RATE_QUERY_BURST", "1000"),
        ("MAX_QUERY_LIMIT", "4"),
    ]);
    let mut c = relay.connect();
    let (_, p1) = store(&mut c, b"p1", &[]);
    let (_, p2) = store(&mut c, b"p2", &[]);
    let (_, p3) = store(&mut c, b"p3", &[]);
    let k1: Vec<String> = (0..3u32)
        .map(|n| {
            store(&mut c, format!("a{n}").as_bytes(), &[p1])
                .1
                .to_string()
        })
        .collect();
    let k2 = store(&mut c, b"b0", &[p2]).1.to_string();
    // Three parents, `max_query_limit` 4: one entry per parent per page.
    let v = query(&mut c, &format!("parent={p1}&parent={p2}&parent={p3}"));
    let groups = v["parents"].as_array().unwrap();
    assert_eq!(groups.len(), 3);
    assert!(v.get("block_ids").is_none() && v["head"].is_string());
    for (g, p) in groups.iter().zip([p1, p2, p3]) {
        assert_eq!(s(g, "parent"), p.to_string(), "request order");
    }
    assert_eq!(listed(&groups[0]), vec![k1[0].clone()]);
    assert_eq!(groups[0]["more"], true);
    assert_eq!(listed(&groups[1]), vec![k2.clone()]);
    assert_eq!(groups[1]["more"], false);
    assert_eq!(listed(&groups[2]), Vec::<String>::new());
    assert_eq!(groups[2]["more"], false, "a complete, empty listing");
    // Continue the first parent only, with its own cursor; the others from `head`.
    let head = s(&v, "head");
    let v2 = query(
        &mut c,
        &format!(
            "parent={p1}.{}&parent={p2}&cursor={head}",
            s(&groups[0], "cursor")
        ),
    );
    let g2 = v2["parents"].as_array().unwrap();
    assert_eq!(listed(&g2[0]), k1[1..], "two parents: two per page");
    assert!(listed(&g2[1]).is_empty(), "nothing after head");
    // Two parents: two per page; `desc` grouped.
    let v3 = query(
        &mut c,
        &format!("parent={p1}&parent={p2}&order=desc&limit=9"),
    );
    let g3 = v3["parents"].as_array().unwrap();
    assert_eq!(listed(&g3[0]), vec![k1[2].clone(), k1[1].clone()]);
    assert_eq!(g3[0]["more"], true);
    // One unrecognised cursor fails the whole request.
    let bad = "0".repeat(40);
    let r = get(
        &mut c,
        &format!("/sbtp/v1/query?parent={p1}.{bad}&parent={p2}"),
        "",
    );
    assert_eq!(
        (r.status, r.json()["error"].clone()),
        (400, "InvalidCursor".into())
    );
    // Malformed forms.
    let many: Vec<String> = (0..33u8)
        .map(|n| format!("parent={}", BlockId([n; 32])))
        .collect();
    for q in [
        many.join("&"),
        format!("parent={p1}&parent={p1}"),
        format!("parent={p1}.{head}"),
        format!("parent={p1}&parent={p2}&fields=parents"),
    ] {
        let r = get(&mut c, &format!("/sbtp/v1/query?{q}"), "");
        assert_eq!(
            (r.status, r.json()["error"].clone()),
            (400, "InvalidParameter".into())
        );
    }
    let ok: Vec<String> = (0..32u8)
        .map(|n| format!("parent={}", BlockId([n; 32])))
        .collect();
    let v = query(&mut c, &ok.join("&"));
    assert_eq!(v["parents"].as_array().unwrap().len(), 32);
}

/// ADR 0051 rule 27: a cursor taken from one parent's listing, used for another, starts that
/// listing at the same gap, as `since` would: it grants nothing that a listing from the start
/// of that parent would not show.
#[test]
fn cursor_reuse_across_parents_grants_nothing() {
    let relay = start(&[("RATE_PUT_BURST", "1000"), ("RATE_QUERY_BURST", "1000")]);
    let mut c = relay.connect();
    let (_, a) = store(&mut c, b"pa", &[]);
    let (_, b) = store(&mut c, b"pb", &[]);
    let b0 = store(&mut c, b"b early", &[b]).1.to_string();
    let a0 = store(&mut c, b"a0", &[a]).1.to_string();
    let b1 = store(&mut c, b"b late", &[b]).1.to_string();
    let va = query(&mut c, &format!("parent={a}"));
    assert_eq!(listed(&va), vec![a0]);
    let cur = s(&va, "cursor");
    // `asc` for `b` from `a`'s cursor: only `b`'s children after that gap.
    let vb = query(&mut c, &format!("parent={b}&cursor={cur}"));
    assert_eq!(listed(&vb), vec![b1.clone()]);
    // `desc`: only `b`'s children before it.
    let vd = query(&mut c, &format!("parent={b}&order=desc&cursor={cur}"));
    assert_eq!(listed(&vd), vec![b0.clone()]);
    // Together they are exactly `b`'s full listing: nothing more, nothing of `a`.
    let full = query(&mut c, &format!("parent={b}"));
    assert_eq!(listed(&full), vec![b0, b1]);
}

/// ADR 0051 rule 26: a `/query` takes `⌈N / 8⌉` `query` tokens at admission. With a burst of 8
/// and a refill of 1 per minute: two requests of 32 parents (4 tokens each) pass, a third
/// request gets `429`.
#[test]
fn grouped_query_weight() {
    let relay = start(&[("RATE_QUERY_BURST", "8"), ("RATE_QUERY_PER_MIN", "1")]);
    let mut c = relay.connect();
    let q: Vec<String> = (0..32u8)
        .map(|n| format!("parent={}", BlockId([n; 32])))
        .collect();
    let q = q.join("&");
    query(&mut c, &q);
    query(&mut c, &q);
    let r = get(&mut c, "/sbtp/v1/query", "");
    assert_eq!(r.status, 429);
}

/// ADR 0051 rule 31: `/info` publishes `read_api: 2`.
#[test]
fn info_publishes_read_api_2() {
    let relay = start(&[]);
    let mut c = relay.connect();
    assert_eq!(get(&mut c, "/sbtp/v1/info", "").json()["read_api"], 2);
}
