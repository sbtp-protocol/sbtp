//! The accept loop, the connection bounds, the error mapping, `/info` and CORS, over real loopback
//! sockets (ADR 0012, ADR 0018 rules 23 to 27, 31, 33, 34 and 37).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::ffi::OsString;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::routing::{get, post};
use common::{
    TestServer, connect, env, exchange, get as http_get, is_closed, read_response, settings,
    tmp_dir,
};
use sbtp_relay::api::read_body;
use sbtp_relay::index::{IndexBackend, RedbIndex};

fn server(pairs: &[(&str, &str)]) -> TestServer {
    TestServer::start(&settings(pairs), Router::new())
}

/// ADR 0018 rules 21 and 29, ADR 0020 rules 23 and 25(c), over HTTP: a CORS preflight and a
/// request to an unknown path each take a `block` token, then `/info` gets `429 RateLimited`
/// with the JSON body, `Retry-After` and the CORS headers; the `put` bucket refuses a `PUT`
/// before its body is read. `query` keeps its own bucket.
#[test]
fn block_and_put_buckets_give_429() {
    let relay = server(&[
        ("RATE_BLOCK_BURST", "2"),
        ("RATE_BLOCK_PER_MIN", "1"),
        ("RATE_PUT_BURST", "1"),
        ("RATE_PUT_PER_MIN", "1"),
    ]);
    let mut c = relay.connect();
    let preflight = exchange(
        &mut c,
        "OPTIONS /sbtp/v1/block HTTP/1.1\r\nHost: x\r\nOrigin: https://a.example\r\n\
         Access-Control-Request-Method: PUT\r\n\r\n",
    );
    assert!(preflight.status < 300, "{}", preflight.status);
    assert_eq!(http_get(&mut c, "/no/such/path", "").status, 404);
    let r = http_get(&mut c, "/sbtp/v1/info", "");
    assert_eq!(r.status, 429);
    assert_eq!(r.json()["error"], "RateLimited");
    let retry: u64 = r.header("retry-after").unwrap().parse().unwrap();
    assert!((59..=60).contains(&retry), "Retry-After {retry}");
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    assert_eq!(http_get(&mut c, "/sbtp/v1/query", "").status, 200);

    // `put`: the first `PUT` takes the token (and fails validation); the second is refused at
    // admission, before its body is read.
    let mut c = relay.connect();
    let first = exchange(
        &mut c,
        "PUT /sbtp/v1/block HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx",
    );
    assert_eq!(first.status, 400);
    let second = exchange(
        &mut c,
        "PUT /sbtp/v1/block HTTP/1.1\r\nHost: x\r\nContent-Length: 70000\r\n\r\n",
    );
    assert_eq!(second.status, 429);
    assert_eq!(second.json()["error"], "RateLimited");
    assert!(second.header("retry-after").is_some());
}

#[test]
fn info_has_exactly_the_adr_members() {
    let relay = server(&[("MIN_POW_DIFFICULTY", "20"), ("MAX_QUERY_LIMIT", "500")]);
    let mut c = relay.connect();
    let r = http_get(&mut c, "/sbtp/v1/info", "");
    assert_eq!(r.status, 200);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(
        r.json(),
        serde_json::json!({
            "min_pow_difficulty": 20,
            "max_future_ms": 300_000,
            "block_versions": [1],
            "max_query_limit": 500,
            "block_ttl_ms": 2_592_000_000_u64,
        })
    );
    // ADR 0019 rule 25: no header carries the name or version of the relay.
    assert_eq!(r.header("server"), None);
    for (name, value) in &r.headers {
        assert!(!value.contains("sbtp-relay"), "{name}: {value}");
    }
}

/// ADR 0019 rule 7: with eviction by age disabled, `/info` publishes `null`, never 0.
#[test]
fn info_publishes_null_when_eviction_is_disabled() {
    let relay = server(&[("BLOCK_TTL_MS", "0")]);
    let mut c = relay.connect();
    let r = http_get(&mut c, "/sbtp/v1/info", "");
    assert_eq!(r.json()["block_ttl_ms"], serde_json::Value::Null);
    assert!(r.json().as_object().unwrap().contains_key("block_ttl_ms"));
}

/// ADR 0019 rule 29: a direct peer (not in `trusted_proxies`) holds at most
/// `max_connections_per_client` (default 8) connections; the 9th is closed at accept, without a
/// response, and the count is released when a connection ends.
#[test]
fn direct_client_over_its_bound_is_closed_at_accept() {
    let relay = server(&[("TRUSTED_PROXIES", "")]);
    let mut held: Vec<_> = (0..8)
        .map(|_| {
            let mut c = relay.connect();
            assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
            c
        })
        .collect();
    let mut ninth = relay.connect();
    let t = Instant::now();
    assert!(is_closed(&mut ninth));
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    // `X-Forwarded-For` from an untrusted peer does not change its key (rule 31).
    let mut spoofed = relay.connect();
    let _ = spoofed.write_all(
        b"GET /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\nX-Forwarded-For: 203.0.113.1\r\n\r\n",
    );
    assert!(is_closed(&mut spoofed));

    drop(held.pop());
    std::thread::sleep(Duration::from_millis(300));
    let mut again = relay.connect();
    assert_eq!(http_get(&mut again, "/sbtp/v1/info", "").status, 200);

    // An exempt key is not bounded (rule 31).
    let relay = server(&[
        ("TRUSTED_PROXIES", ""),
        ("RATE_LIMIT_EXEMPT", "127.0.0.1/32"),
    ]);
    let mut all: Vec<_> = (0..10).map(|_| relay.connect()).collect();
    for c in &mut all {
        assert_eq!(http_get(c, "/sbtp/v1/info", "").status, 200);
    }
}

/// ADR 0019 rule 30: through a peer in `trusted_proxies` (loopback by default), connections are
/// not counted; requests in flight are, per `X-Forwarded-For` client key. The 9th gets `429` with
/// `Retry-After: 1` from its head alone, before any handler runs and before its body is read.
#[test]
fn proxied_client_over_its_bound_gets_429_before_the_body() {
    let extra = Router::new().route(
        "/test/hold",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            "held"
        }),
    );
    let relay = TestServer::start(&settings(&[]), extra);
    let xff = "X-Forwarded-For: 203.0.113.7\r\n";
    let mut holds: Vec<_> = (0..8)
        .map(|_| {
            let mut c = relay.connect();
            c.write_all(
                format!("GET /test/hold HTTP/1.1\r\nHost: relay.test\r\n{xff}\r\n").as_bytes(),
            )
            .unwrap();
            c
        })
        .collect();
    std::thread::sleep(Duration::from_millis(400));

    let mut ninth = relay.connect();
    let t = Instant::now();
    let r = exchange(
        &mut ninth,
        "PUT /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 1000\r\n\
         X-Forwarded-For: 198.51.100.1, 203.0.113.7\r\nOrigin: https://app.example\r\n\r\n",
    );
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(r.status, 429);
    assert_eq!(r.json()["error"], "RateLimited");
    assert_eq!(r.header("retry-after"), Some("1"));
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));

    // Another client through the same proxy is served.
    let mut other = relay.connect();
    let r = http_get(
        &mut other,
        "/sbtp/v1/info",
        "X-Forwarded-For: 203.0.113.8\r\n",
    );
    assert_eq!(r.status, 200);

    for c in &mut holds {
        assert_eq!(read_response(c).unwrap().status, 200);
    }
    // Every response was written: the key is below its bound again.
    let mut c = relay.connect();
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", xff).status, 200);
}

/// ADR 0020 rules 7 to 10 and 22 end to end: through a trusted peer, `ip:port` and `[v6]:port`
/// give the client's own key; `unknown` on the right of a forged address gives the proxy's key; a
/// preflight over the bound gets the `429` with its CORS headers.
#[test]
fn forwarded_forms_and_refused_preflight() {
    // The handler reports that it holds its request, then holds it until the test releases it:
    // no timing assumption.
    let (arrived_tx, arrived) = std::sync::mpsc::channel::<()>();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let gate = Arc::clone(&release);
    let extra = Router::new().route(
        "/test/hold",
        get(move || {
            let (arrived_tx, gate) = (arrived_tx.clone(), Arc::clone(&gate));
            async move {
                let _ = arrived_tx.send(());
                let _ = gate
                    .acquire()
                    .await
                    .map(tokio::sync::SemaphorePermit::forget);
                "held"
            }
        }),
    );
    let relay = TestServer::start(&settings(&[("MAX_CONNECTIONS_PER_CLIENT", "1")]), extra);
    let hold = |xff: &str| {
        let mut c = relay.connect();
        c.write_all(
            format!(
                "GET /test/hold HTTP/1.1\r\nHost: relay.test\r\nX-Forwarded-For: {xff}\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
        arrived.recv_timeout(Duration::from_secs(10)).unwrap();
        c
    };
    let status = |xff: &str| {
        let mut c = relay.connect();
        http_get(
            &mut c,
            "/sbtp/v1/info",
            &format!("X-Forwarded-For: {xff}\r\n"),
        )
        .status
    };
    let mut holds = vec![hold("203.0.113.7:4711"), hold("[2001:db8::1]:4711,")];
    // Same address, other port and other forms: same key, over its bound of 1.
    assert_eq!(status("203.0.113.7"), 429);
    assert_eq!(status("198.51.100.1, 203.0.113.7:1"), 429);
    assert_eq!(status("2001:db8::2"), 429, "same /64");
    assert_eq!(status("203.0.113.8:4711"), 200);
    // `unknown` ends the search: the proxy's key, not the forged address on its left.
    holds.push(hold("198.51.100.50, unknown"));
    assert_eq!(status("198.51.100.50"), 200);
    assert_eq!(status("203.0.113.9, unknown"), 429);
    let mut c = relay.connect();
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 429);
    // A preflight over the bound is refused like any request, with CORS headers.
    let mut c = relay.connect();
    let r = exchange(
        &mut c,
        "OPTIONS /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\nX-Forwarded-For: 203.0.113.7\r\n\
         Origin: https://app.example\r\nAccess-Control-Request-Method: PUT\r\n\r\n",
    );
    assert_eq!(r.status, 429);
    assert_eq!(r.json()["error"], "RateLimited");
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    // A preflight under the bound gets the normal CORS answer.
    let r = exchange(
        &mut relay.connect(),
        "OPTIONS /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\nX-Forwarded-For: 203.0.113.20\r\n\
         Origin: https://app.example\r\nAccess-Control-Request-Method: PUT\r\n\r\n",
    );
    assert_eq!(r.status, 200);
    assert!(r.header("access-control-allow-methods").is_some());
    release.add_permits(holds.len());
    for c in &mut holds {
        assert_eq!(read_response(c).unwrap().status, 200);
    }
}

/// ADR 0019 rules 14 and 30 under write backpressure: a response whose body is finished but not
/// yet written to the socket keeps its request counted; the pipelined request behind it is
/// served, and every count is released once the client reads.
#[test]
fn unwritten_response_stays_counted_until_written() {
    const BIG: usize = 64 << 20; // larger than the loopback socket buffers
    let extra = Router::new().route("/test/big", get(|| async { vec![b'x'; BIG] }));
    let relay = TestServer::start(&settings(&[("MAX_CONNECTIONS_PER_CLIENT", "1")]), extra);
    let xff = "X-Forwarded-For: 203.0.113.7\r\n";
    let mut a = relay.connect();
    a.write_all(
        format!(
            "GET /test/big HTTP/1.1\r\nHost: relay.test\r\n{xff}\r\n\
             GET /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\n{xff}\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(500)); // `a` reads nothing

    let mut b = relay.connect();
    assert_eq!(http_get(&mut b, "/sbtp/v1/info", xff).status, 429);

    // `read_response` may read past the first body into the second response.
    let first = read_response(&mut a).unwrap();
    assert_eq!(first.status, 200);
    let mut rest = first.body.get(BIG..).unwrap().to_vec();
    while !rest.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut chunk = [0u8; 4096];
        let n = std::io::Read::read(&mut a, &mut chunk).unwrap();
        assert_ne!(n, 0);
        rest.extend_from_slice(&chunk[..n]);
    }
    // The pipelined request behind it was served, not refused by its own predecessor.
    assert!(
        rest.starts_with(b"HTTP/1.1 200 "),
        "{:?}",
        String::from_utf8_lossy(&rest)
    );
    std::thread::sleep(Duration::from_millis(200));
    for _ in 0..3 {
        let mut c = relay.connect();
        assert_eq!(http_get(&mut c, "/sbtp/v1/info", xff).status, 200);
    }
}

/// ADR 0019 rule 32: an idle connection past `max_connection_age_ms` is closed at once; a request
/// in progress when the age passes is served with `Connection: close`.
#[test]
fn connection_age_cap() {
    let extra = Router::new().route(
        "/test/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            "slow"
        }),
    );
    let relay = TestServer::start(&settings(&[("MAX_CONNECTION_AGE_MS", "1000")]), extra);
    let mut c = relay.connect();
    let r = http_get(&mut c, "/sbtp/v1/info", "");
    assert_eq!((r.status, r.header("connection")), (200, None));
    let t = Instant::now();
    assert!(is_closed(&mut c));
    assert!(
        t.elapsed() < Duration::from_millis(1_500),
        "{:?}",
        t.elapsed()
    );

    let mut c = relay.connect();
    let r = http_get(&mut c, "/test/slow", "");
    assert_eq!((r.status, r.header("connection")), (200, Some("close")));
    assert!(is_closed(&mut c));
}

/// ADR 0019 rule 33: the response to request `max_requests_per_connection` carries
/// `Connection: close`, and the connection is closed after it.
#[test]
fn request_cap_per_connection() {
    let relay = server(&[("MAX_REQUESTS_PER_CONNECTION", "3")]);
    let mut c = relay.connect();
    for _ in 0..2 {
        let r = http_get(&mut c, "/sbtp/v1/info", "");
        assert_eq!((r.status, r.header("connection")), (200, None));
    }
    let r = http_get(&mut c, "/sbtp/v1/info", "");
    assert_eq!((r.status, r.header("connection")), (200, Some("close")));
    assert!(is_closed(&mut c));
}

#[test]
fn errors_carry_the_json_body() {
    let relay = server(&[]);
    let mut c = relay.connect();
    let r = http_get(&mut c, "/sbtp/v1/nope", "");
    assert_eq!(r.status, 404);
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.json()["error"], "NotFound");
    let r = exchange(
        &mut c,
        "PUT /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(r.status, 405);
    assert_eq!(r.json()["error"], "MethodNotAllowed");
    assert!(r.header("allow").unwrap().contains("GET"));
}

#[test]
fn cors_wildcard_by_default_without_credentials() {
    let relay = server(&[]);
    let mut c = relay.connect();
    let origin = "Origin: https://app.example\r\n";
    for path in ["/sbtp/v1/info", "/sbtp/v1/nope"] {
        let r = http_get(&mut c, path, origin);
        assert_eq!(r.header("access-control-allow-origin"), Some("*"), "{path}");
        let exposed = r
            .header("access-control-expose-headers")
            .unwrap()
            .to_ascii_lowercase();
        assert!(exposed.contains("location") && exposed.contains("retry-after"));
        assert!(r.header("access-control-allow-credentials").is_none());
    }
    let r = exchange(
        &mut c,
        "OPTIONS /sbtp/v1/block HTTP/1.1\r\nHost: relay.test\r\nOrigin: https://app.example\r\n\
         Access-Control-Request-Method: PUT\r\nAccess-Control-Request-Headers: content-type\r\n\r\n",
    );
    assert!((200..300).contains(&r.status));
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    let methods = r.header("access-control-allow-methods").unwrap();
    assert!(methods.contains("GET") && methods.contains("PUT"));
    assert_eq!(
        r.header("access-control-allow-headers")
            .map(str::to_ascii_lowercase),
        Some("content-type".into())
    );
    assert_eq!(r.header("access-control-max-age"), Some("86400"));
    assert!(r.header("access-control-allow-credentials").is_none());
}

#[test]
fn cors_allow_list() {
    let relay = server(&[(
        "CORS_ALLOW_ORIGINS",
        "HTTPS://A.Example,http://localhost:5173",
    )]);
    let mut c = relay.connect();
    let r = http_get(&mut c, "/sbtp/v1/info", "Origin: https://a.example\r\n");
    assert_eq!(
        r.header("access-control-allow-origin"),
        Some("https://a.example")
    );
    assert!(
        r.header("vary")
            .unwrap()
            .to_ascii_lowercase()
            .contains("origin")
    );
    let r = http_get(&mut c, "/sbtp/v1/info", "Origin: https://b.example\r\n");
    assert_eq!(r.status, 200, "the request is still served");
    assert!(r.header("access-control-allow-origin").is_none());
    assert!(
        r.header("vary")
            .unwrap()
            .to_ascii_lowercase()
            .contains("origin")
    );
}

fn explode() -> &'static str {
    panic!("handler panic (expected by the test)")
}

#[test]
fn panic_becomes_500_with_json_body() {
    let extra = Router::new().route("/test/panic", get(|| async { explode() }));
    let relay = TestServer::start(&settings(&[]), extra);
    let before = sbtp_relay::metrics::panics();
    let mut c = relay.connect();
    let r = http_get(&mut c, "/test/panic", "Origin: https://app.example\r\n");
    assert_eq!(r.status, 500);
    assert_eq!(r.json()["error"], "Internal");
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
    assert!(sbtp_relay::metrics::panics() > before);
    // The connection and the relay still serve.
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
}

/// ADR 0018 rule 31: connection `max_connections + 1` is not accepted until one closes.
#[test]
fn connection_cap() {
    let relay = server(&[
        ("MAX_CONNECTIONS", "2"),
        ("MAX_CONNECTIONS_PER_CLIENT", "2"),
    ]);
    let mut a = relay.connect();
    let b = relay.connect();
    assert_eq!(http_get(&mut a, "/sbtp/v1/info", "").status, 200);
    std::thread::sleep(Duration::from_millis(200));
    let mut third = relay.connect(); // completes in the kernel listen queue
    third
        .write_all(b"GET /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\n\r\n")
        .unwrap();
    third
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let e = read_response(&mut third).unwrap_err();
    assert!(
        matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        "{e}"
    );
    drop(a);
    third
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(read_response(&mut third).unwrap().status, 200);
    drop(b);
}

/// Rule 23: headers never completed close the connection at `header_timeout_ms`, without a
/// response.
#[test]
fn slow_headers_are_cut() {
    let relay = server(&[("HEADER_TIMEOUT_MS", "1000")]);
    let mut c = relay.connect();
    c.write_all(b"GET /sbtp/v1/info HTTP/1.1\r\nHost: re")
        .unwrap();
    let t = Instant::now();
    assert!(is_closed(&mut c));
    let waited = t.elapsed();
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_secs(3), "{waited:?}");
}

/// Rule 26, and hyper's header timer not used: a keep-alive connection stays open past
/// `header_timeout_ms` while idle, and is closed at `idle_timeout_ms`.
#[test]
fn idle_connection_closes_at_idle_timeout() {
    let relay = server(&[("HEADER_TIMEOUT_MS", "1000"), ("IDLE_TIMEOUT_MS", "2500")]);
    let mut c = relay.connect();
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
    std::thread::sleep(Duration::from_millis(1_600));
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
    let t = Instant::now();
    assert!(is_closed(&mut c));
    let waited = t.elapsed();
    assert!(waited >= Duration::from_millis(2_300), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");
}

/// Rule 24: a body sent slowly gets `408 RequestTimeout` at `body_timeout_ms`, a deadline on the
/// whole transfer, and the connection is closed.
#[test]
fn slow_body_gets_408() {
    let s = settings(&[("BODY_TIMEOUT_MS", "1000")]);
    let timeout = Duration::from_millis(s.body_timeout_ms);
    let extra = Router::new().route(
        "/test/body",
        post(move |body: Body| async move {
            read_body(body, 1024, timeout)
                .await
                .map(|b| b.len().to_string())
        }),
    );
    let relay = TestServer::start(&s, extra);
    let mut c = relay.connect();
    c.write_all(b"POST /test/body HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 50\r\n\r\n")
        .unwrap();
    let t = Instant::now();
    let writer = {
        let mut w = c.try_clone().unwrap();
        std::thread::spawn(move || {
            for _ in 0..50 {
                if w.write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let r = read_response(&mut c).unwrap();
    let waited = t.elapsed();
    assert_eq!(r.status, 408);
    assert_eq!(r.json()["error"], "RequestTimeout");
    assert_eq!(r.header("connection"), Some("close"));
    assert!(
        waited >= Duration::from_millis(900) && waited < Duration::from_secs(3),
        "{waited:?}"
    );
    assert!(is_closed(&mut c));
    writer.join().unwrap();

    // The same route with a prompt body succeeds, and a body over the limit gets 413.
    let mut c = relay.connect();
    let r = exchange(
        &mut c,
        "POST /test/body HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 3\r\n\r\nabc",
    );
    assert_eq!((r.status, r.body.as_slice()), (200, &b"3"[..]));
    let big = "y".repeat(2_000);
    let r = exchange(
        &mut c,
        &format!(
            "POST /test/body HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 2000\r\n\r\n{big}"
        ),
    );
    assert_eq!(r.status, 413);
    assert_eq!(r.json()["error"], "BodyTooLarge");

    // Review finding 7: a `Content-Length` over the limit is refused from the head alone, before
    // any body byte (none is sent here; reading would wait for the body deadline).
    let mut c = relay.connect();
    let t = Instant::now();
    let r = exchange(
        &mut c,
        "POST /test/body HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 2000\r\n\r\n",
    );
    assert_eq!(r.status, 413);
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
}

/// Rule 25: no response within `request_timeout_ms` gives `503 Unavailable` with `Retry-After`.
#[test]
fn slow_handler_gets_503() {
    let s = settings(&[
        ("REQUEST_TIMEOUT_MS", "1000"),
        ("HEADER_TIMEOUT_MS", "1000"),
        ("BODY_TIMEOUT_MS", "1000"),
        ("QUEUE_TIMEOUT_MS", "100"),
        ("SHED_RETRY_AFTER_S", "7"),
    ]);
    let extra = Router::new().route(
        "/test/slow",
        get(|| async { tokio::time::sleep(Duration::from_secs(10)).await }),
    );
    let relay = TestServer::start(&s, extra);
    let mut c = relay.connect();
    let t = Instant::now();
    let r = http_get(&mut c, "/test/slow", "Origin: https://app.example\r\n");
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(r.status, 503);
    assert_eq!(r.json()["error"], "Unavailable");
    assert_eq!(r.header("retry-after"), Some("7"));
    assert_eq!(r.header("access-control-allow-origin"), Some("*"));
}

/// Rule 23 and 33: headers over `max_header_bytes` are refused by the HTTP layer and the
/// connection is closed.
#[test]
fn oversized_headers_are_rejected() {
    let relay = server(&[("MAX_HEADER_BYTES", "8192")]);
    let mut c = relay.connect();
    let big = "a".repeat(10_000);
    let _ = c.write_all(
        format!("GET /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\nX-Big: {big}\r\n\r\n")
            .as_bytes(),
    );
    let r = read_response(&mut c).unwrap();
    assert_eq!(r.status, 431);
    assert!(is_closed(&mut c));
    // Headers just under the limit are served.
    let mut c = relay.connect();
    let fits = "a".repeat(7_000);
    assert_eq!(
        http_get(&mut c, "/sbtp/v1/info", &format!("X-Fits: {fits}\r\n")).status,
        200
    );
}

/// The shipped start-up path: graceful shutdown closes idle connections, stops the flusher,
/// flushes and closes the index (security review F-3), so that the index file can be opened again.
struct Running {
    addr: std::net::SocketAddr,
    data: std::path::PathBuf,
    stop: tokio::sync::mpsc::UnboundedSender<()>,
    thread: std::thread::JoinHandle<Result<(), sbtp_relay::StartError>>,
}

/// The whole shipped start-up path (`sbtp_relay::run`) on a fresh data directory.
fn run_relay(name: &str, pairs: &[(&str, &str)]) -> Running {
    let data = tmp_dir(name);
    let mut e = env(&[
        ("MIN_POW_DIFFICULTY", "16"),
        ("LISTEN", "127.0.0.1:0"),
        ("DATA_DIR", data.to_str().unwrap()),
        ("WORKER_THREADS", "1"),
    ]);
    e.extend(env(pairs));
    let (stop, stopped) = tokio::sync::mpsc::unbounded_channel::<()>();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        sbtp_relay::run(
            sbtp_core::self_test,
            Vec::<OsString>::new(),
            e,
            move || Ok(stopped),
            move |addr| addr_tx.send(addr).unwrap(),
        )
    });
    Running {
        addr: addr_rx.recv().unwrap(),
        data,
        stop,
        thread,
    }
}

/// Security F-4: a second stop signal during the drain closes the connections at once, and the
/// index is still flushed and closed.
#[test]
fn second_signal_skips_the_drain() {
    let relay = run_relay(
        "second-signal",
        &[
            ("HEADER_TIMEOUT_MS", "60000"),
            ("REQUEST_TIMEOUT_MS", "60000"),
        ],
    );
    let mut c = connect(relay.addr);
    c.write_all(b"GET /sbtp/v1/info HTTP/1.1\r\nHo").unwrap(); // holds the drain
    std::thread::sleep(Duration::from_millis(200));
    relay.stop.send(()).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !relay.thread.is_finished(),
        "the drain waits for the partial head"
    );
    let t = Instant::now();
    relay.stop.send(()).unwrap();
    relay.thread.join().unwrap().unwrap();
    assert!(t.elapsed() < Duration::from_secs(2));
    assert!(is_closed(&mut c));
    RedbIndex::open(&relay.data.join("index.redb"), 1 << 20).unwrap();
}

#[test]
fn graceful_shutdown_flushes_and_closes() {
    let Running {
        addr,
        data,
        stop,
        thread: relay,
    } = run_relay("shutdown", &[]);
    let mut c = connect(addr);
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
    let index = data.join("index.redb");
    assert!(
        RedbIndex::open(&index, 1 << 20).is_err(),
        "the running relay holds the index"
    );

    let t = Instant::now();
    stop.send(()).unwrap();
    assert!(
        is_closed(&mut c),
        "the idle connection is closed at shutdown"
    );
    relay.join().unwrap().unwrap();
    assert!(t.elapsed() < Duration::from_secs(5));
    let reopened = RedbIndex::open(&index, 1 << 20).unwrap();
    assert!(reopened.is_empty().unwrap());
    // The listener is gone.
    assert!(std::net::TcpStream::connect(addr).is_err());
}

/// Security review F-1: a connection that never sends a byte is cut at `header_timeout_ms`, not
/// `idle_timeout_ms`.
#[test]
fn silent_connection_is_cut_at_header_timeout() {
    let relay = server(&[("HEADER_TIMEOUT_MS", "1000"), ("IDLE_TIMEOUT_MS", "10000")]);
    let mut c = relay.connect();
    let t = Instant::now();
    assert!(is_closed(&mut c));
    let waited = t.elapsed();
    assert!(waited >= Duration::from_millis(900), "{waited:?}");
    assert!(waited < Duration::from_millis(2_500), "{waited:?}");
}

/// Rule 25, review finding 2: a response ends when its bytes are flushed to the socket. A client
/// that stops reading (zero window) is cut at `request_timeout_ms` + 1 s, not `idle_timeout_ms`.
#[test]
fn never_reading_client_is_cut_at_the_request_deadline() {
    const BIG: usize = 32 << 20; // larger than the loopback socket buffers
    let s = settings(&[
        ("REQUEST_TIMEOUT_MS", "1000"),
        ("HEADER_TIMEOUT_MS", "1000"),
        ("BODY_TIMEOUT_MS", "1000"),
        ("QUEUE_TIMEOUT_MS", "100"),
        ("IDLE_TIMEOUT_MS", "20000"),
    ]);
    let extra = Router::new().route("/test/big", get(|| async { vec![b'x'; BIG] }));
    let relay = TestServer::start(&s, extra);
    let mut c = relay.connect();
    c.write_all(b"GET /test/big HTTP/1.1\r\nHost: relay.test\r\n\r\n")
        .unwrap();
    std::thread::sleep(Duration::from_millis(3_500));
    let mut total = 0usize;
    let mut chunk = vec![0u8; 1 << 16];
    loop {
        match std::io::Read::read(&mut c, &mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    assert!(
        total < BIG,
        "the whole response was delivered: {total} bytes"
    );
}

/// Review finding 3, security F-3: bytes of a pipelined next request already buffered start the
/// header deadline; a partial pipelined head is cut at `header_timeout_ms`.
#[test]
fn partial_pipelined_head_is_cut_at_header_timeout() {
    let relay = server(&[("HEADER_TIMEOUT_MS", "1000"), ("IDLE_TIMEOUT_MS", "10000")]);
    let mut c = relay.connect();
    let r = exchange(
        &mut c,
        "GET /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\n\r\nGET /sbtp/v1/info HTTP/1.1\r\nHo",
    );
    assert_eq!(r.status, 200);
    let t = Instant::now();
    assert!(is_closed(&mut c));
    let waited = t.elapsed();
    assert!(waited < Duration::from_millis(2_500), "{waited:?}");
}

/// The keep-alive idle period still applies after a request with a body: the tracking of
/// pipelined bytes does not count the body as the next request.
#[test]
fn idle_period_after_a_request_with_a_body() {
    let relay = server(&[("HEADER_TIMEOUT_MS", "1000"), ("IDLE_TIMEOUT_MS", "10000")]);
    let mut c = relay.connect();
    let r = exchange(
        &mut c,
        "PUT /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 5\r\n\r\nhello",
    );
    assert_eq!(r.status, 405);
    std::thread::sleep(Duration::from_millis(1_800));
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", "").status, 200);
}

/// Security F-5: `Content-Length` with `Transfer-Encoding: chunked`: one response, connection
/// closed, the bytes that follow are not parsed as a request.
#[test]
fn content_length_with_transfer_encoding_is_not_smuggled() {
    let relay = server(&[]);
    let mut c = relay.connect();
    let r = exchange(
        &mut c,
        "POST /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\nContent-Length: 5\r\n\
         Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /sbtp/v1/nope HTTP/1.1\r\nHost: relay.test\r\n\r\n",
    );
    assert_ne!(r.status, 404, "the smuggled request was answered first");
    assert!(is_closed(&mut c), "a second response was sent");
}

/// Security F-5: 5,000 pipelined requests in one stream are all served, in order.
#[test]
fn many_pipelined_requests_are_served() {
    const N: usize = 5_000;
    let relay = server(&[("MAX_REQUESTS_PER_CONNECTION", "1000000")]);
    let mut c = relay.connect();
    let mut w = c.try_clone().unwrap();
    let writer = std::thread::spawn(move || {
        let one = "GET /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\n\r\n";
        w.write_all(one.repeat(N).as_bytes()).unwrap();
    });
    // Count status lines on the raw stream (`read_response` reads one response at a time).
    let (mut seen, mut tail, mut chunk) = (0, Vec::new(), vec![0u8; 1 << 16]);
    let status = b"HTTP/1.1 200 OK\r\n";
    while seen < N {
        let n = std::io::Read::read(&mut c, &mut chunk).unwrap();
        assert_ne!(n, 0, "closed after {seen} responses");
        tail.extend_from_slice(&chunk[..n]);
        seen += tail.windows(status.len()).filter(|w| *w == status).count();
        let keep = tail.len().saturating_sub(status.len() - 1);
        tail.drain(..keep);
    }
    assert_eq!(seen, N);
    writer.join().unwrap();
}
