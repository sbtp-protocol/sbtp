//! ADR 0021 end to end, through the process logger with a captured sink: the privacy rule 10
//! (no address, header value, path, cursor or body byte in any line, at `debug` with the client
//! tag on), the events of the request path, and the panic hook of rule 9 (one line, then
//! throttled). One test: the logger and the panic hook are global to this process.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use common::{TestServer, exchange, get as http_get, is_closed, settings};
use sbtp_relay::log::{self, LogConfig};
use sbtp_relay::metrics::{self, Refused};

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn explode() -> &'static str {
    panic!("handler panic (expected by the test)")
}

fn explode_formatted(input: &str) -> &'static str {
    panic!("handler panic on {input} (expected by the test)")
}

/// Four dot-separated decimal groups: an IPv4 address, whatever surrounds it.
fn has_ipv4(line: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .any(|t| t.split('.').filter(|g| !g.is_empty()).count() >= 4)
}

const CLIENT: &str = "203.0.113.77";
const MARKERS: [&str; 9] = [
    "zz-marker-panic",
    CLIENT,
    "2001:db8::77",
    "127.0.0.1",
    "::1",
    "zz-marker-header",
    "marker-path",
    "marker-cursor",
    "zz-marker-body",
];

#[test]
fn privacy_events_and_panics() {
    let sink = Capture(Arc::new(Mutex::new(Vec::new())));
    assert!(
        log::install(Box::new(sink.clone())),
        "first use of the logger"
    );
    let s = settings(&[
        ("LOG_LEVEL", "debug"),
        ("LOG_CLIENT_TAG", "keyed"),
        ("LOG_BURST", "3000"),
        ("LOG_RATE_PER_MIN", "6000"),
        ("MAX_CONNECTIONS_PER_CLIENT", "1"),
    ]);
    log::global().configure(&LogConfig::from_settings(&s));
    let extra = Router::new()
        .route("/test/panic", get(|| async { explode() }))
        .route(
            "/test/panic-formatted",
            get(|| async { explode_formatted("zz-marker-panic") }),
        )
        .route(
            "/test/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(1_500)).await;
                "slow"
            }),
        );
    // Loopback is a trusted proxy by default: the client key comes from X-Forwarded-For.
    let relay = TestServer::start(&s, extra);
    let xff = format!("X-Forwarded-For: {CLIENT}\r\nX-Marker: zz-marker-header\r\n");
    let mut c = relay.connect();
    let r = http_get(&mut c, "/sbtp/v1/marker-path?cursor=marker-cursor", &xff);
    assert_eq!(r.status, 404);
    // A cursor is never logged, whether it is refused for its syntax or not recognised.
    for q in [
        "cursor=marker-cursor",
        "cursor=marker-cursor%00",
        "marker-path=1",
    ] {
        let r = http_get(&mut c, &format!("/sbtp/v1/query?{q}"), &xff);
        assert_eq!(r.status, 400, "{q}");
    }
    let r = http_get(&mut c, "/sbtp/v1/info", "X-Forwarded-For: 2001:db8::77\r\n");
    assert_eq!(r.status, 200);
    let r = http_get(&mut c, "/sbtp/v1/info", "X-Forwarded-For: unknown\r\n");
    assert_eq!(r.status, 200);
    let r = exchange(
        &mut c,
        &format!(
            "PUT /sbtp/v1/info HTTP/1.1\r\nHost: relay.test\r\n{xff}Content-Length: 14\r\n\r\n\
             zz-marker-body"
        ),
    );
    assert_eq!(r.status, 405);
    // A second request of the same client while one is in flight: `429` (ADR 0019 rule 30).
    let refused = metrics::refused_total(Refused::InFlight);
    let mut slow = relay.connect();
    slow.write_all(format!("GET /test/slow HTTP/1.1\r\nHost: relay.test\r\n{xff}\r\n").as_bytes())
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(http_get(&mut c, "/sbtp/v1/info", &xff).status, 429);
    assert_eq!(common::read_response(&mut slow).unwrap().status, 200);
    assert!(metrics::refused_total(Refused::InFlight) > refused);
    // Rule 9: three caught panics give one line; a formatted message is withheld (security
    // review L-2). An uncaught panic has its own throttle and is written at once. The default
    // hook is restored afterwards, so that a
    // failed assertion of this test stays readable.
    log::install_panic_hook();
    assert_eq!(http_get(&mut c, "/test/panic-formatted", &xff).status, 500);
    assert_eq!(http_get(&mut c, "/test/panic", &xff).status, 500);
    assert_eq!(http_get(&mut c, "/test/panic", &xff).status, 500);
    assert!(
        std::thread::spawn(|| panic!("uncaught panic (expected by the test)"))
            .join()
            .is_err()
    );
    let _ = std::panic::take_hook();
    // ADR 0023 rule 14: a damaged file moved by a `GET` miss gives one `block_quarantined` line,
    // without the `block_id`.
    let key = sbtp_core::SigningKey::from_bytes(&[3; 32]);
    let mut damaged = sbtp_core::BlockBuilder::for_key(&key)
        .timestamp(1)
        .payload(b"logged")
        .build(&key, 0)
        .unwrap();
    let id = sbtp_core::parse(&damaged).unwrap().block_id();
    *damaged.last_mut().unwrap() ^= 1;
    let raw = id.as_bytes();
    let file = relay.data.join(format!("blocks/{:02x}/{id}.bin", raw[31]));
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &damaged).unwrap();
    assert_eq!(
        http_get(&mut c, &format!("/sbtp/v1/block/{id}"), &xff).status,
        404
    );
    let hex = id.to_string();
    drop(relay);

    // A direct peer over `max_connections_per_client` is closed at accept: `client_bound`.
    let direct = TestServer::start(
        &settings(&[("TRUSTED_PROXIES", ""), ("MAX_CONNECTIONS_PER_CLIENT", "1")]),
        Router::new(),
    );
    let _held = direct.connect();
    std::thread::sleep(Duration::from_millis(100));
    let mut over = direct.connect();
    assert!(is_closed(&mut over));
    let refused_at_accept = metrics::snapshot()
        .into_iter()
        .find(|(k, _)| *k == "connections_refused");
    assert!(refused_at_accept.is_some_and(|(_, n)| n >= 1));
    drop(direct);

    log::flush();
    let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = out.lines().collect();
    let event = |name: &str| {
        lines
            .iter()
            .filter(|l| {
                l.contains(&format!(" event={name} ")) || l.ends_with(&format!(" event={name}"))
            })
            .copied()
            .collect::<Vec<_>>()
    };
    for line in &lines {
        for m in MARKERS {
            assert!(!line.contains(m), "{m} in {line}");
        }
        assert!(!has_ipv4(line), "{line}");
        assert!(!line.contains(&hex[..16]), "{line}");
        assert!(line.len() < log::MAX_LINE);
    }
    let requests = event("request");
    assert!(requests.len() >= 8, "{out}");
    assert!(
        requests
            .iter()
            .any(|l| l.contains(" route=other method=GET status=404 "))
    );
    assert!(
        requests
            .iter()
            .any(|l| l.contains(" route=/sbtp/v1/info method=PUT status=405 "))
    );
    assert!(event("forwarded_invalid")[0].contains(" reason=unreadable client="));
    let limited = event("rate_limited");
    assert_eq!(limited.len(), 1, "{out}");
    let tag = limited[0].split(" client=").nth(1).unwrap();
    assert!(
        tag.starts_with(|c: char| c.is_ascii_hexdigit()) && tag.len() > 8,
        "{tag}"
    );
    assert!(
        event("client_bound")[0].contains(" limit=1 client="),
        "{out}"
    );
    let quarantined = event("block_quarantined");
    assert_eq!(quarantined.len(), 1, "{out}");
    assert!(
        quarantined[0]
            .ends_with(" event=block_quarantined cause=get reason=signature suppressed=0"),
        "{out}"
    );
    let reconciled = event("store_reconciled");
    assert_eq!(reconciled.len(), 2, "one per start: {out}");
    assert!(
        reconciled[0].contains(
            " files=0 orphans=0 quarantined=0 purged=0 dirs_created=259 epoch_renewed=false \
             duration_ms="
        ),
        "{out}"
    );
    let panics = event("panic");
    assert_eq!(panics.len(), 2, "{out}");
    assert!(panics[0].contains(" location=crates/sbtp-relay/tests/logging.rs:"));
    assert!(panics[0].ends_with(" formatted=true suppressed=0"), "{out}");
    assert!(
        panics[1].ends_with(" suppressed=0 msg=\"uncaught panic (expected by the test)\""),
        "{out}"
    );
}
