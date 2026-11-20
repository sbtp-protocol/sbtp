//! `client_ip_header` end to end (ADR 0044), over real loopback HTTP. The test client connects
//! from `127.0.0.1`, which the default `trusted_proxies` trusts. Client keys are observed through
//! the `query` token bucket (burst 1): a second `/query` with the same key gets `429`. One test
//! per process owns the logger, so the privacy check (no header value, no address in any line)
//! runs in the same test.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::Router;
use common::{TestServer, exchange, get as http_get, settings};
use sbtp_relay::log::{self, LogConfig};

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

const BUCKET: [(&str, &str); 3] = [
    ("RATE_QUERY_BURST", "1"),
    ("RATE_QUERY_PER_MIN", "1"),
    ("LOG_LEVEL", "debug"),
];

fn query(relay: &TestServer, headers: &str) -> u16 {
    let mut c = relay.connect();
    http_get(&mut c, "/sbtp/v1/query", headers).status
}

fn cf(v: &str) -> String {
    format!("CF-Connecting-IP: {v}\r\n")
}

#[test]
fn client_address_from_a_single_value_header() {
    let sink = Capture(Arc::new(Mutex::new(Vec::new())));
    assert!(log::install(Box::new(sink.clone())));

    // Trusted peer, setting on.
    let mut pairs = BUCKET.to_vec();
    pairs.push(("CLIENT_IP_HEADER", "cf-connecting-ip"));
    let s = settings(&pairs);
    log::global().configure(&LogConfig::from_settings(&s));
    let relay = TestServer::start(&s, Router::new());
    assert_eq!(query(&relay, &cf("203.0.113.7")), 200);
    assert_eq!(query(&relay, &cf("203.0.113.7")), 429, "same client");
    assert_eq!(query(&relay, &cf("203.0.113.8")), 200, "another client");
    assert_eq!(
        query(
            &relay,
            &format!("{}X-Forwarded-For: 198.51.100.1\r\n", cf("203.0.113.7"))
        ),
        429,
        "X-Forwarded-For is not read"
    );
    assert_eq!(
        query(&relay, "X-Forwarded-For: 198.51.100.2\r\n"),
        200,
        "no header: the proxy's key, X-Forwarded-For ignored"
    );
    // Every fallback shares the proxy's key, now empty.
    for bad in [
        String::new(),
        cf("203.0.113.9:443"),
        cf("[2001:db8::9]"),
        cf("203.0.113.9, 203.0.113.10"),
        cf("unknown"),
        cf("127.0.0.1"),
        format!("{}{}", cf("203.0.113.11"), cf("203.0.113.12")),
    ] {
        assert_eq!(query(&relay, &bad), 429, "falls back to the peer: {bad:?}");
    }
    assert_eq!(query(&relay, &cf("::ffff:203.0.113.8")), 429, "mapped");
    assert_eq!(query(&relay, &cf("2001:db8:1::1")), 200);
    assert_eq!(query(&relay, &cf("2001:db8:1::2")), 429, "same /64");
    drop(relay);

    // Untrusted peer, setting on: the header is ignored, the key is the peer address.
    let mut pairs = BUCKET.to_vec();
    pairs.push(("CLIENT_IP_HEADER", "cf-connecting-ip"));
    pairs.push(("TRUSTED_PROXIES", "192.0.2.0/24"));
    let relay = TestServer::start(&settings(&pairs), Router::new());
    assert_eq!(query(&relay, &cf("203.0.113.20")), 200);
    assert_eq!(
        query(&relay, &cf("203.0.113.21")),
        429,
        "a forged header does not give a fresh key"
    );
    drop(relay);

    // Trusted peer, setting off: the header is not read, X-Forwarded-For is.
    let relay = TestServer::start(&settings(&BUCKET), Router::new());
    let mut c = relay.connect();
    let xff = |v: &str| format!("X-Forwarded-For: {v}\r\n");
    assert_eq!(
        exchange(
            &mut c,
            &format!(
                "GET /sbtp/v1/query HTTP/1.1\r\nHost: relay.test\r\n{}{}\r\n",
                xff("198.51.100.30"),
                cf("203.0.113.30")
            )
        )
        .status,
        200
    );
    assert_eq!(
        query(
            &relay,
            &format!("{}{}", xff("198.51.100.30"), cf("203.0.113.31"))
        ),
        429
    );
    drop(relay);

    log::flush();
    let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    for marker in ["203.0.113.", "2001:db8:", "198.51.100.", "::ffff:"] {
        for line in out.lines() {
            // The relay's own listen address and `trusted_proxies` settings are not clients.
            if line.contains("event=setting") || line.contains("event=listening") {
                continue;
            }
            assert!(!line.contains(marker), "{marker} in: {line}");
        }
    }
    let fallbacks: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("event=forwarded_invalid reason=client_ip_header"))
        .collect();
    assert_eq!(fallbacks.len(), 1, "throttled: {out}");
}
