//! Client keys (ADR 0018 rule 20; ADR 0020 rules 6 to 10 and 26) and the per-client bound
//! (ADR 0019 rules 29 to 31).
//!
//! The counts live in memory only and are never logged with an address. An entry exists only while
//! its count is above 0; each counted unit is an open connection or a request in flight, so there
//! are at most `max_connections` entries (rule 31) and no eviction is needed.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::http::HeaderMap;

use crate::config::{Cidr, Settings};
use crate::limiter::Limiter;
use crate::log::Throttle;

/// A client key: an IPv4 address, the first `client_ipv6_prefix` bits of an IPv6 address, or the
/// exact address of a trusted peer for its requests without a client address. The prefix length
/// is part of the key, so a /128 key never equals a /64 key. Ordered only so that the limiter
/// can order keys by full time (ADR 0027 rule 2); the order means nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientKey {
    net: IpAddr,
    prefix: u8,
}

impl ClientKey {
    /// The overflow key of a full limiter table (ADR 0018 rule 21, ADR 0020 rule 24). Its prefix
    /// length is no real one, so it never equals the key of an address.
    pub const OVERFLOW: Self = Self {
        net: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        prefix: u8::MAX,
    };

    /// The bytes hashed into the client tag (ADR 0021 rule 13): family, prefix length, address.
    /// Never logged.
    pub(crate) fn tag_input(&self) -> [u8; 18] {
        let mut b = [0; 18];
        b[1] = self.prefix;
        match self.net {
            IpAddr::V4(a) => {
                b[0] = 4;
                b[2..6].copy_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                b[0] = 6;
                b[2..].copy_from_slice(&a.octets());
            }
        }
        b
    }
}

/// An IPv4-mapped IPv6 address as IPv4 (ADR 0018 rule 20).
#[must_use]
pub fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// The outcome of reading `X-Forwarded-For` (ADR 0020 rule 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forwarded {
    /// The rightmost address that is not in `trusted_proxies`, normalised (rule 8).
    Client(IpAddr),
    /// Case (a): no header, or only empty elements and trusted addresses.
    Absent,
    /// Case (b): an element that is not an address (`unknown`, a host name...) ended the search.
    Unreadable,
}

/// One element of the `X-Forwarded-For` list (ADR 0020 rule 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Element {
    Empty,
    Addr(IpAddr),
    Invalid,
}

/// ADR 0022 rule 2: an element with a byte outside visible ASCII, space and horizontal tab is
/// invalid; any other element is read by [`parse_element`].
fn parse_raw_element(item: &[u8]) -> Element {
    let readable = |b: &u8| matches!(b, 0x21..=0x7e | b' ' | b'\t');
    match std::str::from_utf8(item) {
        Ok(s) if item.iter().all(readable) => parse_element(s),
        _ => Element::Invalid,
    }
}

/// ADR 0020 rule 7: a bare IPv4 or IPv6 address, `ipv4:port` or `[ipv6]:port`, once spaces and
/// tabs are removed at both ends. The standard library parsers refuse leading zeros, hexadecimal
/// IPv4 parts and zone identifiers (tested below). A port is 1 to 5 digits of at most 65,535:
/// digits only, because `u16::from_str` accepts a `+` sign. The address is normalised here, once
/// (rule 8).
fn parse_element(item: &str) -> Element {
    let item = item.trim_matches(|c| c == ' ' || c == '\t');
    if item.is_empty() {
        return Element::Empty;
    }
    let is_port =
        |p: &str| p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok();
    let addr = if let Ok(ip) = item.parse::<IpAddr>() {
        Some(ip)
    } else if let Some(rest) = item.strip_prefix('[') {
        rest.split_once("]:")
            .filter(|(_, port)| is_port(port))
            .and_then(|(a, _)| a.parse::<Ipv6Addr>().ok())
            .map(IpAddr::V6)
    } else {
        item.split_once(':')
            .filter(|(_, port)| is_port(port))
            .and_then(|(a, _)| a.parse::<Ipv4Addr>().ok())
            .map(IpAddr::V4)
    };
    addr.map_or(Element::Invalid, |ip| Element::Addr(normalise(ip)))
}

/// The settings of rules 29 to 31, and the throttles of the lines they cause.
#[derive(Debug)]
pub struct ClientPolicy {
    /// `trusted_proxies`.
    pub trusted_proxies: Vec<Cidr>,
    /// `rate_limit_exempt`.
    pub exempt: Vec<Cidr>,
    /// `client_ipv6_prefix`.
    pub ipv6_prefix: u8,
    /// `max_connections_per_client`.
    pub max_per_client: u32,
    /// ADR 0020 rule 11: a trusted proxy wrote an element that is not an address.
    pub(crate) unreadable_log: Throttle,
    /// ADR 0020 rule 11: a request without a client address was refused.
    pub(crate) unaddressed_log: Throttle,
}

impl ClientPolicy {
    /// A policy from its four settings.
    #[must_use]
    pub fn new(trusted_proxies: Vec<Cidr>, exempt: Vec<Cidr>, ipv6_prefix: u8, max: u32) -> Self {
        Self {
            trusted_proxies,
            exempt,
            ipv6_prefix,
            max_per_client: max,
            unreadable_log: Throttle::default(),
            unaddressed_log: Throttle::default(),
        }
    }

    /// The policy of `s`. Every value is in range after [`Settings::load`].
    #[must_use]
    pub fn from_settings(s: &Settings) -> Self {
        Self::new(
            s.trusted_proxies.clone(),
            s.rate_limit_exempt.clone(),
            u8::try_from(s.client_ipv6_prefix).unwrap_or(64),
            u32::try_from(s.max_connections_per_client).unwrap_or(u32::MAX),
        )
    }

    /// Whether `ip` is in `trusted_proxies`.
    #[must_use]
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusts(normalise(ip))
    }

    /// [`Self::is_trusted`] for an address already normalised.
    fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|c| c.contains(ip))
    }

    /// The client key of address `ip`, or `None` when the address is in `rate_limit_exempt`
    /// (rule 31: an exempt key skips the per-client bound). Exemption is tested on the address,
    /// before the IPv6 aggregation (ADR 0020 rule 26).
    #[must_use]
    pub fn key(&self, ip: IpAddr) -> Option<ClientKey> {
        self.forwarded_key(normalise(ip))
    }

    /// The key of a request from the trusted peer `ip` that carries no client address
    /// (ADR 0020 rule 10): the peer's exact address, never its /64, so that such requests do not
    /// share a count with real clients in the proxy's /64. `None` when the address is exempt.
    #[must_use]
    pub fn proxy_key(&self, ip: IpAddr) -> Option<ClientKey> {
        let ip = normalise(ip);
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        self.key_of(ip, prefix)
    }

    /// The key of the normalised address `ip` aggregated to `prefix` bits, unless it is exempt.
    fn key_of(&self, ip: IpAddr, prefix: u8) -> Option<ClientKey> {
        if self.exempt.iter().any(|c| c.contains(ip)) {
            return None;
        }
        Some(ClientKey {
            net: Cidr { addr: ip, prefix }.network(),
            prefix,
        })
    }

    /// The key of a client address returned by [`Self::forwarded_client`], already normalised.
    pub(crate) fn forwarded_key(&self, ip: IpAddr) -> Option<ClientKey> {
        let prefix = if ip.is_ipv4() { 32 } else { self.ipv6_prefix };
        self.key_of(ip, prefix)
    }

    /// ADR 0020 rules 6 to 9, for a request from a trusted peer. All `X-Forwarded-For` field
    /// lines form one list, read from the right: empty elements and addresses in
    /// `trusted_proxies` are stepped over, and the first other address is the client. An invalid
    /// element (`unknown` included) ends the search, because the elements on its left may have
    /// been written by the client. Each line is split at commas on its raw bytes first; an element
    /// with a byte outside visible ASCII, space and tab is one invalid element, and the other
    /// elements of its line are read as usual (ADR 0022, which amends rule 7). No other header
    /// (`Forwarded`, `X-Real-IP`) is read.
    #[must_use]
    pub fn forwarded_client(&self, headers: &HeaderMap) -> Forwarded {
        for line in headers.get_all("x-forwarded-for").iter().rev() {
            for item in line.as_bytes().rsplit(|&b| b == b',') {
                match parse_raw_element(item) {
                    Element::Empty => {}
                    Element::Addr(ip) if self.trusts(ip) => {}
                    Element::Addr(ip) => return Forwarded::Client(ip),
                    Element::Invalid => return Forwarded::Unreadable,
                }
            }
        }
        Forwarded::Absent
    }
}

/// Open connections or requests in flight per client key, bounded by `max`.
#[derive(Debug)]
pub struct Counts {
    max: u32,
    map: Mutex<HashMap<ClientKey, u32>>,
    /// The limiter told of each unit, so that it never drops an entry with a unit in flight (ADR
    /// 0019 rule 31, ADR 0027 rule 4). `None` for counts outside rules 29 and 30.
    limiter: Option<Arc<Limiter>>,
}

/// One counted unit; the count is decremented when it is dropped.
#[derive(Debug)]
pub struct Slot {
    counts: Arc<Counts>,
    key: ClientKey,
}

impl Counts {
    /// An empty table with a bound of `max` per key.
    #[must_use]
    pub fn new(max: u32) -> Arc<Self> {
        Arc::new(Self {
            max,
            map: Mutex::new(HashMap::new()),
            limiter: None,
        })
    }

    /// The counts of ADR 0019 rules 29 and 30: as [`Counts::new`], and each unit pins its key in
    /// `limiter` while it lasts (rule 31).
    #[must_use]
    pub fn pinning(max: u32, limiter: Arc<Limiter>) -> Arc<Self> {
        Arc::new(Self {
            max,
            map: Mutex::new(HashMap::new()),
            limiter: Some(limiter),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<ClientKey, u32>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts one more unit for `key`, or `None` if `key` already holds `max`.
    #[must_use]
    pub fn try_acquire(self: &Arc<Self>, key: ClientKey) -> Option<Slot> {
        {
            let mut map = self.lock();
            let n = map.entry(key).or_insert(0);
            if *n >= self.max {
                return None;
            }
            *n += 1;
        }
        // Outside the lock of the counts: the two locks are never held together. The pin comes
        // before the slot exists, so its release always follows it.
        if let Some(l) = &self.limiter {
            l.pin(key);
        }
        Some(Slot {
            counts: Arc::clone(self),
            key,
        })
    }

    /// Number of keys with a count above 0.
    #[must_use]
    pub fn keys(&self) -> usize {
        self.lock().len()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        {
            let mut map = self.counts.lock();
            if let Some(n) = map.get_mut(&self.key) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&self.key);
                }
            }
        }
        if let Some(l) = &self.counts.limiter {
            l.unpin(self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use axum::http::HeaderValue;

    fn policy(trusted: &[&str], exempt: &[&str]) -> ClientPolicy {
        let cidrs = |l: &[&str]| {
            l.iter()
                .map(|s| {
                    let (a, p) = s.split_once('/').unwrap();
                    Cidr {
                        addr: a.parse().unwrap(),
                        prefix: p.parse().unwrap(),
                    }
                })
                .collect()
        };
        ClientPolicy::new(cidrs(trusted), cidrs(exempt), 64, 2)
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn keys_aggregate_ipv6_per_prefix_and_map_ipv4() {
        let p = policy(&[], &["192.0.2.0/24"]);
        assert_eq!(p.key(ip("2001:db8::1")), p.key(ip("2001:db8::ffff:2")));
        assert_ne!(p.key(ip("2001:db8::1")), p.key(ip("2001:db8:0:1::1")));
        assert_eq!(p.key(ip("::ffff:198.51.100.7")), p.key(ip("198.51.100.7")));
        assert_eq!(p.key(ip("192.0.2.9")), None, "exempt");
        assert_eq!(p.key(ip("::ffff:192.0.2.9")), None, "exempt, mapped");
        // The fallback key of a proxy is its exact address, never its /64, even at the /64's
        // network address.
        assert_ne!(p.proxy_key(ip("2001:db8::")), p.key(ip("2001:db8::5")));
        assert_ne!(
            p.proxy_key(ip("2001:db8::1")),
            p.proxy_key(ip("2001:db8::2"))
        );
        assert_eq!(
            p.proxy_key(ip("::ffff:198.51.100.7")),
            p.key(ip("198.51.100.7"))
        );
        assert_eq!(p.proxy_key(ip("192.0.2.9")), None, "exempt");
    }

    /// ADR 0020 rules 20 and 26: exemption and trust are tested on the address, not on its /64,
    /// and an IPv6 block never matches an IPv4 or IPv4-mapped address.
    #[test]
    fn exemption_and_trust_are_tested_before_aggregation() {
        let p = policy(&["2001:db8::1/128"], &["2001:db8::1/128"]);
        assert_eq!(p.key(ip("2001:db8::1")), None);
        assert!(p.key(ip("2001:db8::2")).is_some(), "same /64, not exempt");
        assert!(p.is_trusted(ip("2001:db8::1")));
        assert!(!p.is_trusted(ip("2001:db8::2")), "same /64, not trusted");
        let p = policy(&["::/1"], &["::/1"]);
        assert!(!p.is_trusted(ip("::ffff:192.0.2.1")));
        assert!(p.key(ip("::ffff:192.0.2.1")).is_some());
    }

    /// ADR 0020 rule 7, one case per row of its table, and the forms named in the ADR.
    #[test]
    fn element_forms() {
        use Element::{Addr, Empty, Invalid};
        for (item, want) in [
            ("", Empty),
            (" \t ", Empty),
            ("203.0.113.7", Addr(ip("203.0.113.7"))),
            (" 203.0.113.7\t", Addr(ip("203.0.113.7"))),
            ("2001:db8::1", Addr(ip("2001:db8::1"))),
            ("2001:DB8::1", Addr(ip("2001:db8::1"))),
            ("::ffff:203.0.113.7", Addr(ip("203.0.113.7"))),
            ("203.0.113.7:4711", Addr(ip("203.0.113.7"))),
            ("203.0.113.7:65535", Addr(ip("203.0.113.7"))),
            ("[2001:db8::1]:4711", Addr(ip("2001:db8::1"))),
            ("[::ffff:203.0.113.7]:1", Addr(ip("203.0.113.7"))),
            ("unknown", Invalid),
            ("_hidden", Invalid),
            ("\"203.0.113.7\"", Invalid),
            ("[2001:db8::1]", Invalid),
            ("203.000.113.007", Invalid),
            ("0xcb.0.113.7", Invalid),
            ("fe80::1%eth0", Invalid),
            ("[fe80::1%eth0]:80", Invalid),
            ("relay.example", Invalid),
            ("203.0.113.7:65536", Invalid),
            ("203.0.113.7:000001", Invalid),
            ("203.0.113.7:+1", Invalid),
            ("203.0.113.7:", Invalid),
            ("[2001:db8::1]:", Invalid),
            ("[203.0.113.7]:80", Invalid),
            ("203.0.113.7:80:80", Invalid),
        ] {
            assert_eq!(parse_element(item), want, "{item:?}");
        }
    }

    /// ADR 0020 rules 6 and 9.
    #[test]
    fn forwarded_client_is_the_rightmost_untrusted_address() {
        use Forwarded::{Absent, Client, Unreadable};
        let p = policy(&["10.0.0.0/8", "2001:db8:ff::/48"], &[]);
        let client = |values: &[&[u8]]| {
            let mut m = HeaderMap::new();
            for v in values {
                m.append("x-forwarded-for", HeaderValue::from_bytes(v).unwrap());
            }
            p.forwarded_client(&m)
        };
        let c = |s| Client(ip(s));
        assert_eq!(client(&[]), Absent);
        assert_eq!(client(&[b""]), Absent);
        assert_eq!(client(&[b"10.0.0.3, ,"]), Absent);
        assert_eq!(
            client(&[b"203.0.113.9, 198.51.100.7, 10.0.0.2"]),
            c("198.51.100.7")
        );
        // Several lines form one list; the last line is on the right.
        assert_eq!(
            client(&[b"203.0.113.9", b"198.51.100.7"]),
            c("198.51.100.7")
        );
        assert_eq!(
            client(&[b"203.0.113.9, 198.51.100.7", b"10.0.0.2", b""]),
            c("198.51.100.7")
        );
        // A trailing comma and empty elements are ignored.
        assert_eq!(client(&[b"198.51.100.7,"]), c("198.51.100.7"));
        assert_eq!(client(&[b"198.51.100.7, , 10.0.0.2,,"]), c("198.51.100.7"));
        // Ports are dropped, IPv6 included; trusted proxies with a port are stepped over.
        assert_eq!(
            client(&[b"[2001:db8::1]:4711, 10.0.0.2:80"]),
            c("2001:db8::1")
        );
        assert_eq!(
            client(&[b"198.51.100.7:4711, [2001:db8:ff::1]:443"]),
            c("198.51.100.7")
        );
        assert_eq!(
            client(&[b"[::ffff:10.0.0.9]:1, ::ffff:198.51.100.7"]),
            c("198.51.100.7")
        );
        // `unknown` on the right of a forged address ends the search (case b).
        assert_eq!(client(&[b"198.51.100.66, unknown"]), Unreadable);
        assert_eq!(client(&[b"198.51.100.66, unknown, 10.0.0.2"]), Unreadable);
        assert_eq!(client(&[b"198.51.100.66", b"unknown"]), Unreadable);
        // `unknown` on the left of the client is never read.
        assert_eq!(
            client(&[b"unknown, 198.51.100.7, 10.0.0.2"]),
            c("198.51.100.7")
        );
        assert_eq!(client(&[b"unknown", b"198.51.100.7"]), c("198.51.100.7"));
        // ADR 0022: a byte outside visible ASCII invalidates its element, not its line.
        // A client's `\xff` before the address its proxy appended does not hide that address.
        assert_eq!(client(&[b"\xff, 203.0.113.7"]), c("203.0.113.7"));
        assert_eq!(
            client(&[b"\xff\x80,203.0.113.7, 10.0.0.2"]),
            c("203.0.113.7")
        );
        // A non-ASCII element met first ends the search (proxy key, rule 11 warning).
        assert_eq!(client(&[b"203.0.113.7, \xff"]), Unreadable);
        // In a multi-line list, only that element is affected.
        assert_eq!(client(&[b"198.51.100.66", b"10.0.0.2\xff"]), Unreadable);
        assert_eq!(
            client(&[b"10.0.0.2\xff", b"198.51.100.7"]),
            c("198.51.100.7")
        );
        assert_eq!(
            client(&[b"198.51.100.66", b"\xff, 198.51.100.7", b"10.0.0.2"]),
            c("198.51.100.7")
        );
        assert_eq!(
            client(&[b"198.51.100.66", b"198.51.100.7, 10.0.0.2\xe9", b"10.0.0.3"]),
            Unreadable
        );
        // `Forwarded` and `X-Real-IP` are never read.
        let mut other = HeaderMap::new();
        other.insert("forwarded", HeaderValue::from_static("for=198.51.100.7"));
        other.insert("x-real-ip", HeaderValue::from_static("198.51.100.7"));
        assert_eq!(p.forwarded_client(&other), Absent);
    }

    #[test]
    fn counts_bound_and_release() {
        let counts = Counts::new(2);
        let policy = policy(&[], &[]);
        let k = policy.key(ip("192.0.2.1")).unwrap();
        let other = policy.key(ip("192.0.2.2")).unwrap();
        let a = counts.try_acquire(k).unwrap();
        let b = counts.try_acquire(k).unwrap();
        assert!(counts.try_acquire(k).is_none());
        let c = counts.try_acquire(other).unwrap();
        drop(a);
        let a = counts.try_acquire(k).unwrap();
        drop((a, b, c));
        assert_eq!(counts.keys(), 0, "no entry is left at count 0");
    }
}
