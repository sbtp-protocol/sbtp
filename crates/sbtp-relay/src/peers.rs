//! Replication peers and their settings (ADR 0048 rules 5, 9, 14 to 16 and 20). Always compiled,
//! so that a build without the `replication` feature still reads and refuses `peers` (rule 3,
//! item 1); the replication itself is [`crate::replication`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The host of a peer URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    /// A DNS name, lowercase, resolved per connection (rule 14).
    Name(String),
    /// A literal address: the operator chose this address, so it is never refused (rule 14).
    Ip(IpAddr),
}

/// A peer's relay URL (rule 20, ADR 0040 rule 4), normalised (RFC 3986 §6.2.2 and §6.2.3):
/// lowercase scheme and host, no default port, no trailing `/`. Only `https`, or `http` for a
/// loopback host (rule 14, tests). No userinfo, query, fragment, percent-encoding, empty, `.` or
/// `..` path segment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerUrl {
    https: bool,
    host: Host,
    port: u16,
    /// The path prefix of the relay URL, empty or starting with `/`, without a trailing `/`.
    path: String,
    text: String,
}

impl PeerUrl {
    /// Parses and normalises `s`.
    ///
    /// # Errors
    ///
    /// A text for the operator, naming what is wrong.
    pub fn parse(s: &str) -> Result<Self, String> {
        // Security review 2026-11-21 I-2: a userinfo part is never printed back.
        let shown = redact_userinfo(s);
        let bad = |why: &str| format!("`{shown}`: {why}");
        let lower = s.get(..8).map(str::to_ascii_lowercase).unwrap_or_default();
        let (https, rest) = if lower == "https://" {
            (true, s.get(8..).unwrap_or_default())
        } else if lower.get(..7) == Some("http://") {
            (false, s.get(7..).unwrap_or_default())
        } else {
            return Err(bad("expected an absolute https URL (ADR 0048 rule 14)"));
        };
        if rest.contains(['?', '#']) {
            return Err(bad("a relay URL has no query or fragment"));
        }
        let (authority, path) = rest.find('/').map_or((rest, ""), |i| {
            (
                rest.get(..i).unwrap_or_default(),
                rest.get(i..).unwrap_or_default(),
            )
        });
        if authority.contains('@') {
            return Err(bad("a relay URL has no userinfo"));
        }
        let (host, port) = split_authority(authority).map_err(|w| bad(&w))?;
        let port = match port {
            None => {
                if https {
                    443
                } else {
                    80
                }
            }
            Some(p) => Some(p)
                .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|p| *p != 0)
                .ok_or_else(|| bad("invalid port"))?,
        };
        let host = parse_host(host).map_err(|w| bad(&w))?;
        if !https && !is_loopback_host(&host) {
            return Err(bad(
                "http is allowed for a loopback host only; a peer URL is https (ADR 0048 rule 14)",
            ));
        }
        let path = normalise_path(path).map_err(|w| bad(&w))?;
        let scheme = if https { "https" } else { "http" };
        let default_port = if https { 443 } else { 80 };
        let host_text = match &host {
            Host::Name(n) => n.clone(),
            Host::Ip(IpAddr::V4(a)) => a.to_string(),
            Host::Ip(IpAddr::V6(a)) => format!("[{a}]"),
        };
        let text = if port == default_port {
            format!("{scheme}://{host_text}{path}")
        } else {
            format!("{scheme}://{host_text}:{port}{path}")
        };
        Ok(Self {
            https,
            host,
            port,
            path,
            text,
        })
    }

    /// Whether the scheme is `https`.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// The host.
    #[must_use]
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The port (443 or 80 when the URL has none).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path prefix, empty or starting with `/`, without a trailing `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The `Host` header value: the host, with the port when it is not the default.
    #[must_use]
    pub fn authority(&self) -> &str {
        let start = if self.https { 8 } else { 7 };
        let end = self.text.len() - self.path.len();
        self.text.get(start..end).unwrap_or_default()
    }

    /// The normalised URL, the key of the peer's cursor row (rule 8).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for PeerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// `host[:port]` or `[v6][:port]`.
fn split_authority(a: &str) -> Result<(&str, Option<&str>), String> {
    if let Some(rest) = a.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "unclosed `[` in the host".to_owned())?;
        return match after {
            "" => Ok((host, None)),
            p => p
                .strip_prefix(':')
                .map(|p| (host, Some(p)))
                .ok_or_else(|| "invalid characters after the IPv6 address".to_owned()),
        };
    }
    Ok(match a.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (a, None),
    })
}

/// A DNS name of letters, digits and `-` in labels of 1 to 63 bytes (253 at most), or an IPv4
/// literal in dotted-decimal form, or the content of an IPv6 literal. A name whose last label is
/// numeric and that is not a dotted-decimal IPv4 address (`127.1`, `0x7f.0.0.1` is a name) is
/// refused: resolvers read such forms as addresses.
fn parse_host(h: &str) -> Result<Host, String> {
    if h.contains(':') {
        let a: Ipv6Addr = h.parse().map_err(|_| "invalid IPv6 address".to_owned())?;
        return Ok(Host::Ip(IpAddr::V6(a)));
    }
    let lower = h.to_ascii_lowercase();
    if lower.is_empty() || lower.len() > 253 {
        return Err("invalid host".to_owned());
    }
    if lower.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let a: Ipv4Addr = lower
            .parse()
            .map_err(|_| "invalid IPv4 address".to_owned())?;
        return Ok(Host::Ip(IpAddr::V4(a)));
    }
    let labels: Vec<&str> = lower.trim_end_matches('.').split('.').collect();
    let label_ok = |l: &&str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    if !labels.iter().all(label_ok) {
        return Err("invalid host name".to_owned());
    }
    if labels
        .last()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(
            "a host name whose last label is numeric is not a valid name or address".into(),
        );
    }
    Ok(Host::Name(labels.join(".")))
}

/// Path segments of unreserved and sub-delimiter characters, `:` and `@`; no `%`, no empty, `.`
/// or `..` segment. The trailing `/` is dropped.
fn normalise_path(p: &str) -> Result<String, String> {
    let p = p.strip_suffix('/').unwrap_or(p);
    if p.is_empty() {
        return Ok(String::new());
    }
    let ok = |b: u8| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@".contains(&b);
    for seg in p.split('/').skip(1) {
        if seg.is_empty() || seg == "." || seg == ".." || !seg.bytes().all(ok) {
            return Err("invalid path (no %, empty, `.` or `..` segment)".to_owned());
        }
    }
    Ok(p.to_owned())
}

fn is_loopback_host(h: &Host) -> bool {
    match h {
        Host::Ip(a) => a.is_loopback(),
        Host::Name(n) => n == "localhost",
    }
}

/// `s` with everything from the scheme's `//` to its last `@`, if any, replaced by `***`
/// (security review 2026-11-21 I-2): an error names the URL without its credentials. The authority
/// is not delimited first, because a password may hold `/`, `?` or `#`; a peer URL never needs an
/// `@`, so hiding a path that holds one costs only a less precise error.
fn redact_userinfo(s: &str) -> String {
    let start = s.find("://").map_or(0, |i| i + 3);
    let rest = s.get(start..).unwrap_or_default();
    match rest.rfind('@') {
        Some(at) => format!(
            "{}***{}",
            s.get(..start).unwrap_or_default(),
            rest.get(at..).unwrap_or_default()
        ),
        None => s.to_owned(),
    }
}

/// ADR 0048 rule 14: whether a resolved address is refused by default: loopback, private
/// (RFC 1918, RFC 4193), shared (RFC 6598, where some clouds serve metadata), link-local (cloud
/// metadata addresses included), unspecified, multicast, broadcast or reserved. An IPv4-mapped
/// or NAT64 (`64:ff9b::/96`) address is judged by the IPv4 address it carries.
#[must_use]
pub fn refused_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => refused_v4(a),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return refused_v4(v4);
            }
            let s = a.segments();
            let v4 = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [.., hi, lo] = s;
                return refused_v4(v4(hi, lo));
            }
            // Security review 2026-11-21 I-1. `64:ff9b:1::/48` (RFC 8215): local-use NAT64, whose
            // mapping to IPv4 is the local network's choice, so it is refused outright.
            if s[..3] == [0x64, 0xff9b, 1] {
                return true;
            }
            // `2002::/16` (6to4, RFC 3056): judged by the IPv4 address in bits 16 to 47.
            if s[0] == 0x2002 {
                return refused_v4(v4(s[1], s[2]));
            }
            // `2001::/32` (Teredo, RFC 4380): judged by the server address (bits 32 to 63) and
            // the client address (the last 32 bits, inverted); refused if either is.
            if s[..2] == [0x2001, 0] {
                return refused_v4(v4(s[2], s[3])) || refused_v4(v4(!s[6], !s[7]));
            }
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                // fc00::/7 unique local (RFC 4193), fe80::/10 link-local, fec0::/10 site-local.
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                // ::/96 IPv4-compatible (deprecated).
                || s[..6] == [0; 6]
        }
    }
}

fn refused_v4(a: Ipv4Addr) -> bool {
    let [o0, o1, o2, _] = a.octets();
    a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_multicast()
        || a.is_broadcast()
        // 0.0.0.0/8 "this network", 100.64.0.0/10 shared (RFC 6598), 240.0.0.0/4 reserved.
        || o0 == 0
        || (o0 == 100 && (o1 & 0xc0) == 64)
        || o0 >= 240
        // Security review 2026-11-21 I-1: 192.0.0.0/24 IETF protocol assignments (RFC 6890),
        // 198.18.0.0/15 benchmarking (RFC 2544).
        || (o0 == 192 && o1 == 0 && o2 == 0)
        || (o0 == 198 && (o1 & 0xfe) == 18)
}

/// `replication_start` (rule 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplicationStart {
    /// From the time the peer was first seen, minus `replication_resync_margin_ms`. The default.
    Now,
    /// The full history (an archive relay).
    All,
}

impl ReplicationStart {
    /// The names, in the file and the environment.
    pub const NAMES: &'static [&'static str] = &["now", "all"];

    /// The name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Now => "now",
            Self::All => "all",
        }
    }

    /// Parses a name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "now" => Some(Self::Now),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

/// ADR 0048 rule 16, estimates: per request in flight, a `/query` body, a block, the identifiers
/// of a page and the TLS and HTTP state of one connection.
pub const EST_REPLICATION_PER_REQUEST: u64 = 131_072 + 65_909 + 32_000 + 90_000;
/// ADR 0048 rule 16: the root store, loaded once.
pub const EST_ROOT_STORE: u64 = 400_000;
/// ADR 0048 rule 16: the state of one peer.
pub const EST_PEER_STATE: u64 = 1_024;

/// The terms of ADR 0048 rule 16, in bytes.
#[must_use]
pub fn memory_bytes(max_in_flight: u64, max_peers: u64) -> u64 {
    max_in_flight
        .saturating_mul(EST_REPLICATION_PER_REQUEST)
        .saturating_add(EST_ROOT_STORE)
        .saturating_add(max_peers.saturating_mul(EST_PEER_STATE))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn peer_urls_are_normalised() {
        let n = |s: &str| PeerUrl::parse(s).unwrap().as_str().to_owned();
        assert_eq!(n("HTTPS://Relay.Example/"), "https://relay.example");
        assert_eq!(n("https://relay.example:443"), "https://relay.example");
        assert_eq!(
            n("https://relay.example:8443/a/b/"),
            "https://relay.example:8443/a/b"
        );
        assert_eq!(n("https://[2001:DB8::1]:443"), "https://[2001:db8::1]");
        assert_eq!(n("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
        assert_eq!(n("http://[::1]:80/"), "http://[::1]");
        let u = PeerUrl::parse("https://relay.example:8443/p").unwrap();
        assert_eq!(u.authority(), "relay.example:8443");
        assert_eq!(u.path(), "/p");
        assert_eq!(u.port(), 8443);
        let u = PeerUrl::parse("https://relay.example").unwrap();
        assert_eq!(u.authority(), "relay.example");
        assert_eq!(u.path(), "");
    }

    #[test]
    fn bad_peer_urls_are_refused() {
        for s in [
            "ftp://relay.example",
            "relay.example",
            "http://relay.example",
            "http://10.0.0.1",
            "https://user@relay.example",
            "https://relay.example/?a=b",
            "https://relay.example/#f",
            "https://relay.example:0",
            "https://relay.example:65536",
            "https://relay.example:+1",
            "https://relay.example:",
            "https://relay..example",
            "https://-relay.example",
            "https://127.1",
            "https://300.0.0.1",
            "https://relay.example/a/../b",
            "https://relay.example/a//b",
            "https://relay.example/%2e",
            "https://[::1",
            "https://[::1]x",
            "https://",
        ] {
            assert!(PeerUrl::parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn refused_addresses() {
        for a in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "::1",
            "::",
            "fd00:ec2::254",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "::10.0.0.1",
            // Security review 2026-11-21 I-1.
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "64:ff9b:1::808:808",
            "2002:a00:1::1",
            "2002:a9fe:a9fe::",
            "2001:0:808:808::f5ff:fffe",
            "2001:0:a00:1::f7f7:f7f7",
        ] {
            assert!(refused_address(a.parse().unwrap()), "{a}");
        }
        for a in [
            "192.0.2.1",
            "8.8.8.8",
            "2001:db8::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "192.0.1.1",
            "198.20.0.1",
            "2002:808:808::1",
            "2001:0:808:808::f7f7:f7f7",
        ] {
            assert!(!refused_address(a.parse().unwrap()), "{a}");
        }
    }

    /// Security review 2026-11-21 I-2: a URL with userinfo is refused, and the error never shows
    /// the userinfo.
    #[test]
    fn userinfo_is_refused_and_never_printed() {
        for s in [
            "https://user:hunter2@relay.example",
            "https://hunter2@relay.example/sbtp",
            "http://user:hunter2@127.0.0.1:8080",
            "ftp://user:hunter2@relay.example",
            "https://a@b:hunter2@relay.example",
            // A password holding `/`, `?` or `#` (a base64 token can hold `/`).
            "https://user:hun/ter2@relay.example",
            "https://user:hun?ter2@relay.example/sbtp",
            "https://user:hun#ter2@relay.example",
            "https://user:hunter2/x?y#z@relay.example/p@q",
        ] {
            let e = PeerUrl::parse(s).unwrap_err();
            assert!(
                !e.contains("hun") && !e.contains("ter2") && !e.contains("user:"),
                "{e}"
            );
            assert!(e.contains("***@"), "{e}");
        }
        assert_eq!(
            redact_userinfo("https://user:hun/ter2@relay.example"),
            "https://***@relay.example"
        );
        assert_eq!(
            redact_userinfo("https://relay.example/sbtp"),
            "https://relay.example/sbtp"
        );
        // An `@` in the path hides what comes before it: less precise, never a leak.
        assert_eq!(
            redact_userinfo("https://relay.example/a@b"),
            "https://***@b"
        );
    }

    /// ADR 0048 rule 16: 723,077 bytes on `small`.
    #[test]
    fn small_replication_terms() {
        assert_eq!(memory_bytes(1, 4), 723_077);
    }
}
