//! The outbound client of replication (ADR 0048 rules 10, 14 and 19; ADR 0029; ADR 0030).
//!
//! A small HTTP/1.1 client for one request shape only: `GET` of a path under a configured peer
//! URL, no request body, no pool, no redirect following, keep-alive while the worker's turn
//! lasts (one connection per worker). The response head is parsed by `httparse` within
//! [`MAX_HEAD`] bytes and [`MAX_HEADERS`] fields; the body is framed by `Content-Length` or
//! `chunked` (RFC 9112 §6 and §7.1), or read to the close, and is never read past its ceiling.
//! A response with both framings, an unknown transfer coding, a content coding, conflicting
//! lengths or a `1xx` is a failed request.
//!
//! TLS: rustls with the `ring` provider, TLS 1.3 only, hostname verified by the `WebPKI`
//! verifier against the roots loaded once at start-up, no resumption, ALPN `http/1.1`.
//!
//! DNS is resolved per connection and every resolved address is checked before it is connected
//! to (rule 14); the connection goes to the checked address, so a name that changes between two
//! lookups cannot reach an address that was not checked.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::http::StatusCode;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::metrics::Failed;
use crate::peers::{Host, PeerUrl, refused_address};

/// Body ceilings of ADR 0029: `GET /block`.
pub const BLOCK_CEILING: usize = sbtp_core::layout::MAX_BLOCK_LEN;
/// `/query`.
pub const QUERY_CEILING: usize = 131_072;
/// Any `4xx` or `5xx` body.
pub const ERROR_CEILING: usize = 16_384;
/// At most this many resolved addresses are tried for one connection.
const MAX_ADDRESSES: usize = 8;
/// The largest response head, status line and fields.
pub const MAX_HEAD: usize = 16_384;
/// The most header fields of a response head.
pub const MAX_HEADERS: usize = 64;
/// The longest chunk-size line, extensions included.
const MAX_CHUNK_LINE: usize = 1_024;
/// The most trailer bytes of a chunked body.
const MAX_TRAILERS: usize = 16_384;
/// One read from the connection.
const READ_CHUNK: usize = 8_192;

/// A failed request (core spec §4, "Client bounds"): nothing from it is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fail {
    /// The metric label.
    pub kind: Failed,
    /// `Retry-After` in seconds, when the response had a valid one.
    pub retry_after: Option<u64>,
}

/// A [`Fail`] without `Retry-After`.
#[must_use]
pub fn fail(kind: Failed) -> Fail {
    Fail {
        kind,
        retry_after: None,
    }
}

/// A response that is not a failed request: a `2xx` with its body under the ceiling, a `404`,
/// or a `400` with its error body (`InvalidCursor`).
#[derive(Debug)]
pub struct Reply {
    /// The status code.
    pub status: StatusCode,
    /// The body; empty for a `404`.
    pub body: Bytes,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// One HTTP/1.1 connection to a peer. Dropping it closes the connection.
pub struct Conn {
    io: Box<dyn Io>,
    /// Bytes read and not yet used.
    buf: Vec<u8>,
    /// Whether the last response left the connection usable for another request.
    reusable: bool,
    /// Whether a request was already sent on it.
    used: bool,
}

/// The client, built once at start-up.
pub struct Client {
    tls: Option<tokio_rustls::TlsConnector>,
    allow_private: bool,
    timeout: Duration,
}

/// How the body of a response is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    Length(u64),
    Chunked,
    Close,
}

/// The parts of a response head the client uses.
#[derive(Debug)]
struct Head {
    status: u16,
    framing: Framing,
    retry_after: Option<u64>,
    coded: bool,
    close: bool,
}

/// Why a head could not be read.
enum HeadError {
    /// The connection ended before any byte of the response: a reused connection the peer had
    /// closed, which may be retried once on a new one.
    Closed,
    Fail(Fail),
}

impl Client {
    /// `tls` is `None` when every peer is a loopback `http` URL.
    #[must_use]
    pub fn new(
        tls: Option<Arc<rustls::ClientConfig>>,
        allow_private: bool,
        timeout: Duration,
    ) -> Self {
        Self {
            tls: tls.map(tokio_rustls::TlsConnector::from),
            allow_private,
            timeout,
        }
    }

    /// `GET {peer}{path}` with `Sbtp-Replication: 1`, over `conn` when it is usable, else over
    /// a new connection stored in `conn`. The whole request, connection and body included, is
    /// bounded by `replication_request_timeout_ms`. A `2xx` body is read up to `ceiling`.
    ///
    /// # Errors
    ///
    /// [`Fail`]: every other outcome. `conn` is closed after a failure.
    pub async fn get(
        &self,
        conn: &mut Option<Conn>,
        peer: &PeerUrl,
        path: &str,
        ceiling: usize,
    ) -> Result<Reply, Fail> {
        let done = tokio::time::timeout(self.timeout, self.exchange(conn, peer, path, ceiling))
            .await
            .unwrap_or(Err(fail(Failed::Timeout)));
        if done.is_err() || conn.as_ref().is_some_and(|c| !c.reusable) {
            *conn = None;
        }
        done
    }

    async fn exchange(
        &self,
        conn: &mut Option<Conn>,
        peer: &PeerUrl,
        path: &str,
        ceiling: usize,
    ) -> Result<Reply, Fail> {
        let request = request(peer, path);
        for _ in 0..2 {
            if conn.as_ref().is_none_or(|c| !c.reusable) {
                *conn = Some(self.connect(peer).await?);
            }
            let Some(c) = conn.as_mut() else {
                return Err(fail(Failed::Connect));
            };
            let reused = c.used;
            c.used = true;
            let sent = async {
                c.io.write_all(request.as_bytes()).await?;
                c.io.flush().await
            }
            .await;
            let head = match sent {
                Ok(()) => c.head().await,
                Err(_) => Err(HeadError::Closed),
            };
            match head {
                Ok(head) => return c.respond(head, ceiling).await,
                // Rule 11 does not cover a keep-alive close: one new connection, at once.
                Err(HeadError::Closed) if reused => *conn = None,
                Err(HeadError::Closed) => return Err(fail(Failed::Invalid)),
                Err(HeadError::Fail(f)) => return Err(f),
            }
        }
        Err(fail(Failed::Invalid))
    }

    /// A new connection: DNS per connection, each address checked (rule 14), TLS for `https`.
    async fn connect(&self, peer: &PeerUrl) -> Result<Conn, Fail> {
        let addrs: Vec<SocketAddr> = match peer.host() {
            // The operator wrote this address: never refused (rule 14).
            Host::Ip(ip) => vec![SocketAddr::new(*ip, peer.port())],
            Host::Name(name) => tokio::net::lookup_host((name.as_str(), peer.port()))
                .await
                .map_err(|_| fail(Failed::Connect))?
                .take(MAX_ADDRESSES)
                .collect(),
        };
        let literal = matches!(peer.host(), Host::Ip(_));
        let allowed: Vec<SocketAddr> = addrs
            .into_iter()
            .filter(|a| literal || self.allow_private || !refused_address(a.ip()))
            .collect();
        if allowed.is_empty() {
            return Err(fail(Failed::Address));
        }
        let mut tcp = None;
        for a in allowed {
            if let Ok(s) = TcpStream::connect(a).await {
                tcp = Some(s);
                break;
            }
        }
        let tcp = tcp.ok_or(fail(Failed::Connect))?;
        let _ = tcp.set_nodelay(true);
        let io: Box<dyn Io> = if peer.is_https() {
            let tls = self.tls.as_ref().ok_or(fail(Failed::Tls))?;
            let name = match peer.host() {
                Host::Ip(ip) => ServerName::from(*ip),
                Host::Name(n) => ServerName::try_from(n.clone()).map_err(|_| fail(Failed::Tls))?,
            };
            Box::new(
                tls.connect(name, tcp)
                    .await
                    .map_err(|_| fail(Failed::Tls))?,
            )
        } else {
            Box::new(tcp)
        };
        Ok(Conn {
            io,
            buf: Vec::new(),
            reusable: true,
            used: false,
        })
    }
}

impl Conn {
    /// Reads more bytes into `buf`; `Ok(0)` at the end of the stream. A TLS stream closed without
    /// `close_notify` reads as the end: every body this client reads is validated after.
    async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; READ_CHUNK];
        match self.io.read(&mut chunk).await {
            Ok(n) => {
                self.buf
                    .extend_from_slice(chunk.get(..n).unwrap_or_default());
                Ok(n)
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// The response head, within [`MAX_HEAD`] bytes and [`MAX_HEADERS`] fields.
    async fn head(&mut self) -> Result<Head, HeadError> {
        let invalid = || HeadError::Fail(fail(Failed::Invalid));
        loop {
            let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut resp = httparse::Response::new(&mut fields);
            match resp.parse(&self.buf) {
                Ok(httparse::Status::Complete(n)) => {
                    let head = parse_head(&resp);
                    self.buf.drain(..n.min(self.buf.len()));
                    return head.ok_or_else(invalid);
                }
                Ok(httparse::Status::Partial) => {}
                Err(_) => return Err(invalid()),
            }
            if self.buf.len() >= MAX_HEAD {
                return Err(HeadError::Fail(fail(Failed::TooLarge)));
            }
            match self.fill().await {
                Ok(0) | Err(_) if self.buf.is_empty() => return Err(HeadError::Closed),
                Ok(0) | Err(_) => return Err(invalid()),
                Ok(_) => {}
            }
        }
    }

    /// The reply to `head`: its body read within its ceiling, or the failure of its status.
    async fn respond(&mut self, head: Head, ceiling: usize) -> Result<Reply, Fail> {
        let retry_after = head.retry_after;
        let failed = |kind| Err(Fail { kind, retry_after });
        let ceiling = match head.status {
            200..=299 if head.coded => return failed(Failed::Invalid),
            200..=299 => ceiling,
            // A `404` is a skip and a `400` may name `InvalidCursor`: both are read, within
            // the error ceiling, so that the connection stays usable.
            400 | 404 => ERROR_CEILING,
            status => {
                // Not read: the connection is closed.
                self.reusable = false;
                return failed(match status {
                    300..=399 => Failed::Redirect,
                    429 => Failed::RateLimited,
                    502..=504 => Failed::Unavailable,
                    400..=499 => Failed::Client,
                    _ => Failed::Server,
                });
            }
        };
        let body = self.body(head.framing, ceiling).await;
        self.reusable = !head.close && head.framing != Framing::Close && body.is_ok();
        let status = StatusCode::from_u16(head.status).map_err(|_| fail(Failed::Invalid))?;
        match (head.status, body) {
            (200..=299, Ok(body)) => Ok(Reply {
                status,
                body: Bytes::from(body),
            }),
            (200..=299, Err(f)) => Err(f),
            // An error body over its ceiling is unparseable, not a failure (core spec §4).
            (_, body) => Ok(Reply {
                status,
                body: body.map(Bytes::from).unwrap_or_default(),
            }),
        }
    }

    /// The body, at most `ceiling` bytes: an announced length over it fails before any byte of
    /// the body is read, and reading stops at the first byte past it.
    async fn body(&mut self, framing: Framing, ceiling: usize) -> Result<Vec<u8>, Fail> {
        let too_large = || fail(Failed::TooLarge);
        let broken = || fail(Failed::Invalid);
        match framing {
            Framing::Length(n) => {
                let n = usize::try_from(n)
                    .ok()
                    .filter(|n| *n <= ceiling)
                    .ok_or_else(too_large)?;
                let mut out = Vec::with_capacity(n);
                self.take(&mut out, n).await?;
                Ok(out)
            }
            Framing::Close => {
                let mut out = Vec::new();
                loop {
                    let take = self.buf.len();
                    if out.len().saturating_add(take) > ceiling {
                        return Err(too_large());
                    }
                    out.append(&mut self.buf);
                    if self.fill().await.map_err(|_| broken())? == 0 {
                        return Ok(out);
                    }
                }
            }
            Framing::Chunked => {
                let mut out = Vec::new();
                loop {
                    let line = self.line(MAX_CHUNK_LINE).await?;
                    let size = chunk_size(&line).ok_or_else(broken)?;
                    if size == 0 {
                        break;
                    }
                    let size = usize::try_from(size)
                        .ok()
                        .filter(|s| out.len().saturating_add(*s) <= ceiling)
                        .ok_or_else(too_large)?;
                    self.take(&mut out, size).await?;
                    if !self.line(2).await?.is_empty() {
                        return Err(broken());
                    }
                }
                // Trailer fields, ignored, up to the empty line.
                let mut trailers = 0usize;
                loop {
                    let line = self.line(MAX_TRAILERS).await?;
                    if line.is_empty() {
                        return Ok(out);
                    }
                    trailers = trailers.saturating_add(line.len() + 2);
                    if trailers > MAX_TRAILERS {
                        return Err(too_large());
                    }
                }
            }
        }
    }

    /// Appends exactly `n` more bytes to `out`.
    async fn take(&mut self, out: &mut Vec<u8>, n: usize) -> Result<(), Fail> {
        let mut left = n;
        while left > 0 {
            if self.buf.is_empty() && self.fill().await.map_err(|_| fail(Failed::Invalid))? == 0 {
                return Err(fail(Failed::Invalid));
            }
            let k = left.min(self.buf.len());
            out.extend(self.buf.drain(..k));
            left -= k;
        }
        Ok(())
    }

    /// One line ending in CRLF, without it, of at most `max` bytes.
    async fn line(&mut self, max: usize) -> Result<Vec<u8>, Fail> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                if i > max {
                    return Err(fail(Failed::TooLarge));
                }
                let line: Vec<u8> = self.buf.drain(..i).collect();
                self.buf.drain(..2);
                return Ok(line);
            }
            if self.buf.len() > max.saturating_add(1) {
                return Err(fail(Failed::TooLarge));
            }
            if self.fill().await.map_err(|_| fail(Failed::Invalid))? == 0 {
                return Err(fail(Failed::Invalid));
            }
        }
    }
}

/// The head fields the client uses, or `None` (a failed request): a `1xx`, both `Content-Length`
/// and `Transfer-Encoding`, a transfer coding other than `chunked` alone, differing or invalid
/// lengths.
fn parse_head(resp: &httparse::Response<'_, '_>) -> Option<Head> {
    let status = resp.code?;
    if !(200..=599).contains(&status) {
        return None;
    }
    let (mut length, mut chunked, mut te, mut retry_after, mut coded, mut close) =
        (None::<u64>, false, 0usize, None, false, false);
    for h in resp.headers.iter() {
        let v = std::str::from_utf8(h.value).ok()?.trim();
        let name = h.name;
        if name.eq_ignore_ascii_case("content-length") {
            if v.is_empty() || v.len() > 19 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n: u64 = v.parse().ok()?;
            if length.is_some_and(|l| l != n) {
                return None;
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            te += 1;
            chunked = v.eq_ignore_ascii_case("chunked");
            if !chunked || te > 1 {
                return None;
            }
        } else if name.eq_ignore_ascii_case("retry-after") {
            retry_after = parse_retry_after(v);
        } else if name.eq_ignore_ascii_case("content-encoding") {
            coded |= !v.eq_ignore_ascii_case("identity");
        } else if name.eq_ignore_ascii_case("connection") {
            close |= v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"));
        }
    }
    let framing = match (length, chunked) {
        (Some(_), true) => return None,
        (Some(n), false) => Framing::Length(n),
        (None, true) => Framing::Chunked,
        (None, false) => Framing::Close,
    };
    // HTTP/1.0 has no keep-alive unless asked for, which this client does not do.
    close |= resp.version != Some(1);
    Some(Head {
        status,
        framing,
        retry_after,
        coded,
        close,
    })
}

/// The hexadecimal size of a chunk-size line, extensions ignored.
fn chunk_size(line: &[u8]) -> Option<u64> {
    let size = line.split(|b| *b == b';').next()?;
    let size = std::str::from_utf8(size)
        .ok()?
        .trim_end_matches([' ', '\t']);
    if size.is_empty() || size.len() > 15 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(size, 16).ok()
}

/// The request: origin form under the peer's path prefix, `Host`, `Sbtp-Replication: 1`
/// (rule 18), a fixed `User-Agent` without version (ADR 0019 rule 25), no content coding. Every
/// part comes from the configuration or from this module: the path prefix and host are
/// validated by [`PeerUrl::parse`], `path` is built from fixed text, digits, a hexadecimal
/// `block_id` and a cursor of the cursor syntax.
fn request(peer: &PeerUrl, path: &str) -> String {
    format!(
        "GET {}{path} HTTP/1.1\r\nHost: {}\r\nSbtp-Replication: 1\r\nUser-Agent: sbtp-relay\r\n\
         Accept-Encoding: identity\r\n\r\n",
        peer.path(),
        peer.authority()
    )
}

/// `Retry-After` as a number of seconds; any other form gives no delay (core spec §4).
fn parse_retry_after(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn retry_after_forms() {
        assert_eq!(parse_retry_after("7"), Some(7));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-1"), None);
        assert_eq!(parse_retry_after("1.5"), None);
        assert_eq!(parse_retry_after("99999999999999999999"), None);
        assert_eq!(parse_retry_after(""), None);
    }

    fn head(raw: &str) -> Option<Head> {
        let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut resp = httparse::Response::new(&mut fields);
        resp.parse(raw.as_bytes()).unwrap();
        parse_head(&resp)
    }

    #[test]
    fn heads_and_framing() {
        let h = head("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nRetry-After: 3\r\n\r\n").unwrap();
        assert_eq!(h.framing, Framing::Length(5));
        assert_eq!(h.retry_after, Some(3));
        assert!(!h.close && !h.coded);
        let h = head("HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n").unwrap();
        assert_eq!(h.framing, Framing::Chunked);
        assert_eq!(
            head("HTTP/1.1 200 OK\r\n\r\n").unwrap().framing,
            Framing::Close
        );
        assert!(
            head("HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n")
                .unwrap()
                .close
        );
        assert!(
            head("HTTP/1.1 200 OK\r\nConnection: keep-alive, close\r\n\r\n")
                .unwrap()
                .close
        );
        assert!(
            head("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n")
                .unwrap()
                .coded
        );
        for bad in [
            "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\n",
        ] {
            assert!(head(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn chunk_sizes() {
        assert_eq!(chunk_size(b"1a"), Some(26));
        assert_eq!(chunk_size(b"0;ext=1"), Some(0));
        assert_eq!(chunk_size(b"10 \t;x"), Some(16));
        assert_eq!(chunk_size(b""), None);
        assert_eq!(chunk_size(b"-1"), None);
        assert_eq!(chunk_size(b"0x10"), None);
        assert_eq!(chunk_size(&[b'f'; 16]), None);
    }

    /// Reads one response from `raw` with the conn machinery, as a test peer sends it.
    async fn read(raw: &'static [u8], ceiling: usize) -> Result<Reply, Fail> {
        let (mut a, b) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let _ = a.write_all(raw).await;
        });
        let mut c = Conn {
            io: Box::new(b),
            buf: Vec::new(),
            reusable: true,
            used: true,
        };
        let head = match c.head().await {
            Ok(h) => h,
            Err(HeadError::Fail(f)) => return Err(f),
            Err(HeadError::Closed) => return Err(fail(Failed::Connect)),
        };
        c.respond(head, ceiling).await
    }

    #[tokio::test]
    async fn bodies_are_bounded() {
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 3)
            .await
            .unwrap();
        assert_eq!(&r.body[..], b"abc");
        let r = read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n1;x\r\nc\r\n0\r\nT: 1\r\n\r\n", 3)
            .await
            .unwrap();
        assert_eq!(&r.body[..], b"abc");
        let too = |r: Result<Reply, Fail>| {
            matches!(
                r,
                Err(Fail {
                    kind: Failed::TooLarge,
                    ..
                })
            )
        };
        assert!(too(read(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd",
            3
        )
        .await));
        assert!(too(read(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",
            3
        )
        .await));
        assert!(too(read(b"HTTP/1.1 200 OK\r\n\r\nabcd", 3).await));
        // A truncated body is a failure, not a short body.
        assert!(
            read(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab", 4)
                .await
                .is_err()
        );
        let r = read(
            b"HTTP/1.1 429 Too Many\r\nRetry-After: 9\r\nContent-Length: 0\r\n\r\n",
            3,
        )
        .await;
        assert_eq!(
            r.unwrap_err(),
            Fail {
                kind: Failed::RateLimited,
                retry_after: Some(9)
            }
        );
        let r = read(
            b"HTTP/1.1 301 Moved\r\nLocation: http://x/\r\nContent-Length: 0\r\n\r\n",
            3,
        )
        .await;
        assert_eq!(r.unwrap_err().kind, Failed::Redirect);
        let r = read(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\na",
            3,
        )
        .await;
        assert_eq!(r.unwrap_err().kind, Failed::Invalid);
    }
}
