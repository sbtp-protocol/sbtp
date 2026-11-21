//! The outbound client of replication (ADR 0048 rules 10, 14 and 19; ADR 0029; ADR 0030).
//!
//! hyper's low-level HTTP/1.1 client (`hyper::client::conn::http1`): no pool, no redirect
//! following, one connection per worker, open only while the worker's turn lasts. The response
//! head is bounded by hyper ([`MAX_HEAD`] bytes, [`MAX_HEADERS`] fields, a read buffer of
//! [`MAX_BUF`]); the body is never read past its ceiling. A `3xx` is a failed request, never
//! followed; a response with a content coding is a failed request (none is asked for).
//!
//! TLS: rustls with the `ring` provider, TLS 1.3 only, hostname verified by rustls's `WebPKI`
//! verifier against the roots loaded once at start-up, no resumption, ALPN `http/1.1`.
//!
//! DNS is resolved per connection and every resolved address is checked before it is connected
//! to (rule 14); the connection goes to the checked address, so a name that changes between two
//! lookups cannot reach an address that was not checked.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, Request, StatusCode, header};
use http_body::Body as _;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

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
/// The largest response head, status line and fields (also the trailer bound of hyper).
pub const MAX_HEAD: usize = 16_384;
/// The most header fields of a response head.
pub const MAX_HEADERS: usize = 64;
/// hyper's read buffer for one connection.
pub const MAX_BUF: usize = 65_536;

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

/// One HTTP/1.1 connection to a peer. Dropping it closes the connection.
pub struct Conn {
    sender: http1::SendRequest<Body>,
    task: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The client, built once at start-up.
pub struct Client {
    tls: Option<tokio_rustls::TlsConnector>,
    allow_private: bool,
    timeout: Duration,
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

    /// `GET {peer}{path}` with `Sbtp-Replication: 1`, over `conn` when it is open, else over a
    /// new connection stored in `conn`. The whole request, connection and body included, is
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
        if done.is_err() {
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
        let c = self.ready(conn, peer).await?;
        let resp = c
            .sender
            .send_request(request(peer, path)?)
            .await
            .map_err(|_| fail(Failed::Invalid))?;
        let status = resp.status();
        let retry_after = parse_retry_after(resp.headers().get(header::RETRY_AFTER));
        let failed = |kind| Err(Fail { kind, retry_after });
        match status.as_u16() {
            200..=299 => {
                // No content coding was asked for: one in the answer is not the defined body.
                let coded = resp
                    .headers()
                    .get_all(header::CONTENT_ENCODING)
                    .iter()
                    .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
                if coded {
                    return failed(Failed::Invalid);
                }
                let body = read_bounded(resp.into_body(), ceiling).await?;
                Ok(Reply { status, body })
            }
            // A `404` is a skip and a `400` may name `InvalidCursor`: both are read within the
            // error ceiling, so that the connection stays usable; an error body over it is
            // unparseable, not a failure (core spec §4). ADR 0052 rule 17: a `451` is a skip too.
            400 | 404 | 451 => {
                let body = read_bounded(resp.into_body(), ERROR_CEILING)
                    .await
                    .unwrap_or_default();
                Ok(Reply { status, body })
            }
            // Not read: `get` closes the connection.
            300..=399 => failed(Failed::Redirect),
            429 => failed(Failed::RateLimited),
            502..=504 => failed(Failed::Unavailable),
            400..=499 => failed(Failed::Client),
            _ => failed(Failed::Server),
        }
    }

    /// `conn` when it is open and ready, else a new connection stored in it. A connection the
    /// peer closed between two requests (keep-alive bounds) is replaced once.
    async fn ready<'c>(
        &self,
        conn: &'c mut Option<Conn>,
        peer: &PeerUrl,
    ) -> Result<&'c mut Conn, Fail> {
        let usable = match conn.as_mut() {
            Some(c) => !c.sender.is_closed() && c.sender.ready().await.is_ok(),
            None => false,
        };
        if !usable {
            *conn = Some(self.connect(peer).await?);
        }
        conn.as_mut().ok_or(fail(Failed::Connect))
    }

    /// One request of the archive copy (ADR 0050 rules 8 and 23) to `url`, over `conn` when it
    /// is open: the whole exchange bounded by the client's timeout, the response body read up to
    /// [`ERROR_CEILING`] and discarded; only the status is returned. A body over that bound
    /// closes the connection, the status still counts. A `3xx` is returned, never followed.
    ///
    /// # Errors
    ///
    /// [`Fail`]: no response (connection, TLS, timeout, broken exchange). `conn` is closed.
    #[cfg(feature = "object-store")]
    pub async fn send_discard(
        &self,
        conn: &mut Option<Conn>,
        url: &PeerUrl,
        req: Request<Body>,
    ) -> Result<StatusCode, Fail> {
        let exchange = async {
            let c = self.ready(conn, url).await?;
            let resp = c
                .sender
                .send_request(req)
                .await
                .map_err(|_| fail(Failed::Invalid))?;
            let status = resp.status();
            let whole = read_bounded(resp.into_body(), ERROR_CEILING).await.is_ok();
            Ok((status, whole))
        };
        let done = tokio::time::timeout(self.timeout, exchange)
            .await
            .unwrap_or(Err(fail(Failed::Timeout)));
        match done {
            Ok((status, whole)) => {
                if !whole {
                    *conn = None;
                }
                Ok(status)
            }
            Err(f) => {
                *conn = None;
                Err(f)
            }
        }
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
        if peer.is_https() {
            let tls = self.tls.as_ref().ok_or(fail(Failed::Tls))?;
            let name = match peer.host() {
                Host::Ip(ip) => ServerName::from(*ip),
                Host::Name(n) => ServerName::try_from(n.clone()).map_err(|_| fail(Failed::Tls))?,
            };
            let stream = tls
                .connect(name, tcp)
                .await
                .map_err(|_| fail(Failed::Tls))?;
            handshake(TokioIo::new(stream)).await
        } else {
            handshake(TokioIo::new(tcp)).await
        }
    }
}

async fn handshake<T>(io: T) -> Result<Conn, Fail>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (sender, connection) = http1::Builder::new()
        .max_buf_size(MAX_BUF)
        .max_headers(MAX_HEADERS)
        .max_header_size(MAX_HEAD)
        .handshake::<T, Body>(io)
        .await
        .map_err(|_| fail(Failed::Connect))?;
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(Conn { sender, task })
}

/// The request: origin form under the peer's path prefix, `Host`, `Sbtp-Replication: 1`
/// (rule 18), a fixed `User-Agent` without version (ADR 0019 rule 25), no content coding.
fn request(peer: &PeerUrl, path: &str) -> Result<Request<Body>, Fail> {
    Request::get(format!("{}{path}", peer.path()))
        .header(header::HOST, peer.authority())
        .header("sbtp-replication", HeaderValue::from_static("1"))
        .header(header::USER_AGENT, HeaderValue::from_static("sbtp-relay"))
        .header(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        )
        .body(Body::empty())
        .map_err(|_| fail(Failed::Invalid))
}

/// `Retry-After` as a number of seconds; any other form gives no delay (core spec §4).
fn parse_retry_after(v: Option<&HeaderValue>) -> Option<u64> {
    let s = v?.to_str().ok()?.trim();
    if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Reads `body` up to `ceiling` bytes (ADR 0029): an announced length over it fails before any
/// byte is read, and the read stops at the first byte past it. Never allocates more than the
/// ceiling.
async fn read_bounded(mut body: Incoming, ceiling: usize) -> Result<Bytes, Fail> {
    let announced = body.size_hint().lower();
    if announced > u64::try_from(ceiling).unwrap_or(u64::MAX) {
        return Err(fail(Failed::TooLarge));
    }
    let mut buf = Vec::with_capacity(usize::try_from(announced).unwrap_or(0).min(ceiling));
    while let Some(frame) =
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
    {
        let frame = frame.map_err(|_| fail(Failed::Invalid))?;
        if let Ok(data) = frame.into_data() {
            if buf.len().saturating_add(data.len()) > ceiling {
                return Err(fail(Failed::TooLarge));
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn retry_after_forms() {
        let v = |s: &'static str| parse_retry_after(Some(&HeaderValue::from_static(s)));
        assert_eq!(v("7"), Some(7));
        assert_eq!(v(" 30 "), Some(30));
        assert_eq!(v("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(v("-1"), None);
        assert_eq!(v("1.5"), None);
        assert_eq!(v("99999999999999999999"), None);
        assert_eq!(parse_retry_after(None), None);
    }

    /// One exchange with a scripted peer that reads the request and answers `raw`.
    async fn read(raw: &'static [u8], ceiling: usize) -> Result<Reply, Fail> {
        let (mut peer, ours) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let _ = peer.read(&mut buf).await;
            let _ = peer.write_all(raw).await;
            let _ = peer.shutdown().await;
        });
        let mut conn = Some(handshake(TokioIo::new(ours)).await?);
        let client = Client::new(None, false, Duration::from_secs(5));
        let url = PeerUrl::parse("http://127.0.0.1").unwrap();
        client.get(&mut conn, &url, "/x", ceiling).await
    }

    #[tokio::test]
    async fn bodies_heads_and_statuses_are_bounded() {
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 3)
            .await
            .unwrap();
        assert_eq!(&r.body[..], b"abc");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                        2\r\nab\r\n1\r\nc\r\n0\r\n\r\n";
        assert_eq!(&read(chunked, 3).await.unwrap().body[..], b"abc");
        let kind = |r: Result<Reply, Fail>| r.unwrap_err().kind;
        let long = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd";
        assert_eq!(kind(read(long, 3).await), Failed::TooLarge);
        let long_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                             4\r\nabcd\r\n0\r\n\r\n";
        assert_eq!(kind(read(long_chunked, 3).await), Failed::TooLarge);
        assert_eq!(
            kind(read(b"HTTP/1.1 200 OK\r\n\r\nabcd", 3).await),
            Failed::TooLarge
        );
        // A truncated body is a failure, not a short body.
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab";
        assert!(read(short, 4).await.is_err());
        let limited = b"HTTP/1.1 429 Too Many\r\nRetry-After: 9\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            read(limited, 3).await.unwrap_err(),
            Fail {
                kind: Failed::RateLimited,
                retry_after: Some(9)
            }
        );
        let moved = b"HTTP/1.1 301 Moved\r\nLocation: http://x/\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(kind(read(moved, 3).await), Failed::Redirect);
        let coded = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\na";
        assert_eq!(kind(read(coded, 3).await), Failed::Invalid);
        // A head over the bound, or with too many fields, is refused by hyper.
        let big_head: &'static [u8] = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: 0\r\n\r\n",
                "a".repeat(MAX_HEAD)
            )
            .into_bytes()
            .into_boxed_slice(),
        );
        assert!(read(big_head, 3).await.is_err());
        let many: &'static [u8] = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\n\r\n",
                "X: 1\r\n".repeat(MAX_HEADERS + 1)
            )
            .into_bytes()
            .into_boxed_slice(),
        );
        assert!(read(many, 3).await.is_err());
    }
}
