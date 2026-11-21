//! Accept loop and connection bounds (ADR 0018 rules 23 to 27 and 31; ADR 0019 rules 12 to 23 and
//! 28 to 33).
//!
//! `axum::serve` has no connection cap and no timeouts, so the relay drives hyper's HTTP/1.1
//! connection itself (HTTP/1.1 only: rule 27).
//!
//! - `max_connections`: a permit is taken **before** `accept`, and is owned by the connection task.
//!   At the cap the relay does not accept; new connections wait in the kernel listen queue (rule 31).
//! - `max_connections_per_client` (ADR 0019 rules 29 to 31): a peer outside `trusted_proxies` is
//!   counted at accept, and a connection over the bound is closed before any byte is read. A
//!   request through a trusted peer is counted from the end of its headers until its response is
//!   written to the socket, under the client key of `X-Forwarded-For`; over the bound it gets `429`
//!   from the router's middleware (`api::refuse`) before its body is read
//!   (spec §4, "Admission control": `429` for requests in flight).
//! - Keep-alive caps (ADR 0019 rules 32 and 33; spec §4, a relay MAY close a connection after a
//!   number of requests or a duration): the response to request number
//!   `max_requests_per_connection`, or any response once the connection is `max_connection_age_ms`
//!   old, carries `Connection: close`; an idle connection past its age is closed at once.
//! - Timers (ADR 0019 rules 12 to 16): each connection task holds one deadline that follows the
//!   connection's phase:
//!   - fresh (accepted, no byte yet): `header_timeout_ms` (security review F-1: a silent
//!     connection must not hold a permit for the whole idle period);
//!   - idle (between two requests of a keep-alive connection): `idle_timeout_ms` (rule 26);
//!   - head (the first byte of a request has arrived): `header_timeout_ms` (rule 23);
//!   - busy (headers parsed, response not yet flushed to the socket): `request_timeout_ms` plus
//!     [`RESPONSE_GRACE`]. The `503` of rule 25 comes from the router's middleware at
//!     `request_timeout_ms`; the grace lets it be written. A response whose bytes have not all been
//!     written to the socket at the end of the grace is cut (rule 25), so a client that stops
//!     reading cannot keep its connection.
//!
//!   At the deadline the connection is dropped, which closes the socket without a response.
//!   hyper's own `header_read_timeout` is disabled: it starts when hyper starts waiting for a
//!   request, not at its first byte, and restarts after each response, so it would also close idle
//!   keep-alive connections at `header_timeout_ms` instead of `idle_timeout_ms`.
//! - Pipelined bytes (review finding 3, security F-3): bytes of the next request that hyper has
//!   already read when a response ends start the header deadline at once. The relay knows them by
//!   counting the bytes read and locating the end of each request: the blank line that ends the
//!   head (a byte scan, not a parser) plus the exact body length hyper reports. When the end is not
//!   known exactly (chunked body, or a later request of a pipelined burst), the connection falls
//!   back to the idle deadline, bounded by `idle_timeout_ms + header_timeout_ms` (ADR 0019
//!   rule 16).
//! - `max_header_bytes` is both hyper's `max_header_size` (`431`, connection closed) and its
//!   `max_buf_size`, so the read buffer never grows beyond it (rule 23).

use std::collections::TryReserveError;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, Method, Request, header};
use http_body::Body as _;
use hyper::body::{Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, watch};
use tokio::time::Instant;
use tower::ServiceExt as _;

use crate::api::{Refusal, refuse};
use crate::client::{ClientKey, ClientPolicy, Counts, Forwarded, Slot};
use crate::config::Settings;
use crate::limiter::Limiter;
use crate::log::{self, Event, Level, Throttle, Value};
use crate::metrics::{self, AcceptClass};

/// Time allowed, after `request_timeout_ms`, to write the `503` of rule 25 or finish a response.
pub const RESPONSE_GRACE: Duration = Duration::from_secs(1);

/// Pause after `accept` fails with an error that is not per-connection, so that the loop does not
/// spin (ADR 0020 rule 1).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Pause after a per-connection `accept` error once more than [`ACCEPT_GUARD_AFTER`] calls in a
/// row have failed (ADR 0020 rule 3).
const ACCEPT_GUARD_PAUSE: Duration = Duration::from_millis(1);

/// Consecutive failed `accept` calls retried at once before [`ACCEPT_GUARD_PAUSE`] applies.
const ACCEPT_GUARD_AFTER: u32 = 16;

/// The consecutive-failure count of ADR 0020 rule 3, over both classes, reset by a success; and
/// one throttled log line per class (rule 4).
#[derive(Debug, Default)]
struct AcceptFailures {
    consecutive: u32,
    pause_log: Throttle,
    retry_log: Throttle,
}

impl AcceptFailures {
    /// Counts and logs a failed `accept` (throttled per class, no address) and waits the pause
    /// it calls for.
    async fn handle(&mut self, e: &io::Error) {
        let pause = self.failed(e);
        let (class, throttle) = if accept_needs_backoff(e) {
            (AcceptClass::Backoff, &self.pause_log)
        } else {
            (AcceptClass::Transient, &self.retry_log)
        };
        metrics::accept_error(class);
        let msg = e.to_string();
        let mut fields = Vec::with_capacity(3);
        if let Some(n) = log::errno(e) {
            fields.push(("errno", Value::Int(n)));
        }
        fields.push(("class", Value::Str(class.name())));
        fields.push(("msg", Value::Str(&msg)));
        log::throttled(throttle, Event::AcceptFailed, &fields, None);
        if let Some(pause) = pause {
            tokio::time::sleep(pause).await;
        }
    }

    /// Records a failed `accept` and returns the pause before the next one, if any.
    fn failed(&mut self, e: &io::Error) -> Option<Duration> {
        self.consecutive = self.consecutive.saturating_add(1);
        if accept_needs_backoff(e) {
            Some(ACCEPT_BACKOFF)
        } else if self.consecutive > ACCEPT_GUARD_AFTER {
            Some(ACCEPT_GUARD_PAUSE)
        } else {
            None
        }
    }
}

/// The class of a request for the token buckets of ADR 0018 rule 21, from its method and path
/// only, in the connection's service function, before the router sees the request (ADR 0020
/// rule 23 and clarification N2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestClass {
    /// Every request that is not `put` or `query`: `GET /block`, `POST /blocks` (with the weight
    /// of [`request_weight`], ADR 0051 rule 7), `/info`, a CORS preflight on any path, an
    /// unknown path, any other method on a known path.
    Block,
    /// `GET` or `HEAD` (which the router answers as `GET`) of `/sbtp/v1/query`.
    Query,
    /// `PUT /sbtp/v1/block`.
    Put,
}

impl RequestClass {
    /// The class of a request with `method` and `path` (ADR 0020 rule 23, clarification N2:
    /// exact method and path; a preflight and a `405` are answered without index access and cost
    /// a `block` token).
    #[must_use]
    pub fn of(method: &Method, path: &str) -> Self {
        match (method, path) {
            (&Method::PUT, "/sbtp/v1/block") => Self::Put,
            (&Method::GET | &Method::HEAD, "/sbtp/v1/query") => Self::Query,
            _ => Self::Block,
        }
    }
}

/// ADR 0051 rule 7: the identifiers a batch is charged for when it has no usable
/// `Content-Length` (64 tokens).
const BATCH_UNKNOWN_IDS: u64 = 256;

/// The tokens of `req` at admission (ADR 0018 rule 21, amended by ADR 0051 rules 7 and 26), from
/// its method, path and headers only; [`crate::limiter::Limiter::take_tokens`] caps them at the
/// burst of the bucket.
///
/// - `POST /sbtp/v1/blocks`: `⌈N / 4⌉` tokens of the `block` bucket, `N = ⌈Content-Length /
///   32⌉`, at least 1; 64 when the request has no `Content-Length` or also a
///   `Transfer-Encoding` (the handler refuses both, after this charge).
/// - `/query`: `⌈N / 8⌉` tokens of the `query` bucket, `N` the number of `parent=` pairs of the
///   raw query string (bounded by the request line), 1 when there is none.
/// - Every other request: 1 token.
#[must_use]
pub fn request_weight<B>(req: &Request<B>) -> u64 {
    match (req.method(), req.uri().path()) {
        (&Method::POST, crate::batch::PATH) => {
            let headers = req.headers();
            let length = headers
                .get(header::CONTENT_LENGTH)
                .filter(|_| !headers.contains_key(header::TRANSFER_ENCODING))
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            let ids = length.map_or(BATCH_UNKNOWN_IDS, |l| l.div_ceil(32));
            ids.div_ceil(4).max(1)
        }
        (&Method::GET | &Method::HEAD, "/sbtp/v1/query") => {
            let parents = req.uri().query().map_or(0, |q| {
                q.split('&').filter(|p| p.starts_with("parent=")).count()
            });
            (parents as u64).div_ceil(8).max(1)
        }
        _ => 1,
    }
}

/// The client of a request, computed once at step 3 of ADR 0018 rule 28 and passed to the
/// router as a request extension (ADR 0020 rule 21). The handlers (the per-client `PUT` bound of
/// ADR 0018 rule 18) read it here and never derive the key again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestClient {
    /// The client key; `None` when the client address is in `rate_limit_exempt`.
    pub key: Option<ClientKey>,
    /// The class of the request.
    pub class: RequestClass,
}

/// The source of stop requests: the first ends the accept loop and starts the drain; a second
/// one during the drain closes every connection at once (security review F-4).
pub trait StopSignal {
    /// Completes at the next stop request.
    fn recv(&mut self) -> impl Future<Output = ()>;
}

/// A channel as a stop signal (tests, embedding). A closed channel never signals.
impl StopSignal for tokio::sync::mpsc::UnboundedReceiver<()> {
    async fn recv(&mut self) {
        if tokio::sync::mpsc::UnboundedReceiver::recv(self)
            .await
            .is_none()
        {
            std::future::pending::<()>().await;
        }
    }
}

/// The connection bounds taken from the settings.
#[derive(Clone, Debug)]
pub struct ConnLimits {
    /// `max_connections`.
    pub max_connections: u32,
    /// `max_connection_age_ms`.
    pub max_connection_age: Duration,
    /// `max_requests_per_connection`.
    pub max_requests_per_connection: u64,
    /// Client keys and `max_connections_per_client`.
    pub clients: Arc<ClientPolicy>,
    /// The token buckets of ADR 0018 rule 21.
    pub limiter: Arc<Limiter>,
    /// `max_header_bytes`.
    pub max_header_bytes: usize,
    /// `header_timeout_ms`.
    pub header_timeout: Duration,
    /// `request_timeout_ms`.
    pub request_timeout: Duration,
    /// `idle_timeout_ms`.
    pub idle_timeout: Duration,
}

impl ConnLimits {
    /// The bounds of `s`. Every value is in range after [`Settings::load`].
    ///
    /// # Errors
    ///
    /// The limiter table could not be allocated (ADR 0027 clarification T2).
    pub fn from_settings(s: &Settings) -> Result<Self, TryReserveError> {
        Ok(Self {
            max_connections: u32::try_from(s.max_connections).unwrap_or(u32::MAX),
            max_connection_age: Duration::from_millis(s.max_connection_age_ms),
            max_requests_per_connection: s.max_requests_per_connection,
            clients: Arc::new(ClientPolicy::from_settings(s)),
            limiter: Arc::new(Limiter::from_settings(s)?),
            max_header_bytes: usize::try_from(s.max_header_bytes).unwrap_or(usize::MAX),
            header_timeout: Duration::from_millis(s.header_timeout_ms),
            request_timeout: Duration::from_millis(s.request_timeout_ms),
            idle_timeout: Duration::from_millis(s.idle_timeout_ms),
        })
    }
}

/// Whether the accept loop pauses [`ACCEPT_BACKOFF`] after a failed `accept` (ADR 0020 rules 1
/// and 2, which replace ADR 0019 rule 23; security review R-1). It continues at once only for the
/// closed list of errors known to concern one pending connection, so that an unforeseen
/// persistent error cannot spin a core, and [`AcceptFailures`] bounds a persistent error of the
/// list (rule 3):
///
/// - `ECONNABORTED`, `ECONNRESET`: the peer gave up or reset before the accept (POSIX, BSD);
/// - `EINTR`: interrupted by a signal;
/// - `EPERM`: on Linux, a firewall rule refused this connection;
/// - `EPROTO`, `ENOPROTOOPT`, `ENETDOWN`, `ENETUNREACH`, `EHOSTDOWN`, `EHOSTUNREACH`, `ENONET`,
///   `EOPNOTSUPP`: the pending network errors that Linux `accept(2)` reports for the new socket
///   and that its manual says to retry like `EAGAIN`; `ETIMEDOUT`, listed there among the "other
///   errors" some kernels return for the new socket.
///
/// Everything else pauses, including the resource classes `EMFILE`, `ENFILE`, `ENOBUFS` and
/// `ENOMEM`, and an error without an `errno`.
#[must_use]
pub fn accept_needs_backoff(e: &io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return true;
    };
    #[cfg(target_os = "linux")]
    if code == libc::ENONET {
        return false;
    }
    !matches!(
        code,
        libc::ECONNABORTED
            | libc::ECONNRESET
            | libc::EINTR
            | libc::EPERM
            | libc::EPROTO
            | libc::ENOPROTOOPT
            | libc::ENETDOWN
            | libc::ENETUNREACH
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::EOPNOTSUPP
            | libc::ETIMEDOUT
    )
}

/// How the drain of [`serve`] ended (the `shutdown` line's `phase`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drain {
    /// Every connection finished: no request handler runs any more.
    Drained,
    /// The drain deadline passed with connections still open.
    Deadline,
    /// A second stop signal cut the drain.
    Forced,
}

impl Drain {
    /// Whether every request handler had ended when [`serve`] returned. After `Deadline` or
    /// `Forced`, handlers left may still record demands until the runtime is dropped, so the
    /// stop is not clean for ADR 0046 rule 13 (security review 2026-11-21, L-3).
    #[must_use]
    pub fn complete(self) -> bool {
        self == Self::Drained
    }
}

/// Serves `app` on `listener` until `stop` signals, then stops accepting, lets each connection
/// finish its request (hyper graceful shutdown), and returns once every connection is closed,
/// after `request_timeout + RESPONSE_GRACE` at the latest, or at once on a second stop request.
/// Returns how the drain ended.
///
/// # Errors
///
/// None at present; accept errors are retried.
pub async fn serve<S: StopSignal>(
    listener: TcpListener,
    app: Router,
    limits: ConnLimits,
    mut stop: S,
) -> io::Result<Drain> {
    let permits = Arc::new(Semaphore::new(limits.max_connections as usize));
    let (stopping_tx, stopping) = watch::channel(false);
    let mut builder = http1::Builder::new();
    builder
        .header_read_timeout(None)
        .max_header_size(limits.max_header_bytes)
        .max_buf_size(limits.max_header_bytes);
    let builder = Arc::new(builder);
    // ADR 0019 rule 31, ADR 0027 rule 4: a key with a connection or a request counted here keeps
    // its limiter entry.
    let connections = Counts::pinning(limits.clients.max_per_client, Arc::clone(&limits.limiter));
    let requests = Counts::pinning(limits.clients.max_per_client, Arc::clone(&limits.limiter));
    let refused_log = Throttle::default();
    let mut failures = AcceptFailures::default();
    {
        let stopped = stop.recv();
        tokio::pin!(stopped);
        loop {
            let permit = tokio::select! {
                biased;
                () = &mut stopped => break,
                p = Arc::clone(&permits).acquire_owned() => match p {
                    Ok(p) => p,
                    Err(_) => break,
                },
            };
            let (stream, peer) = tokio::select! {
                biased;
                () = &mut stopped => break,
                r = listener.accept() => match r {
                    Ok(accepted) => {
                        failures.consecutive = 0;
                        accepted
                    }
                    Err(e) => {
                        failures.handle(&e).await;
                        continue;
                    }
                },
            };
            // ADR 0019 rule 29: a direct peer is counted after the accept, before any byte. Its
            // key is computed once for the connection (ADR 0020 rule 21).
            let trusted = limits.clients.is_trusted(peer.ip());
            let direct = limits.clients.key(peer.ip()).filter(|_| !trusted);
            let slot = match direct {
                None => None,
                Some(key) => {
                    let Some(slot) = connections.try_acquire(key) else {
                        // ADR 0019 rule 31: behind a reverse proxy, its address belongs in
                        // `trusted_proxies`.
                        metrics::connection_refused();
                        log::throttled(
                            &refused_log,
                            Event::ClientBound,
                            &[(
                                "limit",
                                Value::Int(u64::from(limits.clients.max_per_client)),
                            )],
                            Some(&key),
                        );
                        continue; // Drops the stream (closed, nothing sent) and the permit.
                    };
                    Some(slot)
                }
            };
            let conn = Connection {
                builder: Arc::clone(&builder),
                app: app.clone(),
                limits: limits.clone(),
                stopping: stopping.clone(),
                peer,
                admission: if trusted {
                    Admission::Proxied(Arc::clone(&requests))
                } else {
                    Admission::Direct(direct)
                },
            };
            let open = metrics::OpenConnection::new();
            tokio::spawn(async move {
                conn.run(stream).await;
                drop(open);
                drop(slot);
                drop(permit);
            });
        }
    }
    drop(listener);
    log::emit(Event::Shutdown, &[("phase", Value::Str("signal"))]);
    let _ = stopping_tx.send(true);
    // Every connection task holds one permit until it ends.
    let drain = tokio::time::timeout(
        limits.request_timeout + RESPONSE_GRACE,
        permits.acquire_many(limits.max_connections),
    );
    // `deadline`: connections still open after the drain deadline are dropped; `forced`: a
    // second stop signal closes every connection now.
    let phase = tokio::select! {
        r = drain => match r {
            Ok(_) => (Level::Info, "drained", Drain::Drained),
            Err(_) => (Level::Warn, "deadline", Drain::Deadline),
        },
        () = stop.recv() => (Level::Warn, "forced", Drain::Forced),
    };
    log::emit_at(phase.0, Event::Shutdown, &[("phase", Value::Str(phase.1))]);
    // The connection tasks left are dropped with the runtime, which closes their sockets.
    Ok(phase.2)
}

struct Connection {
    builder: Arc<http1::Builder>,
    app: Router,
    limits: ConnLimits,
    stopping: watch::Receiver<bool>,
    peer: SocketAddr,
    admission: Admission,
}

/// How the requests of one connection are admitted at step 3.
#[derive(Debug)]
enum Admission {
    /// A peer outside `trusted_proxies`: its key, computed at accept (`None` when exempt). Its
    /// connections are counted at accept, its requests are not (ADR 0019 rule 29).
    Direct(Option<ClientKey>),
    /// A peer in `trusted_proxies`: each request's key comes from `X-Forwarded-For`, and requests
    /// in flight are counted per key in this table (ADR 0019 rule 30), separate from the
    /// connection count of direct peers (ADR 0020 rule 28).
    Proxied(Arc<Counts>),
}

/// Step 3 of ADR 0018 rule 28, in the order of ADR 0020 rule 22, for one request on a connection
/// from `peer`. Returns the request's in-flight slot, if it is counted; a refused request is
/// marked by [`refuse`]. Every request gets its [`RequestClient`].
fn admit(
    clients: &ClientPolicy,
    limiter: &Limiter,
    peer: IpAddr,
    admission: &Admission,
    req: &mut Request<Body>,
) -> Option<Slot> {
    // (a) Client address and exemption (ADR 0020 rules 6 to 10 and 26). The key is computed here
    // once and never derived again from the connection or the headers (rule 21). Without a
    // client address, the key is the proxy's exact address (rule 10), not its /64.
    let (key, addressed) = match admission {
        Admission::Direct(key) => (*key, true),
        // ADR 0044: the single-value header replaces `X-Forwarded-For`. A missing or malformed
        // one falls back to the peer's exact address (rule 5, as ADR 0020 rule 10); the request
        // is never refused for it. Neither the value nor the address is logged (rule 7).
        Admission::Proxied(_) if clients.client_ip_header.is_some() => {
            if let Some(ip) = clients.header_client(req.headers()) {
                (clients.forwarded_key(ip), true)
            } else {
                let key = clients.proxy_key(peer);
                log::throttled(
                    &clients.header_fallback_log,
                    Event::ForwardedInvalid,
                    &[("reason", Value::Str("client_ip_header"))],
                    key.as_ref(),
                );
                (key, false)
            }
        }
        Admission::Proxied(_) => match clients.forwarded_client(req.headers()) {
            Forwarded::Client(ip) => (clients.forwarded_key(ip), true),
            Forwarded::Absent => (clients.proxy_key(peer), false),
            Forwarded::Unreadable => {
                // The requests of that proxy share one client key; the proxy must write a bare
                // address (ADR 0019 rule 42, ADR 0020 rule 7). The header value is never logged.
                let key = clients.proxy_key(peer);
                log::throttled(
                    &clients.unreadable_log,
                    Event::ForwardedInvalid,
                    &[("reason", Value::Str("unreadable"))],
                    key.as_ref(),
                );
                (key, false)
            }
        },
    };
    // (b) The class, from the method and the path only (ADR 0020 rule 23): a CORS preflight, a
    // wrong method and an unknown path are `block` requests, like any other.
    let class = RequestClass::of(req.method(), req.uri().path());
    req.extensions_mut().insert(RequestClient { key, class });
    // An exempt request skips (b) to (d).
    let key = key?;
    // Refused requests from a trusted peer without a client address: the proxy must write
    // X-Forwarded-For (ADR 0019 rule 42, ADR 0020 rule 11). Logged with the key computed at (a),
    // also after the limiter moved the request to the overflow key at (c).
    let unaddressed = || {
        if !addressed {
            log::throttled(
                &clients.unaddressed_log,
                Event::ForwardedInvalid,
                &[("reason", Value::Str("absent"))],
                Some(&key),
            );
        }
    };
    // (c) The tokens of `class` (one, or the weight of ADR 0051), for every class: `block`, `query` and `put` (ADR 0018 rules 21
    // and 29). A request refused here is not counted in flight (ADR 0020 rule 25). A request
    // attributed to the overflow key is counted on it (rule 24).
    // ADR 0051 rules 7 and 26: a batch and a `/query` with several parents take their weight,
    // from the head only, before the body is read.
    let tokens = request_weight(req);
    let slot_key = match limiter.take_tokens(key, class, tokens) {
        Ok(k) => k,
        Err(retry_after_s) => {
            refuse(
                req,
                Refusal::EmptyBucket {
                    class,
                    retry_after_s,
                },
            );
            unaddressed();
            return None;
        }
    };
    // (d) The in-flight count, on a connection from a trusted peer. A request refused here keeps
    // its token spent (ADR 0018 rule 28).
    let Admission::Proxied(requests) = admission else {
        return None;
    };
    let slot = requests.try_acquire(slot_key);
    if slot.is_none() {
        // The `429` comes with the CORS headers, a refused preflight included (`api::refuse`).
        refuse(req, Refusal::InFlight);
        unaddressed();
    }
    slot
}

impl Connection {
    async fn run(mut self, stream: TcpStream) {
        let state = Arc::new(ConnState::new(self.limits));
        let io = TokioIo::new(Watched {
            inner: stream,
            state: Arc::clone(&state),
        });
        let svc = {
            let state = Arc::clone(&state);
            let app = self.app.clone();
            let peer = self.peer.ip();
            let admission = self.admission;
            let clients = Arc::clone(&state.limits.clients);
            let limiter = Arc::clone(&state.limits.limiter);
            hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                state.request_started(req.body().size_hint().exact());
                let state = Arc::clone(&state);
                let mut req = req.map(Body::new);
                // Step 3 of ADR 0018 rule 28, before the request reaches the router and before
                // the body is read (spec §4, `429` for requests in flight). The slot belongs to
                // this request: it moves into its response body and is released once that
                // response has been written to the socket (`ConnState::flushed`).
                let slot = admit(&clients, &limiter, peer, &admission, &mut req);
                let app = app.clone();
                async move {
                    let mut response = match app.oneshot(req).await {
                        Ok(r) => r,
                        Err(never) => match never {},
                    };
                    // ADR 0019 rules 32 and 33 (spec §4: a response MAY carry
                    // `Connection: close`).
                    if state.last_request() {
                        response
                            .headers_mut()
                            .insert(header::CONNECTION, HeaderValue::from_static("close"));
                    }
                    Ok::<_, Infallible>(response.map(|inner| Tracked {
                        inner,
                        _done: Done { state, slot },
                    }))
                }
            })
        };
        let conn = self.builder.serve_connection(io, svc);
        tokio::pin!(conn);
        let mut stopping = *self.stopping.borrow();
        if stopping {
            conn.as_mut().graceful_shutdown();
        }
        loop {
            let deadline = state.deadline();
            tokio::select! {
                // Errors (malformed request, reset, oversized headers already answered by hyper)
                // end the connection; nothing about the peer is logged.
                _ = conn.as_mut() => return,
                () = tokio::time::sleep_until(deadline) => {
                    if state.deadline() <= Instant::now() {
                        return; // Dropping `conn` closes the socket (rules 23, 25, 26).
                    }
                }
                () = state.changed.notified() => {}
                _ = self.stopping.changed(), if !stopping => {
                    stopping = true;
                    conn.as_mut().graceful_shutdown();
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Fresh,
    Idle,
    Head,
    Busy,
}

/// Locates the blank line that ends a request head. Not a parser: it only decides which timer
/// applies, and both possible timers are bounded.
#[derive(Clone, Copy)]
enum Scan {
    /// Not tracking (after a chunked body or a pipelined burst).
    Off,
    /// Inside a head: whether the current line has content, whether a line has ended, whether
    /// a `\r` opened the current line.
    Head {
        content: bool,
        had_line: bool,
        cr: bool,
    },
    /// The head ended at this stream offset.
    Ended(u64),
}

const SCAN_START: Scan = Scan::Head {
    content: false,
    had_line: false,
    cr: false,
};

impl Scan {
    /// Advances over `bytes`, which start at stream offset `at`.
    fn feed(&mut self, bytes: &[u8], at: u64) {
        for (i, &b) in bytes.iter().enumerate() {
            let Self::Head {
                content,
                had_line,
                cr,
            } = self
            else {
                return;
            };
            match b {
                b'\n' if !*content && *had_line => {
                    *self = Self::Ended(at + i as u64 + 1);
                }
                b'\n' => {
                    *had_line |= *content;
                    *content = false;
                    *cr = false;
                }
                b'\r' if !*content && !*cr => *cr = true,
                _ => *content = true,
            }
        }
    }
}

struct Inner {
    phase: Phase,
    deadline: Instant,
    /// Bytes read from the socket since the accept.
    read: u64,
    scan: Scan,
    /// Stream offset just after the current request (head and body), when known exactly.
    end: Option<u64>,
    /// The response body has been dropped by hyper: every byte of it is in hyper's write buffer.
    body_done: bool,
    /// Requests whose head has been parsed on this connection.
    requests: u64,
    /// ADR 0019 rule 30: the counts of the requests whose response body is entirely in hyper's
    /// write buffer but not yet written to the socket, in response order. Each request owns its
    /// slot until then; all are released at the next completed flush, which writes every
    /// buffered byte (or when the connection ends).
    unflushed: Vec<Slot>,
}

/// The phase and deadline of one connection, shared by its IO wrapper, its service and the body
/// of its current response.
struct ConnState {
    limits: ConnLimits,
    /// When the connection was accepted (ADR 0019 rule 32).
    opened: Instant,
    inner: Mutex<Inner>,
    changed: Notify,
}

impl ConnState {
    fn new(limits: ConnLimits) -> Self {
        let opened = Instant::now();
        Self {
            inner: Mutex::new(Inner {
                phase: Phase::Fresh,
                deadline: opened + limits.header_timeout,
                read: 0,
                scan: SCAN_START,
                end: None,
                body_done: false,
                requests: 0,
                unflushed: Vec::new(),
            }),
            limits,
            opened,
            changed: Notify::new(),
        }
    }

    /// Whether the response being built is the last of the connection: request number
    /// `max_requests_per_connection` (rule 33), or a connection past `max_connection_age_ms`
    /// (rule 32).
    fn last_request(&self) -> bool {
        self.lock().requests >= self.limits.max_requests_per_connection
            || self.opened.elapsed() >= self.limits.max_connection_age
    }

    /// Enters the idle phase: `idle_timeout_ms`, but no later than the connection's age limit, so
    /// that an idle connection past its age is closed at once (rule 32).
    fn enter_idle(&self, inner: &mut Inner) {
        let age_left = self
            .limits
            .max_connection_age
            .saturating_sub(self.opened.elapsed());
        self.enter(inner, Phase::Idle, self.limits.idle_timeout.min(age_left));
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn deadline(&self) -> Instant {
        self.lock().deadline
    }

    fn enter(&self, inner: &mut Inner, phase: Phase, after: Duration) {
        inner.phase = phase;
        inner.deadline = Instant::now() + after;
        self.changed.notify_one();
    }

    /// Bytes arrived: if no request was in progress, this is the first byte of one.
    fn bytes_read(&self, bytes: &[u8]) {
        let mut inner = self.lock();
        if matches!(inner.phase, Phase::Fresh | Phase::Idle) {
            self.enter(&mut inner, Phase::Head, self.limits.header_timeout);
        }
        let at = inner.read;
        inner.scan.feed(bytes, at);
        inner.read = at.saturating_add(bytes.len() as u64);
    }

    /// hyper has parsed a head; `body_len` is the exact body length, if hyper knows it.
    fn request_started(&self, body_len: Option<u64>) {
        let mut inner = self.lock();
        inner.end = match (inner.scan, body_len) {
            (Scan::Ended(head), Some(len)) => Some(head.saturating_add(len)),
            _ => None,
        };
        inner.scan = Scan::Off;
        inner.body_done = false;
        inner.requests = inner.requests.saturating_add(1);
        self.enter(
            &mut inner,
            Phase::Busy,
            self.limits.request_timeout + RESPONSE_GRACE,
        );
    }

    /// hyper dropped the body of a response: its bytes are all in hyper's write buffer.
    fn body_dropped(&self, slot: Option<Slot>) {
        let mut inner = self.lock();
        inner.body_done = true;
        inner.unflushed.extend(slot);
    }

    /// The socket accepted every byte hyper had buffered: every response whose body is done has
    /// been written, and its count is released. Once the current response body is done, the
    /// response is complete: the connection waits for the next request.
    fn flushed(&self) {
        let mut inner = self.lock();
        let written = std::mem::take(&mut inner.unflushed);
        if inner.phase == Phase::Busy && inner.body_done {
            self.end_response(&mut inner);
        }
        drop(inner);
        drop(written);
    }

    fn end_response(&self, inner: &mut Inner) {
        match inner.end.take() {
            Some(end) if inner.read > end => {
                // Bytes of the next request are already in hyper's buffer.
                self.enter(inner, Phase::Head, self.limits.header_timeout);
            }
            Some(_) => {
                inner.scan = SCAN_START;
                self.enter_idle(inner);
            }
            None => self.enter_idle(inner),
        }
    }
}

/// Reports to the connection when hyper drops the response body, and hands it the request's
/// count under ADR 0019 rule 30, if any.
struct Done {
    state: Arc<ConnState>,
    slot: Option<Slot>,
}

impl Drop for Done {
    fn drop(&mut self) {
        self.state.body_dropped(self.slot.take());
    }
}

/// A response body that reports its end to the connection.
struct Tracked {
    inner: Body,
    _done: Done,
}

impl http_body::Body for Tracked {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The TCP stream, with hooks on reads (first byte of a request, request boundaries) and on
/// flushes (end of a response). hyper calls `poll_flush` on it only once its own write buffer has
/// been written out.
struct Watched {
    inner: TcpStream,
    state: Arc<ConnState>,
}

impl AsyncRead for Watched {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Some(new) = buf.filled().get(before..).filter(|b| !b.is_empty()) {
            self.state.bytes_read(new);
        }
        polled
    }
}

impl AsyncWrite for Watched {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(polled, Poll::Ready(Ok(()))) {
            self.state.flushed();
        }
        polled
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Refused;

    #[test]
    fn backoff_unless_the_error_concerns_one_connection() {
        // Resource exhaustion, and errors nobody foresaw (security review R-1).
        for code in [
            libc::EMFILE,
            libc::ENFILE,
            libc::ENOBUFS,
            libc::ENOMEM,
            libc::EBADF,
            libc::EINVAL,
            libc::ENOTSOCK,
            libc::EFAULT,
        ] {
            assert!(accept_needs_backoff(&io::Error::from_raw_os_error(code)));
        }
        assert!(accept_needs_backoff(&io::Error::other("no errno")));
        for code in [
            libc::ECONNABORTED,
            libc::ECONNRESET,
            libc::EPROTO,
            libc::EINTR,
            libc::EPERM,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
            libc::ETIMEDOUT,
        ] {
            assert!(!accept_needs_backoff(&io::Error::from_raw_os_error(code)));
        }
    }

    /// ADR 0020 rule 3: 17 failures of a listed error in a row; the 17th and later pause 1 ms,
    /// an unlisted error always pauses 50 ms, and a success resets the count.
    #[test]
    fn consecutive_accept_failures_are_paced() {
        let listed = io::Error::from_raw_os_error(libc::EPERM);
        let other = io::Error::from_raw_os_error(libc::EMFILE);
        let mut f = AcceptFailures::default();
        for _ in 0..16 {
            assert_eq!(f.failed(&listed), None);
        }
        assert_eq!(f.failed(&listed), Some(ACCEPT_GUARD_PAUSE));
        assert_eq!(f.failed(&listed), Some(ACCEPT_GUARD_PAUSE));
        assert_eq!(f.failed(&other), Some(ACCEPT_BACKOFF));
        f.consecutive = 0; // a successful accept
        assert_eq!(f.failed(&other), Some(ACCEPT_BACKOFF));
        assert_eq!(f.failed(&listed), None, "2 failures in a row");
    }

    /// ADR 0051 rules 7 and 26 (the planned `weights.json`): `N` → tokens, before any cap.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn request_weights() {
        let batch = |len: Option<&str>, te: bool| {
            let mut b = Request::builder()
                .method(Method::POST)
                .uri("/sbtp/v1/blocks");
            if let Some(l) = len {
                b = b.header(header::CONTENT_LENGTH, l);
            }
            if te {
                b = b.header(header::TRANSFER_ENCODING, "chunked");
            }
            request_weight(&b.body(()).unwrap())
        };
        for (n, tokens) in [
            (1u64, 1),
            (4, 1),
            (5, 2),
            (8, 2),
            (9, 3),
            (255, 64),
            (256, 64),
        ] {
            assert_eq!(batch(Some(&(n * 32).to_string()), false), tokens, "{n}");
        }
        // Every batch of N ids takes at least N / 4 tokens: at most 4 blocks per token.
        for n in 1..=256u64 {
            assert!(n <= 4 * batch(Some(&(n * 32).to_string()), false), "{n}");
        }
        assert_eq!(batch(Some("0"), false), 1, "at least one token");
        assert_eq!(batch(Some("33"), false), 1, "⌈33 / 32⌉ = 2 ids");
        assert_eq!(batch(None, false), 64, "no Content-Length");
        assert_eq!(batch(Some("32"), true), 64, "chunked");
        assert_eq!(
            batch(Some("99999999999"), false),
            781_250_000,
            "capped by the limiter"
        );
        let query = |q: &str| {
            let r = Request::builder()
                .uri(format!("/sbtp/v1/query{q}"))
                .body(())
                .unwrap();
            request_weight(&r)
        };
        let parents = |n: usize| {
            let q: Vec<String> = (0..n).map(|k| format!("parent={k}")).collect();
            format!("?{}", q.join("&"))
        };
        assert_eq!(query(""), 1);
        assert_eq!(query("?limit=5"), 1);
        for (n, tokens) in [(1, 1), (8, 1), (9, 2), (16, 2), (26, 4), (32, 4), (33, 5)] {
            assert_eq!(query(&parents(n)), tokens, "{n}");
        }
        assert_eq!(query("?cursor=parent=x"), 1, "only pairs named parent");
        let other = Request::builder()
            .method(Method::GET)
            .uri("/sbtp/v1/block/00")
            .body(())
            .unwrap();
        assert_eq!(request_weight(&other), 1);
    }

    /// ADR 0020 rule 23 and clarification N2: the class comes from the exact method and path.
    #[test]
    fn request_class_from_method_and_path() {
        use RequestClass::{Block, Put, Query};
        for (method, path, class) in [
            (Method::PUT, "/sbtp/v1/block", Put),
            (Method::PUT, "/sbtp/v1/query", Block),
            (Method::PUT, "/nowhere", Block),
            (Method::PUT, "/sbtp/v1/block/00", Block),
            (Method::GET, "/sbtp/v1/query", Query),
            (Method::HEAD, "/sbtp/v1/query", Query),
            (Method::POST, "/sbtp/v1/query", Block),
            (Method::OPTIONS, "/sbtp/v1/query", Block),
            (Method::GET, "/sbtp/v1/block/00", Block),
            (Method::GET, "/sbtp/v1/info", Block),
            (Method::OPTIONS, "/sbtp/v1/block", Block),
            (Method::GET, "/nowhere", Block),
            (Method::GET, "/sbtp/v1/query/", Block),
        ] {
            assert_eq!(RequestClass::of(&method, path), class, "{method} {path}");
        }
    }

    fn test_limiter() -> Limiter {
        let s = Settings::load(Vec::<std::ffi::OsString>::new(), Vec::new())
            .unwrap_or_else(|_| unreachable!());
        Limiter::from_settings(&s).unwrap_or_else(|_| unreachable!())
    }

    /// ADR 0020 rules 21, 22 and 28: one key per request, passed as an extension; the
    /// connection count of a direct peer and the in-flight count of the same key through a
    /// trusted peer are separate; an exempt address skips the count.
    #[test]
    fn admission_uses_one_key_and_separate_counts() {
        let cidr = |a: &str, prefix| crate::config::Cidr {
            addr: a.parse().unwrap_or_else(|_| unreachable!()),
            prefix,
        };
        let clients = ClientPolicy::new(
            vec![cidr("10.0.0.1", 32)],
            vec![cidr("192.0.2.9", 32)],
            64,
            1,
        );
        let proxy: IpAddr = [10, 0, 0, 1].into();
        let client: IpAddr = [198, 51, 100, 7].into();
        let key = clients.key(client);
        let connections = Counts::new(1);
        let proxied = Admission::Proxied(Counts::new(1));
        let limiter = test_limiter();
        let request = |xff: &str| {
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/sbtp/v1/block")
                .header("x-forwarded-for", xff)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
                .body(Body::empty())
                .unwrap_or_else(|_| unreachable!())
        };
        // The client holds its one direct connection.
        let direct = connections.try_acquire(key.unwrap_or_else(|| unreachable!()));
        assert!(direct.is_some());
        // Through the proxy, the same key still has its own in-flight count.
        let mut first = request("198.51.100.7:4711");
        let held = admit(&clients, &limiter, proxy, &proxied, &mut first);
        assert!(held.is_some());
        assert_eq!(
            first.extensions().get::<RequestClient>(),
            Some(&RequestClient {
                key,
                class: RequestClass::Block
            })
        );
        // Over the in-flight bound: refused, with the method as received.
        let mut second = request("198.51.100.7");
        assert!(admit(&clients, &limiter, proxy, &proxied, &mut second).is_none());
        assert_eq!(
            second.extensions().get::<Refused>().map(|r| &r.method),
            Some(&Method::OPTIONS)
        );
        assert_eq!(
            second.extensions().get::<RequestClient>().map(|c| c.class),
            Some(RequestClass::Block),
            "a preflight is a block request"
        );
        // An exempt client address skips the count.
        let mut exempt = request("192.0.2.9");
        assert!(admit(&clients, &limiter, proxy, &proxied, &mut exempt).is_none());
        assert!(exempt.extensions().get::<Refused>().is_none());
        assert_eq!(
            exempt.extensions().get::<RequestClient>().map(|c| c.key),
            Some(None)
        );
        // On a direct connection, the key computed at accept is used; headers are not read.
        let mut on_direct = request("192.0.2.9");
        assert!(
            admit(
                &clients,
                &limiter,
                client,
                &Admission::Direct(key),
                &mut on_direct
            )
            .is_none()
        );
        assert_eq!(
            on_direct.extensions().get::<RequestClient>().map(|c| c.key),
            Some(key)
        );
        drop((direct, held));
    }

    /// Code review CR5 (ADR 0020 rule 10): through an IPv6 proxy, a request without a client
    /// address is counted on the proxy's exact address, not on the /64 shared with real clients.
    #[test]
    fn request_without_client_address_uses_the_exact_proxy_key() {
        let proxy: IpAddr = "2001:db8::1".parse().unwrap_or_else(|_| unreachable!());
        let clients = ClientPolicy::new(
            vec![crate::config::Cidr {
                addr: proxy,
                prefix: 128,
            }],
            Vec::new(),
            64,
            1,
        );
        let proxied = Admission::Proxied(Counts::new(1));
        let limiter = test_limiter();
        let request = |xff: Option<&[u8]>| {
            let mut b = Request::builder().uri("/sbtp/v1/info");
            if let Some(xff) = xff {
                let value = HeaderValue::from_bytes(xff).unwrap_or_else(|_| unreachable!());
                b = b.header("x-forwarded-for", value);
            }
            b.body(Body::empty()).unwrap_or_else(|_| unreachable!())
        };
        // A real client in the proxy's /64 holds its bound of 1.
        let mut real = request(Some(b"2001:db8::2"));
        let held = admit(&clients, &limiter, proxy, &proxied, &mut real);
        assert!(held.is_some());
        // ADR 0022: a client's non-ASCII element before the proxy's does not hide the client.
        let mut hidden = request(Some(b"\xff, 2001:db8::2"));
        assert!(admit(&clients, &limiter, proxy, &proxied, &mut hidden).is_none());
        assert_eq!(
            hidden
                .extensions()
                .get::<RequestClient>()
                .and_then(|c| c.key),
            clients.key("2001:db8::2".parse().unwrap_or_else(|_| unreachable!()))
        );
        // Header-less and unreadable requests (`unknown`, or a non-ASCII element on the right:
        // the rule 11 warning) are admitted on the proxy's own key.
        let unreadable: [Option<&[u8]>; 3] = [None, Some(b"unknown"), Some(b"2001:db8::2, \xff")];
        for xff in unreadable {
            let mut r = request(xff);
            let slot = admit(&clients, &limiter, proxy, &proxied, &mut r);
            assert!(slot.is_some(), "{xff:?}");
            assert_eq!(
                r.extensions().get::<RequestClient>().and_then(|c| c.key),
                clients.proxy_key(proxy)
            );
            assert_ne!(clients.proxy_key(proxy), clients.key(proxy), "{xff:?}");
        }
        drop(held);
    }

    /// A limiter with a `query` burst of `burst`, one token per minute, and the smallest table.
    fn query_limiter(burst: &str) -> Limiter {
        let env = [
            ("SBTP_RELAY_RATE_QUERY_BURST", burst),
            ("SBTP_RELAY_RATE_QUERY_PER_MIN", "1"),
            ("SBTP_RELAY_RATE_LIMIT_MAX_CLIENTS", "64"),
        ]
        .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)));
        let s = Settings::load(Vec::<std::ffi::OsString>::new(), env)
            .unwrap_or_else(|_| unreachable!());
        Limiter::from_settings(&s).unwrap_or_else(|_| unreachable!())
    }

    /// ADR 0020 rule 25(c) and rule 23: a CORS preflight and a request to an unknown path each
    /// cost one `block` token, like `/info` and `GET /block`; the `query` and `put` buckets are
    /// separate, and each class refuses with its own `Retry-After` (ADR 0018 rules 21 and 29).
    #[test]
    fn preflight_and_unknown_path_cost_a_block_token() {
        let env = [
            ("SBTP_RELAY_RATE_BLOCK_BURST", "3"),
            ("SBTP_RELAY_RATE_BLOCK_PER_MIN", "1"),
            ("SBTP_RELAY_RATE_PUT_BURST", "1"),
            ("SBTP_RELAY_RATE_PUT_PER_MIN", "2"),
            ("SBTP_RELAY_RATE_LIMIT_MAX_CLIENTS", "64"),
        ]
        .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)));
        let s = Settings::load(Vec::<std::ffi::OsString>::new(), env)
            .unwrap_or_else(|_| unreachable!());
        let limiter = Limiter::from_settings(&s).unwrap_or_else(|_| unreachable!());
        let clients = ClientPolicy::new(Vec::new(), Vec::new(), 64, 8);
        let peer: IpAddr = [192, 0, 2, 9].into();
        let direct = Admission::Direct(clients.key(peer));
        let request = |method: Method, uri: &str| {
            let mut b = Request::builder().method(method.clone()).uri(uri);
            if method == Method::OPTIONS {
                b = b
                    .header(header::ORIGIN, "https://a.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT");
            }
            let mut r = b.body(Body::empty()).unwrap_or_else(|_| unreachable!());
            let slot = admit(&clients, &limiter, peer, &direct, &mut r);
            assert!(slot.is_none(), "a direct peer is counted at accept");
            refusal(&r)
        };
        // Three `block` tokens: a preflight, an unknown path, then `/info` finds the bucket empty.
        assert_eq!(request(Method::OPTIONS, "/sbtp/v1/block"), None);
        assert_eq!(request(Method::GET, "/no/such/path"), None);
        assert_eq!(request(Method::DELETE, "/sbtp/v1/info"), None);
        let block_empty = Some(Refusal::EmptyBucket {
            class: RequestClass::Block,
            retry_after_s: 60,
        });
        assert_eq!(request(Method::GET, "/sbtp/v1/info"), block_empty);
        assert_eq!(request(Method::OPTIONS, "/sbtp/v1/query"), block_empty);
        assert_eq!(request(Method::GET, "/sbtp/v1/block/00"), block_empty);
        // The other classes keep their own buckets: `query` (burst 20) and `put` (burst 1, two
        // per minute: `Retry-After: 30`).
        assert_eq!(request(Method::GET, "/sbtp/v1/query"), None);
        assert_eq!(request(Method::PUT, "/sbtp/v1/block"), None);
        assert_eq!(
            request(Method::PUT, "/sbtp/v1/block"),
            Some(Refusal::EmptyBucket {
                class: RequestClass::Put,
                retry_after_s: 30,
            })
        );
    }

    /// `GET /sbtp/v1/query` from the trusted proxy `10.0.0.1` for the client `xff`.
    fn proxied_query(xff: &str) -> Request<Body> {
        Request::builder()
            .uri("/sbtp/v1/query")
            .header("x-forwarded-for", xff)
            .body(Body::empty())
            .unwrap_or_else(|_| unreachable!())
    }

    fn refusal(r: &Request<Body>) -> Option<Refusal> {
        r.extensions().get::<Refused>().map(|r| r.refusal)
    }

    fn proxy_policy() -> ClientPolicy {
        let trusted = crate::config::Cidr {
            addr: [10, 0, 0, 1].into(),
            prefix: 32,
        };
        ClientPolicy::new(vec![trusted], Vec::new(), 64, 1)
    }

    /// ADR 0020 rule 25 (security review of 1c-b, L-2): a client at its in-flight bound that
    /// keeps sending spends its tokens (a request refused at (d) keeps its token, ADR 0018 rule
    /// 28), then gets the `429` of the empty bucket with the `Retry-After` of rule 29; a request
    /// refused for an empty bucket is not counted in flight.
    #[test]
    fn in_flight_client_exhausts_its_bucket() {
        let clients = proxy_policy();
        let limiter = query_limiter("3");
        let counts = Counts::new(1);
        let proxied = Admission::Proxied(Arc::clone(&counts));
        let proxy: IpAddr = [10, 0, 0, 1].into();
        let mut first = proxied_query("198.51.100.7");
        let held = admit(&clients, &limiter, proxy, &proxied, &mut first);
        assert!(held.is_some() && refusal(&first).is_none());
        for _ in 0..2 {
            let mut r = proxied_query("198.51.100.7");
            assert!(admit(&clients, &limiter, proxy, &proxied, &mut r).is_none());
            assert_eq!(refusal(&r), Some(Refusal::InFlight));
        }
        let mut empty = proxied_query("198.51.100.7");
        assert!(admit(&clients, &limiter, proxy, &proxied, &mut empty).is_none());
        assert_eq!(
            refusal(&empty),
            Some(Refusal::EmptyBucket {
                class: RequestClass::Query,
                retry_after_s: 60
            })
        );
        // Only the held slot is counted: the bucket refusal took no count.
        assert_eq!(counts.keys(), 1);
        drop(held);
        assert_eq!(counts.keys(), 0);
    }

    /// ADR 0020 rule 24 (security review of 1c-b, L-2): when the limiter table is full of active
    /// keys, requests of unknown keys take their token and their in-flight count on the overflow
    /// key, so two different unknown clients share one count.
    #[test]
    fn overflow_requests_share_one_in_flight_count() {
        let clients = proxy_policy();
        let limiter = query_limiter("2");
        for k in 0..64u8 {
            let key = clients.key([192, 0, 2, k].into());
            assert!(
                limiter
                    .take(key.unwrap_or_else(|| unreachable!()), RequestClass::Query)
                    .is_ok()
            );
        }
        let counts = Counts::new(1);
        let proxied = Admission::Proxied(Arc::clone(&counts));
        let proxy: IpAddr = [10, 0, 0, 1].into();
        let mut a = proxied_query("198.51.100.1");
        let held = admit(&clients, &limiter, proxy, &proxied, &mut a);
        assert!(held.is_some());
        let mut b = proxied_query("198.51.100.2");
        assert!(admit(&clients, &limiter, proxy, &proxied, &mut b).is_none());
        assert_eq!(refusal(&b), Some(Refusal::InFlight), "one overflow count");
        // The handlers still see each request's own key.
        assert_eq!(
            b.extensions().get::<RequestClient>().and_then(|c| c.key),
            clients.key([198, 51, 100, 2].into())
        );
        drop(held);
    }

    /// Code review of ADR 0019, finding 1: when hyper parses request N+1 before response N is
    /// written to the socket, each request keeps its own count, and a flush releases only the
    /// responses it wrote. (hyper 1.12 was not seen to parse ahead of an unwritten response end to
    /// end, so this is tested on the connection state.)
    #[tokio::test]
    async fn each_request_owns_its_count_until_its_response_is_written() {
        let clients = ClientPolicy::new(Vec::new(), Vec::new(), 64, 2);
        let key = clients
            .key([192, 0, 2, 1].into())
            .unwrap_or_else(|| unreachable!());
        let counts = Counts::new(clients.max_per_client);
        let state = Arc::new(ConnState::new(ConnLimits {
            max_connections: 4,
            max_connection_age: Duration::from_secs(60),
            max_requests_per_connection: 100,
            clients: Arc::new(clients),
            limiter: Arc::new(test_limiter()),
            max_header_bytes: 16_384,
            header_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(30),
        }));
        let done = |slot| Done {
            state: Arc::clone(&state),
            slot,
        };
        state.request_started(Some(0));
        drop(done(counts.try_acquire(key))); // response 1 buffered, not written
        state.request_started(Some(0));
        let second = done(counts.try_acquire(key));
        assert!(
            second.slot.is_some(),
            "two in flight, within the bound of 2"
        );
        assert!(
            counts.try_acquire(key).is_none(),
            "response 1 is still in flight"
        );
        state.flushed(); // writes response 1 only
        let probe = counts.try_acquire(key);
        assert!(probe.is_some(), "request 1 released");
        assert!(counts.try_acquire(key).is_none(), "request 2 still counted");
        drop((probe, second));
        state.flushed();
        assert_eq!(counts.keys(), 0);
    }

    fn end_of(stream: &[u8], split: usize) -> Option<u64> {
        let mut s = SCAN_START;
        let (a, b) = stream.split_at(split);
        s.feed(a, 0);
        s.feed(b, a.len() as u64);
        match s {
            Scan::Ended(e) => Some(e),
            _ => None,
        }
    }

    #[test]
    fn scan_finds_the_end_of_a_head() {
        let req = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nNEXT";
        for split in 0..req.len() {
            assert_eq!(end_of(req, split), Some(27), "split {split}");
        }
        assert_eq!(end_of(b"GET / HTTP/1.1\nHost: a\n\nX", 3), Some(24));
        // Leading empty lines are not a head end.
        assert_eq!(end_of(b"\r\n\r\nGET / HTTP/1.1\r\n\r\n", 0), Some(22));
        assert_eq!(end_of(b"GET / HTTP/1.1\r\nHost: a\r\n", 5), None);
    }
}
