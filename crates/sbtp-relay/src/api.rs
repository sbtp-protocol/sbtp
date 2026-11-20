//! Routes and middleware of `/sbtp/v1/` (spec §4; ADR 0007, ADR 0012, ADR 0018).
//!
//! Layers, outermost first: counters and the `request` line ([`observe`], ADR 0021 rules 40 and
//! 41), relabel of a refused preflight ([`refuse`]), CORS (ADR 0012 rules 23
//! to 28, so that every relay response carries it), panic to `500` (ADR 0018 rule 37), request
//! deadline to `503` (rule 25), refusal to `429` (ADR 0019 rule 30, ADR 0020 rule 22), JSON body
//! on `405`. axum's `Router::layer` wraps each route and the fallback: the layers run after the
//! path is matched and before the method is dispatched.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use http_body::Body as _;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::blocks::{Relay, get_block, put_block};
use crate::config::{CorsOrigins, Settings};
use crate::error::{ApiError, panic_response};
use crate::index::IndexBackend;
use crate::log::{self, Event, Level, Throttle, Value};
use crate::metrics::{self, Route};
use crate::query::{QueryState, query};
use crate::server::{RequestClass, RequestClient};

/// The routes of the relay, without middleware: `/info`, `PUT /sbtp/v1/block`,
/// `GET /sbtp/v1/block/{block_id}` and `GET /sbtp/v1/query` over `relay` and its index.
pub fn routes<I: IndexBackend + 'static>(settings: &Settings, relay: Arc<Relay<I>>) -> Router {
    let info = Bytes::from(info_body(settings));
    let queries = Router::new()
        .route("/sbtp/v1/query", get(query::<I>))
        .with_state(Arc::new(QueryState::new(settings, relay.index().clone())));
    let blocks = Router::new()
        .route("/sbtp/v1/block", put(put_block::<I>))
        .route("/sbtp/v1/block/{id}", get(get_block::<I>))
        .with_state(relay);
    Router::new()
        .route(
            "/sbtp/v1/info",
            get(move || {
                let info = info.clone();
                async move {
                    (
                        [(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        )],
                        info,
                    )
                }
            }),
        )
        .merge(blocks)
        .merge(queries)
        .fallback(|| async { ApiError::not_found() })
}

/// The JSON body of `GET /sbtp/v1/info`: the members of ADR 0007 rule 11 and ADR 0012 rule 20,
/// nothing else (ADR 0018 rule 38). `software` (ADR 0012 rule 21, optional) is not published
/// (ADR 0019 rule 25).
fn info_body(s: &Settings) -> String {
    serde_json::json!({
        "min_pow_difficulty": s.min_pow_difficulty,
        "max_future_ms": s.max_future_ms,
        "block_versions": [sbtp_core::layout::VERSION_V1],
        "max_query_limit": s.max_query_limit,
        // ADR 0019 rule 7: `null` when eviction by age is disabled, never 0.
        "block_ttl_ms": s.block_ttl_ms,
    })
    .to_string()
}

/// Wraps `router` in the relay's middleware.
pub fn layered(router: Router, settings: &Settings) -> Router {
    let deadline = Arc::new(Deadline {
        request: Duration::from_millis(settings.request_timeout_ms),
        retry_after_s: settings.shed_retry_after_s,
    });
    router
        .layer(middleware::map_response(json_405))
        .layer(middleware::from_fn(refused))
        .layer(middleware::from_fn_with_state(deadline, request_deadline))
        .layer(middleware::from_fn(mark_caught))
        .layer(CatchPanicLayer::custom(panic_response))
        .layer(cors(&settings.cors_allow_origins))
        .layer(middleware::from_fn(relabel_refused_preflight))
        .layer(middleware::from_fn(observe))
}

/// Directly inside `CatchPanicLayer`: a panic while the request is polled here is caught, and
/// the panic hook writes it queued and throttled (ADR 0021 rule 9, `log::Caught`).
fn mark_caught(req: Request, next: Next) -> log::Caught<impl Future<Output = Response>> {
    log::Caught::new(next.run(req))
}

/// ADR 0021 rules 39 to 41: counts every response by route template and status class, and writes
/// the `request` line at `debug` only. Outermost, so that it sees the final status. The route is
/// the template axum matched, the method one of a fixed set: nothing the client chose is logged.
async fn observe(req: Request, next: Next) -> Response {
    let start = tokio::time::Instant::now();
    let route = Route::of(
        req.extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    let method = match *req.method() {
        Method::GET => "GET",
        Method::PUT => "PUT",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::POST => "POST",
        Method::DELETE => "DELETE",
        _ => "other",
    };
    let response = next.run(req).await;
    metrics::request(route, response.status());
    if log::global().enabled(Level::Debug) {
        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        log::emit(
            Event::Request,
            &[
                ("route", Value::Str(route.template())),
                ("method", Value::Str(method)),
                ("status", Value::Int(u64::from(response.status().as_u16()))),
                ("duration_ms", Value::Int(ms)),
            ],
        );
    }
    response
}

/// The production application: [`routes`] inside [`layered`].
pub fn app<I: IndexBackend + 'static>(settings: &Settings, relay: Arc<Relay<I>>) -> Router {
    layered(routes(settings, relay), settings)
}

/// ADR 0012 rules 23 to 27. No credentials, whatever the setting (rule 26): `allow_credentials` is
/// never called.
/// The origins were validated, lowercased and converted to header values by the settings loader.
fn cors(origins: &CorsOrigins) -> CorsLayer {
    let allow = match origins {
        CorsOrigins::Any => AllowOrigin::any(),
        CorsOrigins::List(list) => AllowOrigin::list(list.iter().cloned()),
    };
    CorsLayer::new()
        .allow_origin(allow)
        .allow_methods([Method::GET, Method::PUT])
        .allow_headers([header::CONTENT_TYPE])
        .max_age(Duration::from_secs(86_400))
        .expose_headers([header::LOCATION, header::RETRY_AFTER])
}

struct Deadline {
    request: Duration,
    retry_after_s: u64,
}

/// ADR 0018 rule 25: no response within `request_timeout_ms` of the end of the headers gives
/// `503 Unavailable` with `Retry-After`. The handler future is dropped. The transfer of a response
/// that has started is bounded by the connection task (`server`).
async fn request_deadline(State(d): State<Arc<Deadline>>, req: Request, next: Next) -> Response {
    static SHED_LOG: Throttle = Throttle::new();
    let key = client_key(&req);
    if let Ok(response) = tokio::time::timeout(d.request, next.run(req)).await {
        return response;
    }
    let r = metrics::Refused::RequestTimeout;
    metrics::refused(r);
    log::throttled(
        &SHED_LOG,
        Event::Shed,
        &[("reason", Value::Str(r.reason()))],
        key.as_ref(),
    );
    ApiError::unavailable(d.retry_after_s).into_response()
}

/// The client key of a request, as computed once at admission (ADR 0020 rule 21).
fn client_key(req: &Request) -> Option<crate::client::ClientKey> {
    req.extensions().get::<RequestClient>().and_then(|c| c.key)
}

/// Why step 3 of ADR 0018 rule 28 refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Over `max_connections_per_client` requests in flight (ADR 0019 rule 30): `Retry-After: 1`.
    InFlight,
    /// The token bucket of `class` is empty (ADR 0018 rules 21 and 29).
    EmptyBucket {
        /// The bucket.
        class: RequestClass,
        /// Seconds until one token is available.
        retry_after_s: u64,
    },
}

/// The marker of a refused request. `method` is the method the client sent, which later layers
/// and log lines must read instead of the request's (see [`refuse`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    /// Why the request was refused.
    pub refusal: Refusal,
    /// The method as received.
    pub method: Method,
}

/// Marks `req` as refused at step 3 (ADR 0020 rule 22). Every refusal point (the token bucket,
/// the in-flight count) goes through here. The request then gets the `429` of
/// [`refused`], with the CORS headers of a normal response (ADR 0018 rule 34).
///
/// The CORS layer answers every `OPTIONS` itself, before [`refused`] could run, so a refused
/// preflight would get a `200`. [`relabel_refused_preflight`], placed directly outside the CORS
/// layer, therefore relabels a refused `OPTIONS` as `GET`; the original method stays in
/// [`Refused::method`]. The relabelled request never reaches a handler: [`refused`] wraps every
/// route and the fallbacks and answers it first. Tested by `refused_preflight_layer_order`.
pub fn refuse(req: &mut Request, refusal: Refusal) {
    let method = req.method().clone();
    req.extensions_mut().insert(Refused { refusal, method });
}

/// See [`refuse`]. Must stay the layer directly outside the CORS layer.
async fn relabel_refused_preflight(mut req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS && req.extensions().get::<Refused>().is_some() {
        *req.method_mut() = Method::GET;
    }
    next.run(req).await
}

/// ADR 0019 rule 30 and ADR 0020 rule 22: a request marked by [`refuse`] gets `429 RateLimited`
/// before its method is dispatched and before its body is read (spec §4, "Admission control").
/// axum runs this layer after the path is matched; no handler runs.
async fn refused(req: Request, next: Next) -> Response {
    static IN_FLIGHT_LOG: Throttle = Throttle::new();
    // ADR 0021 rule 6: `class` is the bucket; one throttle per bucket.
    static BLOCK_LOG: Throttle = Throttle::new();
    static QUERY_LOG: Throttle = Throttle::new();
    static PUT_LOG: Throttle = Throttle::new();
    let (r, retry_after_s, throttle): (_, _, &'static Throttle) =
        match req.extensions().get::<Refused>().map(|r| r.refusal) {
            Some(Refusal::InFlight) => (metrics::Refused::InFlight, 1, &IN_FLIGHT_LOG),
            Some(Refusal::EmptyBucket {
                class: RequestClass::Block,
                retry_after_s,
            }) => (metrics::Refused::BlockRate, retry_after_s, &BLOCK_LOG),
            Some(Refusal::EmptyBucket {
                class: RequestClass::Query,
                retry_after_s,
            }) => (metrics::Refused::QueryRate, retry_after_s, &QUERY_LOG),
            Some(Refusal::EmptyBucket {
                class: RequestClass::Put,
                retry_after_s,
            }) => (metrics::Refused::PutRate, retry_after_s, &PUT_LOG),
            None => return next.run(req).await,
        };
    metrics::refused(r);
    log::throttled(
        throttle,
        Event::RateLimited,
        &[("class", Value::Str(r.reason()))],
        client_key(&req).as_ref(),
    );
    ApiError::rate_limited(retry_after_s).into_response()
}

/// axum answers an unsupported method with an empty `405`; ADR 0012 rule 17 wants the JSON body
/// and the `Allow` header.
async fn json_405(response: Response) -> Response {
    if response.status() != StatusCode::METHOD_NOT_ALLOWED {
        return response;
    }
    let allow = response.headers().get(header::ALLOW).cloned();
    let mut json = ApiError::method_not_allowed().into_response();
    if let Some(allow) = allow {
        json.headers_mut().insert(header::ALLOW, allow);
    }
    json
}

/// Reads a whole request body of at most `limit` bytes, which must arrive within `timeout` of the
/// call: a deadline on the whole transfer, not between two reads (ADR 0018 rule 24). The caller
/// calls it once the request is admitted, so that the deadline starts at admission.
///
/// # Errors
///
/// `408 RequestTimeout` at the deadline; `413 BodyTooLarge` over `limit`, before any byte is read
/// when `Content-Length` already exceeds it (ADR 0018 rule 28 step 4); `400` if the body is
/// malformed (bad chunked framing, after which hyper drops the connection). The first two close
/// the connection.
pub async fn read_body(body: Body, limit: usize, timeout: Duration) -> Result<Bytes, ApiError> {
    tokio::time::timeout(timeout, collect(body, limit))
        .await
        .unwrap_or_else(|_| Err(ApiError::request_timeout()))
}

/// Kept instead of `http_body_util::Limited`: its overflow error reaches the caller as a boxed
/// error to downcast (`LengthLimitError`) to tell `413` from a malformed body, and it would add a
/// direct dependency; this loop maps both cases directly.
async fn collect(mut body: Body, limit: usize) -> Result<Bytes, ApiError> {
    let announced = body.size_hint().lower();
    if announced > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(ApiError::body_too_large());
    }
    // `announced` is at most `limit` here, so the buffer is bounded by the limit.
    let mut buf = Vec::with_capacity(usize::try_from(announced).unwrap_or(limit));
    while let Some(frame) =
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
    {
        let frame = frame.map_err(|_| {
            ApiError::invalid_parameter().with_message("the request body could not be read")
        })?;
        if let Ok(data) = frame.into_data() {
            if buf.len().saturating_add(data.len()) > limit {
                return Err(ApiError::body_too_large());
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    /// Security review of ADR 0020, L-1: fails if the relabel layer, the CORS layer and the
    /// refusal layer change order. A refused preflight gets the `429` with CORS headers and runs
    /// no handler (the `GET` handler has a visible side effect); a preflight under the bound gets
    /// the normal CORS answer.
    #[tokio::test]
    async fn refused_preflight_layer_order() {
        let settings = Settings::load(Vec::<std::ffi::OsString>::new(), Vec::new()).unwrap();
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let app = layered(
            Router::new().route(
                "/x",
                get(move || {
                    counted.fetch_add(1, Ordering::Relaxed);
                    async { "ran" }
                }),
            ),
            &settings,
        );
        let preflight = |refused: bool| {
            let mut req = Request::builder()
                .method(Method::OPTIONS)
                .uri("/x")
                .header(header::ORIGIN, "https://app.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PUT")
                .body(Body::empty())
                .unwrap();
            if refused {
                refuse(&mut req, Refusal::InFlight);
            }
            req
        };
        let r = app.clone().oneshot(preflight(true)).await.unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()[header::RETRY_AFTER], "1");
        assert_eq!(r.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(
            !r.headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS)
        );
        assert_eq!(runs.load(Ordering::Relaxed), 0, "no handler ran");

        let r = app.clone().oneshot(preflight(false)).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(
            r.headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS)
        );
        assert_eq!(runs.load(Ordering::Relaxed), 0);

        let mut get_req = preflight(false);
        *get_req.method_mut() = Method::GET;
        refuse(&mut get_req, Refusal::InFlight);
        let r = app.oneshot(get_req).await.unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            runs.load(Ordering::Relaxed),
            0,
            "a refused GET runs no handler"
        );
    }

    #[test]
    fn refuse_keeps_the_original_method() {
        let mut req = Request::builder()
            .method(Method::OPTIONS)
            .body(Body::empty())
            .unwrap();
        refuse(&mut req, Refusal::InFlight);
        assert_eq!(
            req.extensions().get::<Refused>(),
            Some(&Refused {
                refusal: Refusal::InFlight,
                method: Method::OPTIONS
            })
        );
    }
}
