//! HTTP routes (SPEC §5), the per-request guards (SPEC §7) and the CORS headers.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, CACHE_CONTROL, CONTENT_LENGTH,
    CONTENT_TYPE, LOCATION, RETRY_AFTER,
};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use sbtp_core::{BlockId, Error as BlockError, MAX_BLOCK_LEN};

use crate::store::Put;
use crate::{ClientKey, Live, Relay};
use crate::{MAX_FUTURE_MS, MAX_QUERY_LIMIT, MAX_SUBSCRIPTIONS_PER_IP, REQUESTS_PER_CLIENT};

/// A handler's result: its early exits are error responses.
pub type Reply = Result<Response, Response>;

/// spec §5: an error response, `{ "error": name }`. Names are fixed ASCII identifiers.
pub fn error(status: StatusCode, name: &str) -> Response {
    json(status, format!("{{\"error\":\"{name}\"}}"))
}

/// spec §7: `429 RateLimited` with `Retry-After` in seconds.
pub fn rate_limited(seconds: u64) -> Response {
    let mut response = error(StatusCode::TOO_MANY_REQUESTS, "RateLimited");
    response.headers_mut().insert(RETRY_AFTER, seconds.into());
    response
}

/// A JSON body that no cache keeps.
fn json(status: StatusCode, body: String) -> Response {
    let headers = [
        (CONTENT_TYPE, "application/json"),
        (CACHE_CONTROL, "no-store"),
    ];
    (status, headers, body).into_response()
}

/// Runs store or CPU work off the async workers; a failure is `503 Unavailable` (transient).
pub async fn blocking<T: Send + 'static>(
    relay: &Arc<Relay>,
    f: impl FnOnce(&Relay) -> Result<T, redb::Error> + Send + 'static,
) -> Result<T, Response> {
    let relay = Arc::clone(relay);
    let result = tokio::task::spawn_blocking(move || f(&relay).map_err(|e| e.to_string())).await;
    result.map_err(|e| e.to_string()).flatten().map_err(|e| {
        tracing::error!(error = e, "store error");
        error(StatusCode::SERVICE_UNAVAILABLE, "Unavailable")
    })
}

pub fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/sbtp/v1/block", put(put_block))
        .route("/sbtp/v1/block/{id}", get(get_block))
        .route("/sbtp/v1/query", get(query))
        .route("/sbtp/v1/info", get(info))
        .route("/sbtp/v1/subscribe", get(crate::subscribe::subscribe))
        .fallback(|| async { error(StatusCode::NOT_FOUND, "NotFound") })
        .method_not_allowed_fallback(|| async {
            error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed")
        })
        .layer(middleware::from_fn_with_state(Arc::clone(&relay), guard))
        .with_state(relay)
}

const CORS: [(HeaderName, &str); 2] = [
    (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
    (ACCESS_CONTROL_EXPOSE_HEADERS, "Location, Retry-After"),
];
/// CORS preflight of a browser `PUT` with `Content-Type: application/octet-stream`.
const PREFLIGHT: [(HeaderName, &str); 3] = [
    (ACCESS_CONTROL_ALLOW_METHODS, "GET, PUT"),
    (ACCESS_CONTROL_ALLOW_HEADERS, "content-type"),
    (ACCESS_CONTROL_MAX_AGE, "86400"),
];

/// spec §5 CORS headers on every response, around the limits of spec §7.
async fn guard(State(relay): State<Arc<Relay>>, req: Request, next: Next) -> Response {
    let response = if req.method() == Method::OPTIONS {
        (StatusCode::NO_CONTENT, PREFLIGHT).into_response()
    } else {
        limited(&relay, req, next).await.unwrap_or_else(|r| r)
    };
    (CORS, response).into_response()
}

/// spec §7: per-client rate and concurrency, then the global request cap.
async fn limited(relay: &Relay, mut req: Request, next: Next) -> Reply {
    let key = client_key(relay, &req);
    let factor = relay.factor(key);
    let (f, max) = (
        f64::from(factor),
        REQUESTS_PER_CLIENT.saturating_mul(factor),
    );
    relay.rate.check(key, f, 1.0).map_err(rate_limited)?;
    let busy = || rate_limited(1);
    let _client = relay.requests.acquire(key, max).ok_or_else(busy)?;
    let _slot = relay
        .request_slots
        .try_acquire()
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Unavailable"))?;
    req.extensions_mut().insert(key);
    Ok(next.run(req).await)
}

/// The client address: the last entry of the proxy's header when configured, else the peer.
fn client_key(relay: &Relay, req: &Request) -> ClientKey {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let header = relay.config.client_ip_header.as_ref();
    let last = header.and_then(|name| req.headers().get_all(name).iter().next_back());
    let entry = last.and_then(|v| Some(v.to_str().ok()?.rsplit(',').next()?.trim()));
    // A bare address, or `ip:port` and `[v6]:port` as some proxies write it.
    let parse = |e: &str| e.parse().or(e.parse().map(|s: SocketAddr| s.ip())).ok();
    entry
        .and_then(parse)
        .or(peer)
        .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into())
        .into()
}

fn now_ms() -> u64 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
}

/// Status of a §4 rejection on `PUT` (spec §5 table).
fn rejected(e: BlockError) -> Response {
    tracing::debug!(error = e.name(), "block rejected");
    let status = match e {
        BlockError::InvalidPublicKey | BlockError::InvalidSignature => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        _ => StatusCode::BAD_REQUEST,
    };
    error(status, e.name())
}

async fn put_block(
    State(relay): State<Arc<Relay>>,
    Extension(key): Extension<ClientKey>,
    headers: HeaderMap,
    body: Body,
) -> Reply {
    let too_large = || error(StatusCode::PAYLOAD_TOO_LARGE, "BodyTooLarge");
    // spec §5, §7: a body over 65,909 bytes is rejected before it is read.
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse().ok());
    if declared.is_some_and(|n: u64| n > MAX_BLOCK_LEN as u64) {
        return Err(too_large());
    }
    let read = axum::body::to_bytes(body, MAX_BLOCK_LEN);
    let bytes = tokio::time::timeout(relay.config.body_timeout, read)
        .await
        .map_err(|_| error(StatusCode::REQUEST_TIMEOUT, "RequestTimeout"))?
        // The limit, or a body cut short; either way nothing more is read.
        .map_err(|_| too_large())?;
    // Per client and per /48, in bytes, valid or not, before any CPU or disk is spent.
    #[allow(clippy::cast_precision_loss)]
    let (factor, cost) = (f64::from(relay.factor(key)), bytes.len() as f64);
    // The /48 is charged only once the client's own budget admits the body (re-review R-L-1).
    (relay.put_bytes.check(key, factor, cost))
        .and_then(|()| relay.put_bytes_wide.check(key.wide(), factor, cost))
        .map_err(rate_limited)?;
    blocking(&relay, move |relay| {
        // spec §5 `PUT`, in order: F1 to F9, P1, C1, C2, C3, the deny list, then storage.
        let checked = sbtp_core::parse(&bytes).and_then(|block| {
            block.check_timestamp(now_ms(), MAX_FUTURE_MS)?;
            block
                .check_pow(relay.config.min_pow_difficulty)?
                .verify_signature()
        });
        let block = match checked {
            Ok(block) => block,
            Err(e) => return Ok(Err(rejected(e))),
        };
        let id = *block.block_id();
        let quota = relay.config.max_store_bytes;
        let put = relay.store.put(&block, quota, |position| {
            let frame = [&position.to_be_bytes()[..], &bytes].concat().into();
            // No receiver is not an error: nobody is subscribed.
            let _ = relay.live.send(Live {
                position,
                id: id.0,
                frame,
            });
        })?;
        Ok(match put {
            Put::Existing => Ok(StatusCode::OK.into_response()),
            Put::Denied(name) => Err(error(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS, name)),
            Put::Full => {
                tracing::warn!("disk quota reached, block refused");
                Err(error(StatusCode::INSUFFICIENT_STORAGE, "StorageFull"))
            }
            Put::Stored(position) => {
                tracing::info!(block = %id, position, "block stored");
                let location = format!("/sbtp/v1/block/{id}");
                Ok((StatusCode::CREATED, [(LOCATION, location)]).into_response())
            }
        })
    })
    .await?
}

async fn get_block(
    State(relay): State<Arc<Relay>>,
    id: Result<Path<String>, PathRejection>,
) -> Reply {
    let id = id.ok().and_then(|Path(s)| s.parse::<BlockId>().ok());
    let id = id.ok_or_else(|| error(StatusCode::BAD_REQUEST, "InvalidParameter"))?;
    let bytes = blocking(&relay, move |relay| relay.store.get(&id)).await?;
    let bytes = bytes.ok_or_else(|| error(StatusCode::NOT_FOUND, "NotFound"))?;
    let bytes = bytes.map_err(|_| error(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS, "Denied"))?;
    let headers = [
        (CONTENT_TYPE, "application/octet-stream"),
        (CACHE_CONTROL, "public, max-age=31536000, immutable"),
    ];
    Ok((headers, bytes).into_response())
}

/// Parameters of `/query` and `/subscribe` (spec §5, §6).
#[derive(Default)]
pub struct Params {
    pub parent: Option<BlockId>,
    pub since: Option<u64>,
    pub limit: Option<u64>,
}

/// spec §5: an unknown, repeated or malformed parameter is `400 InvalidParameter`.
pub fn params(uri: &Uri, allowed: &[&str]) -> Result<Params, Response> {
    let bad = || error(StatusCode::BAD_REQUEST, "InvalidParameter");
    let mut p = Params::default();
    for pair in uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|s| !s.is_empty())
    {
        let (name, value) = pair.split_once('=').ok_or_else(bad)?;
        let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
        let fresh = match name {
            _ if !allowed.contains(&name) => false,
            "parent" => p
                .parent
                .replace(value.parse().map_err(|_| bad())?)
                .is_none(),
            // spec §5: at most 20 digits; above 2^64 − 1 is malformed.
            "since" if digits && value.len() <= 20 => {
                p.since.replace(value.parse().map_err(|_| bad())?).is_none()
            }
            // spec §5: at least 1; a value above the cap is lowered, so overflow saturates.
            "limit" if digits => p.limit.replace(value.parse().unwrap_or(u64::MAX)).is_none(),
            _ => false,
        };
        if !fresh || p.limit == Some(0) {
            return Err(bad());
        }
    }
    Ok(p)
}

/// spec §5: a position beyond every position given is `400 InvalidPosition`.
pub fn check_position(relay: &Relay, since: u64) -> Result<(), Response> {
    if since > relay.store.max_position() {
        return Err(error(StatusCode::BAD_REQUEST, "InvalidPosition"));
    }
    Ok(())
}

async fn query(State(relay): State<Arc<Relay>>, uri: Uri) -> Reply {
    let p = params(&uri, &["parent", "since", "limit"])?;
    let since = p.since.unwrap_or(0);
    check_position(&relay, since)?;
    let limit = p.limit.unwrap_or(100).min(MAX_QUERY_LIMIT.into());
    let limit = usize::try_from(limit).unwrap_or(1);
    let page = blocking(&relay, move |relay| {
        relay.store.page(p.parent, since, limit, None)
    })
    .await?;
    // spec §5: about 90 KB for 1,000 entries, under the 131,072-byte cap.
    let (mut ids, mut positions) = (String::new(), String::new());
    for (n, item) in page.items.iter().enumerate() {
        let comma = if n == 0 { "" } else { "," };
        let _ = write!(ids, "{comma}\"{}\"", BlockId(item.id));
        let _ = write!(positions, "{comma}\"{}\"", item.position);
    }
    let (since, more) = (page.since, page.more);
    let body = format!(
        "{{\"block_ids\":[{ids}],\"positions\":[{positions}],\"since\":\"{since}\",\"more\":{more}}}"
    );
    Ok(json(StatusCode::OK, body))
}

async fn info(State(relay): State<Arc<Relay>>) -> Reply {
    let last = relay.store.last_served();
    let (id, pow) = (&relay.store.relay_id, relay.config.min_pow_difficulty);
    let body = format!(
        "{{\"relay_id\":\"{id}\",\"min_pow_difficulty\":{pow},\"max_future_ms\":{MAX_FUTURE_MS},\
         \"block_versions\":[1],\"max_query_limit\":{MAX_QUERY_LIMIT},\
         \"max_subscriptions_per_ip\":{MAX_SUBSCRIPTIONS_PER_IP},\"last_position\":\"{last}\"}}"
    );
    Ok(json(StatusCode::OK, body))
}
