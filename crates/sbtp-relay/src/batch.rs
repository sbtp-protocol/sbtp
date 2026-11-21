//! `POST /sbtp/v1/blocks`, the batch read (spec §4; ADR 0051 rules 1 to 12).
//!
//! The body is 1 to 256 distinct raw 32-byte `block_id` values. The response is one record per
//! identifier, in request order: `length (u32, big-endian) ‖ length bytes`, `length = 0` when the
//! block is not served. Every record goes through the read path of `GET /block`
//! ([`Relay::fetch`]: the cache, or a file that passes full validation and R1 in one job of the
//! block reader threads, rule 5), and each served block is a demand of that block, at most once
//! per epoch (rule 8), except for a copy (`Sbtp-Replication: 1`, rule 9).
//!
//! The first record is read before the response head is sent, so that a full read queue gives
//! `503` and an I/O error `500`, as on `GET /block`. The others are streamed: [`BatchBody`] reads
//! the next block only when hyper polls for more, that is once hyper's write buffer has room, so
//! that a batch holds at most one block beyond its HTTP send buffer (rule 5) and a slow reader
//! holds no reader thread. The body ends early, after a complete record (rule 3), when the next
//! record would bring it above 1,048,576 bytes (rule 4), when the time budget is spent (half of
//! `request_timeout_ms`, so that the rest of the body is written before the connection's response
//! deadline, ADR 0018 rule 25), or when a later read is refused or fails.
//!
//! Admission (ADR 0051 rule 7): `server::request_weight` charges `⌈N / 4⌉` `block` tokens from
//! `Content-Length` before the body is read. A request without `Content-Length`, or with a
//! `Transfer-Encoding`, is charged 64 tokens and then refused here with `400`
//! (`InvalidParameter`) before any byte of the body is read, and its connection is closed: the
//! batch body is at most 8,192 bytes, which every client can announce.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body::{Frame, SizeHint};
use sbtp_core::BlockId;
use tokio::time::Instant;

use crate::api::read_body;
use crate::blocks::{Fetched, Relay, is_replication};
use crate::config::Settings;
use crate::error::ApiError;
use crate::index::IndexBackend;
use crate::metrics::{self, BatchEnd};

/// The route (ADR 0051 rule 1).
pub const PATH: &str = "/sbtp/v1/blocks";

/// Identifiers per request at most (rule 1).
pub const MAX_IDS: usize = 256;

/// The body ceiling of a request: `MAX_IDS × 32` bytes (rule 1).
pub const MAX_REQUEST_BYTES: usize = MAX_IDS * 32;

/// The body ceiling of a response (rule 4).
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// The length prefix of a record.
const RECORD_HEAD: usize = 4;

/// Why a batch request was refused with `400`, one variant per rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchError {
    /// No `Content-Length`, or a `Transfer-Encoding` (this relay's rule, see the module text).
    NoLength,
    /// Rule 1: an empty body.
    Empty,
    /// Rule 1: a length that is not a multiple of 32.
    NotWhole,
    /// Rule 1: an identifier given twice.
    Duplicate,
}

impl BatchError {
    /// The `400 InvalidParameter` of this error.
    #[must_use]
    pub fn to_api(self) -> ApiError {
        let invalid = ApiError::invalid_parameter;
        match self {
            Self::NoLength => invalid()
                .with_message(
                    "POST /sbtp/v1/blocks needs a Content-Length and no Transfer-Encoding",
                )
                .closing(),
            Self::Empty => invalid().with_message("the body holds no block_id"),
            Self::NotWhole => {
                invalid().with_message("the body is not a whole number of 32-byte ids")
            }
            Self::Duplicate => invalid().with_message("a block_id is repeated"),
        }
    }
}

/// The identifiers of a request body of at most [`MAX_REQUEST_BYTES`] (rule 1).
///
/// # Errors
///
/// [`BatchError::Empty`], [`BatchError::NotWhole`] or [`BatchError::Duplicate`].
pub fn parse_ids(body: &[u8]) -> Result<Vec<BlockId>, BatchError> {
    if body.is_empty() {
        return Err(BatchError::Empty);
    }
    if !body.len().is_multiple_of(32) {
        return Err(BatchError::NotWhole);
    }
    let (chunks, _) = body.as_chunks::<32>();
    let ids: Vec<BlockId> = chunks.iter().map(|c| BlockId(*c)).collect();
    let mut sorted: Vec<&[u8; 32]> = ids.iter().map(BlockId::as_bytes).collect();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w.first() == w.get(1)) {
        return Err(BatchError::Duplicate);
    }
    Ok(ids)
}

/// The state of the batch route.
pub struct BatchState<I> {
    relay: Arc<Relay<I>>,
    /// No record is started once this much time has passed since the request was handled.
    budget: Duration,
}

impl<I: IndexBackend + 'static> BatchState<I> {
    /// The route's state over `relay`.
    #[must_use]
    pub fn new(s: &Settings, relay: Arc<Relay<I>>) -> Self {
        Self {
            relay,
            budget: Duration::from_millis(s.request_timeout_ms / 2),
        }
    }
}

/// `POST /sbtp/v1/blocks` (ADR 0051 rules 1 to 12).
pub async fn post_blocks<I: IndexBackend + 'static>(
    State(state): State<Arc<BatchState<I>>>,
    req: Request,
) -> Response {
    let started = Instant::now();
    let relay = Arc::clone(&state.relay);
    let headers = req.headers();
    let announced = headers
        .get(header::CONTENT_LENGTH)
        .filter(|_| !headers.contains_key(header::TRANSFER_ENCODING))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let Some(announced) = announced else {
        return BatchError::NoLength.to_api().into_response();
    };
    // Rule 1: `413` before the body is read.
    if announced > MAX_REQUEST_BYTES as u64 {
        return ApiError::body_too_large().into_response();
    }
    // Rule 9; rule 10: `If-None-Match` is not read.
    let copy = is_replication(headers);
    let body = match read_body(req.into_body(), MAX_REQUEST_BYTES, relay.body_timeout()).await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let ids = match parse_ids(&body) {
        Ok(ids) => ids,
        Err(e) => return e.to_api().into_response(),
    };
    drop(body);
    metrics::batch_request();
    // The first record decides the status, as on `GET /block`; it always fits (rule 4).
    let Some(&first) = ids.first() else {
        return BatchError::Empty.to_api().into_response();
    };
    let mut out = BatchBody {
        relay: Arc::clone(&relay),
        ids,
        next: 0,
        sent: 0,
        copy,
        deadline: started + state.budget,
        prefix: None,
        block: None,
        reading: None,
        done: false,
    };
    match Arc::clone(&relay).fetch(first).await {
        Fetched::Busy(r) => return relay.shed_response(r),
        Fetched::Failed => return ApiError::internal().into_response(),
        fetched => {
            if out.emit(fetched).is_err() {
                return ApiError::internal().into_response();
            }
        }
    }
    let mut r = Response::new(Body::new(out));
    *r.status_mut() = StatusCode::OK;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Rule 2; rule 9 adds `CDN-Cache-Control` for a copy.
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if copy {
        h.insert(
            HeaderName::from_static("cdn-cache-control"),
            HeaderValue::from_static("no-store"),
        );
    }
    r
}

type Reading = Pin<Box<dyn Future<Output = Fetched> + Send>>;

/// The streamed body of a batch: the records after the first, each read when hyper asks for
/// more (rule 5).
struct BatchBody<I> {
    relay: Arc<Relay<I>>,
    ids: Vec<BlockId>,
    /// The index of the next identifier to read.
    next: usize,
    /// Body bytes emitted so far.
    sent: usize,
    /// `Sbtp-Replication: 1`: no demand (rule 9).
    copy: bool,
    /// No record is started after this instant (rule 3, time budget).
    deadline: Instant,
    /// The length prefix of the current record, then its block, not yet handed to hyper.
    prefix: Option<Bytes>,
    block: Option<Bytes>,
    /// The read of identifier `next`, while it runs.
    reading: Option<Reading>,
    done: bool,
}

impl<I: IndexBackend + 'static> BatchBody<I> {
    /// Queues the record of identifier `next` from `fetched`, or ends the body (rule 3). `Err`
    /// when the body ends; then nothing was queued.
    fn emit(&mut self, fetched: Fetched) -> Result<(), ()> {
        let Some(&id) = self.ids.get(self.next) else {
            return Err(());
        };
        let (len, block) = match fetched {
            Fetched::Served(bytes) => (bytes.len(), Some(bytes)),
            Fetched::Missing => (0, None),
            // ADR 0052 rules 8 and 15: a `length = 0` record, counted, not demand.
            Fetched::Denied(m) => {
                metrics::denied(metrics::DenyRoute::Batch, m.is_key(), 1);
                (0, None)
            }
            Fetched::Busy(_) => return self.end(BatchEnd::Busy),
            Fetched::Failed => return self.end(BatchEnd::Failed),
        };
        // Rule 4: never start a record that would bring the body above the ceiling.
        let record = RECORD_HEAD.saturating_add(len);
        if self.sent.saturating_add(record) > MAX_RESPONSE_BYTES {
            return self.end(BatchEnd::Ceiling);
        }
        let Ok(prefix) = u32::try_from(len) else {
            return self.end(BatchEnd::Failed);
        };
        self.sent += record;
        self.next += 1;
        self.prefix = Some(Bytes::copy_from_slice(&prefix.to_be_bytes()));
        if let Some(b) = block {
            // Rule 8: a served block is a demand, once per epoch (the demand set), never a copy's.
            if !self.copy {
                self.relay.served(&id);
            }
            metrics::batch_record(true);
            self.block = Some(b);
        } else {
            metrics::batch_record(false);
        }
        if self.next == self.ids.len() {
            self.done = true;
        }
        Ok(())
    }

    /// Ends the body after the last complete record, counted by `why`; always `Err`.
    fn end(&mut self, why: BatchEnd) -> Result<(), ()> {
        metrics::batch_end(why);
        self.done = true;
        Err(())
    }
}

impl<I: IndexBackend + 'static> http_body::Body for BatchBody<I> {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if let Some(p) = this.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(p))));
        }
        if let Some(b) = this.block.take() {
            return Poll::Ready(Some(Ok(Frame::data(b))));
        }
        if this.done {
            return Poll::Ready(None);
        }
        if this.reading.is_none() {
            if Instant::now() >= this.deadline {
                let _ = this.end(BatchEnd::Budget);
                return Poll::Ready(None);
            }
            let Some(&id) = this.ids.get(this.next) else {
                this.done = true;
                return Poll::Ready(None);
            };
            this.reading = Some(Box::pin(Arc::clone(&this.relay).fetch(id)));
        }
        let Some(reading) = this.reading.as_mut() else {
            return Poll::Ready(None);
        };
        let Poll::Ready(fetched) = reading.as_mut().poll(cx) else {
            return Poll::Pending;
        };
        this.reading = None;
        if this.emit(fetched).is_err() {
            return Poll::Ready(None);
        }
        match this.prefix.take() {
            Some(p) => Poll::Ready(Some(Ok(Frame::data(p)))),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.prefix.is_none() && self.block.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn ids_are_parsed_and_checked() {
        let one = [7u8; 32];
        assert_eq!(parse_ids(&one), Ok(vec![BlockId(one)]));
        assert_eq!(parse_ids(&[]), Err(BatchError::Empty));
        assert_eq!(parse_ids(&[1; 33]), Err(BatchError::NotWhole));
        assert_eq!(parse_ids(&[1; 31]), Err(BatchError::NotWhole));
        assert_eq!(parse_ids(&[1; 64]), Err(BatchError::Duplicate));
        let mut many = Vec::new();
        for n in 0..MAX_IDS {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            many.extend_from_slice(&id);
        }
        let ids = parse_ids(&many).unwrap();
        assert_eq!(ids.len(), MAX_IDS);
        assert_eq!(ids[3].as_bytes()[7], 3, "request order is kept");
        // A duplicate far apart.
        let first = many[..32].to_owned();
        many.extend_from_slice(&first);
        assert_eq!(parse_ids(&many), Err(BatchError::Duplicate));
        for e in [
            BatchError::NoLength,
            BatchError::Empty,
            BatchError::NotWhole,
            BatchError::Duplicate,
        ] {
            let a = e.to_api();
            assert_eq!((a.status().as_u16(), a.name()), (400, "InvalidParameter"));
        }
    }

    struct Fixture {
        relay: Arc<Relay<crate::index::RedbIndex>>,
        app: axum::Router,
        _pool: crate::pool::IndexPool<crate::index::RedbIndex>,
    }

    fn fixture(name: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("sbtp-batch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let env = [("SBTP_RELAY_MIN_POW_DIFFICULTY", "0")]
            .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)));
        let settings = Settings::load(Vec::<std::ffi::OsString>::new(), env).unwrap();
        let index_file = dir.join("index.redb");
        let index = Arc::new(crate::index::RedbIndex::open(&index_file, 1 << 20).unwrap());
        let store = crate::store::Store::open(&dir, index_file, settings.max_store_bytes).unwrap();
        let pool = crate::pool::IndexPool::start(&index, &settings).unwrap();
        let relay = Arc::new(Relay::new(&settings, store, pool.handle()).unwrap());
        let app = crate::api::routes(&settings, Arc::clone(&relay));
        Fixture {
            relay,
            app,
            _pool: pool,
        }
    }

    async fn call(f: &Fixture, method: &str, uri: &str, body: Vec<u8>, copy: bool) -> Response {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_LENGTH, body.len());
        if copy {
            req = req.header("sbtp-replication", "1");
        }
        f.app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    fn block(n: u8) -> (Vec<u8>, BlockId) {
        let k = sbtp_core::SigningKey::from_bytes(&[5; 32]);
        let bytes = sbtp_core::BlockBuilder::for_key(&k)
            .timestamp(1)
            .payload(&[n; 20])
            .build(&k, 0)
            .unwrap();
        let id = sbtp_core::parse(&bytes).unwrap().block_id();
        (bytes, id)
    }

    /// Rules 8 and 9: each served record is a demand of its block, once per epoch however many
    /// batches serve it; an empty record is none; a copy (`Sbtp-Replication: 1`) counts none.
    #[tokio::test]
    async fn served_records_are_demand_once() {
        for copy in [false, true] {
            let f = fixture(if copy { "copy" } else { "demand" });
            let (a, ida) = block(1);
            let (b, idb) = block(2);
            for bytes in [a, b] {
                let r = call(&f, "PUT", "/sbtp/v1/block", bytes, false).await;
                assert_eq!(r.status(), StatusCode::CREATED);
            }
            // The acceptances are recorded by the index writer, not in the set (ADR 0046 rule 14).
            assert_eq!(f.relay.demand().len(), 0);
            let missing = BlockId([9; 32]);
            let body: Vec<u8> = [ida, missing, idb].iter().flat_map(|i| i.0).collect();
            for _ in 0..3 {
                let r = call(&f, "POST", PATH, body.clone(), copy).await;
                assert_eq!(r.status(), StatusCode::OK);
                let bytes = axum::body::to_bytes(r.into_body(), MAX_RESPONSE_BYTES)
                    .await
                    .unwrap();
                assert!(bytes.len() > 12);
            }
            if copy {
                assert_eq!(f.relay.demand().len(), 0, "a copy is not demand");
            } else {
                assert_eq!(
                    f.relay.demand().len(),
                    2,
                    "once per block, the missing one not"
                );
                assert!(f.relay.demand().contains(&ida) && f.relay.demand().contains(&idb));
                assert!(!f.relay.demand().contains(&missing));
            }
        }
    }

    /// Rule 4: the first record always fits.
    const _: () = assert!(RECORD_HEAD + sbtp_core::layout::MAX_BLOCK_LEN <= MAX_RESPONSE_BYTES);
    const _: () = assert!(MAX_REQUEST_BYTES == 8_192);
}
