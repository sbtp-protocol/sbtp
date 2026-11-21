//! Error responses (ADR 0012 rules 16 and 17, amended by ADR 0018 rules 33 and 34).

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// A relay error: an HTTP status, an error name of ADR 0012 rule 17 and an optional message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    status: StatusCode,
    name: &'static str,
    message: Option<&'static str>,
    retry_after_s: Option<u64>,
    close: bool,
}

impl ApiError {
    fn new(status: StatusCode, name: &'static str) -> Self {
        Self {
            status,
            name,
            message: None,
            retry_after_s: None,
            close: false,
        }
    }

    /// `404 NotFound`: unknown path (ADR 0012 rule 17).
    #[must_use]
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NotFound")
    }

    /// `405 MethodNotAllowed`. The caller keeps the `Allow` header.
    #[must_use]
    pub fn method_not_allowed() -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed")
    }

    /// `408 RequestTimeout`: the body did not arrive within `body_timeout_ms` (ADR 0018 rule 24).
    /// The connection is closed after the response.
    #[must_use]
    pub fn request_timeout() -> Self {
        Self {
            close: true,
            ..Self::new(StatusCode::REQUEST_TIMEOUT, "RequestTimeout")
        }
    }

    /// `413 BodyTooLarge` (ADR 0008 rule 8). The connection is closed: the rest of the body is not
    /// read.
    #[must_use]
    pub fn body_too_large() -> Self {
        Self {
            close: true,
            ..Self::new(StatusCode::PAYLOAD_TOO_LARGE, "BodyTooLarge")
        }
    }

    /// `400 InvalidParameter`: malformed request (body that could not be read, for example).
    #[must_use]
    pub fn invalid_parameter() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidParameter")
    }

    /// `400 InvalidCursor`: a `/query` cursor this relay does not recognise (ADR 0012 rule 9, ADR
    /// 0024 rule 7). The client starts again without a cursor.
    #[must_use]
    pub fn invalid_cursor() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidCursor").with_message(
            "cursor not recognised by this relay; start again without a cursor and deduplicate",
        )
    }

    /// A block rejected by F1 to F9 or C1 (`400`), or by C2 or C3 (`422`), named by its variant
    /// (ADR 0004, ADR 0012 rule 17). `BlockIdMismatch` never comes from a `PUT` (ADR 0004 rule 14):
    /// it maps to `500`.
    #[must_use]
    pub fn rejected(e: &sbtp_core::Error) -> Self {
        use sbtp_core::Error as E;
        match e {
            E::InvalidPublicKey | E::InvalidSignature => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, e.name())
            }
            E::BlockIdMismatch { .. } => Self::internal(),
            _ => Self::new(StatusCode::BAD_REQUEST, e.name()),
        }
    }

    /// `400 TimestampTooFarInFuture`: policy check P1 (ADR 0007 rules 3 and 9).
    #[must_use]
    pub fn timestamp_too_far() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "TimestampTooFarInFuture")
    }

    /// `507 StorageFull` (ADR 0013 rule 19), without `Retry-After`. ADR 0023 rule 18 keeps the
    /// `MAY` of rule 19 out of this relay, since it cannot predict when room frees; ADR 0046 rule
    /// 8 amends it for demand eviction only ([`ApiError::storage_full_retry`]). This form is the
    /// answer with demand eviction off (eviction by age included), while it is suspended (rule
    /// 13), after a stuck pass, and below the high-water mark.
    #[must_use]
    pub fn storage_full() -> Self {
        Self::new(StatusCode::INSUFFICIENT_STORAGE, "StorageFull")
    }

    /// `507 StorageFull` with `Retry-After: retry_after_s` (ADR 0046 rule 8, amending ADR 0023
    /// rule 18): demand eviction is on, neither suspended nor stuck, and the store is above its
    /// high-water mark, so the next sweeper run makes room (security review 2026-11-21, L-4).
    #[must_use]
    pub fn storage_full_retry(retry_after_s: u64) -> Self {
        Self {
            retry_after_s: Some(retry_after_s),
            ..Self::storage_full()
        }
    }

    /// `500 Internal`. No detail is disclosed.
    #[must_use]
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal")
    }

    /// `429 RateLimited` with `Retry-After: retry_after_s` (ADR 0018 rule 29).
    #[must_use]
    pub fn rate_limited(retry_after_s: u64) -> Self {
        Self {
            retry_after_s: Some(retry_after_s),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, "RateLimited")
        }
    }

    /// `503 Unavailable` with `Retry-After: retry_after_s` (ADR 0018 rule 30).
    #[must_use]
    pub fn unavailable(retry_after_s: u64) -> Self {
        Self {
            retry_after_s: Some(retry_after_s),
            ..Self::new(StatusCode::SERVICE_UNAVAILABLE, "Unavailable")
        }
    }

    /// Adds a human-readable message (at most 200 characters, no block bytes, paths or internal
    /// error text: ADR 0012 rule 16).
    #[must_use]
    pub fn with_message(mut self, message: &'static str) -> Self {
        debug_assert!(message.len() <= 200);
        self.message = Some(message);
        self
    }

    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The error name of ADR 0012 rule 17.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = serde_json::Map::new();
        body.insert("error".into(), self.name.into());
        if let Some(m) = self.message {
            body.insert("message".into(), m.into());
        }
        let mut response = Response::new(Body::from(serde_json::Value::Object(body).to_string()));
        *response.status_mut() = self.status;
        let h = response.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        // ADR 0012 rule 32: error responses are not cached.
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(s) = self.retry_after_s {
            h.insert(header::RETRY_AFTER, HeaderValue::from(s));
        }
        if self.close {
            h.insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        response
    }
}

/// ADR 0018 rule 37: a failed blocking task is a relay fault, never unwrapped.
impl From<tokio::task::JoinError> for ApiError {
    fn from(_: tokio::task::JoinError) -> Self {
        Self::internal()
    }
}

/// The `CatchPanicLayer::custom` handler: counts the panic and answers `500 Internal`. The panic
/// payload is not disclosed. The panic hook of the binary (`log::install_panic_hook`, ADR 0021
/// rule 9) has already written the throttled `panic` line.
pub(crate) fn panic_response(_: Box<dyn std::any::Any + Send + 'static>) -> Response {
    crate::metrics::panicked();
    ApiError::internal().into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn join_error_maps_to_internal() {
        let failed = tokio::spawn(async { panic!("boom") }).await;
        let e = ApiError::from(failed.unwrap_err());
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(e.name(), "Internal");
    }
}
