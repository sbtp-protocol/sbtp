//! Generic layer 2 grammar validation (`sbtp-l2`, `docs/spec/l2-grammar.md` §1 to §3), feature
//! `l2`. Every rule runs in `sbtp-l2`; this module only copies the result out.

use sbtp_core::BlockId;
use sbtp_core::layout::{HASH_LEN, MAX_BLOCK_LEN};
use sbtp_l2::{Body, L2Error, Payload, validate_l2_invariants};
use wasm_bindgen::prelude::*;

use crate::error::{BindError, names};
use crate::{BuildError, bytes_in};

impl From<L2Error> for BindError {
    /// `InvalidPayload`, with the `sbtp-l2` rule name as the whole message (its `Display` is the
    /// variant name), so that a caller can branch on `e.message`.
    fn from(error: L2Error) -> Self {
        Self::new(names::INVALID_PAYLOAD, error.to_string())
    }
}

/// What grammar validation returns about a payload, copied out of WASM memory.
///
/// Grammar validation checks the payload only: it does not make the block authentic. Validate the
/// block first (`validateRequested`), then its payload.
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Payload {
    kind: String,
    edge_count: usize,
    enc_key: Option<([u8; 32], u8)>,
    raw_body: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl L2Payload {
    /// The `kind` (spec §1.3).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The number of edges (spec §2.1).
    #[wasm_bindgen(getter, js_name = edgeCount)]
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edge_count
    }

    /// For an `sbtp.enc_key` (spec §5.5): the 32-byte X25519 key to seal to. `undefined`
    /// otherwise. Check the key block's directory tag (`isDirectoryTag`) before using it.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn x25519(&self) -> Option<Vec<u8>> {
        self.enc_key.map(|(key, _)| key.to_vec())
    }

    /// For an `sbtp.enc_key`: its `intro_bucket`, 0 to 15. `undefined` otherwise.
    #[wasm_bindgen(getter, js_name = introBucket)]
    #[must_use]
    pub fn intro_bucket(&self) -> Option<u8> {
        self.enc_key.map(|(_, bucket)| bucket)
    }

    /// For a kind outside `sbtp.*` (an application kind): the encoded body, a map or a byte string
    /// checked for type only, for the application's own validation (spec §2.4). `undefined` for
    /// the `sbtp.*` kinds.
    #[wasm_bindgen(getter, js_name = rawBody)]
    #[must_use]
    pub fn raw_body(&self) -> Option<Vec<u8>> {
        self.raw_body.clone()
    }
}

impl L2Payload {
    fn from_payload(payload: &Payload<'_>) -> Self {
        Self {
            kind: payload.kind.into(),
            edge_count: payload.edges.len(),
            enc_key: match &payload.body {
                Body::EncKey(key) => Some((key.x25519, key.intro_bucket)),
                _ => None,
            },
            raw_body: match payload.body {
                Body::Raw(bytes) => Some(bytes.to_vec()),
                _ => None,
            },
        }
    }
}

/// Splits concatenated 32-byte parents. More than 8 is left to `sbtp-l2` (`TooManyParents`).
pub(crate) fn parents_of(parents: &[u8]) -> Result<Vec<BlockId>, BindError> {
    let (chunks, rest) = parents.as_chunks::<HASH_LEN>();
    if !rest.is_empty() {
        return Err(BindError::length(
            "parents",
            "a multiple of 32",
            parents.len(),
        ));
    }
    Ok(chunks.iter().map(|id| BlockId(*id)).collect())
}

/// Grammar validation of `payload` for a block whose header parents are `parents` (concatenated
/// 32-byte identifiers, in header order).
///
/// # Errors
///
/// `InvalidLength` for `parents`, otherwise `InvalidPayload` with the rule name.
pub fn validate_l2_payload(parents: &[u8], payload: &[u8]) -> Result<L2Payload, BindError> {
    let parents = parents_of(parents)?;
    Ok(L2Payload::from_payload(&validate_l2_invariants(
        &parents, payload,
    )?))
}

/// Grammar validation of a payload (`l2-grammar.md` §2.4): `parents` is the concatenation of the
/// block's header parents (`info.parents`), `payload` its payload. Run it on a block that already
/// passed `validateRequested`.
///
/// # Errors
///
/// `InvalidArgument`, `InvalidLength`, or `InvalidPayload` whose `message` is the `sbtp-l2` rule
/// name (`TooManyParents` included).
#[wasm_bindgen(js_name = validateL2Payload)]
pub fn validate_l2_payload_js(
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] parents: &JsValue,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array")] payload: &JsValue,
) -> Result<L2Payload, JsValue> {
    let parents = bytes_in("parents", parents, MAX_BLOCK_LEN, |len| {
        BuildError::TooManyParents {
            count: len / HASH_LEN,
        }
        .into()
    })?;
    let payload = bytes_in("payload", payload, MAX_BLOCK_LEN, |_| {
        L2Error::PayloadTooLong.into()
    })?;
    Ok(validate_l2_payload(&parents, &payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbtp_l2::cbor::{Value, encode};

    fn payload(kind: &str, body: Value<'_>) -> Vec<u8> {
        encode(&Value::Map(vec![
            ("body", body),
            ("edges", Value::Array(vec![])),
            ("kind", Value::Text(kind)),
            ("v", Value::Uint(1)),
        ]))
        .unwrap()
    }

    #[test]
    fn application_kind_returns_its_raw_body() {
        let body = Value::Map(vec![("t", Value::Text("hi"))]);
        let bytes = payload("app.note", body);
        let info = validate_l2_payload(&[], &bytes).unwrap();
        assert_eq!(info.kind(), "app.note");
        assert_eq!(info.edge_count(), 0);
        assert!(info.raw_body().is_some());
        assert_eq!(info.x25519(), None);
    }

    #[test]
    fn invalid_payload_names_the_rule() {
        let err = validate_l2_payload(&[], &[0xa0]).unwrap_err();
        assert_eq!(err.name(), "InvalidPayload");
        assert_eq!(err.message(), "BadEnvelope");
        // A causal parent no edge covers.
        let bytes = payload("app.note", Value::Map(vec![]));
        let err = validate_l2_payload(&[7; 32], &bytes).unwrap_err();
        assert_eq!(err.message(), "UncoveredParent");
        let err = validate_l2_payload(&[7; 33], &bytes).unwrap_err();
        assert_eq!(err.name(), "InvalidLength");
        let err = validate_l2_payload(&[0; 9 * 32], &bytes).unwrap_err();
        assert_eq!(err.message(), "TooManyParents");
    }
}
