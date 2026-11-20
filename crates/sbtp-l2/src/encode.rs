//! Encoding a [`Payload`] in the deterministic profile (spec §1.2), for the sender side.

use alloc::vec;
use alloc::vec::Vec;

use sbtp_core::BlockId;

use crate::cbor::{self, Value};
use crate::payload::{Body, CHUNK_SIZE, Edge, Payload, Rel, Target};
use crate::{L2Error, validate_l2_invariants};

impl Payload<'_> {
    /// Encodes the payload for a block with these header parents.
    ///
    /// The output is checked with [`validate_l2_invariants`] before it is returned: an encoder MUST
    /// emit only conforming payloads (ADR 0011 rule 12).
    ///
    /// Sender side: this trusts its caller. [`Payload`] has public fields, so a caller can build
    /// values the decoder never returns, for example `Rel::Unknown { verb: "in", .. }`, which
    /// encodes as and re-decodes to [`Rel::In`]. The final validation guarantees a conforming
    /// payload, not that it decodes to the same [`Payload`].
    ///
    /// # Errors
    ///
    /// The [`L2Error`] the encoded payload fails on.
    pub fn encode(&self, parents: &[BlockId]) -> Result<Vec<u8>, L2Error> {
        let edges = self.edges.iter().map(edge).collect();
        let value = Value::Map(vec![
            ("v", Value::Uint(1)),
            ("kind", Value::Text(self.kind)),
            ("edges", Value::Array(edges)),
            ("body", body(&self.body)),
        ]);
        let out = cbor::encode(&value)?;
        validate_l2_invariants(parents, &out)?;
        Ok(out)
    }
}

fn opt_text<'a>(entries: &mut Vec<(&'a str, Value<'a>)>, key: &'a str, v: Option<&'a str>) {
    if let Some(s) = v {
        entries.push((key, Value::Text(s)));
    }
}

fn pair<'a>(a: u64, b: u64) -> Value<'a> {
    Value::Array(vec![Value::Uint(a), Value::Uint(b)])
}

fn edge<'a>(e: &'a Edge<'a>) -> Value<'a> {
    let mut m = Vec::new();
    match &e.target {
        Target::Parent(p) => m.push(("p", Value::Uint(u64::from(*p)))),
        Target::Block(id) => m.push(("block", Value::Bytes(id))),
        Target::Chunk(id) => m.push(("chunk", Value::Bytes(id))),
    }
    m.push(("rel", Value::Text(e.rel.verb())));
    let mut meta = Vec::new();
    match &e.rel {
        Rel::Supersedes { reason } => opt_text(&mut meta, "reason", *reason),
        Rel::ComposedOf { seq, mime } => {
            meta.push(("seq", Value::Uint(*seq)));
            opt_text(&mut meta, "mime", *mime);
        }
        Rel::Cites { span: Some((o, l)) } => meta.push(("span", pair(*o, *l))),
        Rel::Supports {
            confidence: Some(c),
        }
        | Rel::Refutes {
            confidence: Some(c),
        } => meta.push(("confidence", Value::Uint(u64::from(*c)))),
        Rel::DelegatesTo { task_id } => opt_text(&mut meta, "task_id", *task_id),
        Rel::Fulfills { status } => opt_text(&mut meta, "status", *status),
        Rel::Extension {
            meta: Some(raw), ..
        }
        | Rel::Unknown {
            meta: Some(raw), ..
        } => {
            m.push(("meta", Value::Raw(raw)));
        }
        _ => {}
    }
    // spec §2.1: an edge with no metadata omits the key.
    if !meta.is_empty() {
        m.push(("meta", Value::Map(meta)));
    }
    Value::Map(m)
}

fn ids(ids: &[[u8; 32]]) -> Value<'_> {
    Value::Array(ids.iter().map(|id| Value::Bytes(id)).collect())
}

fn body<'a>(body: &'a Body<'a>) -> Value<'a> {
    match body {
        Body::Manifest(mf) => {
            let mut m = vec![
                ("mime", Value::Text(mf.mime)),
                ("total_size", Value::Uint(mf.total_size)),
                ("chunk_size", Value::Uint(CHUNK_SIZE)),
                ("chunks", ids(&mf.chunks)),
            ];
            if let Some(d) = mf.duration_ms {
                m.push(("duration_ms", Value::Uint(d)));
            }
            if let Some((w, h)) = mf.resolution {
                m.push(("resolution", pair(w, h)));
            }
            Value::Map(m)
        }
        // An application body, encoded by its application; checked by `cbor::encode`.
        Body::Raw(raw) => Value::Raw(raw),
    }
}
