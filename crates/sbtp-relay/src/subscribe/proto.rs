//! The messages of `sbtp.subscribe.v1` (ADR 0054 rules 6 to 9): client messages parsed strictly,
//! relay control messages and binary delivery frames built within their bounds. No I/O here.

use sbtp_core::BlockId;
use serde_json::{Map, Value};

use crate::store;

/// The subprotocol of version 1 (rule 2).
pub const SUBPROTOCOL: &str = "sbtp.subscribe.v1";
/// Rule 7: the largest client message.
pub const MAX_CLIENT_MESSAGE: usize = 4_096;
/// Rule 8: the largest relay control message.
pub const MAX_CONTROL: usize = 1_024;
/// Rule 9: the largest delivery frame.
pub const MAX_FRAME: usize = 65_536;
/// Rule 7: the most parents of one subscription.
pub const MAX_PARENTS: usize = 32;
/// Rule 9: the delivery frame type.
pub const DELIVERY: u8 = 0x01;
/// Rule 9: flag bit 0, each entry carries parents and length.
pub const FLAG_FIELDS: u8 = 0b01;
/// Rule 9: flag bit 1, each entry carries a match mask.
pub const FLAG_MASK: u8 = 0b10;

/// What a subscription matches (rule 11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Filter {
    /// The children of these parents, in the order of the `subscribe` message.
    Parents(Vec<BlockId>),
    /// Every block (`all: true`).
    All,
}

impl Filter {
    /// Rule 26: the `query` tokens of the `subscribe`: `⌈N/8⌉` for `N` parents, 4 for `all`.
    #[must_use]
    pub fn tokens(&self) -> u64 {
        match self {
            Self::Parents(p) => (p.len() as u64).div_ceil(8).max(1),
            Self::All => 4,
        }
    }
}

/// A client message (rule 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMsg {
    /// `subscribe`.
    Subscribe {
        /// The client's identifier of the subscription.
        sub: u32,
        /// What it matches.
        filter: Filter,
        /// `fields: "parents"`.
        fields: bool,
    },
    /// `unsubscribe`.
    Unsubscribe {
        /// The subscription to remove.
        sub: u32,
    },
}

/// Why a client message is refused (rule 7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bad {
    /// Not a JSON object: the connection is closed with 1007.
    NotObject,
    /// A JSON object that is not a valid message: `error` `InvalidParameter`, the connection stays
    /// open. `sub` when it could be read.
    Invalid {
        /// The `sub` of the message, when it is a valid one.
        sub: Option<u32>,
        /// A fixed text, never the client's content.
        message: &'static str,
    },
}

fn invalid(sub: Option<u32>, message: &'static str) -> Bad {
    Bad::Invalid { sub, message }
}

/// Parses one client text message (rule 7). The caller has bounded it to
/// [`MAX_CLIENT_MESSAGE`] bytes.
///
/// # Errors
///
/// [`Bad`].
pub fn parse(text: &str) -> Result<ClientMsg, Bad> {
    let Ok(Value::Object(o)) = serde_json::from_str::<Value>(text) else {
        return Err(Bad::NotObject);
    };
    let sub = o
        .get("sub")
        .and_then(Value::as_u64)
        .and_then(|s| u32::try_from(s).ok().filter(|s| *s >= 1));
    let Some(op) = o.get("op").and_then(Value::as_str) else {
        return Err(invalid(sub, "missing or malformed op"));
    };
    let sub_or = |m| sub.ok_or_else(|| invalid(None, m));
    match op {
        "unsubscribe" => {
            only(&o, &["op", "sub"], sub)?;
            Ok(ClientMsg::Unsubscribe {
                sub: sub_or("sub must be an integer from 1 to 4294967295")?,
            })
        }
        "subscribe" => {
            only(&o, &["op", "sub", "parents", "all", "fields"], sub)?;
            let sub = sub_or("sub must be an integer from 1 to 4294967295")?;
            let filter = match (o.get("parents"), o.get("all")) {
                (Some(p), None) => Filter::Parents(parents(p).ok_or_else(|| {
                    invalid(
                        Some(sub),
                        "parents must be 1 to 32 distinct lowercase hex block_id values",
                    )
                })?),
                (None, Some(Value::Bool(true))) => Filter::All,
                (None, Some(_)) => return Err(invalid(Some(sub), "all must be true")),
                _ => {
                    return Err(invalid(
                        Some(sub),
                        "a subscribe carries exactly one of parents and all",
                    ));
                }
            };
            let fields = match o.get("fields") {
                None => false,
                Some(Value::String(s)) if s == "parents" => true,
                Some(_) => return Err(invalid(Some(sub), "fields must be \"parents\"")),
            };
            Ok(ClientMsg::Subscribe {
                sub,
                filter,
                fields,
            })
        }
        _ => Err(invalid(sub, "unknown op")),
    }
}

fn only(o: &Map<String, Value>, allowed: &[&str], sub: Option<u32>) -> Result<(), Bad> {
    if o.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(invalid(sub, "unknown member"))
    }
}

fn parents(v: &Value) -> Option<Vec<BlockId>> {
    let a = v.as_array()?;
    if a.is_empty() || a.len() > MAX_PARENTS {
        return None;
    }
    let mut out: Vec<BlockId> = Vec::with_capacity(a.len());
    for p in a {
        let id = store::parse_hex_id(p.as_str()?)?;
        if out.contains(&id) {
            return None;
        }
        out.push(id);
    }
    Some(out)
}

/// `subscribed` (rule 14).
#[must_use]
pub fn subscribed(sub: u32, start: &str) -> String {
    format!(r#"{{"op":"subscribed","sub":{sub},"start":"{start}"}}"#)
}

/// `unsubscribed` (rule 17).
#[must_use]
pub fn unsubscribed(sub: u32) -> String {
    format!(r#"{{"op":"unsubscribed","sub":{sub}}}"#)
}

/// `gap` (rule 18).
#[must_use]
pub fn gap(sub: u32, cursor: &str) -> String {
    format!(r#"{{"op":"gap","sub":{sub},"cursor":"{cursor}"}}"#)
}

/// `tick` (rule 31).
#[must_use]
pub fn tick(cursor: &str) -> String {
    format!(r#"{{"op":"tick","cursor":"{cursor}"}}"#)
}

/// `error` (rule 8): `name` one of the names of core spec §4, "Errors"; `message` a fixed text.
#[must_use]
pub fn error(sub: Option<u32>, name: &str, retry_after: Option<u64>, message: &str) -> String {
    let mut o = Map::new();
    o.insert("op".into(), "error".into());
    if let Some(s) = sub {
        o.insert("sub".into(), s.into());
    }
    o.insert("error".into(), name.into());
    if let Some(r) = retry_after {
        o.insert("retry_after".into(), r.max(1).into());
    }
    o.insert("message".into(), message.into());
    Value::Object(o).to_string()
}

/// One entry of a delivery frame (rule 9).
#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
    /// The block.
    pub id: &'a BlockId,
    /// The match mask, for a parent subscription.
    pub mask: Option<u32>,
    /// Its Parents Hashes and length, with `fields`.
    pub fields: Option<(&'a [BlockId], u32)>,
}

impl Item<'_> {
    /// The bytes of the entry.
    #[must_use]
    pub fn len(&self) -> usize {
        32 + self.mask.map_or(0, |_| 4) + self.fields.map_or(0, |(p, _)| 1 + 32 * p.len() + 4)
    }

    /// Whether the entry is empty (never: a `block_id` is 32 bytes).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// The header bytes of a delivery frame with a cursor of `c` bytes.
#[must_use]
pub fn header_len(c: usize) -> usize {
    9 + c
}

/// A delivery frame (rule 9) for `sub` with `items` (1 to 65,535, all of the same shape) and
/// `cursor`, the gap after the last of them. `None` when it would break rule 9 (no item, a
/// cursor out of 1 to 128 bytes, a frame over [`MAX_FRAME`] bytes, more than 8 parents).
#[must_use]
pub fn delivery(sub: u32, cursor: &str, items: &[Item<'_>]) -> Option<Vec<u8>> {
    let first = items.first()?;
    let c = u8::try_from(cursor.len())
        .ok()
        .filter(|c| (1..=128).contains(c))?;
    let n = u16::try_from(items.len()).ok()?;
    let size = header_len(cursor.len()) + items.iter().map(Item::len).sum::<usize>();
    if size > MAX_FRAME {
        return None;
    }
    let mut flags = 0;
    if first.fields.is_some() {
        flags |= FLAG_FIELDS;
    }
    if first.mask.is_some() {
        flags |= FLAG_MASK;
    }
    let mut out = Vec::with_capacity(size);
    out.push(DELIVERY);
    out.extend_from_slice(&sub.to_be_bytes());
    out.push(flags);
    out.push(c);
    out.extend_from_slice(cursor.as_bytes());
    out.extend_from_slice(&n.to_be_bytes());
    for it in items {
        if it.mask.is_some() != first.mask.is_some()
            || it.fields.is_some() != first.fields.is_some()
        {
            return None;
        }
        out.extend_from_slice(it.id.as_bytes());
        if let Some(m) = it.mask {
            out.extend_from_slice(&m.to_be_bytes());
        }
        if let Some((parents, len)) = it.fields {
            out.push(u8::try_from(parents.len()).ok().filter(|p| *p <= 8)?);
            for p in parents {
                out.extend_from_slice(p.as_bytes());
            }
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn bad(text: &str) -> Bad {
        parse(text).unwrap_err()
    }

    /// ADR 0054 rule 7: the valid forms.
    #[test]
    fn client_messages() {
        let m = parse(&format!(
            r#"{{"op":"subscribe","sub":7,"parents":["{A}","{B}"],"fields":"parents"}}"#
        ))
        .unwrap();
        let ClientMsg::Subscribe {
            sub: 7,
            filter: Filter::Parents(p),
            fields: true,
        } = m
        else {
            panic!("{m:?}");
        };
        assert_eq!(p.len(), 2);
        assert_eq!(
            parse(r#"{"op":"subscribe","sub":4294967295,"all":true}"#).unwrap(),
            ClientMsg::Subscribe {
                sub: u32::MAX,
                filter: Filter::All,
                fields: false
            }
        );
        assert_eq!(
            parse(r#"{"op":"unsubscribe","sub":1}"#).unwrap(),
            ClientMsg::Unsubscribe { sub: 1 }
        );
    }

    /// ADR 0054 rule 7: a frame that is not a JSON object closes (1007); every other fault is an
    /// `InvalidParameter`, with the `sub` when it is valid.
    #[test]
    fn invalid_client_messages() {
        for t in ["", "[]", "1", "\"x\"", "{", "null"] {
            assert_eq!(bad(t), Bad::NotObject, "{t}");
        }
        let thirty_three: Vec<String> = (0..33u8)
            .map(|n| format!("\"{n:02x}{}\"", &A[2..]))
            .collect();
        for (t, sub) in [
            (r#"{"op":"subscribe","sub":0,"all":true}"#.to_owned(), None),
            (
                r#"{"op":"subscribe","sub":4294967296,"all":true}"#.to_owned(),
                None,
            ),
            (
                r#"{"op":"subscribe","sub":"1","all":true}"#.to_owned(),
                None,
            ),
            (r#"{"op":"subscribe","sub":1}"#.to_owned(), Some(1)),
            (
                r#"{"op":"subscribe","sub":1,"all":false}"#.to_owned(),
                Some(1),
            ),
            (
                format!(r#"{{"op":"subscribe","sub":1,"all":true,"parents":["{A}"]}}"#),
                Some(1),
            ),
            (
                r#"{"op":"subscribe","sub":1,"parents":[]}"#.to_owned(),
                Some(1),
            ),
            (
                format!(
                    r#"{{"op":"subscribe","sub":1,"parents":["{}"]}}"#,
                    A.to_uppercase()
                ),
                Some(1),
            ),
            (
                format!(r#"{{"op":"subscribe","sub":1,"parents":["{A}","{A}"]}}"#),
                Some(1),
            ),
            (
                format!(
                    r#"{{"op":"subscribe","sub":1,"parents":[{}]}}"#,
                    thirty_three.join(",")
                ),
                Some(1),
            ),
            (
                r#"{"op":"subscribe","sub":1,"all":true,"fields":"x"}"#.to_owned(),
                Some(1),
            ),
            (
                r#"{"op":"subscribe","sub":1,"all":true,"extra":1}"#.to_owned(),
                Some(1),
            ),
            (r#"{"op":"resubscribe","sub":1}"#.to_owned(), Some(1)),
            (r#"{"sub":1}"#.to_owned(), Some(1)),
            (r#"{"op":"unsubscribe"}"#.to_owned(), None),
            (
                r#"{"op":"unsubscribe","sub":2,"all":true}"#.to_owned(),
                Some(2),
            ),
        ] {
            let Bad::Invalid { sub: got, .. } = bad(&t) else {
                panic!("{t}");
            };
            assert_eq!(got, sub, "{t}");
        }
    }

    /// ADR 0054 rule 26: the tokens of a `subscribe`.
    #[test]
    fn subscribe_tokens() {
        let p = |n: usize| Filter::Parents(vec![BlockId([0; 32]); n]);
        assert_eq!([p(1), p(8), p(9), p(32)].map(|f| f.tokens()), [1, 1, 2, 4]);
        assert_eq!(Filter::All.tokens(), 4);
    }

    /// ADR 0054 rule 8: control messages are JSON objects within 1,024 bytes.
    #[test]
    fn control_messages() {
        let cursor = "c".repeat(128);
        for m in [
            subscribed(u32::MAX, &cursor),
            unsubscribed(u32::MAX),
            gap(u32::MAX, &cursor),
            tick(&cursor),
            error(Some(u32::MAX), "RateLimited", Some(0), &"m".repeat(200)),
        ] {
            assert!(m.len() <= MAX_CONTROL, "{m}");
            assert!(serde_json::from_str::<Value>(&m).unwrap().is_object());
        }
        let e: Value = serde_json::from_str(&error(None, "RateLimited", Some(0), "x")).unwrap();
        assert_eq!(e["retry_after"], 1);
        assert!(e.get("sub").is_none());
    }

    /// ADR 0054 rule 9: the layout of a delivery frame, with a mask and fields.
    #[test]
    fn delivery_layout() {
        let id = BlockId([7; 32]);
        let parents = [BlockId([1; 32]), BlockId([2; 32])];
        let item = Item {
            id: &id,
            mask: Some(0b10),
            fields: Some((&parents, 300)),
        };
        let f = delivery(9, "cur", &[item]).unwrap();
        assert_eq!(f.len(), 9 + 3 + 32 + 4 + 1 + 64 + 4);
        assert_eq!(&f[..7], &[1, 0, 0, 0, 9, 0b11, 3]);
        assert_eq!(&f[7..10], b"cur");
        assert_eq!(&f[10..12], &[0, 1]);
        assert_eq!(&f[12..44], &[7; 32]);
        assert_eq!(&f[44..48], &[0, 0, 0, 2]);
        assert_eq!(f[48], 2);
        assert_eq!(&f[f.len() - 4..], &300u32.to_be_bytes());
        let plain = Item {
            id: &id,
            mask: None,
            fields: None,
        };
        let f = delivery(1, "c", &[plain, plain]).unwrap();
        assert_eq!((f[5], f.len()), (0, 9 + 1 + 64));
        assert!(delivery(1, "", &[plain]).is_none());
        assert!(delivery(1, &"c".repeat(129), &[plain]).is_none());
        assert!(delivery(1, "c", &[]).is_none());
        assert!(delivery(1, "c", &[plain, item]).is_none());
        assert!(
            delivery(1, "c", &vec![plain; 2_048]).is_none(),
            "over 65,536 bytes"
        );
    }
}
