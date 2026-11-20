//! The deterministic CBOR profile of ADR 0011 (spec §1.2): a strict checker, a cursor used to read
//! a checked payload, and the encoder.
//!
//! [`Reader`] is public so that an application validates the body of its own kinds with the same
//! cursor (ADR 0038 rule 9). It applies the head-level rules of the profile on every read, but the
//! map-level rules (key order, no duplicate) are checked by [`check_profile`] only: read a buffer
//! with a [`Reader`] after it passed [`check_profile`], as [`crate::validate_l2_invariants`] does.
//!
//! Hand-written on purpose: the profile needs only seven item types, and the decoder must reject
//! every non-deterministic encoding, which general-purpose CBOR crates accept. Nothing here
//! recurses on input: nesting is tracked on a heap stack bounded by the input length, so a deeply
//! nested payload cannot overflow the call stack.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::L2Error;

/// Largest payload, in bytes (spec §1.1, ADR 0011 rule 11).
pub const MAX_PAYLOAD_LEN: usize = 65_535;

/// The CBOR major types the profile allows. `Simple` is `false`, `true` or `null` only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Major {
    /// Major type 0, an unsigned integer.
    Uint,
    /// Major type 1, a negative integer `-1 - n`.
    Nint,
    /// Major type 2, a byte string.
    Bytes,
    /// Major type 3, a text string.
    Text,
    /// Major type 4, an array.
    Array,
    /// Major type 5, a map.
    Map,
    /// Major type 7, `false`, `true` or `null`.
    Simple,
}

const FALSE: u64 = 20;
const TRUE: u64 = 21;
const NULL: u64 = 22;

/// A read cursor over a byte buffer. Every read is bounds-checked.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A cursor at the start of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Whether every byte of the buffer was read.
    #[must_use]
    pub const fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> Result<u8, L2Error> {
        let b = *self.buf.get(self.pos).ok_or(L2Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], L2Error> {
        let n = usize::try_from(n).map_err(|_| L2Error::Truncated)?;
        let end = self.pos.checked_add(n).ok_or(L2Error::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(L2Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    fn be(&mut self, n: u64) -> Result<u64, L2Error> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// Reads one item head and applies the head-level rules of the profile (spec §1.2). The
    /// argument is the value of an integer, the length of a string, the count of an array or map,
    /// or the simple value.
    ///
    /// # Errors
    ///
    /// `Truncated`, `Tag`, `Float`, `Malformed`, `SimpleValue`, `IndefiniteLength` or
    /// `NonShortestForm`.
    pub fn head(&mut self) -> Result<(Major, u64), L2Error> {
        let ib = self.byte()?;
        let major = ib >> 5;
        let ai = ib & 0x1f;
        if major == 6 {
            return Err(L2Error::Tag); // spec §1.2, ADR 0011 rule 8
        }
        if major == 7 {
            return match u64::from(ai) {
                v @ (FALSE | TRUE | NULL) => Ok((Major::Simple, v)),
                25..=27 => Err(L2Error::Float), // spec §1.2, ADR 0011 rule 7
                28..=31 => Err(L2Error::Malformed),
                _ => Err(L2Error::SimpleValue), // spec §1.2, ADR 0011 rule 9
            };
        }
        // spec §1.2: shortest form for integers, lengths and counts (RFC 8949 §4.2.1).
        let (arg, min) = match ai {
            0..=23 => (u64::from(ai), 0),
            24 => (self.be(1)?, 24),
            25 => (self.be(2)?, 0x100),
            26 => (self.be(4)?, 0x1_0000),
            27 => (self.be(8)?, 0x1_0000_0000),
            31 if (2..=5).contains(&major) => return Err(L2Error::IndefiniteLength),
            _ => return Err(L2Error::Malformed),
        };
        if arg < min {
            return Err(L2Error::NonShortestForm);
        }
        let major = match major {
            0 => Major::Uint,
            1 => Major::Nint,
            2 => Major::Bytes,
            3 => Major::Text,
            4 => Major::Array,
            _ => Major::Map,
        };
        Ok((major, arg))
    }

    /// Skips one item, returns its encoded bytes. Iterative: a pending-item counter, no recursion.
    ///
    /// # Errors
    ///
    /// As [`Reader::head`], for any head of the item.
    pub fn skip(&mut self) -> Result<&'a [u8], L2Error> {
        let start = self.pos;
        let mut pending: u64 = 1;
        while pending > 0 {
            pending -= 1;
            let (major, arg) = self.head()?;
            match major {
                Major::Bytes | Major::Text => {
                    self.take(arg)?;
                }
                Major::Array => pending = pending.checked_add(arg).ok_or(L2Error::Truncated)?,
                Major::Map => {
                    let n = arg.checked_mul(2).ok_or(L2Error::Truncated)?;
                    pending = pending.checked_add(n).ok_or(L2Error::Truncated)?;
                }
                Major::Uint | Major::Nint | Major::Simple => {}
            }
        }
        self.buf.get(start..self.pos).ok_or(L2Error::Truncated)
    }

    /// Reads a head of the given major type and returns its argument; any other type yields `err`.
    ///
    /// # Errors
    ///
    /// `err`, or an error of [`Reader::head`].
    pub fn expect(&mut self, want: Major, err: L2Error) -> Result<u64, L2Error> {
        match self.head()? {
            (m, arg) if m == want => Ok(arg),
            _ => Err(err),
        }
    }

    /// An unsigned integer.
    ///
    /// # Errors
    ///
    /// `err` for another type, or an error of [`Reader::head`].
    pub fn uint(&mut self, err: L2Error) -> Result<u64, L2Error> {
        self.expect(Major::Uint, err)
    }

    /// A signed integer of the profile range, `-2^64` to `2^64 - 1` (ADR 0011 rule 6).
    ///
    /// # Errors
    ///
    /// `err` for another type, or an error of [`Reader::head`].
    pub fn int(&mut self, err: L2Error) -> Result<i128, L2Error> {
        match self.head()? {
            (Major::Uint, v) => Ok(i128::from(v)),
            (Major::Nint, v) => Ok(-1 - i128::from(v)),
            _ => Err(err),
        }
    }

    /// A text string, borrowed from the buffer.
    ///
    /// # Errors
    ///
    /// `err` for another type, `InvalidUtf8`, or an error of [`Reader::head`].
    pub fn text(&mut self, err: L2Error) -> Result<&'a str, L2Error> {
        let n = self.expect(Major::Text, err)?;
        core::str::from_utf8(self.take(n)?).map_err(|_| L2Error::InvalidUtf8)
    }

    /// A byte string, borrowed from the buffer.
    ///
    /// # Errors
    ///
    /// `err` for another type, or an error of [`Reader::head`].
    pub fn bytes(&mut self, err: L2Error) -> Result<&'a [u8], L2Error> {
        let n = self.expect(Major::Bytes, err)?;
        self.take(n)
    }

    /// A byte string of exactly 32 bytes.
    ///
    /// # Errors
    ///
    /// `err` for another type or another length, or an error of [`Reader::head`].
    pub fn id32(&mut self, err: L2Error) -> Result<[u8; 32], L2Error> {
        self.bytes(err)?.try_into().map_err(|_| err)
    }
}

/// One open array or map during [`check_profile`]. `left` counts the items still expected (two
/// per map entry) and is never zero while the frame is on the stack.
struct Frame<'a> {
    left: u64,
    is_map: bool,
    prev_key: Option<&'a [u8]>,
}

/// Checks that `buf` is exactly one data item of the ADR 0011 profile (spec §1.2).
///
/// Linear in the input length. The stack holds only frames still waiting for an item, each of
/// which needs at least one more input byte, so its size is bounded by the input length.
///
/// # Errors
///
/// The [`L2Error`] of the first broken rule of spec §1.2.
pub fn check_profile(buf: &[u8]) -> Result<(), L2Error> {
    if buf.len() > MAX_PAYLOAD_LEN {
        return Err(L2Error::PayloadTooLong); // spec §1.2, ADR 0011 rule 11
    }
    let mut r = Reader::new(buf);
    let mut stack: Vec<Frame<'_>> = Vec::new();
    loop {
        let is_key = stack.last().is_some_and(|f| f.is_map && f.left % 2 == 0);
        let start = r.pos;
        let (major, arg) = r.head()?;
        match major {
            Major::Bytes => {
                r.take(arg)?;
            }
            Major::Text => {
                // spec §1.2: text strings MUST be valid UTF-8.
                core::str::from_utf8(r.take(arg)?).map_err(|_| L2Error::InvalidUtf8)?;
            }
            _ => {}
        }
        if let Some(frame) = stack.last_mut() {
            if is_key {
                // spec §1.2: text keys, bytewise order of the encoded keys, no duplicate.
                if major != Major::Text {
                    return Err(L2Error::MapKeyNotText);
                }
                let key = buf.get(start..r.pos).ok_or(L2Error::Truncated)?;
                match frame.prev_key.map(|prev| prev.cmp(key)) {
                    Some(Ordering::Equal) => return Err(L2Error::DuplicateMapKey),
                    Some(Ordering::Greater) => return Err(L2Error::MapKeysUnsorted),
                    _ => frame.prev_key = Some(key),
                }
            }
            frame.left -= 1;
        }
        while stack.last().is_some_and(|f| f.left == 0) {
            stack.pop();
        }
        let left = match major {
            Major::Array => arg,
            Major::Map => arg.checked_mul(2).ok_or(L2Error::Truncated)?,
            _ => 0,
        };
        if left > 0 {
            stack.push(Frame {
                left,
                is_map: major == Major::Map,
                prev_key: None,
            });
        }
        if stack.is_empty() {
            break;
        }
    }
    if r.at_end() {
        Ok(())
    } else {
        Err(L2Error::TrailingBytes) // spec §1.2: exactly one data item
    }
}

/// A CBOR value of the profile, for encoding. Map keys are sorted by the encoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value `-1 - n`.
    Nint(u64),
    /// A byte string.
    Bytes(&'a [u8]),
    /// A text string.
    Text(&'a str),
    /// An array.
    Array(Vec<Value<'a>>),
    /// A map with text keys, in any order: [`encode`] sorts them.
    Map(Vec<(&'a str, Value<'a>)>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// An item already encoded (copied from a decoded payload). [`encode`] checks it.
    Raw(&'a [u8]),
}

fn put_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    // Shortest form (spec §1.2). The casts are exact: each arm bounds `arg`.
    #[allow(clippy::cast_possible_truncation)]
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => out.extend_from_slice(&[m | 0x18, arg as u8]),
        0x100..=0xffff => {
            out.push(m | 0x19);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 0x1a);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 0x1b);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn len64(n: usize) -> u64 {
    // usize is at most 64 bits on every supported target.
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Encodes `value` in the deterministic profile of spec §1.2 (ADR 0011).
///
/// Sender side: this trusts its caller. It recurses on the nesting of `value`, so the depth of a
/// [`Value`] tree is the caller's responsibility; it is never built from network input (a decoded
/// payload re-enters only as a flat [`Value::Raw`], checked iteratively by [`check_profile`]).
///
/// # Errors
///
/// `DuplicateMapKey` for a map with two equal keys, the [`check_profile`] error of a non-conforming
/// [`Value::Raw`] item, or `PayloadTooLong`.
pub fn encode(value: &Value<'_>) -> Result<Vec<u8>, L2Error> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    if out.len() > MAX_PAYLOAD_LEN {
        return Err(L2Error::PayloadTooLong);
    }
    Ok(out)
}

fn encode_into(value: &Value<'_>, out: &mut Vec<u8>) -> Result<(), L2Error> {
    match value {
        Value::Uint(n) => put_head(out, 0, *n),
        Value::Nint(n) => put_head(out, 1, *n),
        Value::Bytes(b) => {
            put_head(out, 2, len64(b.len()));
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            put_head(out, 3, len64(s.len()));
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            put_head(out, 4, len64(items.len()));
            for item in items {
                encode_into(item, out)?;
            }
        }
        Value::Map(entries) => {
            let mut sorted = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let mut key = Vec::new();
                encode_into(&Value::Text(k), &mut key)?;
                sorted.push((key, v));
            }
            // spec §1.2: bytewise order of the encoded keys (not length-first).
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            if sorted
                .windows(2)
                .any(|w| w.first().map(|e| &e.0) == w.get(1).map(|e| &e.0))
            {
                return Err(L2Error::DuplicateMapKey);
            }
            put_head(out, 5, len64(sorted.len()));
            for (key, v) in sorted {
                out.extend_from_slice(&key);
                encode_into(v, out)?;
            }
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
        Value::Raw(bytes) => {
            check_profile(bytes)?;
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}
