//! Helpers to read a body of the profile (spec §2.5): closed maps, required fields, arrays and
//! 32-byte identifiers.
//!
//! Used by the `sbtp.*` kinds of this crate and public for application kinds (ADR 0038 rule 9).
//! Every helper reads from a [`Reader`] over a buffer that already passed
//! [`crate::cbor::check_profile`]. [`fields`] and [`array()`] are generic over the caller's error
//! type, so that an application closure can return its own errors (any type that an [`L2Error`]
//! converts into).

use alloc::vec::Vec;

use crate::L2Error;
use crate::cbor::{Major, Reader};
use crate::payload::Id;

/// A body field of the wrong CBOR type.
pub const BAD: L2Error = L2Error::BodyFieldValue;

/// A 32-byte identifier in a body (spec §1.4): a byte string of another length is
/// [`L2Error::BodyIdSize`], any other type [`L2Error::BodyFieldValue`].
///
/// # Errors
///
/// `BodyIdSize`, `BodyFieldValue`, or an error of [`Reader::head`].
pub fn id(r: &mut Reader<'_>) -> Result<Id, L2Error> {
    r.bytes(BAD)?.try_into().map_err(|_| L2Error::BodyIdSize)
}

/// Reads a closed map: calls `f` on each key, with the reader on its value; `f` reads the value
/// and returns `true`, or returns `false` for a key the body rule does not define.
///
/// # Errors
///
/// [`L2Error::BodyType`] if the item is not a map, [`L2Error::BodyUnknownField`] for a key `f`
/// refuses, or the first error of `f`.
pub fn fields<'a, E: From<L2Error>>(
    r: &mut Reader<'a>,
    f: impl FnMut(&'a str, &mut Reader<'a>) -> Result<bool, E>,
) -> Result<(), E> {
    closed_map(r, L2Error::BodyType, L2Error::BodyUnknownField, f)
}

/// Reads a closed map, as [`fields`], with the caller's errors: `not_map` when the item is not a
/// map, `unknown` for a key `f` refuses. Shared by the bodies, the edges and their `meta`.
pub(crate) fn closed_map<'a, E: From<L2Error>>(
    r: &mut Reader<'a>,
    not_map: L2Error,
    unknown: L2Error,
    mut f: impl FnMut(&'a str, &mut Reader<'a>) -> Result<bool, E>,
) -> Result<(), E> {
    let n = r.expect(Major::Map, not_map)?;
    for _ in 0..n {
        // The profile (spec §1.2) already made every key a text string.
        let key = r.text(not_map)?;
        if !f(key, r)? {
            return Err(unknown.into());
        }
    }
    Ok(())
}

/// A required field: `None` is [`L2Error::BodyMissingField`].
///
/// # Errors
///
/// `BodyMissingField` when `v` is `None`.
pub fn required<T>(v: Option<T>) -> Result<T, L2Error> {
    v.ok_or(L2Error::BodyMissingField)
}

/// An array of items read by `item`; `non_empty` for the CDDL `[+ ...]`.
///
/// # Errors
///
/// [`BAD`] if the item is not an array, [`L2Error::BodyEmptyArray`] for an empty array when
/// `non_empty`, or the first error of `item`.
pub fn array<'a, T, E: From<L2Error>>(
    r: &mut Reader<'a>,
    non_empty: bool,
    mut item: impl FnMut(&mut Reader<'a>) -> Result<T, E>,
) -> Result<Vec<T>, E> {
    let n = r.expect(Major::Array, BAD)?;
    if non_empty && n == 0 {
        return Err(L2Error::BodyEmptyArray.into()); // spec §2.5, CDDL `[+ ...]`
    }
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(item(r)?);
    }
    Ok(out)
}

/// `[uint, uint]`: `cites.span` and `resolution`.
///
/// # Errors
///
/// `bad` if the item is not an array of exactly two unsigned integers, or an error of
/// [`Reader::head`].
pub fn pair(r: &mut Reader<'_>, bad: L2Error) -> Result<(u64, u64), L2Error> {
    if r.expect(Major::Array, bad)? != 2 {
        return Err(bad);
    }
    Ok((r.uint(bad)?, r.uint(bad)?))
}
