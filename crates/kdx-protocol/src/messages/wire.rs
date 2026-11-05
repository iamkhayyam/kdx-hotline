//! Small shared encode/decode helpers for payload types.
//!
//! Encoders are infallible by design (every caller relies on `encode() ->
//! Bytes`), so a value too large for its length prefix or count field is
//! clamped rather than wrapped: strings are cut on a UTF-8 boundary, byte
//! blobs and lists are cut to the largest length the prefix can carry, and
//! exactly that many bytes / entries are written. The prefix therefore always
//! matches what follows, so an oversized field can never spill into the next
//! field and be parsed as forged records. Callers are expected to cap values
//! before encoding; the debug assertions here flag the ones that don't.

use bytes::{Buf, BufMut, BytesMut};

use crate::ProtocolError;

/// Largest byte length a u16 length prefix (or entry count) can describe.
pub(crate) const MAX_U16_LEN: usize = u16::MAX as usize;

/// Largest entry count a u32 count field can describe.
pub(crate) const MAX_U32_LEN: usize = u32::MAX as usize;

/// Upper bound on a list decoder's up-front `Vec` capacity; the vector still
/// grows normally past it as real entries are decoded.
const MAX_PREALLOC: usize = 1024;

/// Report a value that does not fit its wire field and is about to be
/// clamped. Debug builds treat this as a bug in the caller (who should have
/// capped the value first); release builds clamp silently.
fn oversize(what: &'static str, len: usize, max: usize) {
    #[cfg(test)]
    if test_support::oversize_allowed() {
        return;
    }
    debug_assert!(
        len <= max,
        "{what} of {len} exceeds wire limit {max}; it will be clamped"
    );
}

/// Longest prefix of `s` that is at most `max` bytes and ends on a UTF-8
/// character boundary.
pub(crate) fn clamp_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Write a u16-length-prefixed UTF-8 string, clamped to [`MAX_U16_LEN`]
/// bytes on a character boundary.
pub(crate) fn put_str(buf: &mut BytesMut, s: &str) {
    if s.len() > MAX_U16_LEN {
        oversize("string length", s.len(), MAX_U16_LEN);
    }
    let s = clamp_str(s, MAX_U16_LEN);
    buf.put_u16(s.len() as u16);
    buf.put_slice(s.as_bytes());
}

/// Write a u16-length-prefixed byte blob (salt, bitmap), clamped to
/// [`MAX_U16_LEN`] bytes.
pub(crate) fn put_bytes16(buf: &mut BytesMut, bytes: &[u8]) {
    if bytes.len() > MAX_U16_LEN {
        oversize("byte field length", bytes.len(), MAX_U16_LEN);
    }
    let n = bytes.len().min(MAX_U16_LEN);
    buf.put_u16(n as u16);
    buf.put_slice(&bytes[..n]);
}

/// Write a u16 entry count for a list of `len` items and return how many
/// entries the caller must then encode (`len` clamped to [`MAX_U16_LEN`]).
pub(crate) fn put_count16(buf: &mut BytesMut, len: usize) -> usize {
    if len > MAX_U16_LEN {
        oversize("list count", len, MAX_U16_LEN);
    }
    let n = len.min(MAX_U16_LEN);
    buf.put_u16(n as u16);
    n
}

/// Write a u32 entry count for a list of `len` items and return how many
/// entries the caller must then encode (`len` clamped to [`MAX_U32_LEN`]).
pub(crate) fn put_count32(buf: &mut BytesMut, len: usize) -> usize {
    if len > MAX_U32_LEN {
        oversize("list count", len, MAX_U32_LEN);
    }
    let n = len.min(MAX_U32_LEN);
    buf.put_u32(n as u32);
    n
}

/// Capacity hint for a list decoder: never more entries than the remaining
/// payload could possibly hold at `min_entry_len` bytes each, and never more
/// than a small fixed cap, so a tiny payload claiming a huge count cannot
/// force a large allocation.
pub(crate) fn list_capacity(count: usize, remaining: usize, min_entry_len: usize) -> usize {
    count
        .min(remaining / min_entry_len.max(1))
        .min(MAX_PREALLOC)
}

pub(crate) fn get_str(buf: &mut &[u8], context: &'static str) -> Result<String, ProtocolError> {
    if buf.remaining() < 2 {
        return Err(ProtocolError::MalformedPayload(context));
    }
    let len = buf.get_u16() as usize;
    if buf.remaining() < len {
        return Err(ProtocolError::MalformedPayload(context));
    }
    let s = String::from_utf8(buf[..len].to_vec())
        .map_err(|_| ProtocolError::MalformedPayload(context))?;
    buf.advance(len);
    Ok(s)
}

/// Read a u16-length-prefixed byte blob.
pub(crate) fn get_bytes16(
    buf: &mut &[u8],
    context: &'static str,
) -> Result<Vec<u8>, ProtocolError> {
    if buf.remaining() < 2 {
        return Err(ProtocolError::MalformedPayload(context));
    }
    let len = buf.get_u16() as usize;
    if buf.remaining() < len {
        return Err(ProtocolError::MalformedPayload(context));
    }
    let bytes = buf[..len].to_vec();
    buf.advance(len);
    Ok(bytes)
}

/// Read a one-byte boolean / presence flag. Only the canonical encodings
/// `0` and `1` are accepted.
pub(crate) fn get_bool(buf: &mut &[u8], context: &'static str) -> Result<bool, ProtocolError> {
    if buf.remaining() < 1 {
        return Err(ProtocolError::MalformedPayload(context));
    }
    match buf.get_u8() {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProtocolError::MalformedPayload(context)),
    }
}

pub(crate) fn expect_end(buf: &[u8], context: &'static str) -> Result<(), ProtocolError> {
    if buf.has_remaining() {
        return Err(ProtocolError::MalformedPayload(context));
    }
    Ok(())
}

/// Lets this crate's own unit tests encode deliberately oversized values to
/// check the clamping, without tripping the debug assertion meant for
/// callers. Per-thread, so it cannot leak into concurrently running tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::Cell;

    thread_local! {
        static ALLOW_OVERSIZE: Cell<bool> = const { Cell::new(false) };
    }

    pub(crate) fn oversize_allowed() -> bool {
        ALLOW_OVERSIZE.with(Cell::get)
    }

    /// Run `f` with the oversize debug assertion disabled on this thread.
    pub(crate) fn allow_oversize<R>(f: impl FnOnce() -> R) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                ALLOW_OVERSIZE.with(|c| c.set(false));
            }
        }
        ALLOW_OVERSIZE.with(|c| c.set(true));
        let _reset = Reset;
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::allow_oversize;
    use super::*;

    #[test]
    fn clamp_str_respects_char_boundaries() {
        assert_eq!(clamp_str("hello", 10), "hello");
        assert_eq!(clamp_str("hello", 3), "hel");
        // "é" is two bytes; cutting at 1 must back off to 0.
        assert_eq!(clamp_str("é", 1), "");
        assert_eq!(clamp_str("aé", 2), "a");
    }

    #[test]
    fn put_str_clamps_and_prefix_matches_body() {
        // 65,534 ASCII bytes then a 3-byte char straddling the u16 limit.
        let s = format!("{}€tail", "a".repeat(MAX_U16_LEN - 1));
        let mut buf = BytesMut::new();
        allow_oversize(|| put_str(&mut buf, &s));
        let mut rd: &[u8] = &buf;
        let back = get_str(&mut rd, "test").unwrap();
        assert!(rd.is_empty(), "prefix must cover exactly the bytes written");
        assert_eq!(back, "a".repeat(MAX_U16_LEN - 1));
    }

    #[test]
    fn put_bytes16_and_counts_clamp() {
        let blob = vec![0xAB; MAX_U16_LEN + 10];
        let mut buf = BytesMut::new();
        allow_oversize(|| put_bytes16(&mut buf, &blob));
        let mut rd: &[u8] = &buf;
        assert_eq!(get_bytes16(&mut rd, "test").unwrap().len(), MAX_U16_LEN);
        assert!(rd.is_empty());

        let mut buf = BytesMut::new();
        assert_eq!(allow_oversize(|| put_count16(&mut buf, 70_000)), MAX_U16_LEN);
        assert_eq!(&buf[..], &[0xFF, 0xFF]);
        let mut buf = BytesMut::new();
        assert_eq!(put_count32(&mut buf, 70_000), 70_000);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "exceeds wire limit")]
    fn oversize_string_trips_debug_assert() {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &"x".repeat(MAX_U16_LEN + 1));
    }

    #[test]
    fn get_bool_accepts_only_zero_and_one() {
        assert!(!get_bool(&mut &[0u8][..], "t").unwrap());
        assert!(get_bool(&mut &[1u8][..], "t").unwrap());
        assert!(get_bool(&mut &[2u8][..], "t").is_err());
        assert!(get_bool(&mut &[][..], "t").is_err());
    }

    #[test]
    fn list_capacity_is_bounded_by_payload() {
        assert_eq!(list_capacity(u32::MAX as usize, 20, 62), 0);
        assert_eq!(list_capacity(10, 1000, 10), 10);
        assert_eq!(list_capacity(100_000, 10_000_000, 1), MAX_PREALLOC);
    }
}
