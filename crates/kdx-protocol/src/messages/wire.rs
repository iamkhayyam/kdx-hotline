//! Small shared encode/decode helpers for payload types.

use bytes::{Buf, BufMut, BytesMut};

use crate::ProtocolError;

pub(crate) fn put_str(buf: &mut BytesMut, s: &str) {
    buf.put_u16(s.len() as u16);
    buf.put_slice(s.as_bytes());
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

pub(crate) fn expect_end(buf: &[u8], context: &'static str) -> Result<(), ProtocolError> {
    if buf.has_remaining() {
        return Err(ProtocolError::MalformedPayload(context));
    }
    Ok(())
}
