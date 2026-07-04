//! Typed payloads carried inside [`crate::KdxFrame`]s, one module per
//! opcode range. Each type provides `encode() -> Bytes` and
//! `decode(&[u8]) -> Result<Self, ProtocolError>`.

mod handshake;

pub use handshake::{HandshakeInit, HandshakeResp};
