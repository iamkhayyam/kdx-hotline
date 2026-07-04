//! Typed payloads carried inside [`crate::KdxFrame`]s, one module per
//! opcode range. Each type provides `encode() -> Bytes` and
//! `decode(&[u8]) -> Result<Self, ProtocolError>`.

mod auth;
mod handshake;

pub use auth::{AuthChallenge, AuthRequest, AuthResponse, AuthResult};
pub use handshake::{HandshakeInit, HandshakeResp};
