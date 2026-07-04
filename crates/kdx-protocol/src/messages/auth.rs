use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::ProtocolError;

/// Client → server: begin authentication for `username`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub username: String,
}

/// Server → client: a fresh random challenge plus the Argon2id salt and cost
/// parameters the client needs to recompute its verifier locally. The
/// password itself never crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub challenge: [u8; 32],
    pub salt: Vec<u8>,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Client → server: `SHA-256(challenge || argon2id(password, salt, params))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub response: [u8; 32],
}

/// Server → client: outcome. On success carries the session id and the
/// account's base class (0 guest, 1 user, 2 power user, 3 admin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub success: bool,
    pub session_id: [u8; 16],
    pub class: u8,
    pub message: String,
}

fn put_str(buf: &mut BytesMut, s: &str) {
    buf.put_u16(s.len() as u16);
    buf.put_slice(s.as_bytes());
}

fn get_str(buf: &mut &[u8], context: &'static str) -> Result<String, ProtocolError> {
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

impl AuthRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(2 + self.username.len());
        put_str(&mut buf, &self.username);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AuthRequest")?;
        if payload.has_remaining() {
            return Err(ProtocolError::MalformedPayload("AuthRequest"));
        }
        Ok(Self { username })
    }
}

impl AuthChallenge {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(32 + 12 + 2 + self.salt.len());
        buf.put_slice(&self.challenge);
        buf.put_u32(self.m_cost);
        buf.put_u32(self.t_cost);
        buf.put_u32(self.p_cost);
        buf.put_u16(self.salt.len() as u16);
        buf.put_slice(&self.salt);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 32 + 12 + 2 {
            return Err(ProtocolError::MalformedPayload("AuthChallenge"));
        }
        let mut challenge = [0u8; 32];
        payload.copy_to_slice(&mut challenge);
        let m_cost = payload.get_u32();
        let t_cost = payload.get_u32();
        let p_cost = payload.get_u32();
        let salt_len = payload.get_u16() as usize;
        if payload.remaining() != salt_len {
            return Err(ProtocolError::MalformedPayload("AuthChallenge"));
        }
        Ok(Self {
            challenge,
            salt: payload[..salt_len].to_vec(),
            m_cost,
            t_cost,
            p_cost,
        })
    }
}

impl AuthResponse {
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self.response)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        let response: [u8; 32] = payload
            .try_into()
            .map_err(|_| ProtocolError::MalformedPayload("AuthResponse"))?;
        Ok(Self { response })
    }
}

impl AuthResult {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + 16 + 1 + 2 + self.message.len());
        buf.put_u8(self.success as u8);
        buf.put_slice(&self.session_id);
        buf.put_u8(self.class);
        put_str(&mut buf, &self.message);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 1 + 16 + 1 + 2 {
            return Err(ProtocolError::MalformedPayload("AuthResult"));
        }
        let success = payload.get_u8() != 0;
        let mut session_id = [0u8; 16];
        payload.copy_to_slice(&mut session_id);
        let class = payload.get_u8();
        let message = get_str(&mut payload, "AuthResult")?;
        if payload.has_remaining() {
            return Err(ProtocolError::MalformedPayload("AuthResult"));
        }
        Ok(Self {
            success,
            session_id,
            class,
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip() {
        let msg = AuthRequest {
            username: "phraq".into(),
        };
        assert_eq!(AuthRequest::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn challenge_round_trip() {
        let msg = AuthChallenge {
            challenge: [7u8; 32],
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        };
        assert_eq!(AuthChallenge::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn response_round_trip() {
        let msg = AuthResponse { response: [9u8; 32] };
        assert_eq!(AuthResponse::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn result_round_trip() {
        let msg = AuthResult {
            success: true,
            session_id: [3u8; 16],
            class: 2,
            message: "welcome back".into(),
        };
        assert_eq!(AuthResult::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn rejects_truncation() {
        assert!(AuthRequest::decode(&[0]).is_err());
        assert!(AuthChallenge::decode(&[0u8; 10]).is_err());
        assert!(AuthResponse::decode(&[0u8; 31]).is_err());
        assert!(AuthResult::decode(&[1]).is_err());
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut bytes = AuthRequest {
            username: "x".into(),
        }
        .encode()
        .to_vec();
        bytes.push(0xFF);
        assert!(AuthRequest::decode(&bytes).is_err());
    }
}
