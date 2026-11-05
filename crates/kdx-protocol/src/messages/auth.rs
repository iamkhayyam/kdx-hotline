use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::account::Credential;
use super::wire::{expect_end, get_bool, get_str, put_str};
use crate::ProtocolError;

/// Client → server: begin authentication for `username`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub username: String,
}

/// Server → client: a fresh random challenge plus the Argon2id salt and cost
/// parameters the client needs to recompute its salted password locally. The
/// password itself never crosses the wire. Clients must bound the parameters
/// (`kdx_crypto::KdfParams::check_bounds`) before running Argon2.
///
/// Wire: `challenge[32] m_cost:u32 t_cost:u32 p_cost:u32 salt_len:u16 salt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub challenge: [u8; 32],
    pub salt: Vec<u8>,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Client → server: the SCRAM-style `ClientProof` (`ClientKey XOR
/// HMAC(StoredKey, AuthMessage)`, see `kdx_crypto::scram`), bound to the
/// username, the challenge and the TLS channel.
///
/// Wire: `proof[32]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResponse {
    pub response: [u8; 32],
}

/// Server → client: outcome. On success carries the session id, the
/// account's base class (0 guest, 1 user, 2 power user, 3 admin), the
/// session's effective privilege bits (class defaults, plus role and
/// account grants, minus account revokes — the server's `Privileges`
/// bitflags) and the `ServerSignature` (`HMAC(ServerKey, AuthMessage)`) the
/// client must verify before trusting the login. On failure the session id,
/// class, privileges and signature are all zero. A failure may also be sent
/// directly in reply to `AuthRequest` (throttled, server full, invalid
/// username) without a challenge round.
///
/// The privileges are a login-time snapshot. They stay accurate for the
/// session's lifetime because the server disconnects the live sessions of
/// an account whose class or effective privileges change (through its
/// overrides, its roles, or a role's privileges); they must log in again.
///
/// Wire: `success:u8 session_id[16] class:u8 privileges:u32 message:str
/// server_signature[32]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResult {
    pub success: bool,
    pub session_id: [u8; 16],
    pub class: u8,
    pub privileges: u32,
    pub message: String,
    pub server_signature: [u8; 32],
}

/// Client → server (logged in): start changing your own password. Empty
/// payload. Answered with `PasswordChangeChallenge`, or `Error` (guest
/// account, throttled).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordChangeBegin;

/// Server → client: a fresh challenge plus the salt and Argon2id parameters
/// of the account's *current* credential, for the proof in
/// `PasswordChangeProof`. Clients bound the parameters exactly as for a
/// login. Valid for one proof, until the server's change timeout.
///
/// Wire: same layout as `AuthChallenge` — `challenge[32] m_cost:u32
/// t_cost:u32 p_cost:u32 salt_len:u16 salt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordChangeChallenge {
    pub challenge: [u8; 32],
    pub salt: Vec<u8>,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Client → server: proof of the *current* password over the
/// password-change message (`kdx_crypto::scram`: its own domain label, the
/// login fields for the current credential, and the whole new credential),
/// plus the new `credential`, derived locally from the new password. Neither
/// password is sent. Answered with `PasswordChangeResult`, or `Error` (no
/// challenge outstanding, unacceptable credential).
///
/// Wire: `proof[32] credential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordChangeProof {
    pub proof: [u8; 32],
    pub credential: Credential,
}

/// Server → client: outcome of a `PasswordChangeProof`. On success the
/// `server_signature` is `HMAC(ServerKey, ChangeMessage)` under the *old*
/// credential, which the client must verify; on failure it is all zeros.
///
/// Wire: `success:u8 message:str server_signature[32]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordChangeResult {
    pub success: bool,
    pub message: String,
    pub server_signature: [u8; 32],
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
        let mut buf = BytesMut::with_capacity(1 + 16 + 1 + 4 + 2 + self.message.len() + 32);
        buf.put_u8(self.success as u8);
        buf.put_slice(&self.session_id);
        buf.put_u8(self.class);
        buf.put_u32(self.privileges);
        put_str(&mut buf, &self.message);
        buf.put_slice(&self.server_signature);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 1 + 16 + 1 + 4 + 2 {
            return Err(ProtocolError::MalformedPayload("AuthResult"));
        }
        let success = payload.get_u8() != 0;
        let mut session_id = [0u8; 16];
        payload.copy_to_slice(&mut session_id);
        let class = payload.get_u8();
        let privileges = payload.get_u32();
        let message = get_str(&mut payload, "AuthResult")?;
        if payload.remaining() != 32 {
            return Err(ProtocolError::MalformedPayload("AuthResult"));
        }
        let mut server_signature = [0u8; 32];
        payload.copy_to_slice(&mut server_signature);
        Ok(Self {
            success,
            session_id,
            class,
            privileges,
            message,
            server_signature,
        })
    }
}

impl PasswordChangeBegin {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "PasswordChangeBegin")?;
        Ok(Self)
    }
}

impl PasswordChangeChallenge {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(32 + 12 + 2 + self.salt.len());
        buf.put_slice(&self.challenge);
        buf.put_u32(self.m_cost);
        buf.put_u32(self.t_cost);
        buf.put_u32(self.p_cost);
        super::wire::put_bytes16(&mut buf, &self.salt);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 32 + 12 {
            return Err(ProtocolError::MalformedPayload("PasswordChangeChallenge"));
        }
        let mut challenge = [0u8; 32];
        payload.copy_to_slice(&mut challenge);
        let m_cost = payload.get_u32();
        let t_cost = payload.get_u32();
        let p_cost = payload.get_u32();
        let salt = super::wire::get_bytes16(&mut payload, "PasswordChangeChallenge")?;
        expect_end(payload, "PasswordChangeChallenge")?;
        Ok(Self {
            challenge,
            salt,
            m_cost,
            t_cost,
            p_cost,
        })
    }
}

impl PasswordChangeProof {
    pub fn encode(&self) -> Bytes {
        let mut buf =
            BytesMut::with_capacity(32 + Credential::MIN_LEN + self.credential.salt.len());
        buf.put_slice(&self.proof);
        self.credential.put(&mut buf);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 32 {
            return Err(ProtocolError::MalformedPayload("PasswordChangeProof"));
        }
        let mut proof = [0u8; 32];
        payload.copy_to_slice(&mut proof);
        let credential = Credential::get(&mut payload, "PasswordChangeProof")?;
        expect_end(payload, "PasswordChangeProof")?;
        Ok(Self { proof, credential })
    }
}

impl PasswordChangeResult {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + 2 + self.message.len() + 32);
        buf.put_u8(self.success as u8);
        put_str(&mut buf, &self.message);
        buf.put_slice(&self.server_signature);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let success = get_bool(&mut payload, "PasswordChangeResult")?;
        let message = get_str(&mut payload, "PasswordChangeResult")?;
        if payload.remaining() != 32 {
            return Err(ProtocolError::MalformedPayload("PasswordChangeResult"));
        }
        let mut server_signature = [0u8; 32];
        payload.copy_to_slice(&mut server_signature);
        Ok(Self {
            success,
            message,
            server_signature,
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
            // High and low bits both survive (u32, big-endian).
            privileges: 0x8008_0101,
            message: "welcome back".into(),
            server_signature: [5u8; 32],
        };
        assert_eq!(AuthResult::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn result_layout_puts_privileges_after_class() {
        let msg = AuthResult {
            success: true,
            session_id: [3u8; 16],
            class: 2,
            privileges: 0x000C_01FF,
            message: "hi".into(),
            server_signature: [5u8; 32],
        };
        let bytes = msg.encode();
        let mut expected = vec![1u8];
        expected.extend_from_slice(&[3u8; 16]);
        expected.push(2);
        expected.extend_from_slice(&[0x00, 0x0C, 0x01, 0xFF]);
        expected.extend_from_slice(&[0, 2, b'h', b'i']);
        expected.extend_from_slice(&[5u8; 32]);
        assert_eq!(&bytes[..], &expected[..]);
        // Every strict prefix is refused (privileges included).
        for len in 0..bytes.len() {
            assert!(AuthResult::decode(&bytes[..len]).is_err(), "prefix of {len} bytes");
        }
    }

    #[test]
    fn result_requires_exactly_one_signature() {
        let msg = AuthResult {
            success: false,
            session_id: [0u8; 16],
            class: 0,
            privileges: 0,
            message: "invalid credentials".into(),
            server_signature: [0u8; 32],
        };
        let bytes = msg.encode().to_vec();
        assert!(AuthResult::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(AuthResult::decode(&long).is_err());
    }

    #[test]
    fn password_change_round_trips() {
        assert_eq!(
            PasswordChangeBegin::decode(&PasswordChangeBegin.encode()).unwrap(),
            PasswordChangeBegin
        );
        assert!(PasswordChangeBegin::decode(&[0]).is_err());

        let challenge = PasswordChangeChallenge {
            challenge: [7u8; 32],
            salt: vec![3; 16],
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        };
        let bytes = challenge.encode();
        // Same layout as AuthChallenge.
        let as_login = AuthChallenge::decode(&bytes).unwrap();
        assert_eq!(as_login.salt, challenge.salt);
        assert_eq!(PasswordChangeChallenge::decode(&bytes).unwrap(), challenge);

        let proof = PasswordChangeProof {
            proof: [9u8; 32],
            credential: Credential {
                m_cost: 19456,
                t_cost: 2,
                p_cost: 1,
                salt: vec![4; 16],
                stored_key: [5; 32],
                server_key: [6; 32],
            },
        };
        let bytes = proof.encode();
        assert_eq!(PasswordChangeProof::decode(&bytes).unwrap(), proof);
        for len in 0..bytes.len() {
            assert!(PasswordChangeProof::decode(&bytes[..len]).is_err());
        }

        let result = PasswordChangeResult {
            success: true,
            message: "password changed".into(),
            server_signature: [8u8; 32],
        };
        let bytes = result.encode();
        assert_eq!(PasswordChangeResult::decode(&bytes).unwrap(), result);
        // Canonical flag byte only.
        let mut odd = bytes.to_vec();
        odd[0] = 2;
        assert!(PasswordChangeResult::decode(&odd).is_err());
        let mut long = bytes.to_vec();
        long.push(0);
        assert!(PasswordChangeResult::decode(&long).is_err());
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
