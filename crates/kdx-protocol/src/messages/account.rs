use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{
    expect_end, get_bytes16, get_str, list_capacity, put_bytes16, put_count32, put_str,
};
use crate::ProtocolError;

/// A SCRAM credential derived on the client from a new password (see
/// `kdx_crypto::scram`): fresh salt, Argon2id parameters, StoredKey and
/// ServerKey. It is what `AccountCreate`, `AccountSetPassword` and
/// `PasswordChangeProof` carry instead of a password, so no password ever
/// crosses the wire. Servers must validate it
/// (`kdx_crypto::StoredCredential::check_acceptable`) before storing it.
///
/// Wire (embedded): `m_cost:u32 t_cost:u32 p_cost:u32 salt_len:u16 salt
/// stored_key[32] server_key[32]`.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: Vec<u8>,
    pub stored_key: [u8; 32],
    pub server_key: [u8; 32],
}

impl std::fmt::Debug for Credential {
    // Key material stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("m_cost", &self.m_cost)
            .field("t_cost", &self.t_cost)
            .field("p_cost", &self.p_cost)
            .field("salt_len", &self.salt.len())
            .finish_non_exhaustive()
    }
}

impl Credential {
    /// Smallest embedded encoding (empty salt).
    pub(crate) const MIN_LEN: usize = 12 + 2 + 32 + 32;

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_u32(self.m_cost);
        buf.put_u32(self.t_cost);
        buf.put_u32(self.p_cost);
        put_bytes16(buf, &self.salt);
        buf.put_slice(&self.stored_key);
        buf.put_slice(&self.server_key);
    }

    pub(crate) fn get(buf: &mut &[u8], context: &'static str) -> Result<Self, ProtocolError> {
        if buf.remaining() < 12 {
            return Err(ProtocolError::MalformedPayload(context));
        }
        let m_cost = buf.get_u32();
        let t_cost = buf.get_u32();
        let p_cost = buf.get_u32();
        let salt = get_bytes16(buf, context)?;
        if buf.remaining() < 64 {
            return Err(ProtocolError::MalformedPayload(context));
        }
        let mut stored_key = [0u8; 32];
        buf.copy_to_slice(&mut stored_key);
        let mut server_key = [0u8; 32];
        buf.copy_to_slice(&mut server_key);
        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
            salt,
            stored_key,
            server_key,
        })
    }
}

/// Client → server: provision a new account. Requires `USER_ADMIN`. The
/// creating client derives the new account's `credential` from its initial
/// password locally, so the password never crosses the wire (the server
/// validates the credential and stores it as is). `base_class` is 0..=3;
/// `granted`/`revoked` are privilege-override bitmasks. Answered with
/// `AccountListResponse` or `Error`.
///
/// Wire: `username:str credential base_class:u8 granted:u32 revoked:u32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCreate {
    pub username: String,
    pub credential: Credential,
    pub base_class: u8,
    pub granted: u32,
    pub revoked: u32,
}

/// Client → server: an administrator resets `username`'s password to a
/// `credential` the admin's client derived from the new password locally.
/// Requires `USER_ADMIN` and the right to manage that account (same rules as
/// `AccountUpdate`; never your own — use the password change). The account's
/// live sessions are disconnected. Answered with `AccountListResponse` or
/// `Error`.
///
/// Wire: `username:str credential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSetPassword {
    pub username: String,
    pub credential: Credential,
}

/// Client → server: change an existing account's class and privilege
/// overrides (not its password). Requires `USER_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUpdate {
    pub username: String,
    pub base_class: u8,
    pub granted: u32,
    pub revoked: u32,
}

/// Client → server: list every account (the Accounts window). Empty payload.
/// Requires `USER_ADMIN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountListRequest;

/// One account as shown in the Accounts window (no password material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    pub username: String,
    pub base_class: u8,
    pub granted: u32,
    pub revoked: u32,
}

/// Server → client: the full account list, in reply to `AccountListRequest`
/// or after any account mutation (create/update) succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountListResponse {
    pub accounts: Vec<AccountSummary>,
}

impl AccountCreate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            2 + self.username.len() + Credential::MIN_LEN + self.credential.salt.len() + 9,
        );
        put_str(&mut buf, &self.username);
        self.credential.put(&mut buf);
        buf.put_u8(self.base_class);
        buf.put_u32(self.granted);
        buf.put_u32(self.revoked);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AccountCreate")?;
        let credential = Credential::get(&mut payload, "AccountCreate")?;
        if payload.remaining() < 1 + 4 + 4 {
            return Err(ProtocolError::MalformedPayload("AccountCreate"));
        }
        let base_class = payload.get_u8();
        let granted = payload.get_u32();
        let revoked = payload.get_u32();
        expect_end(payload, "AccountCreate")?;
        Ok(Self {
            username,
            credential,
            base_class,
            granted,
            revoked,
        })
    }
}

impl AccountSetPassword {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(
            2 + self.username.len() + Credential::MIN_LEN + self.credential.salt.len(),
        );
        put_str(&mut buf, &self.username);
        self.credential.put(&mut buf);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AccountSetPassword")?;
        let credential = Credential::get(&mut payload, "AccountSetPassword")?;
        expect_end(payload, "AccountSetPassword")?;
        Ok(Self {
            username,
            credential,
        })
    }
}

impl AccountUpdate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(12 + self.username.len());
        put_str(&mut buf, &self.username);
        buf.put_u8(self.base_class);
        buf.put_u32(self.granted);
        buf.put_u32(self.revoked);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AccountUpdate")?;
        if payload.remaining() < 1 + 4 + 4 {
            return Err(ProtocolError::MalformedPayload("AccountUpdate"));
        }
        let base_class = payload.get_u8();
        let granted = payload.get_u32();
        let revoked = payload.get_u32();
        expect_end(payload, "AccountUpdate")?;
        Ok(Self {
            username,
            base_class,
            granted,
            revoked,
        })
    }
}

impl AccountListRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "AccountListRequest")?;
        Ok(Self)
    }
}

impl AccountListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        let n = put_count32(&mut buf, self.accounts.len());
        for a in &self.accounts[..n] {
            put_str(&mut buf, &a.username);
            buf.put_u8(a.base_class);
            buf.put_u32(a.granted);
            buf.put_u32(a.revoked);
        }
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("AccountListResponse"));
        }
        let count = payload.get_u32() as usize;
        // Minimum entry: username prefix + class + granted + revoked.
        let min_entry = 2 + 1 + 4 + 4;
        let mut accounts = Vec::with_capacity(list_capacity(count, payload.remaining(), min_entry));
        for _ in 0..count {
            let username = get_str(&mut payload, "AccountListResponse")?;
            if payload.remaining() < 1 + 4 + 4 {
                return Err(ProtocolError::MalformedPayload("AccountListResponse"));
            }
            let base_class = payload.get_u8();
            let granted = payload.get_u32();
            let revoked = payload.get_u32();
            accounts.push(AccountSummary {
                username,
                base_class,
                granted,
                revoked,
            });
        }
        expect_end(payload, "AccountListResponse")?;
        Ok(Self { accounts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> Credential {
        Credential {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
            salt: vec![7; 16],
            stored_key: [1; 32],
            server_key: [2; 32],
        }
    }

    #[test]
    fn account_create_round_trip() {
        let c = AccountCreate {
            username: "acidburn".into(),
            credential: credential(),
            base_class: 2,
            granted: 0x0000_0008,
            revoked: 0x0000_0040,
        };
        assert_eq!(AccountCreate::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn account_set_password_round_trip() {
        let m = AccountSetPassword {
            username: "phraq".into(),
            credential: credential(),
        };
        let bytes = m.encode();
        assert_eq!(bytes.len(), 2 + 5 + Credential::MIN_LEN + 16);
        assert_eq!(AccountSetPassword::decode(&bytes).unwrap(), m);
        // Every truncation and any trailing byte is refused.
        for len in 0..bytes.len() {
            assert!(AccountSetPassword::decode(&bytes[..len]).is_err());
        }
        let mut long = bytes.to_vec();
        long.push(0);
        assert!(AccountSetPassword::decode(&long).is_err());
    }

    #[test]
    fn credential_debug_hides_keys() {
        let shown = format!("{:?}", credential());
        assert!(shown.contains("salt_len"));
        assert!(!shown.contains("stored_key") && !shown.contains("server_key"));
    }

    #[test]
    fn account_update_round_trip() {
        let u = AccountUpdate {
            username: "phraq".into(),
            base_class: 1,
            granted: 0xDEAD_BEEF,
            revoked: 0,
        };
        assert_eq!(AccountUpdate::decode(&u.encode()).unwrap(), u);
    }

    #[test]
    fn account_list_round_trip() {
        let list = AccountListResponse {
            accounts: vec![
                AccountSummary {
                    username: "admin".into(),
                    base_class: 3,
                    granted: 0,
                    revoked: 0,
                },
                AccountSummary {
                    username: "guest".into(),
                    base_class: 0,
                    granted: 1,
                    revoked: 2,
                },
            ],
        };
        assert_eq!(AccountListResponse::decode(&list.encode()).unwrap(), list);

        let empty = AccountListResponse { accounts: vec![] };
        assert_eq!(AccountListResponse::decode(&empty.encode()).unwrap(), empty);
        assert!(AccountListRequest::decode(&AccountListRequest.encode()).is_ok());
    }

    #[test]
    fn rejects_truncated() {
        assert!(AccountCreate::decode(&[0]).is_err());
        assert!(AccountSetPassword::decode(&[0]).is_err());
        assert!(AccountUpdate::decode(&[0]).is_err());
        assert!(AccountListResponse::decode(&[0, 0]).is_err());
    }
}
