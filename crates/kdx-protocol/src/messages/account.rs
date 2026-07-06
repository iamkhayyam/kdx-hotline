use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// Client → server: provision a new account. Requires `USER_ADMIN`. The
/// `password` is the new account's *initial* password — the one case where a
/// password crosses the wire, and only under TLS: the server hashes it with
/// Argon2id on receipt (challenge-response never sends a password otherwise).
/// `base_class` is 0..=3; `granted`/`revoked` are privilege-override bitmasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCreate {
    pub username: String,
    pub password: String,
    pub base_class: u8,
    pub granted: u32,
    pub revoked: u32,
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
        let mut buf = BytesMut::with_capacity(16 + self.username.len() + self.password.len());
        put_str(&mut buf, &self.username);
        put_str(&mut buf, &self.password);
        buf.put_u8(self.base_class);
        buf.put_u32(self.granted);
        buf.put_u32(self.revoked);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AccountCreate")?;
        let password = get_str(&mut payload, "AccountCreate")?;
        if payload.remaining() < 1 + 4 + 4 {
            return Err(ProtocolError::MalformedPayload("AccountCreate"));
        }
        let base_class = payload.get_u8();
        let granted = payload.get_u32();
        let revoked = payload.get_u32();
        expect_end(payload, "AccountCreate")?;
        Ok(Self {
            username,
            password,
            base_class,
            granted,
            revoked,
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
        buf.put_u32(self.accounts.len() as u32);
        for a in &self.accounts {
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
        let mut accounts = Vec::with_capacity(count.min(1024));
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

    #[test]
    fn account_create_round_trip() {
        let c = AccountCreate {
            username: "acidburn".into(),
            password: "hacktheplanet".into(),
            base_class: 2,
            granted: 0x0000_0008,
            revoked: 0x0000_0040,
        };
        assert_eq!(AccountCreate::decode(&c.encode()).unwrap(), c);
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
        assert!(AccountUpdate::decode(&[0]).is_err());
        assert!(AccountListResponse::decode(&[0, 0]).is_err());
    }
}
