use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// One role as seen over the wire: a named, colorable bundle of privilege
/// bits a SysOp can assign to accounts on top of their base class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInfo {
    pub id: [u8; 16],
    pub name: String,
    pub privileges: u32,
    pub rank: i32,
    /// Empty string means "no color set" — there is no wire-level `Option`.
    pub color: String,
}

/// Client → server: request every defined role. Empty payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleListRequest;

/// Server → client: full role list, in reply to `RoleListRequest` or after
/// any mutation (create/update/delete/assign/unassign) succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleListResponse {
    pub roles: Vec<RoleInfo>,
}

/// Client → server: define a new role. Requires `USER_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleCreate {
    pub name: String,
    pub privileges: u32,
    pub rank: i32,
    pub color: String,
}

/// Client → server: rename/re-scope an existing role. Requires `USER_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleUpdate {
    pub id: [u8; 16],
    pub name: String,
    pub privileges: u32,
    pub rank: i32,
    pub color: String,
}

/// Client → server: delete a role outright. Requires `USER_ADMIN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleDelete {
    pub id: [u8; 16],
}

/// Client → server: attach a role to an account by username. Requires
/// `USER_ADMIN`. Idempotent server-side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssign {
    pub username: String,
    pub role_id: [u8; 16],
}

/// Client → server: detach a role from an account by username. Requires
/// `USER_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleUnassign {
    pub username: String,
    pub role_id: [u8; 16],
}

/// Client → server: which roles does this account currently hold?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRolesRequest {
    pub username: String,
}

/// Server → client: reply to `AccountRolesRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRolesResponse {
    pub username: String,
    pub role_ids: Vec<[u8; 16]>,
}

fn encode_role(buf: &mut BytesMut, r: &RoleInfo) {
    buf.put_slice(&r.id);
    put_str(buf, &r.name);
    buf.put_u32(r.privileges);
    buf.put_i32(r.rank);
    put_str(buf, &r.color);
}

fn decode_role(payload: &mut &[u8]) -> Result<RoleInfo, ProtocolError> {
    if payload.remaining() < 16 {
        return Err(ProtocolError::MalformedPayload("RoleInfo"));
    }
    let mut id = [0u8; 16];
    payload.copy_to_slice(&mut id);
    let name = get_str(payload, "RoleInfo")?;
    if payload.remaining() < 4 + 4 {
        return Err(ProtocolError::MalformedPayload("RoleInfo"));
    }
    let privileges = payload.get_u32();
    let rank = payload.get_i32();
    let color = get_str(payload, "RoleInfo")?;
    Ok(RoleInfo {
        id,
        name,
        privileges,
        rank,
        color,
    })
}

fn get_id(payload: &mut &[u8], context: &'static str) -> Result<[u8; 16], ProtocolError> {
    if payload.remaining() < 16 {
        return Err(ProtocolError::MalformedPayload(context));
    }
    let mut id = [0u8; 16];
    payload.copy_to_slice(&mut id);
    Ok(id)
}

impl RoleListRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "RoleListRequest")?;
        Ok(Self)
    }
}

impl RoleListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u16(self.roles.len() as u16);
        for role in &self.roles {
            encode_role(&mut buf, role);
        }
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 2 {
            return Err(ProtocolError::MalformedPayload("RoleListResponse"));
        }
        let count = payload.get_u16() as usize;
        let mut roles = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            roles.push(decode_role(&mut payload)?);
        }
        expect_end(payload, "RoleListResponse")?;
        Ok(Self { roles })
    }
}

impl RoleCreate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.name);
        buf.put_u32(self.privileges);
        buf.put_i32(self.rank);
        put_str(&mut buf, &self.color);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let name = get_str(&mut payload, "RoleCreate")?;
        if payload.remaining() < 4 + 4 {
            return Err(ProtocolError::MalformedPayload("RoleCreate"));
        }
        let privileges = payload.get_u32();
        let rank = payload.get_i32();
        let color = get_str(&mut payload, "RoleCreate")?;
        expect_end(payload, "RoleCreate")?;
        Ok(Self {
            name,
            privileges,
            rank,
            color,
        })
    }
}

impl RoleUpdate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_slice(&self.id);
        put_str(&mut buf, &self.name);
        buf.put_u32(self.privileges);
        buf.put_i32(self.rank);
        put_str(&mut buf, &self.color);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let id = get_id(&mut payload, "RoleUpdate")?;
        let name = get_str(&mut payload, "RoleUpdate")?;
        if payload.remaining() < 4 + 4 {
            return Err(ProtocolError::MalformedPayload("RoleUpdate"));
        }
        let privileges = payload.get_u32();
        let rank = payload.get_i32();
        let color = get_str(&mut payload, "RoleUpdate")?;
        expect_end(payload, "RoleUpdate")?;
        Ok(Self {
            id,
            name,
            privileges,
            rank,
            color,
        })
    }
}

impl RoleDelete {
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self.id)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        let id: [u8; 16] = payload
            .try_into()
            .map_err(|_| ProtocolError::MalformedPayload("RoleDelete"))?;
        Ok(Self { id })
    }
}

impl RoleAssign {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.username);
        buf.put_slice(&self.role_id);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "RoleAssign")?;
        let role_id = get_id(&mut payload, "RoleAssign")?;
        expect_end(payload, "RoleAssign")?;
        Ok(Self { username, role_id })
    }
}

impl RoleUnassign {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.username);
        buf.put_slice(&self.role_id);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "RoleUnassign")?;
        let role_id = get_id(&mut payload, "RoleUnassign")?;
        expect_end(payload, "RoleUnassign")?;
        Ok(Self { username, role_id })
    }
}

impl AccountRolesRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.username);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AccountRolesRequest")?;
        expect_end(payload, "AccountRolesRequest")?;
        Ok(Self { username })
    }
}

impl AccountRolesResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.username);
        buf.put_u16(self.role_ids.len() as u16);
        for id in &self.role_ids {
            buf.put_slice(id);
        }
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let username = get_str(&mut payload, "AccountRolesResponse")?;
        if payload.remaining() < 2 {
            return Err(ProtocolError::MalformedPayload("AccountRolesResponse"));
        }
        let count = payload.get_u16() as usize;
        let mut role_ids = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            role_ids.push(get_id(&mut payload, "AccountRolesResponse")?);
        }
        expect_end(payload, "AccountRolesResponse")?;
        Ok(Self { username, role_ids })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_role() -> RoleInfo {
        RoleInfo {
            id: [7u8; 16],
            name: "Moderator".into(),
            privileges: 0b11_0000_0000_0000_0000,
            rank: 10,
            color: "#e11b1b".into(),
        }
    }

    #[test]
    fn all_round_trip() {
        let req = RoleListRequest;
        assert_eq!(RoleListRequest::decode(&req.encode()).unwrap(), req);

        let list = RoleListResponse {
            roles: vec![sample_role(), {
                let mut r = sample_role();
                r.name = "VIP".into();
                r.color = String::new();
                r
            }],
        };
        assert_eq!(RoleListResponse::decode(&list.encode()).unwrap(), list);

        let create = RoleCreate {
            name: "Moderator".into(),
            privileges: 0xFF,
            rank: 5,
            color: "#3df56e".into(),
        };
        assert_eq!(RoleCreate::decode(&create.encode()).unwrap(), create);

        let update = RoleUpdate {
            id: [1u8; 16],
            name: "Mod".into(),
            privileges: 0xAB,
            rank: -1,
            color: String::new(),
        };
        assert_eq!(RoleUpdate::decode(&update.encode()).unwrap(), update);

        let delete = RoleDelete { id: [2u8; 16] };
        assert_eq!(RoleDelete::decode(&delete.encode()).unwrap(), delete);

        let assign = RoleAssign {
            username: "phraq".into(),
            role_id: [3u8; 16],
        };
        assert_eq!(RoleAssign::decode(&assign.encode()).unwrap(), assign);

        let unassign = RoleUnassign {
            username: "phraq".into(),
            role_id: [3u8; 16],
        };
        assert_eq!(RoleUnassign::decode(&unassign.encode()).unwrap(), unassign);

        let acc_req = AccountRolesRequest {
            username: "phraq".into(),
        };
        assert_eq!(AccountRolesRequest::decode(&acc_req.encode()).unwrap(), acc_req);

        let acc_resp = AccountRolesResponse {
            username: "phraq".into(),
            role_ids: vec![[3u8; 16], [4u8; 16]],
        };
        assert_eq!(AccountRolesResponse::decode(&acc_resp.encode()).unwrap(), acc_resp);
    }

    #[test]
    fn empty_lists_round_trip() {
        let list = RoleListResponse { roles: vec![] };
        assert_eq!(RoleListResponse::decode(&list.encode()).unwrap(), list);

        let acc_resp = AccountRolesResponse {
            username: "nobody".into(),
            role_ids: vec![],
        };
        assert_eq!(AccountRolesResponse::decode(&acc_resp.encode()).unwrap(), acc_resp);
    }

    #[test]
    fn rejects_malformed() {
        assert!(RoleListResponse::decode(&[0]).is_err());
        assert!(RoleDelete::decode(&[0u8; 15]).is_err());
        assert!(RoleAssign::decode(&[0, 5]).is_err());
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut bytes = RoleDelete { id: [1u8; 16] }.encode().to_vec();
        bytes.push(0xFF);
        assert!(RoleDelete::decode(&bytes).is_err());
    }
}
