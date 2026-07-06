use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// One server in the tracker directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub users: u32,
    pub max_users: u32,
    pub description: String,
}

/// Client → server: list the tracker's known servers, optionally filtered by a
/// case-insensitive name substring (empty = all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerListRequest {
    pub filter: String,
}

/// Server → client: the tracker directory, sorted by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerListResponse {
    pub servers: Vec<TrackerServer>,
}

impl TrackerListRequest {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.filter);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let filter = get_str(&mut payload, "TrackerListRequest")?;
        expect_end(payload, "TrackerListRequest")?;
        Ok(Self { filter })
    }
}

impl TrackerListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.servers.len() as u32);
        for s in &self.servers {
            put_str(&mut buf, &s.name);
            put_str(&mut buf, &s.host);
            buf.put_u16(s.port);
            buf.put_u32(s.users);
            buf.put_u32(s.max_users);
            put_str(&mut buf, &s.description);
        }
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("TrackerListResponse"));
        }
        let count = payload.get_u32() as usize;
        let mut servers = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let name = get_str(&mut payload, "TrackerListResponse")?;
            let host = get_str(&mut payload, "TrackerListResponse")?;
            if payload.remaining() < 2 + 4 + 4 {
                return Err(ProtocolError::MalformedPayload("TrackerListResponse"));
            }
            let port = payload.get_u16();
            let users = payload.get_u32();
            let max_users = payload.get_u32();
            let description = get_str(&mut payload, "TrackerListResponse")?;
            servers.push(TrackerServer {
                name,
                host,
                port,
                users,
                max_users,
                description,
            });
        }
        expect_end(payload, "TrackerListResponse")?;
        Ok(Self { servers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let req = TrackerListRequest { filter: "under".into() };
        assert_eq!(TrackerListRequest::decode(&req.encode()).unwrap(), req);

        let resp = TrackerListResponse {
            servers: vec![
                TrackerServer {
                    name: "The Underground".into(),
                    host: "kdx.example.net".into(),
                    port: 10700,
                    users: 7,
                    max_users: 100,
                    description: "warez & wares".into(),
                },
                TrackerServer {
                    name: "Empty".into(),
                    host: "10.0.0.2".into(),
                    port: 10701,
                    users: 0,
                    max_users: 32,
                    description: String::new(),
                },
            ],
        };
        assert_eq!(TrackerListResponse::decode(&resp.encode()).unwrap(), resp);

        let empty = TrackerListResponse { servers: vec![] };
        assert_eq!(TrackerListResponse::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn rejects_truncated() {
        assert!(TrackerListRequest::decode(&[]).is_err());
        assert!(TrackerListResponse::decode(&[0, 0]).is_err());
    }
}
