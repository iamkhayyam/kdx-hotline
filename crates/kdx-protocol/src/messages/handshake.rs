use bytes::{BufMut, Bytes, BytesMut};

use crate::ProtocolError;

/// Client's opening message: the protocol version it speaks and a feature
/// bitset for capability negotiation. No cipher negotiation — transport
/// security is TLS, established before any KDX bytes flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInit {
    pub version: u8,
    pub features: u16,
}

/// Server's reply: the version the session will use and the feature
/// intersection both sides support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResp {
    pub version: u8,
    pub features: u16,
}

impl HandshakeInit {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(3);
        buf.put_u8(self.version);
        buf.put_u16(self.features);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() != 3 {
            return Err(ProtocolError::MalformedPayload("HandshakeInit"));
        }
        Ok(Self {
            version: payload[0],
            features: u16::from_be_bytes([payload[1], payload[2]]),
        })
    }
}

impl HandshakeResp {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(3);
        buf.put_u8(self.version);
        buf.put_u16(self.features);
        buf.freeze()
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() != 3 {
            return Err(ProtocolError::MalformedPayload("HandshakeResp"));
        }
        Ok(Self {
            version: payload[0],
            features: u16::from_be_bytes([payload[1], payload[2]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_round_trip() {
        let msg = HandshakeInit {
            version: 1,
            features: 0b1010,
        };
        assert_eq!(HandshakeInit::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn resp_round_trip() {
        let msg = HandshakeResp {
            version: 1,
            features: 0,
        };
        assert_eq!(HandshakeResp::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn rejects_truncated() {
        assert!(HandshakeInit::decode(&[1]).is_err());
        assert!(HandshakeResp::decode(&[1, 2, 3, 4]).is_err());
    }
}
