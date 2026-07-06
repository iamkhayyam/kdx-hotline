use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// Client → server: send a private message to `to` (a username). The server
/// routes it to that user's connection(s) and stamps the sender/time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateSend {
    pub to: String,
    pub text: String,
}

/// Server → client: a private message delivered to the recipient (or echoed
/// to the sender's other sessions). `from` is the sender's username; `to` is
/// the intended recipient (so a client can slot the echo into the right
/// conversation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateMessage {
    pub from: String,
    pub to: String,
    pub timestamp: u64,
    pub text: String,
}

impl PrivateSend {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4 + self.to.len() + self.text.len());
        put_str(&mut buf, &self.to);
        put_str(&mut buf, &self.text);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let to = get_str(&mut payload, "PrivateSend")?;
        let text = get_str(&mut payload, "PrivateSend")?;
        expect_end(payload, "PrivateSend")?;
        Ok(Self { to, text })
    }
}

impl PrivateMessage {
    pub fn encode(&self) -> Bytes {
        let mut buf =
            BytesMut::with_capacity(12 + self.from.len() + self.to.len() + self.text.len());
        put_str(&mut buf, &self.from);
        put_str(&mut buf, &self.to);
        buf.put_u64(self.timestamp);
        put_str(&mut buf, &self.text);
        buf.freeze()
    }

    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let from = get_str(&mut payload, "PrivateMessage")?;
        let to = get_str(&mut payload, "PrivateMessage")?;
        if payload.remaining() < 8 {
            return Err(ProtocolError::MalformedPayload("PrivateMessage"));
        }
        let timestamp = payload.get_u64();
        let text = get_str(&mut payload, "PrivateMessage")?;
        expect_end(payload, "PrivateMessage")?;
        Ok(Self {
            from,
            to,
            timestamp,
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let send = PrivateSend {
            to: "acidburn".into(),
            text: "meet me in /incoming".into(),
        };
        assert_eq!(PrivateSend::decode(&send.encode()).unwrap(), send);

        let msg = PrivateMessage {
            from: "phraq".into(),
            to: "acidburn".into(),
            timestamp: 1_751_600_000,
            text: "the drop is live".into(),
        };
        assert_eq!(PrivateMessage::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn rejects_malformed() {
        assert!(PrivateSend::decode(&[0]).is_err());
        assert!(PrivateMessage::decode(&[0, 1, 65]).is_err());
    }
}
