use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::wire::{expect_end, get_str, put_str};
use crate::ProtocolError;

/// A newsgroup as seen over the wire. `min_read_class` / `min_post_class` are
/// base-class thresholds (0 guest … 3 admin) the server enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsgroupInfo {
    pub id: [u8; 16],
    pub name: String,
    pub description: String,
    pub min_read_class: u8,
    pub min_post_class: u8,
}

/// One post in a thread. `parent_id` all-zeros marks a thread root (there is no
/// wire-level `Option`), mirroring the empty-string-means-none convention used
/// elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsPost {
    pub id: [u8; 16],
    pub newsgroup_id: [u8; 16],
    pub parent_id: [u8; 16],
    pub author: String,
    pub subject: String,
    pub body: String,
    pub timestamp: u64,
}

/// Client → server: list every newsgroup. Empty payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsgroupListRequest;

/// Server → client: newsgroups the caller may see (server filters by read
/// class), in reply to `NewsgroupListRequest` or after a newsgroup is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsgroupListResponse {
    pub groups: Vec<NewsgroupInfo>,
}

/// Client → server: every post in a newsgroup (the client builds the tree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsThreadListRequest {
    pub newsgroup_id: [u8; 16],
}

/// Server → client: the posts of a newsgroup, oldest first. Also the reply to
/// a successful post/delete so the News window re-renders from one shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsThreadListResponse {
    pub newsgroup_id: [u8; 16],
    pub posts: Vec<NewsPost>,
}

/// Client → server: create a post (or a reply, when `parent_id` is non-zero).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsPostCreate {
    pub newsgroup_id: [u8; 16],
    pub parent_id: [u8; 16],
    pub subject: String,
    pub body: String,
}

/// Client → server: delete a post you authored (admins may delete any).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsPostDelete {
    pub post_id: [u8; 16],
}

/// Client → server: define a newsgroup. Requires `USER_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsgroupCreate {
    pub name: String,
    pub description: String,
    pub min_read_class: u8,
    pub min_post_class: u8,
}

fn get_id(payload: &mut &[u8], ctx: &'static str) -> Result<[u8; 16], ProtocolError> {
    if payload.remaining() < 16 {
        return Err(ProtocolError::MalformedPayload(ctx));
    }
    let mut id = [0u8; 16];
    payload.copy_to_slice(&mut id);
    Ok(id)
}

impl NewsgroupListRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::new()
    }
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        expect_end(payload, "NewsgroupListRequest")?;
        Ok(Self)
    }
}

impl NewsgroupListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u32(self.groups.len() as u32);
        for g in &self.groups {
            buf.put_slice(&g.id);
            put_str(&mut buf, &g.name);
            put_str(&mut buf, &g.description);
            buf.put_u8(g.min_read_class);
            buf.put_u8(g.min_post_class);
        }
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("NewsgroupListResponse"));
        }
        let count = payload.get_u32() as usize;
        let mut groups = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let id = get_id(&mut payload, "NewsgroupListResponse")?;
            let name = get_str(&mut payload, "NewsgroupListResponse")?;
            let description = get_str(&mut payload, "NewsgroupListResponse")?;
            if payload.remaining() < 2 {
                return Err(ProtocolError::MalformedPayload("NewsgroupListResponse"));
            }
            let min_read_class = payload.get_u8();
            let min_post_class = payload.get_u8();
            groups.push(NewsgroupInfo {
                id,
                name,
                description,
                min_read_class,
                min_post_class,
            });
        }
        expect_end(payload, "NewsgroupListResponse")?;
        Ok(Self { groups })
    }
}

impl NewsThreadListRequest {
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self.newsgroup_id)
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let newsgroup_id = get_id(&mut payload, "NewsThreadListRequest")?;
        expect_end(payload, "NewsThreadListRequest")?;
        Ok(Self { newsgroup_id })
    }
}

fn encode_post(buf: &mut BytesMut, p: &NewsPost) {
    buf.put_slice(&p.id);
    buf.put_slice(&p.newsgroup_id);
    buf.put_slice(&p.parent_id);
    put_str(buf, &p.author);
    put_str(buf, &p.subject);
    put_str(buf, &p.body);
    buf.put_u64(p.timestamp);
}

fn decode_post(payload: &mut &[u8]) -> Result<NewsPost, ProtocolError> {
    let id = get_id(payload, "NewsPost")?;
    let newsgroup_id = get_id(payload, "NewsPost")?;
    let parent_id = get_id(payload, "NewsPost")?;
    let author = get_str(payload, "NewsPost")?;
    let subject = get_str(payload, "NewsPost")?;
    let body = get_str(payload, "NewsPost")?;
    if payload.remaining() < 8 {
        return Err(ProtocolError::MalformedPayload("NewsPost"));
    }
    let timestamp = payload.get_u64();
    Ok(NewsPost {
        id,
        newsgroup_id,
        parent_id,
        author,
        subject,
        body,
        timestamp,
    })
}

impl NewsThreadListResponse {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_slice(&self.newsgroup_id);
        buf.put_u32(self.posts.len() as u32);
        for p in &self.posts {
            encode_post(&mut buf, p);
        }
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let newsgroup_id = get_id(&mut payload, "NewsThreadListResponse")?;
        if payload.remaining() < 4 {
            return Err(ProtocolError::MalformedPayload("NewsThreadListResponse"));
        }
        let count = payload.get_u32() as usize;
        let mut posts = Vec::with_capacity(count.min(65536));
        for _ in 0..count {
            posts.push(decode_post(&mut payload)?);
        }
        expect_end(payload, "NewsThreadListResponse")?;
        Ok(Self {
            newsgroup_id,
            posts,
        })
    }
}

impl NewsPostCreate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_slice(&self.newsgroup_id);
        buf.put_slice(&self.parent_id);
        put_str(&mut buf, &self.subject);
        put_str(&mut buf, &self.body);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let newsgroup_id = get_id(&mut payload, "NewsPostCreate")?;
        let parent_id = get_id(&mut payload, "NewsPostCreate")?;
        let subject = get_str(&mut payload, "NewsPostCreate")?;
        let body = get_str(&mut payload, "NewsPostCreate")?;
        expect_end(payload, "NewsPostCreate")?;
        Ok(Self {
            newsgroup_id,
            parent_id,
            subject,
            body,
        })
    }
}

impl NewsPostDelete {
    pub fn encode(&self) -> Bytes {
        Bytes::copy_from_slice(&self.post_id)
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let post_id = get_id(&mut payload, "NewsPostDelete")?;
        expect_end(payload, "NewsPostDelete")?;
        Ok(Self { post_id })
    }
}

impl NewsgroupCreate {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        put_str(&mut buf, &self.name);
        put_str(&mut buf, &self.description);
        buf.put_u8(self.min_read_class);
        buf.put_u8(self.min_post_class);
        buf.freeze()
    }
    pub fn decode(mut payload: &[u8]) -> Result<Self, ProtocolError> {
        let name = get_str(&mut payload, "NewsgroupCreate")?;
        let description = get_str(&mut payload, "NewsgroupCreate")?;
        if payload.remaining() < 2 {
            return Err(ProtocolError::MalformedPayload("NewsgroupCreate"));
        }
        let min_read_class = payload.get_u8();
        let min_post_class = payload.get_u8();
        expect_end(payload, "NewsgroupCreate")?;
        Ok(Self {
            name,
            description,
            min_read_class,
            min_post_class,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newsgroup_list_round_trip() {
        let msg = NewsgroupListResponse {
            groups: vec![
                NewsgroupInfo {
                    id: [1u8; 16],
                    name: "general".into(),
                    description: "misc".into(),
                    min_read_class: 0,
                    min_post_class: 1,
                },
                NewsgroupInfo {
                    id: [2u8; 16],
                    name: "staff".into(),
                    description: "".into(),
                    min_read_class: 3,
                    min_post_class: 3,
                },
            ],
        };
        assert_eq!(NewsgroupListResponse::decode(&msg.encode()).unwrap(), msg);
        assert!(NewsgroupListRequest::decode(&NewsgroupListRequest.encode()).is_ok());
    }

    #[test]
    fn thread_list_round_trip() {
        let msg = NewsThreadListResponse {
            newsgroup_id: [9u8; 16],
            posts: vec![
                NewsPost {
                    id: [1u8; 16],
                    newsgroup_id: [9u8; 16],
                    parent_id: [0u8; 16],
                    author: "phraq".into(),
                    subject: "hi".into(),
                    body: "first".into(),
                    timestamp: 1_751_600_000,
                },
                NewsPost {
                    id: [2u8; 16],
                    newsgroup_id: [9u8; 16],
                    parent_id: [1u8; 16],
                    author: "acidburn".into(),
                    subject: "re: hi".into(),
                    body: "hello".into(),
                    timestamp: 1_751_600_100,
                },
            ],
        };
        assert_eq!(NewsThreadListResponse::decode(&msg.encode()).unwrap(), msg);
    }

    #[test]
    fn create_delete_round_trip() {
        let c = NewsPostCreate {
            newsgroup_id: [7u8; 16],
            parent_id: [0u8; 16],
            subject: "topic".into(),
            body: "body text".into(),
        };
        assert_eq!(NewsPostCreate::decode(&c.encode()).unwrap(), c);

        let req = NewsThreadListRequest { newsgroup_id: [7u8; 16] };
        assert_eq!(NewsThreadListRequest::decode(&req.encode()).unwrap(), req);

        let del = NewsPostDelete { post_id: [3u8; 16] };
        assert_eq!(NewsPostDelete::decode(&del.encode()).unwrap(), del);

        let g = NewsgroupCreate {
            name: "general".into(),
            description: "chatter".into(),
            min_read_class: 0,
            min_post_class: 2,
        };
        assert_eq!(NewsgroupCreate::decode(&g.encode()).unwrap(), g);
    }

    #[test]
    fn rejects_truncated() {
        assert!(NewsThreadListRequest::decode(&[0, 1, 2]).is_err());
        assert!(NewsPostCreate::decode(&[0u8; 8]).is_err());
        assert!(NewsgroupListResponse::decode(&[0, 0]).is_err());
    }
}
