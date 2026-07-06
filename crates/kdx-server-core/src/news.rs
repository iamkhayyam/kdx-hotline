//! Public News: newsgroups and threaded posts, with per-class read/post
//! enforcement. Thin domain layer over `kdx_storage::news` (mirrors
//! `RoleManager`): it validates UUIDs and surfaces rows the connection handler
//! turns into wire messages. Access checks (class thresholds, authorship on
//! delete) live in the connection dispatch, which holds the session.

use kdx_storage::news as storage;
use kdx_storage::SqlitePool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum NewsError {
    #[error("stored id is not a valid uuid")]
    CorruptId,
    #[error("no such newsgroup")]
    NoSuchGroup,
    #[error("no such post")]
    NoSuchPost,
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
}

/// A newsgroup with its id decoded to a `Uuid` and classes to `u8`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Newsgroup {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub min_read_class: u8,
    pub min_post_class: u8,
}

/// A post with ids decoded. `parent_id` is `None` for a thread root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    pub id: Uuid,
    pub newsgroup_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub author: String,
    pub subject: String,
    pub body: String,
    pub timestamp: u64,
}

fn group_from_row(r: storage::NewsgroupRow) -> Result<Newsgroup, NewsError> {
    Ok(Newsgroup {
        id: Uuid::parse_str(&r.id).map_err(|_| NewsError::CorruptId)?,
        name: r.name,
        description: r.description,
        min_read_class: r.min_read_class as u8,
        min_post_class: r.min_post_class as u8,
    })
}

fn post_from_row(r: storage::PostRow) -> Result<Post, NewsError> {
    let parent_id = match r.parent_id {
        Some(p) => Some(Uuid::parse_str(&p).map_err(|_| NewsError::CorruptId)?),
        None => None,
    };
    Ok(Post {
        id: Uuid::parse_str(&r.id).map_err(|_| NewsError::CorruptId)?,
        newsgroup_id: Uuid::parse_str(&r.newsgroup_id).map_err(|_| NewsError::CorruptId)?,
        parent_id,
        author: r.author,
        subject: r.subject,
        body: r.body,
        timestamp: r.created_at as u64,
    })
}

pub struct NewsManager {
    pool: SqlitePool,
}

impl NewsManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create_group(
        &self,
        name: &str,
        description: &str,
        min_read_class: u8,
        min_post_class: u8,
    ) -> Result<Newsgroup, NewsError> {
        let row = storage::create_group(
            &self.pool,
            name,
            description,
            min_read_class as i64,
            min_post_class as i64,
        )
        .await?;
        group_from_row(row)
    }

    pub async fn list_groups(&self) -> Result<Vec<Newsgroup>, NewsError> {
        storage::all_groups(&self.pool)
            .await?
            .into_iter()
            .map(group_from_row)
            .collect()
    }

    pub async fn group(&self, id: Uuid) -> Result<Newsgroup, NewsError> {
        let row = storage::group_by_id(&self.pool, &id.to_string())
            .await?
            .ok_or(NewsError::NoSuchGroup)?;
        group_from_row(row)
    }

    pub async fn posts(&self, newsgroup_id: Uuid) -> Result<Vec<Post>, NewsError> {
        storage::posts_for_group(&self.pool, &newsgroup_id.to_string())
            .await?
            .into_iter()
            .map(post_from_row)
            .collect()
    }

    pub async fn post(&self, id: Uuid) -> Result<Post, NewsError> {
        let row = storage::post_by_id(&self.pool, &id.to_string())
            .await?
            .ok_or(NewsError::NoSuchPost)?;
        post_from_row(row)
    }

    pub async fn create_post(
        &self,
        newsgroup_id: Uuid,
        parent_id: Option<Uuid>,
        author: &str,
        subject: &str,
        body: &str,
        timestamp: u64,
    ) -> Result<Post, NewsError> {
        let parent = parent_id.map(|p| p.to_string());
        let row = storage::create_post(
            &self.pool,
            &newsgroup_id.to_string(),
            parent.as_deref(),
            author,
            subject,
            body,
            timestamp as i64,
        )
        .await?;
        post_from_row(row)
    }

    pub async fn delete_post(&self, id: Uuid) -> Result<(), NewsError> {
        storage::delete_post(&self.pool, &id.to_string()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn mgr() -> (NewsManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = kdx_storage::connect(&dir.path().join("test.db"))
            .await
            .unwrap();
        (NewsManager::new(pool), dir)
    }

    #[tokio::test]
    async fn create_group_post_and_reply() {
        let (news, _dir) = mgr().await;
        let g = news.create_group("general", "chatter", 0, 1).await.unwrap();
        assert_eq!(news.list_groups().await.unwrap().len(), 1);

        let root = news
            .create_post(g.id, None, "phraq", "hi", "first", 100)
            .await
            .unwrap();
        let reply = news
            .create_post(g.id, Some(root.id), "acidburn", "re: hi", "hello", 200)
            .await
            .unwrap();
        assert_eq!(reply.parent_id, Some(root.id));

        let posts = news.posts(g.id).await.unwrap();
        assert_eq!(posts.len(), 2);

        news.delete_post(reply.id).await.unwrap();
        assert_eq!(news.posts(g.id).await.unwrap().len(), 1);
    }
}
