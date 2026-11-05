//! Public News: newsgroups and threaded posts, with per-class read/post
//! enforcement. Thin domain layer over `kdx_storage::news` (mirrors
//! `RoleManager`): it validates UUIDs and surfaces rows the connection handler
//! turns into wire messages. Access checks (class thresholds, authorship on
//! delete) live in the connection dispatch, which holds the session.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use kdx_storage::news as storage;
use kdx_storage::SqlitePool;
use tokio::time::Instant;
use uuid::Uuid;

/// Highest class threshold a newsgroup may require (Admin). Anything above
/// would make the group invisible to everyone, admins included.
pub const MAX_CLASS_THRESHOLD: u8 = 3;

/// Posts an account may make in a burst before the rate limit applies.
pub const POST_BURST: u32 = 5;
/// After a burst, one more post is allowed per this interval.
pub const POST_REFILL: Duration = Duration::from_secs(10);
/// Rate-limit entries kept before idle (fully refilled) ones are pruned.
const RATE_TABLE_PRUNE_AT: usize = 1024;

/// Most posts sent in one thread-list reply (the newest ones).
pub const THREAD_REPLY_MAX_POSTS: u32 = 200;
/// Rough byte budget for one thread-list reply, well under what the client
/// reassembles (4 MiB) even with maximum-size posts.
pub const THREAD_REPLY_MAX_BYTES: usize = 1024 * 1024;

/// Turn the newest-first posts of a group into a thread-list reply (DOS-11):
/// keep the newest ones that fit [`THREAD_REPLY_MAX_BYTES`], order them
/// oldest first, and show any reply whose parent fell outside the window as
/// a thread root, so the client's tree still displays it.
pub fn reply_window(newest_first: Vec<Post>) -> Vec<Post> {
    let mut budget = THREAD_REPLY_MAX_BYTES;
    let mut window = Vec::new();
    for post in newest_first {
        // Fixed fields (three ids, timestamp, length prefixes) plus text.
        let cost = 64 + post.author.len() + post.subject.len() + post.body.len();
        if cost > budget {
            break;
        }
        budget -= cost;
        window.push(post);
    }
    window.reverse();
    let ids: HashSet<Uuid> = window.iter().map(|p| p.id).collect();
    for post in &mut window {
        if post.parent_id.is_some_and(|parent| !ids.contains(&parent)) {
            post.parent_id = None;
        }
    }
    window
}

#[derive(Debug, thiserror::Error)]
pub enum NewsError {
    #[error("stored id is not a valid uuid")]
    CorruptId,
    #[error("no such newsgroup")]
    NoSuchGroup,
    #[error("no such post")]
    NoSuchPost,
    #[error("the post you replied to is not in this newsgroup")]
    NoSuchParent,
    #[error("class thresholds must be between 0 and 3")]
    InvalidClass,
    #[error("storage error: {0}")]
    Storage(#[from] kdx_storage::StorageError),
}

/// Token bucket for one account's posting.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn refilled(&self, now: Instant) -> f64 {
        let earned = now.duration_since(self.last).as_secs_f64() / POST_REFILL.as_secs_f64();
        (self.tokens + earned).min(POST_BURST as f64)
    }
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
    /// Per-account posting buckets (DOS-11). Keyed by username so opening
    /// more connections doesn't buy more posts.
    post_rate: Mutex<HashMap<String, Bucket>>,
}

impl NewsManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            post_rate: Mutex::new(HashMap::new()),
        }
    }

    /// Spend one post from `author`'s bucket: `true` if the post may go
    /// ahead, `false` if they're posting too fast.
    pub fn allow_post(&self, author: &str) -> bool {
        let now = Instant::now();
        let mut table = self.post_rate.lock().unwrap_or_else(|e| e.into_inner());
        if table.len() >= RATE_TABLE_PRUNE_AT {
            table.retain(|_, b| b.refilled(now) < POST_BURST as f64);
        }
        let bucket = table.entry(author.to_owned()).or_insert(Bucket {
            tokens: POST_BURST as f64,
            last: now,
        });
        let tokens = bucket.refilled(now);
        bucket.last = now;
        if tokens >= 1.0 {
            bucket.tokens = tokens - 1.0;
            true
        } else {
            bucket.tokens = tokens;
            false
        }
    }

    pub async fn create_group(
        &self,
        name: &str,
        description: &str,
        min_read_class: u8,
        min_post_class: u8,
    ) -> Result<Newsgroup, NewsError> {
        if min_read_class > MAX_CLASS_THRESHOLD || min_post_class > MAX_CLASS_THRESHOLD {
            return Err(NewsError::InvalidClass);
        }
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

    /// The newest `limit` posts in a newsgroup, newest first.
    pub async fn recent_posts(&self, newsgroup_id: Uuid, limit: u32) -> Result<Vec<Post>, NewsError> {
        storage::recent_posts_for_group(&self.pool, &newsgroup_id.to_string(), limit as i64)
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
        .await
        .map_err(|e| match e {
            // The only way the guarded insert writes nothing: the parent
            // isn't a post in this group.
            kdx_storage::StorageError::NotFound => NewsError::NoSuchParent,
            other => NewsError::Storage(other),
        })?;
        post_from_row(row)
    }

    /// Delete a post and, by cascade, every reply beneath it (moderators).
    pub async fn delete_post(&self, id: Uuid) -> Result<(), NewsError> {
        storage::delete_post(&self.pool, &id.to_string()).await?;
        Ok(())
    }

    /// Delete `author`'s own post, refusing (`Ok(false)`) if anyone else
    /// replied anywhere beneath it, since the cascade would take their
    /// replies down too.
    pub async fn delete_own_post(&self, id: Uuid, author: &str) -> Result<bool, NewsError> {
        Ok(storage::delete_own_post(&self.pool, &id.to_string(), author).await?)
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

    #[tokio::test]
    async fn class_thresholds_above_admin_are_refused() {
        let (news, _dir) = mgr().await;
        assert!(matches!(
            news.create_group("hidden", "", 4, 0).await,
            Err(NewsError::InvalidClass)
        ));
        assert!(matches!(
            news.create_group("hidden", "", 0, 200).await,
            Err(NewsError::InvalidClass)
        ));
        assert!(news.list_groups().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cross_group_reply_is_no_such_parent() {
        let (news, _dir) = mgr().await;
        let g1 = news.create_group("g1", "", 0, 0).await.unwrap();
        let g2 = news.create_group("g2", "", 0, 0).await.unwrap();
        let root = news.create_post(g2.id, None, "a", "s", "b", 1).await.unwrap();
        assert!(matches!(
            news.create_post(g1.id, Some(root.id), "b", "re", "r", 2).await,
            Err(NewsError::NoSuchParent)
        ));
    }

    #[test]
    fn reply_window_is_bounded_ordered_and_reparents_orphans() {
        let post = |n: u64, parent: Option<Uuid>, body_len: usize| Post {
            id: Uuid::from_u128(n as u128 + 1),
            newsgroup_id: Uuid::nil(),
            parent_id: parent,
            author: "a".into(),
            subject: format!("s{n}"),
            body: "b".repeat(body_len),
            timestamp: n,
        };
        // Oldest root, a reply to it, then a newer root; newest first.
        let root = post(0, None, 10);
        let reply = post(1, Some(root.id), 10);
        let newer = post(2, None, 10);
        let all = reply_window(vec![newer.clone(), reply.clone(), root.clone()]);
        assert_eq!(
            all.iter().map(|p| p.timestamp).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(all[1].parent_id, Some(root.id));

        // A byte budget that fits only the two newest posts: the reply's
        // parent falls outside, so it's shown as a root.
        let big = THREAD_REPLY_MAX_BYTES / 2 - 100;
        let window = reply_window(vec![
            post(2, None, big),
            post(1, Some(root.id), big),
            post(0, None, big),
        ]);
        assert_eq!(window.len(), 2);
        assert_eq!(window[0].timestamp, 1);
        assert_eq!(window[0].parent_id, None);
    }

    #[tokio::test]
    async fn posting_is_rate_limited_per_account() {
        let (news, _dir) = mgr().await;
        // Pause only now: sqlx's pool timeouts misbehave under a paused clock.
        tokio::time::pause();
        for _ in 0..POST_BURST {
            assert!(news.allow_post("spammer"));
        }
        assert!(!news.allow_post("spammer"));
        // Someone else is unaffected.
        assert!(news.allow_post("bystander"));
        // One refill interval later, exactly one more post.
        tokio::time::advance(POST_REFILL).await;
        assert!(news.allow_post("spammer"));
        assert!(!news.allow_post("spammer"));
    }
}
