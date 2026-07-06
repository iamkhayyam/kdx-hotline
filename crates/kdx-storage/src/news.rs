//! Public News persistence: newsgroups and their threaded posts. Access
//! semantics (which class may read/post) live in kdx-server-core; storage only
//! records the thresholds and the post tree.

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct NewsgroupRow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub min_read_class: i64,
    pub min_post_class: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct PostRow {
    pub id: String,
    pub newsgroup_id: String,
    /// `None` for a thread root, else the post this one replies to.
    pub parent_id: Option<String>,
    pub author: String,
    pub subject: String,
    pub body: String,
    pub created_at: i64,
}

pub async fn create_group(
    pool: &SqlitePool,
    name: &str,
    description: &str,
    min_read_class: i64,
    min_post_class: i64,
) -> Result<NewsgroupRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO newsgroups (id, name, description, min_read_class, min_post_class)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(description)
    .bind(min_read_class)
    .bind(min_post_class)
    .execute(pool)
    .await?;
    Ok(NewsgroupRow {
        id,
        name: name.to_owned(),
        description: description.to_owned(),
        min_read_class,
        min_post_class,
    })
}

pub async fn all_groups(pool: &SqlitePool) -> Result<Vec<NewsgroupRow>, StorageError> {
    let rows = sqlx::query_as::<_, NewsgroupRow>(
        "SELECT id, name, description, min_read_class, min_post_class
         FROM newsgroups ORDER BY name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn group_by_id(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<NewsgroupRow>, StorageError> {
    let row = sqlx::query_as::<_, NewsgroupRow>(
        "SELECT id, name, description, min_read_class, min_post_class
         FROM newsgroups WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
pub async fn create_post(
    pool: &SqlitePool,
    newsgroup_id: &str,
    parent_id: Option<&str>,
    author: &str,
    subject: &str,
    body: &str,
    created_at: i64,
) -> Result<PostRow, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO news_posts (id, newsgroup_id, parent_id, author, subject, body, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(newsgroup_id)
    .bind(parent_id)
    .bind(author)
    .bind(subject)
    .bind(body)
    .bind(created_at)
    .execute(pool)
    .await?;
    Ok(PostRow {
        id,
        newsgroup_id: newsgroup_id.to_owned(),
        parent_id: parent_id.map(str::to_owned),
        author: author.to_owned(),
        subject: subject.to_owned(),
        body: body.to_owned(),
        created_at,
    })
}

/// Every post in a newsgroup, oldest first — the client assembles the thread
/// tree from `parent_id`.
pub async fn posts_for_group(
    pool: &SqlitePool,
    newsgroup_id: &str,
) -> Result<Vec<PostRow>, StorageError> {
    let rows = sqlx::query_as::<_, PostRow>(
        "SELECT id, newsgroup_id, parent_id, author, subject, body, created_at
         FROM news_posts WHERE newsgroup_id = ? ORDER BY created_at, id",
    )
    .bind(newsgroup_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn post_by_id(pool: &SqlitePool, id: &str) -> Result<Option<PostRow>, StorageError> {
    let row = sqlx::query_as::<_, PostRow>(
        "SELECT id, newsgroup_id, parent_id, author, subject, body, created_at
         FROM news_posts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Delete a post (and, via ON DELETE CASCADE, its replies).
pub async fn delete_post(pool: &SqlitePool, id: &str) -> Result<(), StorageError> {
    let result = sqlx::query("DELETE FROM news_posts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(StorageError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> (SqlitePool, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::connect(&dir.path().join("test.db")).await.unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn group_and_threaded_posts() {
        let (pool, _dir) = pool().await;
        let g = create_group(&pool, "general", "misc chatter", 0, 1).await.unwrap();
        assert_eq!(all_groups(&pool).await.unwrap().len(), 1);

        let root = create_post(&pool, &g.id, None, "phraq", "hi", "first post", 100)
            .await
            .unwrap();
        let reply = create_post(&pool, &g.id, Some(&root.id), "acidburn", "re: hi", "hello", 200)
            .await
            .unwrap();

        let posts = posts_for_group(&pool, &g.id).await.unwrap();
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].id, root.id);
        assert_eq!(posts[1].parent_id.as_deref(), Some(root.id.as_str()));
        assert_eq!(reply.subject, "re: hi");
    }

    #[tokio::test]
    async fn deleting_root_cascades_to_replies() {
        let (pool, _dir) = pool().await;
        let g = create_group(&pool, "g", "", 0, 1).await.unwrap();
        let root = create_post(&pool, &g.id, None, "a", "s", "b", 1).await.unwrap();
        create_post(&pool, &g.id, Some(&root.id), "b", "re", "r", 2).await.unwrap();

        delete_post(&pool, &root.id).await.unwrap();
        assert!(posts_for_group(&pool, &g.id).await.unwrap().is_empty());
        assert!(matches!(
            delete_post(&pool, &root.id).await,
            Err(StorageError::NotFound)
        ));
    }
}
