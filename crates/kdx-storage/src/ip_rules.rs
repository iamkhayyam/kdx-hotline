//! Allow-Deny IP rules: an ordered list of rules checked at connection
//! accept. Semantics (match order, fail-open default, wiring into the
//! accept loop) live in kdx-server-core; storage only stores rows and
//! answers "list them in priority order".

use sqlx::SqlitePool;
use uuid::Uuid;

use crate::StorageError;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct IpRuleRow {
    pub id: String,
    pub position: i64,
    /// "allow" or "deny" — enforced by a CHECK constraint at write time.
    pub action: String,
    pub cidr: String,
    pub note: String,
    pub created_by: String,
    pub created_at: i64,
}

/// Insert a rule. `position` is a caller-chosen priority: lower wins,
/// so an allow-exception ahead of a broader deny gets `position < deny.position`.
pub async fn create(
    pool: &SqlitePool,
    position: i64,
    action: &str,
    cidr: &str,
    note: &str,
    created_by: &str,
    created_at: i64,
) -> Result<String, StorageError> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO ip_rules (id, position, action, cidr, note, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(position)
    .bind(action)
    .bind(cidr)
    .bind(note)
    .bind(created_by)
    .bind(created_at)
    .execute(pool)
    .await?;
    Ok(id)
}

/// Delete a rule by id. A no-op if the row is already gone.
pub async fn delete(pool: &SqlitePool, id: &str) -> Result<(), StorageError> {
    sqlx::query("DELETE FROM ip_rules WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// All rules in match order (lowest `position` first). Ties on position
/// break on `created_at` so a rule added later doesn't jump ahead.
pub async fn list(pool: &SqlitePool) -> Result<Vec<IpRuleRow>, StorageError> {
    let rows = sqlx::query_as::<_, IpRuleRow>(
        "SELECT id, position, action, cidr, note, created_by, created_at
         FROM ip_rules
         ORDER BY position ASC, created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
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
    async fn create_list_delete_round_trip() {
        let (pool, _dir) = pool().await;
        let a = create(&pool, 10, "deny", "1.2.3.0/24", "spammy /24", "sysop", 100)
            .await
            .unwrap();
        let _b = create(&pool, 5, "allow", "1.2.3.4/32", "our office", "sysop", 200)
            .await
            .unwrap();

        // Ordered by priority (position ASC): allow-exception first, then deny.
        let rows = list(&pool).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].action, "allow");
        assert_eq!(rows[0].cidr, "1.2.3.4/32");
        assert_eq!(rows[1].action, "deny");

        delete(&pool, &a).await.unwrap();
        assert_eq!(list(&pool).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn position_ties_break_on_created_at() {
        let (pool, _dir) = pool().await;
        create(&pool, 10, "deny", "10.0.0.0/8", "first", "sysop", 100).await.unwrap();
        create(&pool, 10, "deny", "192.168.0.0/16", "second", "sysop", 200).await.unwrap();

        let rows = list(&pool).await.unwrap();
        assert_eq!(rows[0].cidr, "10.0.0.0/8");
        assert_eq!(rows[1].cidr, "192.168.0.0/16");
    }

    #[tokio::test]
    async fn check_constraint_rejects_bogus_action() {
        let (pool, _dir) = pool().await;
        let err = create(&pool, 0, "maybe", "0.0.0.0/0", "", "sysop", 0).await;
        assert!(err.is_err(), "CHECK(action IN ('allow','deny')) must reject 'maybe'");
    }
}
