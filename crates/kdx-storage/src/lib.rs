//! Persistence layer for KDX: all sqlx queries and migrations live here so a
//! later SQLite → Postgres swap touches only this crate. Served file bytes
//! live on the filesystem, never in the database.

pub mod accounts;
pub mod bans;
pub mod db;
pub mod file_tree;
pub mod history;
pub mod ip_rules;
pub mod news;
pub mod roles;
pub mod transfer_state;

pub use db::connect;
pub use sqlx::SqlitePool;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("row not found")]
    NotFound,
}
