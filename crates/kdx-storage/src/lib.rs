//! Persistence layer for KDX: all sqlx queries and migrations live here so a
//! later SQLite → Postgres swap touches only this crate. Served file bytes
//! live on the filesystem, never in the database.
