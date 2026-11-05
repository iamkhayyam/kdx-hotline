use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteSynchronous};

use crate::StorageError;

/// How long a connection waits on a locked database before failing with
/// SQLITE_BUSY. Set explicitly (rather than relying on the driver default)
/// so the behaviour is visible here.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Open (creating if missing) the SQLite database at `path` and run all
/// pending migrations. This is the only place migrations execute.
///
/// `path` is a plain filesystem path, never a URL: `%XX`, `?`, `#`, a
/// leading `file:` or the name `:memory:` all name an ordinary file.
///
/// The database holds login verifiers, so on Unix the file is created
/// owner-only (0600) before SQLite opens it — SQLite gives its `-wal` /
/// `-shm` side files the main file's mode — and an existing database or
/// side file that is group/other-accessible is tightened to owner-only,
/// with a warning.
pub async fn connect(path: &Path) -> Result<SqlitePool, StorageError> {
    let path = literal_path(path);
    #[cfg(unix)]
    secure_db_files(&path)?;
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        // WAL keeps readers unblocked during chunk-ack bitmap writes.
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        // In WAL mode NORMAL is still crash-safe for the database (a power
        // loss can only roll back the last few commits), and it drops the
        // fsync from every commit — only checkpoints sync.
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(BUSY_TIMEOUT)
        // Enforce foreign keys so ON DELETE CASCADE fires (account_roles,
        // news_posts). SQLite leaves this off per-connection by default.
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// sqlx opens files with `SQLITE_OPEN_URI`, so a relative name starting
/// with `file:` would be parsed as a URI, and SQLite treats a bare
/// `:memory:` as an in-memory database. Anchoring relative paths at `./`
/// makes SQLite open exactly the named file in both cases.
fn literal_path(path: &Path) -> PathBuf {
    if path.is_relative() {
        Path::new(".").join(path)
    } else {
        path.to_path_buf()
    }
}

/// `<db>-wal` / `<db>-shm`: SQLite's WAL-mode side files.
fn side_file(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(unix)]
fn secure_db_files(path: &Path) -> Result<(), StorageError> {
    use std::fs::{self, OpenOptions};
    use std::io::ErrorKind;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Create the file owner-only if it doesn't exist yet. SQLite would
    // otherwise create it 0644 (its default under a 022 umask). An empty
    // file is a valid, empty database to SQLite.
    match OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }

    for file in [path.to_path_buf(), side_file(path, "-wal"), side_file(path, "-shm")] {
        let meta = match fs::metadata(&file) {
            Ok(meta) => meta,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let mode = meta.permissions().mode();
        if mode & 0o077 == 0 {
            continue;
        }
        tracing::warn!(
            file = %file.display(),
            mode = format_args!("{:o}", mode & 0o7777),
            "database file is accessible to group/other; restricting to owner-only"
        );
        if let Err(e) = fs::set_permissions(&file, fs::Permissions::from_mode(mode & 0o700)) {
            // Don't refuse to start (e.g. a filesystem without Unix modes),
            // but make the exposure loud.
            tracing::warn!(
                file = %file.display(),
                error = %e,
                "could not restrict database file permissions; it holds login verifiers"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn opens_exactly_the_named_file() {
        let dir = tempfile::tempdir().unwrap();
        // Each of these used to be rewritten by the `sqlite://` URL parser:
        // `%20` percent-decoded, `?` and `#` split off as query/fragment.
        for name in ["a%20b.db", "q?mode=ro.db", "h#frag.db"] {
            let path = dir.path().join(name);
            let pool = connect(&path).await.unwrap();
            sqlx::query("INSERT INTO history (id, timestamp, action) VALUES ('x', 1, 'probe')")
                .execute(&pool)
                .await
                .unwrap();
            pool.close().await;
            assert!(path.is_file(), "{name} was not created");
        }
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| !n.ends_with("-wal") && !n.ends_with("-shm"))
            .collect();
        names.sort();
        assert_eq!(names, vec!["a%20b.db", "h#frag.db", "q?mode=ro.db"]);
    }

    #[test]
    fn relative_uri_like_names_are_anchored() {
        assert_eq!(literal_path(Path::new("file:x.db")), Path::new("./file:x.db"));
        assert_eq!(literal_path(Path::new(":memory:")), Path::new("./:memory:"));
        assert_eq!(literal_path(Path::new("/var/lib/kdx.db")), Path::new("/var/lib/kdx.db"));
    }

    #[tokio::test]
    async fn reopening_keeps_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kdx.db");
        let pool = connect(&path).await.unwrap();
        sqlx::query("INSERT INTO history (id, timestamp, action) VALUES ('x', 1, 'probe')")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let pool = connect(&path).await.unwrap();
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM history")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn pragmas_applied() {
        let dir = tempfile::tempdir().unwrap();
        let pool = connect(&dir.path().join("kdx.db")).await.unwrap();
        let (sync,): (i64,) = sqlx::query_as("PRAGMA synchronous").fetch_one(&pool).await.unwrap();
        assert_eq!(sync, 1, "synchronous should be NORMAL");
        let (busy,): (i64,) = sqlx::query_as("PRAGMA busy_timeout").fetch_one(&pool).await.unwrap();
        assert_eq!(busy, BUSY_TIMEOUT.as_millis() as i64);
        let (fk,): (i64,) = sqlx::query_as("PRAGMA foreign_keys").fetch_one(&pool).await.unwrap();
        assert_eq!(fk, 1);
        let (mode,): (String,) = sqlx::query_as("PRAGMA journal_mode").fetch_one(&pool).await.unwrap();
        assert_eq!(mode, "wal");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn new_database_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kdx.db");
        let pool = connect(&path).await.unwrap();
        // A write so the WAL / SHM side files exist too.
        sqlx::query("INSERT INTO history (id, timestamp, action) VALUES ('x', 1, 'probe')")
            .execute(&pool)
            .await
            .unwrap();
        for file in [path.clone(), side_file(&path, "-wal"), side_file(&path, "-shm")] {
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{} has mode {:o}", file.display(), mode);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn existing_world_readable_database_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kdx.db");
        // A database and its live WAL/SHM, world-readable as an older build
        // left them. Keep the first pool open so the side files stay put.
        let first = connect(&path).await.unwrap();
        sqlx::query("INSERT INTO history (id, timestamp, action) VALUES ('x', 1, 'probe')")
            .execute(&first)
            .await
            .unwrap();
        let files = [path.clone(), side_file(&path, "-wal"), side_file(&path, "-shm")];
        for file in &files {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let _second = connect(&path).await.unwrap();
        for file in &files {
            let mode = std::fs::metadata(file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{} has mode {:o}", file.display(), mode);
        }
    }
}
