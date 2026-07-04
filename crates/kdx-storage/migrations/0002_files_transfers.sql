CREATE TABLE file_nodes (
    id              TEXT    PRIMARY KEY,               -- UUID v4 ('root' for the root)
    parent_id       TEXT    REFERENCES file_nodes(id),
    name            TEXT    NOT NULL,
    kind            INTEGER NOT NULL,                  -- 0 dir, 1 file, 2 dropbox, 3 upload folder
    size            INTEGER NOT NULL DEFAULT 0,
    sha256          BLOB,                              -- files only
    min_class_read  INTEGER NOT NULL DEFAULT 0,        -- minimum BaseClass to list/download
    min_class_write INTEGER NOT NULL DEFAULT 2,        -- minimum BaseClass to upload/modify
    storage_path    TEXT,                              -- on-disk path, files only
    UNIQUE(parent_id, name)
);

INSERT INTO file_nodes (id, parent_id, name, kind) VALUES ('root', NULL, '', 0);

CREATE TABLE transfer_state (
    id          TEXT    PRIMARY KEY,                   -- UUID v4, the wire transfer id
    account_id  TEXT    NOT NULL,
    parent_id   TEXT    NOT NULL,                      -- destination folder node
    name        TEXT    NOT NULL,                      -- destination file name
    size        INTEGER NOT NULL,
    chunk_size  INTEGER NOT NULL,
    sha256      BLOB    NOT NULL,                      -- expected whole-file hash
    bitmap      BLOB    NOT NULL,                      -- received-chunk bitmap, LSB-first
    temp_path   TEXT    NOT NULL,                      -- partial file on disk
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
