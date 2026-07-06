-- Public News: newsgroups and threaded posts. Per-class access is stored as
-- minimum base-class thresholds (0 guest … 3 admin); the server compares the
-- reader/poster's class against them. Threading is by parent_id: a NULL parent
-- is a thread root, otherwise the post replies to another post.
CREATE TABLE newsgroups (
    id              TEXT    PRIMARY KEY,               -- UUID v4
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT    NOT NULL DEFAULT '',
    min_read_class  INTEGER NOT NULL DEFAULT 0,        -- min base class to read
    min_post_class  INTEGER NOT NULL DEFAULT 1,        -- min base class to post
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE news_posts (
    id            TEXT    PRIMARY KEY,                 -- UUID v4
    newsgroup_id  TEXT    NOT NULL REFERENCES newsgroups(id) ON DELETE CASCADE,
    parent_id     TEXT    REFERENCES news_posts(id) ON DELETE CASCADE, -- NULL = thread root
    author        TEXT    NOT NULL,                    -- username
    subject       TEXT    NOT NULL,
    body          TEXT    NOT NULL,
    created_at    INTEGER NOT NULL                     -- unix seconds
);

CREATE INDEX idx_news_posts_group ON news_posts (newsgroup_id, created_at);
