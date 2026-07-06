-- Server History: an append-only audit log of admin-relevant events (logins,
-- kicks/bans, account/role/newsgroup mutations, settings changes, broadcasts,
-- shutdown). `actor` is the username responsible (NULL for events with no
-- single responsible user, though in practice every recorded event has one).
CREATE TABLE history (
    id          TEXT    PRIMARY KEY,               -- UUID v4
    timestamp   INTEGER NOT NULL,                  -- unix seconds
    actor       TEXT,
    action      TEXT    NOT NULL,                  -- short machine-readable kind, e.g. "login", "kicked"
    detail      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_history_timestamp ON history (timestamp);
