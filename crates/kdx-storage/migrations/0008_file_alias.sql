-- File aliases: a node kind that transparently resolves to another node,
-- so a folder can carry a "pointer" entry that behaves like the target
-- when read/downloaded. Structural rules (semantics live in
-- kdx-server-core::files::tree):
--
--   * kind = 4 designates an alias row.
--   * target_id is the UUID of the pointed-to node — nullable in the
--     schema so pre-existing rows keep validating, but MUST be non-NULL
--     for kind=4 (enforced by the CHECK below).
--   * ON DELETE SET NULL means: when the *target* is deleted, the alias
--     survives as a dangling row that resolves to "not found" at
--     runtime — we don't cascade-delete the alias because a user's own
--     directory shouldn't quietly lose entries when someone else
--     removes something elsewhere in the tree. Cleanup can happen in
--     the admin UI.
--   * No target_id on non-alias rows.
ALTER TABLE file_nodes ADD COLUMN target_id TEXT
    REFERENCES file_nodes(id) ON DELETE SET NULL;

-- SQLite doesn't allow adding a CHECK constraint via ALTER TABLE, so
-- enforcement of "alias rows must have a target, non-alias rows must
-- not" lives in the domain layer (kdx-server-core::files::tree). Any
-- direct storage-layer writes are wrong; go through the domain API.

CREATE INDEX idx_file_nodes_target_id ON file_nodes (target_id);
