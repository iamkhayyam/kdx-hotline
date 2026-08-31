-- P1-4: optional owner login on a folder (dropboxes: owner may read/delete).
-- Folder access items themselves ([db]/[ul]/[default] name suffixes) derive
-- from the node's name at load, so no column is needed for them.
ALTER TABLE file_nodes ADD COLUMN owner TEXT;
