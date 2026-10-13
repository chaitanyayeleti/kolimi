-- Bind the CSRF double-submit token to its session: store the hash of the
-- token that was issued with the session, so a forged/planted cookie value
-- alone is not enough.
ALTER TABLE sessions ADD COLUMN csrf_hash BLOB;
