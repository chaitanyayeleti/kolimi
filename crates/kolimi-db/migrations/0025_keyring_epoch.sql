-- Optimistic concurrency and rollback protection for the account keyring.
--
-- The keyring already carries a client-side epoch and MAC; storing the epoch
-- lets the server reject a replace that would move backwards (for example a
-- replay of an old keyring after a passphrase rotation).
ALTER TABLE e2ee_keyrings ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;

-- Existing rows predate the column: recover the epoch already sealed inside
-- the keyring JSON, so the first rotation does not mistake a tagged keyring
-- for an epoch-0 legacy one.
UPDATE e2ee_keyrings
SET epoch = COALESCE(CAST(json_extract(keyring, '$.epoch') AS INTEGER), 0)
WHERE epoch = 0;
