-- Per-folder encryption policy (RFC 0009 / decision 0001 option B).
--
-- A folder marked encrypted declares that everything beneath it is
-- client-side encrypted. The server stores only the flag (metadata it can
-- already infer from ciphertext); it never holds keys. Clients use the
-- flag to decide whether to encrypt before upload, and the server uses it
-- to refuse plaintext writes into the subtree.
ALTER TABLE nodes ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0;

-- Finding a folder's flag while walking a path is the hot lookup.
CREATE INDEX nodes_encrypted ON nodes(user_id, id) WHERE encrypted = 1;
