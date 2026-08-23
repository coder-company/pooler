-- The key identifier is durable metadata used to fence stale encrypted-store
-- instances after a master-key rotation. The identifier is not secret.
CREATE TABLE IF NOT EXISTS encryption_fence (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key_id BLOB CHECK (key_id IS NULL OR length(key_id) = 16)
);

INSERT OR IGNORE INTO encryption_fence (id, key_id)
VALUES (1, NULL);
