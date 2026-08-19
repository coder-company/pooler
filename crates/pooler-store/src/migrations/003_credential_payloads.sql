CREATE TABLE IF NOT EXISTS credential_payloads (
    credential_id TEXT PRIMARY KEY NOT NULL
        REFERENCES credentials (credential_id) ON DELETE CASCADE,
    envelope BLOB NOT NULL CHECK (length(envelope) > 0),
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS credential_payloads_updated_at
    ON credential_payloads (updated_at);
