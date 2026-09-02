-- Token rotation has a generation distinct from general credential metadata.
-- Rebuild the table without a generation default so an already-open pre-v12
-- writer cannot insert a payload while silently omitting the new fence.
ALTER TABLE credential_payloads RENAME TO credential_payloads_v11;

CREATE TABLE credential_payloads (
    credential_id TEXT PRIMARY KEY NOT NULL
        REFERENCES credentials (credential_id) ON DELETE CASCADE,
    envelope BLOB NOT NULL CHECK (length(envelope) > 0),
    updated_at INTEGER NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0)
);

INSERT INTO credential_payloads (credential_id, envelope, updated_at, generation)
SELECT payload.credential_id, payload.envelope, payload.updated_at, credential.revision
FROM credential_payloads_v11 AS payload
JOIN credentials AS credential
  ON credential.credential_id = payload.credential_id;

DROP TABLE credential_payloads_v11;

CREATE INDEX credential_payloads_updated_at
    ON credential_payloads (updated_at);

-- A pre-v12 writer that was already connected during this migration still
-- uses an envelope-only UPSERT. Reject that write instead of allowing it to
-- change token material while preserving a stale generation. Current writers
-- must advance generation whenever they replace an envelope.
CREATE TRIGGER credential_payloads_require_generation_advance
BEFORE UPDATE OF envelope ON credential_payloads
WHEN NEW.generation <= OLD.generation
BEGIN
    SELECT RAISE(ABORT, 'credential payload generation must advance');
END;
