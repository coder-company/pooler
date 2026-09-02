-- Re-encrypting an unchanged OAuth payload must not masquerade as a token
-- refresh or login. Keep the semantic generation stable during master-key
-- rotation while preserving migration 012's fail-closed fence for already-open
-- generation-unaware writers.
CREATE TABLE credential_payload_reencryption_guard (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    active INTEGER NOT NULL CHECK (active IN (0, 1))
);

INSERT INTO credential_payload_reencryption_guard (singleton, active)
VALUES (1, 0);

DROP TRIGGER credential_payloads_require_generation_advance;

CREATE TRIGGER credential_payloads_require_generation_advance
BEFORE UPDATE OF envelope ON credential_payloads
WHEN NEW.generation <= OLD.generation
 AND NOT EXISTS (
     SELECT 1 FROM credential_payload_reencryption_guard
     WHERE singleton = 1 AND active = 1
 )
BEGIN
    SELECT RAISE(ABORT, 'credential payload generation must advance');
END;
