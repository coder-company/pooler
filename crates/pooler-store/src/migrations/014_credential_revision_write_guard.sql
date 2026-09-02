-- Already-open pre-v11 writers allocate credential revisions per row. After
-- deletion they can therefore recreate an old revision and let an in-flight
-- payload CAS mistake a new credential incarnation for the original one.
-- Require every insert or update to consume a revision allocated by the
-- singleton clock in the same transaction. Legacy writers cannot arm this
-- guard and fail closed; deletion remains safe because it cannot resurrect a
-- stale payload without a guarded recreation.
CREATE TABLE credential_revision_write_guard (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    revision INTEGER CHECK (revision IS NULL OR revision > 0)
);

INSERT INTO credential_revision_write_guard (singleton, revision)
VALUES (1, NULL);

CREATE TRIGGER credentials_require_revision_guard_insert
BEFORE INSERT ON credentials
WHEN NOT EXISTS (
    SELECT 1 FROM credential_revision_write_guard
    WHERE singleton = 1 AND revision = NEW.revision
)
BEGIN
    SELECT RAISE(ABORT, 'credential revision was not allocated');
END;

CREATE TRIGGER credentials_require_revision_guard_update
BEFORE UPDATE ON credentials
WHEN NOT EXISTS (
    SELECT 1 FROM credential_revision_write_guard
    WHERE singleton = 1 AND revision = NEW.revision
)
BEGIN
    SELECT RAISE(ABORT, 'credential revision was not allocated');
END;

CREATE TRIGGER credentials_clear_revision_guard_insert
AFTER INSERT ON credentials
BEGIN
    UPDATE credential_revision_write_guard SET revision = NULL
    WHERE singleton = 1 AND revision = NEW.revision;
END;

CREATE TRIGGER credentials_clear_revision_guard_update
AFTER UPDATE ON credentials
BEGIN
    UPDATE credential_revision_write_guard SET revision = NULL
    WHERE singleton = 1 AND revision = NEW.revision;
END;
