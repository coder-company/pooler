-- Preserve credential generations across metadata deletion and recreation
-- without retaining one tombstone row per historical credential ID. All
-- credential mutations draw from this single monotonically increasing clock.
CREATE TABLE credential_revision_clock (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0)
);

INSERT INTO credential_revision_clock (singleton, revision)
SELECT 1, COALESCE(MAX(revision), 0) FROM credentials;

-- Identify the transactional SQLite generation domain independently of the
-- spelling of its filesystem path. This also distinguishes a replacement
-- database opened later at the same pathname.
CREATE TABLE store_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    identity BLOB NOT NULL CHECK (length(identity) = 16)
);

INSERT INTO store_identity (singleton, identity)
VALUES (1, randomblob(16));
