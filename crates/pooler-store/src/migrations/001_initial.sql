CREATE TABLE IF NOT EXISTS credentials (
    credential_id TEXT PRIMARY KEY NOT NULL,
    provider_id TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    updated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
);

CREATE TABLE IF NOT EXISTS affinities (
    key TEXT PRIMARY KEY NOT NULL,
    provider_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    upstream_model TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    route_id TEXT NOT NULL,
    model TEXT NOT NULL,
    candidates_json TEXT NOT NULL,
    selected_provider TEXT,
    selected_credential TEXT,
    upstream_model TEXT,
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    configuration_generation INTEGER NOT NULL CHECK (configuration_generation >= 0),
    reason TEXT,
    recorded_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS decisions_recorded_at_idx
    ON decisions (recorded_at, id);
