-- Version-2 identity and durable control-plane state.
-- Version-1 encrypted payloads remain adoptable: an empty fingerprint marks
-- legacy metadata and keeps the version-1 credential AAD until an explicit
-- fingerprint adoption transaction re-encrypts the payload.
ALTER TABLE credentials ADD COLUMN configuration_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE decisions ADD COLUMN target_binding_id TEXT;
ALTER TABLE decisions ADD COLUMN priority_tier INTEGER;

-- The old affinity key was not scoped by route/model/pool/binding and cannot
-- be safely restored. Purge it during the one-shot migration before exposing
-- the new composite namespace.
DELETE FROM affinities;

CREATE TABLE IF NOT EXISTS scoped_affinities (
    key TEXT NOT NULL,
    route_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    logical_model TEXT NOT NULL,
    account_pool_id TEXT NOT NULL,
    target_binding_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    credential_id TEXT NOT NULL
        REFERENCES credentials (credential_id) ON DELETE CASCADE,
    upstream_model TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (
        key, route_id, policy_id, logical_model, account_pool_id,
        target_binding_id
    )
);

CREATE INDEX IF NOT EXISTS scoped_affinities_expiry_idx
    ON scoped_affinities (expires_at, last_used_at);

CREATE TABLE IF NOT EXISTS managed_secrets (
    secret_id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER,
    envelope BLOB NOT NULL CHECK (length(envelope) > 0)
);

CREATE INDEX IF NOT EXISTS managed_secrets_updated_idx
    ON managed_secrets (updated_at, secret_id);

CREATE TABLE IF NOT EXISTS management_sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    actor_id TEXT NOT NULL,
    cookie_hash BLOB NOT NULL CHECK (length(cookie_hash) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS management_sessions_cookie_hash_idx
    ON management_sessions (cookie_hash);
CREATE INDEX IF NOT EXISTS management_sessions_expiry_idx
    ON management_sessions (expires_at, session_id);

CREATE TABLE IF NOT EXISTS management_drafts (
    draft_id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    etag TEXT NOT NULL,
    base_generation INTEGER NOT NULL CHECK (base_generation >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    envelope BLOB NOT NULL CHECK (length(envelope) > 0)
);

CREATE INDEX IF NOT EXISTS management_drafts_owner_idx
    ON management_drafts (owner_id, updated_at, draft_id);

CREATE TABLE IF NOT EXISTS management_audit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    outcome TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    error_code TEXT,
    recorded_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS management_audit_recorded_idx
    ON management_audit_records (recorded_at, id);

CREATE TABLE IF NOT EXISTS management_reload_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id TEXT,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    status TEXT NOT NULL,
    etag TEXT,
    error_code TEXT,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0)
);

CREATE INDEX IF NOT EXISTS management_reload_started_idx
    ON management_reload_records (started_at, id);

CREATE TABLE IF NOT EXISTS oauth_flows (
    flow_id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    flow_kind TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed', 'cancelled')),
    state_hash BLOB NOT NULL CHECK (length(state_hash) = 32),
    pkce_envelope BLOB,
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state_consumed_at INTEGER,
    completed_at INTEGER,
    error_code TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS oauth_flows_active_account_idx
    ON oauth_flows (provider_id, account_id)
    WHERE status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS oauth_flows_state_hash_idx
    ON oauth_flows (state_hash);
CREATE INDEX IF NOT EXISTS oauth_flows_expiry_idx
    ON oauth_flows (expires_at, flow_id);
