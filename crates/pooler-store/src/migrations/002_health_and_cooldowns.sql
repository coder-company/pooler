CREATE TABLE IF NOT EXISTS credential_health (
    credential_id TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('healthy', 'cooling_down', 'disabled')),
    failure_count INTEGER NOT NULL CHECK (failure_count >= 0),
    cooldown_until INTEGER,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cooldowns (
    scope TEXT NOT NULL,
    scope_key TEXT NOT NULL,
    until_at INTEGER NOT NULL,
    reason TEXT,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (scope, scope_key)
);

CREATE INDEX IF NOT EXISTS cooldowns_until_idx
    ON cooldowns (until_at);
