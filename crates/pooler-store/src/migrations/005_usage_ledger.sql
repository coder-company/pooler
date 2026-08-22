CREATE TABLE usage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at INTEGER NOT NULL,
    envelope BLOB NOT NULL
);

CREATE INDEX usage_records_recorded_at_idx
    ON usage_records(recorded_at, id);
