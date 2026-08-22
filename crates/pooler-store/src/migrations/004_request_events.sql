CREATE TABLE request_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recorded_at INTEGER NOT NULL,
    envelope BLOB NOT NULL
);

CREATE INDEX request_events_recorded_at_id
    ON request_events(recorded_at, id);
