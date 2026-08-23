-- Request identifiers remain inside the encrypted envelope. These keyed
-- metadata columns let SQLite retain and read one timeline without scanning
-- or decrypting unrelated events.
ALTER TABLE request_events ADD COLUMN request_index BLOB;
ALTER TABLE request_events ADD COLUMN event_index INTEGER;

CREATE INDEX request_events_request_index
    ON request_events(request_index, event_index, id);
