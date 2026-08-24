ALTER TABLE management_reload_records
    ADD COLUMN completed_generation INTEGER CHECK (completed_generation >= 0);
