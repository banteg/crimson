-- Old runs live under their public id. Each new upload stages its own three R2 objects
-- before a D1 INSERT atomically publishes the winning object's prefix to readers.
ALTER TABLE runs ADD COLUMN storage_id TEXT;
CREATE UNIQUE INDEX runs_storage_id ON runs(storage_id) WHERE storage_id IS NOT NULL;

-- A committed deletion records exactly which bucket prefix disappeared. The
-- existing hourly maintenance retries failures after the player's session ends.
CREATE TABLE deleted_run_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  storage TEXT NOT NULL UNIQUE
);
CREATE TRIGGER remove_run_seats BEFORE DELETE ON runs BEGIN
  DELETE FROM run_players WHERE run_id = OLD.id;
END;
CREATE TRIGGER queue_run_files AFTER DELETE ON runs BEGIN
  INSERT OR REPLACE INTO deleted_run_files(storage) VALUES (coalesce(OLD.storage_id, OLD.id));
END;

-- A crash between the first R2 write and publication leaves a durable lease. Expiring it
-- queues only an unowned prefix. A late writer cannot publish after losing its lease.
CREATE TABLE staged_run_files (storage TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);
CREATE INDEX staged_run_expiry ON staged_run_files(expires_at);
CREATE TRIGGER release_staged_files AFTER DELETE ON staged_run_files
WHEN NOT EXISTS (SELECT 1 FROM runs WHERE storage_id = OLD.storage) BEGIN
  INSERT OR REPLACE INTO deleted_run_files(storage) VALUES (OLD.storage);
END;
