-- Published custom quests, each backed by a verified completion replay.
CREATE TABLE custom_quests (
  id TEXT PRIMARY KEY,
  digest TEXT NOT NULL UNIQUE,
  account_id INTEGER REFERENCES accounts (id),
  first_run_id TEXT NOT NULL REFERENCES runs (id),
  title TEXT NOT NULL,
  author TEXT,
  source TEXT,
  seed INTEGER NOT NULL DEFAULT 0,
  definition TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX custom_quests_created ON custom_quests (created_at DESC);
