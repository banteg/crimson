-- Accounts are sets of keys; a key that signs its first upload or login starts one (docs/rewrite/leaderboard-identity.md).
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY,
  created_at INTEGER NOT NULL,
  -- The name of the account's latest accepted run.
  name TEXT NOT NULL DEFAULT '',
  name_hidden INTEGER NOT NULL DEFAULT 0,
  banned INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE keys (
  public_key TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  fingerprint TEXT NOT NULL,
  added_at INTEGER NOT NULL,
  banned INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX keys_account ON keys (account_id);

-- A linked GitHub, Discord or X account: its id, handle and avatar, never its tokens. One per provider.
CREATE TABLE links (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  handle TEXT NOT NULL,
  avatar_url TEXT,
  linked_at INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);
CREATE UNIQUE INDEX links_account ON links (account_id, provider);

CREATE TABLE names (
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  name TEXT NOT NULL,
  first_at INTEGER NOT NULL,
  last_at INTEGER NOT NULL,
  PRIMARY KEY (account_id, name)
);

CREATE TABLE runs (
  -- SHA-256 of the run's core input stream: the same run whatever bytes encode it.
  id TEXT PRIMARY KEY,
  payload_sha256 TEXT NOT NULL,
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  public_key TEXT NOT NULL,
  name TEXT NOT NULL,
  board TEXT NOT NULL,
  -- "major.minor" for quests, empty for Survival.
  quest TEXT NOT NULL DEFAULT '',
  score INTEGER NOT NULL,
  game_version TEXT NOT NULL,
  ticks INTEGER NOT NULL,
  result TEXT NOT NULL,
  accepted_at INTEGER NOT NULL,
  hidden INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX runs_board ON runs (board, quest, score, accepted_at);
CREATE INDEX runs_account ON runs (account_id, accepted_at);

CREATE TABLE challenges (
  challenge TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE login_links (
  token_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  expires_at INTEGER NOT NULL
);

-- An OAuth sign-in in flight, bound to the site session that started it.
CREATE TABLE oauth_states (
  state_hash TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL,
  provider TEXT NOT NULL,
  code_verifier TEXT,
  expires_at INTEGER NOT NULL
);

CREATE TABLE moderation_log (
  id INTEGER PRIMARY KEY,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);
