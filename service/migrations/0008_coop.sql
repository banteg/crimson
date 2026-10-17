-- A co-op run's players, one row per seat, player one (seat 0) first (docs/rewrite/leaderboard-identity.md, "Co-op
-- runs"). runs keeps seat 0's account, key and name in its own columns, as for a one-player run, which has no rows
-- here. When a player deletes their account, a run shared with a partner stays: the seat keeps its account, with its
-- key and name cleared, and runs.account_id, which a run lists under, moves to the partner.
CREATE TABLE run_players (
  run_id TEXT NOT NULL REFERENCES runs (id),
  seat INTEGER NOT NULL,
  account_id INTEGER NOT NULL REFERENCES accounts (id),
  public_key TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (run_id, seat)
);
CREATE INDEX run_players_account ON run_players (account_id);

-- When a deleted account's player shares co-op runs, their seats keep pointing at the account, which stays as a bare
-- row: no name, keys, links, names or sessions, but its id, so a partner's runs with different players stay
-- different pairs, and its bot and ban marks, so deleting an account never lifts a moderator's decision. It goes with
-- the last run it sits in.
ALTER TABLE accounts ADD COLUMN deleted_at INTEGER;

-- The seeds co-op rooms gave their pairs (docs/rewrite/leaderboard-identity.md, "Co-op runs"): a room issues a seed
-- only once both seats have proven their keys, so a two-player upload ranks only when its seed was issued to the keys
-- its replay records, in seat order. Anyone holding the replay could rewrite those keys; nobody can rewrite this.
CREATE TABLE coop_runs (
  seed INTEGER PRIMARY KEY,
  room_id TEXT NOT NULL,
  seat0_key TEXT NOT NULL,
  seat1_key TEXT NOT NULL,
  issued_at INTEGER NOT NULL
);
