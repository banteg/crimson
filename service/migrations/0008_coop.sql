-- A co-op run's players, one row per seat, player one (seat 0) first (docs/rewrite/leaderboard-identity.md, "Co-op
-- runs"). runs keeps seat 0's account, key and name in its own columns, as for a one-player run, which has no rows
-- here. When a player deletes their account, a run shared with a partner stays: the seat keeps its row with the
-- account, key and name cleared, and runs.account_id, which a run lists under, moves to the partner.
CREATE TABLE run_players (
  run_id TEXT NOT NULL REFERENCES runs (id),
  seat INTEGER NOT NULL,
  account_id INTEGER REFERENCES accounts (id),
  public_key TEXT NOT NULL,
  name TEXT NOT NULL,
  PRIMARY KEY (run_id, seat)
);
CREATE INDEX run_players_account ON run_players (account_id);
