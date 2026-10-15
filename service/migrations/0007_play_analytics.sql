-- Short-lived random browser/day tokens, never keys, accounts or event histories.
CREATE TABLE play_uniques (
  day TEXT NOT NULL,
  token TEXT NOT NULL,
  PRIMARY KEY (day, token)
) WITHOUT ROWID;

CREATE TABLE play_totals (
  day TEXT NOT NULL,
  mode TEXT NOT NULL,
  unique_browsers INTEGER NOT NULL DEFAULT 0,
  ready INTEGER NOT NULL DEFAULT 0,
  sessions INTEGER NOT NULL DEFAULT 0,
  engaged INTEGER NOT NULL DEFAULT 0,
  runs INTEGER NOT NULL DEFAULT 0,
  active_seconds INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, mode)
) WITHOUT ROWID;

-- Deduplication and counting commit together, including concurrent retries.
CREATE TRIGGER count_play_unique AFTER INSERT ON play_uniques BEGIN
  INSERT INTO play_totals (day, mode, unique_browsers) VALUES (NEW.day, 'all', 1)
  ON CONFLICT (day, mode) DO UPDATE SET unique_browsers = unique_browsers + 1;
END;
