-- The bot category and moderator roles (docs/rewrite/bots.md).
-- A moderator marks an account as a bot: its runs list on the bot boards.
ALTER TABLE accounts ADD COLUMN bot INTEGER NOT NULL DEFAULT 0;
-- '', 'mod' or 'admin'.
ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT '';
-- The replay's pilot as JSON, '' when it declares none.
ALTER TABLE runs ADD COLUMN pilot TEXT NOT NULL DEFAULT '';
-- A moderator's category for the run, 'human' or 'bot'; NULL follows the pilot and the account.
ALTER TABLE runs ADD COLUMN category TEXT;
-- The verifier's input signals as JSON, NULL until measured.
ALTER TABLE runs ADD COLUMN signals TEXT;
UPDATE accounts SET role = 'admin' WHERE id = 1;
