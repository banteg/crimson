-- Removing or replacing a provider link revokes every join it authorized, even if the same
-- provider identity is linked again before an old confirmation page is submitted.
CREATE TRIGGER revoke_link_joins AFTER DELETE ON links BEGIN
  DELETE FROM merge_requests WHERE into_account = OLD.account_id
    AND provider = OLD.provider AND subject = OLD.subject;
END;

-- The Worker confirms a request with a conditional UPDATE that checks the session, expiry and
-- current provider ownership. All moves happen inside that same statement and the request is
-- consumed. A concurrent unlink or replacement can only run before or after the entire merge.
ALTER TABLE merge_requests ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0;
CREATE TRIGGER merge_confirmed_accounts AFTER UPDATE OF confirmed ON merge_requests
WHEN NEW.confirmed = 1 BEGIN
  UPDATE keys SET account_id = NEW.into_account WHERE account_id = NEW.from_account;
  UPDATE custom_quests SET account_id = NEW.into_account WHERE account_id = NEW.from_account;
  UPDATE runs SET account_id = NEW.into_account WHERE account_id = NEW.from_account;
  UPDATE run_players SET account_id = NEW.into_account WHERE account_id = NEW.from_account;
  UPDATE sessions SET account_id = NEW.into_account WHERE account_id = NEW.from_account;
  UPDATE login_links SET account_id = NEW.into_account WHERE account_id = NEW.from_account;
  UPDATE OR IGNORE links SET account_id = NEW.into_account WHERE account_id = NEW.from_account;
  DELETE FROM links WHERE account_id = NEW.from_account;
  UPDATE links SET handle = NEW.handle, avatar_url = NEW.avatar_url
    WHERE provider = NEW.provider AND subject = NEW.subject AND account_id = NEW.into_account;
  INSERT INTO names (account_id, name, first_at, last_at)
    SELECT NEW.into_account, name, first_at, last_at FROM names WHERE account_id = NEW.from_account
    ON CONFLICT (account_id, name) DO UPDATE SET first_at = min(first_at, excluded.first_at), last_at = max(last_at, excluded.last_at);
  DELETE FROM names WHERE account_id = NEW.from_account;

  -- Keep the latest seat name, bot mark and stronger moderator role.
  UPDATE accounts SET name = coalesce((
    SELECT name FROM (
      SELECT r.name, r.accepted_at FROM runs r WHERE r.account_id = NEW.into_account AND NOT EXISTS (SELECT 1 FROM run_players p WHERE p.run_id = r.id)
      UNION ALL SELECT p.name, r.accepted_at FROM run_players p JOIN runs r ON r.id = p.run_id WHERE p.account_id = NEW.into_account)
    ORDER BY accepted_at DESC LIMIT 1), name),
    bot = (SELECT max(bot) FROM accounts WHERE id IN (NEW.from_account, NEW.into_account)),
    role = (SELECT role FROM accounts WHERE id IN (NEW.from_account, NEW.into_account)
      ORDER BY CASE role WHEN 'admin' THEN 2 WHEN 'mod' THEN 1 ELSE 0 END DESC LIMIT 1)
    WHERE id = NEW.into_account;
  DELETE FROM merge_requests WHERE from_account = NEW.from_account OR into_account = NEW.from_account;
  DELETE FROM accounts WHERE id = NEW.from_account;
END;
