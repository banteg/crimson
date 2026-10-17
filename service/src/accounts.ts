// Account changes the site makes: linking, merging, unlinking and deletion.

import type { Env } from "./http";
import type { Identity, ProviderName } from "./oauth";

import { randomToken } from "./crypto";
import { tokenHash } from "./auth";
import { groundKey } from "./ground";
import { timelineKey } from "./runs";
import { accountRun } from "./views";

const MERGE_TTL_MS = 10 * 60 * 1000;
const ROLE_RANK = "CASE role WHEN 'admin' THEN 2 WHEN 'mod' THEN 1 ELSE 0 END";

export type LinkResult = { outcome: "linked" } | { outcome: "confirm"; token: string; into: number };

// Link `identity`, matched by the provider's account ID, to the signed-in account. When another account already
// linked it, nothing changes yet: the player confirms moving this account into that one (`confirmMerge`).
export async function linkIdentity(env: Env, accountId: number, sessionToken: string, provider: ProviderName, identity: Identity): Promise<LinkResult> {
  const owner = await env.DB.prepare("SELECT account_id FROM links WHERE provider = ? AND subject = ?")
    .bind(provider, identity.subject)
    .first<{ account_id: number }>();
  if (owner && owner.account_id !== accountId) {
    const token = randomToken();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM merge_requests WHERE expires_at < ?").bind(Date.now()),
      env.DB.prepare(
        `INSERT INTO merge_requests (token_hash, session_hash, from_account, into_account, provider, subject, handle, avatar_url, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        await tokenHash(token), await tokenHash(sessionToken), accountId, owner.account_id, provider, identity.subject,
        identity.handle, identity.avatar_url, Date.now() + MERGE_TTL_MS,
      ),
    ]);
    return { outcome: "confirm", token, into: owner.account_id };
  }
  await env.DB.batch([
    // One link per provider: a new one replaces the account's earlier link there.
    env.DB.prepare("DELETE FROM links WHERE account_id = ? AND provider = ? AND subject != ?").bind(accountId, provider, identity.subject),
    env.DB.prepare(
      `INSERT INTO links (provider, subject, account_id, handle, avatar_url, linked_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (provider, subject) DO UPDATE SET handle = excluded.handle, avatar_url = excluded.avatar_url`,
    ).bind(provider, identity.subject, accountId, identity.handle, identity.avatar_url, Date.now()),
  ]);
  return { outcome: "linked" };
}

// Move the signed-in account's keys, runs (its co-op seats too), names and links into the confirmed account, in one
// transaction. The request must come from the session and account that started it.
export async function confirmMerge(env: Env, accountId: number, sessionToken: string, token: string): Promise<number | null> {
  const request = await env.DB.prepare(
    `DELETE FROM merge_requests WHERE token_hash = ? AND session_hash = ? AND from_account = ? AND expires_at >= ?
     RETURNING into_account, provider, subject, handle, avatar_url`,
  )
    .bind(await tokenHash(token), await tokenHash(sessionToken), accountId, Date.now())
    .first<{ into_account: number; provider: string; subject: string; handle: string; avatar_url: string | null }>();
  if (!request) return null;
  const from = accountId;
  const into = request.into_account;
  await env.DB.batch([
    env.DB.prepare("UPDATE keys SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE custom_quests SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE runs SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE run_players SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE sessions SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE login_links SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE OR IGNORE links SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("DELETE FROM links WHERE account_id = ?").bind(from),
    env.DB.prepare("UPDATE links SET handle = ?, avatar_url = ? WHERE provider = ? AND subject = ?")
      .bind(request.handle, request.avatar_url, request.provider, request.subject),
    env.DB.prepare(
      `INSERT INTO names (account_id, name, first_at, last_at) SELECT ?, name, first_at, last_at FROM names WHERE account_id = ?
       ON CONFLICT (account_id, name) DO UPDATE SET first_at = min(first_at, excluded.first_at), last_at = max(last_at, excluded.last_at)`,
    ).bind(into, from),
    env.DB.prepare("DELETE FROM names WHERE account_id = ?").bind(from),
    // The name of the account's latest run, from its own seat in a co-op one.
    env.DB.prepare(
      `UPDATE accounts SET name = coalesce((
         SELECT name FROM (
           SELECT r.name, r.accepted_at FROM runs r WHERE r.account_id = ?1 AND NOT EXISTS (SELECT 1 FROM run_players p WHERE p.run_id = r.id)
           UNION ALL SELECT p.name, r.accepted_at FROM run_players p JOIN runs r ON r.id = p.run_id WHERE p.account_id = ?1)
         ORDER BY accepted_at DESC LIMIT 1), name) WHERE id = ?1`,
    ).bind(into),
    // A moderator's bot mark and the stronger role go with the keys (docs/rewrite/bots.md): a merge neither moves a
    // bot's runs to the human boards nor loses a moderator or the admin.
    env.DB.prepare(
      `UPDATE accounts SET bot = (SELECT max(bot) FROM accounts WHERE id IN (?, ?)),
         role = (SELECT role FROM accounts WHERE id IN (?, ?) ORDER BY ${ROLE_RANK} DESC LIMIT 1) WHERE id = ?`,
    ).bind(from, into, from, into, into),
    env.DB.prepare("DELETE FROM merge_requests WHERE from_account = ? OR into_account = ?").bind(from, from),
    env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(from),
  ]);
  return into;
}

export async function unlink(env: Env, accountId: number, provider: ProviderName): Promise<void> {
  await env.DB.prepare("DELETE FROM links WHERE account_id = ? AND provider = ?").bind(accountId, provider).run();
}

// Delete an account and everything tied to it: runs with their replay and timeline files, names, links, keys and
// sessions. A co-op run stays while a partner who has not deleted theirs sits in it (docs/rewrite/leaderboard-identity.md,
// "Co-op runs"): it lists under the partner, and the deleted player's seat loses its key and name but keeps pointing
// at their account, which stays as a bare row with its bot and ban marks (migrations/0008_coop.sql) until its last
// such run goes. The admin's account stays, since only the admin makes moderators; false when it is that one.
export async function deleteAccount(env: Env, accountId: number): Promise<boolean> {
  const account = await env.DB.prepare("SELECT role FROM accounts WHERE id = ?").bind(accountId).first<{ role: string }>();
  if (account?.role === "admin") return false;
  const partner = (run: string) =>
    `EXISTS (SELECT 1 FROM run_players p JOIN accounts pa ON pa.id = p.account_id
             WHERE p.run_id = ${run}.id AND p.account_id != ?1 AND pa.deleted_at IS NULL)`;
  const { results } = await env.DB.prepare(`SELECT id FROM runs WHERE ${accountRun("runs")} AND NOT ${partner("runs")}`)
    .bind(accountId)
    .all<{ id: string }>();
  const gone = JSON.stringify(results.map((run) => run.id));
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE custom_quests SET
         account_id = NULL,
         first_run_id = (SELECT id FROM runs WHERE board = 'quests' AND quest = custom_quests.id AND account_id != ? ORDER BY accepted_at LIMIT 1)
       WHERE (account_id = ? OR first_run_id IN (SELECT id FROM runs WHERE account_id = ?))
         AND EXISTS (SELECT 1 FROM runs WHERE board = 'quests' AND quest = custom_quests.id AND account_id != ?)`,
    ).bind(accountId, accountId, accountId, accountId),
    env.DB.prepare("DELETE FROM custom_quests WHERE account_id = ? OR first_run_id IN (SELECT id FROM runs WHERE account_id = ?)").bind(accountId, accountId),
    // Shared co-op runs listed under the account move to the partner.
    env.DB.prepare(
      `UPDATE runs SET public_key = '', name = '',
         account_id = (SELECT p.account_id FROM run_players p JOIN accounts pa ON pa.id = p.account_id
                       WHERE p.run_id = runs.id AND p.account_id != ?1 AND pa.deleted_at IS NULL ORDER BY p.seat LIMIT 1)
       WHERE account_id = ?1 AND ${partner("runs")}`,
    ).bind(accountId),
    env.DB.prepare("DELETE FROM run_players WHERE run_id IN (SELECT value FROM json_each(?))").bind(gone),
    env.DB.prepare("DELETE FROM runs WHERE id IN (SELECT value FROM json_each(?))").bind(gone),
    env.DB.prepare("UPDATE run_players SET public_key = '', name = '' WHERE account_id = ?").bind(accountId),
    ...["names", "links", "keys", "sessions", "login_links"].map((table) =>
      env.DB.prepare(`DELETE FROM ${table} WHERE account_id = ?`).bind(accountId),
    ),
    env.DB.prepare("DELETE FROM merge_requests WHERE from_account = ? OR into_account = ?").bind(accountId, accountId),
    env.DB.prepare(
      "UPDATE accounts SET name = '', name_hidden = 0, role = '', deleted_at = ?2 WHERE id = ?1 AND EXISTS (SELECT 1 FROM run_players WHERE account_id = ?1)",
    ).bind(accountId, Date.now()),
    // The account, unless a shared run keeps it, and any deleted partner whose last run went with it.
    env.DB.prepare(
      "DELETE FROM accounts WHERE (id = ? OR deleted_at IS NOT NULL) AND NOT EXISTS (SELECT 1 FROM run_players WHERE account_id = accounts.id)",
    ).bind(accountId),
  ]);
  if (results.length) await env.REPLAYS.delete(results.flatMap((run) => [`runs/${run.id}.crd`, timelineKey(run.id), groundKey(run.id)]));
  return true;
}

// The join a session started, for its confirmation page; it stays pending until confirmed.
export async function pendingJoin(env: Env, accountId: number, sessionToken: string, token: string): Promise<{ into: number; provider: string } | null> {
  const request = await env.DB.prepare(
    "SELECT into_account, provider FROM merge_requests WHERE token_hash = ? AND session_hash = ? AND from_account = ? AND expires_at >= ?",
  )
    .bind(await tokenHash(token), await tokenHash(sessionToken), accountId, Date.now())
    .first<{ into_account: number; provider: string }>();
  return request && { into: request.into_account, provider: request.provider };
}
