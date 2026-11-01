// Account changes the site makes: linking, merging, unlinking and deletion.

import type { Env } from "./http";
import type { Identity, ProviderName } from "./oauth";

import { randomToken } from "./crypto";
import { tokenHash } from "./auth";
import { runObjects } from "./runs";
import { accountRun } from "./views";

const MERGE_TTL_MS = 10 * 60 * 1000;
const currentLink = `EXISTS (SELECT 1 FROM links WHERE account_id = merge_requests.into_account
  AND provider = merge_requests.provider AND subject = merge_requests.subject)`;

export type LinkResult = { outcome: "linked" } | { outcome: "confirm"; token: string; into: number };

// Link `identity`, matched by the provider's account ID, to the signed-in account. When another account already
// linked it, nothing changes yet: the player confirms moving this account into that one (`confirmMerge`).
export async function linkIdentity(env: Env, accountId: number, sessionToken: string, provider: ProviderName, identity: Identity): Promise<LinkResult> {
  const token = randomToken();
  const hash = await tokenHash(token);
  const now = Date.now();
  const fresh = "NOT EXISTS (SELECT 1 FROM merge_requests WHERE token_hash = ?)";
  const [, join] = await env.DB.batch<{ into_account: number }>([
    env.DB.prepare("DELETE FROM merge_requests WHERE expires_at < ?").bind(now),
    env.DB.prepare(
      `INSERT INTO merge_requests (token_hash, session_hash, from_account, into_account, provider, subject, handle, avatar_url, expires_at)
       SELECT ?, ?, ?, account_id, provider, subject, ?, ?, ? FROM links
       WHERE provider = ? AND subject = ? AND account_id != ? RETURNING into_account`,
    ).bind(hash, await tokenHash(sessionToken), accountId, identity.handle, identity.avatar_url, now + MERGE_TTL_MS, provider, identity.subject, accountId),
    env.DB.prepare(`DELETE FROM links WHERE account_id = ? AND provider = ? AND subject != ? AND ${fresh}`)
      .bind(accountId, provider, identity.subject, hash),
    env.DB.prepare(
      `INSERT INTO links (provider, subject, account_id, handle, avatar_url, linked_at) SELECT ?, ?, ?, ?, ?, ? WHERE ${fresh}
       ON CONFLICT (provider, subject) DO UPDATE SET handle = excluded.handle, avatar_url = excluded.avatar_url`,
    ).bind(provider, identity.subject, accountId, identity.handle, identity.avatar_url, now, hash),
  ]);
  const target = join!.results[0];
  return target ? { outcome: "confirm", token, into: target.into_account } : { outcome: "linked" };
}

// Move the signed-in account's keys, runs (its co-op seats too), names and links into the confirmed account, in one
// transaction. The request must come from the session and account that started it.
export async function confirmMerge(env: Env, accountId: number, sessionToken: string, token: string): Promise<number | null> {
  const request = await env.DB.prepare(
    `UPDATE merge_requests SET confirmed = 1
     WHERE token_hash = ? AND session_hash = ? AND from_account = ? AND expires_at >= ? AND ${currentLink}
     RETURNING into_account`,
  ).bind(await tokenHash(token), await tokenHash(sessionToken), accountId, Date.now()).first<{ into_account: number }>();
  return request?.into_account ?? null;
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
  const [, , , removed] = await env.DB.batch<{ storage: string }>([
    // Transfer shared runs first, so a custom quest's surviving co-op clear
    // can also continue to back its page after the owner leaves.
    env.DB.prepare(
      `UPDATE runs SET public_key = '', name = '',
         account_id = (SELECT p.account_id FROM run_players p JOIN accounts pa ON pa.id = p.account_id
                       WHERE p.run_id = runs.id AND p.account_id != ?1 AND pa.deleted_at IS NULL ORDER BY p.seat LIMIT 1)
       WHERE account_id = ?1 AND ${partner("runs")}`,
    ).bind(accountId),
    env.DB.prepare(
      `UPDATE custom_quests SET
         account_id = NULL,
         first_run_id = (SELECT id FROM runs WHERE board = 'quests' AND quest = custom_quests.id AND account_id != ? ORDER BY accepted_at LIMIT 1)
       WHERE (account_id = ? OR first_run_id IN (SELECT id FROM runs WHERE account_id = ?))
         AND EXISTS (SELECT 1 FROM runs WHERE board = 'quests' AND quest = custom_quests.id AND account_id != ?)`,
    ).bind(accountId, accountId, accountId, accountId),
    env.DB.prepare("DELETE FROM custom_quests WHERE account_id = ? OR first_run_id IN (SELECT id FROM runs WHERE account_id = ?)").bind(accountId, accountId),
    // The deletion's transaction also removes the seats and records its R2
    // cleanup. RETURNING names the exact generation deleted, including legacy
    // public-id prefixes. No read outside the transaction selects its victims.
    env.DB.prepare(`DELETE FROM runs WHERE ${accountRun("runs")} AND NOT ${partner("runs")}
      RETURNING coalesce(storage_id, id) AS storage`).bind(accountId),
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
  // The deletion has committed. A transient bucket error leaves a durable
  // cleanup request and must not make the player repeat an expired session.
  await cleanDeletedRunFiles(env, removed!.results.map(row => row.storage)).catch(error =>
    console.error("Run file deletion will be retried", error));
  return true;
}

export async function cleanDeletedRunFiles(env: Env, deleted?: string[]): Promise<void> {
  if (!deleted) {
    await env.DB.prepare(`DELETE FROM staged_run_files WHERE storage IN (
      SELECT storage FROM staged_run_files WHERE expires_at <= ? ORDER BY expires_at LIMIT 300)`).bind(Date.now()).run();
  }
  const query = `SELECT q.id, q.storage, EXISTS (SELECT 1 FROM runs r WHERE
    r.storage_id = q.storage OR (r.storage_id IS NULL AND r.id = q.storage)) AS owned FROM deleted_run_files q`;
  for (let start = 0; start < (deleted?.length ?? 1); start += 300) {
    // Old Workers used a public id for every acceptance. Keep a prefix if it
    // is referenced again while cleanup is waiting.
    const work = deleted
      ? env.DB.prepare(query + " WHERE q.storage IN (SELECT value FROM json_each(?))").bind(JSON.stringify(deleted.slice(start, start + 300)))
      : env.DB.prepare(query + " ORDER BY q.id LIMIT 300");
    const { results } = await work.all<{id: number; storage: string; owned: number}>();
    if (!results.length) continue;
    const objects = results.filter(row => !row.owned).flatMap(row => runObjects(row.storage));
    if (objects.length) await env.REPLAYS.delete(objects);
    // A late derived-file write can enqueue a fresh request for the same prefix.
    await env.DB.prepare("DELETE FROM deleted_run_files WHERE id IN (SELECT value FROM json_each(?))")
      .bind(JSON.stringify(results.map(row => row.id))).run();
  }
}

// The join a session started, for its confirmation page; it stays pending until confirmed.
export async function pendingJoin(env: Env, accountId: number, sessionToken: string, token: string): Promise<{ into: number; provider: string } | null> {
  const request = await env.DB.prepare(
    `SELECT into_account, provider FROM merge_requests WHERE token_hash = ? AND session_hash = ? AND from_account = ? AND expires_at >= ? AND ${currentLink}`,
  )
    .bind(await tokenHash(token), await tokenHash(sessionToken), accountId, Date.now())
    .first<{ into_account: number; provider: string }>();
  return request && { into: request.into_account, provider: request.provider };
}
