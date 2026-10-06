// Account changes the site makes: linking, merging, unlinking and deletion.

import type { Env } from "./http";
import type { Identity, ProviderName } from "./oauth";

import { randomToken } from "./crypto";
import { tokenHash } from "./auth";

const MERGE_TTL_MS = 10 * 60 * 1000;

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

// Move the signed-in account's keys, runs, names and links into the confirmed account, in one transaction. The
// request must come from the session and account that started it.
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
    env.DB.prepare("UPDATE runs SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE sessions SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE login_links SET account_id = ? WHERE account_id = ?").bind(into, from),
    // The target keeps its own link where both have one for a provider.
    env.DB.prepare("UPDATE OR IGNORE links SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("DELETE FROM links WHERE account_id = ?").bind(from),
    env.DB.prepare("UPDATE links SET handle = ?, avatar_url = ? WHERE provider = ? AND subject = ?")
      .bind(request.handle, request.avatar_url, request.provider, request.subject),
    env.DB.prepare(
      `INSERT INTO names (account_id, name, first_at, last_at) SELECT ?, name, first_at, last_at FROM names WHERE account_id = ?
       ON CONFLICT (account_id, name) DO UPDATE SET first_at = min(first_at, excluded.first_at), last_at = max(last_at, excluded.last_at)`,
    ).bind(into, from),
    env.DB.prepare("DELETE FROM names WHERE account_id = ?").bind(from),
    env.DB.prepare(
      "UPDATE accounts SET name = coalesce((SELECT name FROM runs WHERE account_id = ? ORDER BY accepted_at DESC LIMIT 1), name) WHERE id = ?",
    ).bind(into, into),
    env.DB.prepare("DELETE FROM merge_requests WHERE from_account = ? OR into_account = ?").bind(from, from),
    env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(from),
  ]);
  return into;
}

export async function unlink(env: Env, accountId: number, provider: ProviderName): Promise<void> {
  await env.DB.prepare("DELETE FROM links WHERE account_id = ? AND provider = ?").bind(accountId, provider).run();
}

// Delete an account and everything tied to it: runs and their replay files, names, links, keys and sessions.
export async function deleteAccount(env: Env, accountId: number): Promise<void> {
  const { results } = await env.DB.prepare("SELECT id FROM runs WHERE account_id = ?").bind(accountId).all<{ id: string }>();
  if (results.length) await env.REPLAYS.delete(results.map((run) => `runs/${run.id}.crd`));
  await env.DB.batch(
    ["runs", "names", "links", "keys", "sessions", "login_links"]
      .map((table) => env.DB.prepare(`DELETE FROM ${table} WHERE account_id = ?`).bind(accountId))
      .concat(
        env.DB.prepare("DELETE FROM merge_requests WHERE from_account = ? OR into_account = ?").bind(accountId, accountId),
        env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(accountId),
      ),
  );
}
