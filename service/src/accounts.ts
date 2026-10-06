// Account changes the site makes: linking, merging, unlinking and deletion.

import type { Env } from "./http";
import type { Identity, ProviderName } from "./oauth";

export type LinkOutcome = "linked" | "merged";

// Link `identity` to the signed-in account. When it is already linked to another account, signing in with it
// proves both accounts are the player's: this account's keys, runs and names move into that one.
export async function linkIdentity(env: Env, accountId: number, provider: ProviderName, identity: Identity): Promise<{ outcome: LinkOutcome; accountId: number }> {
  const now = Date.now();
  const owner = await env.DB.prepare("SELECT account_id FROM links WHERE provider = ? AND subject = ?")
    .bind(provider, identity.subject)
    .first<{ account_id: number }>();
  if (owner && owner.account_id !== accountId) {
    await mergeAccounts(env, accountId, owner.account_id);
    await refreshLink(env, provider, identity);
    return { outcome: "merged", accountId: owner.account_id };
  }
  await env.DB.batch([
    // One link per provider: a new one replaces the account's earlier link there.
    env.DB.prepare("DELETE FROM links WHERE account_id = ? AND provider = ? AND subject != ?").bind(accountId, provider, identity.subject),
    env.DB.prepare(
      `INSERT INTO links (provider, subject, account_id, handle, avatar_url, linked_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (provider, subject) DO UPDATE SET handle = excluded.handle, avatar_url = excluded.avatar_url`,
    ).bind(provider, identity.subject, accountId, identity.handle, identity.avatar_url, now),
  ]);
  return { outcome: "linked", accountId };
}

function refreshLink(env: Env, provider: ProviderName, identity: Identity) {
  return env.DB.prepare("UPDATE links SET handle = ?, avatar_url = ? WHERE provider = ? AND subject = ?")
    .bind(identity.handle, identity.avatar_url, provider, identity.subject)
    .run();
}

async function mergeAccounts(env: Env, from: number, into: number): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("UPDATE keys SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE runs SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE sessions SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("UPDATE login_links SET account_id = ? WHERE account_id = ?").bind(into, from),
    // The target keeps its own link where both have one for a provider.
    env.DB.prepare("UPDATE OR IGNORE links SET account_id = ? WHERE account_id = ?").bind(into, from),
    env.DB.prepare("DELETE FROM links WHERE account_id = ?").bind(from),
    env.DB.prepare(
      `INSERT INTO names (account_id, name, first_at, last_at) SELECT ?, name, first_at, last_at FROM names WHERE account_id = ?
       ON CONFLICT (account_id, name) DO UPDATE SET first_at = min(first_at, excluded.first_at), last_at = max(last_at, excluded.last_at)`,
    ).bind(into, from),
    env.DB.prepare("DELETE FROM names WHERE account_id = ?").bind(from),
    env.DB.prepare(
      "UPDATE accounts SET name = coalesce((SELECT name FROM runs WHERE account_id = ? ORDER BY accepted_at DESC LIMIT 1), name) WHERE id = ?",
    ).bind(into, into),
    env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(from),
  ]);
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
      .concat(env.DB.prepare("DELETE FROM accounts WHERE id = ?").bind(accountId)),
  );
}
