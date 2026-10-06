// Shared request plumbing: the bindings, JSON answers and accounts.

import { fingerprint } from "./crypto";

export interface Env {
  DB: D1Database;
  REPLAYS: R2Bucket;
  // The site (web/, built into dist/).
  ASSETS: Fetcher;
  // OAuth apps for account linking; a provider shows only with both its ID and secret.
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  DISCORD_CLIENT_ID?: string;
  DISCORD_CLIENT_SECRET?: string;
  X_CLIENT_ID?: string;
  X_CLIENT_SECRET?: string;
}

export function json(body: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(body, { status, headers });
}

// The game moves a run refused with a 4xx out of its outbox and keeps the reason (src/crimson/leaderboard/client.py).
export function refuse(status: number, reason: string): Response {
  return json({ reason }, status);
}

// The account a key belongs to; a key the service has not seen starts its own.
export async function accountForKey(env: Env, publicKeyHex: string, publicKey: Uint8Array, now: number): Promise<number> {
  const known = await env.DB.prepare("SELECT account_id FROM keys WHERE public_key = ?").bind(publicKeyHex).first<{ account_id: number }>();
  if (known) return known.account_id;
  const account = await env.DB.prepare("INSERT INTO accounts (created_at) VALUES (?) RETURNING id").bind(now).first<{ id: number }>();
  await env.DB.prepare("INSERT INTO keys (public_key, account_id, fingerprint, added_at) VALUES (?, ?, ?, ?)")
    .bind(publicKeyHex, account!.id, await fingerprint(publicKey), now)
    .run();
  return account!.id;
}
