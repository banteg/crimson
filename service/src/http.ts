// Shared request plumbing: the bindings, JSON answers and accounts.

import type { CoopRoom } from "./coop";
import { fingerprint } from "./crypto";

export interface Env {
  DB: D1Database;
  REPLAYS: R2Bucket;
  // The game's files as the project distributes them, for the playable game.
  GAME_FILES: R2Bucket;
  // The site (web/, built into dist/).
  ASSETS: Fetcher;
  // Shared ingestion budget, keyed by the application rather than a visitor.
  PLAY_ANALYTICS_LIMITER: RateLimit;
  // Co-op rooms (coop.ts), and the budget for making them, keyed by the visitor's address.
  COOP_ROOMS: DurableObjectNamespace<CoopRoom>;
  COOP_ROOM_LIMITER: RateLimit;
  // Cloudflare Realtime TURN for co-op peer connections (turn.ts); without both, peers get STUN only.
  TURN_KEY_ID?: string;
  TURN_KEY_API_TOKEN?: string;
  // OAuth apps for account linking; a provider shows only with both its ID and secret.
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  DISCORD_CLIENT_ID?: string;
  DISCORD_CLIENT_SECRET?: string;
  X_CLIENT_ID?: string;
  X_CLIENT_SECRET?: string;
  TWITCH_CLIENT_ID?: string;
  TWITCH_CLIENT_SECRET?: string;
}

export function json(body: unknown, status = 200, headers: HeadersInit = {}): Response {
  return Response.json(body, { status, headers });
}

// The game moves a run refused with a 4xx out of its outbox and keeps the reason (src/crimson/leaderboard/client.py).
export function refuse(status: number, reason: string): Response {
  return json({ reason }, status);
}

// The account a key belongs to; a key the service has not seen starts its own. The new account and its key go in one
// batch, which D1 runs alone: requests with the same new key at once (a co-op pair's pages each upload their run)
// make one account between them.
export async function accountForKey(env: Env, publicKeyHex: string, publicKey: Uint8Array, now: number): Promise<number> {
  const known = await env.DB.prepare("SELECT account_id FROM keys WHERE public_key = ?").bind(publicKeyHex).first<{ account_id: number }>();
  if (known) return known.account_id;
  const [, , account] = await env.DB.batch<{ account_id: number }>([
    env.DB.prepare("INSERT INTO accounts (created_at) SELECT ? WHERE NOT EXISTS (SELECT 1 FROM keys WHERE public_key = ?)").bind(now, publicKeyHex),
    env.DB.prepare("INSERT INTO keys (public_key, account_id, fingerprint, added_at) SELECT ?, last_insert_rowid(), ?, ? WHERE changes() > 0")
      .bind(publicKeyHex, await fingerprint(publicKey), now),
    env.DB.prepare("SELECT account_id FROM keys WHERE public_key = ?").bind(publicKeyHex),
  ]);
  return account!.results[0]!.account_id;
}
