// The game's sign-in on the site: a signed challenge buys a one-time login link (docs/rewrite/leaderboard-identity.md).

import { concat, fromHex, hex, LOGIN_DOMAIN, randomToken, sha256, verifyEd25519 } from "./crypto";
import { accountForKey, type Env, json, refuse } from "./http";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const LOGIN_LINK_TTL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const SESSION_COOKIE = "session";

async function body(request: Request): Promise<Record<string, unknown>> {
  const value = await request.json().catch(() => null);
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

export const tokenHash = async (token: string) => hex(await sha256(new TextEncoder().encode(token)));

export async function postChallenge(request: Request, env: Env): Promise<Response> {
  const { public_key } = await body(request);
  if (typeof public_key !== "string" || !fromHex(public_key, 32)) return refuse(400, "expected public_key");
  const challenge = randomToken();
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM challenges WHERE expires_at < ?").bind(now),
    env.DB.prepare("INSERT INTO challenges (challenge, public_key, expires_at) VALUES (?, ?, ?)").bind(challenge, public_key, now + CHALLENGE_TTL_MS),
  ]);
  return json({ challenge });
}

export async function postLogin(request: Request, env: Env): Promise<Response> {
  const { public_key, challenge, signature } = await body(request);
  if (typeof public_key !== "string" || typeof challenge !== "string" || typeof signature !== "string")
    return refuse(400, "expected public_key, challenge and signature");
  const publicKey = fromHex(public_key, 32);
  const signatureBytes = fromHex(signature, 64);
  if (!publicKey || !signatureBytes) return refuse(400, "malformed key or signature");
  const now = Date.now();
  // A challenge works once, for the key it was issued to.
  const issued = await env.DB.prepare("DELETE FROM challenges WHERE challenge = ? AND public_key = ? AND expires_at >= ? RETURNING 1")
    .bind(challenge, public_key, now)
    .first();
  if (!issued) return refuse(401, "unknown or expired challenge");
  if (!(await verifyEd25519(publicKey, signatureBytes, concat(LOGIN_DOMAIN, new TextEncoder().encode(challenge)))))
    return refuse(401, "signature does not match");
  const key = await env.DB.prepare("SELECT banned FROM keys WHERE public_key = ?").bind(public_key).first<{ banned: number }>();
  if (key?.banned) return refuse(403, "this key is banned");
  const accountId = await accountForKey(env, public_key, publicKey, now);
  const token = randomToken();
  await env.DB.prepare("INSERT INTO login_links (token_hash, account_id, expires_at) VALUES (?, ?, ?)")
    .bind(await tokenHash(token), accountId, now + LOGIN_LINK_TTL_MS)
    .run();
  return json({ url: `${new URL(request.url).origin}/login/${token}` });
}

// The account a login link signs in as, without spending it. Opening /login/<token> only shows this: the browser
// switches accounts when the player confirms (postLoginLink), so a link someone else made for their own key cannot
// sign this browser in to their account unseen.
export async function loginLink(env: Env, token: string): Promise<number | null> {
  const link = await env.DB.prepare("SELECT account_id FROM login_links WHERE token_hash = ? AND expires_at >= ?")
    .bind(await tokenHash(token), Date.now())
    .first<{ account_id: number }>();
  return link?.account_id ?? null;
}

// POST /api/login {token}, from the site's own pages: trade the link for a session cookie, once. The browser's
// previous session, if any, ends with it.
export async function postLoginLink(request: Request, env: Env): Promise<Response> {
  const { token } = await body(request);
  const now = Date.now();
  const link = await env.DB.prepare("DELETE FROM login_links WHERE token_hash = ? AND expires_at >= ? RETURNING account_id")
    .bind(await tokenHash(String(token)), now)
    .first<{ account_id: number }>();
  if (!link) return refuse(410, "this sign-in link has expired; open your profile from the game again");
  const previous = sessionToken(request);
  const session = randomToken();
  await env.DB.batch([
    ...(previous ? [env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await tokenHash(previous))] : []),
    env.DB.prepare("INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?, ?, ?)")
      .bind(await tokenHash(session), link.account_id, now + SESSION_TTL_MS),
  ]);
  const cookie = `${SESSION_COOKIE}=${session}; Path=/; HttpOnly;${secure(request)} SameSite=Lax; Max-Age=${SESSION_TTL_MS / 1000}`;
  return json({ account: link.account_id }, 200, { "Set-Cookie": cookie });
}

// Secure everywhere but plain-HTTP local development, where some browsers refuse Secure cookies on localhost.
export function secure(request: Request): string {
  return new URL(request.url).protocol === "https:" ? " Secure;" : "";
}

export function sessionToken(request: Request): string | null {
  const cookie = request.headers.get("cookie") ?? "";
  return cookie.split(/;\s*/).find((part) => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1) || null;
}

export async function sessionAccount(request: Request, env: Env): Promise<number | null> {
  const token = sessionToken(request);
  if (!token) return null;
  const session = await env.DB.prepare("SELECT account_id FROM sessions WHERE token_hash = ? AND expires_at >= ?")
    .bind(await tokenHash(token), Date.now())
    .first<{ account_id: number }>();
  return session?.account_id ?? null;
}
