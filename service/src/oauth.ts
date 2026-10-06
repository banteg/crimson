// Linking a GitHub, Discord or X account to a player's account (docs/rewrite/leaderboard-identity.md).
//
// Authorization-code flow with a state bound to the site session, and PKCE for X. Client secrets and the token
// exchange stay in the Worker; the provider token is used once to read the profile and never stored.

import { hex, randomToken, sha256 } from "./crypto";
import type { Env } from "./http";

export type ProviderName = "github" | "discord" | "x";

export interface Identity {
  subject: string;
  handle: string;
  avatar_url: string | null;
}

interface Provider {
  name: ProviderName;
  label: string;
  authorize: string;
  token: string;
  scope: string;
  pkce: boolean;
  // GitHub takes the client secret in the form; Discord and X in HTTP basic auth.
  secretInForm: boolean;
  credentials(env: Env): { id: string; secret: string } | null;
  profile(accessToken: string): Promise<Identity>;
}

const STATE_TTL_MS = 10 * 60 * 1000;
const USER_AGENT = "crimson.land";

const configured = (id: string | undefined, secret: string | undefined) => (id && secret ? { id, secret } : null);

async function getJson(url: string, accessToken: string): Promise<any> {
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json", "User-Agent": USER_AGENT },
  });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.json();
}

export const PROVIDERS: Record<ProviderName, Provider> = {
  github: {
    name: "github",
    label: "GitHub",
    authorize: "https://github.com/login/oauth/authorize",
    token: "https://github.com/login/oauth/access_token",
    // No scope: the public profile is all the link needs.
    scope: "",
    pkce: false,
    secretInForm: true,
    credentials: (env) => configured(env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET),
    async profile(accessToken) {
      const user = await getJson("https://api.github.com/user", accessToken);
      return { subject: String(user.id), handle: user.login, avatar_url: user.avatar_url ?? null };
    },
  },
  discord: {
    name: "discord",
    label: "Discord",
    authorize: "https://discord.com/oauth2/authorize",
    token: "https://discord.com/api/oauth2/token",
    scope: "identify",
    pkce: false,
    secretInForm: false,
    credentials: (env) => configured(env.DISCORD_CLIENT_ID, env.DISCORD_CLIENT_SECRET),
    async profile(accessToken) {
      const user = await getJson("https://discord.com/api/users/@me", accessToken);
      const avatar = user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png` : null;
      return { subject: String(user.id), handle: user.username, avatar_url: avatar };
    },
  },
  x: {
    name: "x",
    label: "X",
    authorize: "https://x.com/i/oauth2/authorize",
    token: "https://api.x.com/2/oauth2/token",
    scope: "users.read tweet.read",
    pkce: true,
    secretInForm: false,
    credentials: (env) => configured(env.X_CLIENT_ID, env.X_CLIENT_SECRET),
    async profile(accessToken) {
      const { data } = await getJson("https://api.x.com/2/users/me?user.fields=profile_image_url", accessToken);
      return { subject: String(data.id), handle: data.username, avatar_url: data.profile_image_url ?? null };
    },
  },
};

// Providers show only once their client ID and secret are both configured.
export function configuredProviders(env: Env): Provider[] {
  return Object.values(PROVIDERS).filter((provider) => provider.credentials(env) !== null);
}

export function provider(env: Env, name: string): Provider | null {
  const found = PROVIDERS[name as ProviderName];
  return found && found.credentials(env) ? found : null;
}

const callbackUrl = (origin: string, name: ProviderName) => `${origin}/auth/${name}/callback`;
const hashOf = async (text: string) => hex(await sha256(new TextEncoder().encode(text)));
const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// The provider's sign-in URL, with a state bound to this site session.
export async function authorizeUrl(env: Env, origin: string, chosen: Provider, sessionToken: string): Promise<string> {
  const { id } = chosen.credentials(env)!;
  const state = randomToken();
  const verifier = chosen.pkce ? randomToken() : null;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM oauth_states WHERE expires_at < ?").bind(Date.now()),
    env.DB.prepare("INSERT INTO oauth_states (state_hash, session_hash, provider, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?)")
      .bind(await hashOf(state), await hashOf(sessionToken), chosen.name, verifier, Date.now() + STATE_TTL_MS),
  ]);
  const url = new URL(chosen.authorize);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", id);
  url.searchParams.set("redirect_uri", callbackUrl(origin, chosen.name));
  url.searchParams.set("state", state);
  if (chosen.scope) url.searchParams.set("scope", chosen.scope);
  if (verifier) {
    url.searchParams.set("code_challenge", base64url(await sha256(new TextEncoder().encode(verifier))));
    url.searchParams.set("code_challenge_method", "S256");
  }
  return url.toString();
}

// The callback: check the state belongs to this session, exchange the code and read the profile once.
export async function completeLink(
  env: Env,
  origin: string,
  chosen: Provider,
  sessionToken: string,
  state: string,
  code: string,
): Promise<Identity | null> {
  const row = await env.DB.prepare(
    "DELETE FROM oauth_states WHERE state_hash = ? AND provider = ? AND expires_at >= ? RETURNING session_hash, code_verifier",
  )
    .bind(await hashOf(state), chosen.name, Date.now())
    .first<{ session_hash: string; code_verifier: string | null }>();
  if (!row || row.session_hash !== (await hashOf(sessionToken))) return null;
  const { id, secret } = chosen.credentials(env)!;
  const form = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: callbackUrl(origin, chosen.name) });
  if (row.code_verifier) form.set("code_verifier", row.code_verifier);
  const headers: Record<string, string> = {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json",
    "User-Agent": USER_AGENT,
  };
  if (chosen.secretInForm) form.set("client_id", id), form.set("client_secret", secret);
  else headers.Authorization = `Basic ${btoa(`${id}:${secret}`)}`;
  const response = await fetch(chosen.token, { method: "POST", headers, body: form });
  const token = (await response.json().catch(() => ({}))) as { access_token?: string };
  if (!response.ok || !token.access_token) return null;
  return chosen.profile(token.access_token);
}
