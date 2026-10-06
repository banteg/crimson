import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { concat, hex, LOGIN_DOMAIN, sha256 } from "../../src/crypto";
import worker from "../../src/index";

const ORIGIN = "https://crimson.land";
const configured = { ...env, GITHUB_CLIENT_SECRET: "github-secret", X_CLIENT_ID: "x-id", X_CLIENT_SECRET: "x-secret" };

function call(path: string, init: RequestInit = {}, bindings: typeof env = configured): Promise<Response> {
  return worker.fetch(new Request(`${ORIGIN}${path}`, { redirect: "manual", ...init }), bindings);
}

// A game key signed in on the site: its session cookie.
async function signIn(): Promise<{ cookie: string; accountId: number }> {
  const key = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const publicKey = hex(new Uint8Array((await crypto.subtle.exportKey("raw", key.publicKey)) as ArrayBuffer));
  const post = (path: string, body: unknown) => call(path, { method: "POST", body: JSON.stringify(body) });
  const { challenge } = (await (await post("/api/auth/challenge", { public_key: publicKey })).json()) as { challenge: string };
  const signature = hex(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.privateKey, concat(LOGIN_DOMAIN, new TextEncoder().encode(challenge)))));
  const { url } = (await (await post("/api/auth/login", { public_key: publicKey, challenge, signature })).json()) as { url: string };
  const landed = await call(new URL(url).pathname);
  return { cookie: landed.headers.get("set-cookie")!.split(";")[0]!, accountId: Number(landed.headers.get("location")!.split("/").pop()) };
}

// The provider's side of the sign-in: its token endpoint and profile API.
function provider(profile: object) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.includes("token")) return Response.json({ access_token: "provider-token", token_type: "bearer" });
    return Response.json(profile);
  });
}

async function link(cookie: string, name: string): Promise<{ authorize: URL; callback: (code?: string, as?: string) => Promise<Response> }> {
  const start = await call(`/auth/${name}/start`, { headers: { cookie } });
  expect(start.status).toBe(303);
  const authorize = new URL(start.headers.get("location")!);
  return {
    authorize,
    callback: (code = "code", as = cookie) =>
      call(`/auth/${name}/callback?code=${code}&state=${authorize.searchParams.get("state")}`, { headers: { cookie: as } }),
  };
}

afterEach(() => vi.restoreAllMocks());
// Storage persists across this file's tests, so each test links its own provider identity.
const ids = { next: 1000 };
const uniqueId = () => ids.next++;

describe("pages", () => {
  it("every page links the privacy and terms pages", async () => {
    for (const path of ["/", "/privacy", "/terms"]) {
      const html = await (await call(path)).text();
      expect(html).toContain('href="/privacy"');
      expect(html).toContain('href="/terms"');
    }
  });

  it("a provider shows only with both its client ID and secret", async () => {
    const { cookie, accountId } = await signIn();
    const page = async (bindings: typeof env) => (await call(`/players/${accountId}`, { headers: { cookie } }, bindings)).text();

    expect(await page(env)).not.toContain("Link GitHub");
    const html = await page(configured);
    expect(html).toContain("Link GitHub");
    expect(html).toContain("Link X");
    expect(html).not.toContain("Link Discord");
  });
});

describe("linking", () => {
  it("GitHub links with no scope and keeps only the id, handle and avatar", async () => {
    const { cookie, accountId } = await signIn();
    const { authorize, callback } = await link(cookie, "github");
    expect(authorize.origin + authorize.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(authorize.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/auth/github/callback`);
    expect(authorize.searchParams.has("scope")).toBe(false);
    const id = uniqueId();
    const calls = provider({ id, login: "banteg", avatar_url: "https://avatars.githubusercontent.com/u/42" });

    const html = await (await callback()).text();

    expect(html).toContain("Linked GitHub.");
    const [tokenRequest] = calls.mock.calls[0]!;
    const form = await new Request(tokenRequest as RequestInfo, calls.mock.calls[0]![1]).text();
    expect(new URLSearchParams(form).get("client_secret")).toBe("github-secret");
    const row = await env.DB.prepare("SELECT * FROM links WHERE account_id = ?").bind(accountId).first();
    expect(row).toEqual({
      provider: "github", subject: String(id), account_id: accountId, handle: "banteg",
      avatar_url: "https://avatars.githubusercontent.com/u/42", linked_at: expect.any(Number),
    });
  });

  it("X uses PKCE and HTTP basic client auth", async () => {
    const { cookie } = await signIn();
    const { authorize, callback } = await link(cookie, "x");
    expect(authorize.searchParams.get("scope")).toBe("users.read tweet.read");
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    const calls = provider({ data: { id: String(uniqueId()), username: "banteg", profile_image_url: null } });

    await callback();

    const init = calls.mock.calls[0]![1]!;
    expect(new Headers(init.headers).get("authorization")).toBe(`Basic ${btoa("x-id:x-secret")}`);
    const verifier = new URLSearchParams(String(init.body)).get("code_verifier")!;
    const challenge = btoa(String.fromCharCode(...(await sha256(new TextEncoder().encode(verifier)))))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(challenge).toBe(authorize.searchParams.get("code_challenge"));
  });

  it("a state only completes in the session that started it", async () => {
    const [owner, other] = [await signIn(), await signIn()];
    const { callback } = await link(owner.cookie, "github");
    const calls = provider({ id: uniqueId(), login: "banteg" });

    expect(await (await callback("code", other.cookie)).text()).toContain("failed or expired");
    expect(calls).not.toHaveBeenCalled();
  });

  it("signing in with a linked login moves another computer's key into that account", async () => {
    const [home, laptop] = [await signIn(), await signIn()];
    provider({ id: uniqueId(), login: "banteg" });
    await (await link(home.cookie, "github")).callback();

    const html = await (await (await link(laptop.cookie, "github")).callback()).text();

    expect(html).toContain("joined your GitHub-linked account");
    const { results } = await env.DB.prepare("SELECT DISTINCT account_id FROM keys WHERE account_id IN (?, ?)").bind(home.accountId, laptop.accountId).all();
    expect(results).toEqual([{ account_id: home.accountId }]);
  });
});

describe("account", () => {
  const post = (path: string, cookie: string, origin = ORIGIN) => call(path, { method: "POST", headers: { cookie, origin } });

  it("unlink removes the link", async () => {
    const { cookie, accountId } = await signIn();
    provider({ id: uniqueId(), login: "banteg" });
    await (await link(cookie, "github")).callback();

    expect((await post("/account/unlink/github", cookie)).status).toBe(303);
    expect(await env.DB.prepare("SELECT 1 FROM links WHERE account_id = ?").bind(accountId).first()).toBeNull();
  });

  it("delete removes the account, its keys and sessions", async () => {
    const { cookie, accountId } = await signIn();

    expect((await post("/account/delete", cookie, "https://evil.example")).status).toBe(403);
    const deleted = await post("/account/delete", cookie);

    expect(deleted.headers.get("set-cookie")).toContain("Max-Age=0");
    for (const table of ["accounts", "keys", "sessions"]) {
      const column = table === "accounts" ? "id" : "account_id";
      expect(await env.DB.prepare(`SELECT 1 FROM ${table} WHERE ${column} = ?`).bind(accountId).first()).toBeNull();
    }
  });
});
