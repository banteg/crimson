import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { concat, hex, LOGIN_DOMAIN, sha256 } from "../../src/crypto";
import worker from "../../src/index";
import type { BoardView, JoinView, ProfileView, QuestMenuView } from "../../src/api-types";
import questTitles from "../../src/quests.json";

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

async function api<T>(path: string, cookie = ""): Promise<T> {
  const response = await call(path, { headers: { cookie } });
  expect(response.status).toBe(200);
  return response.json() as Promise<T>;
}

describe("site", () => {
  it("every route gets the site's page, titled for what a shared link points at", async () => {
    for (const [path, title] of [["/", "crimson.land"], ["/boards/quests/1.1", `1.1 ${questTitles["1.1"]} · crimson.land`], ["/about", "About · crimson.land"]]) {
      const html = await (await call(path!)).text();
      expect(html).toContain(`<title>${title}</title>`);
      expect(html).toContain(`<meta property="og:title" content="${title}">`);
      expect(html).toContain('<div id="app">');
    }
  });

  it("the playable game loads its files from the asset bucket, and nothing else from it", async () => {
    await env.GAME_FILES.put("v1.9.93/sfx.paq", "paq\0");
    const file = await call("/play/game/sfx.paq");
    expect([file.status, await file.text(), file.headers.get("etag")]).toEqual([200, "paq\0", expect.any(String)]);
    expect((await call("/play/game/missing.paq")).status).toBe(404);
    expect((await call("/play/game/crimson.paq")).status).toBe(404);
    const play = await call("/play");
    expect([play.status, play.headers.get("location")]).toEqual([301, `${ORIGIN}/play/`]);
  });

  it("the site answers only over HTTPS, except plain-HTTP localhost for wrangler dev", async () => {
    const plain = (url: string, init: RequestInit = {}) => worker.fetch(new Request(url, { redirect: "manual", ...init }), configured);

    const get = await plain("http://crimson.land/privacy?x=1");
    expect([get.status, get.headers.get("location")]).toEqual([301, "https://crimson.land/privacy?x=1"]);
    expect((await plain("http://crimson.land/api/runs", { method: "POST", body: "{}" })).status).toBe(308);
    expect((await call("/privacy")).headers.get("strict-transport-security")).toContain("max-age=31536000");
    const local = await plain("http://localhost:8787/privacy");
    expect([local.status, local.headers.has("strict-transport-security")]).toEqual([200, false]);
  });

  it("the quest menu lists a stage's ten quests by title with their player counts", async () => {
    const menu = await api<QuestMenuView>("/api/quests/quests-hardcore/2");

    expect(menu).toMatchObject({ board: "quests-hardcore", stage: 2 });
    expect(menu.quests.map((quest) => quest.quest)).toEqual(Array.from({ length: 10 }, (_, i) => `2.${i + 1}`));
    expect(menu.quests[0]).toEqual({ quest: "2.1", title: questTitles["2.1"], players: 0 });
    expect((await api<BoardView>("/api/boards/quests-hardcore/2.3")).title).toBe(`2.3 ${questTitles["2.3"]} · hardcore`);
    expect((await call("/api/boards/quests/9.9")).status).toBe(404);
  });

  it("a profile shows its links, and to its owner the providers configured with both ID and secret", async () => {
    const { cookie, accountId } = await signIn();
    await env.DB.prepare("INSERT INTO links (provider, subject, account_id, handle, avatar_url, linked_at) VALUES ('discord', '9', ?, 'banteg', NULL, 0)")
      .bind(accountId).run();

    const own = await api<ProfileView>(`/api/players/${accountId}`, cookie);
    expect(own.player.links).toEqual([{ provider: "discord", handle: "banteg", avatar_url: null, url: "https://discord.com/users/9" }]);
    expect(own.account!.providers).toEqual([
      { name: "github", label: "GitHub", linked: false },
      { name: "x", label: "X", linked: false },
    ]);
    expect((await api<ProfileView>(`/api/players/${accountId}`)).account).toBeNull();
  });
});

describe("linking", () => {
  it("GitHub links with no scope and keeps only the id, handle and avatar", async () => {
    const { cookie, accountId } = await signIn();
    const { authorize, callback } = await link(cookie, "github");
    expect(authorize.origin + authorize.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(authorize.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/auth/github/callback`);
    expect(authorize.searchParams.has("scope")).toBe(false);
    const calls = provider({ id: 42, login: "banteg", avatar_url: "https://avatars.githubusercontent.com/u/42" });

    const landed = await callback();

    expect(landed.headers.get("location")).toBe(`/players/${accountId}?notice=linked&provider=github`);
    const [tokenRequest] = calls.mock.calls[0]!;
    const form = await new Request(tokenRequest as RequestInfo, calls.mock.calls[0]![1]).text();
    expect(new URLSearchParams(form).get("client_secret")).toBe("github-secret");
    const row = await env.DB.prepare("SELECT * FROM links WHERE account_id = ?").bind(accountId).first();
    expect(row).toEqual({
      provider: "github", subject: "42", account_id: accountId, handle: "banteg",
      avatar_url: "https://avatars.githubusercontent.com/u/42", linked_at: expect.any(Number),
    });
  });

  it("X uses PKCE and HTTP basic client auth", async () => {
    const { cookie } = await signIn();
    const { authorize, callback } = await link(cookie, "x");
    expect(authorize.searchParams.get("scope")).toBe("users.read tweet.read");
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    const calls = provider({ data: { id: "7", username: "banteg", profile_image_url: null } });

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
    const calls = provider({ id: 42, login: "banteg" });

    expect((await callback("code", other.cookie)).headers.get("location")).toContain("notice=failed");
    expect(calls).not.toHaveBeenCalled();
  });

  it("a login another account linked asks before moving this key into it, then moves everything at once", async () => {
    const [home, laptop] = [await signIn(), await signIn()];
    provider({ id: 42, login: "banteg" });
    await (await link(home.cookie, "github")).callback();
    const keysOf = async (id: number) => (await env.DB.prepare("SELECT count(*) AS n FROM keys WHERE account_id = ?").bind(id).first<{ n: number }>())!.n;

    const landed = await (await link(laptop.cookie, "github")).callback();

    const token = /^\/join\/([0-9a-f]{64})$/.exec(landed.headers.get("location")!)![1]!;
    const pending = await api<JoinView>(`/api/join/${token}`, laptop.cookie);
    expect(pending).toMatchObject({ destination: { id: home.accountId }, moving: { keys: 1, runs: 0, names: 0 }, provider: "GitHub" });
    expect([await keysOf(home.accountId), await keysOf(laptop.accountId)]).toEqual([1, 1]);
    const confirm = (cookie: string) =>
      call("/api/join", { method: "POST", headers: { cookie, origin: ORIGIN }, body: JSON.stringify({ token }) });

    expect((await confirm(home.cookie)).status).toBe(410);
    expect(await (await confirm(laptop.cookie)).json()).toEqual({ account: home.accountId });
    expect([await keysOf(home.accountId), await keysOf(laptop.accountId)]).toEqual([2, 0]);
    expect(await env.DB.prepare("SELECT 1 FROM accounts WHERE id = ?").bind(laptop.accountId).first()).toBeNull();
  });
});

describe("account", () => {
  const post = (path: string, cookie: string, origin = ORIGIN) => call(path, { method: "POST", headers: { cookie, origin } });

  it("unlink removes the link", async () => {
    const { cookie, accountId } = await signIn();
    provider({ id: 42, login: "banteg" });
    await (await link(cookie, "github")).callback();

    expect((await post("/api/account/unlink/github", cookie)).status).toBe(200);
    expect(await env.DB.prepare("SELECT 1 FROM links WHERE account_id = ?").bind(accountId).first()).toBeNull();
  });

  it("delete removes the account, its keys and sessions", async () => {
    const { cookie, accountId } = await signIn();

    expect((await post("/api/account/delete", cookie, "https://evil.example")).status).toBe(403);
    const deleted = await post("/api/account/delete", cookie);

    expect(deleted.headers.get("set-cookie")).toContain("Max-Age=0");
    for (const table of ["accounts", "keys", "sessions"]) {
      const column = table === "accounts" ? "id" : "account_id";
      expect(await env.DB.prepare(`SELECT 1 FROM ${table} WHERE ${column} = ?`).bind(accountId).first()).toBeNull();
    }
  });
});
