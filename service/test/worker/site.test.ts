import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { concat, hex, LOGIN_DOMAIN, sha256 } from "../../src/crypto";
import worker from "../../src/index";
import type { BoardView, JoinView, ProfileView, QuestMenuView } from "../../src/api-types";
import questTitles from "../../src/quests.json";

const ORIGIN = "https://crimson.land";
const configured = {
  ...env, GITHUB_CLIENT_SECRET: "github-secret", X_CLIENT_ID: "x-id", X_CLIENT_SECRET: "x-secret",
  TWITCH_CLIENT_ID: "twitch-id", TWITCH_CLIENT_SECRET: "twitch-secret",
};

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
  const token = new URL(url).pathname.split("/").pop();
  const signed = await call("/api/login", { method: "POST", headers: { origin: ORIGIN }, body: JSON.stringify({ token }) });
  return { cookie: signed.headers.get("set-cookie")!.split(";")[0]!, accountId: ((await signed.json()) as { account: number }).account };
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
  const { account } = await api<{ account: number }>("/api/me", cookie);
  const start = await call(`/auth/${name}/start?account=${account}`, { headers: { cookie } });
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
    for (const [path, title] of [["/", "crimson.land"], ["/quests/1.1", `1.1: ${questTitles["1.1"]} · crimson.land`], ["/about", "About · crimson.land"]]) {
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
    const head = await call("/play/game/sfx.paq", { method: "HEAD" });
    expect([head.status, head.headers.get("content-length"), await head.text()]).toEqual([200, "4", ""]);
    expect((await call("/play/game/missing.paq")).status).toBe(404);
    expect((await call("/play/game/missing.paq", { method: "HEAD" })).status).toBe(404);
    expect((await call("/play/game/crimson.paq")).status).toBe(404);
    const play = await call("/play?assets=/elsewhere/");
    expect([play.status, play.headers.get("location")]).toEqual([301, `${ORIGIN}/play/?assets=/elsewhere/`]);
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

  it("links to the boards' old paths move to the new ones", async () => {
    const moved = async (path: string) => {
      const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { redirect: "manual" }), configured);
      return [response.status, response.headers.get("location")];
    };
    expect(await moved("/boards/survival?category=bot")).toEqual([301, `${ORIGIN}/survival?category=bot`]);
    expect(await moved("/boards/quests/1.1")).toEqual([301, `${ORIGIN}/quests/1.1`]);
    expect(await moved("/boards/quests-hardcore/2.3")).toEqual([301, `${ORIGIN}/quests/hardcore/2.3`]);
    expect(await moved("/quests-hardcore/4")).toEqual([301, `${ORIGIN}/quests/hardcore/4`]);
    expect((await call("/quests/hardcore/4")).status).toBe(200);
  });

  it("the quest menu lists a stage's ten quests by title with their player counts", async () => {
    const menu = await api<QuestMenuView>("/api/quests/hardcore/2");

    expect(menu).toMatchObject({ board: "quests-hardcore", stage: 2 });
    expect(menu.quests.map((quest) => quest.quest)).toEqual(Array.from({ length: 10 }, (_, i) => `2.${i + 1}`));
    expect(menu.quests[0]).toEqual({ quest: "2.1", title: questTitles["2.1"], players: 0 });
    expect((await api<BoardView>("/api/quests/hardcore/2.3")).title).toBe(`2.3: ${questTitles["2.3"]} · hardcore`);
    expect((await call("/api/quests/9.9")).status).toBe(404);
  });

  it("a co-op pair's boards sit under /coop, beside one player's", async () => {
    expect(await (await call("/survival/coop")).text()).toContain("<title>Survival · co-op · crimson.land</title>");
    expect(await (await call("/quests/hardcore/coop/2.3")).text()).toContain(`<title>2.3: ${questTitles["2.3"]} · hardcore · co-op · crimson.land</title>`);
    expect(await api<BoardView>("/api/survival/coop")).toMatchObject({ board: "survival-coop", rows: [] });
    expect(await api<QuestMenuView>("/api/quests/coop/3")).toMatchObject({ board: "quests-coop", stage: 3 });
    expect((await api<BoardView>("/api/quests/hardcore/coop/2.3")).board).toBe("quests-hardcore-coop");
    const scores = (body: unknown) => call("/api/scores", { method: "POST", body: JSON.stringify(body) });
    expect((await scores({ board: "quests-hardcore-coop", quest: "2.3" })).status).toBe(200);
    // A custom quest ranks one player only.
    expect((await scores({ board: "quests-coop", quest: "0123456789ab" })).status).toBe(400);
    expect((await scores({ board: "survival-coop", quest: "1.1" })).status).toBe(400);
  });

  it("board totals count every ranked run in the category, not only the best runs the board shows", async () => {
    expect((await api<BoardView>("/api/survival")).totals).toEqual({ runs: 0, kills: 0, elapsed_ms: 0 });
    await env.DB.batch([
      env.DB.prepare("INSERT INTO accounts (id, created_at, bot, banned) VALUES (1, 0, 0, 0), (2, 0, 1, 0), (3, 0, 0, 1)"),
      env.DB.prepare("INSERT INTO keys (public_key, account_id, fingerprint, added_at) VALUES ('key', 1, 'human', 0), ('bot-key', 2, 'bot', 0)"),
    ]);
    const runs = [
      { id: "best", account: 1, score: 100 },
      { id: "other", account: 1, score: 50 },
      { id: "bot", account: 2 },
      { id: "pilot", account: 1, pilot: '{"name":"Bot"}' },
      { id: "override", account: 2, category: "human" },
      { id: "hidden", account: 1, hidden: 1 },
      { id: "retired", account: 1, retired: "old rules" },
      { id: "banned", account: 3 },
      { id: "quest", account: 1, board: "quests", quest: "1.1" },
    ];
    for (const run of runs) {
      await env.DB.prepare(
        `INSERT INTO runs (id, payload_sha256, account_id, public_key, name, board, quest, score, game_version, ticks,
           result, accepted_at, pilot, category, hidden, retired)
         VALUES (?, ?, ?, 'key', 'Player', ?, ?, ?, 'test', 1, ?, 0, ?, ?, ?, ?)`,
      ).bind(run.id, run.id, run.account, run.board ?? "survival", run.quest ?? "", run.score ?? 1,
        JSON.stringify({ kills: 10, elapsed_ms: 61000, players: [{ most_used_weapon_id: 1 }] }),
        run.pilot ?? "", run.category ?? null, run.hidden ?? 0, run.retired ?? null).run();
    }
    const humans = await api<BoardView>("/api/survival?limit=1");
    expect(humans.rows.map((row) => row.run)).toEqual(["best"]);
    expect(humans.totals).toEqual({ runs: 3, kills: 30, elapsed_ms: 183000 });
    expect((await api<BoardView>("/api/survival?category=bot&limit=1")).totals).toEqual({ runs: 2, kills: 20, elapsed_ms: 122000 });
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
      { name: "twitch", label: "Twitch", linked: false },
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

  it("Twitch links with no scope, its secret in the form and the client ID on Helix", async () => {
    const { cookie, accountId } = await signIn();
    await env.DB.prepare("UPDATE accounts SET name = 'Onetake' WHERE id = ?").bind(accountId).run();
    const { authorize, callback } = await link(cookie, "twitch");
    expect(authorize.origin + authorize.pathname).toBe("https://id.twitch.tv/oauth2/authorize");
    expect(authorize.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/auth/twitch/callback`);
    expect(authorize.searchParams.has("scope")).toBe(false);
    expect(authorize.searchParams.has("code_challenge")).toBe(false);
    const calls = provider({
      data: [{ id: "141981764", login: "onetakeruns", display_name: "OnetakeRuns", profile_image_url: "https://static-cdn.jtvnw.net/a.png" }],
    });

    const landed = await callback();

    expect(landed.headers.get("location")).toBe(`/players/${accountId}?notice=linked&provider=twitch`);
    const [tokenUrl, tokenInit] = calls.mock.calls[0]!;
    expect(String(tokenUrl)).toBe("https://id.twitch.tv/oauth2/token");
    const form = new URLSearchParams(String(tokenInit!.body));
    expect([form.get("client_id"), form.get("client_secret")]).toEqual(["twitch-id", "twitch-secret"]);
    const [profileUrl, profileInit] = calls.mock.calls[1]!;
    expect(String(profileUrl)).toBe("https://api.twitch.tv/helix/users");
    expect(new Headers(profileInit!.headers).get("client-id")).toBe("twitch-id");
    const row = await env.DB.prepare("SELECT * FROM links WHERE account_id = ?").bind(accountId).first();
    expect(row).toEqual({
      provider: "twitch", subject: "141981764", account_id: accountId, handle: "onetakeruns",
      avatar_url: "https://static-cdn.jtvnw.net/a.png", linked_at: expect.any(Number),
    });
    const own = await api<ProfileView>(`/api/players/${accountId}`, cookie);
    expect(own.player.name).toBe("onetakeruns");
    expect(own.player.links[0]!.url).toBe("https://www.twitch.tv/onetakeruns");
    // Another account claiming the typed alias cannot change a linked player's shown handle.
    await env.DB.prepare("INSERT INTO accounts (name, created_at) VALUES ('Onetake', 0)").run();
    expect((await api<ProfileView>(`/api/players/${accountId}`, cookie)).player.name).toBe("onetakeruns");
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
    expect(pending).toMatchObject({
      destination: { id: home.accountId }, source: { id: laptop.accountId }, moving: { keys: 1, runs: 0, names: 0 }, provider: "GitHub",
    });
    expect([await keysOf(home.accountId), await keysOf(laptop.accountId)]).toEqual([1, 1]);
    const confirm = (cookie: string, account: number) =>
      call("/api/join", { method: "POST", headers: { cookie, origin: ORIGIN }, body: JSON.stringify({ token, account }) });

    expect((await confirm(home.cookie, home.accountId)).status).toBe(410);
    expect((await confirm(laptop.cookie, home.accountId)).status).toBe(409);
    expect(await (await confirm(laptop.cookie, laptop.accountId)).json()).toEqual({ account: home.accountId });
    expect([await keysOf(home.accountId), await keysOf(laptop.accountId)]).toEqual([2, 0]);
    expect(await env.DB.prepare("SELECT 1 FROM accounts WHERE id = ?").bind(laptop.accountId).first()).toBeNull();
  });

  it("a join keeps a moderator's bot mark and the stronger role", async () => {
    const [home, laptop] = [await signIn(), await signIn()];
    await env.DB.prepare("UPDATE accounts SET bot = 1, role = 'admin' WHERE id = ?").bind(laptop.accountId).run();
    provider({ id: 42, login: "banteg" });
    await (await link(home.cookie, "github")).callback();
    const token = /^\/join\/([0-9a-f]{64})$/.exec((await (await link(laptop.cookie, "github")).callback()).headers.get("location")!)![1]!;

    await call("/api/join", { method: "POST", headers: { cookie: laptop.cookie, origin: ORIGIN }, body: JSON.stringify({ token, account: laptop.accountId }) });

    expect(await env.DB.prepare("SELECT bot, role FROM accounts WHERE id = ?").bind(home.accountId).first()).toEqual({ bot: 1, role: "admin" });
  });
});

describe("account", () => {
  const post = (path: string, cookie: string, account: number, origin = ORIGIN) =>
    call(path, { method: "POST", headers: { cookie, origin }, body: JSON.stringify({ account }) });

  it("unlink removes the link", async () => {
    const { cookie, accountId } = await signIn();
    provider({ id: 42, login: "banteg" });
    await (await link(cookie, "github")).callback();

    expect((await post("/api/account/unlink/github", cookie, accountId)).status).toBe(200);
    expect(await env.DB.prepare("SELECT 1 FROM links WHERE account_id = ?").bind(accountId).first()).toBeNull();
  });

  it("delete removes the account, its keys and sessions", async () => {
    const { cookie, accountId } = await signIn();

    expect((await post("/api/account/delete", cookie, accountId, "https://evil.example")).status).toBe(403);
    const deleted = await post("/api/account/delete", cookie, accountId);

    expect(deleted.headers.get("set-cookie")).toContain("Max-Age=0");
    for (const table of ["accounts", "keys", "sessions"]) {
      const column = table === "accounts" ? "id" : "account_id";
      expect(await env.DB.prepare(`SELECT 1 FROM ${table} WHERE ${column} = ?`).bind(accountId).first()).toBeNull();
    }
  });

  it("the admin's account cannot be deleted", async () => {
    const { cookie, accountId } = await signIn();
    await env.DB.prepare("UPDATE accounts SET role = 'admin' WHERE id = ?").bind(accountId).run();

    expect((await post("/api/account/delete", cookie, accountId)).status).toBe(403);
    expect(await env.DB.prepare("SELECT 1 FROM accounts WHERE id = ?").bind(accountId).first()).not.toBeNull();
  });

  it("a tab still showing another account changes nothing once the browser signed in elsewhere", async () => {
    const [shown, current] = [await signIn(), await signIn()];
    provider({ id: 42, login: "banteg" });

    expect((await post("/api/account/delete", current.cookie, shown.accountId)).status).toBe(409);
    expect((await post("/api/account/unlink/github", current.cookie, shown.accountId)).status).toBe(409);
    const start = await call(`/auth/github/start?account=${shown.accountId}`, { headers: { cookie: current.cookie } });
    expect(start.headers.get("location")).toBe(`/players/${current.accountId}?notice=switched`);
    expect(await env.DB.prepare("SELECT 1 FROM accounts WHERE id = ?").bind(current.accountId).first()).not.toBeNull();
  });
});
