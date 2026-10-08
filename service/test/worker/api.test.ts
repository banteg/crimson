import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { concat, hex, LOGIN_DOMAIN, RUN_DOMAIN, sha256 } from "../../src/crypto";
import { decodeReplay, inflateReplay } from "../../src/replay";
import type { BoardView, ProfileView, RunDetailView } from "../../src/api-types";
import vectors from "../vectors.json";

const ORIGIN = "https://crimson.land";
const decode64 = (text: string) => Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));

class Player {
  private constructor(private readonly key: CryptoKeyPair, readonly publicKey: string) {}

  static async create(): Promise<Player> {
    const key = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    return new Player(key, hex(new Uint8Array((await crypto.subtle.exportKey("raw", key.publicKey)) as ArrayBuffer)));
  }

  async sign(message: Uint8Array): Promise<string> {
    return hex(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, this.key.privateKey, message)));
  }

  // The game's upload envelope (src/crimson/leaderboard/client.py).
  async upload(file: string, name: string, signed = name): Promise<Response> {
    const payloadSha = await sha256(inflateReplay(decode64(file)));
    const signature = await this.sign(concat(RUN_DOMAIN, payloadSha, new TextEncoder().encode(signed)));
    return post("/api/runs", { replay: file, name, public_key: this.publicKey, signature });
  }
}

function post(path: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${ORIGIN}${path}`, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
}

async function reason(response: Response): Promise<string> {
  return ((await response.json()) as { reason: string }).reason;
}

// The game's sign-in: a signed challenge buys a one-time login link.
async function login(player: Player): Promise<string> {
  const { challenge } = (await (await post("/api/auth/challenge", { public_key: player.publicKey })).json()) as { challenge: string };
  const signature = await player.sign(concat(LOGIN_DOMAIN, new TextEncoder().encode(challenge)));
  const response = await post("/api/auth/login", { public_key: player.publicKey, challenge, signature });
  expect(response.status).toBe(200);
  return ((await response.json()) as { url: string }).url;
}

describe("runs", () => {
  it("a verified ranked run joins its board under its name", async () => {
    const player = await Player.create();
    const response = await player.upload(vectors.ranked_run, "banteg");

    expect(response.status).toBe(201);
    const run = (await response.json()) as { id: string; board: string; score: number };
    expect(run).toMatchObject({ board: "survival", score: 749 });
    const account = await env.DB.prepare("SELECT accounts.name, keys.fingerprint FROM accounts JOIN keys ON keys.account_id = accounts.id").first();
    expect(account).toMatchObject({ name: "banteg" });
    expect(await env.REPLAYS.head(`runs/${run.id}.crd`)).not.toBeNull();
    const stored = await env.DB.prepare("SELECT client, platform FROM runs WHERE id = ?").bind(run.id).first();
    expect(stored).toMatchObject({ client: "crimson", platform: expect.stringMatching(/^[a-z]+-[a-z0-9_]+$/) });

    const board = (await (await SELF.fetch(`${ORIGIN}/api/boards/survival`)).json()) as BoardView;
    const result = decodeReplay(inflateReplay(decode64(vectors.ranked_run))).result;
    expect(board.rows).toHaveLength(1);
    expect(board.rows[0]).toMatchObject({
      rank: 1,
      run: run.id,
      score: 749,
      elapsed_ms: result.elapsed_ms,
      most_used_weapon_id: result.players[0]!.most_used_weapon_id,
    });
  });

  it("the game reads a board's runs as high score records", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };

    const { scores } = (await (await post("/api/scores", { board: "survival", quest: "" })).json()) as { scores: Record<string, number | string>[] };
    expect(scores).toHaveLength(1);
    expect(scores[0]).toMatchObject({ run: id, name: "banteg", score: 749, experience: 749 });
    expect((await post("/api/scores", { board: "quests", quest: "" })).status).toBe(400);
  });

  it("a verified run's page has the timeline its verification recorded", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };

    const detail = (await (await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).json()) as RunDetailView;
    expect(detail).toMatchObject({
      board: "survival", score: 749, rank: 1, name: "banteg", top: null, best: null,
      result: { outcome: "death", pending_perks: 0, health: decodeReplay(inflateReplay(decode64(vectors.ranked_run))).result.players[0]!.health },
    });
    const timeline = detail.timeline!;
    // One sample a second and the last tick: the curves end on the run's result.
    expect(timeline.samples.at(-1)!.slice(1, 5)).toEqual([749, detail.timeline!.samples.at(-1)![2], 0, detail.result.kills]);
    expect(timeline.duration_s).toBe(detail.result.elapsed_ms / 1000);
    expect(timeline.path.length).toBeGreaterThan(timeline.samples.length * 9);
    expect(timeline.weapons[0]).toMatchObject({ t: expect.any(Number), id: 1 });
    expect(timeline.samples.at(-1)![5]).toBeGreaterThan(0);

    // A run accepted before timelines existed gets one replayed from its file, the same as verification's.
    await env.REPLAYS.delete(`runs/${id}.timeline.json`);
    expect(await (await SELF.fetch(`${ORIGIN}/api/runs/${id}/timeline`)).json()).toEqual(timeline);
    expect(await env.REPLAYS.head(`runs/${id}.timeline.json`)).not.toBeNull();
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${"0".repeat(64)}`)).status).toBe(404);
  });

  it.each(["quests", "quests-hardcore"])("%s details retain the exact stored scoring inputs without a migration", async (board) => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    // Model an existing accepted quest row; chart health rounds to tenths, but scoring truncates raw HP.
    const result = decodeReplay(inflateReplay(decode64(vectors.ranked_run))).result;
    Object.assign(result, { outcome: "quest_completed", elapsed_ms: 64093, pending_perks: 2, quest_final_ms: 57143 });
    result.players[0]!.health = 99.999;
    await env.DB.prepare("UPDATE runs SET board = ?, quest = '1.2', score = ?, result = ? WHERE id = ?")
      .bind(board, result.quest_final_ms, JSON.stringify(result), id).run();

    const detail = (await (await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).json()) as RunDetailView;
    expect(detail).toMatchObject({
      board, score: 57143,
      result: { outcome: "quest_completed", elapsed_ms: 64093, health: 99.999, pending_perks: 2 },
    });
  });

  it("a hidden name shows only the fingerprint, on boards, run pages, the game's scores and the profile", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const { fingerprint } = (await env.DB.prepare("SELECT fingerprint FROM keys").first<{ fingerprint: string }>())!;
    await env.DB.prepare("UPDATE accounts SET name_hidden = 1").run();
    const get = async <T>(path: string) => (await (await SELF.fetch(`${ORIGIN}${path}`)).json()) as T;

    const detail = await get<RunDetailView>(`/api/runs/${id}`);
    expect([detail.name, detail.player.name]).toEqual([fingerprint, null]);
    expect((await get<BoardView>("/api/boards/survival")).rows[0]!.player.name).toBeNull();
    const { scores } = (await (await post("/api/scores", { board: "survival", quest: "" })).json()) as { scores: { name: string }[] };
    expect(scores[0]!.name).toBe(fingerprint);
    expect((await get<ProfileView>(`/api/players/${detail.player.id}`)).names).toEqual([]);
    expect(await (await SELF.fetch(`${ORIGIN}/runs/${id}`)).text()).toContain(`<title>${fingerprint} · Survival · crimson.land</title>`);
  });

  it("a linked account shows its handle over a mistyped name; an unlinked default name shows the fingerprint", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "10tons]]")).json()) as { id: string };
    await env.DB.prepare("INSERT INTO links (provider, subject, account_id, handle, avatar_url, linked_at) SELECT 'x', '9', id, 'Razenpok', NULL, 0 FROM accounts")
      .run();
    const get = async <T>(path: string) => (await (await SELF.fetch(`${ORIGIN}${path}`)).json()) as T;

    const detail = await get<RunDetailView>(`/api/runs/${id}`);
    expect([detail.name, detail.player.name]).toEqual(["10tons]]", "Razenpok"]);
    expect(await (await SELF.fetch(`${ORIGIN}/runs/${id}`)).text()).toContain("<title>Razenpok · Survival · crimson.land</title>");

    // Once the handle is another account's, a name matching it gets the fingerprint, and the default name shows only that.
    await env.DB.prepare("INSERT INTO accounts (id, created_at) VALUES (99, 0)").run();
    await env.DB.prepare("UPDATE links SET account_id = 99").run();
    await env.DB.prepare("UPDATE accounts SET name = 'razenpok' WHERE id != 99").run();
    expect((await get<BoardView>("/api/boards/survival")).rows[0]!.player).toMatchObject({ name: "razenpok", clash: true });
    await env.DB.prepare("UPDATE accounts SET name = '10tons' WHERE id != 99").run();
    expect((await get<BoardView>("/api/boards/survival")).rows[0]!.player.name).toBeNull();
  });

  it("a shared run's link previews what happened, over its card", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const html = await (await SELF.fetch(`${ORIGIN}/runs/${id}`)).text();
    expect(html).toMatch(/<meta property="og:description" content="banteg survived \d+:\d\d for [\d,]+ xp, #1 on the board\. [\d,]+ kills/);
    expect(html).toContain(`<meta property="og:image" content="${ORIGIN}/runs/${id}.png">`);
    expect(html).toContain('<meta name="twitter:card" content="summary_large_image">');

    const card = await SELF.fetch(`${ORIGIN}/runs/${id}.png`);
    expect(card.headers.get("content-type")).toBe("image/png");
    const header = new DataView(await card.arrayBuffer());
    expect([header.getUint32(16), header.getUint32(20)]).toEqual([1200, 630]);
    expect((await SELF.fetch(`${ORIGIN}/runs/${"0".repeat(64)}.png`)).status).toBe(404);
  });

  it("a timeline goes with its run: hidden runs and deleted accounts have none", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const timeline = () => SELF.fetch(`${ORIGIN}/api/runs/${id}/timeline`);
    expect((await timeline()).status).toBe(200);

    await env.DB.prepare("UPDATE runs SET hidden = 1").run();
    expect((await timeline()).status).toBe(404);
    await env.DB.prepare("UPDATE runs SET hidden = 0").run();

    const cookie = (await SELF.fetch(await login(player), { redirect: "manual" })).headers.get("set-cookie")!.split(";")[0]!;
    expect((await SELF.fetch(`${ORIGIN}/api/account/delete`, { method: "POST", headers: { cookie, origin: ORIGIN } })).status).toBe(200);
    expect((await env.REPLAYS.list()).objects).toEqual([]);
    expect((await timeline()).status).toBe(404);
  });

  it("a run's replay downloads as the file the game sent; a hidden or banned run's does not", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const replay = () => SELF.fetch(`${ORIGIN}/runs/${id}.crd`);

    const response = await replay();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toMatch(/^public, max-age=\d+, must-revalidate$/);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(decode64(vectors.ranked_run));

    await env.DB.prepare("UPDATE runs SET hidden = 1").run();
    expect((await replay()).status).toBe(404);
    await env.DB.prepare("UPDATE runs SET hidden = 0").run();

    await env.DB.prepare("UPDATE accounts SET banned = 1").run();
    expect((await replay()).status).toBe(404);
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).status).toBe(404);
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${id}/timeline`)).status).toBe(404);
  });

  it("a run is accepted once, whoever sends it again", async () => {
    const [owner, copier] = [await Player.create(), await Player.create()];
    expect((await owner.upload(vectors.ranked_run, "owner")).status).toBe(201);

    expect((await owner.upload(vectors.ranked_run, "owner")).status).toBe(409);
    expect((await copier.upload(vectors.ranked_run, "copier")).status).toBe(409);
  });

  it("a claimed result the simulation does not reach is refused", async () => {
    const response = await (await Player.create()).upload(vectors.ranked_run_inflated, "banteg");

    expect(response.status).toBe(422);
    expect(await reason(response)).toContain("players[0].experience");
  });

  it("a signature over another name is refused", async () => {
    const response = await (await Player.create()).upload(vectors.ranked_run, "banteg", "someone");

    expect(response.status).toBe(401);
  });

  it("runs outside the ranked profile are refused with their reasons", async () => {
    const response = await (await Player.create()).upload(vectors.unranked_run, "banteg");

    expect(response.status).toBe(422);
    expect(await reason(response)).toBe("not a ranked run: mode, weapon_usage, unfinished");
  });
});

describe("site login", () => {
  it("a signed challenge buys a one-time link that sets a session", async () => {
    const url = await login(await Player.create());
    expect(url.startsWith(`${ORIGIN}/login/`)).toBe(true);

    const first = await SELF.fetch(url, { redirect: "manual" });
    expect(first.status).toBe(303);
    expect(first.headers.get("set-cookie")).toMatch(/^session=[0-9a-f]{64}; .*HttpOnly; Secure/);
    expect((await SELF.fetch(url, { redirect: "manual" })).status).toBe(410);
  });

  it("a challenge works once and only for its key", async () => {
    const [player, other] = [await Player.create(), await Player.create()];
    const { challenge } = (await (await post("/api/auth/challenge", { public_key: player.publicKey })).json()) as { challenge: string };
    const message = concat(LOGIN_DOMAIN, new TextEncoder().encode(challenge));

    const stolen = await post("/api/auth/login", { public_key: other.publicKey, challenge, signature: await other.sign(message) });
    expect(stolen.status).toBe(401);
    const signature = await player.sign(message);
    expect((await post("/api/auth/login", { public_key: player.publicKey, challenge, signature })).status).toBe(200);
    expect((await post("/api/auth/login", { public_key: player.publicKey, challenge, signature })).status).toBe(401);
  });
});

// A site session for the player, as the game's Profile button opens one.
async function signIn(player: Player): Promise<string> {
  const response = await SELF.fetch(await login(player), { redirect: "manual" });
  return response.headers.get("set-cookie")!.split(";")[0]!;
}

function asSession(cookie: string) {
  return {
    get: (path: string) => SELF.fetch(`${ORIGIN}${path}`, { headers: { cookie } }),
    post: (path: string, body: unknown) =>
      SELF.fetch(`${ORIGIN}${path}`, { method: "POST", body: JSON.stringify(body), headers: { cookie, origin: ORIGIN, "content-type": "application/json" } }),
  };
}

const board = async (query = "") => (await (await SELF.fetch(`${ORIGIN}/api/boards/survival${query}`)).json()) as BoardView;

describe("bots and moderation", () => {
  async function moderatedRun(role: "mod" | "admin") {
    const [player, moderator] = [await Player.create(), await Player.create()];
    const { id } = (await (await player.upload(vectors.ranked_run, "astra")).json()) as { id: string };
    const session = asSession(await signIn(moderator));
    const { account } = (await (await session.get("/api/me")).json()) as { account: number };
    await env.DB.prepare("UPDATE accounts SET role = ? WHERE id = ?").bind(role, account).run();
    const owner = (await env.DB.prepare("SELECT account_id FROM runs WHERE id = ?").bind(id).first<{ account_id: number }>())!.account_id;
    return { id, owner, moderator: account, session };
  }

  it("a run lists on its category's board, and an account marked as a bot moves its runs there", async () => {
    const { id, owner, session } = await moderatedRun("mod");
    expect((await board()).rows.map((row) => row.run)).toEqual([id]);
    expect((await board("?category=bot")).rows).toEqual([]);

    expect((await session.post(`/api/mod/accounts/${owner}`, { bot: true, note: "Astra" })).status).toBe(200);
    expect((await board()).rows).toEqual([]);
    const bots = await board("?category=bot");
    expect(bots).toMatchObject({ category: "bot", rows: [{ rank: 1, run: id, player: { id: owner, bot: true }, pilot: null }] });
    const detail = (await (await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).json()) as RunDetailView;
    expect(detail).toMatchObject({ category: "bot", rank: 1, moderation: null });
    // The game's high score screen shows the human board unless it asks for the bots'.
    expect(((await (await post("/api/scores", { board: "survival", quest: "" })).json()) as { scores: unknown[] }).scores).toEqual([]);
    expect(((await (await post("/api/scores", { board: "survival", quest: "", category: "bot" })).json()) as { scores: unknown[] }).scores).toHaveLength(1);
    expect((await SELF.fetch(`${ORIGIN}/api/boards/survival?category=tas`)).status).toBe(400);
  });

  it("a run that declares its pilot lists on the bot board under the bot's name", async () => {
    const player = await Player.create();
    const response = await player.upload(vectors.piloted_run, "egornomic");
    expect(response.status).toBe(201);
    const { id } = (await response.json()) as { id: string };

    const pilot = { name: "Astra", model: "gpt-5", url: "https://example.com/astra" };
    expect((await board()).rows).toEqual([]);
    expect((await board("?category=bot")).rows).toEqual([expect.objectContaining({ run: id, pilot, player: expect.objectContaining({ bot: false }) })]);
    expect(await (await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).json()).toMatchObject({ category: "bot", pilot, rank: 1 });
    // The pilot does not change the run: the same inputs without it are the same run.
    expect((await (await Player.create()).upload(vectors.ranked_run, "banteg")).status).toBe(409);
  });

  it("a moderator's category for a run wins over the account's mark, and every action is logged", async () => {
    const { id, owner, moderator, session } = await moderatedRun("mod");
    await session.post(`/api/mod/accounts/${owner}`, { bot: true, note: "" });
    expect((await session.post(`/api/mod/runs/${id}`, { category: "human", note: "played by hand" })).status).toBe(200);
    expect((await board()).rows.map((row) => row.run)).toEqual([id]);
    const detail = (await (await session.get(`/api/runs/${id}`)).json()) as RunDetailView;
    expect(detail.moderation).toMatchObject({ source: "moderator", override: "human" });

    await session.post(`/api/mod/runs/${id}`, { category: null, note: "" });
    expect((await board("?category=bot")).rows.map((row) => row.run)).toEqual([id]);
    const { actions } = (await (await session.get("/api/mod/log")).json()) as { actions: { actor: string; action: string; target: string; note: string }[] };
    expect(actions.map((action) => [action.actor, action.action, action.target, action.note])).toEqual([
      [`account ${moderator}`, "category follows account", `run ${id}`, ""],
      [`account ${moderator}`, "category human", `run ${id}`, "played by hand"],
      [`account ${moderator}`, "mark bot", `account ${owner}`, ""],
    ]);
  });

  it("moderators see a run's signals, measured at upload or later from its replay", async () => {
    const { id, owner, session } = await moderatedRun("mod");
    const detail = (await (await session.get(`/api/runs/${id}`)).json()) as RunDetailView;
    expect(detail.moderation).toMatchObject({ source: "default", override: null, flagged: [] });
    const signals = detail.moderation!.signals!;
    expect(signals.ticks).toBeGreaterThan(0);

    await env.DB.prepare("UPDATE runs SET signals = NULL").run();
    expect(((await (await session.get("/api/mod/flags")).json()) as { unmeasured: number }).unmeasured).toBe(1);
    expect(await (await session.post("/api/mod/measure", {})).json()).toEqual({ unmeasured: 0 });
    expect(JSON.parse((await env.DB.prepare("SELECT signals FROM runs WHERE id = ?").bind(id).first<{ signals: string }>())!.signals)).toEqual(signals);

    // A flagged human run is listed; once it is a bot run it is not.
    await env.DB.prepare("UPDATE runs SET signals = ?").bind(JSON.stringify({ ...signals, aim_on_creature: 0.3 })).run();
    const flags = (await (await session.get("/api/mod/flags")).json()) as { runs: { id: string; flagged: string[] }[] };
    expect(flags.runs).toEqual([expect.objectContaining({ id, flagged: ["aim_on_creature"] })]);
    await session.post(`/api/mod/accounts/${owner}`, { bot: true, note: "" });
    expect(((await (await session.get("/api/mod/flags")).json()) as { runs: unknown[] }).runs).toEqual([]);

    const profile = (await (await session.get(`/api/players/${owner}`)).json()) as ProfileView;
    expect(profile).toMatchObject({ player: { bot: true }, moderation: { role: "", overlapping_runs: 0 }, runs: [{ id, category: "bot" }] });
  });

  it("only moderators moderate, and only the admin makes moderators", async () => {
    const { owner, moderator, session } = await moderatedRun("mod");
    const outsider = asSession(await signIn(await Player.create()));
    expect((await outsider.get("/api/mod/flags")).status).toBe(403);
    expect((await outsider.post(`/api/mod/accounts/${owner}`, { bot: true })).status).toBe(403);
    expect((await SELF.fetch(`${ORIGIN}/api/players/${owner}`, {}).then((r) => r.json()) as ProfileView).moderation).toBeNull();
    expect((await session.post(`/api/mod/roles/${owner}`, { role: "mod" })).status).toBe(403);
    // A moderation request from another site is refused.
    expect((await SELF.fetch(`${ORIGIN}/api/mod/accounts/${owner}`, { method: "POST", body: "{}", headers: { origin: "https://example.com" } })).status).toBe(403);

    await env.DB.prepare("UPDATE accounts SET role = 'admin' WHERE id = ?").bind(moderator).run();
    expect((await session.post(`/api/mod/roles/${owner}`, { role: "mod", note: "welcome" })).status).toBe(200);
    expect(await env.DB.prepare("SELECT role FROM accounts WHERE id = ?").bind(owner).first()).toEqual({ role: "mod" });
    // The admin's own role is not one a request can take away.
    expect((await session.post(`/api/mod/roles/${moderator}`, { role: "" })).status).toBe(404);
  });
});
