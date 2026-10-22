import { env, SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { concat, COOP_RUN_DOMAIN, fromHex, hex, LOGIN_DOMAIN, RUN_DOMAIN, sha256 } from "../../src/crypto";
import { confirmMerge } from "../../src/accounts";
import { tokenHash } from "../../src/auth";
import { decodeReplay, inflateReplay, REPLAY_RULES } from "../../src/replay";
import type { BoardView, CustomQuestDetailView, CustomQuestsListView, GameScore, LoginView, ProfileView, ReplaysView, RunDetailView, Timeline } from "../../src/api-types";
import { STALE, timelineFor, validateRecipeSource } from "../../src/runs";
import vectors from "../vectors.json";

const ORIGIN = "https://crimson.land";
const decode64 = (text: string) => Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
const encode64 = (bytes: Uint8Array) => btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(""));

// A replay file holding `payload` in a zstd frame of raw blocks (RFC 8878): one declaring its content size, as
// replays must, with no compression.
function zstdRaw(payload: Uint8Array): Uint8Array {
  const BLOCK = 128 * 1024;
  const size = payload.length;
  const parts: Uint8Array[] = [Uint8Array.of(0x28, 0xb5, 0x2f, 0xfd, 0xa0, size & 255, (size >> 8) & 255, (size >> 16) & 255, size >>> 24)];
  for (let at = 0; at < size; at += BLOCK) {
    const block = payload.subarray(at, at + BLOCK);
    const header = (block.length << 3) | Number(at + BLOCK >= size);
    parts.push(Uint8Array.of(header & 255, (header >> 8) & 255, header >> 16), block);
  }
  return concat(...parts);
}

// The replay `file` with the bytes `from` in its payload rewritten to `to`, as anyone holding it could.
function rewritten(file: string, from: Uint8Array, to: Uint8Array): string {
  const payload = inflateReplay(decode64(file));
  payload.set(to, payload.findIndex((_, i) => from.every((byte, j) => payload[i + j] === byte)));
  return encode64(zstdRaw(payload));
}
// A seat key and a 32-bit number as the payload holds them: msgpack bin 8 and uint 32.
const seatKey = (key: string) => concat(Uint8Array.of(0xc4, 32), fromHex(key, 32)!);
const uint32 = (value: number) => Uint8Array.of(0xce, value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
// The replay `file` with the seat key `from` its header records rewritten to `to`.
const rekeyed = (file: string, from: string, to: string) => rewritten(file, seatKey(from), seatKey(to));
// The replay `file` with the 32-bit number `from` rewritten to `to`.
const renumbered = (file: string, from: number, to: number) => rewritten(file, uint32(from), uint32(to));

class Player {
  private constructor(private readonly key: CryptoKeyPair, readonly publicKey: string) {}

  static async create(): Promise<Player> {
    const key = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    return new Player(key, hex(new Uint8Array((await crypto.subtle.exportKey("raw", key.publicKey)) as ArrayBuffer)));
  }

  // The player whose key a co-op vector records for `seat` (service/scripts/vectors.py SEAT_SEEDS).
  static async seated(seat: number): Promise<Player> {
    // PKCS #8 for an Ed25519 key from its 32-byte seed (RFC 8410).
    const pkcs8 = concat(Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20), fromHex(vectors.coop_run.seat_seeds[seat]!, 32)!);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    return new Player({ privateKey } as CryptoKeyPair, vectors.coop_run.seat_keys[seat]!);
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

  // This player's entry in a co-op upload's `signers`, signing `seat`.
  async signer(file: string, seat: number, name: string, signedSeat = seat): Promise<{ seat: number; name: string; public_key: string; signature: string }> {
    const payloadSha = await sha256(inflateReplay(decode64(file)));
    const signature = await this.sign(concat(COOP_RUN_DOMAIN, payloadSha, Uint8Array.of(signedSeat), new TextEncoder().encode(name)));
    return { seat, name, public_key: this.publicKey, signature };
  }
}

// A co-op run uploaded with each player's signature, player one first.
async function uploadPair(file: string, ...players: [Player, string][]): Promise<Response> {
  const signers = await Promise.all(players.map(([player, name], seat) => player.signer(file, seat, name)));
  return post("/api/runs", { replay: file, signers });
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
  it.each([REPLAY_RULES + 1])("refuses rules %s before verifying a run", async (rules) => {
    const header = new TextEncoder().encode("rules");
    const file = rewritten(vectors.ranked_run, concat(header, Uint8Array.of(REPLAY_RULES)), concat(header, Uint8Array.of(rules)));
    const response = await (await Player.create()).upload(file, "banteg");

    expect(response.status).toBe(422);
    expect(await reason(response)).toBe(`replay was recorded under rules ${rules}; this service verifies rules 1 and ${REPLAY_RULES}`);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM runs").first("n")).toBe(0);
  });

  it("a verified ranked run joins its board under its name", async () => {
    const player = await Player.create();
    const response = await player.upload(vectors.ranked_run, "banteg");

    expect(response.status).toBe(201);
    const run = (await response.json()) as { id: string; board: string; score: number };
    expect(run).toMatchObject({ id: vectors.ranked_run_id, board: "survival", score: 749 });
    const account = await env.DB.prepare("SELECT accounts.name, keys.fingerprint FROM accounts JOIN keys ON keys.account_id = accounts.id").first();
    expect(account).toMatchObject({ name: "banteg" });
    expect(await env.REPLAYS.head(`runs/${run.id}.crd`)).not.toBeNull();
    const stored = await env.DB.prepare("SELECT client, platform FROM runs WHERE id = ?").bind(run.id).first();
    expect(stored).toMatchObject({ client: "crimson", platform: expect.stringMatching(/^[a-z]+-[a-z0-9_]+$/) });

    const board = (await (await SELF.fetch(`${ORIGIN}/api/survival`)).json()) as BoardView;
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
    expect((await get<BoardView>("/api/survival")).rows[0]!.player.name).toBeNull();
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
    expect((await get<BoardView>("/api/survival")).rows[0]!.player).toMatchObject({ name: "razenpok", clash: true });
    await env.DB.prepare("UPDATE accounts SET name = '10tons' WHERE id != 99").run();
    expect((await get<BoardView>("/api/survival")).rows[0]!.player.name).toBeNull();
  });

  it("a shared run's link previews what happened, over its card", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const html = await (await SELF.fetch(`${ORIGIN}/runs/${id}`)).text();
    expect(html).toMatch(/<meta property="og:description" content="banteg survived \d+:\d\d for [\d,]+ xp, #1 on the board\. [\d,]+ kills/);
    expect(html).toContain(`<meta property="og:image" content="${ORIGIN}/runs/${id}.png">`);
    expect(html).toContain('<meta name="twitter:card" content="player">');
    expect(html).toContain(`<meta name="twitter:player" content="${ORIGIN}/play/?watch=${id}">`);

    const card = await SELF.fetch(`${ORIGIN}/runs/${id}.png`);
    expect(card.headers.get("content-type")).toBe("image/png");
    const header = new DataView(await card.arrayBuffer());
    expect([header.getUint32(16), header.getUint32(20)]).toEqual([1200, 900]);
    expect((await SELF.fetch(`${ORIGIN}/runs/${"0".repeat(64)}.png`)).status).toBe(404);

    const ground = await SELF.fetch(`${ORIGIN}/runs/${id}.ground.jpg`);
    expect(ground.headers.get("content-type")).toBe("image/jpeg");
    expect([...new Uint8Array(await ground.arrayBuffer()).subarray(0, 2)]).toEqual([0xff, 0xd8]);
    expect((await SELF.fetch(`${ORIGIN}/runs/${"0".repeat(64)}.ground.jpg`)).status).toBe(404);
  });

  it("a timeline goes with its run: hidden runs and deleted accounts have none", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const timeline = () => SELF.fetch(`${ORIGIN}/api/runs/${id}/timeline`);
    expect((await timeline()).status).toBe(200);

    await env.DB.prepare("UPDATE runs SET hidden = 1").run();
    expect((await timeline()).status).toBe(404);
    await env.DB.prepare("UPDATE runs SET hidden = 0").run();

    const cookie = await signIn(player);
    const { account } = (await (await SELF.fetch(`${ORIGIN}/api/me`, { headers: { cookie } })).json()) as { account: number };
    const remove = await SELF.fetch(`${ORIGIN}/api/account/delete`, { method: "POST", body: JSON.stringify({ account }), headers: { cookie, origin: ORIGIN } });
    expect(remove.status).toBe(200);
    expect((await env.REPLAYS.list()).objects).toEqual([]);
    expect((await timeline()).status).toBe(404);
  });

  it("a run's replay downloads as the file the game sent and lists for CI; a hidden or banned run's does neither", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const replay = () => SELF.fetch(`${ORIGIN}/runs/${id}.crd`);

    const response = await replay();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toMatch(/^public, max-age=\d+, must-revalidate$/);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(decode64(vectors.ranked_run));

    const listed = async () => ((await (await SELF.fetch(`${ORIGIN}/api/replays`)).json()) as ReplaysView).runs;
    expect(await listed()).toEqual([id]);

    await env.DB.prepare("UPDATE runs SET hidden = 1").run();
    expect((await replay()).status).toBe(404);
    expect(await listed()).toEqual([]);
    await env.DB.prepare("UPDATE runs SET hidden = 0").run();

    await env.DB.prepare("UPDATE accounts SET banned = 1").run();
    expect((await replay()).status).toBe(404);
    expect(await listed()).toEqual([]);
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).status).toBe(404);
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${id}/timeline`)).status).toBe(404);
  });

  it("a retired run leaves the boards, the game's scores and the replay list, and keeps its page, reason and replay", async () => {
    const player = await Player.create();
    const { id } = (await (await player.upload(vectors.ranked_run, "banteg")).json()) as { id: string };
    const reason = "A perk pick from a menu left open, which the rules no longer take";
    await env.DB.prepare("UPDATE runs SET retired = ?").bind(reason).run();

    const board = (await (await SELF.fetch(`${ORIGIN}/api/survival`)).json()) as BoardView;
    expect(board.rows).toHaveLength(0);
    const { scores } = (await (await post("/api/scores", { board: "survival", quest: "" })).json()) as { scores: unknown[] };
    expect(scores).toHaveLength(0);
    const detail = (await (await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).json()) as RunDetailView;
    expect(detail).toMatchObject({ id, retired: reason, rank: null });
    expect((await SELF.fetch(`${ORIGIN}/runs/${id}.crd`)).status).toBe(200);
    expect(((await (await SELF.fetch(`${ORIGIN}/api/replays`)).json()) as ReplaysView).runs).toEqual([]);
    const account = await env.DB.prepare("SELECT account_id FROM runs WHERE id = ?").bind(id).first<{ account_id: number }>();
    const profile = (await (await SELF.fetch(`${ORIGIN}/api/players/${account!.account_id}`)).json()) as ProfileView;
    expect(profile.runs).toMatchObject([{ id, retired: reason }]);
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

  it("a command the rules do not allow is refused with the core's reason", async () => {
    const response = await (await Player.create()).upload(vectors.illegal_command_run, "banteg");

    expect(response.status).toBe(422);
    // Python's verifier words it the same (scripts/vectors.py).
    expect(await reason(response)).toBe("tick 0: perk_pick without an open perk menu");
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
  it("a signed challenge buys a one-time link that signs in only once confirmed from the site's own page", async () => {
    const url = await login(await Player.create());
    expect(url.startsWith(`${ORIGIN}/login/`)).toBe(true);
    const token = new URL(url).pathname.split("/").pop()!;

    // Opening the link shows the confirmation page: no session, and the link stays unspent.
    const opened = await SELF.fetch(url, { redirect: "manual" });
    expect([opened.status, opened.headers.has("set-cookie"), opened.headers.get("content-security-policy")]).toEqual([200, false, "frame-ancestors 'none'"]);
    expect((await SELF.fetch(`${ORIGIN}/api/login/${token}`)).status).toBe(200);

    const confirm = (origin: string) =>
      SELF.fetch(`${ORIGIN}/api/login`, { method: "POST", body: JSON.stringify({ token }), headers: { origin, "content-type": "application/json" } });
    expect((await confirm("https://evil.example")).status).toBe(403);
    const signed = await confirm(ORIGIN);
    expect(signed.status).toBe(200);
    expect(signed.headers.get("set-cookie")).toMatch(/^session=[0-9a-f]{64}; .*HttpOnly; Secure/);
    expect((await confirm(ORIGIN)).status).toBe(410);
    expect((await SELF.fetch(`${ORIGIN}/api/login/${token}`)).status).toBe(410);
  });

  it("someone else's link names their account, and confirming it ends the browser's own session", async () => {
    const [victim, attacker] = [await Player.create(), await Player.create()];
    const own = await signIn(victim);
    const ownAccount = ((await (await SELF.fetch(`${ORIGIN}/api/me`, { headers: { cookie: own } })).json()) as { account: number }).account;
    const token = new URL(await login(attacker)).pathname.split("/").pop()!;

    const view = (await (await SELF.fetch(`${ORIGIN}/api/login/${token}`, { headers: { cookie: own } })).json()) as LoginView;
    expect(view.current?.id).toBe(ownAccount);
    expect(view.account.id).not.toBe(ownAccount);
    const switched = await SELF.fetch(`${ORIGIN}/api/login`, { method: "POST", body: JSON.stringify({ token }), headers: { cookie: own, origin: ORIGIN } });
    expect(((await switched.json()) as { account: number }).account).toBe(view.account.id);
    expect(((await (await SELF.fetch(`${ORIGIN}/api/me`, { headers: { cookie: own } })).json()) as { account: number | null }).account).toBeNull();
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

// A site session for the player, as the game's Profile button opens one and the player confirms it.
async function signIn(player: Player): Promise<string> {
  const token = new URL(await login(player)).pathname.split("/").pop();
  const response = await SELF.fetch(`${ORIGIN}/api/login`, { method: "POST", body: JSON.stringify({ token }), headers: { origin: ORIGIN } });
  return response.headers.get("set-cookie")!.split(";")[0]!;
}

function asSession(cookie: string) {
  return {
    get: (path: string) => SELF.fetch(`${ORIGIN}${path}`, { headers: { cookie } }),
    post: (path: string, body: unknown) =>
      SELF.fetch(`${ORIGIN}${path}`, { method: "POST", body: JSON.stringify(body), headers: { cookie, origin: ORIGIN, "content-type": "application/json" } }),
  };
}

const board = async (query = "") => (await (await SELF.fetch(`${ORIGIN}/api/survival${query}`)).json()) as BoardView;

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
    expect((await SELF.fetch(`${ORIGIN}/api/survival?category=tas`)).status).toBe(400);
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

describe("custom quests", () => {
  it("publishing a custom quest with a verified clear replay creates its page, leaderboard, and portable binary", async () => {
    const player = await Player.create();
    const file = vectors.custom_quest_run.file;
    const payloadSha = await sha256(inflateReplay(decode64(file)));
    const signature = await player.sign(concat(RUN_DOMAIN, payloadSha, new TextEncoder().encode("banteg")));
    const response = await post("/api/custom", {
      replay: file,
      name: "banteg",
      public_key: player.publicKey,
      signature,
      source: vectors.custom_quest_run.source,
      seed: 0,
    });

    expect(response.status).toBe(201);
    const published = (await response.json()) as { id: string; quest: string; digest: string; score: number; url: string };
    const questId = vectors.custom_quest_run.digest.slice(0, 12);
    expect(published).toMatchObject({
      quest: questId,
      digest: vectors.custom_quest_run.digest,
      score: vectors.custom_quest_run.score,
      url: `/custom/${questId}`,
    });

    const detail = (await (await SELF.fetch(`${ORIGIN}/api/custom/${questId}`)).json()) as CustomQuestDetailView;
    expect(detail).toMatchObject({
      id: questId,
      digest: vectors.custom_quest_run.digest,
      title: "Quick Clear",
      author: "banteg",
      source: vectors.custom_quest_run.source,
      first_run_id: published.id,
      board: { rows: [expect.objectContaining({ rank: 1, run: published.id, score: vectors.custom_quest_run.score })] },
    });

    const list = (await (await SELF.fetch(`${ORIGIN}/api/custom`)).json()) as CustomQuestsListView;
    expect(list.quests).toEqual([
      expect.objectContaining({
        id: questId,
        title: "Quick Clear",
        author: "banteg",
        entry_count: 1,
        has_source: true,
        players: 1,
        top_score: vectors.custom_quest_run.score,
      }),
    ]);

    const bin = await SELF.fetch(`${ORIGIN}/custom/${questId}.bin`);
    expect(bin.status).toBe(200);
    const binBytes = new Uint8Array(await bin.arrayBuffer());
    expect(binBytes.byteLength).toBe(6184);
    expect(hex(await sha256(binBytes))).toBe(vectors.custom_quest_run.digest);
    const runView = (await (await SELF.fetch(`${ORIGIN}/api/runs/${published.id}`)).json()) as RunDetailView;
    expect(runView.custom_slots).toEqual([2, 3, 2]);

    const other = await Player.create();
    const otherSig = await other.sign(concat(RUN_DOMAIN, payloadSha, new TextEncoder().encode("other")));
    const hijack = await post("/api/custom", {
      replay: file,
      name: "other",
      public_key: other.publicKey,
      signature: otherSig,
      source: vectors.custom_quest_run.source,
    });
    expect(hijack.status).toBe(403);

    const badSource = await post("/api/custom", {
      replay: file,
      name: "banteg",
      public_key: player.publicKey,
      signature,
      source: 'quest "Wrong Title" version 1\nauthor "banteg"\nterrain (2, 3, 2)\nat 0s:\n    spawn alien.small_gray at (512, 448)\n',
    });
    expect(badSource.status).toBe(422);
    const baseQuest = decodeReplay(inflateReplay(decode64(file))).run.custom_quest!;
    expect(
      validateRecipeSource(
        'quest "Quick (Wave #2 [beta]" version 1 # comment\nauthor "banteg [1] #1"\nweapon shotgun\nterrain (2, 3, 2)\nfixed_weapon true\nat 500ms:\n    spawn 0x26 at (512, 420)\n',
        { ...baseQuest, title: "Quick (Wave #2 [beta]", author: "banteg [1] #1" },
      ),
    ).toBe(true);
    expect(
      validateRecipeSource(
        vectors.custom_quest_run.source.replace("weapon shotgun", "weapon pistol"),
        baseQuest,
      ),
    ).toBe(false);
    expect(
      validateRecipeSource(
        vectors.custom_quest_run.source.replace("alien.small_gray", "spider.small_blue"),
        baseQuest,
      ),
    ).toBe(false);

    const otherSession = asSession(await signIn(other));
    const otherMe = (await (await otherSession.get("/api/me")).json()) as { account: number };
    await env.DB.prepare(
      `INSERT INTO runs (id, payload_sha256, account_id, public_key, name, board, quest, score, game_version, client,
         client_version, platform, pilot, ticks, result, signals, accepted_at)
       SELECT ?, payload_sha256, ?, ?, 'other', board, quest, score + 100, game_version, client,
         client_version, platform, pilot, ticks, result, signals, accepted_at + 1
       FROM runs WHERE id = ?`,
    ).bind("b".repeat(64), otherMe.account, other.publicKey, published.id).run();

    const session = asSession(await signIn(player));
    const me = (await (await session.get("/api/me")).json()) as { account: number };
    const deleted = await session.post("/api/account/delete", { account: me.account });
    expect(deleted.status).toBe(200);

    const surviving = (await (await SELF.fetch(`${ORIGIN}/api/custom/${questId}`)).json()) as CustomQuestDetailView;
    expect(surviving.creator).toBeNull();
    expect(surviving.first_run_id).toBe("b".repeat(64));

    expect((await otherSession.post("/api/account/delete", { account: otherMe.account })).status).toBe(200);
    expect((await SELF.fetch(`${ORIGIN}/api/custom/${questId}`)).status).toBe(404);
  });

  it("POST /api/custom refuses a survival replay", async () => {
    const player = await Player.create();
    const payloadSha = await sha256(inflateReplay(decode64(vectors.ranked_run)));
    const signature = await player.sign(concat(RUN_DOMAIN, payloadSha, new TextEncoder().encode("banteg")));
    const response = await post("/api/custom", {
      replay: vectors.ranked_run,
      name: "banteg",
      public_key: player.publicKey,
      signature,
    });
    expect(response.status).toBe(422);
    expect(await reason(response)).toContain("custom quest");
  });
});

describe("co-op runs", () => {
  const file = vectors.coop_run.file;
  const get = async <T>(path: string) => (await (await SELF.fetch(`${ORIGIN}${path}`)).json()) as T;
  const accountOf = async (player: Player) =>
    (await env.DB.prepare("SELECT account_id FROM keys WHERE public_key = ?").bind(player.publicKey).first<{ account_id: number }>())!.account_id;
  const names = (row: { team: { name: string | null; player: { name: string | null } | null }[] | null }) =>
    row.team!.map((seat) => [seat.name, seat.player?.name ?? null]);
  // The players whose keys the co-op vectors record, player one first.
  const pair = async () => [await Player.seated(0), await Player.seated(1)] as const;
  const refused = async (body: unknown) => {
    const response = await post("/api/runs", body);
    return [response.status, await reason(response)];
  };
  // A copy of the co-op run `id` under another id, score and seats, as if those players had played it.
  const copyRun = (id: string, runId: string, score: number, seats: [number, string][]) => [
    env.DB.prepare(
      `INSERT INTO runs (id, payload_sha256, account_id, public_key, name, board, quest, score, game_version, client, client_version, platform,
         pilot, ticks, result, signals, accepted_at)
       SELECT ?, payload_sha256, ?, '', ?, board, quest, ?, game_version, client, client_version, platform, pilot, ticks, result, signals, accepted_at + 1
       FROM runs WHERE id = ?`,
    ).bind(runId, seats[0]![0], seats[0]![1], score, id),
    ...seats.map(([account, name], seat) =>
      env.DB.prepare("INSERT INTO run_players (run_id, seat, account_id, public_key, name) VALUES (?, ?, ?, '', ?)").bind(runId, seat, account, name),
    ),
  ];
  // The room's record of the seed it issued the vectors' pair, which their run starts from (src/coop.ts).
  const seed = decodeReplay(inflateReplay(decode64(file))).run.seed;
  const attest = (keys = vectors.coop_run.seat_keys, issued = seed) =>
    env.DB.prepare("INSERT INTO coop_runs (seed, room_id, seat0_key, seat1_key, issued_at) VALUES (?, 'roomroom00', ?, ?, ?)")
      .bind(issued, keys[0], keys[1], Date.now())
      .run();
  beforeEach(() => attest());
  const remove = async (player: Player) => {
    const session = asSession(await signIn(player));
    const { account } = (await (await session.get("/api/me")).json()) as { account: number };
    expect((await session.post("/api/account/delete", { account })).status).toBe(200);
  };

  it("a pair's run, signed by both, ranks on its own board under both names", async () => {
    const [alice, bob] = await pair();
    const response = await uploadPair(file, [alice, "alice"], [bob, "bob"]);

    expect(response.status).toBe(201);
    const run = (await response.json()) as { id: string; board: string; score: number };
    const result = decodeReplay(inflateReplay(decode64(file))).result;
    expect(run).toEqual({ id: vectors.coop_run.run_id, board: "survival-coop", quest: "", score: result.players[0]!.experience });
    expect((await get<BoardView>("/api/survival")).rows).toEqual([]);
    const board = await get<BoardView>("/api/survival/coop");
    expect(board).toMatchObject({ board: "survival-coop", title: "Survival · co-op", rows: [{ rank: 1, run: run.id, player: { id: await accountOf(alice) } }] });
    expect(names(board.rows[0]!)).toEqual([["alice", "alice"], ["bob", "bob"]]);

    const detail = await get<RunDetailView>(`/api/runs/${run.id}`);
    expect(detail).toMatchObject({ board: "survival-coop", rank: 1, name: "alice", result: { healths: result.players.map((p) => p.health) } });
    expect(names(detail)).toEqual([["alice", "alice"], ["bob", "bob"]]);
    expect(await (await SELF.fetch(`${ORIGIN}/runs/${run.id}`)).text()).toContain("<title>alice &amp; bob · Survival · co-op · crimson.land</title>");
    const { scores } = (await (await post("/api/scores", { board: "survival-coop", quest: "" })).json()) as { scores: GameScore[] };
    expect(scores).toMatchObject([{ run: run.id, name: "alice & bob", names: ["alice", "bob"] }]);
    // Each player's profile lists it, and each account takes its own name.
    for (const [player, name] of [[alice, "alice"], [bob, "bob"]] as const) {
      const profile = await get<ProfileView>(`/api/players/${await accountOf(player)}`);
      expect([profile.player.name, profile.runs.map((r) => r.id)]).toEqual([name, [run.id]]);
    }
    expect((await SELF.fetch(`${ORIGIN}/runs/${run.id}.png`)).headers.get("content-type")).toBe("image/png");

    expect((await uploadPair(file, [alice, "alice"], [bob, "bob"])).status).toBe(409);
  });

  it("a pair's run page has both players' timelines, and an older one-player timeline is replayed again", async () => {
    const [alice, bob] = await pair();
    expect((await uploadPair(file, [alice, "alice"], [bob, "bob"])).status).toBe(201);
    const id = vectors.coop_run.run_id;
    const detail = await get<RunDetailView>(`/api/runs/${id}`);
    expect(detail.timeline!.players!.map((player) => player.death_s)).toEqual([31.568, 27.904]);

    // A co-op timeline recorded before timelines kept each player's own.
    const { players: _, ...older } = detail.timeline!;
    await env.REPLAYS.put(`runs/${id}.timeline.json`, JSON.stringify(older));
    expect(await get<Timeline>(`/api/runs/${id}/timeline`)).toEqual(detail.timeline);
    expect(await (await env.REPLAYS.get(`runs/${id}.timeline.json`))!.json()).toEqual(detail.timeline);
  });

  it("an older co-op timeline whose run no longer replays is kept, and its run replayed once", async () => {
    const [alice, bob] = await pair();
    expect((await uploadPair(file, [alice, "alice"], [bob, "bob"])).status).toBe(201);
    const id = vectors.coop_run.run_id;
    const { players: _, ...older } = (await get<RunDetailView>(`/api/runs/${id}`)).timeline!;
    await env.REPLAYS.put(`runs/${id}.timeline.json`, JSON.stringify(older));
    // A replay the verifier refuses in place of the run's.
    await env.REPLAYS.put(`runs/${id}.crd`, decode64(vectors.illegal_command_run));
    let replays = 0;
    const REPLAYS = new Proxy(env.REPLAYS, {
      get(target, key) {
        if (key === "get") return (name: string) => (name.endsWith(".crd") && replays++, target.get(name));
        const value = Reflect.get(target, key);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    for (let view = 0; view < 3; view++) expect(await timelineFor({ ...env, REPLAYS }, id, 2)).toEqual(older);
    expect(replays).toBe(1);
    expect((await env.REPLAYS.head(`runs/${id}.timeline.json`))!.customMetadata![STALE]).toContain("perk_pick without an open perk");
    expect(await get<Timeline>(`/api/runs/${id}/timeline`)).toEqual(older);
  });

  it("an upgraded co-op timeline that fails to store is not marked stale, and the next view stores it", async () => {
    const [alice, bob] = await pair();
    expect((await uploadPair(file, [alice, "alice"], [bob, "bob"])).status).toBe(201);
    const id = vectors.coop_run.run_id;
    const upgraded = (await get<RunDetailView>(`/api/runs/${id}`)).timeline!;
    const { players: _, ...older } = upgraded;
    await env.REPLAYS.put(`runs/${id}.timeline.json`, JSON.stringify(older));
    let failures = 1;
    const REPLAYS = new Proxy(env.REPLAYS, {
      get(target, key) {
        if (key === "put")
          return (...args: Parameters<R2Bucket["put"]>) => (failures-- > 0 ? Promise.reject(new Error("R2 is down")) : target.put(...args));
        const value = Reflect.get(target, key);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

    await expect(timelineFor({ ...env, REPLAYS }, id, 2)).rejects.toThrow("R2 is down");
    const kept = (await env.REPLAYS.get(`runs/${id}.timeline.json`))!;
    expect([kept.customMetadata, await kept.json()]).toEqual([{}, older]);
    expect(await timelineFor({ ...env, REPLAYS }, id, 2)).toEqual(upgraded);
    expect(await (await env.REPLAYS.get(`runs/${id}.timeline.json`))!.json()).toEqual(upgraded);
  });

  it("both partners' pages upload the same run at once: the service takes it once", async () => {
    const [alice, bob] = await pair();
    const statuses = await Promise.all([0, 1].map(() => uploadPair(file, [alice, "alice"], [bob, "bob"]).then((response) => response.status)));

    expect(statuses.sort()).toEqual([201, 409]);
    expect((await get<BoardView>("/api/survival/coop")).rows.map((row) => names(row))).toEqual([[["alice", "alice"], ["bob", "bob"]]]);
  });

  it("a co-op run needs each recorded seat key's signature for its own seat", async () => {
    const [alice, bob] = await pair();
    const [a, b] = [await alice.signer(file, 0, "alice"), await bob.signer(file, 1, "bob")];

    expect(await refused({ replay: file, signers: [a] })).toEqual([422, "a 2-player run needs every player's signature, one for each seat"]);
    const solo = await alice.upload(file, "alice");
    expect([solo.status, await reason(solo)]).toEqual([422, "a 2-player run needs every player's signature, one for each seat"]);
    expect(await refused({ replay: file, signers: [a, { ...b, seat: 0 }] })).toEqual([422, "signers must take seats 0..1 once each"]);
    expect(await refused({ replay: file, signers: [a, await alice.signer(file, 1, "alice")] })).toEqual([422, "each player signs with a key of their own"]);
    // Each seat takes only the key the replay records for it, so the pair cannot swap seats.
    expect(await refused({ replay: file, signers: [await bob.signer(file, 0, "bob"), await alice.signer(file, 1, "alice")] })).toEqual([
      422, "seat 0 must be signed by the key the replay records for it",
    ]);
    // Signatures bind their seats: the right key signing another seat, or a one-player signature, does not verify.
    expect((await refused({ replay: file, signers: [a, await bob.signer(file, 1, "bob", 0)] }))[0]).toBe(401);
    const payloadSha = await sha256(inflateReplay(decode64(file)));
    const plain = { ...b, signature: await bob.sign(concat(RUN_DOMAIN, payloadSha, new TextEncoder().encode("bob"))) };
    expect((await refused({ replay: file, signers: [a, plain] }))[0]).toBe(401);
    // A co-op replay that records no keys cannot rank, whoever signs it.
    const unkeyed = vectors.coop_run.unkeyed_quest_file;
    expect(await refused({ replay: unkeyed, signers: [await alice.signer(unkeyed, 0, "alice"), await bob.signer(unkeyed, 1, "bob")] })).toEqual([
      422, "a co-op run must record its players' keys (replay format 34)",
    ]);

    await bob.upload(vectors.ranked_run, "bob");
    await env.DB.prepare("UPDATE keys SET banned = 1 WHERE public_key = ?").bind(bob.publicKey).run();
    expect(await refused({ replay: file, signers: [a, b] })).toEqual([403, "this key is banned"]);
    expect(await env.DB.prepare("SELECT count(*) AS n FROM runs WHERE board = 'survival-coop'").first()).toEqual({ n: 0 });
  });

  it("a partner cannot take the run alone by signing the other seat with a throwaway key", async () => {
    const [alice, bob] = await pair();
    const throwaway = await Player.create();
    // bob holds the replay too: he signs player one's seat with a fresh key and his own seat with his.
    const hijack = { replay: file, signers: [await throwaway.signer(file, 0, "alice"), await bob.signer(file, 1, "bob")] };
    expect(await refused(hijack)).toEqual([422, "seat 0 must be signed by the key the replay records for it"]);
    // Rewriting the replay to record the throwaway key in seat 0 makes every signature verify, but the room issued the
    // run's seed to alice's key, not to it.
    const forged = rekeyed(file, alice.publicKey, throwaway.publicKey);
    expect(decodeReplay(inflateReplay(decode64(forged))).seat_keys!.map(hex)).toEqual([throwaway.publicKey, bob.publicKey]);
    const rewritten = { replay: forged, signers: [await throwaway.signer(forged, 0, "alice"), await bob.signer(forged, 1, "bob")] };
    expect(await refused(rewritten)).toEqual([422, "the room issued this run's seed to other players' keys"]);
    expect(await env.DB.prepare("SELECT count(*) AS n FROM runs").first()).toEqual({ n: 0 });

    // The real pair's upload still lands.
    const response = await uploadPair(file, [alice, "alice"], [bob, "bob"]);
    expect(response.status).toBe(201);
    const detail = await get<RunDetailView>(`/api/runs/${vectors.coop_run.run_id}`);
    expect(detail.team!.map((seat) => seat.player!.id)).toEqual([await accountOf(alice), await accountOf(bob)]);
  });

  it("a co-op run ranks only from a seed its room issued to its players' keys, in their seats", async () => {
    const [alice, bob] = await pair();
    await env.DB.prepare("DELETE FROM coop_runs").run();
    expect(await refused({ replay: file, signers: [await alice.signer(file, 0, "alice"), await bob.signer(file, 1, "bob")] })).toEqual([
      422, "a co-op run must start from a seed its room issued",
    ]);
    // A seed issued to the pair the other way round, or to one of them with someone else, is not this run's.
    for (const keys of [[bob.publicKey, alice.publicKey], [alice.publicKey, (await Player.create()).publicKey]]) {
      await attest(keys);
      expect((await uploadPair(file, [alice, "alice"], [bob, "bob"])).status).toBe(422);
      await env.DB.prepare("DELETE FROM coop_runs").run();
    }
    // A one-player run needs no room.
    expect((await (await Player.create()).upload(vectors.ranked_run, "solo")).status).toBe(201);

    await attest();
    expect((await uploadPair(file, [alice, "alice"], [bob, "bob"])).status).toBe(201);
  });

  it("a co-op run whose seed sets bit 31, which rand never reads, does not rank even from a room's record", async () => {
    const [alice, bob] = await pair();
    // Flipping bit 31 of the seed flips only that bit of every rng state after it, so the run with the claimed final
    // state flipped too plays and verifies as the run, under another run id.
    const flip = (value: number) => (value ^ 0x80000000) >>> 0;
    const { rng_state } = decodeReplay(inflateReplay(decode64(file))).result;
    const flipped = renumbered(renumbered(file, seed, flip(seed)), rng_state, flip(rng_state));
    expect(decodeReplay(inflateReplay(decode64(flipped))).run.seed).toBe(flip(seed));
    await attest(vectors.coop_run.seat_keys, flip(seed));
    const signers = [await alice.signer(flipped, 0, "alice"), await bob.signer(flipped, 1, "bob")];
    expect(await refused({ replay: flipped, signers })).toEqual([422, "a co-op run's seed must have bit 31 clear"]);
    expect(await env.DB.prepare("SELECT count(*) AS n FROM runs").first()).toEqual({ n: 0 });
  });

  it("the co-op board keeps each pair's best run, whichever seats they took", async () => {
    const [alice, bob] = await pair();
    const carol = await Player.create();
    const { id } = (await (await uploadPair(file, [alice, "alice"], [bob, "bob"])).json()) as { id: string };
    await carol.upload(vectors.ranked_run, "carol");
    const [a, b, c] = [await accountOf(alice), await accountOf(bob), await accountOf(carol)];
    // The same pair seated the other way round, scoring more, and alice with carol, scoring less.
    await env.DB.batch([...copyRun(id, "b".repeat(64), 5000, [[b, "bob"], [a, "alice"]]), ...copyRun(id, "c".repeat(64), 10, [[a, "alice"], [c, "carol"]])]);

    const board = await get<BoardView>("/api/survival/coop");
    expect(board.rows.map((row) => [row.run, row.rank])).toEqual([["b".repeat(64), 1], ["c".repeat(64), 2]]);
    expect(board.totals.runs).toBe(3);
    const detail = await get<RunDetailView>(`/api/runs/${id}`);
    expect(detail).toMatchObject({ rank: null, best: { id: "b".repeat(64), score: 5000 }, top: { id: "b".repeat(64), name: "bob & alice" } });

    // Either player's bot mark moves the pair's runs to the bot board; a banned partner takes them off the boards.
    await env.DB.prepare("UPDATE accounts SET bot = 1 WHERE id = ?").bind(c).run();
    expect((await get<BoardView>("/api/survival/coop")).rows.map((row) => row.run)).toEqual(["b".repeat(64)]);
    expect((await get<BoardView>("/api/survival/coop?category=bot")).rows.map((row) => row.run)).toEqual(["c".repeat(64)]);
    await env.DB.prepare("UPDATE accounts SET banned = 1 WHERE id = ?").bind(b).run();
    expect((await get<BoardView>("/api/survival/coop")).rows).toEqual([]);
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).status).toBe(404);
  });

  it("a board of many pairs lists them all", async () => {
    const [alice, bob] = await pair();
    const { id } = (await (await uploadPair(file, [alice, "alice"], [bob, "bob"])).json()) as { id: string };
    // 70 more pairs, 140 accounts: more than D1 binds in one statement.
    const pairs = 70;
    const now = Date.now();
    await env.DB.batch(
      Array.from({ length: pairs * 2 }, (_, i) =>
        env.DB.prepare("INSERT INTO accounts (id, created_at, name) VALUES (?, ?, ?)").bind(1000 + i, now, `p${i}`),
      ),
    );
    await env.DB.batch(
      Array.from({ length: pairs }, (_, i) =>
        copyRun(id, i.toString(16).padStart(64, "0"), 2000 + i, [[1000 + 2 * i, `p${2 * i}`], [1000 + 2 * i + 1, `p${2 * i + 1}`]]),
      ).flat(),
    );

    const board = await get<BoardView>("/api/survival/coop");
    expect(board.rows).toHaveLength(pairs + 1);
    expect(board.rows[0]!.team!.map((seat) => seat.player!.name)).toEqual([`p${2 * (pairs - 1)}`, `p${2 * pairs - 1}`]);
    const { scores } = (await (await post("/api/scores", { board: "survival-coop", quest: "" })).json()) as { scores: GameScore[] };
    expect(scores).toHaveLength(pairs + 1);
    expect(scores[0]!.names).toEqual([`p${2 * (pairs - 1)}`, `p${2 * pairs - 1}`]);
  });

  it("a player who deletes their account leaves a shared run to their partner, their seat a deleted player", async () => {
    const [alice, bob] = await pair();
    const { id } = (await (await uploadPair(file, [alice, "alice"], [bob, "bob"])).json()) as { id: string };
    const [aliceAccount, bobAccount] = [await accountOf(alice), await accountOf(bob)];

    // Player one leaves: the run lists under bob, player one's seat a deleted player.
    await remove(alice);
    const detail = await get<RunDetailView>(`/api/runs/${id}`);
    expect([detail.player.id, detail.team!.map((seat) => [seat.player?.id ?? null, seat.name])]).toEqual([bobAccount, [[null, null], [bobAccount, "bob"]]]);
    expect((await get<BoardView>("/api/survival/coop")).rows.map((row) => row.run)).toEqual([id]);
    expect((await get<ProfileView>(`/api/players/${bobAccount}`)).runs.map((run) => run.id)).toEqual([id]);
    const { scores } = (await (await post("/api/scores", { board: "survival-coop", quest: "" })).json()) as { scores: GameScore[] };
    expect(scores[0]!.name).toBe("? & bob");
    // The seat keeps a bare account, with no name, key, link or session, and no profile.
    expect(await env.DB.prepare("SELECT account_id, public_key, name FROM run_players WHERE seat = 0").first()).toEqual({ account_id: aliceAccount, public_key: "", name: "" });
    expect(await env.DB.prepare("SELECT name, deleted_at IS NOT NULL AS deleted FROM accounts WHERE id = ?").bind(aliceAccount).first()).toEqual({ name: "", deleted: 1 });
    for (const table of ["keys", "names", "links", "sessions"])
      expect(await env.DB.prepare(`SELECT count(*) AS n FROM ${table} WHERE account_id = ?`).bind(aliceAccount).first()).toEqual({ n: 0 });
    expect((await SELF.fetch(`${ORIGIN}/api/players/${aliceAccount}`)).status).toBe(404);
    expect(await env.REPLAYS.head(`runs/${id}.crd`)).not.toBeNull();

    // The last player on it takes it along, and the bare account goes with its last run.
    await remove(bob);
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).status).toBe(404);
    expect(await env.DB.prepare("SELECT count(*) AS n FROM run_players").first()).toEqual({ n: 0 });
    expect(await env.DB.prepare("SELECT count(*) AS n FROM accounts").first()).toEqual({ n: 0 });
    expect((await env.REPLAYS.list()).objects).toEqual([]);
  });

  it("a deleted player's seat keeps their moderation and their team", async () => {
    const [alice, bob] = await pair();
    const carol = await Player.create();
    const { id } = (await (await uploadPair(file, [alice, "alice"], [bob, "bob"])).json()) as { id: string };
    await carol.upload(vectors.ranked_run, "carol");
    const [a, b, c] = [await accountOf(alice), await accountOf(bob), await accountOf(carol)];
    // bob also played with carol, scoring less.
    await env.DB.batch(copyRun(id, "c".repeat(64), 10, [[b, "bob"], [c, "carol"]]));

    // Both of bob's partners delete their accounts: he keeps two runs with two different deleted players.
    await remove(alice);
    await remove(carol);
    const board = await get<BoardView>("/api/survival/coop");
    expect(board.rows.map((row) => [row.run, row.team!.map((seat) => seat.player?.id ?? null)])).toEqual([
      [id, [null, b]],
      ["c".repeat(64), [b, null]],
    ]);

    // A ban or bot mark on a deleted player still applies to the runs they played.
    await env.DB.prepare("UPDATE accounts SET bot = 1 WHERE id = ?").bind(c).run();
    expect((await get<BoardView>("/api/survival/coop?category=bot")).rows.map((row) => row.run)).toEqual(["c".repeat(64)]);
    await env.DB.prepare("UPDATE accounts SET banned = 1 WHERE id = ?").bind(a).run();
    expect((await get<BoardView>("/api/survival/coop")).rows).toEqual([]);
    expect((await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).status).toBe(404);
  });

  it("a banned player's flagged co-op run leaves the moderators' flags, whichever seat they took", async () => {
    const [alice, bob] = await pair();
    const { id } = (await (await uploadPair(file, [alice, "alice"], [bob, "bob"])).json()) as { id: string };
    const moderator = await Player.create();
    const session = asSession(await signIn(moderator));
    const { account } = (await (await session.get("/api/me")).json()) as { account: number };
    await env.DB.prepare("UPDATE accounts SET role = 'mod' WHERE id = ?").bind(account).run();
    const signals = JSON.parse((await env.DB.prepare("SELECT signals FROM runs WHERE id = ?").bind(id).first<{ signals: string }>())!.signals);
    await env.DB.prepare("UPDATE runs SET signals = ?").bind(JSON.stringify({ ...signals, aim_on_creature: 0.3 })).run();
    const flagged = async () => ((await (await session.get("/api/mod/flags")).json()) as { runs: { id: string }[] }).runs.map((run) => run.id);

    expect(await flagged()).toEqual([id]);
    await env.DB.prepare("UPDATE accounts SET banned = 1 WHERE id = ?").bind(await accountOf(bob)).run();
    expect(await flagged()).toEqual([]);
  });

  it("joining accounts moves a co-op seat along", async () => {
    const [alice, bob] = await pair();
    const alt = await Player.create();
    const { id } = (await (await uploadPair(file, [alice, "alice"], [bob, "bob"])).json()) as { id: string };
    await alt.upload(vectors.ranked_run, "bobby");
    const [from, into] = [await accountOf(bob), await accountOf(alt)];
    const [token, sessionToken] = ["t".repeat(64), "s".repeat(64)];
    await env.DB.prepare(
      `INSERT INTO merge_requests (token_hash, session_hash, from_account, into_account, provider, subject, handle, avatar_url, expires_at)
       VALUES (?, ?, ?, ?, 'github', '1', 'bob', NULL, ?)`,
    ).bind(await tokenHash(token), await tokenHash(sessionToken), from, into, Date.now() + 60_000).run();

    expect(await confirmMerge(env, from, sessionToken, token)).toBe(into);
    expect(await env.DB.prepare("SELECT account_id FROM run_players WHERE run_id = ? AND seat = 1").bind(id).first()).toEqual({ account_id: into });
    expect((await get<ProfileView>(`/api/players/${into}`)).runs.map((run) => run.board).sort()).toEqual(["survival", "survival-coop"]);
    expect((await get<RunDetailView>(`/api/runs/${id}`)).team!.map((seat) => seat.player!.id)).toEqual([await accountOf(alice), into]);
  });
});

describe("historical rules coexist with the current default", () => {
  it("accepts a signed queued rules-1 co-op upload from another 0.18 development build", async () => {
    const original = decodeReplay(inflateReplay(decode64(vectors.legacy_coop_run)));
    const file = rewritten(vectors.legacy_coop_run,
      new TextEncoder().encode(original.game_version),
      new TextEncoder().encode("0.18.0+build.0123456789abcdef01234567"));
    const [alice, bob] = await Promise.all([Player.seated(0), Player.seated(1)]);
    await env.DB.prepare("INSERT INTO coop_runs (seed, room_id, seat0_key, seat1_key, issued_at) VALUES (?, 'roomroom00', ?, ?, ?)")
      .bind(original.run.seed, vectors.coop_run.seat_keys[0], vectors.coop_run.seat_keys[1], Date.now()).run();
    const response = await uploadPair(file, [alice, "alice"], [bob, "bob"]);
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({ id: vectors.legacy_coop_run_id });
    expect(await env.DB.prepare("SELECT rules FROM runs WHERE id = ?").bind(vectors.legacy_coop_run_id).first("rules")).toBe(1);
  });

  it("stores future positive rules without rebuilding the table, while uploads still reject unsupported rules", async () => {
    const response = await (await Player.create()).upload(vectors.ranked_run, "current");
    expect(response.status).toBe(201);
    const { id } = await response.json() as { id: string };
    await env.DB.prepare("UPDATE runs SET rules = 3 WHERE id = ?").bind(id).run();
    expect(await env.DB.prepare("SELECT rules FROM runs WHERE id = ?").bind(id).first("rules")).toBe(3);
    await expect(env.DB.prepare("UPDATE runs SET rules = 0 WHERE id = ?").bind(id).run()).rejects.toThrow("CHECK constraint failed");
  });

  it("keeps legacy IDs, dispatches both profiles in a reused verifier and filters boards", async () => {
    const player = await Player.create();
    const oldResponse = await player.upload(vectors.legacy_ranked_run, "historical");
    expect(oldResponse.status).toBe(201);
    const old = await oldResponse.json() as { id: string };
    expect(old.id).toBe(vectors.legacy_ranked_run_id);
    const newResponse = await player.upload(vectors.ranked_run, "current");
    expect(newResponse.status).toBe(201);
    const current = await newResponse.json() as { id: string };
    for (const [rules, id] of [[1, old.id], [2, current.id]]) {
      const board = await (await SELF.fetch(`${ORIGIN}/api/survival?rules=${rules}`)).json() as BoardView;
      expect(board.rows).toHaveLength(1);
      expect(board.rows[0]).toMatchObject({ run: id, rules });
      const detail = await (await SELF.fetch(`${ORIGIN}/api/runs/${id}`)).json() as RunDetailView;
      expect(detail.rules).toBe(rules);
    }
    const combined = await (await SELF.fetch(`${ORIGIN}/api/survival`)).json() as BoardView;
    expect(combined.totals.runs).toBe(2);
    expect(await env.DB.prepare("SELECT retired FROM runs WHERE id = ?").bind(old.id).first("retired")).toBeNull();
    expect((await SELF.fetch(`${ORIGIN}/api/survival?rules=3`)).status).toBe(400);
    // Reinitialize with old rules again after current rules; it must still verify.
    expect((await player.upload(vectors.legacy_ranked_run, "historical")).status).toBe(409);
  });
});
