// POST /api/runs: a signed ranked run (docs/rewrite/leaderboard-identity.md, "Protocol").

import { concat, COOP_RUN_DOMAIN, fromHex, hex, latin1, RUN_DOMAIN, sha256, verifyEd25519 } from "./crypto";
import { accountForKey, type Env, json, refuse } from "./http";
import { outcomeReasons, rankedBoard, rankedScore, unrankedReasons } from "./ranked";
import { FIXED_WEAPON_BONUSES, FIXED_WEAPON_PERKS, type Signals, type Timeline } from "./api-types";
import { type CustomQuest, decodeReplay, inflateReplay, type Replay, REPLAY_RULES, ReplayError, SEED_BITS } from "./replay";
import { GroundBake, groundArt, groundKey } from "./ground";
import { encodeJpeg } from "./jpeg";
import { encodePortableQuest, encodeTransport, runIdentity } from "./transport";
import questDsl from "./quest-dsl.json";
import { runGround, SIZE } from "../web/src/terrain/rules";
import { type Verdict, verifyRun } from "./verify";

const MAX_BODY_BYTES = 16 * 1024 * 1024;
const NAME_MAX_CHARS = 31;
// The replay format's most players.
const MAX_SIGNERS = 4;

// A player's signature over the run: the one-player envelope's top-level name, key and signature, or one entry of a
// co-op envelope's `signers`, whose signature binds its seat too.
interface Signer {
  seat: number;
  name: string;
  public_key: string;
  signature: string;
}

interface Upload {
  replay: string;
  signers: Signer[];
  // The envelope signs with `signers` and COOP_RUN_DOMAIN rather than one player's RUN_DOMAIN.
  coop: boolean;
  source: string | null;
  seed: number;
}

const isString = (field: unknown) => typeof field === "string";

function parseSigner(body: unknown): Signer | null {
  if (typeof body !== "object" || body === null) return null;
  const { seat, name, public_key, signature } = body as Record<string, unknown>;
  if (typeof seat !== "number" || !Number.isInteger(seat) || ![name, public_key, signature].every(isString)) return null;
  return { seat, name: name as string, public_key: public_key as string, signature: signature as string };
}

function parseUpload(body: unknown): Upload | null {
  if (typeof body !== "object" || body === null) return null;
  const { replay, name, public_key, signature, signers, source, seed } = body as Record<string, unknown>;
  if (!isString(replay)) return null;
  if (source !== undefined && source !== null && (typeof source !== "string" || source.length === 0 || source.length > 65536))
    return null;
  if (seed !== undefined && (typeof seed !== "number" || !Number.isInteger(seed) || seed < 0 || seed > 0xffffffff))
    return null;
  const coop = signers !== undefined;
  const parsed = coop
    ? Array.isArray(signers) && signers.length <= MAX_SIGNERS ? signers.map(parseSigner) : [null]
    : [[name, public_key, signature].every(isString) ? { seat: 0, name: name as string, public_key: public_key as string, signature: signature as string } : null];
  if (!parsed.length || parsed.some((signer) => signer === null)) return null;
  return {
    replay: replay as string,
    signers: parsed as Signer[],
    coop,
    source: typeof source === "string" ? source : null,
    seed: typeof seed === "number" ? seed : 0,
  };
}

// Why a run's signers do not stand for its players (docs/rewrite/leaderboard-identity.md, "Co-op runs"), or null:
// one signer a player, each seat once, a key of their own each, and each seat signed by the key the replay records
// for it. A co-op replay must record its seats' keys: the payload digest every signature covers then binds each key
// to its seat, so neither partner can sign the other's seat with a key of their own.
function signersReason(signers: Signer[], players: number, seatKeys: Uint8Array[] | null): string | null {
  if (players > 1 && seatKeys === null) return "a co-op run must record its players' keys (replay format 34)";
  if (signers.length !== players)
    return players > 1 ? `a ${players}-player run needs every player's signature, one for each seat` : "a one-player run has one signer";
  const seats = new Set(signers.map((signer) => signer.seat));
  if (seats.size !== players || [...seats].some((seat) => seat < 0 || seat >= players)) return `signers must take seats 0..${players - 1} once each`;
  if (new Set(signers.map((signer) => signer.public_key)).size !== players) return "each player signs with a key of their own";
  const stranger = seatKeys && signers.find((signer) => signer.public_key !== hex(seatKeys[signer.seat]!));
  if (stranger) return `seat ${stranger.seat} must be signed by the key the replay records for it`;
  return null;
}

// Why a co-op run's room does not stand for its pair, or null: its seed must be one a room issued (src/coop.ts), and
// to the keys its replay records, in seat order. Either partner holds the replay and could rewrite those keys to sign
// both seats alone; the room recorded the keys each seat proved before the run began. Rooms issue seeds in the bits
// rand reads, and a seed outside them would play the run of the seed inside.
async function roomReason(env: Env, replay: Replay): Promise<string | null> {
  if (replay.run.player_count < 2) return null;
  if ((replay.run.seed & SEED_BITS) !== replay.run.seed) return "a co-op run's seed must have bit 31 clear";
  const issued = await env.DB.prepare("SELECT seat0_key, seat1_key FROM coop_runs WHERE seed = ?")
    .bind(replay.run.seed)
    .first<{ seat0_key: string; seat1_key: string }>();
  if (!issued) return "a co-op run must start from a seed its room issued";
  if (replay.seat_keys!.map(hex).join() !== [issued.seat0_key, issued.seat1_key].join())
    return "the room issued this run's seed to other players' keys";
  return null;
}

function base64(text: string): Uint8Array | null {
  try {
    return Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

// A replay file's run and its payload's digest. The payload, many times the file's size, goes with this call rather
// than staying through verification.
async function readReplay(file: Uint8Array): Promise<{ replay: Replay; payloadSha: Uint8Array }> {
  const payload = inflateReplay(file);
  return { replay: decodeReplay(payload), payloadSha: await sha256(payload) };
}

export async function customQuestDigest(quest: CustomQuest): Promise<string> {
  return hex(await sha256(encodePortableQuest(quest)));
}

const RECIPE_WEAPONS: Record<string, number> = questDsl.weapons;
const RECIPE_BONUSES: Record<string, number> = questDsl.bonuses;
const RECIPE_PERKS: Record<string, number> = questDsl.perks;
const RECIPE_TEMPLATES: Record<string, number> = questDsl.templates;

function stripRecipeComment(line: string): string {
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "\\" && inQuote) i++;
    else if (ch === '"') inQuote = !inQuote;
    else if (ch === "#" && !inQuote) return line.slice(0, i).trim();
  }
  return line.trim();
}

function unclosedDelimiterDepth(line: string): number {
  let inQuote = false;
  let depth = 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "\\" && inQuote) i++;
    else if (ch === '"') inQuote = !inQuote;
    else if (!inQuote && (ch === "[" || ch === "(")) depth++;
    else if (!inQuote && (ch === "]" || ch === ")")) depth--;
  }
  return depth;
}

function parseIdList(raw: string, table: Record<string, number>, maxId?: number): number[] | null {
  const items = raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const seen = new Set<string>();
  const out: number[] = [];
  for (const item of items) {
    if (seen.has(item)) return null;
    const id = table[item];
    if (id === undefined || (maxId !== undefined && (id < 2 || id > maxId))) return null;
    seen.add(item);
    out.push(id);
  }
  return out;
}

function sameIds(a: readonly number[], b: readonly number[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function validateRecipeSource(source: string, quest: CustomQuest): boolean {
  const rawLines = source.split(/\r?\n/).map(stripRecipeComment).filter(Boolean);
  const lines: string[] = [];
  for (let i = 0; i < rawLines.length; i++) {
    let line = rawLines[i]!;
    while (unclosedDelimiterDepth(line) > 0 && i + 1 < rawLines.length) {
      line += " " + rawLines[++i]!;
    }
    lines.push(line);
  }
  if (lines.length < 2) return false;
  const header = /^quest\s+("(?:[^"\\]|\\.)*")\s+version\s+1$/.exec(lines[0]!);
  if (!header) return false;
  try {
    if (JSON.parse(header[1]!) !== quest.title) return false;
  } catch {
    return false;
  }
  let author: string | null = null;
  let weapon = 1;
  let terrain: [number, number, number] = [0, 1, 0];
  let fixedWeapon = false;
  const noBonuses = new Set<number>();
  const noPerks = new Set<number>();
  const noWeapons = new Set<number>();
  const seenSettings = new Set<string>();
  let idx = 1;
  for (; idx < lines.length; idx++) {
    const line = lines[idx]!;
    let m: RegExpExecArray | null;
    if ((m = /^author\s+("(?:[^"\\]|\\.)*")$/.exec(line))) {
      if (seenSettings.has("author")) return false;
      seenSettings.add("author");
      try {
        author = JSON.parse(m[1]!) as string;
      } catch {
        return false;
      }
    } else if ((m = /^order\s+(?:chronological|as-written)$/.exec(line))) {
      if (seenSettings.has("order")) return false;
      seenSettings.add("order");
    } else if ((m = /^weapon\s+([A-Za-z_]\w*)$/.exec(line))) {
      if (seenSettings.has("weapon")) return false;
      seenSettings.add("weapon");
      const id = RECIPE_WEAPONS[m[1]!.toLowerCase()];
      if (!id) return false;
      weapon = id;
    } else if ((m = /^terrain\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)$/.exec(line))) {
      if (seenSettings.has("terrain")) return false;
      seenSettings.add("terrain");
      terrain = [Number(m[1]), Number(m[2]), Number(m[3])];
    } else if ((m = /^fixed_weapon\s+(true|false)$/.exec(line))) {
      if (seenSettings.has("fixed_weapon")) return false;
      seenSettings.add("fixed_weapon");
      fixedWeapon = m[1] === "true";
    } else if ((m = /^(no_bonuses|no_perks|no_weapons)\s*\[([^\]]*)\]$/.exec(line))) {
      const kind = m[1]!;
      if (seenSettings.has(kind)) return false;
      seenSettings.add(kind);
      const ids =
        kind === "no_bonuses"
          ? parseIdList(m[2]!, RECIPE_BONUSES)
          : kind === "no_perks"
            ? parseIdList(m[2]!, RECIPE_PERKS)
            : parseIdList(m[2]!, RECIPE_WEAPONS, 33);
      if (!ids) return false;
      const target = kind === "no_bonuses" ? noBonuses : kind === "no_perks" ? noPerks : noWeapons;
      ids.forEach((id) => target.add(id));
    } else {
      break;
    }
  }
  if (fixedWeapon) {
    FIXED_WEAPON_BONUSES.forEach((id) => noBonuses.add(id));
    FIXED_WEAPON_PERKS.forEach((id) => noPerks.add(id));
    for (let id = 2; id <= 33; id++) noWeapons.add(id);
  }
  if (author !== quest.author || weapon !== quest.start_weapon_id) return false;
  if (terrain.some((slot, i) => slot !== quest.terrain_slots[i])) return false;
  if (!sameIds([...noBonuses].sort((a, b) => a - b), quest.no_bonuses)) return false;
  if (!sameIds([...noPerks].sort((a, b) => a - b), quest.no_perks)) return false;
  if (!sameIds([...noWeapons].sort((a, b) => a - b), quest.no_weapons)) return false;

  let hasSpawn = false;
  const templates = new Set<number>();
  for (; idx < lines.length; idx++) {
    const line = lines[idx]!;
    const withoutStrings = line.replace(/"(?:[^"\\]|\\.)*"/g, '""');
    const directSpawn = /^(?:spawn|burst|place)\s+(0[xX][0-9a-fA-F]+|\d+)\s+(?:at|on)\b/.exec(withoutStrings);
    if (directSpawn) {
      const id = Number(directSpawn[1]!);
      if (!Number.isInteger(id) || id < 0 || id > 67 || id === 2) return false;
      templates.add(id);
    }
    if (/^(?:spawn|burst|place)\b/.test(withoutStrings)) hasSpawn = true;
    for (const match of withoutStrings.matchAll(/\b(?:alien|spider|lizard|zombie|nest|formation|template)\.[A-Za-z_]\w*\b/g)) {
      const id = RECIPE_TEMPLATES[match[0].toLowerCase()];
      if (id === undefined) return false;
      templates.add(id);
    }
    for (const match of withoutStrings.matchAll(/\b(?:0[xX][0-9a-fA-F]+|\d+)(?!(?:\.\d|[eE]|ms\b|s\b|deg\b))\b/g)) {
      const id = Number(match[0]);
      if (Number.isInteger(id) && id >= 0 && id <= 67 && id !== 2) templates.add(id);
    }
  }
  return hasSpawn && templates.size > 0 && quest.entries.every((entry) => templates.has(entry.spawn_id));
}

export async function postRun(request: Request, env: Env, options: { requireCustomQuest?: boolean } = {}): Promise<Response> {
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY_BYTES) return refuse(413, "upload too large");
  const upload = parseUpload(await request.json().catch(() => null));
  if (upload === null) return refuse(400, "expected replay, and name, public_key and signature or signers");
  const file = base64(upload.replay);
  const keys = upload.signers.map((signer) => ({ publicKey: fromHex(signer.public_key, 32), signature: fromHex(signer.signature, 64) }));
  if (!file || keys.some(({ publicKey, signature }) => !publicKey || !signature)) return refuse(400, "malformed key, signature or replay");
  const names = upload.signers.map((signer) => latin1(signer.name));
  if (upload.signers.some((signer, i) => names[i] === null || signer.name.length > NAME_MAX_CHARS || [...names[i]!].some((code) => code < 0x20)))
    return refuse(422, `name must be at most ${NAME_MAX_CHARS} characters in 0x20..0xFF`);

  let replay: Replay;
  let payloadSha: Uint8Array;
  try {
    ({ replay, payloadSha } = await readReplay(file));
  } catch (error) {
    if (error instanceof ReplayError) return refuse(422, error.message);
    throw error;
  }
  if (options.requireCustomQuest && replay.run.custom_quest === null)
    return refuse(422, "expected a custom quest replay");
  if (upload.source !== null && (!options.requireCustomQuest || !replay.run.custom_quest || !validateRecipeSource(upload.source, replay.run.custom_quest)))
    return refuse(422, "recipe source does not match the replay's custom quest");
  if (replay.rules !== REPLAY_RULES)
    return refuse(422, `replay was recorded under rules ${replay.rules}; this service verifies rules ${REPLAY_RULES}`);
  const signersRefusal = signersReason(upload.signers, replay.run.player_count, replay.seat_keys);
  if (signersRefusal) return refuse(422, signersRefusal);
  for (const [i, signer] of upload.signers.entries()) {
    const message = upload.coop ? concat(COOP_RUN_DOMAIN, payloadSha, Uint8Array.of(signer.seat), names[i]!) : concat(RUN_DOMAIN, payloadSha, names[i]!);
    if (!(await verifyEd25519(keys[i]!.publicKey!, keys[i]!.signature!, message))) return refuse(401, "signature does not match");
  }
  const roomRefusal = await roomReason(env, replay);
  if (roomRefusal) return refuse(422, roomRefusal);
  // Signers in seat order: player one, whose account the run lists under, first.
  const seated = upload.signers.map((signer, i) => ({ ...signer, key: keys[i]!.publicKey! })).sort((a, b) => a.seat - b.seat);
  const owner = seated[0]!;

  const marks = seated.map(() => "?").join(", ");
  const banned = await env.DB.prepare(`SELECT 1 FROM keys WHERE public_key IN (${marks}) AND banned`).bind(...seated.map((signer) => signer.public_key)).first();
  if (banned) return refuse(403, "this key is banned");
  const reasons = [...unrankedReasons(replay.run), ...outcomeReasons(replay.run, replay.result)];
  if (reasons.length) return refuse(422, `not a ranked run: ${reasons.join(", ")}`);

  const transport = encodeTransport(replay);
  const runId = hex(await sha256(runIdentity(transport)));
  const custom = replay.run.custom_quest;
  const digest = custom ? await customQuestDigest(custom) : null;
  const quest = digest ? digest.slice(0, 12) : questOf(replay);
  const existingQuest = custom
    ? await env.DB.prepare("SELECT digest, account_id, source FROM custom_quests WHERE id = ?")
        .bind(quest)
        .first<{ digest: string; account_id: number | null; source: string | null }>()
    : null;
  if (existingQuest && existingQuest.digest !== digest) return refuse(409, "quest id collision");

  const existing = await env.DB.prepare("SELECT account_id FROM runs WHERE id = ?").bind(runId).first<{ account_id: number }>();
  if (existing) {
    if (options.requireCustomQuest && custom && digest && upload.source !== null) {
      const now = Date.now();
      const accountId = await accountForKey(env, owner.public_key, owner.key, now);
      if (existing.account_id !== accountId || (existingQuest && existingQuest.account_id !== accountId))
        return refuse(403, "only the quest's creator can attach its recipe");
      if (existingQuest && existingQuest.source !== null && existingQuest.source !== upload.source)
        return refuse(409, "this quest already has a recipe");
      await env.DB.prepare(
        `INSERT INTO custom_quests (id, digest, account_id, first_run_id, title, author, source, seed, definition, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           source = coalesce(custom_quests.source, excluded.source),
           seed = CASE WHEN custom_quests.source IS NULL AND excluded.source IS NOT NULL THEN excluded.seed ELSE custom_quests.seed END
         WHERE custom_quests.account_id = excluded.account_id AND custom_quests.digest = excluded.digest`,
      )
        .bind(quest, digest, accountId, runId, custom.title, custom.author, upload.source, upload.seed ?? 0, JSON.stringify(custom), now)
        .run();
      return json({ id: runId, board: "quests", quest, digest, url: `/custom/${quest}` }, 200);
    }
    return refuse(409, "this run was already accepted");
  }

  const { verdict, ground } = await verifyWithGround(env, new URL(request.url).origin, replay, transport);
  if (!verdict.ok) return refuse(422, verdict.reason);

  const board = rankedBoard(replay.run)!;

  const score = rankedScore(replay.run, replay.result);
  const now = Date.now();
  const accounts: number[] = [];
  for (const signer of seated) accounts.push(await accountForKey(env, signer.public_key, signer.key, now));
  const accountId = accounts[0]!;
  if (upload.source !== null && existingQuest) {
    if (existingQuest.account_id !== accountId) return refuse(403, "only the quest's creator can attach its recipe");
    if (existingQuest.source !== null && existingQuest.source !== upload.source) return refuse(409, "this quest already has a recipe");
  }
  await env.REPLAYS.put(`runs/${runId}.crd`, file, { httpMetadata: { contentType: "application/octet-stream" } });
  await putTimeline(env, runId, verdict.timeline);
  await putGround(env, runId, ground!);
  const statements = [
    env.DB.prepare(
      `INSERT INTO runs (id, payload_sha256, account_id, public_key, name, board, quest, score, game_version, client,
         client_version, platform, pilot, ticks, result, signals, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      runId, hex(payloadSha), accountId, owner.public_key, owner.name, board, quest, score, replay.game_version,
      replay.recorder.client, replay.recorder.version, replay.recorder.platform, replay.pilot ? JSON.stringify(replay.pilot) : "",
      replay.ticks.length, JSON.stringify(replay.result), JSON.stringify(verdict.signals), now,
    ),
    // A co-op run's seats; a one-player run has only its own columns.
    ...(seated.length > 1
      ? seated.map((signer, seat) =>
          env.DB.prepare("INSERT INTO run_players (run_id, seat, account_id, public_key, name) VALUES (?, ?, ?, ?, ?)")
            .bind(runId, seat, accounts[seat], signer.public_key, signer.name),
        )
      : []),
    ...seated.flatMap((signer, seat) => [
      env.DB.prepare("UPDATE accounts SET name = ? WHERE id = ?").bind(signer.name, accounts[seat]),
      env.DB.prepare(
        `INSERT INTO names (account_id, name, first_at, last_at) VALUES (?, ?, ?, ?)
         ON CONFLICT (account_id, name) DO UPDATE SET last_at = excluded.last_at`,
      ).bind(accounts[seat], signer.name, now, now),
    ]),
  ];
  if (custom && digest) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO custom_quests (id, digest, account_id, first_run_id, title, author, source, seed, definition, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           source = CASE WHEN custom_quests.account_id = excluded.account_id AND custom_quests.source IS NULL THEN excluded.source ELSE custom_quests.source END,
           seed = CASE WHEN custom_quests.account_id = excluded.account_id AND custom_quests.source IS NULL AND excluded.source IS NOT NULL THEN excluded.seed ELSE custom_quests.seed END
         WHERE custom_quests.digest = excluded.digest`,
      ).bind(quest, digest, accountId, runId, custom.title, custom.author, upload.source ?? null, upload.seed ?? 0, JSON.stringify(custom), now),
    );
  }
  try {
    await env.DB.batch(statements);
  } catch (error) {
    // Another upload of the run got there while this one verified: a co-op pair's pages each upload it at its end.
    if (await env.DB.prepare("SELECT 1 FROM runs WHERE id = ?").bind(runId).first()) return refuse(409, "this run was already accepted");
    throw error;
  }
  return json(custom ? { id: runId, board, quest, score, digest, url: `/custom/${quest}` } : { id: runId, board, quest, score }, 201);
}

export const timelineKey = (runId: string) => `runs/${runId}.timeline.json`;

const questOf = (replay: Replay) => (replay.run.quest_level ? `${replay.run.quest_level.major}.${replay.run.quest_level.minor}` : "");

// One run's ground bakes at a time in an isolate: its buffers (about 40 MB) would not fit beside another's.
let baking: Promise<unknown> = Promise.resolve();

// A run verified with its ground baked along, on the terrain its seed generates, as a JPEG (null when the run does not
// verify); scripts/reverify.mjs bakes every stored run's this way for a deploy. Only the JPEG outlives the call, so
// the bake's buffers are let go before anything waits on storage.
export function verifyWithGround(env: Env, origin: string, replay: Replay, transport: Uint8Array): Promise<{ verdict: Verdict; ground: Uint8Array | null }> {
  const run = baking.then(async () => {
    const terrain = runGround(replay.run.seed, {
      quest: questOf(replay),
      hardcore: replay.run.hardcore,
      customSlots: replay.run.custom_quest?.terrain_slots,
    });
    const bake = new GroundBake(terrain, await groundArt(env, origin), SIZE);
    const verdict = await verifyRun(env, replay, transport, (bakes) => bake.bake(bakes));
    return { verdict, ground: verdict.ok ? await encodeJpeg(bake.pixels()) : null };
  });
  baking = run.catch(() => {});
  return run;
}

async function putGround(env: Env, runId: string, jpeg: Uint8Array): Promise<Uint8Array> {
  await env.REPLAYS.put(groundKey(runId), jpeg, { httpMetadata: { contentType: "image/jpeg" } });
  return jpeg;
}

// A stored timeline's metadata key for why its run could not be replayed to bring it up to date.
export const STALE = "stale";

function putTimeline(env: Env, runId: string, timeline: Timeline, customMetadata?: Record<string, string>): Promise<R2Object> {
  return env.REPLAYS.put(timelineKey(runId), JSON.stringify(timeline), { httpMetadata: { contentType: "application/json" }, customMetadata });
}

// A run's input signals (src/signals.ts). Runs accepted before signals were measured get theirs the first time a
// moderator asks, by replaying their stored file; a run the verifier now refuses has those of the ticks before.
export async function signalsFor(env: Env, runId: string): Promise<Signals | null> {
  const run = await env.DB.prepare("SELECT signals FROM runs WHERE id = ?").bind(runId).first<{ signals: string | null }>();
  if (!run) return null;
  if (run.signals) return JSON.parse(run.signals) as Signals;
  const file = await env.REPLAYS.get(`runs/${runId}.crd`);
  if (!file) return null;
  const replay = decodeReplay(inflateReplay(new Uint8Array(await file.arrayBuffer())));
  const { signals } = await verifyRun(env, replay, encodeTransport(replay));
  await env.DB.prepare("UPDATE runs SET signals = ? WHERE id = ?").bind(JSON.stringify(signals), runId).run();
  return signals;
}

// The timeline of a run of `players` players. Runs accepted before timelines were recorded, and co-op runs recorded
// before timelines kept each player's own, get theirs the first time it is asked for, by replaying their stored file
// again. A stored one whose run no longer replays stays, marked (STALE) so later views serve it without trying again;
// views that arrive while the first replays each replay too, until one of them stores its result. Null when there is
// neither a timeline nor a replay.
export async function timelineFor(env: Env, runId: string, players: number): Promise<Timeline | null> {
  const object = await env.REPLAYS.get(timelineKey(runId));
  const stored = await object?.json<Timeline>();
  if (stored && ((stored.players?.length ?? 1) === players || object!.customMetadata?.[STALE] !== undefined)) return stored;
  const file = await env.REPLAYS.get(`runs/${runId}.crd`);
  if (!file) return stored ?? null;
  const replayed = await replayTimeline(env, file).catch((error: unknown) => {
    if (!stored) throw error;
    return String(error);
  });
  // Only a replay that fails marks the stored timeline; failing to store a new one leaves it for the next view.
  if (typeof replayed !== "string") {
    await putTimeline(env, runId, replayed);
    return replayed;
  }
  if (!stored) throw new Error(`run ${runId} no longer verifies: ${replayed}`);
  await putTimeline(env, runId, stored, { [STALE]: replayed });
  return stored;
}

// A stored replay's timeline, or why the verifier refuses it.
async function replayTimeline(env: Env, file: R2ObjectBody): Promise<Timeline | string> {
  const replay = decodeReplay(inflateReplay(new Uint8Array(await file.arrayBuffer())));
  const verdict = await verifyRun(env, replay, encodeTransport(replay));
  return verdict.ok ? verdict.timeline : verdict.reason;
}

// A run's ground as it ended (src/ground.ts), as a JPEG. Runs accepted before grounds were baked get theirs the first
// time it is asked for, by replaying their stored file again; null when there is no such replay.
export async function groundFor(env: Env, origin: string, runId: string): Promise<Uint8Array | null> {
  const stored = await env.REPLAYS.get(groundKey(runId));
  if (stored) return new Uint8Array(await stored.arrayBuffer());
  const file = await env.REPLAYS.get(`runs/${runId}.crd`);
  if (!file) return null;
  const replay = decodeReplay(inflateReplay(new Uint8Array(await file.arrayBuffer())));
  const { verdict, ground } = await verifyWithGround(env, origin, replay, encodeTransport(replay));
  if (!verdict.ok) throw new Error(`run ${runId} no longer verifies: ${verdict.reason}`);
  return putGround(env, runId, ground!);
}
