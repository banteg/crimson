// POST /api/runs: a signed ranked run (docs/rewrite/leaderboard-identity.md, "Protocol").

import { concat, fromHex, hex, latin1, RUN_DOMAIN, sha256, verifyEd25519 } from "./crypto";
import { accountForKey, type Env, json, refuse } from "./http";
import { outcomeReasons, rankedBoard, rankedScore, unrankedReasons } from "./ranked";
import type { Signals, Timeline } from "./api-types";
import { type CustomQuest, decodeReplay, inflateReplay, type Replay, REPLAY_RULES, ReplayError } from "./replay";
import { GroundBake, groundArt, groundKey } from "./ground";
import { encodeJpeg } from "./jpeg";
import { encodePortableQuest, encodeTransport } from "./transport";
import questDsl from "./quest-dsl.json";
import { runGround, SIZE } from "../web/src/terrain/rules";
import { type Verdict, verifyRun } from "./verify";

const MAX_BODY_BYTES = 16 * 1024 * 1024;
const NAME_MAX_CHARS = 31;

interface Upload {
  replay: string;
  name: string;
  public_key: string;
  signature: string;
  source: string | null;
  seed: number;
}

function parseUpload(body: unknown): Upload | null {
  if (typeof body !== "object" || body === null) return null;
  const { replay, name, public_key, signature, source, seed } = body as Record<string, unknown>;
  if ([replay, name, public_key, signature].some((field) => typeof field !== "string")) return null;
  if (source !== undefined && source !== null && (typeof source !== "string" || source.length === 0 || source.length > 65536))
    return null;
  if (seed !== undefined && (typeof seed !== "number" || !Number.isInteger(seed) || seed < 0 || seed > 0xffffffff))
    return null;
  return {
    replay: replay as string,
    name: name as string,
    public_key: public_key as string,
    signature: signature as string,
    source: typeof source === "string" ? source : null,
    seed: typeof seed === "number" ? seed : 0,
  };
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
    noBonuses.add(3);
    noPerks.add(9);
    noPerks.add(16);
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
  if (upload === null) return refuse(400, "expected replay, name, public_key and signature");
  const publicKey = fromHex(upload.public_key, 32);
  const signature = fromHex(upload.signature, 64);
  const file = base64(upload.replay);
  const name = latin1(upload.name);
  if (!publicKey || !signature || !file) return refuse(400, "malformed key, signature or replay");
  if (name === null || upload.name.length > NAME_MAX_CHARS || [...name].some((code) => code < 0x20))
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
  if (!(await verifyEd25519(publicKey, signature, concat(RUN_DOMAIN, payloadSha, name))))
    return refuse(401, "signature does not match");

  const key = await env.DB.prepare("SELECT banned FROM keys WHERE public_key = ?").bind(upload.public_key).first<{ banned: number }>();
  if (key?.banned) return refuse(403, "this key is banned");
  const reasons = [...unrankedReasons(replay.run), ...outcomeReasons(replay.run, replay.result)];
  if (reasons.length) return refuse(422, `not a ranked run: ${reasons.join(", ")}`);

  const transport = encodeTransport(replay);
  const runId = hex(await sha256(transport));
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
      const accountId = await accountForKey(env, upload.public_key, publicKey, now);
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
  const accountId = await accountForKey(env, upload.public_key, publicKey, now);
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
      runId, hex(payloadSha), accountId, upload.public_key, upload.name, board, quest, score, replay.game_version,
      replay.recorder.client, replay.recorder.version, replay.recorder.platform, replay.pilot ? JSON.stringify(replay.pilot) : "",
      replay.ticks.length, JSON.stringify(replay.result), JSON.stringify(verdict.signals), now,
    ),
    env.DB.prepare("UPDATE accounts SET name = ? WHERE id = ?").bind(upload.name, accountId),
    env.DB.prepare(
      `INSERT INTO names (account_id, name, first_at, last_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (account_id, name) DO UPDATE SET last_at = excluded.last_at`,
    ).bind(accountId, upload.name, now, now),
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
  await env.DB.batch(statements);
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
      board: rankedBoard(replay.run)!,
      quest: questOf(replay),
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

function putTimeline(env: Env, runId: string, timeline: Timeline): Promise<R2Object> {
  return env.REPLAYS.put(timelineKey(runId), JSON.stringify(timeline), { httpMetadata: { contentType: "application/json" } });
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

// A run's timeline. Runs accepted before timelines were recorded get theirs the first time it is asked for, by
// replaying their stored file again; null when there is no such replay.
export async function timelineFor(env: Env, runId: string): Promise<Timeline | null> {
  const stored = await env.REPLAYS.get(timelineKey(runId));
  if (stored) return stored.json<Timeline>();
  const file = await env.REPLAYS.get(`runs/${runId}.crd`);
  if (!file) return null;
  const replay = decodeReplay(inflateReplay(new Uint8Array(await file.arrayBuffer())));
  const verdict = await verifyRun(env, replay, encodeTransport(replay));
  if (!verdict.ok) throw new Error(`run ${runId} no longer verifies: ${verdict.reason}`);
  await putTimeline(env, runId, verdict.timeline);
  return verdict.timeline;
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
