// POST /api/runs: a signed ranked run (docs/rewrite/leaderboard-identity.md, "Protocol").

import { concat, fromHex, hex, latin1, RUN_DOMAIN, sha256, verifyEd25519 } from "./crypto";
import { accountForKey, type Env, json, refuse } from "./http";
import { outcomeReasons, rankedBoard, rankedScore, unrankedReasons } from "./ranked";
import type { Signals, Timeline } from "./api-types";
import { type CustomQuest, decodeReplay, inflateReplay, type Replay, REPLAY_RULES, ReplayError } from "./replay";
import { GroundBake, groundArt, groundKey } from "./ground";
import { encodeJpeg } from "./jpeg";
import { encodePortableQuest, encodeTransport } from "./transport";
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

const RECIPE_WEAPONS: Record<string, number> = {
  pistol: 1, assault_rifle: 2, shotgun: 3, sawed_off_shotgun: 4, submachine_gun: 5, gauss_gun: 6, mean_minigun: 7,
  flamethrower: 8, plasma_rifle: 9, multi_plasma: 10, plasma_minigun: 11, rocket_launcher: 12, seeker_rockets: 13,
  plasma_shotgun: 14, blow_torch: 15, hr_flamer: 16, mini_rocket_swarmers: 17, rocket_minigun: 18, pulse_gun: 19,
  jackhammer: 20, ion_rifle: 21, ion_minigun: 22, ion_cannon: 23, shrinkifier_5k: 24, blade_gun: 25, spider_plasma: 26,
  evil_scythe: 27, plasma_cannon: 28, splitter_gun: 29, gauss_shotgun: 30, ion_shotgun: 31, flameburst: 32, raygun: 33,
  plague_spreader_gun: 41, bubblegun: 42, rainbow_gun: 43, grim_weapon: 44, fire_bullets: 45, transmutator: 50,
  blaster_r_300: 51, lightning_rifle: 52, nuke_launcher: 53,
};
const RECIPE_BONUSES: Record<string, number> = {
  energizer: 2, weapon: 3, weapon_power_up: 4, nuke: 5, double_experience: 6, shock_chain: 7, fireblast: 8,
  reflex_boost: 9, shield: 10, freeze: 11, medikit: 12, speed: 13, fire_bullets: 14,
};
const RECIPE_PERKS: Record<string, number> = {
  bloody_mess_quick_learner: 1, bloody_mess: 1, quick_learner: 1, sharpshooter: 2, fastloader: 3,
  lean_mean_exp_machine: 4, long_distance_runner: 5, pyrokinetic: 6, grim_deal: 8, alternate_weapon: 9,
  plaguebearer: 10, evil_eyes: 11, ammo_maniac: 12, radioactive: 13, fastshot: 14, fatal_lottery: 15,
  random_weapon: 16, mr_melee: 17, anxious_loader: 18, final_revenge: 19, telekinetic: 20, perk_expert: 21,
  unstoppable: 22, regression_bullets: 23, infernal_contract: 24, poison_bullets: 25, dodger: 26, bonus_magnet: 27,
  uranium_filled_bullets: 28, doctor: 29, monster_vision: 30, hot_tempered: 31, bonus_economist: 32, thick_skinned: 33,
  barrel_greaser: 34, ammunition_within: 35, veins_of_poison: 36, toxic_avenger: 37, regeneration: 38, pyromaniac: 39,
  ninja: 40, highlander: 41, jinxed: 42, perk_master: 43, reflex_boosted: 44, greater_regeneration: 45,
  breathing_room: 46, death_clock: 47, my_favourite_weapon: 48, bandage: 49, angry_reloader: 50, ion_gun_master: 51,
  stationary_reloader: 52, man_bomb: 53, fire_caugh: 54, living_fortress: 55, tough_reloader: 56, lifeline_50_50: 57,
};
const RECIPE_TEMPLATES: Record<string, number> = {
  "alien.small_gray": 38, "alien.fast": 43, "alien.small_green": 37, "alien.green": 36, "alien.purple": 40,
  "alien.big_gray": 41, "alien.gray_fast": 42, "alien.boss": 44, "alien.cyan": 45, "alien.ghost": 15,
  "alien.bonus_carrier": 39, "alien.delayed": 54, "alien.flanker": 26, "alien.spawner_ring": 14, "alien.random": 6,
  "spider.small_blue": 64, "spider.plasma": 60, "spider.splitter": 1, "spider.boss": 58, "spider.red_boss": 59,
  "spider.white_fast": 62, "spider.small_brown": 63, "spider.ranged": 55, "spider.stop_and_go": 56,
  "spider.stop_and_go_weak": 57, "spider.flanker": 27, "spider.random": 3, "spider.random_red": 51,
  "spider.random_green": 52, "lizard.gray": 47, "lizard.boss": 48, "lizard.flanker": 28, "lizard.random": 4,
  "zombie.random": 65, "zombie.spawner_boss": 0, "zombie.small_white": 66, "zombie.brute": 67, "nest.alien": 7,
  "nest.alien_slow": 8, "nest.alien_weak": 9, "nest.spider": 10, "nest.plasma": 11, "nest.spider_weak": 16,
  "nest.lizard": 12, "nest.lizard_slow": 13, "formation.alien_ring": 18, "formation.alien_ring_small": 25,
  "formation.alien_chain": 19, "formation.lizard_chain": 17, "formation.alien_grid": 21,
  "formation.alien_grid_green": 20, "formation.alien_grid_bronze": 24, "formation.lizard_grid": 22,
  "formation.spider_grid": 23, "template.zombie_boss_spawner_00": 0, "template.spider_sp2_splitter_01": 1,
  "template.spider_sp1_random_03": 3, "template.lizard_random_04": 4, "template.spider_sp2_random_05": 5,
  "template.alien_random_06": 6, "template.den_alien_basic_07": 7, "template.den_alien_basic_slower_08": 8,
  "template.den_alien_weak_small_09": 9, "template.den_spider_basic_0a": 10,
  "template.den_spider_plasma_shooters_0b": 11, "template.den_lizard_weak_0c": 12,
  "template.den_lizard_weak_slower_0d": 13, "template.alien_spawner_ring_24_0e": 14, "template.alien_ghost_0f": 15,
  "template.den_spider_weak_10": 16, "template.formation_chain_lizard_4_11": 17,
  "template.formation_ring_alien_8_12": 18, "template.formation_chain_alien_10_13": 19,
  "template.formation_grid_alien_green_14": 20, "template.formation_grid_alien_white_15": 21,
  "template.formation_grid_lizard_white_16": 22, "template.formation_grid_spider_sp1_white_17": 23,
  "template.formation_grid_alien_bronze_18": 24, "template.formation_ring_alien_5_19": 25,
  "template.ai1_alien_blue_tint_1a": 26, "template.ai1_spider_sp1_blue_tint_1b": 27,
  "template.ai1_lizard_blue_tint_1c": 28, "template.alien_random_1d": 29, "template.alien_random_1e": 30,
  "template.alien_random_1f": 31, "template.alien_random_green_20": 32, "template.alien_hidden_1_21": 33,
  "template.alien_hidden_2_22": 34, "template.alien_hidden_3_23": 35, "template.alien_const_green_24": 36,
  "template.alien_small_green_man_25": 37, "template.alien_small_gray_26": 38, "template.alien_bonus_carrier_27": 39,
  "template.alien_const_purple_28": 40, "template.alien_big_gray_29": 41, "template.alien_const_grey_fast_2a": 42,
  "template.alien_deadly_fast_2b": 43, "template.alien_const_red_boss_2c": 44, "template.alien_const_cyan_ai2_2d": 45,
  "template.lizard_random_2e": 46, "template.lizard_const_grey_2f": 47, "template.lizard_const_yellow_boss_30": 48,
  "template.lizard_random_31": 49, "template.spider_sp1_random_32": 50, "template.spider_sp1_random_red_33": 51,
  "template.spider_sp1_random_green_34": 52, "template.spider_sp2_random_35": 53, "template.alien_delayed_start_36": 54,
  "template.spider_sp2_ranged_variant_37": 55, "template.spider_sp1_stop_and_go_38": 56,
  "template.spider_sp1_stop_and_go_weak_39": 57, "template.spider_boss_3a": 58,
  "template.spider_sp1_const_red_boss_3b": 59, "template.spider_plasma_shooter_3c": 60,
  "template.spider_sp1_random_3d": 61, "template.spider_sp1_const_white_fast_3e": 62,
  "template.spider_sp1_const_brown_small_3f": 63, "template.spider_small_blue_40": 64, "template.zombie_random_41": 65,
  "template.zombie_small_white_42": 66, "template.zombie_const_green_brute_43": 67,
};

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
    while ((line.split("[").length - line.split("]").length > 0 || line.split("(").length - line.split(")").length > 0) && i + 1 < rawLines.length) {
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
    if (/^(?:spawn|burst|place)\b/.test(withoutStrings)) hasSpawn = true;
    for (const match of withoutStrings.matchAll(/\b(?:alien|spider|lizard|zombie|nest|formation|template)\.[A-Za-z_]\w*\b/g)) {
      const id = RECIPE_TEMPLATES[match[0].toLowerCase()];
      if (id === undefined) return false;
      templates.add(id);
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
        .first<{ digest: string; account_id: number; source: string | null }>()
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
      return json({ id: runId, board: "quests", quest, digest, url: `/q/${quest}` }, 200);
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
  return json(custom ? { id: runId, board, quest, score, digest, url: `/q/${quest}` } : { id: runId, board, quest, score }, 201);
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
