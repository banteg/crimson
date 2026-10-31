// Replay decoding and validation, a port of src/crimson/replay/codec.py (docs/formats/replay.md).
//
// Every rule here mirrors the Python codec, which records the replays; test/vectors.json, generated from it, keeps
// the two in step.

import { decompress } from "fzstd";
import { BUILDS } from "./api-types";
import { F64, Head, MapValue, PayloadError, Reader, type Value } from "./msgpack";

export const REPLAY_FORMAT_VERSION = 35;
// Each readable format's keys, in order. Format 30 had no `rules`, so its replays play under rules 1; formats before
// 32 had no `pilot`, so their runs declare none; format 33 adds `run.custom_quest` (RUN_KEYS); formats before 34 had
// no `seat_keys`, so their runs name no seat's key; formats before 35 had no `run.cl_build`, so their runs play 1.9.93.
type ReplayKey = "format_version" | "game_version" | "rules" | "recorder" | "pilot" | "seat_keys" | "run" | "result" | "ticks";
const REPLAY_KEYS: Record<number, readonly ReplayKey[]> = {
  30: ["format_version", "game_version", "recorder", "run", "result", "ticks"],
  31: ["format_version", "game_version", "rules", "recorder", "run", "result", "ticks"],
  32: ["format_version", "game_version", "rules", "recorder", "pilot", "run", "result", "ticks"],
  33: ["format_version", "game_version", "rules", "recorder", "pilot", "run", "result", "ticks"],
  34: ["format_version", "game_version", "rules", "recorder", "pilot", "seat_keys", "run", "result", "ticks"],
  35: ["format_version", "game_version", "rules", "recorder", "pilot", "seat_keys", "run", "result", "ticks"],
};
const RUN_KEYS = [
  "game_mode_id", "seed", "quest_level", "player_count", "hardcore", "preserve_bugs", "quest_fail_retry_count",
  "detail_preset", "violence_disabled", "friendly_fire", "status", "typo_dictionary_words",
  "typo_highscore_names", "typo_carry",
] as const;
const V30_RULES = 1;
// The original builds whose rules a run can play (src/crimson/cl_build.py ClBuild).
export const ClBuild = { V1_9_8: BUILDS["1.9.8"], V1_9_93: BUILDS["1.9.93"] } as const;
const CL_BUILDS = new Set<number>(Object.values(BUILDS));
// An Ed25519 public key's bytes (src/crimson/replay/types.py SEAT_KEY_BYTES).
export const SEAT_KEY_BYTES = 32;
// The bits of a run's seed the game reads: MSVC's rand never reads bit 31 of its state, so seeds s and s ^ 0x80000000
// play the same run.
export const SEED_BITS = 0x7fffffff;
// The simulation rules this service verifies (src/crimson/game_version.py REPLAY_RULES).
export const REPLAY_RULES = 2;
// The rules this service verifies: the first ranked runs' and the current ones.
export const VERIFIED_RULES = [1, REPLAY_RULES];
const MAX_FILE_BYTES = 65 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;
const MAX_WINDOW_BYTES = 8 * 1024 * 1024;
const ZSTD_MAGIC = [0x28, 0xb5, 0x2f, 0xfd];

export const GameMode = { SURVIVAL: 1, RUSH: 2, QUESTS: 3, TYPO: 4, TUTORIAL: 8 } as const;
const REPLAY_MODES = new Set<number>(Object.values(GameMode));
const SINGLE_PLAYER_MODES = new Set<number>([GameMode.TYPO, GameMode.TUTORIAL]);
const MODE_OUTCOMES: Record<number, Set<string>> = {
  [GameMode.SURVIVAL]: new Set(["death", "incomplete"]),
  [GameMode.RUSH]: new Set(["death", "incomplete"]),
  [GameMode.QUESTS]: new Set(["death", "quest_completed", "incomplete"]),
  [GameMode.TYPO]: new Set(["death", "incomplete"]),
  [GameMode.TUTORIAL]: new Set(["tutorial_completed", "incomplete"]),
};
const KNOWN_GAME_MODES = new Set([0, 1, 2, 3, 4, 8]);
const WEAPON_USAGE_SLOTS = 53;
const MAX_WEAPON_ID = 53;
const NAME_MAX_CHARS = 16;
const HIGHSCORE_NAME_MAX_CHARS = 31;
const MAX_TYPO_DICTIONARY_WORDS = 2048;
const MAX_TYPO_HIGHSCORE_NAMES = 512;
const RECORDER_FIELD_MAX_CHARS = 64;
// src/crimson/replay/codec.py PILOT_*_MAX_CHARS.
const PILOT_NAME_MAX_CHARS = 31;
const PILOT_FIELD_MAX_CHARS = 64;
const PILOT_URL_MAX_CHARS = 200;
const I32_MIN = -(2 ** 31);
const I32_MAX = 2 ** 31 - 1;
const U32_MAX = 2 ** 32 - 1;

// Input flag bits (src/crimson/replay/types.py).
export const Flags = {
  MOVE_KEYS_PRESENT: 1 << 3,
  MOVE_KEYS: (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7),
  MOVE_MODE_PRESENT: 1 << 8,
  MOVE_MODE_SHIFT: 9,
  AIM_SCHEME_PRESENT: 1 << 12,
  AIM_SCHEME_SHIFT: 13,
  MASK3: 0x7,
  SUPPORTED:
    (1 << 0) | (1 << 1) | (1 << 2) | (1 << 16) | (1 << 17) | (1 << 18) | (1 << 19) | (1 << 3) | (1 << 4) |
    (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (0x7 << 9) | (1 << 12) | (0x7 << 13),
} as const;
const AIM_SCHEMES = new Set([0, 1, 2, 3, 4, 5, 7]);

// A tick's movement scheme and aim scheme. Like Python's decoder, recordings without them ran static movement when they
// held movement keys, else the pad, with mouse aim; the 3-bit aim field stores the -1 scheme as all ones.
export function tickControls(flags: number): { moveMode: number; aimScheme: number } {
  const moveKeys = Boolean(flags & Flags.MOVE_KEYS_PRESENT);
  const moveMode = flags & Flags.MOVE_MODE_PRESENT ? (flags >>> Flags.MOVE_MODE_SHIFT) & Flags.MASK3 : moveKeys ? 2 : 3;
  const aimRaw = (flags >>> Flags.AIM_SCHEME_SHIFT) & Flags.MASK3;
  return { moveMode, aimScheme: flags & Flags.AIM_SCHEME_PRESENT ? (aimRaw === Flags.MASK3 ? -1 : aimRaw) : 0 };
}

export interface QuestLevel {
  major: number;
  minor: number;
}
export interface SpawnEntry {
  pos: { x: number; y: number };
  heading: number;
  spawn_id: number;
  trigger_ms: number;
  count: number;
}
export interface CustomQuest {
  title: string;
  author: string | null;
  start_weapon_id: number;
  terrain_slots: [number, number, number];
  entries: SpawnEntry[];
  no_bonuses: number[];
  no_perks: number[];
  no_weapons: number[];
}
export interface RunStatus {
  quest_unlock_index: number;
  quest_unlock_index_hardcore: number;
  weapon_usage_counts: number[];
}
export interface TypoCarry {
  target_world: { x: number; y: number } | null;
  submit_count: number;
  match_count: number;
  highscore_names_loaded: boolean;
}
export interface RunSpec {
  game_mode_id: number;
  seed: number;
  quest_level: QuestLevel | null;
  custom_quest: CustomQuest | null;
  player_count: number;
  hardcore: boolean;
  preserve_bugs: boolean;
  quest_fail_retry_count: number;
  detail_preset: number;
  violence_disabled: number;
  friendly_fire: boolean;
  status: RunStatus;
  typo_dictionary_words: string[];
  typo_highscore_names: string[];
  typo_carry: TypoCarry;
  // The original build whose rules the run plays (ClBuild).
  cl_build: number;
}
export interface PlayerResult {
  experience: number;
  health: number;
  most_used_weapon_id: number;
}
export interface RunResult {
  outcome: string;
  elapsed_ms: number;
  kills: number;
  shots_fired: number;
  shots_hit: number;
  rng_state: number;
  pending_perks: number;
  quest_final_ms: number | null;
  players: PlayerResult[];
}
export type PlayerInput = [number, number, number, number, number];
export type Command =
  | { type: "perk_menu_open"; player_index: number }
  | { type: "perk_pick"; player_index: number; choice_index: number }
  | { type: "typo_char"; player_index: number; ch: string }
  | { type: "typo_backspace"; player_index: number }
  | { type: "typo_submit"; player_index: number };
// A replay's ticks as columns, since a long run has a million: each player input's four axes and flag word, and the
// few commands by tick.
export class Ticks {
  constructor(
    readonly length: number,
    private readonly players: number,
    private readonly axes: Float32Array,
    private readonly flags: Uint32Array,
    readonly commands: Map<number, Command[]>,
  ) {}

  input(tick: number, player: number): PlayerInput {
    const at = tick * this.players + player;
    const axes = this.axes;
    return [axes[at * 4]!, axes[at * 4 + 1]!, axes[at * 4 + 2]!, axes[at * 4 + 3]!, this.flags[at]!];
  }
}
export interface Recorder {
  client: string;
  version: string;
  platform: string;
}
// The program that played the run, when the replay declares one (docs/rewrite/bots.md).
export interface Pilot {
  name: string;
  model: string;
  url: string;
}
export interface Replay {
  format_version: number;
  game_version: string;
  rules: number;
  recorder: Recorder;
  pilot: Pilot | null;
  // Each seat's Ed25519 public key, player one first, which the run's signatures must come from
  // (docs/rewrite/leaderboard-identity.md, "Co-op runs"); null when the replay names none.
  seat_keys: Uint8Array[] | null;
  run: RunSpec;
  result: RunResult;
  ticks: Ticks;
}

export class ReplayError extends Error {}

function require(condition: boolean, message: string): asserts condition {
  if (!condition) throw new ReplayError(message);
}

// The payload of a replay file, with the codec's file, window and payload ceilings.
export function inflateReplay(data: Uint8Array): Uint8Array {
  require(data.length <= MAX_FILE_BYTES, `replay file too large (> ${MAX_FILE_BYTES} bytes)`);
  require(ZSTD_MAGIC.every((byte, i) => data[i] === byte), "replay must use the zstd envelope");
  const frame = zstdFrame(data);
  require(frame.windowSize <= MAX_WINDOW_BYTES, `replay zstd frame window exceeds ${MAX_WINDOW_BYTES / 2 ** 20} MiB`);
  require(frame.contentSize !== null, "replay zstd frame must declare its content size");
  require(frame.contentSize <= MAX_PAYLOAD_BYTES, `replay payload too large (> ${MAX_PAYLOAD_BYTES} bytes)`);
  try {
    return decompress(data, new Uint8Array(frame.contentSize));
  } catch {
    throw new ReplayError("invalid replay zstd payload");
  }
}

// RFC 8878 frame header: the window and content sizes the frame declares.
function zstdFrame(data: Uint8Array): { windowSize: number; contentSize: number | null } {
  require(data.length >= 6, "invalid replay zstd payload");
  const descriptor = data[4]!;
  const fcsFlag = descriptor >> 6;
  const singleSegment = (descriptor >> 5) & 1;
  const dictionaryBytes = [0, 1, 2, 4][descriptor & 3]!;
  let at = 5;
  let windowSize = 0;
  if (!singleSegment) {
    const window = data[at++]!;
    const base = 2 ** (10 + (window >> 3));
    windowSize = base + (base / 8) * (window & 7);
  }
  at += dictionaryBytes;
  const fcsBytes = [singleSegment, 2, 4, 8][fcsFlag]!;
  let contentSize: number | null = null;
  if (fcsBytes) {
    require(data.length >= at + fcsBytes, "invalid replay zstd payload");
    contentSize = 0;
    for (let i = fcsBytes - 1; i >= 0; i--) contentSize = contentSize * 256 + data[at + i]!;
    if (fcsBytes === 2) contentSize += 256;
  }
  if (singleSegment) windowSize = contentSize ?? 0;
  return { windowSize, contentSize };
}

export function decodeReplay(payload: Uint8Array): Replay {
  let replay: Replay;
  try {
    replay = new Schema(new Reader(payload)).replay();
  } catch (error) {
    if (error instanceof PayloadError) throw new ReplayError(`invalid replay payload: ${error.message}`);
    throw error;
  }
  validateReplay(replay);
  return replay;
}

// The wire shape, as msgspec decodes it: maps with every key in declared order, typed and range-checked values. The
// ticks decode straight into their columns, the rest into values first.
class Schema {
  constructor(private readonly reader: Reader) {}

  replay(): Replay {
    const reader = this.reader;
    const head = reader.token();
    require(head instanceof Head && head.kind === "map", "replay must be a map");
    const version = head.length && reader.key() === "format_version" ? reader.value() : undefined;
    const names = typeof version === "number" ? REPLAY_KEYS[version] : undefined;
    require(
      names !== undefined,
      `unsupported replay format version: ${String(version)} (this build reads versions ${Object.keys(REPLAY_KEYS).join(", ")})`,
    );
    const order = `replay must have exactly the keys ${names!.join(", ")} in that order`;
    require(head.length === names!.length, order);
    // Every format has the run before the ticks, which take its player count.
    const fields: Partial<Record<ReplayKey, Value>> = {};
    let run: RunSpec | null = null;
    let ticks: Ticks | null = null;
    for (const name of names!.slice(1)) {
      require(reader.key() === name, order);
      if (name === "run") run = this.runSpec(reader.value(), version as number);
      else if (name === "ticks") ticks = this.ticks(run!.player_count);
      else fields[name] = reader.value();
    }
    if (!reader.done) throw new PayloadError("trailing bytes after the payload");
    const format_version = this.int(version!, "format_version");
    return {
      format_version,
      game_version: this.str(fields.game_version!, "game_version"),
      rules: format_version === 30 ? V30_RULES : this.int(fields.rules!, "rules"),
      recorder: this.recorder(fields.recorder!),
      pilot: format_version < 32 || fields.pilot === null ? null : this.pilot(fields.pilot!),
      seat_keys: format_version < 34 || fields.seat_keys === null ? null : this.seatKeys(fields.seat_keys!),
      run: run!,
      result: this.result(fields.result!),
      ticks: ticks!,
    };
  }

  // Each input is checked here, as validateReplay checks the rest: its axes are kept as f32.
  private ticks(players: number): Ticks {
    const count = this.length("array");
    require(count >= 0, "ticks must be an array");
    // The columns are sized from the count, so it must fit the bytes left: a tick takes at least its three headers
    // and, per input, a header, four float64 axes and a flag byte.
    require(count * (3 + players * 38) <= this.reader.remaining, "ticks are fewer than the array declares");
    const axes = new Float32Array(count * players * 4);
    const flags = new Uint32Array(count * players);
    const commands = new Map<number, Command[]>();
    for (let t = 0; t < count; t++) {
      if (this.length("array") !== 2) throw new ReplayError(`ticks[${t}] must be [inputs, commands]`);
      const inputs = this.length("array");
      if (inputs !== players)
        throw new ReplayError(inputs < 0 ? `ticks[${t}].inputs must be an array` : `ticks[${t}] has ${inputs} player inputs, expected ${players}`);
      for (let p = 0; p < players; p++) {
        if (this.length("array") !== 5) throw new ReplayError(`ticks[${t}].inputs[${p}] must have 5 values`);
        const at = t * players + p;
        for (let axis = 0; axis < 4; axis++) {
          const value = this.reader.float64();
          if (value === undefined) throw new ReplayError(`ticks[${t}].inputs[${p}][${axis}] must be a float64`);
          if (!Number.isFinite(value) || Math.fround(value) !== value) requireF32(value, `ticks[${t}].inputs[${p}][${axis}]`);
          axes[at * 4 + axis] = value;
        }
        const flag = this.reader.value();
        if (typeof flag !== "number") throw new ReplayError(`ticks[${t}].inputs[${p}][4] must be an integer`);
        const error = inputFlagsError(flag);
        if (error !== null) throw new ReplayError(`ticks[${t}].inputs[${p}].flags ${error}`);
        flags[at] = flag;
      }
      const commandCount = this.length("array");
      if (commandCount < 0) throw new ReplayError(`ticks[${t}].commands must be an array`);
      if (commandCount)
        commands.set(t, Array.from({ length: commandCount }, (_, c) => this.command(this.reader.value(), `ticks[${t}].commands[${c}]`)));
    }
    return new Ticks(count, players, axes, flags, commands);
  }

  // The length of the next array or map, or -1 when the next value is another kind.
  private length(kind: Head["kind"]): number {
    const token = this.reader.token();
    return token instanceof Head && token.kind === kind ? token.length : -1;
  }

  private recorder(value: Value): Recorder {
    const f = this.fields(value, "recorder", ["client", "version", "platform"]);
    return {
      client: this.str(f.client, "recorder.client"),
      version: this.str(f.version, "recorder.version"),
      platform: this.str(f.platform, "recorder.platform"),
    };
  }

  private pilot(value: Value): Pilot {
    const f = this.fields(value, "pilot", ["name", "model", "url"]);
    return { name: this.str(f.name, "pilot.name"), model: this.str(f.model, "pilot.model"), url: this.str(f.url, "pilot.url") };
  }

  private seatKeys(value: Value): Uint8Array[] {
    return this.array(value, "seat_keys").map((key, i) => {
      require(key instanceof Uint8Array, `seat_keys[${i}] must be bytes`);
      return key;
    });
  }

  private spawnEntries(value: Value, field: string): SpawnEntry[] {
    return this.array(value, field).map((entry, i) => {
      const e = this.fields(entry, `${field}[${i}]`, ["pos", "heading", "spawn_id", "trigger_ms", "count"]);
      const pos = this.fields(e.pos, `${field}[${i}].pos`, ["x", "y"]);
      return {
        pos: {
          x: this.float(pos.x, `${field}[${i}].pos.x`),
          y: this.float(pos.y, `${field}[${i}].pos.y`),
        },
        heading: this.float(e.heading, `${field}[${i}].heading`),
        spawn_id: this.int(e.spawn_id, `${field}[${i}].spawn_id`),
        trigger_ms: this.int(e.trigger_ms, `${field}[${i}].trigger_ms`),
        count: this.int(e.count, `${field}[${i}].count`),
      };
    });
  }

  private customQuest(value: Value): CustomQuest {
    require(value instanceof MapValue, "run.custom_quest must be a map");
    const keys = value.entries.map(([key]) => key);
    const legacy = keys.includes("tables");
    if (legacy) {
      const f = this.fields(value, "run.custom_quest", [
        "title", "author", "start_weapon_id", "terrain_slots", "tables", "variants",
      ]);
      const terrain = this.array(f.terrain_slots, "run.custom_quest.terrain_slots");
      require(terrain.length === 3, "run.custom_quest.terrain_slots must have 3 entries");
      const tables = this.array(f.tables, "run.custom_quest.tables").map((t, i) =>
        this.spawnEntries(t, `run.custom_quest.tables[${i}]`),
      );
      const variants = this.array(f.variants, "run.custom_quest.variants").map((v, i) =>
        this.int(v, `run.custom_quest.variants[${i}]`),
      );
      const used = [...new Set(variants)].sort((a, b) => a - b);
      require(
        variants.length === 8 && tables.length >= 1 && used.length === tables.length && used.every((idx, i) => idx === i),
        "run.custom_quest.variants must pick one of the tables for each of 8 variants",
      );
      return {
        title: this.str(f.title, "run.custom_quest.title"),
        author: f.author === null ? null : this.str(f.author, "run.custom_quest.author"),
        start_weapon_id: this.int(f.start_weapon_id, "run.custom_quest.start_weapon_id"),
        terrain_slots: [
          this.int(terrain[0]!, "run.custom_quest.terrain_slots[0]"),
          this.int(terrain[1]!, "run.custom_quest.terrain_slots[1]"),
          this.int(terrain[2]!, "run.custom_quest.terrain_slots[2]"),
        ],
        entries: tables[variants[0]!]!,
        no_bonuses: [],
        no_perks: [],
        no_weapons: [],
      };
    }
    const f = this.fields(value, "run.custom_quest", [
      "title", "author", "start_weapon_id", "terrain_slots", "entries", "no_bonuses", "no_perks", "no_weapons",
    ]);
    const terrain = this.array(f.terrain_slots, "run.custom_quest.terrain_slots");
    require(terrain.length === 3, "run.custom_quest.terrain_slots must have 3 entries");
    return {
      title: this.str(f.title, "run.custom_quest.title"),
      author: f.author === null ? null : this.str(f.author, "run.custom_quest.author"),
      start_weapon_id: this.int(f.start_weapon_id, "run.custom_quest.start_weapon_id"),
      terrain_slots: [
        this.int(terrain[0]!, "run.custom_quest.terrain_slots[0]"),
        this.int(terrain[1]!, "run.custom_quest.terrain_slots[1]"),
        this.int(terrain[2]!, "run.custom_quest.terrain_slots[2]"),
      ],
      entries: this.spawnEntries(f.entries, "run.custom_quest.entries"),
      no_bonuses: this.array(f.no_bonuses, "run.custom_quest.no_bonuses").map((id, i) =>
        this.int(id, `run.custom_quest.no_bonuses[${i}]`),
      ),
      no_perks: this.array(f.no_perks, "run.custom_quest.no_perks").map((id, i) =>
        this.int(id, `run.custom_quest.no_perks[${i}]`),
      ),
      no_weapons: this.array(f.no_weapons, "run.custom_quest.no_weapons").map((id, i) =>
        this.int(id, `run.custom_quest.no_weapons[${i}]`),
      ),
    };
  }

  private runSpec(value: Value, format: number): RunSpec {
    const f = this.fields(
      value, "run", format < 33 ? RUN_KEYS : format < 35 ? [...RUN_KEYS, "custom_quest"] : [...RUN_KEYS, "custom_quest", "cl_build"],
    );
    const game_mode_id = this.int(f.game_mode_id, "run.game_mode_id");
    require(KNOWN_GAME_MODES.has(game_mode_id), `run.game_mode_id ${game_mode_id} is not a game mode`);
    const cl_build = format < 35 ? ClBuild.V1_9_93 : this.int(f.cl_build!, "run.cl_build");
    require(CL_BUILDS.has(cl_build), `run.cl_build ${cl_build} is not a build`);
    let quest_level: QuestLevel | null = null;
    if (f.quest_level !== null) {
      const level = this.fields(f.quest_level, "run.quest_level", ["major", "minor"]);
      quest_level = {
        major: this.range(this.int(level.major, "run.quest_level.major"), 1, 5, "run.quest_level.major"),
        minor: this.range(this.int(level.minor, "run.quest_level.minor"), 1, 10, "run.quest_level.minor"),
      };
    }
    const custom_quest = format < 33 || f.custom_quest === null ? null : this.customQuest(f.custom_quest!);
    require(
      Number(quest_level !== null) + Number(custom_quest !== null) === (game_mode_id === GameMode.QUESTS ? 1 : 0),
      "quests need exactly one of run.quest_level and run.custom_quest; other modes need neither",
    );
    const status = this.fields(f.status, "run.status", [
      "quest_unlock_index", "quest_unlock_index_full", "weapon_usage_counts",
    ]);
    const usage = this.array(status.weapon_usage_counts, "run.status.weapon_usage_counts");
    require(usage.length === WEAPON_USAGE_SLOTS, `run.status.weapon_usage_counts must have ${WEAPON_USAGE_SLOTS} entries`);
    const carry = this.fields(f.typo_carry, "run.typo_carry", [
      "target_world", "submit_count", "match_count", "highscore_names_loaded",
    ]);
    let target_world = null;
    if (carry.target_world !== null) {
      const xy = this.fields(carry.target_world, "run.typo_carry.target_world", ["x", "y"]);
      target_world = { x: this.float(xy.x, "run.typo_carry.target_world.x"), y: this.float(xy.y, "run.typo_carry.target_world.y") };
    }
    return {
      game_mode_id,
      seed: this.int(f.seed, "run.seed"),
      quest_level,
      custom_quest,
      player_count: this.range(this.int(f.player_count, "run.player_count"), 1, 4, "run.player_count"),
      hardcore: this.bool(f.hardcore, "run.hardcore"),
      preserve_bugs: this.bool(f.preserve_bugs, "run.preserve_bugs"),
      quest_fail_retry_count: this.range(this.int(f.quest_fail_retry_count, "run.quest_fail_retry_count"), 0, Infinity, "run.quest_fail_retry_count"),
      detail_preset: this.range(this.int(f.detail_preset, "run.detail_preset"), 0, Infinity, "run.detail_preset"),
      violence_disabled: this.range(this.int(f.violence_disabled, "run.violence_disabled"), 0, Infinity, "run.violence_disabled"),
      friendly_fire: this.bool(f.friendly_fire, "run.friendly_fire"),
      status: {
        quest_unlock_index: this.int(status.quest_unlock_index, "run.status.quest_unlock_index"),
        quest_unlock_index_hardcore: this.int(status.quest_unlock_index_full, "run.status.quest_unlock_index_full"),
        weapon_usage_counts: usage.map((count, i) => this.int(count, `run.status.weapon_usage_counts[${i}]`)),
      },
      typo_dictionary_words: this.array(f.typo_dictionary_words, "run.typo_dictionary_words").map((w, i) =>
        this.str(w, `run.typo_dictionary_words[${i}]`),
      ),
      typo_highscore_names: this.array(f.typo_highscore_names, "run.typo_highscore_names").map((n, i) =>
        this.str(n, `run.typo_highscore_names[${i}]`),
      ),
      typo_carry: {
        target_world,
        submit_count: this.int(carry.submit_count, "run.typo_carry.submit_count"),
        match_count: this.int(carry.match_count, "run.typo_carry.match_count"),
        highscore_names_loaded: this.bool(carry.highscore_names_loaded, "run.typo_carry.highscore_names_loaded"),
      },
      cl_build,
    };
  }

  private result(value: Value): RunResult {
    const f = this.fields(value, "result", [
      "outcome", "elapsed_ms", "kills", "shots_fired", "shots_hit", "rng_state", "pending_perks", "quest_final_ms",
      "players",
    ]);
    const outcome = this.str(f.outcome, "result.outcome");
    require(["death", "quest_completed", "tutorial_completed", "incomplete"].includes(outcome), `result.outcome ${outcome} is invalid`);
    return {
      outcome,
      elapsed_ms: this.int(f.elapsed_ms, "result.elapsed_ms"),
      kills: this.int(f.kills, "result.kills"),
      shots_fired: this.int(f.shots_fired, "result.shots_fired"),
      shots_hit: this.int(f.shots_hit, "result.shots_hit"),
      rng_state: this.int(f.rng_state, "result.rng_state"),
      pending_perks: this.int(f.pending_perks, "result.pending_perks"),
      quest_final_ms: f.quest_final_ms === null ? null : this.int(f.quest_final_ms, "result.quest_final_ms"),
      players: this.array(f.players, "result.players").map((player, i) => {
        const p = this.fields(player, `result.players[${i}]`, ["experience", "health", "most_used_weapon_id"]);
        return {
          experience: this.int(p.experience, `result.players[${i}].experience`),
          health: this.float(p.health, `result.players[${i}].health`),
          most_used_weapon_id: this.range(
            this.int(p.most_used_weapon_id, `result.players[${i}].most_used_weapon_id`), 0, MAX_WEAPON_ID,
            `result.players[${i}].most_used_weapon_id`,
          ),
        };
      }),
    };
  }

  private command(value: Value, field: string): Command {
    require(value instanceof MapValue && value.entries[0]?.[0] === "type", `${field} must be a command map`);
    const type = this.str(value.entries[0]![1], `${field}.type`);
    switch (type) {
      case "perk_menu_open":
      case "typo_backspace":
      case "typo_submit": {
        const f = this.fields(value, field, ["type", "player_index"]);
        return { type, player_index: this.int(f.player_index, `${field}.player_index`) };
      }
      case "perk_pick": {
        const f = this.fields(value, field, ["type", "player_index", "choice_index"]);
        return {
          type,
          player_index: this.int(f.player_index, `${field}.player_index`),
          choice_index: this.int(f.choice_index, `${field}.choice_index`),
        };
      }
      case "typo_char": {
        const f = this.fields(value, field, ["type", "player_index", "ch"]);
        const ch = this.str(f.ch, `${field}.ch`);
        require([...ch].length === 1, `${field}.ch must be one character`);
        return { type, player_index: this.int(f.player_index, `${field}.player_index`), ch };
      }
      default:
        throw new ReplayError(`${field}.type ${JSON.stringify(type)} is not a command`);
    }
  }

  private fields<const K extends string>(value: Value, field: string, names: readonly K[]): Record<K, Value> {
    require(value instanceof MapValue, `${field} must be a map`);
    const keys = value.entries.map(([key]) => key);
    require(
      keys.length === names.length && keys.every((key, i) => key === names[i]),
      `${field} must have exactly the keys ${names.join(", ")} in that order`,
    );
    return Object.fromEntries(value.entries) as Record<K, Value>;
  }

  private int(value: Value, field: string): number {
    require(typeof value === "number", `${field} must be an integer`);
    return value;
  }

  private float(value: Value, field: string): number {
    require(value instanceof F64, `${field} must be a float64`);
    return value.value;
  }

  private bool(value: Value, field: string): boolean {
    require(typeof value === "boolean", `${field} must be a boolean`);
    return value;
  }

  private str(value: Value, field: string): string {
    require(typeof value === "string", `${field} must be a string`);
    return value;
  }

  private array(value: Value, field: string): Value[] {
    require(Array.isArray(value), `${field} must be an array`);
    return value;
  }

  private range(value: number, low: number, high: number, field: string): number {
    require(low <= value && value <= high, `${field} must be in ${low}..${high}`);
    return value;
  }
}

function requireInt(value: number, low: number, high: number, field: string): void {
  require(low <= value && value <= high, `${field} must be in ${low}..${high}`);
}

function requireF32(value: number, field: string): void {
  require(Number.isFinite(value), `${field} must be finite`);
  require(Math.fround(value) === value, `${field} must be a canonical f32`);
}

export function inputFlagsError(value: number): string | null {
  if (value < 0 || value > U32_MAX || (value & ~Flags.SUPPORTED) !== 0) return "contain unsupported bits";
  if (!(value & Flags.MOVE_KEYS_PRESENT) && value & Flags.MOVE_KEYS) return "set movement-key values without MOVE_KEYS_PRESENT";
  const moveMode = (value >>> Flags.MOVE_MODE_SHIFT) & Flags.MASK3;
  if (!(value & Flags.MOVE_MODE_PRESENT) && moveMode !== 0) return "set a movement mode without MOVE_MODE_PRESENT";
  if (value & Flags.MOVE_MODE_PRESENT && moveMode > 5) return "contain an invalid movement mode";
  const aimScheme = (value >>> Flags.AIM_SCHEME_SHIFT) & Flags.MASK3;
  if (!(value & Flags.AIM_SCHEME_PRESENT) && aimScheme !== 0) return "set an aim scheme without AIM_SCHEME_PRESENT";
  if (value & Flags.AIM_SCHEME_PRESENT && !AIM_SCHEMES.has(aimScheme)) return "contain an invalid aim scheme";
  return null;
}

const isPrintableAscii = (text: string) => [...text].every((ch) => ch >= " " && ch <= "~");
const isHighscoreName = (text: string) => /^[A-Za-z.]+$/.test(text) && text.length <= HIGHSCORE_NAME_MAX_CHARS;

function requireAscending(values: number[], low: number, high: number, field: string): void {
  let prev = low - 1;
  for (const value of values) {
    require(value > prev && value <= high, `${field} must be strictly ascending IDs in ${low}..${high}`);
    prev = value;
  }
}

export function validateCustomQuest(quest: CustomQuest): void {
  require(quest.title.length >= 1 && quest.title.length <= 64 && isPrintableAscii(quest.title), "run.custom_quest: title must be 1..64 printable ASCII characters");
  if (quest.author !== null)
    require(quest.author.length >= 1 && quest.author.length <= 31 && isPrintableAscii(quest.author), "run.custom_quest: author must be 1..31 printable ASCII characters");
  const w = quest.start_weapon_id;
  require(w >= 1 && w <= MAX_WEAPON_ID && (w < 34 || w > 40) && (w < 46 || w > 49), "run.custom_quest: a custom quest needs a starting weapon");
  require(quest.terrain_slots.every((slot) => slot >= 0 && slot <= 7), "run.custom_quest: terrain slots must be in 0..7");
  requireAscending(quest.no_bonuses, 2, 14, "run.custom_quest: no_bonuses");
  requireAscending(quest.no_perks, 1, 57, "run.custom_quest: no_perks");
  require(!quest.no_perks.includes(7), "run.custom_quest: no_perks cannot disable instant_winner");
  requireAscending(quest.no_weapons, 2, 33, "run.custom_quest: no_weapons");
  require(quest.entries.length >= 1 && quest.entries.length <= 256, "run.custom_quest: a table holds 1..256 entries");
  const perTrigger = new Map<number, number>();
  let total = 0;
  for (const entry of quest.entries) {
    require(entry.spawn_id >= 0 && entry.spawn_id <= 0x43 && entry.spawn_id !== 2, "run.custom_quest: unused spawn template");
    require(entry.trigger_ms >= 0 && entry.trigger_ms <= 3600000, "run.custom_quest: trigger times must be in 0..3600000 ms");
    for (const coord of [entry.pos.x, entry.pos.y]) {
      require(coord >= -1024 && coord <= 2048, "run.custom_quest: positions must be in -1024..2048");
      requireF32(coord, "run.custom_quest: positions");
    }
    requireF32(entry.heading, "run.custom_quest: headings");
    require(entry.count >= 1 && entry.count <= 384, "run.custom_quest: copies must be in 1..384");
    const copies = (perTrigger.get(entry.trigger_ms) ?? 0) + entry.count;
    require(copies <= 384, "run.custom_quest: copies exceed the per-trigger copy limit");
    perTrigger.set(entry.trigger_ms, copies);
    total += entry.count;
  }
  require(total <= 8192, "run.custom_quest: total copies exceed the quest copy limit");
}
export function validateReplay(replay: Replay): void {
  require(Boolean(replay.game_version), "game_version must be non-empty");
  require(replay.rules >= 1, "rules must be at least 1");
  // 1.9.8 rules arrived with rules 2; no earlier profile plays them.
  require(replay.run.cl_build === ClBuild.V1_9_93 || replay.rules >= 2, "1.9.8 rules need rules 2");
  for (const field of ["client", "version", "platform"] as const) {
    const value = replay.recorder[field];
    require(
      value.length > 0 && value.length <= RECORDER_FIELD_MAX_CHARS && isPrintableAscii(value),
      `recorder.${field} must be 1..${RECORDER_FIELD_MAX_CHARS} printable ASCII characters`,
    );
  }
  const pilot = replay.pilot;
  if (pilot) {
    require(
      pilot.name.length > 0 && pilot.name.length <= PILOT_NAME_MAX_CHARS && isPrintableAscii(pilot.name),
      `pilot.name must be 1..${PILOT_NAME_MAX_CHARS} printable ASCII characters`,
    );
    require(
      pilot.model.length <= PILOT_FIELD_MAX_CHARS && isPrintableAscii(pilot.model),
      `pilot.model must be at most ${PILOT_FIELD_MAX_CHARS} printable ASCII characters`,
    );
    require(
      !pilot.url || (pilot.url.startsWith("https://") && pilot.url.length <= PILOT_URL_MAX_CHARS && isPrintableAscii(pilot.url)),
      `pilot.url must be empty or an https:// URL of at most ${PILOT_URL_MAX_CHARS} printable ASCII characters`,
    );
  }
  const run = replay.run;
  if (replay.seat_keys !== null) {
    const keys = replay.seat_keys;
    require(keys.length === run.player_count, `seat_keys has ${keys.length} entries, expected ${run.player_count}`);
    keys.forEach((key, i) => require(key.length === SEAT_KEY_BYTES, `seat_keys[${i}] must be ${SEAT_KEY_BYTES} bytes`));
    require(new Set(keys.map((key) => key.join())).size === keys.length, "seat_keys must be distinct");
  }
  const mode = run.game_mode_id;
  require(REPLAY_MODES.has(mode), `run.game_mode_id ${mode} is not a replayable mode`);
  requireInt(run.seed, 0, U32_MAX, "run.seed");
  require(
    Number(run.quest_level !== null) + Number(run.custom_quest !== null) === (mode === GameMode.QUESTS ? 1 : 0),
    "quests need exactly one of run.quest_level and run.custom_quest; other modes need neither",
  );
  if (run.custom_quest !== null) {
    require(!run.hardcore, "custom quests do not use hardcore");
    validateCustomQuest(run.custom_quest);
  }
  require(!SINGLE_PLAYER_MODES.has(mode) || run.player_count === 1, "typo and tutorial replays require player_count == 1");
  requireInt(run.quest_fail_retry_count, 0, I32_MAX, "run.quest_fail_retry_count");
  requireInt(run.detail_preset, 1, 5, "run.detail_preset");
  requireInt(run.violence_disabled, 0, 0xff, "run.violence_disabled");
  requireInt(run.status.quest_unlock_index, I32_MIN, I32_MAX, "run.status.quest_unlock_index");
  requireInt(run.status.quest_unlock_index_hardcore, I32_MIN, I32_MAX, "run.status.quest_unlock_index_hardcore");
  run.status.weapon_usage_counts.forEach((count, i) => requireInt(count, 0, U32_MAX, `run.status.weapon_usage_counts[${i}]`));
  require(run.typo_dictionary_words.length <= MAX_TYPO_DICTIONARY_WORDS, "run.typo_dictionary_words has too many entries");
  run.typo_dictionary_words.forEach((word, i) =>
    require(word.length > 0 && word.length < NAME_MAX_CHARS && isPrintableAscii(word), `run.typo_dictionary_words[${i}] is invalid`),
  );
  require(run.typo_highscore_names.length <= MAX_TYPO_HIGHSCORE_NAMES, "run.typo_highscore_names has too many entries");
  run.typo_highscore_names.forEach((name, i) => require(isHighscoreName(name), `run.typo_highscore_names[${i}] is invalid`));
  const carry = run.typo_carry;
  const carryIsDefault =
    carry.target_world === null && carry.submit_count === 0 && carry.match_count === 0 && !carry.highscore_names_loaded;
  require(mode === GameMode.TYPO || carryIsDefault, "run.typo_carry is set only for typo");
  if (carry.target_world !== null) {
    requireF32(carry.target_world.x, "run.typo_carry.target_world.x");
    requireF32(carry.target_world.y, "run.typo_carry.target_world.y");
  }
  requireInt(carry.submit_count, 0, I32_MAX, "run.typo_carry.submit_count");
  requireInt(carry.match_count, 0, carry.submit_count, "run.typo_carry.match_count");

  const result = replay.result;
  require(MODE_OUTCOMES[mode]!.has(result.outcome), `result.outcome ${result.outcome} is invalid for this mode`);
  require((result.quest_final_ms !== null) === (result.outcome === "quest_completed"), "result.quest_final_ms must be set only for completed quests");
  requireInt(result.rng_state, 0, U32_MAX, "result.rng_state");
  require(result.players.length === run.player_count, `result.players has ${result.players.length} entries, expected ${run.player_count}`);
  result.players.forEach((player, i) => requireF32(player.health, `result.players[${i}].health`));

  require(replay.ticks.length > 0, "replay must contain at least one tick");
  replay.ticks.commands.forEach((commands, t) => {
    commands.forEach((command, c) => {
      const field = `ticks[${t}].commands[${c}]`;
      require(0 <= command.player_index && command.player_index < run.player_count, `${field}.player_index is out of range`);
      if (command.type === "perk_pick") requireInt(command.choice_index, 0, 6, `${field}.choice_index`);
      require(!command.type.startsWith("typo_") || mode === GameMode.TYPO, `${field} Typ-o commands require game_mode_id=TYPO`);
    });
  });
}
