// Replay decoding and validation, a port of src/crimson/replay/codec.py (docs/formats/replay.md).
//
// Every rule here mirrors the Python codec, which records the replays; test/vectors.json, generated from it, keeps
// the two in step.

import { decompress } from "fzstd";
import { F64, MapValue, PayloadError, readPayload, type Value } from "./msgpack";

export const REPLAY_FORMAT_VERSION = 31;
// Each readable format's keys, in order. Format 30 had no `rules`; its replays play under rules 1.
type ReplayKey = "format_version" | "game_version" | "rules" | "recorder" | "run" | "result" | "ticks";
const REPLAY_KEYS: Record<number, readonly ReplayKey[]> = {
  30: ["format_version", "game_version", "recorder", "run", "result", "ticks"],
  31: ["format_version", "game_version", "rules", "recorder", "run", "result", "ticks"],
};
const V30_RULES = 1;
// The simulation rules this service verifies (src/crimson/replay/types.py REPLAY_RULES).
export const REPLAY_RULES = 1;
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

export interface QuestLevel {
  major: number;
  minor: number;
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
export interface Tick {
  inputs: PlayerInput[];
  commands: Command[];
}
export interface Recorder {
  client: string;
  version: string;
  platform: string;
}
export interface Replay {
  format_version: number;
  game_version: string;
  rules: number;
  recorder: Recorder;
  run: RunSpec;
  result: RunResult;
  ticks: Tick[];
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
  let wire: Value;
  try {
    wire = readPayload(payload);
  } catch (error) {
    if (error instanceof PayloadError) throw new ReplayError(`invalid replay payload: ${error.message}`);
    throw error;
  }
  const replay = new Schema().replay(wire);
  validateReplay(replay);
  return replay;
}

// The wire shape, as msgspec decodes it: maps with every key in declared order, typed and range-checked values.
class Schema {
  replay(value: Value): Replay {
    require(value instanceof MapValue, "replay must be a map");
    const version = new Map(value.entries).get("format_version");
    const names = typeof version === "number" ? REPLAY_KEYS[version] : undefined;
    require(
      names !== undefined,
      `unsupported replay format version: ${String(version)} (this build reads versions ${Object.keys(REPLAY_KEYS).join(", ")})`,
    );
    const fields = this.fields(value, "replay", names!);
    const format_version = this.int(fields.format_version, "format_version");
    return {
      format_version,
      game_version: this.str(fields.game_version, "game_version"),
      rules: format_version === 30 ? V30_RULES : this.int(fields.rules, "rules"),
      recorder: this.recorder(fields.recorder),
      run: this.runSpec(fields.run),
      result: this.result(fields.result),
      ticks: this.array(fields.ticks, "ticks").map((tick, i) => this.tick(tick, `ticks[${i}]`)),
    };
  }

  private recorder(value: Value): Recorder {
    const f = this.fields(value, "recorder", ["client", "version", "platform"]);
    return {
      client: this.str(f.client, "recorder.client"),
      version: this.str(f.version, "recorder.version"),
      platform: this.str(f.platform, "recorder.platform"),
    };
  }

  private runSpec(value: Value): RunSpec {
    const f = this.fields(value, "run", [
      "game_mode_id", "seed", "quest_level", "player_count", "hardcore", "preserve_bugs", "quest_fail_retry_count",
      "detail_preset", "violence_disabled", "friendly_fire", "status", "typo_dictionary_words",
      "typo_highscore_names", "typo_carry",
    ]);
    const game_mode_id = this.int(f.game_mode_id, "run.game_mode_id");
    require(KNOWN_GAME_MODES.has(game_mode_id), `run.game_mode_id ${game_mode_id} is not a game mode`);
    let quest_level: QuestLevel | null = null;
    if (f.quest_level !== null) {
      const level = this.fields(f.quest_level, "run.quest_level", ["major", "minor"]);
      quest_level = {
        major: this.range(this.int(level.major, "run.quest_level.major"), 1, 5, "run.quest_level.major"),
        minor: this.range(this.int(level.minor, "run.quest_level.minor"), 1, 10, "run.quest_level.minor"),
      };
    }
    require((quest_level !== null) === (game_mode_id === GameMode.QUESTS), "run.quest_level must be set for quests and only for quests");
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

  private tick(value: Value, field: string): Tick {
    const parts = this.array(value, field);
    require(parts.length === 2, `${field} must be [inputs, commands]`);
    return {
      inputs: this.array(parts[0]!, `${field}.inputs`).map((input, i) => {
        const axes = this.array(input, `${field}.inputs[${i}]`);
        require(axes.length === 5, `${field}.inputs[${i}] must have 5 values`);
        return [
          this.float(axes[0]!, `${field}.inputs[${i}][0]`),
          this.float(axes[1]!, `${field}.inputs[${i}][1]`),
          this.float(axes[2]!, `${field}.inputs[${i}][2]`),
          this.float(axes[3]!, `${field}.inputs[${i}][3]`),
          this.int(axes[4]!, `${field}.inputs[${i}][4]`),
        ];
      }),
      commands: this.array(parts[1]!, `${field}.commands`).map((command, i) => this.command(command, `${field}.commands[${i}]`)),
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

export function validateReplay(replay: Replay): void {
  require(Boolean(replay.game_version), "game_version must be non-empty");
  require(replay.rules >= 1, "rules must be at least 1");
  for (const field of ["client", "version", "platform"] as const) {
    const value = replay.recorder[field];
    require(
      value.length > 0 && value.length <= RECORDER_FIELD_MAX_CHARS && isPrintableAscii(value),
      `recorder.${field} must be 1..${RECORDER_FIELD_MAX_CHARS} printable ASCII characters`,
    );
  }
  const run = replay.run;
  const mode = run.game_mode_id;
  require(REPLAY_MODES.has(mode), `run.game_mode_id ${mode} is not a replayable mode`);
  requireInt(run.seed, 0, U32_MAX, "run.seed");
  require((run.quest_level !== null) === (mode === GameMode.QUESTS), "run.quest_level must be set for quests and only for quests");
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
  replay.ticks.forEach((tick, t) => {
    require(tick.inputs.length === run.player_count, `ticks[${t}] has ${tick.inputs.length} player inputs, expected ${run.player_count}`);
    tick.inputs.forEach((input, p) => {
      for (let axis = 0; axis < 4; axis++) requireF32(input[axis]!, `ticks[${t}].inputs[${p}][${axis}]`);
      const error = inputFlagsError(input[4]);
      require(error === null, `ticks[${t}].inputs[${p}].flags ${error}`);
    });
    tick.commands.forEach((command, c) => {
      const field = `ticks[${t}].commands[${c}]`;
      require(0 <= command.player_index && command.player_index < run.player_count, `${field}.player_index is out of range`);
      if (command.type === "perk_pick") requireInt(command.choice_index, 0, 6, `${field}.choice_index`);
      require(!command.type.startsWith("typo_") || mode === GameMode.TYPO, `${field} Typ-o commands require game_mode_id=TYPO`);
    });
  });
}
