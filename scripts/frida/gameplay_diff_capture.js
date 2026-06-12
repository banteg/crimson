"use strict";

// Differential gameplay capture:
// - per-gameplay tick records with stable checkpoint payloads
// - deterministic command/event summaries for first-divergence debugging
// - compact before/after snapshots and entity samples on every tick
// - emits a single JSONL stream with explicit run markers:
//   session_start, run_start, tick, run_end, session_end
//
// Attach:
//   frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture.js
//   or via scripts/frida/gameplay_diff_capture_host.py for stop+finalize orchestration
//
// Output:
//   C:\share\frida\gameplay_diff_capture.jsonl
//   (one continuous stream; host finalizer splits into per-run .cdt outputs)

const DEFAULT_LOG_DIR = "C:\\share\\frida";
const DEFAULT_OUT_NAME = "gameplay_diff_capture.jsonl";
const DEFAULT_TRACKED_STATES = "6,7,8,9,10,12,14,18";
const DEFAULT_CONSOLE_EVENTS =
  "start,ready,capture_shutdown,error,hook_error,hook_skip,tickless_event";
const CAPTURE_FORMAT_VERSION = 14;
// First rng caller of native run setup (terrain_generate prelude roll 1). The
// rand state observed before this draw is the state a replay must seed from to
// reproduce the run's setup draws (terrain stamps, quest build) value-for-value.
const RUN_SETUP_FIRST_RNG_CALLER_STATIC = "0x004181cc";
const LINK_BASE = ptr("0x00400000");
const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";
const GAME_MODE_QUESTS = 3;
const MOVE_MODE_UNKNOWN = 0;
const MOVE_MODE_RELATIVE = 1;
const MOVE_MODE_STATIC = 2;
const MOVE_MODE_DUAL_ACTION_PAD = 3;
const MOVE_MODE_MOUSE_POINT_CLICK = 4;
const MOVE_MODE_COMPUTER = 5;
const BONUS_ID_ENERGIZER = "2";
const BONUS_ID_WEAPON_POWER_UP = "4";
const BONUS_ID_DOUBLE_EXPERIENCE = "6";
const BONUS_ID_REFLEX_BOOST = "9";
const BONUS_ID_FREEZE = "11";
const REPLAY_FIRE_DOWN_FLAG = 1 << 0;
const REPLAY_FIRE_PRESSED_FLAG = 1 << 1;
const REPLAY_RELOAD_PRESSED_FLAG = 1 << 2;
const REPLAY_MOVE_KEYS_PRESENT_FLAG = 1 << 3;
const REPLAY_MOVE_FORWARD_FLAG = 1 << 4;
const REPLAY_MOVE_BACKWARD_FLAG = 1 << 5;
const REPLAY_TURN_LEFT_FLAG = 1 << 6;
const REPLAY_TURN_RIGHT_FLAG = 1 << 7;
const REPLAY_MOVE_MODE_PRESENT_FLAG = 1 << 8;
const REPLAY_MOVE_MODE_SHIFT = 9;
const REPLAY_MOVE_MODE_MASK = 0x7;
const REPLAY_AIM_SCHEME_PRESENT_FLAG = 1 << 12;
const REPLAY_AIM_SCHEME_SHIFT = 13;
const REPLAY_AIM_SCHEME_MASK = 0x7;
const REPLAY_RELOAD_DOWN_FLAG = 1 << 16;
const CONFIG_PARSE_ERRORS = [];

function recordConfigParseError(key, raw, reason) {
  CONFIG_PARSE_ERRORS.push({
    key: String(key),
    raw: raw == null ? null : String(raw),
    reason: String(reason || "invalid_config"),
  });
}

function getEnv(key) {
  try {
    return Process.env[key] || null;
  } catch (_) {
    return null;
  }
}

function hasNonEmptyEnv(key) {
  const raw = getEnv(key);
  return raw != null && String(raw).trim().length > 0;
}

function parseIntEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const parsed = parseInt(String(raw).trim(), 0);
  if (!Number.isFinite(parsed)) {
    recordConfigParseError(key, raw, "expected integer");
  }
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const text = String(raw).trim().toLowerCase();
  if (text === "1" || text === "true" || text === "yes" || text === "on") return true;
  if (text === "0" || text === "false" || text === "no" || text === "off") return false;
  recordConfigParseError(key, raw, "expected boolean");
  return fallback;
}

function parseLimitEnv(key, fallback, minValue) {
  const raw = getEnv(key);
  const fallbackInt = Number.isFinite(fallback) ? fallback | 0 : -1;
  if (!raw) return fallbackInt;
  const parsed = parseInt(String(raw).trim(), 0);
  if (!Number.isFinite(parsed)) {
    recordConfigParseError(key, raw, "expected integer limit");
    return fallbackInt;
  }
  if (parsed < 0) return -1;
  const min = Number.isFinite(minValue) ? minValue | 0 : 0;
  return Math.max(min, parsed | 0);
}

function parseStateSet(raw, fallbackCsv, key) {
  const csv = raw && String(raw).trim() ? String(raw) : fallbackCsv;
  const out = new Set();
  const parts = String(csv)
    .split(/[;,]/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  for (let i = 0; i < parts.length; i++) {
    const v = parseInt(parts[i], 0);
    if (Number.isFinite(v)) {
      out.add(v);
      continue;
    }
    if (raw && key) {
      recordConfigParseError(key, parts[i], "expected integer state id");
    }
  }
  return out;
}

function parseStringSet(raw, fallbackCsv) {
  const csv = raw && String(raw).trim() ? String(raw) : fallbackCsv;
  const out = new Set();
  const parts = String(csv)
    .split(/[;,]/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  for (let i = 0; i < parts.length; i++) {
    out.add(String(parts[i]).toLowerCase());
  }
  return out;
}

const CONFIG_ENV_KEYS = [
  "CRIMSON_FRIDA_DIR",
  "CRIMSON_FRIDA_OUT_PATH",
  "CRIMSON_FRIDA_APPEND",
  "CRIMSON_FRIDA_CONSOLE_ALL_EVENTS",
  "CRIMSON_FRIDA_CONSOLE_EVENTS",
  "CRIMSON_FRIDA_INCLUDE_CALLER",
  "CRIMSON_FRIDA_INCLUDE_BT",
  "CRIMSON_FRIDA_INCLUDE_RAW_EVENTS",
  "CRIMSON_FRIDA_ALL_STATES",
  "CRIMSON_FRIDA_STATES",
  "CRIMSON_FRIDA_PLAYER_COUNT",
  "CRIMSON_FRIDA_FOCUS_TICK",
  "CRIMSON_FRIDA_FOCUS_RADIUS",
  "CRIMSON_FRIDA_HEARTBEAT_MS",
  "CRIMSON_FRIDA_FLUSH_CAPTURE_WRITES",
  "CRIMSON_FRIDA_MAX_HEAD",
  "CRIMSON_FRIDA_MAX_EVENTS_PER_TICK",
  "CRIMSON_FRIDA_RNG_HEAD",
  "CRIMSON_FRIDA_RNG_CALLERS",
  "CRIMSON_FRIDA_RNG_ROLL_LOG",
  "CRIMSON_FRIDA_MAX_RNG_ROLL_LOG_EVENTS",
  "CRIMSON_FRIDA_RNG_OUTSIDE_TICK_HEAD",
  "CRIMSON_FRIDA_RNG_STATE_MIRROR",
  "CRIMSON_FRIDA_CREATURE_DELTA_IDS",
  "CRIMSON_FRIDA_CREATURE_SAMPLE_LIMIT",
  "CRIMSON_FRIDA_PROJECTILE_SAMPLE_LIMIT",
  "CRIMSON_FRIDA_SECONDARY_PROJECTILE_SAMPLE_LIMIT",
  "CRIMSON_FRIDA_BONUS_SAMPLE_LIMIT",
  "CRIMSON_FRIDA_INPUT_HOOKS",
  "CRIMSON_FRIDA_RNG_HOOKS",
  "CRIMSON_FRIDA_SFX",
  "CRIMSON_FRIDA_DAMAGE",
  "CRIMSON_FRIDA_EFFECTS",
  "CRIMSON_FRIDA_DAMAGE_PROJECTILE_ONLY",
  "CRIMSON_FRIDA_SPAWNS",
  "CRIMSON_FRIDA_CREATURE_SPAWN_HOOK",
  "CRIMSON_FRIDA_CREATURE_DEATH_HOOK",
  "CRIMSON_FRIDA_BONUS_SPAWN_HOOK",
  "CRIMSON_FRIDA_CREATURE_LIFECYCLE",
  "CRIMSON_FRIDA_CREATURE_MICRO_HOOKS",
  "CRIMSON_FRIDA_CREATURE_MICRO",
  "CRIMSON_FRIDA_CREATURE_MICRO_TICK_START",
  "CRIMSON_FRIDA_CREATURE_MICRO_TICK_END",
  "CRIMSON_FRIDA_CREATURE_MICRO_MAX_HEAD_PER_TICK",
];

function collectConfigEnvOverrides() {
  const overrides = [];
  for (let i = 0; i < CONFIG_ENV_KEYS.length; i++) {
    const key = CONFIG_ENV_KEYS[i];
    if (hasNonEmptyEnv(key)) overrides.push(key);
  }
  overrides.sort();
  return overrides;
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith("\\") || base.endsWith("/") ? "" : "\\";
  return base + sep + leaf;
}

function nowMs() {
  return Date.now();
}

function nowIso() {
  return new Date().toISOString();
}

function toHex(value, width) {
  if (value == null) return null;
  let hex = (value >>> 0).toString(16);
  while (hex.length < width) hex = "0" + hex;
  return "0x" + hex;
}

const LOG_DIR = getEnv("CRIMSON_FRIDA_DIR") || DEFAULT_LOG_DIR;

const CONFIG = {
  outPath: getEnv("CRIMSON_FRIDA_OUT_PATH") || joinPath(LOG_DIR, DEFAULT_OUT_NAME),
  logMode: getEnv("CRIMSON_FRIDA_APPEND") === "1" ? "append" : "truncate",
  consoleAllEvents: parseBoolEnv("CRIMSON_FRIDA_CONSOLE_ALL_EVENTS", false),
  consoleEvents: parseStringSet(getEnv("CRIMSON_FRIDA_CONSOLE_EVENTS"), DEFAULT_CONSOLE_EVENTS),
  includeCaller: parseBoolEnv("CRIMSON_FRIDA_INCLUDE_CALLER", true),
  includeBacktrace: parseBoolEnv("CRIMSON_FRIDA_INCLUDE_BT", false),
  includeRawEvents: parseBoolEnv("CRIMSON_FRIDA_INCLUDE_RAW_EVENTS", false),
  emitTicksOutsideTrackedStates: parseBoolEnv("CRIMSON_FRIDA_ALL_STATES", false),
  trackedStates: parseStateSet(getEnv("CRIMSON_FRIDA_STATES"), DEFAULT_TRACKED_STATES, "CRIMSON_FRIDA_STATES"),
  playerCountOverride: Math.max(0, parseIntEnv("CRIMSON_FRIDA_PLAYER_COUNT", 0)),
  focusTick: parseIntEnv("CRIMSON_FRIDA_FOCUS_TICK", -1),
  focusRadius: Math.max(0, parseIntEnv("CRIMSON_FRIDA_FOCUS_RADIUS", 0)),
  heartbeatMs: Math.max(100, parseIntEnv("CRIMSON_FRIDA_HEARTBEAT_MS", 1000)),
  flushCaptureWrites: parseBoolEnv("CRIMSON_FRIDA_FLUSH_CAPTURE_WRITES", false),
  maxHeadPerKind: parseLimitEnv("CRIMSON_FRIDA_MAX_HEAD", -1, 0),
  maxEventsPerTick: parseLimitEnv("CRIMSON_FRIDA_MAX_EVENTS_PER_TICK", -1, 0),
  maxRngHeadPerTick: parseLimitEnv("CRIMSON_FRIDA_RNG_HEAD", -1, 0),
  maxRngCallerKinds: parseLimitEnv("CRIMSON_FRIDA_RNG_CALLERS", -1, 0),
  enableRngRollLog: parseBoolEnv("CRIMSON_FRIDA_RNG_ROLL_LOG", true),
  maxRngRollLogEvents: parseLimitEnv("CRIMSON_FRIDA_MAX_RNG_ROLL_LOG_EVENTS", -1, 0),
  maxRngOutsideTickHead: parseLimitEnv("CRIMSON_FRIDA_RNG_OUTSIDE_TICK_HEAD", 256, 0),
  enableRngStateMirror: parseBoolEnv("CRIMSON_FRIDA_RNG_STATE_MIRROR", true),
  maxCreatureDeltaIds: parseLimitEnv("CRIMSON_FRIDA_CREATURE_DELTA_IDS", 256, 1),
  creatureSampleLimit: parseLimitEnv("CRIMSON_FRIDA_CREATURE_SAMPLE_LIMIT", -1, 0),
  projectileSampleLimit: parseLimitEnv("CRIMSON_FRIDA_PROJECTILE_SAMPLE_LIMIT", -1, 0),
  secondaryProjectileSampleLimit: parseLimitEnv("CRIMSON_FRIDA_SECONDARY_PROJECTILE_SAMPLE_LIMIT", -1, 0),
  bonusSampleLimit: parseLimitEnv("CRIMSON_FRIDA_BONUS_SAMPLE_LIMIT", -1, 0),
  enableInputHooks: parseBoolEnv("CRIMSON_FRIDA_INPUT_HOOKS", true),
  enableRngHooks: parseBoolEnv("CRIMSON_FRIDA_RNG_HOOKS", true),
  enableSfxHooks: parseBoolEnv("CRIMSON_FRIDA_SFX", true),
  enableDamageHooks: parseBoolEnv("CRIMSON_FRIDA_DAMAGE", true),
  enableEffectHooks: parseBoolEnv("CRIMSON_FRIDA_EFFECTS", true),
  creatureDamageProjectileOnly: parseBoolEnv("CRIMSON_FRIDA_DAMAGE_PROJECTILE_ONLY", true),
  enableSpawnHooks: parseBoolEnv("CRIMSON_FRIDA_SPAWNS", true),
  enableCreatureSpawnHook: parseBoolEnv("CRIMSON_FRIDA_CREATURE_SPAWN_HOOK", true),
  enableCreatureDeathHook: parseBoolEnv("CRIMSON_FRIDA_CREATURE_DEATH_HOOK", true),
  enableBonusSpawnHook: parseBoolEnv("CRIMSON_FRIDA_BONUS_SPAWN_HOOK", true),
  maxPlayerSpawnsByPlayerLimit: -1,
  enableCreatureLifecycleDigest: parseBoolEnv("CRIMSON_FRIDA_CREATURE_LIFECYCLE", true),
  enableCreatureMicroHooks: parseBoolEnv("CRIMSON_FRIDA_CREATURE_MICRO_HOOKS", true),
  creatureMicroSlots: parseStateSet(getEnv("CRIMSON_FRIDA_CREATURE_MICRO"), "", "CRIMSON_FRIDA_CREATURE_MICRO"),
  creatureMicroTickStart: parseIntEnv("CRIMSON_FRIDA_CREATURE_MICRO_TICK_START", -1),
  creatureMicroTickEnd: parseIntEnv("CRIMSON_FRIDA_CREATURE_MICRO_TICK_END", -1),
  creatureMicroMaxHeadPerTick: parseLimitEnv("CRIMSON_FRIDA_CREATURE_MICRO_MAX_HEAD_PER_TICK", -1, 0),
};

const FN = {
  perk_apply: 0x004055e0,
  player_update: 0x004136b0,
  gameplay_update_and_render: 0x0040aab0,
  quest_mode_update: 0x004070e0,
  rush_mode_update: 0x004072b0,
  survival_update: 0x00407cd0,
  survival_spawn_creature: 0x00407510,
  typo_gameplay_update_and_render: 0x004457c0,
  game_state_set: 0x004461c0,
  // Typ-o Shooter fire entrypoint. Classic modes fire from `player_update`.
  player_fire_weapon: 0x00444980,
  weapon_assign_player: 0x00452d40,
  bonus_apply: 0x00409890,
  bonus_try_spawn_on_kill: 0x0041f8d0,
  secondary_projectile_spawn: 0x00420360,
  projectile_spawn: 0x00420440,
  creature_find_in_radius: 0x004206a0,
  creature_apply_damage: 0x004207c0,
  angle_approach: 0x0041f430,
  creature_update_all: 0x00426220,
  player_take_damage: 0x00425e50,
  creature_spawn: 0x00428240,
  creature_handle_death: 0x0041e910,
  creature_spawn_template: 0x00430af0,
  creature_spawn_tinted: 0x00444810,
  quest_start_selected: 0x0043a790,
  perks_update_effects: 0x00406b40,
  quest_spawn_timeline_update: 0x00434250,
  effect_spawn_blood_splatter: 0x0042eb10,
  input_any_key_pressed: 0x00446000,
  input_primary_just_pressed: 0x00446030,
  input_primary_is_down: 0x004460f0,
  crt_srand: 0x00461739,
  crt_rand: 0x00461746,
  // multithread CRT per-thread-data accessor; rand state lives at ptd+0x14.
  crt_getptd: 0x004654b8,
  sfx_play: 0x0043d120,
  sfx_play_panned: 0x0043d260,
  sfx_play_exclusive: 0x0043d460,
};

// Ghidra (latest sync): first function after `player_update`.
const PLAYER_UPDATE_END_RVA = 0x00417640;

const FN_GRIM_RVA = {
  grim_is_key_down: 0x00007320,
  grim_is_key_active: 0x00006fe0,
};

const DATA = {
  config_player_count: 0x0048035c,
  config_game_mode: 0x00480360,
  config_player_mode_flags: 0x00480364,
  config_aim_scheme: 0x0048038c,
  config_key_reload: 0x004807c4,
  perk_choice_ids: 0x004807e8,
  frame_dt: 0x00480840,
  frame_dt_ms: 0x00480844,
  perk_lean_mean_exp_tick_timer_s: 0x004808a4,

  input_primary_latch: 0x00478e50,
  console_open_flag: 0x0047eec8,
  perk_pending_count: 0x00486fac,
  perk_choices_dirty: 0x00486fb0,
  shock_chain_links_left: 0x00486fbc,
  shock_chain_projectile_id: 0x00486fc0,
  creature_active_count: 0x00486fcc,
  quest_spawn_timeline: 0x00486fd0,
  quest_stage_major: 0x00487004,
  quest_stage_minor: 0x00487008,
  bonus_reflex_boost_timer: 0x00487014,
  bonus_freeze_timer: 0x00487018,
  bonus_weapon_power_up_timer: 0x0048701c,
  bonus_energizer_timer: 0x00487020,
  bonus_double_xp_timer: 0x00487024,
  creature_kill_count: 0x00487074,
  quest_transition_timer_ms: 0x00487088,
  time_played_ms: 0x0048718c,
  player_alt_weapon_swap_cooldown_ms: 0x0048719c,
  quest_stage_banner_timer_ms: 0x00487244,
  ui_elements_timeline: 0x00487248,
  ui_transition_direction: 0x0048724c,
  perk_doctor_target_creature_id: 0x00487268,
  game_state_prev: 0x0048726c,
  game_state_id: 0x00487270,
  game_state_pending: 0x00487274,
  ui_transition_alpha: 0x00487278,
  pause_keybind_help_alpha_ms: 0x00487284,
  ui_mouse_x: 0x004871ec,
  ui_mouse_y: 0x004871f0,
  player_aim_screen_x: 0x004871f4,
  player_aim_screen_y: 0x004871f8,

  player_pos_x: 0x004908c4,
  player_pos_y: 0x004908c8,
  player_move_dx: 0x004908cc,
  player_move_dy: 0x004908d0,
  player_health: 0x004908d4,
  player_aim_x: 0x00490900,
  player_aim_y: 0x00490904,
  player_hot_tempered_timer: 0x0049094c,
  player_man_bomb_timer: 0x00490950,
  player_living_fortress_timer: 0x00490954,
  player_fire_cough_timer: 0x00490958,
  player_experience: 0x0049095c,
  player_level: 0x00490964,
  player_perk_counts: 0x00490968,
  player_spread_heat: 0x00490b68,
  player_weapon_id: 0x00490b70,
  player_clip_size: 0x00490b74,
  player_reload_active: 0x00490b78,
  player_ammo: 0x00490b7c,
  player_reload_timer: 0x00490b80,
  player_shot_cooldown: 0x00490b84,
  player_reload_timer_max: 0x00490b88,
  player_alt_weapon_id: 0x00490b8c,
  player_alt_clip_size: 0x00490b90,
  player_alt_reload_active: 0x00490b94,
  player_alt_ammo: 0x00490b98,
  player_alt_reload_timer: 0x00490b9c,
  player_alt_shot_cooldown: 0x00490ba0,
  player_alt_reload_timer_max: 0x00490ba4,
  player_aim_heading: 0x00490bb0,
  player_speed_bonus_timer: 0x00490bc4,
  player_shield_timer: 0x00490bc8,
  player_fire_bullets_timer: 0x00490bcc,
  player_move_key_forward: 0x00490bdc,
  player_move_key_backward: 0x00490be0,
  player_turn_key_left: 0x00490be4,
  player_turn_key_right: 0x00490be8,
  player_fire_key: 0x00490bec,
  player_aim_key_left: 0x00490bf8,
  player_aim_key_right: 0x00490bfc,
  player_axis_aim_x: 0x00490c00,
  player_axis_aim_y: 0x00490c04,
  player_axis_move_x: 0x00490c08,
  player_axis_move_y: 0x00490c0c,
  player_alt_move_key_forward: 0x00490f3c,
  player_alt_move_key_backward: 0x00490f40,
  player_alt_turn_key_left: 0x00490f44,
  player_alt_turn_key_right: 0x00490f48,
  player_alt_fire_key: 0x00490f4c,

  game_status_blob: 0x00485540,
  status_weapon_usage_counts: 0x00485544,

  projectile_pool: 0x004926b8,
  secondary_projectile_pool: 0x00495ad8,
  creature_pool: 0x0049bf38,
  bonus_pool: 0x00482948,

  perk_jinxed_proc_timer_s: 0x004aaf1c,
  quest_spawn_stall_timer_ms: 0x004c3654,
};

const REQUIRED_REPLAY_FN_NAMES = [
  "gameplay_update_and_render",
  "game_state_set",
  "quest_start_selected",
  "quest_mode_update",
  "rush_mode_update",
  "survival_update",
  "typo_gameplay_update_and_render",
];

const REQUIRED_REPLAY_DATA_NAMES = [
  "config_player_count",
  "config_game_mode",
  "config_player_mode_flags",
  "config_aim_scheme",
  "config_key_reload",
  "game_state_prev",
  "game_state_id",
  "game_state_pending",
  "frame_dt",
  "frame_dt_ms",
  "time_played_ms",
  "creature_active_count",
  "creature_kill_count",
  "perk_pending_count",
  "perk_choices_dirty",
  "quest_stage_major",
  "quest_stage_minor",
  "bonus_reflex_boost_timer",
  "bonus_freeze_timer",
  "bonus_weapon_power_up_timer",
  "bonus_energizer_timer",
  "bonus_double_xp_timer",
  "game_status_blob",
  "status_weapon_usage_counts",
  "player_pos_x",
  "player_pos_y",
  "player_move_dx",
  "player_move_dy",
  "player_health",
  "player_aim_x",
  "player_aim_y",
  "player_aim_heading",
  "player_weapon_id",
  "player_clip_size",
  "player_reload_active",
  "player_ammo",
  "player_reload_timer",
  "player_reload_timer_max",
  "player_shot_cooldown",
  "player_experience",
  "player_level",
  "player_speed_bonus_timer",
  "player_shield_timer",
  "player_fire_bullets_timer",
  "projectile_pool",
  "secondary_projectile_pool",
  "creature_pool",
  "bonus_pool",
];

const STRIDES = {
  player: 0x360,
  projectile: 0x40,
  secondary_projectile: 0x2c,
  creature: 0x98,
  bonus: 0x1c,
};

const COUNTS = {
  projectiles: 0x60,
  secondary_projectiles: 0x40,
  creatures: 0x180,
  bonuses: 0x10,
};

const STATUS_WEAPON_USAGE_COUNT = 53;
const PERK_CHOICE_COUNT = 8;
const PERK_COUNT_PER_PLAYER = 0x80;
const PROJECTILE_UPDATE_START = 0x00420b90;
const PROJECTILE_UPDATE_END = 0x00422c6f;
const CRT_RAND_MULT = 214013 >>> 0;
const CRT_RAND_INC = 2531011 >>> 0;
const CREATURE_FLAG_AI7_LINK_TIMER = 0x80;
const CREATURE_HEADING_OFFSET = 0x2c;
const TWO_PI = Math.PI * 2.0;

const fnPtrs = {};
const grimFnPtrs = {};
const dataPtrs = {};
const fireContextByTid = {};
const assignContextByTid = {};
const bonusContextByTid = {};
const damageContextByTid = {};
const creatureDamageContextByTid = {};
const creatureSpawnContextByTid = {};
const creatureDeathContextByTid = {};
const bonusSpawnContextByTid = {};
const inputContextByTid = {};
const rngContextByTid = {};
const crtPtdByTid = {};
const srandContextByTid = {};
const bloodSplatterContextByTid = {};
const creatureUpdateMicroContextByTid = {};
const angleApproachContextByTid = {};
const outState = {
  outFile: null,
  outWarned: false,
  currentOutPath: null,
  captureMetaTemplate: null,
  captureStarted: false,
  captureClosed: false,
  captureTickCount: 0,
  runActive: false,
  currentRunId: 0,
  currentRunTickCount: 0,
  currentRunModeId: -1,
  currentRunQuestMajor: -1,
  currentRunQuestMinor: -1,
  currentRunKey: "",
  currentRunBootstrapQuestAttemptPending: false,
  currentRunElapsedRawStartMs: null,
  currentRunElapsedRawLastMs: null,
  currentRunElapsedNormalizedMs: null,
  lastTickIndexGlobal: null,
  shutdownComplete: false,
  gameplayFrame: 0,
  currentStatePrev: null,
  currentStateId: null,
  currentStatePending: null,
  currentTick: null,
  playerCountResolved: 1,
  heartbeatTimer: null,
  lastPerkCompact: null,
  lastQuestCompact: null,
  sessionId: null,
  sessionFingerprint: null,
  hookStatusByName: {},
  rngCallsTotal: 0,
  rngCallsOutsideTick: 0,
  rngHashState: fnvInit(),
  rngCallSeq: 0,
  rngRollLogEmitted: 0,
  rngRollLogDropped: 0,
  rngMirrorStateU32: null,
  rngMirrorMismatchCount: 0,
  rngMirrorUnknownCalls: 0,
  lastGpurLeaveRngStateReal: null,
  rngSeedEpoch: 0,
  rngOutsideTickPendingHead: [],
  rngOutsideTickPendingCalls: 0,
  rngOutsideTickPendingDropped: 0,
  rngOutsideTickPendingCallerCounts: {},
  pendingRunSetupRng: null,
  perkApplyOutsideTickPendingHead: [],
  perkApplyOutsideTickPendingCalls: 0,
  perkApplyOutsideTickPendingDropped: 0,
  pending_timing_samples: [],
  lastSrandSeed: null,
  lastTickElapsedMs: null,
  lastTickGameplayFrame: null,
  lastCreatureDigest: null,
  questAttemptPendingByLevel: {},
  questAttemptStartsByLevel: {},
  entityUidStates: null,
  lastHookActivity: null,
  lastException: null,
};

function _diagIntOrNull(value) {
  return typeof value === "number" && Number.isFinite(value) ? value | 0 : null;
}

function _diagPtrToString(value) {
  if (value == null) return null;
  try {
    return value.toString();
  } catch (_) {
    return String(value);
  }
}

function _diagTickIndex() {
  const tick = outState.currentTick;
  if (tick && tick.tick_index != null) return tick.tick_index | 0;
  if (outState.lastTickIndexGlobal != null) return outState.lastTickIndexGlobal | 0;
  return null;
}

function _diagGameplayFrame() {
  const tick = outState.currentTick;
  if (tick && tick.gameplay_frame != null) return tick.gameplay_frame | 0;
  if (outState.lastTickGameplayFrame != null) return outState.lastTickGameplayFrame | 0;
  return null;
}

function recordHookActivity(name, phase, context) {
  outState.lastHookActivity = {
    name: String(name || ""),
    phase: String(phase || ""),
    thread_id: context && context.threadId != null ? _diagIntOrNull(context.threadId) : null,
    return_address: context ? _diagPtrToString(context.returnAddress) : null,
    tick_index_global: _diagTickIndex(),
    gameplay_frame: _diagGameplayFrame(),
    state_id: outState.currentStateId == null ? null : outState.currentStateId | 0,
    run_id: outState.runActive ? outState.currentRunId | 0 : null,
  };
}

function buildProcessExceptionPayload(details) {
  const memory = details && details.memory && typeof details.memory === "object" ? details.memory : null;
  const context = details && details.context && typeof details.context === "object" ? details.context : null;
  return {
    type: details && details.type != null ? String(details.type) : null,
    address: details ? _diagPtrToString(details.address) : null,
    memory_operation: memory && memory.operation != null ? String(memory.operation) : null,
    memory_address: memory ? _diagPtrToString(memory.address) : null,
    thread_id: details && details.threadId != null ? _diagIntOrNull(details.threadId) : null,
    pc: context ? _diagPtrToString(context.pc) : null,
    sp: context ? _diagPtrToString(context.sp) : null,
    tick_index_global: _diagTickIndex(),
    gameplay_frame: _diagGameplayFrame(),
    state_id: outState.currentStateId == null ? null : outState.currentStateId | 0,
    run_id: outState.runActive ? outState.currentRunId | 0 : null,
    last_hook: outState.lastHookActivity,
    backtrace: exceptionBacktrace(context),
  };
}

function buildProcessExceptionReason(payload) {
  let reason = "process_exception";
  if (payload && payload.type) reason += ":" + payload.type;
  if (payload && payload.address) reason += "@" + payload.address;
  return reason;
}

function newEntityUidState() {
  return {
    generationByIndex: {},
    activeIndices: {},
    seenInTick: {},
  };
}

function resetEntityUidStates() {
  outState.entityUidStates = {
    creature: newEntityUidState(),
    projectile: newEntityUidState(),
    secondary_projectile: newEntityUidState(),
    bonus: newEntityUidState(),
  };
}

function beginEntityUidTick(kind) {
  const states = outState.entityUidStates || {};
  const state = states[kind];
  if (!state) return;
  state.seenInTick = {};
}

function endEntityUidTick(kind) {
  const states = outState.entityUidStates || {};
  const state = states[kind];
  if (!state) return;
  state.activeIndices = state.seenInTick || {};
  state.seenInTick = {};
}

function nextEntityUid(kind, index) {
  const states = outState.entityUidStates || {};
  const state = states[kind];
  if (!state) return { uid: 0, generation: 0 };
  const idx = index | 0;
  const key = String(idx);
  if (!state.activeIndices[key]) {
    const previous = state.generationByIndex[key] == null ? 0 : state.generationByIndex[key] | 0;
    state.generationByIndex[key] = (previous + 1) | 0;
  }
  state.seenInTick[key] = true;
  const generation = state.generationByIndex[key] == null ? 0 : state.generationByIndex[key] | 0;
  return {
    uid: idx,
    generation: generation,
  };
}

resetEntityUidStates();

function questLevelKey(major, minor) {
  const stageMajor = major == null ? -1 : major | 0;
  const stageMinor = minor == null ? -1 : minor | 0;
  if (stageMajor <= 0 || stageMinor <= 0) return null;
  return String(stageMajor) + "_" + String(stageMinor);
}

function noteQuestAttemptStart(source, gameModeId, major, minor) {
  const modeId = gameModeId == null ? -1 : gameModeId | 0;
  const levelKey = questLevelKey(major, minor);
  if (modeId !== GAME_MODE_QUESTS || !levelKey) return null;
  const pendingMap = outState.questAttemptPendingByLevel;
  const startsMap = outState.questAttemptStartsByLevel;
  const pendingCount = pendingMap[levelKey] == null ? 0 : pendingMap[levelKey] | 0;
  const startsCount = startsMap[levelKey] == null ? 0 : startsMap[levelKey] | 0;
  pendingMap[levelKey] = pendingCount + 1;
  startsMap[levelKey] = startsCount + 1;
  writeLine({
    event: "quest_attempt_start",
    source: source || "unknown",
    game_mode_id: modeId,
    quest_stage_major: major == null ? null : major | 0,
    quest_stage_minor: minor == null ? null : minor | 0,
    quest_level_key: levelKey,
    attempt_index: startsMap[levelKey],
    pending_rollovers_for_level: pendingMap[levelKey],
  });
  return {
    level_key: levelKey,
    attempt_index: startsMap[levelKey],
  };
}

function consumeQuestAttemptRolloverForTick(tickObj) {
  if (!tickObj) return false;
  const gameModeId = tickObj.game_mode_id == null ? -1 : tickObj.game_mode_id | 0;
  if (gameModeId !== GAME_MODE_QUESTS) return false;
  const levelKey = questLevelKey(tickObj.quest_stage_major, tickObj.quest_stage_minor);
  if (!levelKey) return false;
  const pendingMap = outState.questAttemptPendingByLevel;
  const pendingCount = pendingMap[levelKey] == null ? 0 : pendingMap[levelKey] | 0;
  if (pendingCount <= 0) return false;
  if (pendingCount <= 1) {
    delete pendingMap[levelKey];
  } else {
    pendingMap[levelKey] = pendingCount - 1;
  }
  return true;
}

function tickModeId(tickObj) {
  if (!tickObj || tickObj.game_mode_id == null) return -1;
  return tickObj.game_mode_id | 0;
}

function tickQuestMajor(tickObj) {
  if (!tickObj || tickObj.quest_stage_major == null) return -1;
  return tickObj.quest_stage_major | 0;
}

function tickQuestMinor(tickObj) {
  if (!tickObj || tickObj.quest_stage_minor == null) return -1;
  return tickObj.quest_stage_minor | 0;
}

function runKeyForTick(tickObj) {
  return (
    String(tickModeId(tickObj)) +
    "|" +
    String(tickQuestMajor(tickObj)) +
    "|" +
    String(tickQuestMinor(tickObj))
  );
}

function requireRunStartSeedU32(tickObj) {
  if (outState.lastSrandSeed != null) return outState.lastSrandSeed >>> 0;
  return emitCaptureContractError("missing_run_start_seed", tickObj);
}

function openOutFile() {
  if (outState.outFile) return;
  const outPath = outState.currentOutPath || CONFIG.outPath;
  if (!outPath) return;
  const mode = CONFIG.logMode === "append" ? "a" : "w";
  try {
    outState.outFile = new File(outPath, mode);
  } catch (_) {
    outState.outFile = null;
  }
}

function writeLine(obj) {
  if (!obj) return;
  const eventName =
    obj && typeof obj.event === "string" ? String(obj.event).toLowerCase() : "";
  if (!CONFIG.consoleAllEvents && !CONFIG.consoleEvents.has(eventName)) {
    return;
  }
  if (obj.ts_ms == null) obj.ts_ms = nowMs();
  if (obj.ts_iso == null) obj.ts_iso = nowIso();
  console.log(JSON.stringify(obj));
}

function _captureWrite(text, flushNow) {
  try {
    openOutFile();
    if (!outState.outFile) return false;
    outState.outFile.write(String(text));
    if (flushNow && CONFIG.flushCaptureWrites) outState.outFile.flush();
    return true;
  } catch (_) {
    return false;
  }
}

function _captureWriteJsonLine(obj, flushNow) {
  if (!obj) return false;
  return _captureWrite(JSON.stringify(obj) + "\n", flushNow);
}

function _captureForceFlush() {
  try {
    if (!outState.outFile) return;
    outState.outFile.flush();
  } catch (_) {}
}

function emitCaptureContractError(errorCode, tickObj) {
  const row = {
    event: "error",
    error: String(errorCode || "capture_contract_error"),
    run_id: outState.runActive ? outState.currentRunId | 0 : null,
    tick_index_global:
      tickObj && tickObj.tick_index != null ? tickObj.tick_index | 0 : null,
  };
  _captureWriteJsonLine(row, true);
  writeLine(row);
  shutdownCapture(String(errorCode || "capture_contract_error"));
  return null;
}

function emitStartupContractError(errorCode, extra) {
  const row = Object.assign(
    {
      event: "error",
      error: String(errorCode || "capture_startup_error"),
    },
    extra || {}
  );
  writeLine(row);
  return false;
}

function requiredReplayFnNames() {
  const names = REQUIRED_REPLAY_FN_NAMES.slice();
  if (CONFIG.enableRngHooks) {
    names.push("crt_srand");
    names.push("crt_rand");
  }
  return names;
}

function requiredReplayDataNames() {
  return REQUIRED_REPLAY_DATA_NAMES.slice();
}

function replayConfigReadinessErrors() {
  const errors = [];
  if (!CONFIG.enableInputHooks) {
    errors.push({
      key: "CRIMSON_FRIDA_INPUT_HOOKS",
      raw: String(CONFIG.enableInputHooks),
      reason: "must remain enabled for replay-grade capture",
    });
  }
  if (!CONFIG.enableRngHooks) {
    errors.push({
      key: "CRIMSON_FRIDA_RNG_HOOKS",
      raw: String(CONFIG.enableRngHooks),
      reason: "must remain enabled for replay-grade capture",
    });
  }
  if (!CONFIG.enableRngStateMirror) {
    errors.push({
      key: "CRIMSON_FRIDA_RNG_STATE_MIRROR",
      raw: String(CONFIG.enableRngStateMirror),
      reason: "must remain enabled for replay-grade capture",
    });
  }
  if (CONFIG.maxRngHeadPerTick >= 0) {
    errors.push({
      key: "CRIMSON_FRIDA_RNG_HEAD",
      raw: String(CONFIG.maxRngHeadPerTick),
      reason: "must be unlimited (-1) for replay-grade rng_stream rows",
    });
  }
  if (CONFIG.creatureSampleLimit >= 0) {
    errors.push({
      key: "CRIMSON_FRIDA_CREATURE_SAMPLE_LIMIT",
      raw: String(CONFIG.creatureSampleLimit),
      reason: "must be unlimited (-1) for replay-grade entity_samples rows",
    });
  }
  if (CONFIG.projectileSampleLimit >= 0) {
    errors.push({
      key: "CRIMSON_FRIDA_PROJECTILE_SAMPLE_LIMIT",
      raw: String(CONFIG.projectileSampleLimit),
      reason: "must be unlimited (-1) for replay-grade entity_samples rows",
    });
  }
  if (CONFIG.secondaryProjectileSampleLimit >= 0) {
    errors.push({
      key: "CRIMSON_FRIDA_SECONDARY_PROJECTILE_SAMPLE_LIMIT",
      raw: String(CONFIG.secondaryProjectileSampleLimit),
      reason: "must be unlimited (-1) for replay-grade entity_samples rows",
    });
  }
  if (CONFIG.bonusSampleLimit >= 0) {
    errors.push({
      key: "CRIMSON_FRIDA_BONUS_SAMPLE_LIMIT",
      raw: String(CONFIG.bonusSampleLimit),
      reason: "must be unlimited (-1) for replay-grade entity_samples rows",
    });
  }
  return errors;
}

function validateStartupReadiness(ptrs) {
  const invalidConfigDetails = CONFIG_PARSE_ERRORS.concat(replayConfigReadinessErrors());
  if (invalidConfigDetails.length > 0) {
    return emitStartupContractError("invalid_config", {
      details: invalidConfigDetails,
    });
  }
  const missingFns = [];
  const fnNames = requiredReplayFnNames();
  for (let i = 0; i < fnNames.length; i++) {
    const name = fnNames[i];
    if (!ptrs[name]) missingFns.push(name);
  }
  const missingData = [];
  const dataNames = requiredReplayDataNames();
  for (let i = 0; i < dataNames.length; i++) {
    const name = dataNames[i];
    if (!ptrs["data_" + name]) missingData.push(name);
  }
  if (missingFns.length <= 0 && missingData.length <= 0) return true;
  return emitStartupContractError("missing_required_pointers", {
    missing_functions: missingFns,
    missing_data: missingData,
  });
}

function validateInstalledRequiredHooks() {
  const failures = [];
  const names = requiredReplayFnNames();
  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    const status = outState.hookStatusByName[name];
    if (status === "attached") continue;
    failures.push(name + ":" + String(status || "not_installed"));
  }
  if (failures.length <= 0) return true;
  emitCaptureContractError("required_hook_install_failed:" + failures.join(","), null);
  return false;
}

// session_start is the authoritative contract row for the whole JSONL stream.
// It must be emitted from the locally constructed capture meta without fallbacks.
function emitSessionStartRow(meta, outPath) {
  const processObj = meta.process;
  return {
    event: "session_start",
    capture_format_version: CAPTURE_FORMAT_VERSION,
    session_id: outState.sessionId,
    out_path: outPath || CONFIG.outPath,
    platform: String(processObj.platform),
    arch: String(processObj.arch),
    script_version: String(CAPTURE_FORMAT_VERSION),
    config: meta.config,
    session_fingerprint: meta.session_fingerprint,
  };
}

function startCaptureFile(meta, outPath) {
  const targetOutPath = outPath || CONFIG.outPath;
  outState.currentOutPath = targetOutPath;
  outState.outFile = null;
  outState.outWarned = false;
  outState.pending_timing_samples = [];
  outState.captureStarted = false;
  outState.captureClosed = false;
  const started = _captureWriteJsonLine(
    emitSessionStartRow(meta, targetOutPath),
    true,
  );
  if (started) _captureForceFlush();
  outState.captureStarted = started;
  outState.captureClosed = !started;
  if (!started && !outState.outWarned) {
    outState.outWarned = true;
    console.log("gameplay_diff_capture: file logging unavailable; capture file not writable");
  }
  return started;
}

function closeActiveRun(reason, tickObj) {
  if (!outState.runActive) return;
  // Draws between the run's last tick and its close belong to this run, not
  // to the next tick's outside-before bag.
  const outsideTail = takePendingOutsideRngRolls();
  const wrote = _captureWriteJsonLine(
    {
      event: "run_end",
      run_id: outState.currentRunId | 0,
      reason: reason || "run_end",
      mode_id: outState.currentRunModeId | 0,
      quest_stage_major: outState.currentRunQuestMajor | 0,
      quest_stage_minor: outState.currentRunQuestMinor | 0,
      tick_index_global:
        tickObj && tickObj.tick_index != null
          ? tickObj.tick_index | 0
          : outState.lastTickIndexGlobal == null
            ? null
            : outState.lastTickIndexGlobal | 0,
      ticks_written: outState.currentRunTickCount | 0,
      rng_outside_tail: {
        calls: outsideTail.calls | 0,
        dropped: outsideTail.dropped | 0,
        caller_counts: outsideTail.caller_counts || {},
        head: (outsideTail.head || []).map(function (row) {
          return {
            value_15: row.value_15 == null ? null : row.value_15 | 0,
            state_before_u32: row.state_before_u32 == null ? null : row.state_before_u32 >>> 0,
            state_after_u32: row.state_after_u32 == null ? null : row.state_after_u32 >>> 0,
            caller_static: row.caller_static == null ? null : String(row.caller_static),
          };
        }),
      },
    },
    true,
  );
  if (wrote) _captureForceFlush();
  outState.runActive = false;
  outState.currentRunTickCount = 0;
  outState.currentRunModeId = -1;
  outState.currentRunQuestMajor = -1;
  outState.currentRunQuestMinor = -1;
  outState.currentRunKey = "";
  outState.currentRunBootstrapQuestAttemptPending = false;
  outState.currentRunElapsedRawStartMs = null;
  outState.currentRunElapsedRawLastMs = null;
  outState.currentRunElapsedNormalizedMs = null;
  resetEntityUidStates();
}

function startRunForTick(tickObj, reason) {
  try {
    const startReason = reason || "run_start";
    const modeId = tickModeId(tickObj);
    const questMajor = tickQuestMajor(tickObj);
    const questMinor = tickQuestMinor(tickObj);
    const runKey = runKeyForTick(tickObj);
    const runSeed = requireRunStartSeedU32(tickObj);
    if (runSeed == null) return false;
    const playerCount = runPlayerCountFromTick(tickObj);
    outState.currentRunId = (outState.currentRunId | 0) + 1;
    outState.currentRunTickCount = 0;
    outState.currentRunModeId = modeId;
    outState.currentRunQuestMajor = questMajor;
    outState.currentRunQuestMinor = questMinor;
    outState.currentRunKey = runKey;
    outState.currentRunBootstrapQuestAttemptPending =
      startReason === "first_tick" && (outState.currentRunModeId | 0) === GAME_MODE_QUESTS;
    outState.currentRunElapsedRawStartMs = null;
    outState.currentRunElapsedRawLastMs = null;
    outState.currentRunElapsedNormalizedMs = null;
    resetEntityUidStates();
    outState.runActive = true;
    // The setup latch holds the rand state observed before the run's first
    // terrain draw; replays must seed from it (the session srand seed is stale
    // by run start). Consume it so a later run cannot inherit this one's.
    const setupRng = outState.pendingRunSetupRng;
    outState.pendingRunSetupRng = null;
    if (!setupRng) {
      emitCaptureContractError("missing_run_setup_rng_state", tickObj);
      return false;
    }
    const wrote = _captureWriteJsonLine(
      {
        event: "run_start",
        run_id: outState.currentRunId | 0,
        reason: startReason,
        mode_id: outState.currentRunModeId | 0,
        quest_stage_major: outState.currentRunQuestMajor | 0,
        quest_stage_minor: outState.currentRunQuestMinor | 0,
        seed: runSeed >>> 0,
        seed_source: "crt_srand",
        rng_state_at_run_setup: setupRng.state_before_u32 >>> 0,
        rng_setup_caller_static: setupRng.caller_static,
        player_count: playerCount,
        tick_index_global:
          tickObj && tickObj.tick_index != null ? tickObj.tick_index | 0 : null,
      },
      true,
    );
    if (!wrote) {
      emitCaptureContractError("run_start_write_failed", tickObj);
      return false;
    }
    _captureForceFlush();
    return true;
  } catch (error) {
    if (isCaptureContractError(error)) {
      emitCaptureContractError(error.message, tickObj);
      return false;
    }
    throw error;
  }
}

function ensureRunForTick(tickObj) {
  let needsRollover = outState.runActive ? consumeQuestAttemptRolloverForTick(tickObj) : false;
  if (!outState.runActive) {
    return startRunForTick(tickObj, "first_tick");
  }
  const nextRunKey = runKeyForTick(tickObj);
  if (
    needsRollover &&
    nextRunKey === outState.currentRunKey &&
    outState.currentRunBootstrapQuestAttemptPending
  ) {
    // First quest tick can inherit a pre-game quest_attempt marker that belongs
    // to the current attempt, not a true run rollover.
    needsRollover = false;
    outState.currentRunBootstrapQuestAttemptPending = false;
  }
  if (needsRollover || nextRunKey !== outState.currentRunKey) {
    closeActiveRun(needsRollover ? "quest_attempt" : "mode_or_stage_change", tickObj);
    return startRunForTick(tickObj, needsRollover ? "quest_attempt" : "mode_or_stage_change");
  }
  return true;
}

function failCaptureContract(detail) {
  const error = new Error(String(detail || "capture_contract_error"));
  error.name = "CaptureContractError";
  throw error;
}

function isCaptureContractError(error) {
  return !!error && String(error.name || "") === "CaptureContractError";
}

function requireObject(value, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    failCaptureContract(field + " must be an object");
  }
  return value;
}

function requireArray(value, field) {
  if (!Array.isArray(value)) {
    failCaptureContract(field + " must be an array");
  }
  return value;
}

function requireNonEmptyArray(value, field) {
  const rows = requireArray(value, field);
  if (rows.length <= 0) {
    failCaptureContract(field + " must be non-empty");
  }
  return rows;
}

function requireFiniteScalar(value, field) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    failCaptureContract(field + " must be finite");
  }
  return value;
}

function requireInt(value, field) {
  const parsed = intOr(value, null);
  if (parsed == null) {
    failCaptureContract(field + " must be an integer");
  }
  return parsed | 0;
}

function requireNonNegativeInt(value, field) {
  const parsed = requireInt(value, field);
  if (parsed < 0) {
    failCaptureContract(field + " must be >= 0");
  }
  return parsed | 0;
}

function requirePositiveInt(value, field) {
  const parsed = requireInt(value, field);
  if (parsed <= 0) {
    failCaptureContract(field + " must be > 0");
  }
  return parsed | 0;
}

function requireU32(value, field) {
  if (typeof value !== "number" || !Number.isFinite(value) || Math.floor(value) !== value) {
    failCaptureContract(field + " must be an integer");
  }
  if (value < 0 || value > 0xffffffff) {
    failCaptureContract(field + " must be a uint32");
  }
  return value >>> 0;
}

function intOr(value, fallback) {
  if (value == null) return fallback;
  if (typeof value === "number" && Number.isFinite(value)) return value | 0;
  return fallback;
}

function asReplayF32(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return captureNumber(value);
  }
  return 0;
}

function requireReplayBool(value, field) {
  if (value === true || value === false) return value;
  failCaptureContract(field + " must be a boolean");
}

function _digitalMoveAxis(positivePressed, negativePressed) {
  return captureNumber((positivePressed === true ? 1.0 : 0.0) - (negativePressed === true ? 1.0 : 0.0));
}

function packReplayInputFlags(inputRow) {
  const row = inputRow && typeof inputRow === "object" ? inputRow : {};
  let flags = 0;
  if (row.fire_down === true) flags |= REPLAY_FIRE_DOWN_FLAG;
  if (row.fire_pressed === true) flags |= REPLAY_FIRE_PRESSED_FLAG;
  if (row.reload_pressed === true) flags |= REPLAY_RELOAD_PRESSED_FLAG;
  if (row.reload_down === true) flags |= REPLAY_RELOAD_DOWN_FLAG;

  const hasMoveKeys =
    row.move_forward_pressed != null ||
    row.move_backward_pressed != null ||
    row.turn_left_pressed != null ||
    row.turn_right_pressed != null;
  if (hasMoveKeys) {
    flags |= REPLAY_MOVE_KEYS_PRESENT_FLAG;
    if (row.move_forward_pressed === true) flags |= REPLAY_MOVE_FORWARD_FLAG;
    if (row.move_backward_pressed === true) flags |= REPLAY_MOVE_BACKWARD_FLAG;
    if (row.turn_left_pressed === true) flags |= REPLAY_TURN_LEFT_FLAG;
    if (row.turn_right_pressed === true) flags |= REPLAY_TURN_RIGHT_FLAG;
  }

  if (typeof row.move_mode === "number" && Number.isFinite(row.move_mode)) {
    flags |= REPLAY_MOVE_MODE_PRESENT_FLAG;
    flags |= ((row.move_mode | 0) & REPLAY_MOVE_MODE_MASK) << REPLAY_MOVE_MODE_SHIFT;
  }
  if (typeof row.aim_scheme === "number" && Number.isFinite(row.aim_scheme)) {
    flags |= REPLAY_AIM_SCHEME_PRESENT_FLAG;
    flags |= ((row.aim_scheme | 0) & REPLAY_AIM_SCHEME_MASK) << REPLAY_AIM_SCHEME_SHIFT;
  }
  return flags | 0;
}

function replayInputsFromIntentRows(rows, field) {
  const replayRows = requireArray(rows, field);
  const out = [];
  for (let i = 0; i < replayRows.length; i++) {
    const row = requireObject(replayRows[i], field + "[" + i + "]");
    requireInt(row.move_mode, field + "[" + i + "].move_mode");
    requireInt(row.aim_scheme, field + "[" + i + "].aim_scheme");
    out.push([
      requireFiniteScalar(row.move_x, field + "[" + i + "].move_x"),
      requireFiniteScalar(row.move_y, field + "[" + i + "].move_y"),
      requireFiniteScalar(row.aim_x, field + "[" + i + "].aim_x"),
      requireFiniteScalar(row.aim_y, field + "[" + i + "].aim_y"),
      packReplayInputFlags(row),
    ]);
  }
  return out;
}

function runPlayerCountFromTick(tickObj) {
  const checkpoint = requireObject(tickObj && tickObj.checkpoint, "checkpoint");
  const checkpointPlayers = requireNonEmptyArray(checkpoint.players, "checkpoint.players");
  return checkpointPlayers.length | 0;
}

function replayInputIntentFromTick(tickObj) {
  const tick = requireObject(tickObj, "tick");
  const after = requireObject(tick.after, "after");
  const globals = requireObject(after.globals, "after.globals");
  const afterPlayers = requireNonEmptyArray(after.players, "after.players");
  const keyRows = requireArray(tick.input_player_keys, "input_player_keys");
  const moveModes = requireArray(globals.config_player_mode_flags, "after.globals.config_player_mode_flags");
  const aimSchemes = requireArray(globals.config_aim_scheme, "after.globals.config_aim_scheme");
  if (moveModes.length !== afterPlayers.length) {
    failCaptureContract(
      "after.globals.config_player_mode_flags length " +
        moveModes.length +
        " does not match after.players length " +
        afterPlayers.length,
    );
  }
  if (aimSchemes.length !== afterPlayers.length) {
    failCaptureContract(
      "after.globals.config_aim_scheme length " +
        aimSchemes.length +
        " does not match after.players length " +
        afterPlayers.length,
    );
  }
  if (keyRows.length !== afterPlayers.length) {
    failCaptureContract(
      "input_player_keys length " + keyRows.length + " does not match after.players length " + afterPlayers.length,
    );
  }

  const out = [];
  for (let i = 0; i < afterPlayers.length; i++) {
    const player = requireObject(afterPlayers[i], "after.players[" + i + "]");
    const keyRow = requireObject(keyRows[i], "input_player_keys[" + i + "]");
    const moveMode = requireInt(moveModes[i], "after.globals.config_player_mode_flags[" + i + "]");
    const aimScheme = requireInt(aimSchemes[i], "after.globals.config_aim_scheme[" + i + "]");
    let moveForwardPressed = null;
    let moveBackwardPressed = null;
    let turnLeftPressed = null;
    let turnRightPressed = null;
    let moveX = null;
    let moveY = null;
    if (moveMode === MOVE_MODE_RELATIVE || moveMode === MOVE_MODE_STATIC) {
      moveForwardPressed = requireReplayBool(
        keyRow.move_forward_pressed,
        "input_player_keys[" + i + "].move_forward_pressed",
      );
      moveBackwardPressed = requireReplayBool(
        keyRow.move_backward_pressed,
        "input_player_keys[" + i + "].move_backward_pressed",
      );
      turnLeftPressed = requireReplayBool(
        keyRow.turn_left_pressed,
        "input_player_keys[" + i + "].turn_left_pressed",
      );
      turnRightPressed = requireReplayBool(
        keyRow.turn_right_pressed,
        "input_player_keys[" + i + "].turn_right_pressed",
      );
      moveX = _digitalMoveAxis(turnRightPressed, turnLeftPressed);
      moveY = _digitalMoveAxis(moveBackwardPressed, moveForwardPressed);
    } else if (moveMode === MOVE_MODE_UNKNOWN) {
      failCaptureContract(
        "after.globals.config_player_mode_flags[" + i + "] must not be UNKNOWN for replay_input_intent",
      );
    } else if (
      moveMode === MOVE_MODE_DUAL_ACTION_PAD ||
      moveMode === MOVE_MODE_MOUSE_POINT_CLICK ||
      moveMode === MOVE_MODE_COMPUTER
    ) {
      failCaptureContract(
        "after.globals.config_player_mode_flags[" +
          i +
          "]=" +
          moveMode +
          " is unsupported by replay_input_intent without raw move capture",
      );
    } else {
      failCaptureContract("after.globals.config_player_mode_flags[" + i + "] has unsupported value " + moveMode);
    }

    out.push({
      player_index: i,
      move_x: moveX,
      move_y: moveY,
      aim_x: requireFiniteScalar(player.aim_x, "after.players[" + i + "].aim_x"),
      aim_y: requireFiniteScalar(player.aim_y, "after.players[" + i + "].aim_y"),
      aim_heading: requireFiniteScalar(player.aim_heading, "after.players[" + i + "].aim_heading"),
      move_mode: moveMode,
      aim_scheme: aimScheme,
      fire_down: requireReplayBool(keyRow.fire_down, "input_player_keys[" + i + "].fire_down"),
      fire_pressed: requireReplayBool(keyRow.fire_pressed, "input_player_keys[" + i + "].fire_pressed"),
      reload_pressed: requireReplayBool(keyRow.reload_pressed, "input_player_keys[" + i + "].reload_pressed"),
      reload_down: requireReplayBool(keyRow.reload_down, "input_player_keys[" + i + "].reload_down"),
      move_forward_pressed: moveForwardPressed,
      move_backward_pressed: moveBackwardPressed,
      turn_left_pressed: turnLeftPressed,
      turn_right_pressed: turnRightPressed,
    });
  }
  return out;
}

function validateAfterPlayers(players, expectedPlayers) {
  const rows = requireNonEmptyArray(players, "after.players");
  if (rows.length !== expectedPlayers) {
    failCaptureContract(
      "after.players length " + rows.length + " does not match checkpoint.players length " + expectedPlayers
    );
  }
  for (let i = 0; i < rows.length; i++) {
    const row = requireObject(rows[i], "after.players[" + i + "]");
    const playerIndex = requireNonNegativeInt(row.index, "after.players[" + i + "].index");
    if (playerIndex !== i) {
      failCaptureContract("after.players[" + i + "].index=" + playerIndex + " does not match slot " + i);
    }
    requireFiniteScalar(row.pos_x, "after.players[" + i + "].pos_x");
    requireFiniteScalar(row.pos_y, "after.players[" + i + "].pos_y");
    requireFiniteScalar(row.move_dx, "after.players[" + i + "].move_dx");
    requireFiniteScalar(row.move_dy, "after.players[" + i + "].move_dy");
    requireFiniteScalar(row.health, "after.players[" + i + "].health");
    requireFiniteScalar(row.aim_x, "after.players[" + i + "].aim_x");
    requireFiniteScalar(row.aim_y, "after.players[" + i + "].aim_y");
    requireFiniteScalar(row.aim_heading, "after.players[" + i + "].aim_heading");
    requireInt(row.weapon_id, "after.players[" + i + "].weapon_id");
    requireFiniteScalar(row.clip_size_f32, "after.players[" + i + "].clip_size_f32");
    requireFiniteScalar(row.ammo_f32, "after.players[" + i + "].ammo_f32");
    requireInt(row.reload_active_i32, "after.players[" + i + "].reload_active_i32");
    requireFiniteScalar(row.reload_timer, "after.players[" + i + "].reload_timer");
    requireFiniteScalar(row.reload_timer_max, "after.players[" + i + "].reload_timer_max");
    requireFiniteScalar(row.shot_cooldown, "after.players[" + i + "].shot_cooldown");
    requireInt(row.experience, "after.players[" + i + "].experience");
    requireInt(row.level, "after.players[" + i + "].level");
    const bonusTimers = requireObject(row.bonus_timers, "after.players[" + i + "].bonus_timers");
    requireFiniteScalar(bonusTimers.speed_bonus, "after.players[" + i + "].bonus_timers.speed_bonus");
    requireFiniteScalar(bonusTimers.shield, "after.players[" + i + "].bonus_timers.shield");
    requireFiniteScalar(bonusTimers.fire_bullets, "after.players[" + i + "].bonus_timers.fire_bullets");
  }
  return rows;
}

function validateAfterStatus(status) {
  const row = requireObject(status, "after.status");
  requireInt(row.quest_unlock_index, "after.status.quest_unlock_index");
  requireInt(row.quest_unlock_index_full, "after.status.quest_unlock_index_full");
  const weaponUsageCounts = requireArray(row.weapon_usage_counts, "after.status.weapon_usage_counts");
  if (weaponUsageCounts.length !== STATUS_WEAPON_USAGE_COUNT) {
    failCaptureContract(
      "after.status.weapon_usage_counts length " +
        weaponUsageCounts.length +
        " does not match expected " +
        STATUS_WEAPON_USAGE_COUNT
    );
  }
  for (let i = 0; i < weaponUsageCounts.length; i++) {
    requireNonNegativeInt(weaponUsageCounts[i], "after.status.weapon_usage_counts[" + i + "]");
  }
  return row;
}

function validateAfterGlobals(globals) {
  const row = requireObject(globals, "after.globals");
  requireNonNegativeInt(row.time_played_ms, "after.globals.time_played_ms");
  requireNonNegativeInt(row.creature_kill_count, "after.globals.creature_kill_count");
  requireNonNegativeInt(row.perk_pending_count, "after.globals.perk_pending_count");
  requireInt(row.perk_choices_dirty, "after.globals.perk_choices_dirty");
  requireFiniteScalar(row.bonus_weapon_power_up_timer, "after.globals.bonus_weapon_power_up_timer");
  requireFiniteScalar(row.bonus_reflex_boost_timer, "after.globals.bonus_reflex_boost_timer");
  requireFiniteScalar(row.bonus_energizer_timer, "after.globals.bonus_energizer_timer");
  requireFiniteScalar(row.bonus_double_xp_timer, "after.globals.bonus_double_xp_timer");
  requireFiniteScalar(row.bonus_freeze_timer, "after.globals.bonus_freeze_timer");
  return row;
}

function simStateFromTick(tickObj, expectedPlayers) {
  const tick = requireObject(tickObj, "tick");
  const after = requireObject(tick.after, "after");
  const globals = validateAfterGlobals(after.globals);
  const afterPlayers = validateAfterPlayers(after.players, expectedPlayers);
  const status = validateAfterStatus(after.status);
  const players = [];

  for (let i = 0; i < afterPlayers.length; i++) {
    const player = afterPlayers[i];
    players.push({
      index: requireNonNegativeInt(player.index, "after.players[" + i + "].index"),
      pos: {
        x: requireFiniteScalar(player.pos_x, "after.players[" + i + "].pos_x"),
        y: requireFiniteScalar(player.pos_y, "after.players[" + i + "].pos_y"),
      },
      health: requireFiniteScalar(player.health, "after.players[" + i + "].health"),
      weapon: {
        weapon_id: requireInt(player.weapon_id, "after.players[" + i + "].weapon_id"),
        ammo: requireFiniteScalar(player.ammo_f32, "after.players[" + i + "].ammo_f32"),
        // Native stores clip_size as an integral f32; emit the decoded value
        // (clip_size_i32 is the raw bit pattern kept for forensics).
        clip_size: Math.round(
          requireFiniteScalar(player.clip_size_f32, "after.players[" + i + "].clip_size_f32"),
        ),
        reload_active: requireInt(player.reload_active_i32, "after.players[" + i + "].reload_active_i32") !== 0,
        reload_timer: requireFiniteScalar(player.reload_timer, "after.players[" + i + "].reload_timer"),
        reload_timer_max: requireFiniteScalar(
          player.reload_timer_max,
          "after.players[" + i + "].reload_timer_max",
        ),
        shot_cooldown: requireFiniteScalar(player.shot_cooldown, "after.players[" + i + "].shot_cooldown"),
      },
      experience: requireInt(player.experience, "after.players[" + i + "].experience"),
      level: requireInt(player.level, "after.players[" + i + "].level"),
    });
  }

  return {
    gameplay: {
      mode_id: tickModeId(tick),
      quest_stage_major: tickQuestMajor(tick),
      quest_stage_minor: tickQuestMinor(tick),
      perk_pending_count: requireNonNegativeInt(globals.perk_pending_count, "after.globals.perk_pending_count"),
      perk_choices_dirty: requireInt(globals.perk_choices_dirty, "after.globals.perk_choices_dirty") !== 0,
      bonus_timers: {
        weapon_power_up_ms: bonusTimerMs(globals.bonus_weapon_power_up_timer),
        reflex_boost_ms: bonusTimerMs(globals.bonus_reflex_boost_timer),
        energizer_ms: bonusTimerMs(globals.bonus_energizer_timer),
        double_experience_ms: bonusTimerMs(globals.bonus_double_xp_timer),
        freeze_ms: bonusTimerMs(globals.bonus_freeze_timer),
      },
      status: {
        quest_unlock_index: requireInt(status.quest_unlock_index, "after.status.quest_unlock_index"),
        quest_unlock_index_full: requireInt(status.quest_unlock_index_full, "after.status.quest_unlock_index_full"),
        weapon_usage_counts: requireArray(status.weapon_usage_counts, "after.status.weapon_usage_counts").map(
          (value, index) => requireNonNegativeInt(value, "after.status.weapon_usage_counts[" + index + "]"),
        ),
      },
    },
    players: players,
  };
}

function entitySamplesFromTick(tickObj) {
  const samples = requireObject(tickObj && tickObj.samples, "samples");
  const creaturesRaw = requireArray(samples.creatures, "samples.creatures");
  const projectilesRaw = requireArray(samples.projectiles, "samples.projectiles");
  const secondaryRaw = requireArray(samples.secondary_projectiles, "samples.secondary_projectiles");
  const bonusesRaw = requireArray(samples.bonuses, "samples.bonuses");

  beginEntityUidTick("creature");
  beginEntityUidTick("projectile");
  beginEntityUidTick("secondary_projectile");
  beginEntityUidTick("bonus");

  const creatures = [];
  for (let i = 0; i < creaturesRaw.length; i++) {
    const row = requireObject(creaturesRaw[i], "samples.creatures[" + i + "]");
    const index = requireNonNegativeInt(row.index, "samples.creatures[" + i + "].index");
    const uidState = nextEntityUid("creature", index);
    const pos = requireObject(row.pos, "samples.creatures[" + i + "].pos");
    creatures.push({
      uid: uidState.uid,
      generation: uidState.generation,
      pool_kind: "creature",
      index: index,
      active: true,
      type_id: requireInt(row.type_id, "samples.creatures[" + i + "].type_id"),
      hp: requireFiniteScalar(row.hp, "samples.creatures[" + i + "].hp"),
      pos: {
        x: requireFiniteScalar(pos.x, "samples.creatures[" + i + "].pos.x"),
        y: requireFiniteScalar(pos.y, "samples.creatures[" + i + "].pos.y"),
      },
      flags: requireInt(row.flags, "samples.creatures[" + i + "].flags"),
      ai_mode: requireInt(row.ai_mode, "samples.creatures[" + i + "].ai_mode"),
      link_index: requireInt(row.link_index, "samples.creatures[" + i + "].link_index"),
      heading: requireFiniteScalar(row.heading, "samples.creatures[" + i + "].heading"),
      target_heading: requireFiniteScalar(row.target_heading, "samples.creatures[" + i + "].target_heading"),
      orbit_angle: requireFiniteScalar(row.orbit_angle, "samples.creatures[" + i + "].orbit_angle"),
      orbit_radius: requireFiniteScalar(row.orbit_radius, "samples.creatures[" + i + "].orbit_radius"),
      lifecycle_stage: requireFiniteScalar(row.lifecycle_stage, "samples.creatures[" + i + "].lifecycle_stage"),
    });
  }

  const projectiles = [];
  for (let i = 0; i < projectilesRaw.length; i++) {
    const row = requireObject(projectilesRaw[i], "samples.projectiles[" + i + "]");
    const index = requireNonNegativeInt(row.index, "samples.projectiles[" + i + "].index");
    const uidState = nextEntityUid("projectile", index);
    const pos = requireObject(row.pos, "samples.projectiles[" + i + "].pos");
    const vel = requireObject(row.vel, "samples.projectiles[" + i + "].vel");
    projectiles.push({
      uid: uidState.uid,
      generation: uidState.generation,
      pool_kind: "projectile",
      index: index,
      active: true,
      type_id: requireInt(row.type_id, "samples.projectiles[" + i + "].type_id"),
      angle: requireFiniteScalar(row.angle, "samples.projectiles[" + i + "].angle"),
      pos: {
        x: requireFiniteScalar(pos.x, "samples.projectiles[" + i + "].pos.x"),
        y: requireFiniteScalar(pos.y, "samples.projectiles[" + i + "].pos.y"),
      },
      vel: {
        x: requireFiniteScalar(vel.x, "samples.projectiles[" + i + "].vel.x"),
        y: requireFiniteScalar(vel.y, "samples.projectiles[" + i + "].vel.y"),
      },
      life_timer: requireFiniteScalar(row.life_timer, "samples.projectiles[" + i + "].life_timer"),
      speed_scale: requireFiniteScalar(row.speed_scale, "samples.projectiles[" + i + "].speed_scale"),
      damage_pool: requireFiniteScalar(row.damage_pool, "samples.projectiles[" + i + "].damage_pool"),
      hit_radius: requireFiniteScalar(row.hit_radius, "samples.projectiles[" + i + "].hit_radius"),
      travel_budget: requireFiniteScalar(row.travel_budget, "samples.projectiles[" + i + "].travel_budget"),
      owner_id: requireInt(row.owner_id, "samples.projectiles[" + i + "].owner_id"),
    });
  }

  const secondary_projectiles = [];
  for (let i = 0; i < secondaryRaw.length; i++) {
    const row = requireObject(secondaryRaw[i], "samples.secondary_projectiles[" + i + "]");
    const index = requireNonNegativeInt(row.index, "samples.secondary_projectiles[" + i + "].index");
    const uidState = nextEntityUid("secondary_projectile", index);
    const pos = requireObject(row.pos, "samples.secondary_projectiles[" + i + "].pos");
    const vel = requireObject(row.vel, "samples.secondary_projectiles[" + i + "].vel");
    const velX = requireFiniteScalar(vel.x, "samples.secondary_projectiles[" + i + "].vel.x");
    const velY = requireFiniteScalar(vel.y, "samples.secondary_projectiles[" + i + "].vel.y");
    secondary_projectiles.push({
      uid: uidState.uid,
      generation: uidState.generation,
      pool_kind: "secondary_projectile",
      index: index,
      active: true,
      type_id: requireInt(row.type_id, "samples.secondary_projectiles[" + i + "].type_id"),
      angle: requireFiniteScalar(row.angle, "samples.secondary_projectiles[" + i + "].angle"),
      pos: {
        x: requireFiniteScalar(pos.x, "samples.secondary_projectiles[" + i + "].pos.x"),
        y: requireFiniteScalar(pos.y, "samples.secondary_projectiles[" + i + "].pos.y"),
      },
      vel: {
        x: velX,
        y: velY,
      },
      speed: requireFiniteScalar(row.speed, "samples.secondary_projectiles[" + i + "].speed"),
      trail_timer: requireFiniteScalar(row.trail_timer, "samples.secondary_projectiles[" + i + "].trail_timer"),
      owner_id: requireInt(row.owner_id, "samples.secondary_projectiles[" + i + "].owner_id"),
      target_id: requireInt(row.target_id, "samples.secondary_projectiles[" + i + "].target_id"),
    });
  }

  const bonuses = [];
  for (let i = 0; i < bonusesRaw.length; i++) {
    const row = requireObject(bonusesRaw[i], "samples.bonuses[" + i + "]");
    const index = requireNonNegativeInt(row.index, "samples.bonuses[" + i + "].index");
    const uidState = nextEntityUid("bonus", index);
    const pos = requireObject(row.pos, "samples.bonuses[" + i + "].pos");
    bonuses.push({
      uid: uidState.uid,
      generation: uidState.generation,
      pool_kind: "bonus",
      index: index,
      active: true,
      bonus_id: requireInt(row.bonus_id, "samples.bonuses[" + i + "].bonus_id"),
      picked: requireInt(row.state, "samples.bonuses[" + i + "].state") !== 0,
      time_left: requireFiniteScalar(row.time_left, "samples.bonuses[" + i + "].time_left"),
      time_max: requireFiniteScalar(row.time_max, "samples.bonuses[" + i + "].time_max"),
      pos: {
        x: requireFiniteScalar(pos.x, "samples.bonuses[" + i + "].pos.x"),
        y: requireFiniteScalar(pos.y, "samples.bonuses[" + i + "].pos.y"),
      },
      amount: requireInt(row.amount_i32, "samples.bonuses[" + i + "].amount_i32"),
    });
  }

  endEntityUidTick("creature");
  endEntityUidTick("projectile");
  endEntityUidTick("secondary_projectile");
  endEntityUidTick("bonus");

  return {
    creatures: creatures,
    projectiles: projectiles,
    secondary_projectiles: secondary_projectiles,
    bonuses: bonuses,
  };
}

function rngStreamFromTick(tickObj) {
  const rows = requireArray(tickObj && tickObj.rng_stream, "rng_stream");
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    const row = requireObject(rows[i], "rng_stream[" + i + "]");
    const tickCallIndex = requirePositiveInt(row.tick_call_index, "rng_stream[" + i + "].tick_call_index");
    const value15 = requireInt(row.value_15, "rng_stream[" + i + "].value_15");
    if (value15 < 0 || value15 > 0x7fff) {
      failCaptureContract("rng_stream[" + i + "].value_15 must be in 0..32767");
    }
    const stateBefore = requireU32(row.state_before_u32, "rng_stream[" + i + "].state_before_u32");
    const stateAfter = requireU32(row.state_after_u32, "rng_stream[" + i + "].state_after_u32");
    out.push({
      tick_call_index: tickCallIndex,
      value_15: value15,
      state_before_u32: stateBefore,
      state_after_u32: stateAfter,
      caller_static: row.caller_static == null ? null : String(row.caller_static),
    });
  }
  return out;
}

function rngOutsideBagFromRows(bag, field) {
  const src = requireObject(bag, field);
  const calls = requireInt(src.calls, field + ".calls");
  const dropped = requireInt(src.dropped, field + ".dropped");
  if (calls < 0 || dropped < 0) {
    failCaptureContract(field + " calls/dropped must be >= 0");
  }
  const callerCounts = {};
  const srcCounts = src.caller_counts && typeof src.caller_counts === "object" ? src.caller_counts : {};
  const countKeys = Object.keys(srcCounts);
  for (let i = 0; i < countKeys.length; i++) {
    callerCounts[String(countKeys[i])] = srcCounts[countKeys[i]] | 0;
  }
  const head = requireArray(src.head, field + ".head");
  const rows = [];
  for (let i = 0; i < head.length; i++) {
    const row = requireObject(head[i], field + ".head[" + i + "]");
    rows.push({
      value_15: row.value_15 == null ? null : row.value_15 | 0,
      state_before_u32: requireU32(row.state_before_u32, field + ".head[" + i + "].state_before_u32"),
      state_after_u32: requireU32(row.state_after_u32, field + ".head[" + i + "].state_after_u32"),
      caller_static: row.caller_static == null ? null : String(row.caller_static),
    });
  }
  return {
    calls: calls,
    dropped: dropped,
    caller_counts: callerCounts,
    head: rows,
  };
}

function timingSamplesFromTick(tickObj) {
  const out = [];
  const tickIndex = tickObj && tickObj.tick_index != null ? tickObj.tick_index | 0 : -1;
  const gameplayFrame = tickObj && tickObj.gameplay_frame != null ? tickObj.gameplay_frame | 0 : null;
  const rawRows = requireArray(tickObj && tickObj.timing_samples, "timing_samples");
  for (let i = 0; i < rawRows.length; i++) {
    const row = requireObject(rawRows[i], "timing_samples[" + i + "]");
    const phase = row.phase == null ? "" : String(row.phase);
    const writeKind = row.write_kind == null ? "" : String(row.write_kind);
    if (!phase) failCaptureContract("timing_samples[" + i + "].phase must be non-empty");
    if (!writeKind) failCaptureContract("timing_samples[" + i + "].write_kind must be non-empty");
    out.push({
      tick_index: row.tick_index == null ? tickIndex : intOr(row.tick_index, tickIndex),
      gameplay_frame: row.gameplay_frame == null ? gameplayFrame : intOr(row.gameplay_frame, gameplayFrame),
      phase: phase,
      write_kind: writeKind,
      frame_dt_f32: row.frame_dt_f32 == null ? null : captureNumber(row.frame_dt_f32),
      frame_dt_ms_i32: row.frame_dt_ms_i32 == null ? null : intOr(row.frame_dt_ms_i32, null),
      frame_dt_ms_f32: row.frame_dt_ms_f32 == null ? null : captureNumber(row.frame_dt_ms_f32),
      time_scale_active_entry:
        row.time_scale_active_entry == null ? null : !!row.time_scale_active_entry,
      time_scale_active_current:
        row.time_scale_active_current == null ? null : !!row.time_scale_active_current,
      time_scale_factor: row.time_scale_factor == null ? null : captureNumber(row.time_scale_factor),
      bonus_reflex_boost_timer:
        row.bonus_reflex_boost_timer == null ? null : captureNumber(row.bonus_reflex_boost_timer),
      mode_fn: row.mode_fn == null ? null : String(row.mode_fn),
      player_index: row.player_index == null ? null : intOr(row.player_index, null),
    });
  }
  return out;
}

function requireTimingSampleByPhase(rows, phase) {
  const samplePhase = String(phase);
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    if (!row || typeof row !== "object") continue;
    if (String(row.phase || "") === samplePhase) return row;
  }
  failCaptureContract("timing_samples must include phase `" + samplePhase + "`");
}

function normalizeRunElapsedMs(rawElapsedMs, dtMsI32) {
  const dt = dtMsI32 == null ? null : dtMsI32 | 0;
  if (dt == null || dt <= 0) return intOr(rawElapsedMs, -1);

  const raw = intOr(rawElapsedMs, -1);
  const isFirstRunTick =
    (outState.currentRunTickCount | 0) <= 0 || outState.currentRunElapsedNormalizedMs == null;
  if (isFirstRunTick) {
    outState.currentRunElapsedRawStartMs = raw;
    outState.currentRunElapsedRawLastMs = raw;
    outState.currentRunElapsedNormalizedMs = dt;
    return outState.currentRunElapsedNormalizedMs | 0;
  }

  outState.currentRunElapsedRawLastMs = raw;
  outState.currentRunElapsedNormalizedMs = (outState.currentRunElapsedNormalizedMs | 0) + dt;
  return outState.currentRunElapsedNormalizedMs | 0;
}

// tick rows are replay-grade rows. Missing required fields are contract errors,
// not something finalize should coerce after the fact.
function buildTraceTickRow(tickObj) {
  try {
    requireObject(tickObj, "tick");
    const checkpoint = requireObject(tickObj.checkpoint, "checkpoint");
    const checkpointPlayers = requireNonEmptyArray(checkpoint.players, "checkpoint.players");
    requireU32(checkpoint.rng_state, "checkpoint.rng_state");
    const rngStream = rngStreamFromTick(tickObj);
    const rngCalls = requireInt(tickObj.rng_calls, "rng_calls");
    if (rngCalls !== rngStream.length) {
      // The replay contract needs the complete in-tick stream; a truncated
      // head (max_rng_head_per_tick override) is a capture error.
      failCaptureContract(
        "rng_calls " + rngCalls + " does not match rng_stream length " + rngStream.length
      );
    }
    const rngOutsideBefore = rngOutsideBagFromRows(tickObj.rng_outside_before, "rng_outside_before");
    const rngStateEnter = requireU32(tickObj.rng_state_enter_u32, "rng_state_enter_u32");
    const rngStateLeave = requireU32(tickObj.rng_state_leave_u32, "rng_state_leave_u32");
    const timingSamples = timingSamplesFromTick(tickObj);
    if (timingSamples.length <= 0) {
      failCaptureContract("timing_samples must be non-empty");
    }
    const gpurEnterSample = requireTimingSampleByPhase(timingSamples, "gpur_enter");
    checkpoint.state_hash = "";
    checkpoint.command_hash = "";
    const modeId = tickModeId(tickObj);
    if (modeId < 0) {
      failCaptureContract("mode_id must be non-negative");
    }
    const dtMsI32 =
      gpurEnterSample.frame_dt_ms_i32 == null ? null : intOr(gpurEnterSample.frame_dt_ms_i32, null);
    if (dtMsI32 == null || !Number.isFinite(dtMsI32) || dtMsI32 < 0) {
      failCaptureContract("timing_samples.gpur_enter.frame_dt_ms_i32 must be finite and >= 0");
    }
    const dtSeconds =
      gpurEnterSample.frame_dt_f32 == null ? null : captureNumber(gpurEnterSample.frame_dt_f32);
    if (dtSeconds == null || !Number.isFinite(dtSeconds) || dtSeconds < 0) {
      failCaptureContract("timing_samples.gpur_enter.frame_dt_f32 must be finite and >= 0");
    }
    const elapsedRawMs = requireInt(checkpoint.elapsed_ms, "checkpoint.elapsed_ms");
    const elapsedMs = normalizeRunElapsedMs(elapsedRawMs, dtMsI32);
    if (!Number.isFinite(elapsedMs) || elapsedMs < 0) {
      failCaptureContract("elapsed_ms must be finite and >= 0");
    }
    checkpoint.elapsed_ms = elapsedMs;
    const playerCount = checkpointPlayers.length | 0;
    const replayInputIntent = replayInputIntentFromTick(tickObj);
    const replayInputs = replayInputsFromIntentRows(replayInputIntent, "replay_input_intent");
    if ((replayInputs.length | 0) !== (playerCount | 0)) {
      failCaptureContract(
        "replay_inputs length " + replayInputs.length + " does not match checkpoint.players length " + playerCount
      );
    }
    const simState = simStateFromTick(tickObj, playerCount);

    return {
      event: "tick",
      run_id: outState.currentRunId | 0,
      tick_index_global: tickObj && tickObj.tick_index != null ? tickObj.tick_index | 0 : null,
      elapsed_ms: elapsedMs,
      dt: dtSeconds,
      dt_ms_i32: dtMsI32,
      mode_id: modeId,
      quest_stage_major: tickQuestMajor(tickObj),
      quest_stage_minor: tickQuestMinor(tickObj),
      replay_inputs: replayInputs,
      rng_calls: rngCalls,
      rng_outside_before: rngOutsideBefore,
      rng_state_enter_u32: rngStateEnter,
      rng_state_leave_u32: rngStateLeave,
      channels: {
        checkpoint: checkpoint,
        rng_stream: rngStream,
        timing_samples: timingSamples,
        sim_state: simState,
        entity_samples: entitySamplesFromTick(tickObj),
      },
    };
  } catch (error) {
    if (isCaptureContractError(error)) {
      return emitCaptureContractError(error.message, tickObj);
    }
    throw error;
  }
}

function writeCaptureTick(tickObj) {
  if (!tickObj) return;
  if (!outState.captureStarted || outState.captureClosed) return;
  if (!ensureRunForTick(tickObj)) return;
  const tickRow = buildTraceTickRow(tickObj);
  if (!tickRow) return;
  const wrote = _captureWriteJsonLine(tickRow, true);
  if (wrote) {
    outState.captureTickCount += 1;
    outState.currentRunTickCount += 1;
    if (outState.currentRunBootstrapQuestAttemptPending && (outState.currentRunTickCount | 0) > 1) {
      outState.currentRunBootstrapQuestAttemptPending = false;
    }
    outState.lastTickIndexGlobal = tickObj.tick_index == null ? null : tickObj.tick_index | 0;
    return;
  }
  emitCaptureContractError("tick_write_failed", tickObj);
}

function closeCaptureFile() {
  if (!outState.captureStarted || outState.captureClosed) return;
  try {
    if (outState.outFile) {
      if (CONFIG.flushCaptureWrites) outState.outFile.flush();
      outState.outFile.close();
    }
  } catch (_) {
  }
  outState.outFile = null;
  outState.captureClosed = true;
}

function shutdownCapture(reason) {
  if (outState.shutdownComplete) return;
  outState.shutdownComplete = true;
  const why = reason || "shutdown";
  try {
    if (outState.heartbeatTimer) {
      clearInterval(outState.heartbeatTimer);
      outState.heartbeatTimer = null;
    }
  } catch (_) {}
  try {
    finalizeTick();
  } catch (_) {}
  try {
    closeActiveRun("shutdown", null);
  } catch (_) {}
  try {
    const wroteSessionEnd = _captureWriteJsonLine(
      {
        event: "session_end",
        session_id: outState.sessionId,
        ticks_written: outState.captureTickCount | 0,
      },
      true,
    );
    if (wroteSessionEnd) _captureForceFlush();
  } catch (_) {}
  try {
    closeCaptureFile();
  } catch (_) {}
  try {
    writeLine({
      event: "capture_shutdown",
      reason: why,
      ticks_written: outState.captureTickCount,
      capture_started: outState.captureStarted,
      capture_closed: outState.captureClosed,
      out_path: outState.currentOutPath || CONFIG.outPath,
      run_id: outState.currentRunId | 0,
    });
  } catch (_) {}
}

function installShutdownHooks() {
  const attached = {};

  function attachExitHook(moduleName, exportName, reasonPrefix, codeArgIndex) {
    let target = null;
    try {
      target = Module.findExportByName(moduleName, exportName);
    } catch (_) {
      target = null;
    }
    if (!target) return;
    const key = target.toString();
    if (attached[key]) return;
    attached[key] = true;
    try {
      Interceptor.attach(target, {
        onEnter: function (args) {
          let code = null;
          if (codeArgIndex >= 0) {
            try {
              code = args[codeArgIndex] ? args[codeArgIndex].toInt32() : null;
            } catch (_) {
              code = null;
            }
          }
          const reason = code == null ? reasonPrefix : reasonPrefix + ":" + String(code);
          shutdownCapture(reason);
        },
      });
    } catch (_) {}
  }

  attachExitHook("kernel32.dll", "ExitProcess", "exit_process", 0);
  attachExitHook("kernel32.dll", "TerminateProcess", "terminate_process", 1);
  attachExitHook("ntdll.dll", "RtlExitUserProcess", "rtl_exit_user_process", 0);
  attachExitHook("msvcrt.dll", "exit", "crt_exit", 0);
  attachExitHook("msvcrt.dll", "_exit", "crt__exit", 0);
  attachExitHook("ucrtbase.dll", "exit", "ucrt_exit", 0);
  attachExitHook("ucrtbase.dll", "_exit", "ucrt__exit", 0);

  try {
    Process.setExceptionHandler(function (details) {
      const payload = buildProcessExceptionPayload(details);
      const reason = buildProcessExceptionReason(payload);
      outState.lastException = Object.assign({ reason: reason }, payload);
      writeLine(
        Object.assign(
          {
            event: "error",
            error: reason,
          },
          payload,
        ),
      );
      shutdownCapture(reason);
      return false;
    });
  } catch (_) {}
}

function safeReadU8(ptrVal) {
  try {
    return ptrVal.readU8();
  } catch (_) {
    return null;
  }
}

function safeReadS32(ptrVal) {
  try {
    return ptrVal.readS32();
  } catch (_) {
    return null;
  }
}

function safeReadU32(ptrVal) {
  try {
    return ptrVal.readU32();
  } catch (_) {
    return null;
  }
}

function safeReadF32(ptrVal) {
  try {
    return ptrVal.readFloat();
  } catch (_) {
    return null;
  }
}

function safeReadF32Bits(ptrVal) {
  try {
    return ptrVal.readU32();
  } catch (_) {
    return null;
  }
}

function safeReadCString(ptrVal, maxLen) {
  if (!ptrVal) return null;
  try {
    const len = maxLen || 128;
    const out = [];
    for (let i = 0; i < len; i++) {
      const b = ptrVal.add(i).readU8();
      if (b === 0) break;
      out.push(b);
    }
    return out.length ? String.fromCharCode.apply(null, out) : "";
  } catch (_) {
    return null;
  }
}

function u32ToF32(u32) {
  const buf = new ArrayBuffer(4);
  const dv = new DataView(buf);
  dv.setUint32(0, u32 >>> 0, true);
  return dv.getFloat32(0, true);
}

function f32ToU32(v) {
  const buf = new ArrayBuffer(4);
  const dv = new DataView(buf);
  dv.setFloat32(0, Number(v), true);
  return dv.getUint32(0, true);
}

function argAsF32(arg) {
  if (!arg) return null;
  try {
    return u32ToF32(arg.toUInt32());
  } catch (_) {
    return null;
  }
}

function readDataI32(name) {
  const p = dataPtrs[name];
  if (!p) return null;
  return safeReadS32(p);
}

function readDataU32(name) {
  const p = dataPtrs[name];
  if (!p) return null;
  return safeReadU32(p);
}

function readDataF32(name) {
  const p = dataPtrs[name];
  if (!p) return null;
  return captureF32Bits(safeReadF32Bits(p));
}

function readDataF32Stride(name, index, strideBytes) {
  const p = dataPtrs[name];
  if (!p) return null;
  return captureF32Bits(safeReadF32Bits(p.add(index * strideBytes)));
}

function readDataI32Stride(name, index, strideBytes) {
  const p = dataPtrs[name];
  if (!p) return null;
  return safeReadS32(p.add(index * strideBytes));
}

function readConfigPerPlayerI32(name) {
  const count = Math.max(1, outState.playerCountResolved | 0);
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push(readDataI32Stride(name, i, 4));
  }
  return out;
}

function readStatusSnapshotCompact() {
  const packed = readDataU32("game_status_blob");
  const questUnlock = packed == null ? null : packed & 0xffff;
  const questUnlockFull = packed == null ? null : (packed >>> 16) & 0xffff;
  const counts = [];
  const base = dataPtrs.status_weapon_usage_counts;
  if (base) {
    for (let i = 0; i < STATUS_WEAPON_USAGE_COUNT; i++) {
      const value = safeReadU32(base.add(i * 4));
      counts.push(value == null ? null : value >>> 0);
    }
  }
  return {
    quest_unlock_index: questUnlock,
    quest_unlock_index_full: questUnlockFull,
    weapon_usage_counts: counts,
  };
}

function readPlayerI32(name, playerIndex) {
  const p = dataPtrs[name];
  if (!p) return null;
  return safeReadS32(p.add(playerIndex * STRIDES.player));
}

function readPlayerU32(name, playerIndex) {
  const p = dataPtrs[name];
  if (!p) return null;
  return safeReadU32(p.add(playerIndex * STRIDES.player));
}

function readPlayerF32(name, playerIndex) {
  const p = dataPtrs[name];
  if (!p) return null;
  return captureF32Bits(safeReadF32Bits(p.add(playerIndex * STRIDES.player)));
}

function runtimeToStatic(addr) {
  if (!addr || !Process.findModuleByAddress) return null;
  try {
    const mod = Process.findModuleByAddress(addr);
    if (!mod) return null;
    if (String(mod.name).toLowerCase() !== GAME_MODULE.toLowerCase()) return null;
    const delta = addr.sub(mod.base).toUInt32();
    return (0x00400000 + delta) >>> 0;
  } catch (_) {
    return null;
  }
}

// The multithread CRT keeps the rand LCG state at per-thread-data + 0x14
// (srand: `mov [ptd+0x14], seed`; rand: `imul/add` on the same slot). Reading
// it from memory observes the REAL stream, including rand sites the
// crt_rand hook never sees (inlined or otherwise unhooked draws); those show
// up as LCG chain gaps between consecutive observed states.
const CRT_PTD_RAND_STATE_OFFSET = 0x14;
let crtGetPtdFn = null;

function ensureCrtGetPtdFn() {
  if (crtGetPtdFn != null) return crtGetPtdFn;
  if (!fnPtrs.crt_getptd) return null;
  try {
    crtGetPtdFn = new NativeFunction(fnPtrs.crt_getptd, "pointer", [], "mscdecl");
  } catch (_) {
    crtGetPtdFn = null;
  }
  return crtGetPtdFn;
}

// Must execute on the observed thread (hook callbacks do); the ptd pointer is
// stable per thread so only the first read per thread calls _getptd.
function readCrtRandStateU32(threadId) {
  try {
    let ptd = crtPtdByTid[threadId];
    if (!ptd) {
      const fn = ensureCrtGetPtdFn();
      if (!fn) return null;
      ptd = fn();
      if (!ptd || ptd.isNull()) return null;
      crtPtdByTid[threadId] = ptd;
    }
    return ptd.add(CRT_PTD_RAND_STATE_OFFSET).readU32() >>> 0;
  } catch (_) {
    return null;
  }
}

function isProjectileUpdateCaller(callerStatic) {
  if (callerStatic == null) return false;
  const addr = callerStatic >>> 0;
  return addr >= PROJECTILE_UPDATE_START && addr <= PROJECTILE_UPDATE_END;
}

function formatCaller(addr) {
  if (!addr) return null;
  try {
    const mod = Process.findModuleByAddress(addr);
    if (!mod) return addr.toString();
    const off = addr.sub(mod.base).toUInt32();
    return mod.name + "+0x" + off.toString(16);
  } catch (_) {
    return null;
  }
}

function maybeBacktrace(context) {
  if (!CONFIG.includeBacktrace) return null;
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 8)
      .map((addr) => formatCaller(addr) || addr.toString());
  } catch (_) {
    return null;
  }
}

function exceptionBacktrace(context) {
  if (!context) return null;
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 12)
      .map((addr) => formatCaller(addr) || addr.toString());
  } catch (_) {
    return null;
  }
}

function captureF32Bits(bits) {
  if (bits == null) return null;
  return u32ToF32(bits >>> 0);
}

function decodeCapturedF32(v) {
  if (v == null) return null;
  if (typeof v !== "number") return null;
  if (!Number.isFinite(v)) return null;
  return Number(v);
}

function frameDtSource(globalsObj) {
  if (!globalsObj || typeof globalsObj !== "object") return "none";
  if (globalsObj.frame_dt_ms_i32 != null) return "frame_dt_ms_i32";
  if (globalsObj.frame_dt_ms_f32 != null) return "frame_dt_ms_f32";
  if (decodeCapturedF32(globalsObj.frame_dt) != null) return "frame_dt_f32";
  return "none";
}

function captureNumber(v) {
  if (v == null) return null;
  if (!Number.isFinite(v)) return null;
  return captureF32Bits(f32ToU32(v));
}

function normalizeSampleLimit(limit) {
  if (!Number.isFinite(limit)) return -1;
  if (limit < 0) return -1;
  return limit | 0;
}

function bonusTimerMs(v) {
  const value = decodeCapturedF32(v);
  if (value == null || !Number.isFinite(value)) return -1;
  const ms = Math.round(value * 1000);
  return ms < 0 ? 0 : ms;
}

function fnvInit() {
  return 0x811c9dc5 >>> 0;
}

function fnvMixByte(h, byteVal) {
  h ^= byteVal & 0xff;
  h = Math.imul(h, 0x01000193) >>> 0;
  return h >>> 0;
}

function fnvMixString(h, text) {
  const s = String(text);
  for (let i = 0; i < s.length; i++) {
    h = fnvMixByte(h, s.charCodeAt(i));
  }
  return h >>> 0;
}

function hashAny(h, value) {
  if (value === null || value === undefined) return fnvMixString(h, "n");
  const t = typeof value;
  if (t === "number") {
    if (!Number.isFinite(value)) return fnvMixString(h, "d:nan");
    return fnvMixString(h, "d:" + captureNumber(value));
  }
  if (t === "string") return fnvMixString(h, "s:" + value);
  if (t === "boolean") return fnvMixString(h, value ? "b:1" : "b:0");
  if (Array.isArray(value)) {
    h = fnvMixString(h, "[");
    for (let i = 0; i < value.length; i++) h = hashAny(h, value[i]);
    h = fnvMixString(h, "]");
    return h >>> 0;
  }
  if (t === "object") {
    h = fnvMixString(h, "{");
    const keys = Object.keys(value).sort();
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      h = fnvMixString(h, "k:" + k);
      h = hashAny(h, value[k]);
    }
    h = fnvMixString(h, "}");
    return h >>> 0;
  }
  return fnvMixString(h, "u");
}

function hashHex(value) {
  return toHex(hashAny(fnvInit(), value) >>> 0, 8);
}

function hasFocusWindow() {
  return Number.isFinite(CONFIG.focusTick) && CONFIG.focusTick >= 0;
}

function isFocusTick(tickIndex) {
  if (!hasFocusWindow()) return true;
  if (!Number.isFinite(tickIndex)) return false;
  return Math.abs((tickIndex | 0) - (CONFIG.focusTick | 0)) <= CONFIG.focusRadius;
}

function shouldEmitRawEvent() {
  return !!CONFIG.includeRawEvents;
}

function hashModuleSample(exeModule) {
  if (!exeModule) return null;
  const size = exeModule.size | 0;
  if (size <= 0) return null;
  const sampleCount = 128;
  const stride = Math.max(1, Math.floor(size / sampleCount));
  let h = fnvInit();
  for (let i = 0; i < sampleCount; i++) {
    const off = Math.min(size - 1, i * stride);
    const b = safeReadU8(exeModule.base.add(off));
    h = fnvMixByte(h, b == null ? 0 : b);
  }
  return toHex(h >>> 0, 8);
}

function makeSessionFingerprint(exeModule, ptrs) {
  const moduleHash = hashModuleSample(exeModule);
  const payload = {
    pid: Process.id,
    path: exeModule ? exeModule.path : null,
    size: exeModule ? exeModule.size : null,
    module_hash: moduleHash,
    ptrs: ptrs,
    started_ms: nowMs(),
  };
  return {
    session_id: hashHex(payload),
    module_hash: moduleHash,
    ptrs_hash: hashHex(ptrs || {}),
  };
}

function resolvePointers(exeModule, grimModule) {
  for (const key in FN) {
    try {
      fnPtrs[key] = exeModule.base.add(ptr(FN[key]).sub(LINK_BASE));
    } catch (_) {
      fnPtrs[key] = null;
    }
  }
  for (const key in FN_GRIM_RVA) {
    try {
      grimFnPtrs[key] = grimModule ? grimModule.base.add(FN_GRIM_RVA[key]) : null;
    } catch (_) {
      grimFnPtrs[key] = null;
    }
  }
  for (const key in DATA) {
    try {
      dataPtrs[key] = exeModule.base.add(ptr(DATA[key]).sub(LINK_BASE));
    } catch (_) {
      dataPtrs[key] = null;
    }
  }
}

function readGameplayGlobalsCompact() {
  return {
    config_game_mode: readDataI32("config_game_mode"),
    config_player_mode_flags: readConfigPerPlayerI32("config_player_mode_flags"),
    config_aim_scheme: readConfigPerPlayerI32("config_aim_scheme"),
    game_state_prev: readDataI32("game_state_prev"),
    game_state_id: readDataI32("game_state_id"),
    game_state_pending: readDataI32("game_state_pending"),
    frame_dt: readDataF32("frame_dt"),
    frame_dt_ms_i32: readDataI32("frame_dt_ms"),
    // The native global is an i32; emit its numeric value (a float read of
    // the same address yields a denormal bit pattern).
    frame_dt_ms_f32: readDataI32("frame_dt_ms"),
    time_played_ms: readDataI32("time_played_ms"),
    creature_active_count: readDataI32("creature_active_count"),
    creature_kill_count: readDataI32("creature_kill_count"),
    perk_pending_count: readDataI32("perk_pending_count"),
    perk_choices_dirty: readDataI32("perk_choices_dirty"),
    shock_chain_links_left: readDataI32("shock_chain_links_left"),
    shock_chain_projectile_id: readDataI32("shock_chain_projectile_id"),
    quest_spawn_timeline: readDataI32("quest_spawn_timeline"),
    quest_stage_major: readDataI32("quest_stage_major"),
    quest_stage_minor: readDataI32("quest_stage_minor"),
    quest_spawn_stall_timer_ms: readDataI32("quest_spawn_stall_timer_ms"),
    quest_transition_timer_ms: readDataI32("quest_transition_timer_ms"),
    quest_stage_banner_timer_ms: readDataI32("quest_stage_banner_timer_ms"),
    ui_elements_timeline: readDataF32("ui_elements_timeline"),
    ui_transition_direction: readDataI32("ui_transition_direction"),
    ui_transition_alpha: readDataF32("ui_transition_alpha"),
    pause_keybind_help_alpha_ms: readDataI32("pause_keybind_help_alpha_ms"),
    player_alt_weapon_swap_cooldown_ms: readDataI32("player_alt_weapon_swap_cooldown_ms"),
    perk_jinxed_proc_timer_s: readDataF32("perk_jinxed_proc_timer_s"),
    perk_lean_mean_exp_tick_timer_s: readDataF32("perk_lean_mean_exp_tick_timer_s"),
    perk_doctor_target_creature_id: readDataI32("perk_doctor_target_creature_id"),
    bonus_reflex_boost_timer: readDataF32("bonus_reflex_boost_timer"),
    bonus_freeze_timer: readDataF32("bonus_freeze_timer"),
    bonus_weapon_power_up_timer: readDataF32("bonus_weapon_power_up_timer"),
    bonus_energizer_timer: readDataF32("bonus_energizer_timer"),
    bonus_double_xp_timer: readDataF32("bonus_double_xp_timer"),
  };
}

function readPlayerCompact(playerIndex) {
  const clipU32 = readPlayerU32("player_clip_size", playerIndex);
  const ammoU32 = readPlayerU32("player_ammo", playerIndex);
  const reloadActiveU32 = readPlayerU32("player_reload_active", playerIndex);

  return {
    index: playerIndex,
    pos_x: captureNumber(readPlayerF32("player_pos_x", playerIndex)),
    pos_y: captureNumber(readPlayerF32("player_pos_y", playerIndex)),
    move_dx: captureNumber(readPlayerF32("player_move_dx", playerIndex)),
    move_dy: captureNumber(readPlayerF32("player_move_dy", playerIndex)),
    health: captureNumber(readPlayerF32("player_health", playerIndex)),
    aim_x: captureNumber(readPlayerF32("player_aim_x", playerIndex)),
    aim_y: captureNumber(readPlayerF32("player_aim_y", playerIndex)),
    aim_heading: captureNumber(readPlayerF32("player_aim_heading", playerIndex)),
    weapon_id: readPlayerI32("player_weapon_id", playerIndex),
    clip_size_i32: clipU32 == null ? null : clipU32 | 0,
    clip_size_f32: clipU32 == null ? null : captureNumber(u32ToF32(clipU32)),
    ammo_i32: ammoU32 == null ? null : ammoU32 | 0,
    ammo_f32: ammoU32 == null ? null : captureNumber(u32ToF32(ammoU32)),
    reload_active_i32: reloadActiveU32 == null ? null : reloadActiveU32 | 0,
    reload_active_f32: reloadActiveU32 == null ? null : captureNumber(u32ToF32(reloadActiveU32)),
    reload_timer: captureNumber(readPlayerF32("player_reload_timer", playerIndex)),
    reload_timer_max: captureNumber(readPlayerF32("player_reload_timer_max", playerIndex)),
    shot_cooldown: captureNumber(readPlayerF32("player_shot_cooldown", playerIndex)),
    spread_heat: captureNumber(readPlayerF32("player_spread_heat", playerIndex)),
    experience: readPlayerI32("player_experience", playerIndex),
    level: readPlayerI32("player_level", playerIndex),
    perk_timers: {
      hot_tempered: captureNumber(readPlayerF32("player_hot_tempered_timer", playerIndex)),
      man_bomb: captureNumber(readPlayerF32("player_man_bomb_timer", playerIndex)),
      living_fortress: captureNumber(readPlayerF32("player_living_fortress_timer", playerIndex)),
      fire_cough: captureNumber(readPlayerF32("player_fire_cough_timer", playerIndex)),
    },
    bonus_timers: {
      speed_bonus: captureNumber(readPlayerF32("player_speed_bonus_timer", playerIndex)),
      shield: captureNumber(readPlayerF32("player_shield_timer", playerIndex)),
      fire_bullets: captureNumber(readPlayerF32("player_fire_bullets_timer", playerIndex)),
    },
    alt_weapon: {
      weapon_id: readPlayerI32("player_alt_weapon_id", playerIndex),
      clip_size_i32: readPlayerI32("player_alt_clip_size", playerIndex),
      reload_active_i32: readPlayerI32("player_alt_reload_active", playerIndex),
      ammo_i32: readPlayerI32("player_alt_ammo", playerIndex),
      reload_timer: captureNumber(readPlayerF32("player_alt_reload_timer", playerIndex)),
      shot_cooldown: captureNumber(readPlayerF32("player_alt_shot_cooldown", playerIndex)),
      reload_timer_max: captureNumber(readPlayerF32("player_alt_reload_timer_max", playerIndex)),
    },
  };
}

function readPlayersCompact() {
  const count = outState.playerCountResolved;
  const out = [];
  for (let i = 0; i < count; i++) out.push(readPlayerCompact(i));
  return out;
}

function readInputBindingsCompact() {
  const count = outState.playerCountResolved;
  const players = [];
  for (let i = 0; i < count; i++) {
    players.push({
      player_index: i,
      move_forward: readPlayerI32("player_move_key_forward", i),
      move_backward: readPlayerI32("player_move_key_backward", i),
      turn_left: readPlayerI32("player_turn_key_left", i),
      turn_right: readPlayerI32("player_turn_key_right", i),
      fire: readPlayerI32("player_fire_key", i),
      aim_left: readPlayerI32("player_aim_key_left", i),
      aim_right: readPlayerI32("player_aim_key_right", i),
      axis_aim_x: readPlayerI32("player_axis_aim_x", i),
      axis_aim_y: readPlayerI32("player_axis_aim_y", i),
      axis_move_x: readPlayerI32("player_axis_move_x", i),
      axis_move_y: readPlayerI32("player_axis_move_y", i),
    });
  }
  return {
    reload: readDataI32("config_key_reload"),
    players: players,
    alternate_single: {
      move_forward: readDataI32("player_alt_move_key_forward"),
      move_backward: readDataI32("player_alt_move_key_backward"),
      turn_left: readDataI32("player_alt_turn_key_left"),
      turn_right: readDataI32("player_alt_turn_key_right"),
      fire: readDataI32("player_alt_fire_key"),
    },
  };
}

function readInputTelemetryCompact() {
  const count = outState.playerCountResolved;
  const aimScreen = [];
  for (let i = 0; i < count; i++) {
    aimScreen.push({
      player_index: i,
      x: captureNumber(readDataF32Stride("player_aim_screen_x", i, 8)),
      y: captureNumber(readDataF32Stride("player_aim_screen_y", i, 8)),
    });
  }
  return {
    console_open: readDataU32("console_open_flag"),
    primary_latch: readDataU32("input_primary_latch"),
    mouse_x: captureNumber(readDataF32("ui_mouse_x")),
    mouse_y: captureNumber(readDataF32("ui_mouse_y")),
    aim_screen: aimScreen,
  };
}

function readProjectileEntry(index) {
  const pool = dataPtrs.projectile_pool;
  if (!pool || index < 0) return null;
  const base = pool.add(index * STRIDES.projectile);
  const active = safeReadU8(base);
  if (!active) return null;
  return {
    index: index,
    active: active,
    angle: captureNumber(safeReadF32(base.add(0x04))),
    pos: {
      x: captureNumber(safeReadF32(base.add(0x08))),
      y: captureNumber(safeReadF32(base.add(0x0c))),
    },
    vel: {
      x: captureNumber(safeReadF32(base.add(0x18))),
      y: captureNumber(safeReadF32(base.add(0x1c))),
    },
    type_id: safeReadS32(base.add(0x20)),
    life_timer: captureNumber(safeReadF32(base.add(0x24))),
    speed_scale: captureNumber(safeReadF32(base.add(0x2c))),
    damage_pool: captureNumber(safeReadF32(base.add(0x30))),
    hit_radius: captureNumber(safeReadF32(base.add(0x34))),
    // Spawn writes weapon_table[type_id].travel_budget here; replay-grade traces
    // treat that authoritative slot value as the projectile travel budget.
    travel_budget: captureNumber(safeReadF32(base.add(0x38))),
    owner_id: safeReadS32(base.add(0x3c)),
  };
}

function projectileIndexFromPosPtr(posPtr) {
  if (!posPtr || !dataPtrs.projectile_pool) return null;
  try {
    const delta = posPtr.sub(dataPtrs.projectile_pool).toInt32();
    if (delta < 0) return null;
    const localOffset = delta - 0x08;
    if (localOffset < 0) return null;
    if ((localOffset % STRIDES.projectile) !== 0) return null;
    const idx = (localOffset / STRIDES.projectile) | 0;
    if (idx < 0 || idx >= COUNTS.projectiles) return null;
    return idx;
  } catch (_e) {
    return null;
  }
}

function readProjectileEntryByPosPtr(posPtr) {
  const idx = projectileIndexFromPosPtr(posPtr);
  if (idx == null) return null;
  return readProjectileEntry(idx);
}

function readActiveProjectileSample(limit) {
  const normalizedLimit = normalizeSampleLimit(limit);
  const out = [];
  if (!dataPtrs.projectile_pool || normalizedLimit === 0) return out;
  for (let i = 0; i < COUNTS.projectiles; i++) {
    const p = readProjectileEntry(i);
    if (!p) continue;
    out.push(p);
    if (normalizedLimit >= 0 && out.length >= normalizedLimit) break;
  }
  return out;
}

function readSecondaryProjectileEntry(index) {
  const pool = dataPtrs.secondary_projectile_pool;
  if (!pool || index < 0) return null;
  const base = pool.add(index * STRIDES.secondary_projectile);
  const active = safeReadU8(base);
  if (!active) return null;
  return {
    index: index,
    active: active,
    pos: {
      x: captureNumber(safeReadF32(base.add(0x04))),
      y: captureNumber(safeReadF32(base.add(0x08))),
    },
    life_timer: captureNumber(safeReadF32(base.add(0x0c))),
    angle: captureNumber(safeReadF32(base.add(0x10))),
    vel: {
      x: captureNumber(safeReadF32(base.add(0x14))),
      y: captureNumber(safeReadF32(base.add(0x18))),
    },
    trail_timer: captureNumber(safeReadF32(base.add(0x1c))),
    type_id: safeReadS32(base.add(0x20)),
    target_id: safeReadS32(base.add(0x24)),
  };
}

function readActiveSecondaryProjectileSample(limit) {
  const normalizedLimit = normalizeSampleLimit(limit);
  const out = [];
  if (!dataPtrs.secondary_projectile_pool || normalizedLimit === 0) return out;
  for (let i = 0; i < COUNTS.secondary_projectiles; i++) {
    const p = readSecondaryProjectileEntry(i);
    if (!p) continue;
    out.push(p);
    if (normalizedLimit >= 0 && out.length >= normalizedLimit) break;
  }
  return out;
}

function readCreatureEntry(index) {
  const pool = dataPtrs.creature_pool;
  if (!pool || index < 0) return null;
  const base = pool.add(index * STRIDES.creature);
  const activeFlag = safeReadU8(base);
  if (!activeFlag) return null;
  const stateFlag = safeReadU8(base.add(0x08));
  const flags = safeReadS32(base.add(0x8c));
  const linkIndex = safeReadS32(base.add(0x78));
  return {
    index: index,
    active: activeFlag,
    state_flag: stateFlag,
    collision_flag: safeReadU8(base.add(0x09)),
    lifecycle_stage: captureNumber(safeReadF32(base.add(0x10))),
    pos: {
      x: captureNumber(safeReadF32(base.add(0x14))),
      y: captureNumber(safeReadF32(base.add(0x18))),
    },
    hp: captureNumber(safeReadF32(base.add(0x24))),
    type_id: safeReadS32(base.add(0x6c)),
    target_player: safeReadS32(base.add(0x70)),
    flags: flags,
    link_index: linkIndex,
    ai_mode: safeReadS32(base.add(0x90)),
    heading: captureNumber(safeReadF32(base.add(0x2c))),
    target_heading: captureNumber(safeReadF32(base.add(0x30))),
    orbit_angle: captureNumber(safeReadF32(base.add(0x84))),
    orbit_radius: captureNumber(safeReadF32(base.add(0x88))),
    ai7_timer_ms:
      flags != null && linkIndex != null && (flags & CREATURE_FLAG_AI7_LINK_TIMER) !== 0
        ? linkIndex
        : null,
  };
}

function readActiveCreatureSample(limit) {
  const normalizedLimit = normalizeSampleLimit(limit);
  const out = [];
  if (!dataPtrs.creature_pool || normalizedLimit === 0) return out;
  for (let i = 0; i < COUNTS.creatures; i++) {
    const c = readCreatureEntry(i);
    if (!c) continue;
    out.push(c);
    if (normalizedLimit >= 0 && out.length >= normalizedLimit) break;
  }
  return out;
}

function readCreatureLifecycleEntry(index) {
  const pool = dataPtrs.creature_pool;
  if (!pool || index < 0) return null;
  const base = pool.add(index * STRIDES.creature);
  const activeFlag = safeReadU8(base);
  const stateFlag = safeReadU8(base.add(0x08));
  const active = activeFlag == null ? !!stateFlag : !!activeFlag;
  const flags = safeReadS32(base.add(0x8c));
  const linkIndex = safeReadS32(base.add(0x78));
  return {
    index: index,
    active: active,
    active_flag: activeFlag == null ? null : activeFlag,
    state_flag: stateFlag == null ? null : stateFlag,
    type_id: safeReadS32(base.add(0x6c)),
    hp: captureNumber(safeReadF32(base.add(0x24))),
    lifecycle_stage: captureNumber(safeReadF32(base.add(0x10))),
    pos: {
      x: captureNumber(safeReadF32(base.add(0x14))),
      y: captureNumber(safeReadF32(base.add(0x18))),
    },
    flags: flags,
    link_index: linkIndex,
    ai_mode: safeReadS32(base.add(0x90)),
    heading: captureNumber(safeReadF32(base.add(0x2c))),
    target_heading: captureNumber(safeReadF32(base.add(0x30))),
    orbit_angle: captureNumber(safeReadF32(base.add(0x84))),
    orbit_radius: captureNumber(safeReadF32(base.add(0x88))),
    ai7_timer_ms:
      flags != null && linkIndex != null && (flags & CREATURE_FLAG_AI7_LINK_TIMER) !== 0
        ? linkIndex
        : null,
  };
}

function _isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function _distanceBucket(distance) {
  if (!_isFiniteNumber(distance)) return null;
  if (distance < 40.0) return "<40";
  if (distance > 400.0) return ">400";
  return "40-400";
}

function _readCreatureMicroState(index) {
  const pool = dataPtrs.creature_pool;
  if (!pool || index < 0 || index >= COUNTS.creatures) return null;
  const base = pool.add(index * STRIDES.creature);

  const activeFlag = safeReadU8(base);
  const stateFlag = safeReadU8(base.add(0x08));
  const flags = safeReadS32(base.add(0x8c));
  const linkIndex = safeReadS32(base.add(0x78));
  const targetPlayer = safeReadS32(base.add(0x70));
  const hitboxSize = safeReadF32(base.add(0x10));
  const hp = safeReadF32(base.add(0x24));
  const posX = safeReadF32(base.add(0x14));
  const posY = safeReadF32(base.add(0x18));
  const velX = safeReadF32(base.add(0x1c));
  const velY = safeReadF32(base.add(0x20));
  const heading = safeReadF32(base.add(0x2c));
  const targetHeading = safeReadF32(base.add(0x30));
  const forceTarget = safeReadS32(base.add(0x4c));
  const targetX = safeReadF32(base.add(0x50));
  const targetY = safeReadF32(base.add(0x54));
  const moveSpeed = safeReadF32(base.add(0x5c));
  const aiMode = safeReadS32(base.add(0x90));
  const orbitAngle = safeReadF32(base.add(0x84));
  const orbitRadius = safeReadF32(base.add(0x88));
  const frameDt = dataPtrs.frame_dt ? safeReadF32(dataPtrs.frame_dt) : null;

  let distToTarget = null;
  if (_isFiniteNumber(posX) && _isFiniteNumber(posY) && _isFiniteNumber(targetX) && _isFiniteNumber(targetY)) {
    const dx = targetX - posX;
    const dy = targetY - posY;
    distToTarget = Math.sqrt(dx * dx + dy * dy);
  }

  let moveScaleEstimate = null;
  if (
    _isFiniteNumber(velX) &&
    _isFiniteNumber(velY) &&
    _isFiniteNumber(moveSpeed) &&
    _isFiniteNumber(frameDt) &&
    Math.abs(moveSpeed) > 1e-7 &&
    Math.abs(frameDt) > 1e-9
  ) {
    const speedAbs = Math.sqrt(velX * velX + velY * velY);
    moveScaleEstimate = speedAbs / (Math.abs(moveSpeed) * 11.0 * Math.abs(frameDt));
  }

  let linkActiveFlag = null;
  let linkPosX = null;
  let linkPosY = null;
  let distToLink = null;
  const normalizedLinkIndex = linkIndex == null ? null : linkIndex | 0;
  if (normalizedLinkIndex != null && normalizedLinkIndex >= 0 && normalizedLinkIndex < COUNTS.creatures) {
    const linkBase = pool.add(normalizedLinkIndex * STRIDES.creature);
    linkActiveFlag = safeReadU8(linkBase);
    if (linkActiveFlag) {
      linkPosX = safeReadF32(linkBase.add(0x14));
      linkPosY = safeReadF32(linkBase.add(0x18));
      if (_isFiniteNumber(posX) && _isFiniteNumber(posY) && _isFiniteNumber(linkPosX) && _isFiniteNumber(linkPosY)) {
        const linkDx = linkPosX - posX;
        const linkDy = linkPosY - posY;
        distToLink = Math.sqrt(linkDx * linkDx + linkDy * linkDy);
      }
    }
  }

  const ai7TimerMs =
    flags != null && linkIndex != null && (flags & CREATURE_FLAG_AI7_LINK_TIMER) !== 0 ? linkIndex : null;

  return {
    index: index,
    active: activeFlag == null ? !!stateFlag : !!activeFlag,
    active_flag: activeFlag == null ? null : activeFlag,
    state_flag: stateFlag == null ? null : stateFlag,
    ai_mode: aiMode,
    flags: flags,
    link_index: linkIndex,
    target_player: targetPlayer,
    lifecycle_stage: captureNumber(hitboxSize),
    hp: captureNumber(hp),
    force_target: forceTarget,
    ai7_timer_ms: ai7TimerMs,
    heading: captureNumber(heading),
    target_heading: captureNumber(targetHeading),
    orbit_angle: captureNumber(orbitAngle),
    orbit_radius: captureNumber(orbitRadius),
    target_x: captureNumber(targetX),
    target_y: captureNumber(targetY),
    pos: {
      x: captureNumber(posX),
      y: captureNumber(posY),
    },
    vel: {
      x: captureNumber(velX),
      y: captureNumber(velY),
    },
    move_speed: captureNumber(moveSpeed),
    dt_frame: captureNumber(frameDt),
    dist_to_target: captureNumber(distToTarget),
    dist_bucket: _distanceBucket(distToTarget),
    link_active_flag: linkActiveFlag,
    link_pos: {
      x: captureNumber(linkPosX),
      y: captureNumber(linkPosY),
    },
    dist_to_link: captureNumber(distToLink),
    link_dist_bucket: _distanceBucket(distToLink),
    move_scale_estimate: captureNumber(moveScaleEstimate),
  };
}

function _shouldCaptureCreatureMicroForTick(tickIndex) {
  if (!CONFIG.enableCreatureMicroHooks) return false;
  const tick = tickIndex | 0;
  if (CONFIG.creatureMicroTickStart >= 0 && tick < (CONFIG.creatureMicroTickStart | 0)) return false;
  if (CONFIG.creatureMicroTickEnd >= 0 && tick > (CONFIG.creatureMicroTickEnd | 0)) return false;
  return true;
}

function _shouldCaptureCreatureMicroSlot(creatureIndex) {
  const slots = CONFIG.creatureMicroSlots;
  if (!(slots instanceof Set) || slots.size <= 0) return true;
  return slots.has(creatureIndex | 0);
}

function _listCreatureMicroTrackedSlots() {
  const out = [];
  const slots = CONFIG.creatureMicroSlots;
  if (slots instanceof Set && slots.size > 0) {
    for (const slot of slots.values()) {
      const idx = slot | 0;
      if (idx < 0 || idx >= COUNTS.creatures) continue;
      out.push(idx);
    }
    out.sort(function (a, b) {
      return a - b;
    });
    return out;
  }

  const pool = dataPtrs.creature_pool;
  if (!pool) return out;
  const cap =
    CONFIG.creatureMicroMaxHeadPerTick >= 0
      ? Math.max(1, CONFIG.creatureMicroMaxHeadPerTick | 0)
      : COUNTS.creatures;
  for (let i = 0; i < COUNTS.creatures; i++) {
    const active = safeReadU8(pool.add(i * STRIDES.creature));
    if (!active) continue;
    out.push(i);
    if (out.length >= cap) break;
  }
  return out;
}

function _addCreatureMicroEvent(payload, commandToken) {
  const tick = outState.currentTick;
  if (!tick || !payload) return;
  if (!_shouldCaptureCreatureMicroForTick(tick.tick_index)) return;
  const eventKind = String(payload.event_kind || "");
  const cap = CONFIG.creatureMicroMaxHeadPerTick;
  if (cap === 0) return;
  if (eventKind === "angle_approach") {
    if (cap > 0 && (tick.creature_update_micro_angle_rows | 0) >= cap) return;
    tick.creature_update_micro_angle_rows = (tick.creature_update_micro_angle_rows | 0) + 1;
  } else if (eventKind === "creature_update_window") {
    if (cap > 0 && (tick.creature_update_micro_window_rows | 0) >= cap) return;
    tick.creature_update_micro_window_rows = (tick.creature_update_micro_window_rows | 0) + 1;
  } else if (cap > 0 && (tick.creature_update_micro_rows | 0) >= cap) {
    return;
  }
  tick.creature_update_micro_rows = (tick.creature_update_micro_rows | 0) + 1;
  addTickEvent("creature_update_micro", payload, commandToken || "cum");
}

function _creatureIndexFromHeadingPtr(anglePtr) {
  if (!anglePtr || !dataPtrs.creature_pool) return null;
  try {
    const delta = anglePtr.sub(dataPtrs.creature_pool).toInt32();
    if (delta < CREATURE_HEADING_OFFSET) return null;
    const localOffset = delta - CREATURE_HEADING_OFFSET;
    if (localOffset < 0) return null;
    if ((localOffset % STRIDES.creature) !== 0) return null;
    const idx = (localOffset / STRIDES.creature) | 0;
    if (idx < 0 || idx >= COUNTS.creatures) return null;
    return idx;
  } catch (_e) {
    return null;
  }
}

function _classifyAngleApproach(angleIn, target, rate, angleOut) {
  if (
    !_isFiniteNumber(angleIn) ||
    !_isFiniteNumber(target) ||
    !_isFiniteNumber(rate) ||
    !_isFiniteNumber(angleOut)
  ) {
    return {
      branch: null,
      target_effective: null,
      delta_direct: null,
      delta_effective: null,
      step_delta: null,
    };
  }

  const direct = Math.abs(target - angleIn);
  const wrapPlusTarget = target + TWO_PI;
  const wrapMinusTarget = target - TWO_PI;
  const wrapPlus = Math.abs(wrapPlusTarget - angleIn);
  const wrapMinus = Math.abs(wrapMinusTarget - angleIn);

  let targetEffective = target;
  let domain = "direct";
  let domainDist = direct;
  if (wrapPlus < domainDist) {
    domain = "wrap_plus";
    domainDist = wrapPlus;
    targetEffective = wrapPlusTarget;
  }
  if (wrapMinus < domainDist) {
    domain = "wrap_minus";
    domainDist = wrapMinus;
    targetEffective = wrapMinusTarget;
  }

  const stepDelta = angleOut - angleIn;
  let action = "step";
  if (Math.abs(stepDelta) <= 1e-9) {
    action = "none";
  } else if (Math.abs(targetEffective - angleOut) <= 1e-6 || Math.abs(domainDist) <= Math.abs(rate) + 1e-9) {
    action = "snap";
  } else if (stepDelta > 0.0) {
    action = "inc";
  } else {
    action = "dec";
  }

  return {
    branch: action + ":" + domain,
    target_effective: targetEffective,
    delta_direct: target - angleIn,
    delta_effective: targetEffective - angleIn,
    step_delta: stepDelta,
  };
}

function captureCreatureDigest() {
  if (!dataPtrs.creature_pool) {
    return {
      active_count: null,
      active_hash: null,
      active_ids: [],
      active_entries: {},
    };
  }

  let activeCount = 0;
  let hashState = fnvInit();
  const activeIds = [];
  const activeEntries = {};

  for (let i = 0; i < COUNTS.creatures; i++) {
    const entry = readCreatureLifecycleEntry(i);
    if (!entry || !entry.active) continue;
    activeCount += 1;
    activeIds.push(i);
    activeEntries[i] = entry;
    hashState = fnvMixString(
      hashState,
      String(i) +
        ":" +
        String(entry.type_id == null ? -1 : entry.type_id) +
        ":" +
        String(entry.hp == null ? "na" : entry.hp)
    );
    hashState = fnvMixByte(hashState, 0x0a);
  }

  return {
    active_count: activeCount,
    active_hash: toHex(hashState >>> 0, 8),
    active_ids: activeIds,
    active_entries: activeEntries,
  };
}

function diffCreatureDigest(beforeDigest, afterDigest) {
  if (!beforeDigest || !afterDigest) return null;
  const beforeIds = Array.isArray(beforeDigest.active_ids) ? beforeDigest.active_ids : [];
  const afterIds = Array.isArray(afterDigest.active_ids) ? afterDigest.active_ids : [];

  const beforeSet = {};
  for (let i = 0; i < beforeIds.length; i++) beforeSet[beforeIds[i]] = 1;
  const afterSet = {};
  for (let i = 0; i < afterIds.length; i++) afterSet[afterIds[i]] = 1;

  const addedIds = [];
  for (let i = 0; i < afterIds.length; i++) {
    const id = afterIds[i];
    if (!beforeSet[id]) addedIds.push(id);
  }

  const removedIds = [];
  for (let i = 0; i < beforeIds.length; i++) {
    const id = beforeIds[i];
    if (!afterSet[id]) removedIds.push(id);
  }

  const addedHead = [];
  const removedHead = [];
  const maxHead = Math.max(1, CONFIG.maxCreatureDeltaIds | 0);
  const afterEntries = afterDigest.active_entries || {};
  const beforeEntries = beforeDigest.active_entries || {};

  for (let i = 0; i < addedIds.length && addedHead.length < maxHead; i++) {
    const id = addedIds[i];
    if (afterEntries[id]) addedHead.push(afterEntries[id]);
  }
  for (let i = 0; i < removedIds.length && removedHead.length < maxHead; i++) {
    const id = removedIds[i];
    if (beforeEntries[id]) removedHead.push(beforeEntries[id]);
  }

  return {
    before_count: beforeDigest.active_count,
    after_count: afterDigest.active_count,
    before_hash: beforeDigest.active_hash,
    after_hash: afterDigest.active_hash,
    added_total: addedIds.length,
    removed_total: removedIds.length,
    added_ids: addedIds.slice(0, maxHead),
    removed_ids: removedIds.slice(0, maxHead),
    added_overflow: Math.max(0, addedIds.length - maxHead),
    removed_overflow: Math.max(0, removedIds.length - maxHead),
    added_head: addedHead,
    removed_head: removedHead,
  };
}

function readBonusEntry(index) {
  const slot = readBonusSlotRaw(index);
  if (!bonusSlotIsLive(slot)) return null;
  return slot;
}

function readBonusSlotRaw(index) {
  const pool = dataPtrs.bonus_pool;
  if (!pool || index < 0) return null;
  const base = pool.add(index * STRIDES.bonus);
  const bonusId = safeReadS32(base);
  const state = safeReadS32(base.add(0x04));
  return {
    index: index,
    bonus_id: bonusId,
    state: state,
    time_left: captureNumber(safeReadF32(base.add(0x08))),
    time_max: captureNumber(safeReadF32(base.add(0x0c))),
    pos: {
      x: captureNumber(safeReadF32(base.add(0x10))),
      y: captureNumber(safeReadF32(base.add(0x14))),
    },
    amount_f32: captureNumber(safeReadF32(base.add(0x18))),
    amount_i32: safeReadS32(base.add(0x18)),
  };
}

function bonusSlotIsLive(slot) {
  if (!slot) return false;
  if (slot.bonus_id == null || slot.bonus_id <= 0) return false;
  // Native keeps unpicked bonus entries in state == 0.
  if (slot.state == null || slot.state < 0) return false;
  return true;
}

function snapshotBonusPoolRaw() {
  const out = [];
  if (!dataPtrs.bonus_pool) return out;
  for (let i = 0; i < COUNTS.bonuses; i++) {
    out.push(readBonusSlotRaw(i));
  }
  return out;
}

function bonusSlotFingerprint(slot) {
  if (!slot) return "null";
  const pos = slot.pos || {};
  return [
    slot.bonus_id == null ? "na" : String(slot.bonus_id),
    slot.state == null ? "na" : String(slot.state),
    slot.time_left == null ? "na" : String(slot.time_left),
    slot.time_max == null ? "na" : String(slot.time_max),
    pos.x == null ? "na" : String(pos.x),
    pos.y == null ? "na" : String(pos.y),
    slot.amount_i32 == null ? "na" : String(slot.amount_i32),
    slot.amount_f32 == null ? "na" : String(slot.amount_f32),
  ].join("|");
}

function summarizeBonusPoolDelta(beforeSlots, afterSlots) {
  const before = Array.isArray(beforeSlots) ? beforeSlots : [];
  const after = Array.isArray(afterSlots) ? afterSlots : [];
  const changedSlots = [];
  const spawnedSlots = [];
  const removedSlots = [];
  const beforeLiveHead = [];
  const afterLiveHead = [];
  const spawnedHead = [];
  let beforeActiveCount = 0;
  let afterActiveCount = 0;

  for (let i = 0; i < COUNTS.bonuses; i++) {
    const beforeSlot = before[i] || null;
    const afterSlot = after[i] || null;
    const beforeLive = bonusSlotIsLive(beforeSlot);
    const afterLive = bonusSlotIsLive(afterSlot);
    if (beforeLive) {
      beforeActiveCount += 1;
      if (beforeLiveHead.length < CONFIG.maxHeadPerKind) beforeLiveHead.push(beforeSlot);
    }
    if (afterLive) {
      afterActiveCount += 1;
      if (afterLiveHead.length < CONFIG.maxHeadPerKind) afterLiveHead.push(afterSlot);
    }

    if (bonusSlotFingerprint(beforeSlot) === bonusSlotFingerprint(afterSlot)) continue;

    const changed = {
      index: i,
      before: beforeLive ? beforeSlot : null,
      after: afterLive ? afterSlot : null,
      before_bonus_id: beforeSlot && beforeSlot.bonus_id != null ? beforeSlot.bonus_id : null,
      after_bonus_id: afterSlot && afterSlot.bonus_id != null ? afterSlot.bonus_id : null,
      before_state: beforeSlot && beforeSlot.state != null ? beforeSlot.state : null,
      after_state: afterSlot && afterSlot.state != null ? afterSlot.state : null,
    };
    changedSlots.push(changed);
    if (!beforeLive && afterLive) {
      spawnedSlots.push(i);
      if (spawnedHead.length < CONFIG.maxHeadPerKind) spawnedHead.push(afterSlot);
    }
    if (beforeLive && !afterLive) removedSlots.push(i);
  }

  return {
    before_active_count: beforeActiveCount,
    after_active_count: afterActiveCount,
    active_delta: afterActiveCount - beforeActiveCount,
    changed_slots_total: changedSlots.length,
    changed_slots_head: changedSlots.slice(0, CONFIG.maxHeadPerKind),
    changed_slots_overflow: Math.max(0, changedSlots.length - CONFIG.maxHeadPerKind),
    spawned_slots_total: spawnedSlots.length,
    spawned_slots: spawnedSlots.slice(0, CONFIG.maxHeadPerKind),
    spawned_slots_overflow: Math.max(0, spawnedSlots.length - CONFIG.maxHeadPerKind),
    removed_slots_total: removedSlots.length,
    removed_slots: removedSlots.slice(0, CONFIG.maxHeadPerKind),
    removed_slots_overflow: Math.max(0, removedSlots.length - CONFIG.maxHeadPerKind),
    before_live_head: beforeLiveHead,
    after_live_head: afterLiveHead,
    spawned_head: spawnedHead,
  };
}

function readActiveBonusSample(limit) {
  const normalizedLimit = normalizeSampleLimit(limit);
  const out = [];
  if (!dataPtrs.bonus_pool || normalizedLimit === 0) return out;
  for (let i = 0; i < COUNTS.bonuses; i++) {
    const b = readBonusEntry(i);
    if (!b) continue;
    out.push(b);
    if (normalizedLimit >= 0 && out.length >= normalizedLimit) break;
  }
  return out;
}

function updateCurrentStateFromMemory() {
  outState.currentStatePrev = readDataI32("game_state_prev");
  outState.currentStateId = readDataI32("game_state_id");
  outState.currentStatePending = readDataI32("game_state_pending");
}

function resolvePlayerCount() {
  const override = parseInt(CONFIG.playerCountOverride, 10);
  if (Number.isFinite(override) && override >= 1 && override <= 4) {
    outState.playerCountResolved = override | 0;
    return;
  }
  const fromMemory = readDataI32("config_player_count");
  if (fromMemory != null && fromMemory >= 1 && fromMemory <= 4) {
    outState.playerCountResolved = fromMemory | 0;
    return;
  }
  outState.playerCountResolved = 1;
}

function shouldCaptureTickForState(stateId) {
  if (CONFIG.emitTicksOutsideTrackedStates) return true;
  return CONFIG.trackedStates.has(stateId);
}

function makeCoreSnapshot() {
  resolvePlayerCount();
  return {
    globals: readGameplayGlobalsCompact(),
    status: readStatusSnapshotCompact(),
    player_count: outState.playerCountResolved,
    players: readPlayersCompact(),
    input: readInputTelemetryCompact(),
    input_bindings: readInputBindingsCompact(),
  };
}

function parseHexU32(value) {
  if (value == null) return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return null;
    return value >>> 0;
  }
  const text = String(value).trim();
  if (!text) return null;
  const parsed = parseInt(text, 16);
  if (!Number.isFinite(parsed)) return null;
  return parsed >>> 0;
}

function buildEmptyPlayerKeyState(playerIndex) {
  return {
    player_index: playerIndex | 0,
    // Replay input intent is derived from the hooked query stream. Start each tick
    // from an explicit "not observed true" state rather than a tri-state row.
    move_forward_pressed: false,
    move_backward_pressed: false,
    turn_left_pressed: false,
    turn_right_pressed: false,
    fire_down: false,
    fire_pressed: false,
    reload_pressed: false,
    reload_down: false,
  };
}

function ensurePlayerKeyState(tick, playerIndex) {
  if (!tick) return null;
  const idx = playerIndex | 0;
  if (!tick.input_player_keys[idx]) {
    tick.input_player_keys[idx] = buildEmptyPlayerKeyState(idx);
  }
  return tick.input_player_keys[idx];
}

function isPlayerUpdateCaller(callerStaticHex) {
  const caller = parseHexU32(callerStaticHex);
  if (caller == null) return false;
  return caller >= (FN.player_update >>> 0) && caller < (PLAYER_UPDATE_END_RVA >>> 0);
}

function ownerIdToPlayerIndex(ownerId) {
  if (!Number.isFinite(ownerId)) return null;
  const idx = (-100 - (ownerId | 0)) | 0;
  if (idx < 0) return null;
  const playerCount = Math.max(1, outState.playerCountResolved | 0);
  if (idx >= playerCount) return null;
  return idx;
}

function updatePlayerInputKeyState(tick, queryName, keyCode, pressed, callerStaticHex) {
  if (!tick) return;
  if (!Number.isFinite(keyCode)) return;
  const bindings = tick.before && tick.before.input_bindings && tick.before.input_bindings.players;
  const altBindings =
    tick.before && tick.before.input_bindings ? tick.before.input_bindings.alternate_single : null;
  const reloadKey =
    tick.before && tick.before.input_bindings ? tick.before.input_bindings.reload : null;

  const key = keyCode | 0;
  const down = !!pressed;
  const downSeen = function (prev) {
    return prev === true ? true : down;
  };

  const hasReloadBinding = Number.isFinite(reloadKey);
  if (
    (!Array.isArray(bindings) || bindings.length === 0) &&
    (!altBindings || typeof altBindings !== "object") &&
    !hasReloadBinding
  ) {
    return;
  }

  if (Array.isArray(bindings)) {
    for (let i = 0; i < bindings.length; i++) {
      const binding = bindings[i];
      if (!binding || typeof binding !== "object") continue;
      const state = ensurePlayerKeyState(tick, i);
      if (!state) continue;
      if ((binding.move_forward | 0) === key) state.move_forward_pressed = down;
      if ((binding.move_backward | 0) === key) state.move_backward_pressed = down;
      if ((binding.turn_left | 0) === key) state.turn_left_pressed = down;
      if ((binding.turn_right | 0) === key) state.turn_right_pressed = down;
      if ((binding.fire | 0) === key) {
        if (queryName === "grim_is_key_active" || queryName === "grim_is_key_down")
          state.fire_down = downSeen(state.fire_down);
      }
      if (hasReloadBinding && (reloadKey | 0) === key) {
        if (queryName === "grim_is_key_active" || queryName === "grim_is_key_down")
          state.reload_down = downSeen(state.reload_down);
      }
    }
  }

  // player_update queries alternate bindings via grim_is_key_down when player_count == 1.
  const singlePlayerBindings = !Array.isArray(bindings) || bindings.length === 1;
  if (singlePlayerBindings && altBindings && typeof altBindings === "object") {
    const state = ensurePlayerKeyState(tick, 0);
    if (!state) return;
    if ((altBindings.move_forward | 0) === key) state.move_forward_pressed = down;
    if ((altBindings.move_backward | 0) === key) state.move_backward_pressed = down;
    if ((altBindings.turn_left | 0) === key) state.turn_left_pressed = down;
    if ((altBindings.turn_right | 0) === key) state.turn_right_pressed = down;
    if ((altBindings.fire | 0) === key) {
      if (queryName === "grim_is_key_active" || queryName === "grim_is_key_down")
        state.fire_down = downSeen(state.fire_down);
    }
  }
}

function makeTickContext() {
  const before = makeCoreSnapshot();
  const creatureDigestBefore = CONFIG.enableCreatureLifecycleDigest ? captureCreatureDigest() : null;
  const outsideRngBefore = takePendingOutsideRngRolls();
  const outsidePerkApplyBefore = takePendingOutsidePerkApply();
  const tickIndex = Math.max(0, outState.gameplayFrame - 1);
  const beforeGlobals = before && before.globals && typeof before.globals === "object" ? before.globals : {};
  const timingEntryActive = _timeScaleActiveFromBonusTimer(beforeGlobals.bonus_reflex_boost_timer);
  const timingEntryFactor = _timeScaleFactorFromBonusTimer(
    beforeGlobals.bonus_reflex_boost_timer,
    timingEntryActive
  );
  const playerBindings =
    before && before.input_bindings && Array.isArray(before.input_bindings.players)
      ? before.input_bindings.players
      : [];
  const inputPlayerKeys = [];
  for (let i = 0; i < Math.max(playerBindings.length, outState.playerCountResolved | 0); i++) {
    inputPlayerKeys.push(buildEmptyPlayerKeyState(i));
  }
  return {
    tick_index: tickIndex,
    gameplay_frame: outState.gameplayFrame,
    state_id_enter: outState.currentStateId,
    state_pending_enter: outState.currentStatePending,
    state_prev_enter: outState.currentStatePrev,
    ts_enter_ms: nowMs(),
    focus_tick: isFocusTick(tickIndex),
    before: before,
    event_total: 0,
    event_counts: {
      state_transition: 0,
      player_fire: 0,
      weapon_assign: 0,
      bonus_apply: 0,
      bonus_spawn: 0,
      projectile_spawn: 0,
      projectile_find_query: 0,
      projectile_find_hit: 0,
      secondary_projectile_spawn: 0,
      player_damage: 0,
      creature_damage: 0,
      creature_spawn: 0,
      creature_spawn_low: 0,
      creature_death: 0,
      creature_lifecycle: 0,
      creature_update_micro: 0,
      perk_apply: 0,
      sfx: 0,
      perk_delta: 0,
      quest_timeline_delta: 0,
      mode_tick: 0,
      input_primary_edge: 0,
      input_primary_down: 0,
      input_any_key: 0,
    },
    event_heads: {
      state_transition: [],
      player_fire: [],
      weapon_assign: [],
      bonus_apply: [],
      bonus_spawn: [],
      projectile_spawn: [],
      projectile_find_query: [],
      projectile_find_hit: [],
      secondary_projectile_spawn: [],
      player_damage: [],
      creature_damage: [],
      creature_spawn: [],
      creature_spawn_low: [],
      creature_death: [],
      creature_lifecycle: [],
      creature_update_micro: [],
      perk_apply: [],
      sfx: [],
      perk_delta: [],
      quest_timeline_delta: [],
      mode_tick: [],
      input_primary_edge: [],
      input_primary_down: [],
      input_any_key: [],
    },
    command_hash_state: fnvInit(),
    input_hash_state: fnvInit(),
    input_queries: {
      primary_edge: { calls: 0, true_calls: 0 },
      primary_down: { calls: 0, true_calls: 0 },
      any_key: { calls: 0, true_calls: 0 },
    },
    input_player_keys: inputPlayerKeys,
    rng: {
      calls: 0,
      last_value: null,
      hash_state: fnvInit(),
      head: [],
      caller_counts: {},
      caller_overflow: 0,
      first_seq: null,
      last_seq: null,
      seed_epoch_enter: outState.rngSeedEpoch >>> 0,
      seed_epoch_last: outState.rngSeedEpoch >>> 0,
      outside_before_calls: outsideRngBefore.calls,
      outside_before_dropped: outsideRngBefore.dropped,
      outside_before_head: outsideRngBefore.head,
      outside_before_caller_counts: outsideRngBefore.caller_counts,
      mirror_mismatch_total_enter: outState.rngMirrorMismatchCount,
      mirror_unknown_total_enter: outState.rngMirrorUnknownCalls,
    },
    perk_apply_outside_before: outsidePerkApplyBefore,
    timing_entry_active: timingEntryActive,
    timing_entry_factor: timingEntryFactor,
    timing_samples: [],
    sfx_ids: [],
    fire_by_player: {},
    player_fire_direct_by_player: {},
    player_fire_fallback_by_player: {},
    player_projectile_spawn_by_player: {},
    spawn_callers_template: {},
    spawn_callers_low: {},
    spawn_sources_low: {},
    creature_damage_callers: {},
    projectile_find_query_callers: {},
    projectile_find_hit_callers: {},
    projectile_find_query_miss: 0,
    projectile_find_query_owner_collision: 0,
    death_callers: {},
    bonus_spawn_callers: {},
    blood_splatter_calls: 0,
    blood_splatter_rng_draws: 0,
    blood_splatter_projectile_update_calls: 0,
    blood_splatter_callers: {},
    blood_splatter_rng_draws_by_caller: {},
    mode_samples: [],
    creature_digest_before: creatureDigestBefore,
    creature_update_micro_rows: 0,
    creature_update_micro_angle_rows: 0,
    creature_update_micro_window_rows: 0,
    mode_hint: null,
    overflow: false,
  };
}

function pushHead(head, item) {
  if (!head) return;
  if (CONFIG.maxHeadPerKind >= 0 && head.length >= CONFIG.maxHeadPerKind) return;
  head.push(item);
}

function bumpCounterMap(mapObj, key) {
  if (!mapObj || key == null) return;
  if (mapObj[key] != null) {
    mapObj[key] += 1;
    return;
  }
  mapObj[key] = 1;
}

function bumpCounterMapBy(mapObj, key, delta) {
  if (!mapObj || key == null) return;
  const amount = Number(delta);
  if (!Number.isFinite(amount) || amount === 0) return;
  if (mapObj[key] != null) {
    mapObj[key] += amount;
    return;
  }
  mapObj[key] = amount;
}

function topCounterPairs(mapObj, limit) {
  if (!mapObj) return [];
  const entries = Object.keys(mapObj).map(function (k) {
    return { key: k, count: mapObj[k] };
  });
  entries.sort(function (a, b) {
    return b.count - a.count;
  });
  return entries.slice(0, Math.max(1, limit | 0));
}

function modeFnHead(samples, limit) {
  const out = [];
  const seen = {};
  const rows = Array.isArray(samples) ? samples : [];
  const cap = Math.max(1, limit | 0);
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    if (!row || typeof row !== "object") continue;
    const modeFn = row.mode_fn == null ? null : String(row.mode_fn);
    if (!modeFn) continue;
    if (seen[modeFn]) continue;
    seen[modeFn] = true;
    out.push(modeFn);
    if (out.length >= cap) break;
  }
  return out;
}

function feedCommandToken(tick, token) {
  if (!tick || !token) return;
  tick.command_hash_state = fnvMixString(tick.command_hash_state, token);
  tick.command_hash_state = fnvMixByte(tick.command_hash_state, 0x0a);
}

function addTickEvent(kind, payload, commandToken) {
  const tick = outState.currentTick;
  if (!tick) {
    if (shouldEmitRawEvent()) {
      writeLine({
        event: "tickless_event",
        type: kind,
        payload: payload,
      });
    }
    return;
  }
  tick.event_counts[kind] = (tick.event_counts[kind] || 0) + 1;
  if (CONFIG.maxEventsPerTick >= 0 && tick.event_total >= CONFIG.maxEventsPerTick) {
    tick.overflow = true;
    return;
  }
  tick.event_total += 1;
  pushHead(tick.event_heads[kind], payload);
  feedCommandToken(tick, commandToken);
}

function emitRawEvent(obj) {
  if (!obj || !shouldEmitRawEvent()) return;
  writeLine(obj);
}

function _timeScaleActiveFromBonusTimer(timerValue) {
  const timer = decodeCapturedF32(timerValue);
  if (timer == null) return null;
  return timer > 0.0;
}

function _timeScaleFactorFromBonusTimer(timerValue, active) {
  if (active == null) return null;
  if (!active) return 1.0;
  const timer = decodeCapturedF32(timerValue);
  if (timer == null) return 0.3;
  if (timer < 1.0) return ((1.0 - timer) * 0.7) + 0.3;
  return 0.3;
}

function _buildTimingSampleRow(tick, phase, writeKind, payload) {
  const globalsObj =
    payload && payload.globals && typeof payload.globals === "object"
      ? payload.globals
      : readGameplayGlobalsCompact();
  const bonusTimer =
    globalsObj && globalsObj.bonus_reflex_boost_timer != null
      ? decodeCapturedF32(globalsObj.bonus_reflex_boost_timer)
      : null;
  const activeCurrent = _timeScaleActiveFromBonusTimer(
    globalsObj ? globalsObj.bonus_reflex_boost_timer : null
  );
  const entryActive =
    payload && payload.time_scale_active_entry != null
      ? !!payload.time_scale_active_entry
      : tick && tick.timing_entry_active != null
        ? !!tick.timing_entry_active
        : activeCurrent;
  const entryFactorValue =
    payload && payload.time_scale_factor != null
      ? Number(payload.time_scale_factor)
      : tick && tick.timing_entry_factor != null
        ? Number(tick.timing_entry_factor)
        : _timeScaleFactorFromBonusTimer(
            globalsObj ? globalsObj.bonus_reflex_boost_timer : null,
            entryActive
          );
  const modeFn =
    payload && payload.mode_fn != null
      ? String(payload.mode_fn)
      : tick && tick.mode_hint
        ? String(tick.mode_hint)
        : null;
  const playerIndex =
    payload && payload.player_index != null ? intOr(payload.player_index, null) : null;

  return {
    tick_index: tick ? tick.tick_index | 0 : -1,
    gameplay_frame: tick ? tick.gameplay_frame | 0 : outState.gameplayFrame | 0,
    phase: String(phase),
    write_kind: String(writeKind),
    frame_dt_f32:
      globalsObj && globalsObj.frame_dt != null ? captureNumber(globalsObj.frame_dt) : null,
    frame_dt_ms_i32:
      globalsObj && globalsObj.frame_dt_ms_i32 != null
        ? intOr(globalsObj.frame_dt_ms_i32, null)
        : null,
    frame_dt_ms_f32:
      globalsObj && globalsObj.frame_dt_ms_f32 != null
        ? captureNumber(globalsObj.frame_dt_ms_f32)
        : null,
    time_scale_active_entry: entryActive == null ? null : !!entryActive,
    time_scale_active_current: activeCurrent == null ? null : !!activeCurrent,
    time_scale_factor:
      entryFactorValue == null || !Number.isFinite(entryFactorValue)
        ? null
        : captureNumber(entryFactorValue),
    bonus_reflex_boost_timer:
      bonusTimer == null || !Number.isFinite(bonusTimer) ? null : captureNumber(bonusTimer),
    mode_fn: modeFn,
    player_index: playerIndex,
  };
}

function _enqueuePendingTimingSample(row) {
  if (!Array.isArray(outState.pending_timing_samples)) outState.pending_timing_samples = [];
  outState.pending_timing_samples.push(row);
  if (outState.pending_timing_samples.length > 256) {
    outState.pending_timing_samples.splice(0, outState.pending_timing_samples.length - 256);
  }
}

function _consumePendingTimingSamplesIntoTick(tick) {
  const pending = Array.isArray(outState.pending_timing_samples) ? outState.pending_timing_samples : [];
  outState.pending_timing_samples = [];
  for (let i = 0; i < pending.length; i++) {
    const row = pending[i] && typeof pending[i] === "object" ? pending[i] : null;
    if (!row) continue;
    row.tick_index = tick.tick_index | 0;
    row.gameplay_frame = tick.gameplay_frame | 0;
    if (row.time_scale_active_entry == null && tick.timing_entry_active != null) {
      row.time_scale_active_entry = !!tick.timing_entry_active;
    }
    if (row.time_scale_factor == null && tick.timing_entry_factor != null) {
      row.time_scale_factor = captureNumber(tick.timing_entry_factor);
    }
    pushHead(tick.timing_samples, row);
  }
}

function recordTimingSample(phase, writeKind, payload) {
  const tick = outState.currentTick;
  const row = _buildTimingSampleRow(tick, phase, writeKind, payload || {});
  if (tick) {
    pushHead(tick.timing_samples, row);
  } else {
    _enqueuePendingTimingSample(row);
  }
}

const EVENT_HEAD_ORDER = [
  "state_transition",
  "mode_tick",
  "input_primary_edge",
  "input_primary_down",
  "input_any_key",
  "player_fire",
  "weapon_assign",
  "bonus_apply",
  "bonus_spawn",
  "secondary_projectile_spawn",
  "projectile_spawn",
  "projectile_find_query",
  "projectile_find_hit",
  "creature_damage",
  "player_damage",
  "creature_death",
  "creature_spawn",
  "creature_spawn_low",
  "creature_update_micro",
  "perk_apply",
  "sfx",
  "perk_delta",
  "quest_timeline_delta",
  "creature_lifecycle",
];

function asObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value;
}

function toPerkApplyEntry(value) {
  const row = asObject(value);
  const backtrace = Array.isArray(row.backtrace)
    ? row.backtrace.map((item) => String(item))
    : null;
  return {
    perk_id: row.perk_id == null ? null : row.perk_id,
    pending_before: row.pending_before == null ? null : row.pending_before,
    pending_after: row.pending_after == null ? null : row.pending_after,
    caller: row.caller == null ? null : row.caller,
    caller_static: row.caller_static == null ? null : row.caller_static,
    backtrace: backtrace,
  };
}

function buildCaptureEventHeads(eventHeadsByKind) {
  const out = [];
  const byKind = asObject(eventHeadsByKind);
  for (let i = 0; i < EVENT_HEAD_ORDER.length; i++) {
    const kind = EVENT_HEAD_ORDER[i];
    const entries = Array.isArray(byKind[kind]) ? byKind[kind] : [];
    for (let j = 0; j < entries.length; j++) {
      const payload = asObject(entries[j]);
      if (kind === "perk_apply") {
        out.push(
          Object.assign(
            {
              type: "perk_apply",
            },
            toPerkApplyEntry(payload)
          )
        );
      } else {
        out.push({
          type: kind,
          data: payload,
        });
      }
    }
  }
  return out;
}

function pushInputContext(threadId, ctx) {
  let stack = inputContextByTid[threadId];
  if (!stack) {
    stack = [];
    inputContextByTid[threadId] = stack;
  }
  stack.push(ctx);
}

function popInputContext(threadId) {
  const stack = inputContextByTid[threadId];
  if (!stack || stack.length === 0) return null;
  const ctx = stack.pop();
  if (stack.length === 0) delete inputContextByTid[threadId];
  return ctx;
}

function pushAngleApproachContext(threadId, ctx) {
  let stack = angleApproachContextByTid[threadId];
  if (!stack) {
    stack = [];
    angleApproachContextByTid[threadId] = stack;
  }
  stack.push(ctx);
}

function popAngleApproachContext(threadId) {
  const stack = angleApproachContextByTid[threadId];
  if (!stack || stack.length === 0) return null;
  const ctx = stack.pop();
  if (stack.length === 0) delete angleApproachContextByTid[threadId];
  return ctx;
}

function registerInputQuery(kind, pressed, token, payload) {
  const tick = outState.currentTick;
  if (!tick) return;
  const stats = tick.input_queries[kind];
  if (stats) {
    stats.calls += 1;
    if (pressed) stats.true_calls += 1;
  }
  tick.input_hash_state = fnvMixString(tick.input_hash_state, token + ":" + (pressed ? 1 : 0));
  tick.input_hash_state = fnvMixByte(tick.input_hash_state, 0x0a);
  if (pressed) {
    addTickEvent(kind === "primary_edge" ? "input_primary_edge" : kind === "primary_down" ? "input_primary_down" : "input_any_key", payload, token + ":1");
  }
}

function stepCrtRandState(stateU32) {
  return (Math.imul(stateU32 >>> 0, CRT_RAND_MULT) + CRT_RAND_INC) >>> 0;
}

function queueOutsideRngRoll(rollRow) {
  outState.rngOutsideTickPendingCalls += 1;
  // Per-caller counts are exhaustive: every outside-tick draw is attributed
  // even when the detailed head is capped.
  const callerKey = rollRow && rollRow.caller_static ? String(rollRow.caller_static) : "unknown";
  if (outState.rngOutsideTickPendingCallerCounts[callerKey] != null) {
    outState.rngOutsideTickPendingCallerCounts[callerKey] += 1;
  } else {
    outState.rngOutsideTickPendingCallerCounts[callerKey] = 1;
  }
  const cap = CONFIG.maxRngOutsideTickHead;
  if (cap === 0) {
    outState.rngOutsideTickPendingDropped += 1;
    return;
  }
  if (cap > 0 && outState.rngOutsideTickPendingHead.length >= cap) {
    outState.rngOutsideTickPendingDropped += 1;
    return;
  }
  outState.rngOutsideTickPendingHead.push(rollRow);
}

function takePendingOutsideRngRolls() {
  const head = outState.rngOutsideTickPendingHead;
  const calls = outState.rngOutsideTickPendingCalls;
  const dropped = outState.rngOutsideTickPendingDropped;
  const callerCounts = outState.rngOutsideTickPendingCallerCounts;
  outState.rngOutsideTickPendingHead = [];
  outState.rngOutsideTickPendingCalls = 0;
  outState.rngOutsideTickPendingDropped = 0;
  outState.rngOutsideTickPendingCallerCounts = {};
  return {
    head: head,
    calls: calls,
    dropped: dropped,
    caller_counts: callerCounts,
  };
}

function queueOutsidePerkApply(payload) {
  outState.perkApplyOutsideTickPendingCalls += 1;
  const cap = CONFIG.maxHeadPerKind;
  if (cap === 0) {
    outState.perkApplyOutsideTickPendingDropped += 1;
    return;
  }
  if (cap > 0 && outState.perkApplyOutsideTickPendingHead.length >= cap) {
    outState.perkApplyOutsideTickPendingDropped += 1;
    return;
  }
  outState.perkApplyOutsideTickPendingHead.push(payload);
}

function takePendingOutsidePerkApply() {
  const head = outState.perkApplyOutsideTickPendingHead;
  const calls = outState.perkApplyOutsideTickPendingCalls;
  const dropped = outState.perkApplyOutsideTickPendingDropped;
  outState.perkApplyOutsideTickPendingHead = [];
  outState.perkApplyOutsideTickPendingCalls = 0;
  outState.perkApplyOutsideTickPendingDropped = 0;
  return {
    head: head,
    calls: calls,
    dropped: dropped,
  };
}

function emitRngRollEvent(rollRow) {
  if (!rollRow || !CONFIG.enableRngRollLog) return;
  const cap = CONFIG.maxRngRollLogEvents;
  if (cap >= 0 && outState.rngRollLogEmitted >= cap) {
    outState.rngRollLogDropped += 1;
    return;
  }
  outState.rngRollLogEmitted += 1;
  writeLine({
    event: "rng_roll",
    script: "gameplay_diff_capture",
    capture_format_version: CAPTURE_FORMAT_VERSION,
    session_id: outState.sessionId,
    seq: rollRow.seq,
    seed_epoch: rollRow.seed_epoch,
    tick_index: rollRow.tick_index,
    tick_call_index: rollRow.tick_call_index,
    outside_tick: rollRow.outside_tick,
    value_i32: rollRow.value,
    value_u32: rollRow.value_u32,
    value_15: rollRow.value_15,
    caller: rollRow.caller,
    caller_static: rollRow.caller_static,
    state_before_u32: rollRow.state_before_u32,
    state_after_u32: rollRow.state_after_u32,
    state_before_hex: rollRow.state_before_hex,
    state_after_hex: rollRow.state_after_hex,
    expected_value_15: rollRow.expected_value_15,
    mirror_match: rollRow.mirror_match,
  });
}

function registerRngRoll(value, callerStaticHex, callerLabel, stateBeforeRealU32) {
  let valueI32 = null;
  if (Number.isFinite(value)) {
    valueI32 = value | 0;
  }

  outState.rngCallsTotal += 1;
  outState.rngCallSeq += 1;
  outState.rngHashState = fnvMixString(
    outState.rngHashState,
    String(valueI32 == null ? "na" : valueI32) + "@" + String(callerStaticHex || "na")
  );
  outState.rngHashState = fnvMixByte(outState.rngHashState, 0x0a);

  const tick = outState.currentTick;
  const seq = outState.rngCallSeq;
  const tickCallIndex = tick ? tick.rng.calls + 1 : null;
  const mirrorBeforeU32 =
    CONFIG.enableRngStateMirror && outState.rngMirrorStateU32 != null ? outState.rngMirrorStateU32 >>> 0 : null;
  // The real memory state is authoritative; the software mirror only models
  // hooked draws, so mirror-vs-real divergence is evidence of unhooked draws.
  const stateBeforeU32 = stateBeforeRealU32 != null ? stateBeforeRealU32 >>> 0 : mirrorBeforeU32;
  const stateAfterU32 = stateBeforeU32 == null ? null : stepCrtRandState(stateBeforeU32);
  const expectedValue15 =
    mirrorBeforeU32 == null ? null : (stepCrtRandState(mirrorBeforeU32) >>> 16) & 0x7fff;
  let mirrorMatch = null;
  if (CONFIG.enableRngStateMirror) {
    if (expectedValue15 == null) {
      outState.rngMirrorUnknownCalls += 1;
    } else if (valueI32 != null) {
      mirrorMatch = ((valueI32 & 0x7fff) >>> 0) === (expectedValue15 >>> 0);
      if (!mirrorMatch) outState.rngMirrorMismatchCount += 1;
    }
  }
  if (CONFIG.enableRngStateMirror) {
    // The mirror resyncs to the real chain when available so mirror_match
    // flags each unhooked-draw gap once instead of permanently after the
    // first gap.
    if (stateAfterU32 != null) {
      outState.rngMirrorStateU32 = stateAfterU32 >>> 0;
    } else if (mirrorBeforeU32 != null) {
      outState.rngMirrorStateU32 = stepCrtRandState(mirrorBeforeU32) >>> 0;
    }
  }

  const rollRow = {
    seq: seq >>> 0,
    seed_epoch: outState.rngSeedEpoch >>> 0,
    tick_index: tick ? tick.tick_index : null,
    tick_call_index: tickCallIndex,
    outside_tick: !tick,
    value: valueI32,
    value_u32: valueI32 == null ? null : valueI32 >>> 0,
    value_15: valueI32 == null ? null : valueI32 & 0x7fff,
    caller: callerLabel || null,
    caller_static: callerStaticHex || null,
    state_before_u32: stateBeforeU32,
    state_after_u32: stateAfterU32,
    state_before_hex: stateBeforeU32 == null ? null : toHex(stateBeforeU32, 8),
    state_after_hex: stateAfterU32 == null ? null : toHex(stateAfterU32, 8),
    expected_value_15: expectedValue15,
    mirror_match: mirrorMatch,
  };

  if (
    rollRow.caller_static === RUN_SETUP_FIRST_RNG_CALLER_STATIC &&
    rollRow.state_before_u32 != null
  ) {
    // Terrain generation begins a fresh run setup; the latest latch before
    // run_start wins so restarts and quest retries re-latch naturally.
    outState.pendingRunSetupRng = {
      state_before_u32: rollRow.state_before_u32 >>> 0,
      caller_static: String(rollRow.caller_static),
      seq: rollRow.seq >>> 0,
    };
  }

  if (!tick) {
    outState.rngCallsOutsideTick += 1;
    queueOutsideRngRoll(rollRow);
    emitRngRollEvent(rollRow);
    return rollRow;
  }

  tick.rng.calls += 1;
  tick.rng.last_value = valueI32;
  tick.rng.first_seq = tick.rng.first_seq == null ? seq >>> 0 : tick.rng.first_seq;
  tick.rng.last_seq = seq >>> 0;
  tick.rng.seed_epoch_last = outState.rngSeedEpoch >>> 0;
  tick.rng.hash_state = fnvMixString(
    tick.rng.hash_state,
    String(valueI32 == null ? "na" : valueI32) + "@" + String(callerStaticHex || "na") + "#" + String(seq >>> 0)
  );
  tick.rng.hash_state = fnvMixByte(tick.rng.hash_state, 0x0a);

  if (CONFIG.maxRngHeadPerTick < 0 || tick.rng.head.length < CONFIG.maxRngHeadPerTick) {
    tick.rng.head.push(rollRow);
  }

  const key = callerStaticHex || "unknown";
  const callerKindCap = CONFIG.maxRngCallerKinds;
  if (tick.rng.caller_counts[key] != null) {
    tick.rng.caller_counts[key] += 1;
  } else if (callerKindCap < 0 || Object.keys(tick.rng.caller_counts).length < callerKindCap) {
    tick.rng.caller_counts[key] = 1;
  } else {
    tick.rng.caller_overflow += 1;
  }

  emitRngRollEvent(rollRow);
  return rollRow;
}

function readPerkChoicesCompact() {
  const base = dataPtrs.perk_choice_ids;
  const out = [];
  if (!base) return out;
  const seen = {};
  for (let i = 0; i < PERK_CHOICE_COUNT; i++) {
    const perkId = safeReadS32(base.add(i * 4));
    if (perkId == null || perkId <= 0 || seen[perkId]) continue;
    seen[perkId] = true;
    out.push(perkId | 0);
  }
  return out;
}

function readPlayerPerkNonzeroCountsCompact() {
  const base = dataPtrs.player_perk_counts;
  const out = [];
  const playerCount = Math.max(1, outState.playerCountResolved | 0);
  if (!base) {
    for (let i = 0; i < playerCount; i++) out.push([]);
    return out;
  }
  for (let playerIndex = 0; playerIndex < playerCount; playerIndex++) {
    const playerBase = base.add(playerIndex * STRIDES.player);
    const playerRows = [];
    for (let perkId = 0; perkId < PERK_COUNT_PER_PLAYER; perkId++) {
      const count = safeReadS32(playerBase.add(perkId * 4));
      if (count == null || count <= 0) continue;
      playerRows.push([perkId | 0, count | 0]);
    }
    out.push(playerRows);
  }
  return out;
}

function playerBonusTimersMsFromCompactPlayers(players) {
  const out = [];
  for (let i = 0; i < players.length; i++) {
    const p = players[i] || {};
    const bonusTimers = p.bonus_timers && typeof p.bonus_timers === "object" ? p.bonus_timers : {};
    out.push({
      speed_bonus: Math.max(0, bonusTimerMs(bonusTimers.speed_bonus)),
      shield: Math.max(0, bonusTimerMs(bonusTimers.shield)),
      fire_bullets: Math.max(0, bonusTimerMs(bonusTimers.fire_bullets)),
    });
  }
  return out;
}

function checkpointPlayersFromCompact(players) {
  const playerBonusTimersMs = playerBonusTimersMsFromCompactPlayers(players);
  const out = [];
  for (let i = 0; i < players.length; i++) {
    const p = players[i];
    const bonusTimers = playerBonusTimersMs[i] || {};
    out.push({
      pos: { x: p.pos_x == null ? 0 : p.pos_x, y: p.pos_y == null ? 0 : p.pos_y },
      health: p.health == null ? 0 : p.health,
      weapon_id: p.weapon_id == null ? 0 : p.weapon_id,
      ammo: p.ammo_f32 == null ? 0 : p.ammo_f32,
      experience: p.experience == null ? 0 : p.experience,
      level: p.level == null ? 0 : p.level,
      bonus_timers: {
        speed_bonus: bonusTimers.speed_bonus == null ? 0 : bonusTimers.speed_bonus,
        shield: bonusTimers.shield == null ? 0 : bonusTimers.shield,
        fire_bullets: bonusTimers.fire_bullets == null ? 0 : bonusTimers.fire_bullets,
      },
    });
  }
  return out;
}

function checkpointDeathsFromEventHeads(eventHeadsByKind) {
  const byKind = asObject(eventHeadsByKind);
  const rows = Array.isArray(byKind.creature_death) ? byKind.creature_death : [];
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    const payload = asObject(rows[i]);
    const before = asObject(payload.before);
    const creatureIndex = intOr(payload.creature_index, -1);
    const typeId = intOr(payload.type_id, intOr(before.type_id, -1));
    if (creatureIndex < 0 && typeId < 0) continue;
    out.push({
      creature_index: creatureIndex,
      type_id: typeId,
      reward_value: intOr(payload.reward_value, 0),
      xp_awarded: intOr(payload.xp_awarded, 0),
      owner_id: intOr(payload.owner_id, -1),
    });
  }
  return out;
}

function buildInputApprox(afterPlayers, tick) {
  const out = [];
  const keyRows = tick && Array.isArray(tick.input_player_keys) ? tick.input_player_keys : [];
  for (let i = 0; i < afterPlayers.length; i++) {
    const p = afterPlayers[i];
    const fired = tick.fire_by_player[i] || 0;
    const keyRow = keyRows[i] && typeof keyRows[i] === "object" ? keyRows[i] : null;
    let fireDown = keyRow ? keyRow.fire_down : null;
    let firePressed = keyRow ? keyRow.fire_pressed : null;
    if (fired > 0) {
      // Fire hooks are authoritative. If a shot happened this tick, keep replay
      // fire intent active so reconstructed inputs cannot silently drop shots.
      fireDown = true;
      firePressed = true;
    }
    const moving =
      p.move_dx != null &&
      p.move_dy != null &&
      (Math.abs(p.move_dx) > 0.0001 || Math.abs(p.move_dy) > 0.0001);
    out.push({
      player_index: i,
      move_dx: p.move_dx,
      move_dy: p.move_dy,
      aim_x: p.aim_x,
      aim_y: p.aim_y,
      aim_heading: p.aim_heading,
      move_mode: readDataI32Stride("config_player_mode_flags", i, 4),
      aim_scheme: readDataI32Stride("config_aim_scheme", i, 4),
      fired_events: fired,
      moving: !!moving,
      reload_active: p.reload_active_i32 != null ? p.reload_active_i32 !== 0 : null,
      weapon_id: p.weapon_id,
      move_forward_pressed: keyRow ? keyRow.move_forward_pressed : null,
      move_backward_pressed: keyRow ? keyRow.move_backward_pressed : null,
      turn_left_pressed: keyRow ? keyRow.turn_left_pressed : null,
      turn_right_pressed: keyRow ? keyRow.turn_right_pressed : null,
      fire_down: fireDown,
      fire_pressed: firePressed,
      reload_pressed: keyRow ? keyRow.reload_pressed : null,
    });
  }
  return out;
}

function finalizeTick() {
  const tick = outState.currentTick;
  if (!tick) return;
  updateCurrentStateFromMemory();
  const after = makeCoreSnapshot();
  const beforeGlobals = tick.before && tick.before.globals ? tick.before.globals : {};
  const beforeStatus = tick.before && tick.before.status ? tick.before.status : {};
  const beforePlayers = tick.before && tick.before.players ? tick.before.players : [];
  const focused = isFocusTick(tick.tick_index);
  const tsLeave = nowMs();
  const afterPlayers = after.players;
  const globals = after.globals;
  const status = after.status || {};
  let scoreXp = 0;
  for (let i = 0; i < afterPlayers.length; i++) {
    scoreXp += afterPlayers[i].experience == null ? 0 : afterPlayers[i].experience;
  }

  const beforeCreatureCount =
    beforeGlobals.creature_active_count == null ? null : beforeGlobals.creature_active_count;
  const afterCreatureCount =
    globals.creature_active_count == null ? null : globals.creature_active_count;
  const beforeElapsedMs = beforeGlobals.time_played_ms == null ? null : beforeGlobals.time_played_ms;
  const afterElapsedMs = globals.time_played_ms == null ? null : globals.time_played_ms;
  const elapsedDeltaInTick =
    beforeElapsedMs != null && afterElapsedMs != null ? afterElapsedMs - beforeElapsedMs : null;
  const elapsedDeltaFromPrevTick =
    outState.lastTickElapsedMs != null && afterElapsedMs != null
      ? afterElapsedMs - outState.lastTickElapsedMs
      : null;
  const gameplayFrameDeltaFromPrevTick =
    outState.lastTickGameplayFrame != null ? tick.gameplay_frame - outState.lastTickGameplayFrame : null;
  const creatureCountDeltaInTick =
    beforeCreatureCount != null && afterCreatureCount != null
      ? afterCreatureCount - beforeCreatureCount
      : null;
  const deathHookEventCount = tick.event_counts.creature_death || 0;

  let creatureLifecycle = null;
  if (CONFIG.enableCreatureLifecycleDigest) {
    const beforeDigest = tick.creature_digest_before || outState.lastCreatureDigest || captureCreatureDigest();
    const afterDigest = captureCreatureDigest();
    creatureLifecycle = diffCreatureDigest(beforeDigest, afterDigest);
    outState.lastCreatureDigest = afterDigest;
    if (creatureLifecycle) {
      if ((creatureLifecycle.added_total || 0) > 0 || (creatureLifecycle.removed_total || 0) > 0) {
        addTickEvent(
          "creature_lifecycle",
          creatureLifecycle,
          "cl:" + String(creatureLifecycle.added_total || 0) + ":" + String(creatureLifecycle.removed_total || 0)
        );
      }
    }
  }

  const bonusTimers = {
    [BONUS_ID_WEAPON_POWER_UP]: bonusTimerMs(globals.bonus_weapon_power_up_timer),
    [BONUS_ID_REFLEX_BOOST]: bonusTimerMs(globals.bonus_reflex_boost_timer),
    [BONUS_ID_ENERGIZER]: bonusTimerMs(globals.bonus_energizer_timer),
    [BONUS_ID_DOUBLE_EXPERIENCE]: bonusTimerMs(globals.bonus_double_xp_timer),
    [BONUS_ID_FREEZE]: bonusTimerMs(globals.bonus_freeze_timer),
  };
  const checkpointPlayers = checkpointPlayersFromCompact(afterPlayers);
  const perkPendingCount = globals.perk_pending_count == null ? -1 : globals.perk_pending_count;
  const perkChoicesDirty = readDataI32("perk_choices_dirty");
  const perkPendingForCheckpoint = perkPendingCount > 0 ? perkPendingCount : 0;
  const perkChoices =
    perkPendingForCheckpoint > 0 ? readPerkChoicesCompact() : [];
  const perkSnapshot = {
    pending_count: perkPendingForCheckpoint,
    choices_dirty:
      perkPendingForCheckpoint > 0
        ? (perkChoicesDirty != null ? perkChoicesDirty !== 0 : false)
        : true,
    choices: perkChoices,
    player_nonzero_counts: readPlayerPerkNonzeroCountsCompact(),
  };
  const killCount = globals.creature_kill_count == null ? -1 : globals.creature_kill_count;

  const rngCallersSorted = Object.keys(tick.rng.caller_counts)
    .map((k) => ({ caller_static: k, calls: tick.rng.caller_counts[k] }))
    .sort((a, b) => b.calls - a.calls);
  const rngCallers =
    CONFIG.maxRngCallerKinds < 0
      ? rngCallersSorted
      : rngCallersSorted.slice(0, CONFIG.maxRngCallerKinds);
  const inputTrueCount =
    (tick.input_queries.primary_edge.true_calls || 0) +
    (tick.input_queries.primary_down.true_calls || 0) +
    (tick.input_queries.any_key.true_calls || 0);

  const eventSummary = {
    hit_count: tick.event_counts.projectile_find_hit || 0,
    pickup_count: tick.event_counts.bonus_apply || 0,
    sfx_count: tick.event_counts.sfx || 0,
    sfx_head: tick.sfx_ids.slice(0, 4),
    rng_call_count: tick.rng.calls,
    input_true_count: inputTrueCount,
  };
  const playerFireDiagnostics = {
    event_count_player_fire: tick.event_counts.player_fire || 0,
    top_direct_events_by_player: topCounterPairs(tick.player_fire_direct_by_player, 8),
    top_fallback_events_by_player: topCounterPairs(tick.player_fire_fallback_by_player, 8),
    top_player_projectile_spawns_by_player: topCounterPairs(tick.player_projectile_spawn_by_player, 8),
  };

  const timing = {
    gameplay_frame: tick.gameplay_frame,
    gameplay_frame_delta_prev_tick: gameplayFrameDeltaFromPrevTick,
    elapsed_ms_before: beforeElapsedMs,
    elapsed_ms_after: afterElapsedMs,
    elapsed_delta_in_tick_ms: elapsedDeltaInTick,
    elapsed_delta_prev_tick_ms: elapsedDeltaFromPrevTick,
    frame_dt_before: beforeGlobals.frame_dt == null ? null : captureNumber(beforeGlobals.frame_dt),
    frame_dt_after: globals.frame_dt == null ? null : captureNumber(globals.frame_dt),
    frame_dt_ms_before_i32: beforeGlobals.frame_dt_ms_i32 == null ? null : beforeGlobals.frame_dt_ms_i32,
    frame_dt_ms_after_i32: globals.frame_dt_ms_i32 == null ? null : globals.frame_dt_ms_i32,
    frame_dt_ms_before_f32: beforeGlobals.frame_dt_ms_f32 == null ? null : captureNumber(beforeGlobals.frame_dt_ms_f32),
    frame_dt_ms_after_f32: globals.frame_dt_ms_f32 == null ? null : captureNumber(globals.frame_dt_ms_f32),
    frame_dt_source_before: frameDtSource(beforeGlobals),
    frame_dt_source_after: frameDtSource(globals),
    mode_tick_event_count: tick.event_counts.mode_tick || 0,
    mode_tick_sample_count: tick.mode_samples.length,
    mode_tick_mode_fn_head: modeFnHead(tick.mode_samples, 4),
    mode_tick_present: (tick.event_counts.mode_tick || 0) > 0,
  };
  const spawnDiagnostics = {
    before_creature_count: beforeCreatureCount,
    after_creature_count: afterCreatureCount,
    creature_count_delta: creatureCountDeltaInTick,
    event_count_template: tick.event_counts.creature_spawn || 0,
    event_count_low_level: tick.event_counts.creature_spawn_low || 0,
    event_count_creature_damage: tick.event_counts.creature_damage || 0,
    event_count_projectile_find_query: tick.event_counts.projectile_find_query || 0,
    event_count_projectile_find_hit: tick.event_counts.projectile_find_hit || 0,
    event_count_projectile_find_query_miss: tick.projectile_find_query_miss || 0,
    event_count_projectile_find_query_owner_collision: tick.projectile_find_query_owner_collision || 0,
    event_count_death: deathHookEventCount,
    top_template_callers: topCounterPairs(tick.spawn_callers_template, 8),
    top_low_level_callers: topCounterPairs(tick.spawn_callers_low, 8),
    top_low_level_sources: topCounterPairs(tick.spawn_sources_low, 8),
    top_creature_damage_callers: topCounterPairs(tick.creature_damage_callers, 8),
    top_projectile_find_query_callers: topCounterPairs(tick.projectile_find_query_callers, 8),
    top_projectile_find_hit_callers: topCounterPairs(tick.projectile_find_hit_callers, 8),
    top_death_callers: topCounterPairs(tick.death_callers, 8),
    event_count_blood_splatter: tick.blood_splatter_calls || 0,
    blood_splatter_rng_draws: tick.blood_splatter_rng_draws || 0,
    blood_splatter_projectile_update_calls: tick.blood_splatter_projectile_update_calls || 0,
    top_blood_splatter_callers: topCounterPairs(tick.blood_splatter_callers, 8),
    top_blood_splatter_rng_draw_callers: topCounterPairs(
      tick.blood_splatter_rng_draws_by_caller,
      8
    ),
    event_count_bonus_spawn: tick.event_counts.bonus_spawn || 0,
    top_bonus_spawn_callers: topCounterPairs(tick.bonus_spawn_callers, 8),
    mode_samples: tick.mode_samples,
  };
  const rngDiagnostics = {
    calls: tick.rng.calls,
    last_value: tick.rng.last_value,
    hash: toHex(tick.rng.hash_state >>> 0, 8),
    callers: rngCallers,
    caller_overflow: tick.rng.caller_overflow,
    seq_first: tick.rng.first_seq,
    seq_last: tick.rng.last_seq,
    seed_epoch_enter: tick.rng.seed_epoch_enter,
    seed_epoch_last: tick.rng.seed_epoch_last,
    outside_before_calls: tick.rng.outside_before_calls,
    outside_before_dropped: tick.rng.outside_before_dropped,
    outside_before_head: tick.rng.outside_before_head,
    mirror_mismatch_total_enter: tick.rng.mirror_mismatch_total_enter,
    mirror_mismatch_total_leave: outState.rngMirrorMismatchCount,
    mirror_unknown_total_enter: tick.rng.mirror_unknown_total_enter,
    mirror_unknown_total_leave: outState.rngMirrorUnknownCalls,
    roll_log_emitted_total: outState.rngRollLogEmitted,
    roll_log_dropped_total: outState.rngRollLogDropped,
  };
  const perkApplyOutsideBefore = tick.perk_apply_outside_before || { calls: 0, dropped: 0, head: [] };
  const creatureLifecycleDiagnostics = creatureLifecycle || null;
  const creatureCountForCheckpoint =
    creatureLifecycle &&
    typeof creatureLifecycle.after_count === "number" &&
    Number.isFinite(creatureLifecycle.after_count)
      ? creatureLifecycle.after_count | 0
      : globals.creature_active_count == null
        ? -1
        : globals.creature_active_count;
  // Real memory state at gpur leave is authoritative for the checkpoint; the
  // hooked-draws mirror is only the fallback when the ptd read is unavailable.
  const rngStateForCheckpoint =
    outState.lastGpurLeaveRngStateReal != null
      ? outState.lastGpurLeaveRngStateReal >>> 0
      : CONFIG.enableRngStateMirror && outState.rngMirrorStateU32 != null
        ? outState.rngMirrorStateU32 >>> 0
        : null;
  const diagnostics = {
    sampling_phase: "post_gameplay_update_and_render",
    timing: timing,
    spawn: spawnDiagnostics,
    rng: rngDiagnostics,
    player_fire: playerFireDiagnostics,
    perk_apply_outside_before: perkApplyOutsideBefore,
    creature_lifecycle: creatureLifecycleDiagnostics,
    before_players: checkpointPlayersFromCompact(beforePlayers),
    before_status: {
      quest_unlock_index:
        beforeStatus.quest_unlock_index == null ? -1 : beforeStatus.quest_unlock_index,
      quest_unlock_index_full:
        beforeStatus.quest_unlock_index_full == null ? -1 : beforeStatus.quest_unlock_index_full,
    },
  };

  const checkpoint = {
    tick_index: tick.tick_index,
    state_hash: "",
    command_hash: "",
    rng_state: rngStateForCheckpoint == null ? -1 : rngStateForCheckpoint,
    elapsed_ms: globals.time_played_ms == null ? -1 : globals.time_played_ms,
    score_xp: scoreXp,
    kills: killCount,
    creature_count: creatureCountForCheckpoint,
    perk_pending: perkPendingForCheckpoint,
    players: checkpointPlayers,
    status: {
      quest_unlock_index:
        status.quest_unlock_index == null ? -1 : status.quest_unlock_index,
      quest_unlock_index_full:
        status.quest_unlock_index_full == null ? -1 : status.quest_unlock_index_full,
      weapon_usage_counts: Array.isArray(status.weapon_usage_counts)
        ? status.weapon_usage_counts
            .slice(0, STATUS_WEAPON_USAGE_COUNT)
            .map((value) => (value == null ? 0 : value >>> 0))
        : [],
    },
    bonus_timers: bonusTimers,
    deaths: checkpointDeathsFromEventHeads(tick.event_heads),
    perk: perkSnapshot,
    events: eventSummary,
  };

  const frameDtMs =
    globals.frame_dt_ms_i32 != null
      ? captureNumber(globals.frame_dt_ms_i32)
      : globals.frame_dt_ms_f32 != null
        ? captureNumber(globals.frame_dt_ms_f32)
        : decodeCapturedF32(globals.frame_dt) == null
          ? null
          : captureNumber(decodeCapturedF32(globals.frame_dt) * 1000);
  const frameDtMsI32 = globals.frame_dt_ms_i32 == null ? null : globals.frame_dt_ms_i32;
  const out = {
    tick_index: tick.tick_index,
    gameplay_frame: tick.gameplay_frame,
    focus_tick: focused,
    state_id_enter: tick.state_id_enter,
    state_id_leave: outState.currentStateId,
    state_pending_enter: tick.state_pending_enter,
    state_pending_leave: outState.currentStatePending,
    mode_hint: tick.mode_hint == null ? "" : String(tick.mode_hint),
    game_mode_id: globals.config_game_mode == null ? -1 : globals.config_game_mode,
    quest_stage_major: globals.quest_stage_major == null ? -1 : globals.quest_stage_major,
    quest_stage_minor: globals.quest_stage_minor == null ? -1 : globals.quest_stage_minor,
    ts_enter_ms: tick.ts_enter_ms,
    ts_leave_ms: tsLeave,
    duration_ms: tsLeave - tick.ts_enter_ms,
    checkpoint: checkpoint,
    event_counts: tick.event_counts,
    event_overflow: tick.overflow,
    event_heads: buildCaptureEventHeads(tick.event_heads),
    timing_samples: timingSamplesFromTick({
      tick_index: tick.tick_index,
      gameplay_frame: tick.gameplay_frame,
      timing_samples: tick.timing_samples,
      diagnostics: { timing: timing },
    }),
    input_queries: {
      stats: tick.input_queries,
      query_hash: toHex(tick.input_hash_state >>> 0, 8),
    },
    input_player_keys: tick.input_player_keys,
    rng_stream: tick.rng.head,
    rng_calls: tick.rng.calls | 0,
    rng_outside_before: {
      calls: tick.rng.outside_before_calls | 0,
      dropped: tick.rng.outside_before_dropped | 0,
      caller_counts: tick.rng.outside_before_caller_counts || {},
      head: tick.rng.outside_before_head || [],
    },
    rng_state_enter_u32: tick.rng_state_enter_real == null ? null : tick.rng_state_enter_real >>> 0,
    rng_state_leave_u32:
      outState.lastGpurLeaveRngStateReal == null ? null : outState.lastGpurLeaveRngStateReal >>> 0,
    diagnostics: diagnostics,
    input_approx: buildInputApprox(afterPlayers, tick),
    frame_dt_ms: frameDtMs,
    frame_dt_ms_i32: frameDtMsI32,
    before: tick.before,
    after: after,
    samples: {
      creatures: readActiveCreatureSample(CONFIG.creatureSampleLimit),
      projectiles: readActiveProjectileSample(CONFIG.projectileSampleLimit),
      secondary_projectiles: readActiveSecondaryProjectileSample(CONFIG.secondaryProjectileSampleLimit),
      bonuses: readActiveBonusSample(CONFIG.bonusSampleLimit),
    },
  };

  writeCaptureTick(out);
  writeLine({
    event: "tick",
    tick_index: out.tick_index,
    gameplay_frame: out.gameplay_frame,
    state_id: out.state_id_leave,
    rng_calls: tick.rng.calls,
    event_total: tick.event_total,
  });
  if (afterElapsedMs != null) outState.lastTickElapsedMs = afterElapsedMs;
  outState.lastTickGameplayFrame = tick.gameplay_frame;
  outState.currentTick = null;
}

function attachHook(name, ptrVal, handlers) {
  if (!ptrVal) {
    outState.hookStatusByName[name] = "missing_pointer";
    writeLine({ event: "hook_skip", name: name, reason: "missing_pointer" });
    return false;
  }
  try {
    const wrappedHandlers = {};
    if (handlers && typeof handlers.onEnter === "function") {
      wrappedHandlers.onEnter = function (args) {
        recordHookActivity(name, "enter", this);
        return handlers.onEnter.call(this, args);
      };
    }
    if (handlers && typeof handlers.onLeave === "function") {
      wrappedHandlers.onLeave = function (retval) {
        recordHookActivity(name, "leave", this);
        return handlers.onLeave.call(this, retval);
      };
    }
    Interceptor.attach(ptrVal, wrappedHandlers);
    outState.hookStatusByName[name] = "attached";
    writeLine({ event: "hook_ok", name: name, addr: ptrVal.toString() });
    return true;
  } catch (e) {
    outState.hookStatusByName[name] = "attach_error";
    writeLine({ event: "hook_error", name: name, addr: ptrVal.toString(), error: String(e) });
    return false;
  }
}

function installHooks() {
  attachHook("gameplay_update_and_render", fnPtrs.gameplay_update_and_render, {
    onEnter() {
      outState.gameplayFrame += 1;
      updateCurrentStateFromMemory();
      if (!shouldCaptureTickForState(outState.currentStateId)) {
        outState.pending_timing_samples = [];
        outState.currentTick = null;
        return;
      }
      outState.currentTick = makeTickContext();
      outState.currentTick.rng_state_enter_real = readCrtRandStateU32(this.threadId);
      _consumePendingTimingSamplesIntoTick(outState.currentTick);
      recordTimingSample("gpur_enter", "snapshot", {
        globals:
          outState.currentTick &&
          outState.currentTick.before &&
          outState.currentTick.before.globals
            ? outState.currentTick.before.globals
            : null,
      });
    },
    onLeave() {
      outState.lastGpurLeaveRngStateReal = readCrtRandStateU32(this.threadId);
      finalizeTick();
    },
  });

  attachHook("game_state_set", fnPtrs.game_state_set, {
    onEnter(args) {
      this._targetState = args[0].toInt32();
      this._before = {
        prev: readDataI32("game_state_prev"),
        id: readDataI32("game_state_id"),
        pending: readDataI32("game_state_pending"),
      };
      this._caller = CONFIG.includeCaller ? formatCaller(this.returnAddress) : null;
      this._bt = maybeBacktrace(this.context);
    },
    onLeave() {
      updateCurrentStateFromMemory();
      const payload = {
        target_state: this._targetState,
        before: this._before,
        after: {
          prev: outState.currentStatePrev,
          id: outState.currentStateId,
          pending: outState.currentStatePending,
        },
        caller: this._caller,
        backtrace: this._bt,
      };
      addTickEvent(
        "state_transition",
        payload,
        "gs:" + payload.before.id + "->" + payload.target_state
      );
      emitRawEvent(Object.assign({ event: "game_state_set" }, payload));
    },
  });

  attachHook("quest_start_selected", fnPtrs.quest_start_selected, {
    onEnter() {
      noteQuestAttemptStart(
        "quest_start_selected",
        readDataI32("config_game_mode"),
        readDataI32("quest_stage_major"),
        readDataI32("quest_stage_minor")
      );
    },
  });

  function hookModeTick(name) {
    attachHook(name, fnPtrs[name], {
      onEnter() {
        const tick = outState.currentTick;
        if (!tick) return;
        const beforeGlobals = readGameplayGlobalsCompact();
        this._modeCtx = {
          mode_fn: name,
          before: {
            creature_active_count: beforeGlobals.creature_active_count,
            time_played_ms: beforeGlobals.time_played_ms,
            frame_dt_ms_i32: beforeGlobals.frame_dt_ms_i32,
            frame_dt_ms_f32: beforeGlobals.frame_dt_ms_f32,
            quest_spawn_timeline: beforeGlobals.quest_spawn_timeline,
            quest_spawn_stall_timer_ms: beforeGlobals.quest_spawn_stall_timer_ms,
          },
        };
        tick.mode_hint = tick.mode_hint || name;
        addTickEvent("mode_tick", { mode_fn: name }, "m:" + name);
      },
      onLeave() {
        const tick = outState.currentTick;
        const modeCtx = this._modeCtx;
        this._modeCtx = null;
        if (!tick || !modeCtx) return;
        const afterGlobals = readGameplayGlobalsCompact();
        const sample = {
          mode_fn: modeCtx.mode_fn,
          before: modeCtx.before,
          after: {
            creature_active_count: afterGlobals.creature_active_count,
            time_played_ms: afterGlobals.time_played_ms,
            frame_dt_ms_i32: afterGlobals.frame_dt_ms_i32,
            frame_dt_ms_f32: afterGlobals.frame_dt_ms_f32,
            quest_spawn_timeline: afterGlobals.quest_spawn_timeline,
            quest_spawn_stall_timer_ms: afterGlobals.quest_spawn_stall_timer_ms,
          },
        };
        sample.delta = {
          creature_active_count:
            sample.before.creature_active_count != null && sample.after.creature_active_count != null
              ? sample.after.creature_active_count - sample.before.creature_active_count
              : null,
          time_played_ms:
            sample.before.time_played_ms != null && sample.after.time_played_ms != null
              ? sample.after.time_played_ms - sample.before.time_played_ms
              : null,
        };
        if (CONFIG.maxHeadPerKind < 0 || tick.mode_samples.length < CONFIG.maxHeadPerKind) {
          tick.mode_samples.push(sample);
        }
      },
    });
  }
  hookModeTick("quest_mode_update");
  hookModeTick("rush_mode_update");
  hookModeTick("survival_update");
  hookModeTick("typo_gameplay_update_and_render");

  if (CONFIG.enableCreatureMicroHooks) {
    attachHook("creature_update_all", fnPtrs.creature_update_all, {
      onEnter() {
        const tick = outState.currentTick;
        if (!tick) return;
        if (!_shouldCaptureCreatureMicroForTick(tick.tick_index)) return;
        const slots = _listCreatureMicroTrackedSlots();
        if (!Array.isArray(slots) || slots.length <= 0) return;
        const beforeBySlot = {};
        for (let i = 0; i < slots.length; i++) {
          const slot = slots[i] | 0;
          beforeBySlot[slot] = _readCreatureMicroState(slot);
        }
        creatureUpdateMicroContextByTid[this.threadId] = {
          tick_index: tick.tick_index,
          slots: slots,
          before_by_slot: beforeBySlot,
        };
      },
      onLeave() {
        const ctx = creatureUpdateMicroContextByTid[this.threadId];
        delete creatureUpdateMicroContextByTid[this.threadId];
        if (!ctx) return;
        const tick = outState.currentTick;
        if (!tick) return;
        if ((ctx.tick_index | 0) !== (tick.tick_index | 0)) return;
        const slots = Array.isArray(ctx.slots) ? ctx.slots : [];
        const beforeBySlot = asObject(ctx.before_by_slot);
        for (let i = 0; i < slots.length; i++) {
          const slot = slots[i] | 0;
          if (!_shouldCaptureCreatureMicroSlot(slot)) continue;
          const payload = {
            event_kind: "creature_update_window",
            slot: slot,
            before: beforeBySlot[slot] || null,
            after: _readCreatureMicroState(slot),
          };
          _addCreatureMicroEvent(payload, "cum:w:" + String(slot));
          emitRawEvent(Object.assign({ event: "creature_update_micro_window" }, payload));
        }
      },
    });

    attachHook("angle_approach", fnPtrs.angle_approach, {
      onEnter(args) {
        const tick = outState.currentTick;
        if (!tick) return;
        if (!_shouldCaptureCreatureMicroForTick(tick.tick_index)) return;
        const anglePtr = args[0];
        const slot = _creatureIndexFromHeadingPtr(anglePtr);
        if (slot == null) return;
        if (!_shouldCaptureCreatureMicroSlot(slot)) return;
        const angleIn = safeReadF32(anglePtr);
        const target = argAsF32(args[1]);
        const rate = argAsF32(args[2]);
        pushAngleApproachContext(this.threadId, {
          tick_index: tick.tick_index,
          slot: slot,
          angle_ptr: anglePtr,
          angle_in: angleIn,
          target: target,
          rate: rate,
          before: _readCreatureMicroState(slot),
        });
      },
      onLeave() {
        const ctx = popAngleApproachContext(this.threadId);
        if (!ctx) return;
        const tick = outState.currentTick;
        if (!tick) return;
        if ((ctx.tick_index | 0) !== (tick.tick_index | 0)) return;
        const slot = ctx.slot | 0;
        if (slot < 0) return;
        const angleOut = safeReadF32(ctx.angle_ptr);
        const angleInNum = _isFiniteNumber(ctx.angle_in) ? Number(ctx.angle_in) : null;
        const targetNum = _isFiniteNumber(ctx.target) ? Number(ctx.target) : null;
        const rateNum = _isFiniteNumber(ctx.rate) ? Number(ctx.rate) : null;
        const angleOutNum = _isFiniteNumber(angleOut) ? Number(angleOut) : null;
        const classified = _classifyAngleApproach(
          angleInNum,
          targetNum,
          rateNum,
          angleOutNum,
        );
        const payload = {
          event_kind: "angle_approach",
          slot: slot,
          angle_ptr: ctx.angle_ptr ? ctx.angle_ptr.toString() : null,
          angle_in: captureNumber(angleInNum),
          angle_out: captureNumber(angleOutNum),
          target: captureNumber(targetNum),
          target_effective: captureNumber(classified.target_effective),
          rate: captureNumber(rateNum),
          delta_to_target_direct: captureNumber(classified.delta_direct),
          delta_to_target_effective: captureNumber(classified.delta_effective),
          step_delta: captureNumber(classified.step_delta),
          branch: classified.branch,
          before: ctx.before || null,
          after: _readCreatureMicroState(slot),
        };
        _addCreatureMicroEvent(payload, "cum:a:" + String(slot));
        emitRawEvent(Object.assign({ event: "creature_update_micro_angle_approach" }, payload));
      },
    });
  }

  if (CONFIG.enableInputHooks) {
    function addInputQueryHook(name, queryKey, token) {
      attachHook(name, fnPtrs[name], {
        onEnter() {
          const callerStatic = runtimeToStatic(this.returnAddress);
          pushInputContext(this.threadId, {
            query_key: queryKey,
            token: token,
            query: name,
            arg0: null,
            caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
            caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
            backtrace: maybeBacktrace(this.context),
          });
        },
        onLeave(retval) {
          const ctx = popInputContext(this.threadId);
          if (!ctx) return;
          let pressed = false;
          try {
            pressed = retval.toInt32() !== 0;
          } catch (_) {
            pressed = false;
          }
          const payload = {
            query: name,
            pressed: pressed,
            arg0: null,
            caller: ctx.caller,
            caller_static: ctx.caller_static,
            backtrace: ctx.backtrace,
            console_open: readDataU32("console_open_flag"),
            primary_latch: readDataU32("input_primary_latch"),
          };
          const tick = outState.currentTick;
          if (tick) {
            const state = ensurePlayerKeyState(tick, 0);
            if (state) {
              if (ctx.query_key === "primary_down") {
                state.fire_down = state.fire_down === true ? true : !!pressed;
              }
              if (ctx.query_key === "primary_edge") {
                state.fire_pressed = state.fire_pressed === true ? true : !!pressed;
              }
            }
          }
          registerInputQuery(ctx.query_key, pressed, ctx.token, payload);
          emitRawEvent(Object.assign({ event: name }, payload));
        },
      });
    }

    addInputQueryHook("input_primary_just_pressed", "primary_edge", "ipj");
    addInputQueryHook("input_primary_is_down", "primary_down", "ipd");
    addInputQueryHook("input_any_key_pressed", "any_key", "iak");

    function addGrimInputQueryHook(name, ptrVal, classifyKind, tokenPrefix) {
      attachHook(name, ptrVal, {
        onEnter(args) {
          let arg0 = null;
          try {
            arg0 = args[0] ? args[0].toInt32() : null;
          } catch (_) {
            arg0 = null;
          }
          const callerStatic = runtimeToStatic(this.returnAddress);
          if (!isPlayerUpdateCaller(callerStatic == null ? null : toHex(callerStatic, 8))) {
            return;
          }
          pushInputContext(this.threadId, {
            query_key: null,
            token: null,
            query: name,
            arg0: arg0,
            caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
            caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
            backtrace: maybeBacktrace(this.context),
          });
        },
        onLeave(retval) {
          const ctx = popInputContext(this.threadId);
          if (!ctx) return;
          let pressed = false;
          try {
            pressed = retval.toInt32() !== 0;
          } catch (_) {
            pressed = false;
          }
          const queryKey = classifyKind(ctx.arg0);
          updatePlayerInputKeyState(outState.currentTick, name, ctx.arg0, pressed, ctx.caller_static);
          if (!queryKey) return;
          const payload = {
            query: name,
            pressed: pressed,
            arg0: ctx.arg0,
            caller: ctx.caller,
            caller_static: ctx.caller_static,
            backtrace: ctx.backtrace,
            console_open: readDataU32("console_open_flag"),
            primary_latch: readDataU32("input_primary_latch"),
          };
          const token = tokenPrefix + ":" + String(ctx.arg0 == null ? "na" : ctx.arg0);
          registerInputQuery(queryKey, pressed, token, payload);
          emitRawEvent(Object.assign({ event: name }, payload));
        },
      });
    }

    addGrimInputQueryHook(
      "grim_is_key_down",
      grimFnPtrs.grim_is_key_down,
      function (keyCode) {
        return null;
      },
      "gikd"
    );
    addGrimInputQueryHook(
      "grim_is_key_active",
      grimFnPtrs.grim_is_key_active,
      function (keyCode) {
        return null;
      },
      "gika"
    );
  }

  if (CONFIG.enableRngHooks) {
    attachHook("crt_srand", fnPtrs.crt_srand, {
      onEnter(args) {
        let seedU32 = null;
        try {
          seedU32 = args[0].toUInt32() >>> 0;
        } catch (_) {
          seedU32 = null;
        }
        if (seedU32 == null) {
          // Use the tagged contract error row; finalize rejects unknown
          // event tags with an opaque decode error otherwise.
          emitCaptureContractError("crt_srand_missing_seed", null);
          return;
        }
        srandContextByTid[this.threadId] = {
          seed_u32: seedU32 >>> 0,
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        };
      },
      onLeave() {
        const ctx = srandContextByTid[this.threadId];
        delete srandContextByTid[this.threadId];
        if (!ctx) return;
        outState.lastSrandSeed = ctx.seed_u32 >>> 0;
        outState.rngSeedEpoch += 1;
        if (CONFIG.enableRngStateMirror) {
          outState.rngMirrorStateU32 = ctx.seed_u32 >>> 0;
        }
        emitRawEvent({
          event: "crt_srand",
          seed_u32: ctx.seed_u32,
          seed_hex: ctx.seed_u32 == null ? null : toHex(ctx.seed_u32, 8),
          caller: ctx.caller,
          seed_epoch: outState.rngSeedEpoch >>> 0,
          rng_call_seq: outState.rngCallSeq >>> 0,
        });
      },
    });

    attachHook("crt_rand", fnPtrs.crt_rand, {
      onEnter() {
        const callerStatic = runtimeToStatic(this.returnAddress);
        rngContextByTid[this.threadId] = {
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
          state_before_real: readCrtRandStateU32(this.threadId),
        };
      },
      onLeave(retval) {
        const ctx = rngContextByTid[this.threadId];
        delete rngContextByTid[this.threadId];
        let value = null;
        try {
          value = retval.toInt32();
        } catch (_) {
          value = null;
        }
        const roll = registerRngRoll(
          value,
          ctx ? ctx.caller_static : null,
          ctx ? ctx.caller : null,
          ctx ? ctx.state_before_real : null
        );
        emitRawEvent({
          event: "crt_rand",
          value_i32: value,
          caller: ctx ? ctx.caller : null,
          caller_static: ctx ? ctx.caller_static : null,
          seq: roll ? roll.seq : null,
          seed_epoch: roll ? roll.seed_epoch : null,
          tick_index: roll ? roll.tick_index : null,
          tick_call_index: roll ? roll.tick_call_index : null,
          outside_tick: roll ? roll.outside_tick : null,
          state_before_u32: roll ? roll.state_before_u32 : null,
          state_after_u32: roll ? roll.state_after_u32 : null,
          expected_value_15: roll ? roll.expected_value_15 : null,
          mirror_match: roll ? roll.mirror_match : null,
        });
      },
    });
  }

  attachHook("player_fire_weapon", fnPtrs.player_fire_weapon, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      fireContextByTid[this.threadId] = {
        player_index: playerIndex,
        before: readPlayerCompact(playerIndex >= 0 ? playerIndex : 0),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave() {
      const ctx = fireContextByTid[this.threadId];
      delete fireContextByTid[this.threadId];
      if (!ctx) return;
      const idx = ctx.player_index >= 0 ? ctx.player_index : 0;
      const after = readPlayerCompact(idx);
      const payload = {
        player_index: ctx.player_index,
        weapon_before: ctx.before.weapon_id,
        weapon_after: after.weapon_id,
        ammo_before: ctx.before.ammo_f32,
        ammo_after: after.ammo_f32,
        shot_cooldown_after: after.shot_cooldown,
        caller: ctx.caller,
      };
      const tick = outState.currentTick;
      if (tick) {
        tick.fire_by_player[idx] = (tick.fire_by_player[idx] || 0) + 1;
        tick.player_fire_direct_by_player[idx] = (tick.player_fire_direct_by_player[idx] || 0) + 1;
      }
      addTickEvent(
        "player_fire",
        payload,
        "f:" + payload.player_index + ":" + (payload.weapon_after == null ? -1 : payload.weapon_after)
      );
      emitRawEvent(Object.assign({ event: "player_fire_weapon" }, payload));
    },
  });

  attachHook("weapon_assign_player", fnPtrs.weapon_assign_player, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      const weaponId = args[1].toInt32();
      assignContextByTid[this.threadId] = {
        player_index: playerIndex,
        weapon_id: weaponId,
        before: readPlayerCompact(playerIndex),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave() {
      const ctx = assignContextByTid[this.threadId];
      delete assignContextByTid[this.threadId];
      if (!ctx) return;
      const after = readPlayerCompact(ctx.player_index);
      const payload = {
        player_index: ctx.player_index,
        weapon_id: ctx.weapon_id,
        weapon_before: ctx.before.weapon_id,
        weapon_after: after.weapon_id,
        caller: ctx.caller,
      };
      addTickEvent(
        "weapon_assign",
        payload,
        "wa:" + payload.player_index + ":" + (payload.weapon_after == null ? -1 : payload.weapon_after)
      );
      emitRawEvent(Object.assign({ event: "weapon_assign_player" }, payload));
    },
  });

  attachHook("bonus_apply", fnPtrs.bonus_apply, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      const entry = args[1];
      bonusContextByTid[this.threadId] = {
        player_index: playerIndex,
        bonus_id: entry ? safeReadS32(entry) : null,
        entry_state: entry ? safeReadS32(entry.add(4)) : null,
        amount_i32: entry ? safeReadS32(entry.add(0x18)) : null,
        amount_f32: entry ? captureNumber(safeReadF32(entry.add(0x18))) : null,
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave() {
      const ctx = bonusContextByTid[this.threadId];
      delete bonusContextByTid[this.threadId];
      if (!ctx) return;
      const payload = ctx;
      addTickEvent(
        "bonus_apply",
        payload,
        "ba:" + payload.player_index + ":" + (payload.bonus_id == null ? -1 : payload.bonus_id)
      );
      emitRawEvent(Object.assign({ event: "bonus_apply" }, payload));
    },
  });

  if (CONFIG.enableBonusSpawnHook) {
    attachHook("bonus_try_spawn_on_kill", fnPtrs.bonus_try_spawn_on_kill, {
      onEnter(args) {
        const posPtr = args[0];
        const callerStatic = runtimeToStatic(this.returnAddress);
        bonusSpawnContextByTid[this.threadId] = {
          pos: {
            x: captureNumber(posPtr ? safeReadF32(posPtr) : null),
            y: captureNumber(posPtr ? safeReadF32(posPtr.add(4)) : null),
          },
          before_slots: snapshotBonusPoolRaw(),
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
          backtrace: maybeBacktrace(this.context),
        };
      },
      onLeave() {
        const ctx = bonusSpawnContextByTid[this.threadId];
        delete bonusSpawnContextByTid[this.threadId];
        if (!ctx) return;
        const afterSlots = snapshotBonusPoolRaw();
        const summary = summarizeBonusPoolDelta(ctx.before_slots, afterSlots);
        const payload = {
          pos: ctx.pos,
          caller: ctx.caller,
          caller_static: ctx.caller_static,
          backtrace: ctx.backtrace,
          before_active_count: summary.before_active_count,
          after_active_count: summary.after_active_count,
          active_delta: summary.active_delta,
          changed_slots_total: summary.changed_slots_total,
          changed_slots_head: summary.changed_slots_head,
          changed_slots_overflow: summary.changed_slots_overflow,
          spawned_slots_total: summary.spawned_slots_total,
          spawned_slots: summary.spawned_slots,
          spawned_slots_overflow: summary.spawned_slots_overflow,
          removed_slots_total: summary.removed_slots_total,
          removed_slots: summary.removed_slots,
          removed_slots_overflow: summary.removed_slots_overflow,
          before_live_head: summary.before_live_head,
          after_live_head: summary.after_live_head,
          spawned_head: summary.spawned_head,
        };
        const tick = outState.currentTick;
        if (tick && payload.caller_static) {
          bumpCounterMap(tick.bonus_spawn_callers, payload.caller_static);
        }
        addTickEvent(
          "bonus_spawn",
          payload,
          "bs:" +
            String(payload.spawned_slots_total > 0 ? 1 : 0) +
            ":" +
            String(payload.active_delta == null ? 0 : payload.active_delta)
        );
        emitRawEvent(Object.assign({ event: "bonus_try_spawn_on_kill" }, payload));
      },
    });
  }

  attachHook("secondary_projectile_spawn", fnPtrs.secondary_projectile_spawn, {
    onEnter(args) {
      this._ctx = {
        pos: {
          x: captureNumber(safeReadF32(args[0])),
          y: captureNumber(safeReadF32(args[0].add(4))),
        },
        angle_f32: argAsF32(args[1]),
        requested_type_id: args[2].toInt32(),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave(retval) {
      const ctx = this._ctx;
      if (!ctx) return;
      const idx = retval.toInt32();
      const spawned = readSecondaryProjectileEntry(idx);
      const actualType = spawned ? spawned.type_id : null;
      const payload = {
        index: idx,
        requested_type_id: ctx.requested_type_id,
        actual_type_id: actualType,
        spawned: spawned,
        angle_f32: captureNumber(ctx.angle_f32),
        pos: ctx.pos,
        type_overridden: actualType == null ? null : actualType !== ctx.requested_type_id,
        caller: ctx.caller,
      };
      addTickEvent(
        "secondary_projectile_spawn",
        payload,
        "sps:" +
          (payload.requested_type_id == null ? -1 : payload.requested_type_id) +
          "->" +
          (payload.actual_type_id == null ? -1 : payload.actual_type_id)
      );
      emitRawEvent(Object.assign({ event: "secondary_projectile_spawn" }, payload));
    },
  });

  attachHook("projectile_spawn", fnPtrs.projectile_spawn, {
    onEnter(args) {
      const callerStatic = runtimeToStatic(this.returnAddress);
      this._ctx = {
        pos: {
          x: captureNumber(safeReadF32(args[0])),
          y: captureNumber(safeReadF32(args[0].add(4))),
        },
        angle_f32: argAsF32(args[1]),
        requested_type_id: args[2].toInt32(),
        owner_id: args[3].toInt32(),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
      };
    },
    onLeave(retval) {
      const ctx = this._ctx;
      if (!ctx) return;
      const idx = retval.toInt32();
      const spawned = readProjectileEntry(idx);
      const actualType = spawned ? spawned.type_id : null;
      const payload = {
        index: idx,
        requested_type_id: ctx.requested_type_id,
        actual_type_id: actualType,
        spawned: spawned,
        owner_id: ctx.owner_id,
        angle_f32: captureNumber(ctx.angle_f32),
        pos: ctx.pos,
        type_overridden: actualType == null ? null : actualType !== ctx.requested_type_id,
        caller: ctx.caller,
        caller_static: ctx.caller_static,
      };
      addTickEvent(
        "projectile_spawn",
        payload,
        "ps:" +
          (payload.owner_id == null ? -1 : payload.owner_id) +
          ":" +
          (payload.requested_type_id == null ? -1 : payload.requested_type_id) +
          "->" +
          (payload.actual_type_id == null ? -1 : payload.actual_type_id)
      );
      const tick = outState.currentTick;
      const playerIndex = ownerIdToPlayerIndex(ctx.owner_id);
      if (tick && playerIndex != null && isPlayerUpdateCaller(ctx.caller_static)) {
        tick.player_projectile_spawn_by_player[playerIndex] =
          (tick.player_projectile_spawn_by_player[playerIndex] || 0) + 1;
        if ((tick.fire_by_player[playerIndex] || 0) <= 0) {
          const beforePlayers = tick.before && Array.isArray(tick.before.players) ? tick.before.players : [];
          const beforePlayer =
            beforePlayers[playerIndex] && typeof beforePlayers[playerIndex] === "object"
              ? beforePlayers[playerIndex]
              : null;
          const afterPlayer = readPlayerCompact(playerIndex);
          const firePayload = {
            player_index: playerIndex,
            weapon_before: beforePlayer && beforePlayer.weapon_id != null ? beforePlayer.weapon_id : null,
            weapon_after: afterPlayer.weapon_id,
            ammo_before: beforePlayer && beforePlayer.ammo_f32 != null ? beforePlayer.ammo_f32 : null,
            ammo_after: afterPlayer.ammo_f32,
            shot_cooldown_after: afterPlayer.shot_cooldown,
            owner_id: ctx.owner_id,
            requested_type_id: ctx.requested_type_id,
            actual_type_id: actualType,
            source: "projectile_spawn_owner",
            caller: ctx.caller,
            caller_static: ctx.caller_static,
          };
          addTickEvent("player_fire", firePayload, "pfb:" + playerIndex + ":" + String(payload.index | 0));
          tick.fire_by_player[playerIndex] = (tick.fire_by_player[playerIndex] || 0) + 1;
          tick.player_fire_fallback_by_player[playerIndex] =
            (tick.player_fire_fallback_by_player[playerIndex] || 0) + 1;
        }
      }
      emitRawEvent(Object.assign({ event: "projectile_spawn" }, payload));
    },
  });

  attachHook("creature_find_in_radius", fnPtrs.creature_find_in_radius, {
    onEnter(args) {
      const callerStatic = runtimeToStatic(this.returnAddress);
      if (!isProjectileUpdateCaller(callerStatic)) {
        return;
      }
      const queryPosPtr = args[0];
      const projectileIndex = projectileIndexFromPosPtr(queryPosPtr);
      const projectile = readProjectileEntryByPosPtr(queryPosPtr);
      const shockChainProjectileId = readDataI32("shock_chain_projectile_id");
      const shockChainLinksLeft = readDataI32("shock_chain_links_left");
      this._ctx = {
        pos: {
          x: captureNumber(safeReadF32(queryPosPtr)),
          y: captureNumber(safeReadF32(queryPosPtr.add(4))),
        },
        radius_f32: captureNumber(argAsF32(args[1])),
        start_index: args[2] ? args[2].toInt32() : null,
        projectile_index: projectileIndex,
        projectile_owner_id: projectile && projectile.owner_id != null ? projectile.owner_id : null,
        projectile_type_id: projectile && projectile.type_id != null ? projectile.type_id : null,
        projectile_hit_radius: projectile && projectile.hit_radius != null ? projectile.hit_radius : null,
        shock_chain_projectile_id: shockChainProjectileId == null ? null : shockChainProjectileId,
        shock_chain_links_left: shockChainLinksLeft == null ? null : shockChainLinksLeft,
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
        backtrace: maybeBacktrace(this.context),
      };
    },
    onLeave(retval) {
      const ctx = this._ctx;
      if (!ctx) return;
      const creatureIndex = retval ? retval.toInt32() : -1;
      const ownerId = ctx.projectile_owner_id;
      const ownerCollision =
        creatureIndex >= 0 && ownerId != null && Number.isFinite(ownerId) && creatureIndex === ownerId;
      const shockChainTracked =
        ctx.projectile_index != null &&
        ctx.shock_chain_projectile_id != null &&
        ctx.projectile_index === ctx.shock_chain_projectile_id;
      const playerFindSkipped = (creatureIndex < 0 || ownerCollision) && !!shockChainTracked;
      const queryPayload = {
        result_creature_index: creatureIndex >= 0 ? creatureIndex : null,
        result_kind: creatureIndex < 0 ? "miss" : ownerCollision ? "owner_collision" : "hit",
        start_index: ctx.start_index,
        radius_f32: ctx.radius_f32,
        query_pos: ctx.pos,
        projectile_index: ctx.projectile_index,
        projectile_owner_id: ctx.projectile_owner_id,
        projectile_type_id: ctx.projectile_type_id,
        projectile_hit_radius: ctx.projectile_hit_radius,
        owner_collision: ownerCollision,
        player_find_skipped: playerFindSkipped,
        shock_chain_projectile_id: ctx.shock_chain_projectile_id,
        shock_chain_links_left: ctx.shock_chain_links_left,
        caller: ctx.caller,
        caller_static: ctx.caller_static,
        backtrace: ctx.backtrace,
      };
      const tick = outState.currentTick;
      if (tick && queryPayload.caller_static) {
        bumpCounterMap(tick.projectile_find_query_callers, queryPayload.caller_static);
      }
      if (tick && creatureIndex < 0) tick.projectile_find_query_miss = (tick.projectile_find_query_miss || 0) + 1;
      if (tick && ownerCollision) {
        tick.projectile_find_query_owner_collision = (tick.projectile_find_query_owner_collision || 0) + 1;
      }
      addTickEvent(
        "projectile_find_query",
        queryPayload,
        "pfq:" + String(creatureIndex >= 0 ? creatureIndex : -1)
      );
      emitRawEvent(Object.assign({ event: "projectile_find_query" }, queryPayload));
      if (creatureIndex < 0) return;
      const creature = readCreatureLifecycleEntry(creatureIndex);
      const payload = Object.assign({}, queryPayload, {
        creature_index: creatureIndex,
        creature: creature,
        corpse_hit:
          creature && creature.hp != null && Number.isFinite(creature.hp)
            ? creature.hp <= 0
            : null,
      });
      if (tick && payload.caller_static) {
        bumpCounterMap(tick.projectile_find_hit_callers, payload.caller_static);
      }
      addTickEvent(
        "projectile_find_hit",
        payload,
        "pfh:" + String(payload.creature_index == null ? -1 : payload.creature_index)
      );
      emitRawEvent(Object.assign({ event: "projectile_find_hit" }, payload));
    },
  });

  if (CONFIG.enableDamageHooks) {
    attachHook("creature_apply_damage", fnPtrs.creature_apply_damage, {
      onEnter(args) {
        const creatureIndex = args[0] ? args[0].toInt32() : -1;
        const callerStatic = runtimeToStatic(this.returnAddress);
        if (CONFIG.creatureDamageProjectileOnly && !isProjectileUpdateCaller(callerStatic)) {
          return;
        }
        const impulsePtr = args[3];
        creatureDamageContextByTid[this.threadId] = {
          creature_index: creatureIndex,
          damage_f32: captureNumber(argAsF32(args[1])),
          damage_type: args[2] ? args[2].toInt32() : null,
          impulse_x: captureNumber(impulsePtr ? safeReadF32(impulsePtr) : null),
          impulse_y: captureNumber(impulsePtr ? safeReadF32(impulsePtr.add(4)) : null),
          before: readCreatureLifecycleEntry(creatureIndex),
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
          backtrace: maybeBacktrace(this.context),
        };
      },
      onLeave(retval) {
        const ctx = creatureDamageContextByTid[this.threadId];
        delete creatureDamageContextByTid[this.threadId];
        if (!ctx) return;
        const after = readCreatureLifecycleEntry(ctx.creature_index);
        const killReturn = retval ? retval.toInt32() : null;
        const payload = {
          creature_index: ctx.creature_index,
          damage_f32: ctx.damage_f32,
          damage_type: ctx.damage_type,
          impulse_x: ctx.impulse_x,
          impulse_y: ctx.impulse_y,
          hp_before: ctx.before ? ctx.before.hp : null,
          hp_after: after ? after.hp : null,
          hp_delta:
            ctx.before && after && ctx.before.hp != null && after.hp != null
              ? captureNumber(after.hp - ctx.before.hp)
              : null,
          killed: killReturn == null ? null : killReturn !== 0,
          kill_return: killReturn,
          active_before: ctx.before ? ctx.before.active : null,
          active_after: after ? after.active : null,
          caller: ctx.caller,
          caller_static: ctx.caller_static,
          backtrace: ctx.backtrace,
        };
        const tick = outState.currentTick;
        if (tick && payload.caller_static) {
          bumpCounterMap(tick.creature_damage_callers, payload.caller_static);
        }
        addTickEvent(
          "creature_damage",
          payload,
          "cda:" +
            String(payload.creature_index == null ? -1 : payload.creature_index) +
            ":" +
            String(payload.damage_type == null ? -1 : payload.damage_type) +
            ":" +
            String(payload.killed ? 1 : 0)
        );
        emitRawEvent(Object.assign({ event: "creature_apply_damage" }, payload));
      },
    });

    attachHook("player_take_damage", fnPtrs.player_take_damage, {
      onEnter(args) {
        const playerIndex = args[0].toInt32();
        damageContextByTid[this.threadId] = {
          player_index: playerIndex,
          damage_f32: captureNumber(argAsF32(args[1])),
          health_before: readPlayerCompact(playerIndex).health,
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        };
      },
      onLeave() {
        const ctx = damageContextByTid[this.threadId];
        delete damageContextByTid[this.threadId];
        if (!ctx) return;
        const after = readPlayerCompact(ctx.player_index);
        const payload = {
          player_index: ctx.player_index,
          damage_f32: ctx.damage_f32,
          health_before: ctx.health_before,
          health_after: after.health,
          health_delta:
            ctx.health_before != null && after.health != null
              ? captureNumber(after.health - ctx.health_before)
              : null,
          caller: ctx.caller,
        };
        addTickEvent(
          "player_damage",
          payload,
          "pd:" + payload.player_index + ":" + (payload.damage_f32 == null ? 0 : payload.damage_f32)
        );
        emitRawEvent(Object.assign({ event: "player_take_damage" }, payload));
      },
    });
  }

  if (CONFIG.enableEffectHooks) {
    attachHook("effect_spawn_blood_splatter", fnPtrs.effect_spawn_blood_splatter, {
      onEnter(args) {
        const callerStaticU32 = runtimeToStatic(this.returnAddress);
        const callerStaticHex = callerStaticU32 == null ? null : toHex(callerStaticU32, 8);
        const posPtr = args[0];
        bloodSplatterContextByTid[this.threadId] = {
          pos: {
            x: captureNumber(posPtr ? safeReadF32(posPtr) : null),
            y: captureNumber(posPtr ? safeReadF32(posPtr.add(4)) : null),
          },
          angle_f32: captureNumber(argAsF32(args[1])),
          age_f32: captureNumber(argAsF32(args[2])),
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStaticHex,
          caller_static_u32: callerStaticU32 == null ? null : callerStaticU32 >>> 0,
          rng_seq_before: outState.rngCallSeq >>> 0,
        };
      },
      onLeave() {
        const ctx = bloodSplatterContextByTid[this.threadId];
        delete bloodSplatterContextByTid[this.threadId];
        if (!ctx) return;
        const rngSeqAfter = outState.rngCallSeq >>> 0;
        const rngDraws = rngSeqAfter >= ctx.rng_seq_before ? rngSeqAfter - ctx.rng_seq_before : 0;
        const projectileUpdateCaller =
          ctx.caller_static_u32 == null ? false : isProjectileUpdateCaller(ctx.caller_static_u32);
        const payload = {
          pos: ctx.pos,
          angle_f32: ctx.angle_f32,
          age_f32: ctx.age_f32,
          caller: ctx.caller,
          caller_static: ctx.caller_static,
          projectile_update_caller: projectileUpdateCaller,
          rng_seq_before: ctx.rng_seq_before,
          rng_seq_after: rngSeqAfter,
          rng_draws: rngDraws,
        };
        const tick = outState.currentTick;
        if (tick) {
          tick.blood_splatter_calls = (tick.blood_splatter_calls || 0) + 1;
          tick.blood_splatter_rng_draws = (tick.blood_splatter_rng_draws || 0) + rngDraws;
          if (projectileUpdateCaller) {
            tick.blood_splatter_projectile_update_calls =
              (tick.blood_splatter_projectile_update_calls || 0) + 1;
          }
          if (payload.caller_static) {
            bumpCounterMap(tick.blood_splatter_callers, payload.caller_static);
            bumpCounterMapBy(
              tick.blood_splatter_rng_draws_by_caller,
              payload.caller_static,
              rngDraws
            );
          }
        }
        emitRawEvent(
          Object.assign({ event: "effect_spawn_blood_splatter" }, payload, {
            outside_tick: !tick,
            tick_index: tick ? tick.tick_index : Math.max(0, outState.gameplayFrame - 1),
          })
        );
      },
    });
  }

  if (CONFIG.enableCreatureDeathHook) {
    attachHook("creature_handle_death", fnPtrs.creature_handle_death, {
      onEnter(args) {
        const creatureIndex = args[0] ? args[0].toInt32() : -1;
        const keepCorpse = args[1] ? args[1].toInt32() !== 0 : null;
        const before = readCreatureLifecycleEntry(creatureIndex);
        const callerStatic = runtimeToStatic(this.returnAddress);
        creatureDeathContextByTid[this.threadId] = {
          creature_index: creatureIndex,
          keep_corpse: keepCorpse,
          before: before,
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
          backtrace: maybeBacktrace(this.context),
        };
      },
      onLeave() {
        const ctx = creatureDeathContextByTid[this.threadId];
        delete creatureDeathContextByTid[this.threadId];
        if (!ctx) return;
        const after = readCreatureLifecycleEntry(ctx.creature_index);
        const payload = {
          creature_index: ctx.creature_index,
          keep_corpse: ctx.keep_corpse,
          active_before: ctx.before ? ctx.before.active : null,
          active_after: after ? after.active : null,
          before: ctx.before,
          after: after,
          caller: ctx.caller,
          caller_static: ctx.caller_static,
          backtrace: ctx.backtrace,
        };
        const tick = outState.currentTick;
        if (tick && payload.caller_static) {
          bumpCounterMap(tick.death_callers, payload.caller_static);
        }
        addTickEvent(
          "creature_death",
          payload,
          "cd:" +
            String(payload.creature_index == null ? -1 : payload.creature_index) +
            ":" +
            String(payload.keep_corpse ? 1 : 0)
        );
        emitRawEvent(Object.assign({ event: "creature_handle_death" }, payload));
      },
    });
  }

  if (CONFIG.enableSpawnHooks) {
    attachHook("creature_spawn_template", fnPtrs.creature_spawn_template, {
      onEnter(args) {
        const callerStatic = runtimeToStatic(this.returnAddress);
        creatureSpawnContextByTid[this.threadId] = {
          template_id: args[0].toInt32(),
          pos: {
            x: captureNumber(safeReadF32(args[1])),
            y: captureNumber(safeReadF32(args[1].add(4))),
          },
          heading: captureNumber(argAsF32(args[2])),
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
        };
      },
      onLeave(retval) {
        const ctx = creatureSpawnContextByTid[this.threadId];
        delete creatureSpawnContextByTid[this.threadId];
        if (!ctx) return;
        const payload = {
          template_id: ctx.template_id,
          pos: ctx.pos,
          heading: ctx.heading,
          ret_ptr: retval ? retval.toString() : null,
          caller: ctx.caller,
          caller_static: ctx.caller_static,
        };
        const tick = outState.currentTick;
        if (tick && payload.caller_static) {
          bumpCounterMap(tick.spawn_callers_template, payload.caller_static);
        }
        addTickEvent(
          "creature_spawn",
          payload,
          "cs:" + (payload.template_id == null ? -1 : payload.template_id)
        );
        emitRawEvent(Object.assign({ event: "creature_spawn_template" }, payload));
      },
    });

    attachHook("survival_spawn_creature", fnPtrs.survival_spawn_creature, {
      onEnter(args) {
        const callerStatic = runtimeToStatic(this.returnAddress);
        this._spawnCtx = {
          source: "survival_spawn_creature",
          pos: {
            x: captureNumber(safeReadF32(args[0])),
            y: captureNumber(safeReadF32(args[0].add(4))),
          },
          creature_count_before: readDataI32("creature_active_count"),
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
        };
      },
      onLeave() {
        const ctx = this._spawnCtx;
        this._spawnCtx = null;
        if (!ctx) return;
        const creatureCountAfter = readDataI32("creature_active_count");
        const payload = {
          source: ctx.source,
          pos: ctx.pos,
          creature_count_before: ctx.creature_count_before,
          creature_count_after: creatureCountAfter,
          creature_count_delta:
            ctx.creature_count_before != null && creatureCountAfter != null
              ? creatureCountAfter - ctx.creature_count_before
              : null,
          caller: ctx.caller,
          caller_static: ctx.caller_static,
        };
        const tick = outState.currentTick;
        if (tick) {
          if (payload.caller_static) {
            bumpCounterMap(tick.spawn_callers_low, payload.caller_static);
          }
          bumpCounterMap(tick.spawn_sources_low, payload.source);
        }
        addTickEvent("creature_spawn_low", payload, "csl:ssc");
        emitRawEvent(Object.assign({ event: "survival_spawn_creature" }, payload));
      },
    });

    attachHook("creature_spawn_tinted", fnPtrs.creature_spawn_tinted, {
      onEnter(args) {
        const posPtr = args[0];
        const rgbaPtr = args[1];
        const callerStatic = runtimeToStatic(this.returnAddress);
        this._spawnCtx = {
          source: "creature_spawn_tinted",
          type_id: args[2].toInt32(),
          pos: {
            x: captureNumber(safeReadF32(posPtr)),
            y: captureNumber(safeReadF32(posPtr.add(4))),
          },
          tint: {
            r: captureNumber(safeReadF32(rgbaPtr)),
            g: captureNumber(safeReadF32(rgbaPtr.add(4))),
            b: captureNumber(safeReadF32(rgbaPtr.add(8))),
            a: captureNumber(safeReadF32(rgbaPtr.add(12))),
          },
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
        };
      },
      onLeave(retval) {
        const ctx = this._spawnCtx;
        this._spawnCtx = null;
        if (!ctx) return;
        const idx = retval.toInt32();
        const spawned = readCreatureEntry(idx);
        const payload = {
          source: ctx.source,
          index: idx,
          type_id: ctx.type_id,
          pos: ctx.pos,
          tint: ctx.tint,
          spawned: spawned,
          caller: ctx.caller,
          caller_static: ctx.caller_static,
        };
        const tick = outState.currentTick;
        if (tick) {
          if (payload.caller_static) {
            bumpCounterMap(tick.spawn_callers_low, payload.caller_static);
          }
          bumpCounterMap(tick.spawn_sources_low, payload.source);
        }
        addTickEvent(
          "creature_spawn_low",
          payload,
          "csl:cst:" + (payload.type_id == null ? -1 : payload.type_id)
        );
        emitRawEvent(Object.assign({ event: "creature_spawn_tinted" }, payload));
      },
    });

    if (CONFIG.enableCreatureSpawnHook) {
      attachHook("creature_spawn", fnPtrs.creature_spawn, {
        onEnter(args) {
          const posPtr = args[0];
          const rgbaPtr = args[1];
          const callerStatic = runtimeToStatic(this.returnAddress);
          this._spawnCtx = {
            source: "creature_spawn",
            type_id: args[2].toInt32(),
            pos: {
              x: captureNumber(safeReadF32(posPtr)),
              y: captureNumber(safeReadF32(posPtr.add(4))),
            },
            tint: {
              r: captureNumber(safeReadF32(rgbaPtr)),
              g: captureNumber(safeReadF32(rgbaPtr.add(4))),
              b: captureNumber(safeReadF32(rgbaPtr.add(8))),
              a: captureNumber(safeReadF32(rgbaPtr.add(12))),
            },
            caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
            caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
          };
        },
        onLeave(retval) {
          const ctx = this._spawnCtx;
          this._spawnCtx = null;
          if (!ctx) return;
          const idx = retval.toInt32();
          const spawned = readCreatureEntry(idx);
          const payload = {
            source: ctx.source,
            index: idx,
            type_id: ctx.type_id,
            pos: ctx.pos,
            tint: ctx.tint,
            spawned: spawned,
            caller: ctx.caller,
            caller_static: ctx.caller_static,
          };
          const tick = outState.currentTick;
          if (tick) {
            if (payload.caller_static) {
              bumpCounterMap(tick.spawn_callers_low, payload.caller_static);
            }
            bumpCounterMap(tick.spawn_sources_low, payload.source);
          }
          addTickEvent(
            "creature_spawn_low",
            payload,
            "csl:" + (payload.type_id == null ? -1 : payload.type_id)
          );
          emitRawEvent(Object.assign({ event: "creature_spawn" }, payload));
        },
      });
    }
  }

  attachHook("perks_update_effects", fnPtrs.perks_update_effects, {
    onLeave() {
      const compact = {
        perk_jinxed_proc_timer_s: captureNumber(readDataF32("perk_jinxed_proc_timer_s")),
        perk_lean_mean_exp_tick_timer_s: captureNumber(readDataF32("perk_lean_mean_exp_tick_timer_s")),
        perk_doctor_target_creature_id: readDataI32("perk_doctor_target_creature_id"),
        perk_pending_count: readDataI32("perk_pending_count"),
      };
      const prevHash = hashHex(outState.lastPerkCompact || {});
      const nextHash = hashHex(compact);
      if (prevHash === nextHash) return;
      outState.lastPerkCompact = compact;
      addTickEvent(
        "perk_delta",
        compact,
        "pk:" +
          (compact.perk_pending_count == null ? -1 : compact.perk_pending_count) +
          ":" +
          (compact.perk_doctor_target_creature_id == null ? -1 : compact.perk_doctor_target_creature_id)
      );
      emitRawEvent({ event: "perks_update_effects_delta", compact: compact });
    },
  });

  attachHook("perk_apply", fnPtrs.perk_apply, {
    onEnter(args) {
      const callerStatic = runtimeToStatic(this.returnAddress);
      this._perkApplyCtx = {
        perk_id: args[0] ? args[0].toInt32() : null,
        pending_before: readDataI32("perk_pending_count"),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
        backtrace: maybeBacktrace(this.context),
      };
    },
    onLeave() {
      const ctx = this._perkApplyCtx;
      this._perkApplyCtx = null;
      if (!ctx) return;
      const payload = {
        perk_id: ctx.perk_id,
        pending_before: ctx.pending_before,
        pending_after: readDataI32("perk_pending_count"),
        caller: ctx.caller,
        caller_static: ctx.caller_static,
        backtrace: ctx.backtrace,
      };
      const tick = outState.currentTick;
      if (tick) {
        addTickEvent(
          "perk_apply",
          payload,
          "pa:" + (payload.perk_id == null ? -1 : payload.perk_id)
        );
      } else {
        queueOutsidePerkApply(payload);
      }
      emitRawEvent(
        Object.assign({ event: "perk_apply" }, payload, {
          outside_tick: !tick,
          tick_index: tick ? tick.tick_index : Math.max(0, outState.gameplayFrame - 1),
        })
      );
    },
  });

  attachHook("quest_spawn_timeline_update", fnPtrs.quest_spawn_timeline_update, {
    onLeave() {
      const compact = {
        quest_spawn_timeline: readDataI32("quest_spawn_timeline"),
        quest_spawn_stall_timer_ms: readDataI32("quest_spawn_stall_timer_ms"),
        creature_active_count: readDataI32("creature_active_count"),
        quest_transition_timer_ms: readDataI32("quest_transition_timer_ms"),
      };
      const prevHash = hashHex(outState.lastQuestCompact || {});
      const nextHash = hashHex(compact);
      if (prevHash === nextHash) return;
      outState.lastQuestCompact = compact;
      addTickEvent(
        "quest_timeline_delta",
        compact,
        "qt:" +
          (compact.quest_spawn_timeline == null ? -1 : compact.quest_spawn_timeline) +
          ":" +
          (compact.quest_spawn_stall_timer_ms == null ? -1 : compact.quest_spawn_stall_timer_ms)
      );
      emitRawEvent({ event: "quest_spawn_timeline_delta", compact: compact });
    },
  });

  if (CONFIG.enableSfxHooks) {
    function addSfxHook(name, idGetter, tokenPrefix) {
      attachHook(name, fnPtrs[name], {
        onEnter(args) {
          const idVal = idGetter(args);
          const payload = {
            kind: name,
            id_i32: idVal,
            caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
            backtrace: maybeBacktrace(this.context),
          };
          const tick = outState.currentTick;
          if (tick && tick.sfx_ids.length < CONFIG.maxHeadPerKind) {
            tick.sfx_ids.push(String(idVal == null ? "null" : idVal));
          }
          addTickEvent(
            "sfx",
            payload,
            tokenPrefix + ":" + (idVal == null ? -1 : idVal)
          );
          emitRawEvent(Object.assign({ event: name }, payload));
        },
      });
    }

    addSfxHook(
      "sfx_play",
      function (args) {
        return args[0] ? args[0].toInt32() : null;
      },
      "sx"
    );
    addSfxHook(
      "sfx_play_exclusive",
      function (args) {
        return args[0] ? args[0].toInt32() : null;
      },
      "se"
    );
    addSfxHook(
      "sfx_play_panned",
      function (args) {
        return args[0] ? args[0].toInt32() : null;
      },
      "sp"
    );
  }
}

function emitHeartbeat() {
  updateCurrentStateFromMemory();
  if (!shouldCaptureTickForState(outState.currentStateId) && !CONFIG.emitTicksOutsideTrackedStates) {
    return;
  }
  resolvePlayerCount();
  writeLine({
    event: "heartbeat",
    session_id: outState.sessionId,
    gameplay_frame: outState.gameplayFrame,
    state_id: outState.currentStateId,
    state_pending: outState.currentStatePending,
    player_count: outState.playerCountResolved,
    input: readInputTelemetryCompact(),
    rng_calls_total: outState.rngCallsTotal,
    rng_call_seq: outState.rngCallSeq >>> 0,
    rng_calls_outside_tick: outState.rngCallsOutsideTick,
    rng_seed_epoch: outState.rngSeedEpoch >>> 0,
    rng_mirror_state_u32: outState.rngMirrorStateU32,
    rng_mirror_state_hex: outState.rngMirrorStateU32 == null ? null : toHex(outState.rngMirrorStateU32, 8),
    rng_mirror_mismatch_count: outState.rngMirrorMismatchCount,
    rng_mirror_unknown_calls: outState.rngMirrorUnknownCalls,
    rng_roll_log_emitted: outState.rngRollLogEmitted,
    rng_roll_log_dropped: outState.rngRollLogDropped,
    rng_outside_pending_calls: outState.rngOutsideTickPendingCalls,
    rng_outside_pending_dropped: outState.rngOutsideTickPendingDropped,
    perk_apply_outside_pending_calls: outState.perkApplyOutsideTickPendingCalls,
    perk_apply_outside_pending_dropped: outState.perkApplyOutsideTickPendingDropped,
    globals: readGameplayGlobalsCompact(),
    players: readPlayersCompact(),
  });
}

function startHeartbeat() {
  outState.heartbeatTimer = setInterval(function () {
    emitHeartbeat();
  }, Math.max(100, CONFIG.heartbeatMs));
}

function main() {
  let exeModule = null;
  let grimModule = null;
  try {
    exeModule = Process.getModuleByName(GAME_MODULE);
  } catch (_) {
    exeModule = null;
  }
  try {
    grimModule = Process.getModuleByName(GRIM_MODULE);
  } catch (_) {
    grimModule = null;
  }

  if (!exeModule) {
    writeLine({ event: "error", error: "missing_module", module: GAME_MODULE });
    return;
  }

  resolvePointers(exeModule, grimModule);
  updateCurrentStateFromMemory();
  if (CONFIG.enableCreatureLifecycleDigest) {
    outState.lastCreatureDigest = captureCreatureDigest();
  }

  const ptrs = {};
  for (const key in fnPtrs) ptrs[key] = !!fnPtrs[key];
  for (const key in grimFnPtrs) ptrs[key] = !!grimFnPtrs[key];
  for (const key in dataPtrs) ptrs["data_" + key] = !!dataPtrs[key];
  if (!validateStartupReadiness(ptrs)) {
    return;
  }
  outState.sessionFingerprint = makeSessionFingerprint(exeModule, ptrs);
  outState.sessionId = outState.sessionFingerprint.session_id;

  const captureConfig = {
    out_path: CONFIG.outPath,
    capture_profile: "exhaustive_default",
    config_env_overrides: collectConfigEnvOverrides(),
    log_mode: CONFIG.logMode,
    console_all_events: CONFIG.consoleAllEvents,
    console_events: Array.from(CONFIG.consoleEvents.values()),
    include_caller: CONFIG.includeCaller,
    include_backtrace: CONFIG.includeBacktrace,
    emit_ticks_outside_tracked_states: CONFIG.emitTicksOutsideTrackedStates,
    tracked_states: Array.from(CONFIG.trackedStates.values()),
    player_count_override: CONFIG.playerCountOverride,
    focus_tick: CONFIG.focusTick,
    focus_radius: CONFIG.focusRadius,
    heartbeat_ms: CONFIG.heartbeatMs,
    flush_capture_writes: CONFIG.flushCaptureWrites,
    max_head_per_kind: CONFIG.maxHeadPerKind,
    max_events_per_tick: CONFIG.maxEventsPerTick,
    max_rng_head_per_tick: CONFIG.maxRngHeadPerTick,
    max_rng_caller_kinds: CONFIG.maxRngCallerKinds,
    enable_rng_roll_log: CONFIG.enableRngRollLog,
    max_rng_roll_log_events: CONFIG.maxRngRollLogEvents,
    max_rng_outside_tick_head: CONFIG.maxRngOutsideTickHead,
    enable_rng_state_mirror: CONFIG.enableRngStateMirror,
    max_creature_delta_ids: CONFIG.maxCreatureDeltaIds,
    creature_sample_limit: CONFIG.creatureSampleLimit,
    projectile_sample_limit: CONFIG.projectileSampleLimit,
    secondary_projectile_sample_limit: CONFIG.secondaryProjectileSampleLimit,
    bonus_sample_limit: CONFIG.bonusSampleLimit,
    enable_input_hooks: CONFIG.enableInputHooks,
    enable_rng_hooks: CONFIG.enableRngHooks,
    enable_sfx_hooks: CONFIG.enableSfxHooks,
    enable_damage_hooks: CONFIG.enableDamageHooks,
    enable_effect_hooks: CONFIG.enableEffectHooks,
    creature_damage_projectile_only: CONFIG.creatureDamageProjectileOnly,
    enable_spawn_hooks: CONFIG.enableSpawnHooks,
    enable_creature_spawn_hook: CONFIG.enableCreatureSpawnHook,
    enable_creature_death_hook: CONFIG.enableCreatureDeathHook,
    enable_bonus_spawn_hook: CONFIG.enableBonusSpawnHook,
    enable_creature_lifecycle_digest: CONFIG.enableCreatureLifecycleDigest,
    enable_creature_micro_hooks: CONFIG.enableCreatureMicroHooks,
    creature_micro_slots: Array.from(CONFIG.creatureMicroSlots.values()),
    creature_micro_tick_start: CONFIG.creatureMicroTickStart,
    creature_micro_tick_end: CONFIG.creatureMicroTickEnd,
    creature_micro_max_head_per_tick: CONFIG.creatureMicroMaxHeadPerTick,
  };
  const captureMeta = {
    capture_format_version: CAPTURE_FORMAT_VERSION,
    script: "gameplay_diff_capture",
    session_id: outState.sessionId,
    out_path: CONFIG.outPath,
    config: captureConfig,
    session_fingerprint: outState.sessionFingerprint,
    process: {
      pid: Process.id,
      platform: Process.platform,
      arch: Process.arch,
      frida_version: Frida.version,
      runtime: Script.runtime,
    },
    exe: {
      base: exeModule.base.toString(),
      size: exeModule.size,
      path: exeModule.path,
    },
    grim: grimModule
      ? {
          base: grimModule.base.toString(),
          size: grimModule.size,
          path: grimModule.path,
        }
      : null,
    pointers_resolved: ptrs,
  };
  outState.captureMetaTemplate = captureMeta;
  if (!startCaptureFile(captureMeta, CONFIG.outPath)) {
    emitStartupContractError("capture_file_unavailable", {
      out_path: CONFIG.outPath,
    });
    return;
  }

  writeLine({
    event: "start",
    capture_format_version: CAPTURE_FORMAT_VERSION,
    session_id: outState.sessionId,
    out_path: outState.currentOutPath || CONFIG.outPath,
    capture_file_started: outState.captureStarted,
    config: captureConfig,
    session_fingerprint: outState.sessionFingerprint,
    process: captureMeta.process,
    exe: captureMeta.exe,
    grim: captureMeta.grim,
    pointers_resolved: ptrs,
  });

  globalThis.crimsonCaptureStop = function (reason) {
    shutdownCapture(reason || "manual_stop");
    return outState.captureTickCount | 0;
  };
  rpc.exports = {
    stop: function (reason) {
      return globalThis.crimsonCaptureStop(reason || "rpc_stop");
    },
    stats: function () {
      return {
        capture_started: !!outState.captureStarted,
        capture_closed: !!outState.captureClosed,
        run_active: !!outState.runActive,
        run_id: outState.currentRunId | 0,
        ticks_written: outState.captureTickCount | 0,
        out_path: outState.currentOutPath || CONFIG.outPath,
        last_hook: outState.lastHookActivity,
        last_exception: outState.lastException,
      };
    },
  };

  installShutdownHooks();
  installHooks();
  if (!validateInstalledRequiredHooks()) {
    return;
  }
  emitHeartbeat();
  startHeartbeat();

  Script.bindWeak(outState, function () {
    shutdownCapture("script_unload");
  });

  writeLine({
    event: "ready",
    capture_format_version: CAPTURE_FORMAT_VERSION,
    session_id: outState.sessionId,
    capture_file_started: outState.captureStarted,
  });
}

main();
