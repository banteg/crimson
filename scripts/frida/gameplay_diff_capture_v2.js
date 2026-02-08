"use strict";

// Differential capture v2:
// - per-gameplay tick records with stable checkpoint payloads
// - deterministic command/event summaries for first-divergence debugging
// - compact before/after snapshots and optional entity samples
//
// Attach only:
//   frida -n crimsonland.exe -l C:\share\frida\gameplay_diff_capture_v2.js
//
// Output:
//   C:\share\frida\gameplay_diff_capture_v2.jsonl (or CRIMSON_FRIDA_DIR override)

const DEFAULT_LOG_DIR = "C:\\share\\frida";
const DEFAULT_TRACKED_STATES = "6,7,8,9,10,12,14,18";
const LINK_BASE = ptr("0x00400000");
const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";

function getEnv(key) {
  try {
    return Process.env[key] || null;
  } catch (_) {
    return null;
  }
}

function parseIntEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const parsed = parseInt(String(raw).trim(), 0);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const text = String(raw).trim().toLowerCase();
  if (text === "1" || text === "true" || text === "yes" || text === "on") return true;
  if (text === "0" || text === "false" || text === "no" || text === "off") return false;
  return fallback;
}

function parseLimitEnv(key, fallback, minValue) {
  const raw = getEnv(key);
  const fallbackInt = Number.isFinite(fallback) ? fallback | 0 : -1;
  if (!raw) return fallbackInt;
  const parsed = parseInt(String(raw).trim(), 0);
  if (!Number.isFinite(parsed)) return fallbackInt;
  if (parsed < 0) return -1;
  const min = Number.isFinite(minValue) ? minValue | 0 : 0;
  return Math.max(min, parsed | 0);
}

function parseStateSet(raw, fallbackCsv) {
  const csv = raw && String(raw).trim() ? String(raw) : fallbackCsv;
  const out = new Set();
  const parts = String(csv)
    .split(/[;,]/)
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  for (let i = 0; i < parts.length; i++) {
    const v = parseInt(parts[i], 0);
    if (Number.isFinite(v)) out.add(v);
  }
  return out;
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
  outPath: joinPath(LOG_DIR, "gameplay_diff_capture_v2.jsonl"),
  logMode: getEnv("CRIMSON_FRIDA_APPEND") === "1" ? "append" : "truncate",
  includeCaller: parseBoolEnv("CRIMSON_FRIDA_INCLUDE_CALLER", true),
  includeBacktrace: parseBoolEnv("CRIMSON_FRIDA_INCLUDE_BT", false),
  includeTickSnapshots: parseBoolEnv("CRIMSON_FRIDA_V2_INCLUDE_TICK_SNAPSHOTS", true),
  includeRawEvents: parseBoolEnv("CRIMSON_FRIDA_V2_INCLUDE_RAW_EVENTS", false),
  emitTicksOutsideTrackedStates: parseBoolEnv("CRIMSON_FRIDA_V2_ALL_STATES", false),
  trackedStates: parseStateSet(getEnv("CRIMSON_FRIDA_V2_STATES"), DEFAULT_TRACKED_STATES),
  playerCountOverride: parseIntEnv("CRIMSON_FRIDA_PLAYER_COUNT", 0),
  focusTick: parseIntEnv("CRIMSON_FRIDA_V2_FOCUS_TICK", -1),
  focusRadius: Math.max(0, parseIntEnv("CRIMSON_FRIDA_V2_FOCUS_RADIUS", 0)),
  tickDetailsEvery: Math.max(1, parseIntEnv("CRIMSON_FRIDA_V2_TICK_DETAILS_EVERY", 60)),
  heartbeatMs: Math.max(100, parseIntEnv("CRIMSON_FRIDA_V2_HEARTBEAT_MS", 1000)),
  maxHeadPerKind: Math.max(4, parseIntEnv("CRIMSON_FRIDA_V2_MAX_HEAD", 16)),
  maxEventsPerTick: Math.max(32, parseIntEnv("CRIMSON_FRIDA_V2_MAX_EVENTS_PER_TICK", 512)),
  maxRngHeadPerTick: parseLimitEnv("CRIMSON_FRIDA_V2_RNG_HEAD", -1, 0),
  maxRngCallerKinds: parseLimitEnv("CRIMSON_FRIDA_V2_RNG_CALLERS", -1, 1),
  maxCreatureDeltaIds: Math.max(1, parseIntEnv("CRIMSON_FRIDA_V2_CREATURE_DELTA_IDS", 32)),
  creatureSampleLimit: parseIntEnv("CRIMSON_FRIDA_V2_CREATURE_SAMPLE_LIMIT", -1),
  projectileSampleLimit: parseIntEnv("CRIMSON_FRIDA_V2_PROJECTILE_SAMPLE_LIMIT", -1),
  secondaryProjectileSampleLimit: parseIntEnv("CRIMSON_FRIDA_V2_SECONDARY_PROJECTILE_SAMPLE_LIMIT", -1),
  bonusSampleLimit: parseIntEnv("CRIMSON_FRIDA_V2_BONUS_SAMPLE_LIMIT", -1),
  enableInputHooks: parseBoolEnv("CRIMSON_FRIDA_V2_INPUT_HOOKS", true),
  enableRngHooks: parseBoolEnv("CRIMSON_FRIDA_V2_RNG_HOOKS", true),
  enableSfxHooks: parseBoolEnv("CRIMSON_FRIDA_V2_SFX", true),
  enableDamageHooks: parseBoolEnv("CRIMSON_FRIDA_V2_DAMAGE", true),
  creatureDamageProjectileOnly: parseBoolEnv("CRIMSON_FRIDA_V2_DAMAGE_PROJECTILE_ONLY", true),
  enableSpawnHooks: parseBoolEnv("CRIMSON_FRIDA_V2_SPAWNS", true),
  enableCreatureSpawnHook: parseBoolEnv("CRIMSON_FRIDA_V2_CREATURE_SPAWN_HOOK", true),
  enableCreatureDeathHook: parseBoolEnv("CRIMSON_FRIDA_V2_CREATURE_DEATH_HOOK", true),
  enableBonusSpawnHook: parseBoolEnv("CRIMSON_FRIDA_V2_BONUS_SPAWN_HOOK", true),
  enableCreatureLifecycleDigest: parseBoolEnv("CRIMSON_FRIDA_V2_CREATURE_LIFECYCLE", true),
};

const FN = {
  player_update: 0x004136b0,
  gameplay_update_and_render: 0x0040aab0,
  quest_mode_update: 0x004070e0,
  rush_mode_update: 0x004072b0,
  survival_update: 0x00407cd0,
  survival_spawn_creature: 0x00407510,
  typo_gameplay_update_and_render: 0x004457c0,
  game_state_set: 0x004461c0,
  player_fire_weapon: 0x00444980,
  weapon_assign_player: 0x00452d40,
  bonus_apply: 0x00409890,
  bonus_try_spawn_on_kill: 0x0041f8d0,
  secondary_projectile_spawn: 0x00420360,
  projectile_spawn: 0x00420440,
  creature_apply_damage: 0x004207c0,
  player_take_damage: 0x00425e50,
  creature_spawn: 0x00428240,
  creature_handle_death: 0x0041e910,
  creature_spawn_template: 0x00430af0,
  creature_spawn_tinted: 0x00444810,
  perks_update_effects: 0x00406b40,
  quest_spawn_timeline_update: 0x00434250,
  input_any_key_pressed: 0x00446000,
  input_primary_just_pressed: 0x00446030,
  input_primary_is_down: 0x004460f0,
  crt_srand: 0x00461739,
  crt_rand: 0x00461746,
  sfx_play: 0x0043d120,
  sfx_play_panned: 0x0043d260,
  sfx_play_exclusive: 0x0043d460,
};

// Ghidra (latest sync): first function after `player_update`.
const PLAYER_UPDATE_END_RVA = 0x00417640;

const FN_GRIM_RVA = {
  grim_is_key_active: 0x00006fe0,
  grim_was_key_pressed: 0x00007390,
  grim_is_mouse_button_down: 0x00007410,
  grim_was_mouse_button_pressed: 0x00007440,
};

const DATA = {
  config_player_count: 0x0048035c,
  config_game_mode: 0x00480360,
  frame_dt: 0x00480840,
  frame_dt_ms: 0x00480844,
  perk_lean_mean_exp_tick_timer_s: 0x004808a4,

  input_primary_latch: 0x00478e50,
  console_open_flag: 0x0047eec8,
  perk_pending_count: 0x00486fac,
  creature_active_count: 0x00486fcc,
  quest_spawn_timeline: 0x00486fd0,
  bonus_reflex_boost_timer: 0x00487014,
  bonus_freeze_timer: 0x00487018,
  bonus_weapon_power_up_timer: 0x0048701c,
  bonus_energizer_timer: 0x00487020,
  bonus_double_xp_timer: 0x00487024,
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
const PROJECTILE_UPDATE_START = 0x00420b90;
const PROJECTILE_UPDATE_END = 0x00422c6f;

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
const srandContextByTid = {};
const outState = {
  outFile: null,
  outWarned: false,
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
  rngCallsTotal: 0,
  rngCallsOutsideTick: 0,
  rngHashState: fnvInit(),
  lastSeed: null,
  lastTickElapsedMs: null,
  lastTickGameplayFrame: null,
  lastCreatureDigest: null,
};

const UNKNOWN_DEATH = {
  creature_index: -1,
  type_id: -1,
  reward_value: 0,
  xp_awarded: -1,
  owner_id: -1,
};

function openOutFile() {
  if (outState.outFile) return;
  const mode = CONFIG.logMode === "append" ? "a" : "w";
  try {
    outState.outFile = new File(CONFIG.outPath, mode);
  } catch (_) {
    outState.outFile = null;
  }
}

function writeLine(obj) {
  if (!obj) return;
  if (obj.ts_ms == null) obj.ts_ms = nowMs();
  if (obj.ts_iso == null) obj.ts_iso = nowIso();

  const line = JSON.stringify(obj) + "\n";
  let wrote = false;
  try {
    openOutFile();
    if (outState.outFile) {
      outState.outFile.write(line);
      wrote = true;
    }
  } catch (_) {
    wrote = false;
  }

  if (!wrote && !outState.outWarned) {
    outState.outWarned = true;
    console.log("gameplay_diff_capture_v2: file logging unavailable, using console only");
  }
  console.log(line.trim());
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
  return safeReadF32(p);
}

function readDataF32Stride(name, index, strideBytes) {
  const p = dataPtrs[name];
  if (!p) return null;
  return safeReadF32(p.add(index * strideBytes));
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
      counts.push(value == null ? 0 : value >>> 0);
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
  return safeReadF32(p.add(playerIndex * STRIDES.player));
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

function round4(v) {
  if (v == null || !Number.isFinite(v)) return v == null ? null : 0;
  return Math.round(v * 10000) / 10000;
}

function normalizeSampleLimit(limit) {
  if (!Number.isFinite(limit)) return -1;
  if (limit < 0) return -1;
  return limit | 0;
}

function bonusTimerMs(v) {
  if (v == null || !Number.isFinite(v)) return -1;
  const ms = Math.round(v * 1000);
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
    return fnvMixString(h, "d:" + round4(value));
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

function currentTickIsFocused() {
  const tick = outState.currentTick;
  if (!tick) return !hasFocusWindow();
  return isFocusTick(tick.tick_index);
}

function shouldEmitRawEvent() {
  if (!CONFIG.includeRawEvents) return false;
  if (!hasFocusWindow()) return true;
  return currentTickIsFocused();
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
    game_state_prev: readDataI32("game_state_prev"),
    game_state_id: readDataI32("game_state_id"),
    game_state_pending: readDataI32("game_state_pending"),
    frame_dt: readDataF32("frame_dt"),
    frame_dt_ms_i32: readDataI32("frame_dt_ms"),
    frame_dt_ms_f32: readDataF32("frame_dt_ms"),
    time_played_ms: readDataI32("time_played_ms"),
    creature_active_count: readDataI32("creature_active_count"),
    perk_pending_count: readDataI32("perk_pending_count"),
    quest_spawn_timeline: readDataI32("quest_spawn_timeline"),
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
    pos_x: round4(readPlayerF32("player_pos_x", playerIndex)),
    pos_y: round4(readPlayerF32("player_pos_y", playerIndex)),
    move_dx: round4(readPlayerF32("player_move_dx", playerIndex)),
    move_dy: round4(readPlayerF32("player_move_dy", playerIndex)),
    health: round4(readPlayerF32("player_health", playerIndex)),
    aim_x: round4(readPlayerF32("player_aim_x", playerIndex)),
    aim_y: round4(readPlayerF32("player_aim_y", playerIndex)),
    aim_heading: round4(readPlayerF32("player_aim_heading", playerIndex)),
    weapon_id: readPlayerI32("player_weapon_id", playerIndex),
    clip_size_i32: clipU32 == null ? null : clipU32 | 0,
    clip_size_f32: clipU32 == null ? null : round4(u32ToF32(clipU32)),
    ammo_i32: ammoU32 == null ? null : ammoU32 | 0,
    ammo_f32: ammoU32 == null ? null : round4(u32ToF32(ammoU32)),
    reload_active_i32: reloadActiveU32 == null ? null : reloadActiveU32 | 0,
    reload_active_f32: reloadActiveU32 == null ? null : round4(u32ToF32(reloadActiveU32)),
    reload_timer: round4(readPlayerF32("player_reload_timer", playerIndex)),
    reload_timer_max: round4(readPlayerF32("player_reload_timer_max", playerIndex)),
    shot_cooldown: round4(readPlayerF32("player_shot_cooldown", playerIndex)),
    spread_heat: round4(readPlayerF32("player_spread_heat", playerIndex)),
    experience: readPlayerI32("player_experience", playerIndex),
    level: readPlayerI32("player_level", playerIndex),
    perk_timers: {
      hot_tempered: round4(readPlayerF32("player_hot_tempered_timer", playerIndex)),
      man_bomb: round4(readPlayerF32("player_man_bomb_timer", playerIndex)),
      living_fortress: round4(readPlayerF32("player_living_fortress_timer", playerIndex)),
      fire_cough: round4(readPlayerF32("player_fire_cough_timer", playerIndex)),
    },
    bonus_timers: {
      speed_bonus: round4(readPlayerF32("player_speed_bonus_timer", playerIndex)),
      shield: round4(readPlayerF32("player_shield_timer", playerIndex)),
      fire_bullets: round4(readPlayerF32("player_fire_bullets_timer", playerIndex)),
    },
    alt_weapon: {
      weapon_id: readPlayerI32("player_alt_weapon_id", playerIndex),
      clip_size_i32: readPlayerI32("player_alt_clip_size", playerIndex),
      reload_active_i32: readPlayerI32("player_alt_reload_active", playerIndex),
      ammo_i32: readPlayerI32("player_alt_ammo", playerIndex),
      reload_timer: round4(readPlayerF32("player_alt_reload_timer", playerIndex)),
      shot_cooldown: round4(readPlayerF32("player_alt_shot_cooldown", playerIndex)),
      reload_timer_max: round4(readPlayerF32("player_alt_reload_timer_max", playerIndex)),
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
      x: round4(readDataF32Stride("player_aim_screen_x", i, 8)),
      y: round4(readDataF32Stride("player_aim_screen_y", i, 8)),
    });
  }
  return {
    console_open: readDataU32("console_open_flag"),
    primary_latch: readDataU32("input_primary_latch"),
    mouse_x: round4(readDataF32("ui_mouse_x")),
    mouse_y: round4(readDataF32("ui_mouse_y")),
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
    angle: round4(safeReadF32(base.add(0x04))),
    pos: {
      x: round4(safeReadF32(base.add(0x08))),
      y: round4(safeReadF32(base.add(0x0c))),
    },
    vel: {
      x: round4(safeReadF32(base.add(0x18))),
      y: round4(safeReadF32(base.add(0x1c))),
    },
    type_id: safeReadS32(base.add(0x20)),
    life_timer: round4(safeReadF32(base.add(0x24))),
    speed_scale: round4(safeReadF32(base.add(0x2c))),
    damage_pool: round4(safeReadF32(base.add(0x30))),
    hit_radius: round4(safeReadF32(base.add(0x34))),
    base_damage: round4(safeReadF32(base.add(0x38))),
    owner_id: safeReadS32(base.add(0x3c)),
  };
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
      x: round4(safeReadF32(base.add(0x04))),
      y: round4(safeReadF32(base.add(0x08))),
    },
    life_timer: round4(safeReadF32(base.add(0x0c))),
    angle: round4(safeReadF32(base.add(0x10))),
    vel: {
      x: round4(safeReadF32(base.add(0x14))),
      y: round4(safeReadF32(base.add(0x18))),
    },
    trail_timer: round4(safeReadF32(base.add(0x1c))),
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
  return {
    index: index,
    active: activeFlag,
    state_flag: stateFlag,
    collision_flag: safeReadU8(base.add(0x09)),
    hitbox_size: round4(safeReadF32(base.add(0x10))),
    pos: {
      x: round4(safeReadF32(base.add(0x14))),
      y: round4(safeReadF32(base.add(0x18))),
    },
    hp: round4(safeReadF32(base.add(0x24))),
    type_id: safeReadS32(base.add(0x6c)),
    target_player: safeReadS32(base.add(0x70)),
    flags: safeReadS32(base.add(0x8c)),
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
  return {
    index: index,
    active: active,
    active_flag: activeFlag == null ? null : activeFlag,
    state_flag: stateFlag == null ? null : stateFlag,
    type_id: safeReadS32(base.add(0x6c)),
    hp: round4(safeReadF32(base.add(0x24))),
    hitbox_size: round4(safeReadF32(base.add(0x10))),
    pos: {
      x: round4(safeReadF32(base.add(0x14))),
      y: round4(safeReadF32(base.add(0x18))),
    },
    flags: safeReadS32(base.add(0x8c)),
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
    time_left: round4(safeReadF32(base.add(0x08))),
    time_max: round4(safeReadF32(base.add(0x0c))),
    pos: {
      x: round4(safeReadF32(base.add(0x10))),
      y: round4(safeReadF32(base.add(0x14))),
    },
    amount_f32: round4(safeReadF32(base.add(0x18))),
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
    move_forward_pressed: null,
    move_backward_pressed: null,
    turn_left_pressed: null,
    turn_right_pressed: null,
    fire_down: null,
    fire_pressed: null,
    reload_pressed: null,
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

function updatePlayerInputKeyState(tick, queryName, keyCode, pressed, callerStaticHex) {
  if (!tick || !isPlayerUpdateCaller(callerStaticHex)) return;
  if (!Number.isFinite(keyCode)) return;
  const bindings = tick.before && tick.before.input_bindings && tick.before.input_bindings.players;
  if (!Array.isArray(bindings) || bindings.length === 0) return;

  const key = keyCode | 0;
  const down = !!pressed;
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
      if (queryName === "grim_is_key_active") state.fire_down = down;
      if (queryName === "grim_was_key_pressed") state.fire_pressed = down;
    }
    if ((binding.reload | 0) === key && queryName === "grim_was_key_pressed") {
      state.reload_pressed = down;
    }
  }
}

function makeTickContext() {
  const before = makeCoreSnapshot();
  const creatureDigestBefore = CONFIG.enableCreatureLifecycleDigest ? captureCreatureDigest() : null;
  const tickIndex = Math.max(0, outState.gameplayFrame - 1);
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
      secondary_projectile_spawn: 0,
      player_damage: 0,
      creature_damage: 0,
      creature_spawn: 0,
      creature_spawn_low: 0,
      creature_death: 0,
      creature_lifecycle: 0,
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
      secondary_projectile_spawn: [],
      player_damage: [],
      creature_damage: [],
      creature_spawn: [],
      creature_spawn_low: [],
      creature_death: [],
      creature_lifecycle: [],
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
    },
    phase_markers: [
      {
        kind: "state_enter",
        state_id: outState.currentStateId,
        state_pending: outState.currentStatePending,
      },
    ],
    sfx_ids: [],
    fire_by_player: {},
    spawn_callers_template: {},
    spawn_callers_low: {},
    spawn_sources_low: {},
    creature_damage_callers: {},
    death_callers: {},
    bonus_spawn_callers: {},
    mode_samples: [],
    creature_digest_before: creatureDigestBefore,
    mode_hint: null,
    overflow: false,
  };
}

function pushHead(head, item) {
  if (!head || head.length >= CONFIG.maxHeadPerKind) return;
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
        kind: kind,
        payload: payload,
      });
    }
    return;
  }
  tick.event_counts[kind] = (tick.event_counts[kind] || 0) + 1;
  if (tick.event_total >= CONFIG.maxEventsPerTick) {
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

function addPhaseMarker(kind, payload) {
  const tick = outState.currentTick;
  if (!tick) return;
  pushHead(tick.phase_markers, Object.assign({ kind: kind }, payload || {}));
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

function isPrimaryFireKeyCode(keyCode) {
  if (!Number.isFinite(keyCode)) return false;
  resolvePlayerCount();
  const playerCount = Math.max(1, outState.playerCountResolved | 0);
  for (let i = 0; i < playerCount; i++) {
    const fireKey = readPlayerI32("player_fire_key", i);
    if (fireKey != null && fireKey === keyCode) return true;
  }
  return false;
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

function registerRngRoll(value, callerStaticHex, callerLabel) {
  outState.rngCallsTotal += 1;
  outState.rngHashState = fnvMixString(outState.rngHashState, String(value));
  outState.rngHashState = fnvMixByte(outState.rngHashState, 0x0a);

  const tick = outState.currentTick;
  if (!tick) {
    outState.rngCallsOutsideTick += 1;
    return;
  }
  tick.rng.calls += 1;
  tick.rng.last_value = value;
  tick.rng.hash_state = fnvMixString(tick.rng.hash_state, String(value) + "@" + String(callerStaticHex || "na"));
  tick.rng.hash_state = fnvMixByte(tick.rng.hash_state, 0x0a);

  if (CONFIG.maxRngHeadPerTick < 0 || tick.rng.head.length < CONFIG.maxRngHeadPerTick) {
    tick.rng.head.push({
      value: value,
      caller_static: callerStaticHex,
      caller: callerLabel,
    });
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
}

function checkpointPlayersFromCompact(players) {
  const out = [];
  for (let i = 0; i < players.length; i++) {
    const p = players[i];
    out.push({
      pos: { x: p.pos_x == null ? 0 : p.pos_x, y: p.pos_y == null ? 0 : p.pos_y },
      health: p.health == null ? 0 : p.health,
      weapon_id: p.weapon_id == null ? 0 : p.weapon_id,
      ammo: p.ammo_f32 == null ? 0 : p.ammo_f32,
      experience: p.experience == null ? 0 : p.experience,
      level: p.level == null ? 0 : p.level,
    });
  }
  return out;
}

function buildInputApprox(afterPlayers, tick) {
  const out = [];
  for (let i = 0; i < afterPlayers.length; i++) {
    const p = afterPlayers[i];
    const fired = tick.fire_by_player[i] || 0;
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
      fired_events: fired,
      moving: !!moving,
      reload_active: p.reload_active_i32 != null ? p.reload_active_i32 !== 0 : null,
      weapon_id: p.weapon_id,
    });
  }
  return out;
}

function maybeDetailedSamples(tickIndex) {
  if (CONFIG.tickDetailsEvery <= 1) return true;
  return (tickIndex % CONFIG.tickDetailsEvery) === 0;
}

function finalizeTick() {
  const tick = outState.currentTick;
  if (!tick) return;
  updateCurrentStateFromMemory();
  const after = makeCoreSnapshot();
  const beforeGlobals = tick.before && tick.before.globals ? tick.before.globals : {};
  const beforeStatus = tick.before && tick.before.status ? tick.before.status : {};
  const beforePlayers = tick.before && tick.before.players ? tick.before.players : [];
  const focused = tick.focus_tick || isFocusTick(tick.tick_index);
  const tsLeave = nowMs();
  const afterPlayers = after.players;
  const globals = after.globals;
  const status = after.status || {};
  let scoreXp = 0;
  for (let i = 0; i < afterPlayers.length; i++) {
    scoreXp += afterPlayers[i].experience == null ? 0 : afterPlayers[i].experience;
  }

  if (tick.state_id_enter !== outState.currentStateId) {
    addPhaseMarker("state_leave", {
      from: tick.state_id_enter,
      to: outState.currentStateId,
      pending_to: outState.currentStatePending,
    });
  }
  if (tick.mode_hint) {
    addPhaseMarker("mode_hint", { mode_fn: tick.mode_hint });
  }
  if ((tick.input_queries.primary_edge.true_calls || 0) > 0) {
    addPhaseMarker("input_primary_edge", { true_calls: tick.input_queries.primary_edge.true_calls });
  }
  if (tick.rng.calls > 0) {
    addPhaseMarker("rng_activity", { calls: tick.rng.calls });
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
  const spawnHookEventCount =
    (tick.event_counts.creature_spawn || 0) + (tick.event_counts.creature_spawn_low || 0);
  const deathHookEventCount = tick.event_counts.creature_death || 0;
  if (creatureCountDeltaInTick != null && creatureCountDeltaInTick > 0 && spawnHookEventCount <= 0) {
    addPhaseMarker("creature_count_increase_without_spawn_hook", {
      before: beforeCreatureCount,
      after: afterCreatureCount,
      delta: creatureCountDeltaInTick,
    });
  }
  if (creatureCountDeltaInTick != null && creatureCountDeltaInTick < 0 && deathHookEventCount <= 0) {
    addPhaseMarker("creature_count_drop_without_death_hook", {
      before: beforeCreatureCount,
      after: afterCreatureCount,
      delta: creatureCountDeltaInTick,
    });
  }

  let creatureLifecycle = null;
  if (CONFIG.enableCreatureLifecycleDigest) {
    const beforeDigest = tick.creature_digest_before || outState.lastCreatureDigest || captureCreatureDigest();
    const afterDigest = captureCreatureDigest();
    creatureLifecycle = diffCreatureDigest(beforeDigest, afterDigest);
    outState.lastCreatureDigest = afterDigest;
    if (creatureLifecycle) {
      const lifecycleDelta =
        (creatureLifecycle.added_total || 0) - (creatureLifecycle.removed_total || 0);
      if (lifecycleDelta !== 0 && creatureCountDeltaInTick != null && lifecycleDelta !== creatureCountDeltaInTick) {
        addPhaseMarker("creature_lifecycle_delta_mismatch", {
          count_delta: creatureCountDeltaInTick,
          lifecycle_delta: lifecycleDelta,
        });
      }
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
    "4": bonusTimerMs(globals.bonus_weapon_power_up_timer),
    "9": bonusTimerMs(globals.bonus_reflex_boost_timer),
    "2": bonusTimerMs(globals.bonus_energizer_timer),
    "6": bonusTimerMs(globals.bonus_double_xp_timer),
    "11": bonusTimerMs(globals.bonus_freeze_timer),
  };

  const stateHashSeed = {
    globals: {
      time_played_ms: globals.time_played_ms,
      creature_active_count: globals.creature_active_count,
      perk_pending_count: globals.perk_pending_count,
      quest_spawn_timeline: globals.quest_spawn_timeline,
      perk_doctor_target_creature_id: globals.perk_doctor_target_creature_id,
    },
    players: checkpointPlayersFromCompact(afterPlayers),
    bonus_timers: bonusTimers,
  };

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
    hit_count: -1,
    pickup_count: -1,
    sfx_count: tick.event_counts.sfx || 0,
    sfx_head: tick.sfx_ids.slice(0, 4),
    rng_call_count: tick.rng.calls,
    input_true_count: inputTrueCount,
  };

  const timing = {
    gameplay_frame: tick.gameplay_frame,
    gameplay_frame_delta_prev_tick: gameplayFrameDeltaFromPrevTick,
    elapsed_ms_before: beforeElapsedMs,
    elapsed_ms_after: afterElapsedMs,
    elapsed_delta_in_tick_ms: elapsedDeltaInTick,
    elapsed_delta_prev_tick_ms: elapsedDeltaFromPrevTick,
    frame_dt_before: beforeGlobals.frame_dt == null ? null : round4(beforeGlobals.frame_dt),
    frame_dt_after: globals.frame_dt == null ? null : round4(globals.frame_dt),
    frame_dt_ms_before_i32: beforeGlobals.frame_dt_ms_i32 == null ? null : beforeGlobals.frame_dt_ms_i32,
    frame_dt_ms_after_i32: globals.frame_dt_ms_i32 == null ? null : globals.frame_dt_ms_i32,
    frame_dt_ms_before_f32: beforeGlobals.frame_dt_ms_f32 == null ? null : round4(beforeGlobals.frame_dt_ms_f32),
    frame_dt_ms_after_f32: globals.frame_dt_ms_f32 == null ? null : round4(globals.frame_dt_ms_f32),
  };
  const spawnDiagnostics = {
    before_creature_count: beforeCreatureCount,
    after_creature_count: afterCreatureCount,
    creature_count_delta: creatureCountDeltaInTick,
    event_count_template: tick.event_counts.creature_spawn || 0,
    event_count_low_level: tick.event_counts.creature_spawn_low || 0,
    event_count_creature_damage: tick.event_counts.creature_damage || 0,
    event_count_death: deathHookEventCount,
    top_template_callers: topCounterPairs(tick.spawn_callers_template, 8),
    top_low_level_callers: topCounterPairs(tick.spawn_callers_low, 8),
    top_low_level_sources: topCounterPairs(tick.spawn_sources_low, 8),
    top_creature_damage_callers: topCounterPairs(tick.creature_damage_callers, 8),
    top_death_callers: topCounterPairs(tick.death_callers, 8),
    event_count_bonus_spawn: tick.event_counts.bonus_spawn || 0,
    top_bonus_spawn_callers: topCounterPairs(tick.bonus_spawn_callers, 8),
    mode_samples: tick.mode_samples,
  };
  const creatureLifecycleDiagnostics = creatureLifecycle || null;

  const checkpoint = {
    tick_index: tick.tick_index,
    state_hash: String(hashHex(stateHashSeed)),
    command_hash: String(toHex(tick.command_hash_state >>> 0, 8)),
    rng_state: tick.rng.last_value == null ? -1 : tick.rng.last_value,
    elapsed_ms: globals.time_played_ms == null ? -1 : globals.time_played_ms,
    score_xp: scoreXp,
    kills: -1,
    creature_count: globals.creature_active_count == null ? -1 : globals.creature_active_count,
    perk_pending: globals.perk_pending_count == null ? -1 : globals.perk_pending_count,
    players: checkpointPlayersFromCompact(afterPlayers),
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
    rng_marks: {
      rand_calls: tick.rng.calls,
      rand_hash: toHex(tick.rng.hash_state >>> 0, 8),
      rand_last: tick.rng.last_value,
      rand_head: tick.rng.head,
      rand_callers: rngCallers,
      rand_caller_overflow: tick.rng.caller_overflow,
    },
    deaths: [UNKNOWN_DEATH],
    perk: {
      pending_count: -1,
      choices_dirty: false,
      choices: [],
      player_nonzero_counts: [],
    },
    events: eventSummary,
    debug: {
      sampling_phase: "post_gameplay_update_and_render",
      timing: timing,
      spawn: spawnDiagnostics,
      creature_lifecycle: creatureLifecycleDiagnostics,
      before_players: checkpointPlayersFromCompact(beforePlayers),
      before_status: {
        quest_unlock_index:
          beforeStatus.quest_unlock_index == null ? -1 : beforeStatus.quest_unlock_index,
        quest_unlock_index_full:
          beforeStatus.quest_unlock_index_full == null ? -1 : beforeStatus.quest_unlock_index_full,
      },
    },
  };

  const out = {
    event: "tick",
    script: "gameplay_diff_capture_v2",
    session_id: outState.sessionId,
    tick_index: tick.tick_index,
    gameplay_frame: tick.gameplay_frame,
    focus_tick: focused,
    state_id_enter: tick.state_id_enter,
    state_id_leave: outState.currentStateId,
    state_pending_enter: tick.state_pending_enter,
    state_pending_leave: outState.currentStatePending,
    mode_hint: tick.mode_hint,
    ts_enter_ms: tick.ts_enter_ms,
    ts_leave_ms: tsLeave,
    duration_ms: tsLeave - tick.ts_enter_ms,
    checkpoint: checkpoint,
    event_counts: tick.event_counts,
    event_overflow: tick.overflow,
    event_heads: tick.event_heads,
    phase_markers: tick.phase_markers,
    input_queries: {
      stats: tick.input_queries,
      query_hash: toHex(tick.input_hash_state >>> 0, 8),
    },
    input_player_keys: tick.input_player_keys,
    rng: {
      calls: tick.rng.calls,
      last_value: tick.rng.last_value,
      hash: toHex(tick.rng.hash_state >>> 0, 8),
      head: tick.rng.head,
      callers: rngCallers,
      caller_overflow: tick.rng.caller_overflow,
    },
    diagnostics: {
      sampling_phase: "post_gameplay_update_and_render",
      timing: timing,
      spawn: spawnDiagnostics,
      creature_lifecycle: creatureLifecycleDiagnostics,
    },
    input_approx: buildInputApprox(afterPlayers, tick),
  };
  if (creatureLifecycleDiagnostics) {
    out.creature_lifecycle = creatureLifecycleDiagnostics;
  }

  if (CONFIG.includeTickSnapshots && focused) {
    out.before = tick.before;
    out.after = after;
  }

  if (focused && maybeDetailedSamples(tick.tick_index)) {
    out.samples = {
      creatures: readActiveCreatureSample(CONFIG.creatureSampleLimit),
      projectiles: readActiveProjectileSample(CONFIG.projectileSampleLimit),
      secondary_projectiles: readActiveSecondaryProjectileSample(CONFIG.secondaryProjectileSampleLimit),
      bonuses: readActiveBonusSample(CONFIG.bonusSampleLimit),
    };
  }

  writeLine(out);
  if (afterElapsedMs != null) outState.lastTickElapsedMs = afterElapsedMs;
  outState.lastTickGameplayFrame = tick.gameplay_frame;
  outState.currentTick = null;
}

function attachHook(name, ptrVal, handlers) {
  if (!ptrVal) {
    writeLine({ event: "hook_skip", name: name, reason: "missing_pointer" });
    return;
  }
  try {
    Interceptor.attach(ptrVal, handlers);
    writeLine({ event: "hook_ok", name: name, addr: ptrVal.toString() });
  } catch (e) {
    writeLine({ event: "hook_error", name: name, addr: ptrVal.toString(), error: String(e) });
  }
}

function installHooks() {
  attachHook("gameplay_update_and_render", fnPtrs.gameplay_update_and_render, {
    onEnter() {
      outState.gameplayFrame += 1;
      updateCurrentStateFromMemory();
      if (!shouldCaptureTickForState(outState.currentStateId)) {
        outState.currentTick = null;
        return;
      }
      outState.currentTick = makeTickContext();
    },
    onLeave() {
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
      addPhaseMarker("state_set_call", { target_state: payload.target_state });
      emitRawEvent(Object.assign({ event: "game_state_set" }, payload));
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
        if (!tick.mode_hint) addPhaseMarker("mode_enter", { mode_fn: name });
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
        if (tick.mode_samples.length < CONFIG.maxHeadPerKind) {
          tick.mode_samples.push(sample);
        }
      },
    });
  }
  hookModeTick("quest_mode_update");
  hookModeTick("rush_mode_update");
  hookModeTick("survival_update");
  hookModeTick("typo_gameplay_update_and_render");

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
          updatePlayerInputKeyState(outState.currentTick, name, ctx.arg0, pressed, ctx.caller_static);
          const token = tokenPrefix + ":" + String(ctx.arg0 == null ? "na" : ctx.arg0);
          registerInputQuery(queryKey, pressed, token, payload);
          emitRawEvent(Object.assign({ event: name }, payload));
        },
      });
    }

    addGrimInputQueryHook(
      "grim_is_key_active",
      grimFnPtrs.grim_is_key_active,
      function (keyCode) {
        if (keyCode === 0x100) return "primary_down";
        if (isPrimaryFireKeyCode(keyCode)) return "primary_down";
        if (Number.isFinite(keyCode)) return "any_key";
        return null;
      },
      "gika"
    );
    addGrimInputQueryHook(
      "grim_was_key_pressed",
      grimFnPtrs.grim_was_key_pressed,
      function (keyCode) {
        if (isPrimaryFireKeyCode(keyCode)) return "primary_edge";
        if (Number.isFinite(keyCode)) return "any_key";
        return null;
      },
      "gwkp"
    );
    addGrimInputQueryHook(
      "grim_is_mouse_button_down",
      grimFnPtrs.grim_is_mouse_button_down,
      function (button) {
        if (button === 0) return "primary_down";
        if (Number.isFinite(button)) return "any_key";
        return null;
      },
      "gmbd"
    );
    addGrimInputQueryHook(
      "grim_was_mouse_button_pressed",
      grimFnPtrs.grim_was_mouse_button_pressed,
      function (button) {
        if (button === 0) return "primary_edge";
        if (Number.isFinite(button)) return "any_key";
        return null;
      },
      "gmwp"
    );
  }

  if (CONFIG.enableRngHooks) {
    attachHook("crt_srand", fnPtrs.crt_srand, {
      onEnter(args) {
        srandContextByTid[this.threadId] = {
          seed_u32: args[0] ? args[0].toUInt32() >>> 0 : null,
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        };
      },
      onLeave() {
        const ctx = srandContextByTid[this.threadId];
        delete srandContextByTid[this.threadId];
        if (!ctx) return;
        outState.lastSeed = ctx.seed_u32;
        emitRawEvent({
          event: "crt_srand",
          seed_u32: ctx.seed_u32,
          seed_hex: ctx.seed_u32 == null ? null : toHex(ctx.seed_u32, 8),
          caller: ctx.caller,
        });
      },
    });

    attachHook("crt_rand", fnPtrs.crt_rand, {
      onEnter() {
        const callerStatic = runtimeToStatic(this.returnAddress);
        rngContextByTid[this.threadId] = {
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
          caller_static: callerStatic == null ? null : toHex(callerStatic, 8),
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
        registerRngRoll(value, ctx ? ctx.caller_static : null, ctx ? ctx.caller : null);
        const tick = outState.currentTick;
        emitRawEvent({
          event: "crt_rand",
          value_i32: value,
          caller: ctx ? ctx.caller : null,
          caller_static: ctx ? ctx.caller_static : null,
          tick_index: tick ? tick.tick_index : null,
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
        amount_f32: entry ? safeReadF32(entry.add(0x18)) : null,
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
            x: round4(posPtr ? safeReadF32(posPtr) : null),
            y: round4(posPtr ? safeReadF32(posPtr.add(4)) : null),
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
          x: round4(safeReadF32(args[0])),
          y: round4(safeReadF32(args[0].add(4))),
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
        angle_f32: round4(ctx.angle_f32),
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
      this._ctx = {
        pos: {
          x: round4(safeReadF32(args[0])),
          y: round4(safeReadF32(args[0].add(4))),
        },
        angle_f32: argAsF32(args[1]),
        requested_type_id: args[2].toInt32(),
        owner_id: args[3].toInt32(),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
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
        angle_f32: round4(ctx.angle_f32),
        pos: ctx.pos,
        type_overridden: actualType == null ? null : actualType !== ctx.requested_type_id,
        caller: ctx.caller,
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
      emitRawEvent(Object.assign({ event: "projectile_spawn" }, payload));
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
          damage_f32: round4(argAsF32(args[1])),
          damage_type: args[2] ? args[2].toInt32() : null,
          impulse_x: round4(impulsePtr ? safeReadF32(impulsePtr) : null),
          impulse_y: round4(impulsePtr ? safeReadF32(impulsePtr.add(4)) : null),
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
              ? round4(after.hp - ctx.before.hp)
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
          damage_f32: round4(argAsF32(args[1])),
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
              ? round4(after.health - ctx.health_before)
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
            x: round4(safeReadF32(args[1])),
            y: round4(safeReadF32(args[1].add(4))),
          },
          heading: round4(argAsF32(args[2])),
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
            x: round4(safeReadF32(args[0])),
            y: round4(safeReadF32(args[0].add(4))),
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
            x: round4(safeReadF32(posPtr)),
            y: round4(safeReadF32(posPtr.add(4))),
          },
          tint: {
            r: round4(safeReadF32(rgbaPtr)),
            g: round4(safeReadF32(rgbaPtr.add(4))),
            b: round4(safeReadF32(rgbaPtr.add(8))),
            a: round4(safeReadF32(rgbaPtr.add(12))),
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
              x: round4(safeReadF32(posPtr)),
              y: round4(safeReadF32(posPtr.add(4))),
            },
            tint: {
              r: round4(safeReadF32(rgbaPtr)),
              g: round4(safeReadF32(rgbaPtr.add(4))),
              b: round4(safeReadF32(rgbaPtr.add(8))),
              a: round4(safeReadF32(rgbaPtr.add(12))),
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
        perk_jinxed_proc_timer_s: round4(readDataF32("perk_jinxed_proc_timer_s")),
        perk_lean_mean_exp_tick_timer_s: round4(readDataF32("perk_lean_mean_exp_tick_timer_s")),
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
    rng_calls_outside_tick: outState.rngCallsOutsideTick,
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
  outState.sessionFingerprint = makeSessionFingerprint(exeModule, ptrs);
  outState.sessionId = outState.sessionFingerprint.session_id;

  writeLine({
    event: "start",
    script: "gameplay_diff_capture_v2",
    session_id: outState.sessionId,
    out_path: CONFIG.outPath,
    config: {
      log_mode: CONFIG.logMode,
      include_caller: CONFIG.includeCaller,
      include_backtrace: CONFIG.includeBacktrace,
      include_tick_snapshots: CONFIG.includeTickSnapshots,
      include_raw_events: CONFIG.includeRawEvents,
      emit_ticks_outside_tracked_states: CONFIG.emitTicksOutsideTrackedStates,
      tracked_states: Array.from(CONFIG.trackedStates.values()),
      player_count_override: CONFIG.playerCountOverride,
      focus_tick: CONFIG.focusTick,
      focus_radius: CONFIG.focusRadius,
      tick_details_every: CONFIG.tickDetailsEvery,
      heartbeat_ms: CONFIG.heartbeatMs,
      max_head_per_kind: CONFIG.maxHeadPerKind,
      max_events_per_tick: CONFIG.maxEventsPerTick,
      max_rng_head_per_tick: CONFIG.maxRngHeadPerTick,
      max_rng_caller_kinds: CONFIG.maxRngCallerKinds,
      max_creature_delta_ids: CONFIG.maxCreatureDeltaIds,
      creature_sample_limit: CONFIG.creatureSampleLimit,
      projectile_sample_limit: CONFIG.projectileSampleLimit,
      secondary_projectile_sample_limit: CONFIG.secondaryProjectileSampleLimit,
      bonus_sample_limit: CONFIG.bonusSampleLimit,
      enable_input_hooks: CONFIG.enableInputHooks,
      enable_rng_hooks: CONFIG.enableRngHooks,
      enable_sfx_hooks: CONFIG.enableSfxHooks,
      enable_damage_hooks: CONFIG.enableDamageHooks,
      creature_damage_projectile_only: CONFIG.creatureDamageProjectileOnly,
      enable_spawn_hooks: CONFIG.enableSpawnHooks,
      enable_creature_spawn_hook: CONFIG.enableCreatureSpawnHook,
      enable_creature_death_hook: CONFIG.enableCreatureDeathHook,
      enable_bonus_spawn_hook: CONFIG.enableBonusSpawnHook,
      enable_creature_lifecycle_digest: CONFIG.enableCreatureLifecycleDigest,
    },
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
  });

  installHooks();
  emitHeartbeat();
  startHeartbeat();

  writeLine({ event: "ready", session_id: outState.sessionId });
}

main();
