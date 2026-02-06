"use strict";

// Comprehensive gameplay/runtime capture for decompile mapping.
// Attach only:
//   frida -n crimsonland.exe -l C:\\share\\frida\\gameplay_state_capture.js
// Output:
//   C:\\share\\frida\\gameplay_state_capture.jsonl (or CRIMSON_FRIDA_DIR override)
//
// This script is intentionally automatic:
// - no REPL helpers are required
// - key hooks + periodic snapshots run immediately
// - write tracing (MemoryAccessMonitor) is armed automatically when available

const DEFAULT_LOG_DIR = "C:\\share\\frida";

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

function toHex(value, width) {
  if (value == null) return null;
  let hex = (value >>> 0).toString(16);
  while (hex.length < width) hex = "0" + hex;
  return "0x" + hex;
}

function copyObject(src) {
  if (!src || typeof src !== "object") return src;
  return JSON.parse(JSON.stringify(src));
}

function shallowEqual(a, b) {
  if (a === b) return true;
  if (!a || !b) return false;
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  for (let i = 0; i < aKeys.length; i++) {
    const k = aKeys[i];
    if (a[k] !== b[k]) return false;
  }
  return true;
}

const LOG_DIR = getEnv("CRIMSON_FRIDA_DIR") || DEFAULT_LOG_DIR;

const CONFIG = {
  outPath: joinPath(LOG_DIR, "gameplay_state_capture.jsonl"),
  logMode: getEnv("CRIMSON_FRIDA_APPEND") === "1" ? "append" : "truncate",
  includeCaller: getEnv("CRIMSON_FRIDA_INCLUDE_CALLER") !== "0",
  includeBacktrace: getEnv("CRIMSON_FRIDA_INCLUDE_BT") === "1",
  snapshotIntervalMs: parseIntEnv("CRIMSON_FRIDA_SNAPSHOT_MS", 500),
  fullSnapshotIntervalMs: parseIntEnv("CRIMSON_FRIDA_FULL_SNAPSHOT_MS", 2000),
  uiDeltaEveryFrames: Math.max(1, parseIntEnv("CRIMSON_FRIDA_UI_DELTA_EVERY", 1)),
  maxUiDeltaChanges: Math.max(8, parseIntEnv("CRIMSON_FRIDA_UI_DELTA_MAX", 96)),
  uiRenderStates: new Set([0, 2, 4, 6, 9]),
  playerCount: Math.max(1, Math.min(4, parseIntEnv("CRIMSON_FRIDA_PLAYER_COUNT", 1))),
  enableSfxHooks: getEnv("CRIMSON_FRIDA_SFX") !== "0",
  enableMemWatch: getEnv("CRIMSON_FRIDA_MEMWATCH") !== "0",
  memWatchWritesOnly: getEnv("CRIMSON_FRIDA_MEMWATCH_READS") !== "1",
  maxMemEventsPerSec: Math.max(100, parseIntEnv("CRIMSON_FRIDA_MEMWATCH_RATE", 2000)),
  modeTickMs: Math.max(100, parseIntEnv("CRIMSON_FRIDA_MODE_TICK_MS", 300)),
};

const GAME_MODULE = "crimsonland.exe";
const LINK_BASE = ptr("0x00400000");

const STRIDES = {
  player: 0x360,
  projectile: 0x40,
  weapon: 0x7c,
  uiBlock: 0xe8,
  uiSlot: 0x1c,
};

const FN = {
  demo_trial_overlay_render: 0x004047c0,
  ui_render_keybind_help: 0x00405160,
  perks_update_effects: 0x00406b40,
  quest_mode_update: 0x004070e0,
  rush_mode_update: 0x004072b0,
  survival_update: 0x00407cd0,
  bonus_apply: 0x00409890,
  gameplay_update_and_render: 0x0040aab0,
  quest_failed_screen_update: 0x004107e0,
  quest_results_screen_update: 0x00410d20,
  player_update: 0x004136b0,
  ui_menu_assets_init: 0x00419dd0,
  ui_elements_update_and_render: 0x0041a530,
  bonus_hud_slot_activate: 0x0041a810,
  bonus_hud_slot_update_and_render: 0x0041a8b0,
  ui_render_hud: 0x0041aed0,
  hud_update_and_render: 0x0041ca90,
  projectile_spawn: 0x00420440,
  projectile_update: 0x00420b90,
  player_take_damage: 0x00425e50,
  creature_update_all: 0x00426220,
  creature_spawn_template: 0x00430af0,
  quest_spawn_timeline_update: 0x00434250,
  quest_start_selected: 0x0043a790,
  sfx_play: 0x0043d120,
  sfx_play_panned: 0x0043d260,
  sfx_play_exclusive: 0x0043d460,
  ui_menu_item_update: 0x0043e5e0,
  ui_button_update: 0x0043e830,
  player_fire_weapon: 0x00444980,
  typo_gameplay_update_and_render: 0x004457c0,
  game_state_set: 0x004461c0,
  ui_element_render: 0x00446c40,
  ui_menu_layout_init: 0x0044fcb0,
  weapon_assign_player: 0x00452d40,
};

const DATA = {
  config_game_mode: 0x00480360,
  frame_dt: 0x00480840,
  frame_dt_ms: 0x00480844,
  demo_trial_overlay_active: 0x00480850,
  demo_trial_overlay_alpha_ms: 0x00480898,
  perk_lean_mean_exp_tick_timer_s: 0x004808a4,

  ui_subtemplate_start: 0x0048fd78,
  ui_subtemplate_end_excl: 0x00490300,

  quest_results_health_bonus_ms: 0x00482600,
  quest_results_unlock_weapon_id: 0x00482700,
  quest_results_unlock_perk_id: 0x00482704,
  quest_results_final_time_ms: 0x0048270c,
  quest_results_reveal_base_time_ms: 0x00482710,
  quest_results_reveal_health_bonus_ms: 0x00482714,
  quest_results_reveal_perk_bonus_s: 0x00482718,
  quest_results_reveal_total_time_ms: 0x00482720,
  quest_results_reveal_step_timer_ms: 0x00482724,
  quest_spawn_count: 0x00482b08,

  perk_pending_count: 0x00486fac,
  survival_reward_weapon_guard_id: 0x00486fb8,
  creature_active_count: 0x00486fcc,
  quest_spawn_timeline: 0x00486fd0,
  demo_mode_active: 0x0048700d,
  time_scale_active: 0x0048700e,
  time_scale_factor: 0x00487010,
  bonus_reflex_boost_timer: 0x00487014,
  bonus_freeze_timer: 0x00487018,
  bonus_weapon_power_up_timer: 0x0048701c,
  bonus_energizer_timer: 0x00487020,
  bonus_double_xp_timer: 0x00487024,
  bonus_spawn_guard: 0x0048703c,
  quest_transition_timer_ms: 0x00487088,
  time_played_ms: 0x0048718c,
  player_heading_turn_delta: 0x00487198,
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
  player_muzzle_flash_alpha: 0x00490bac,
  player_aim_heading: 0x00490bb0,
  player_low_health_timer: 0x00490bc0,
  player_speed_bonus_timer: 0x00490bc4,
  player_shield_timer: 0x00490bc8,
  player_fire_bullets_timer: 0x00490bcc,

  projectile_pool: 0x004926b8,

  perk_jinxed_proc_timer_s: 0x004aaf1c,
  quest_spawn_stall_timer_ms: 0x004c3654,

  weapon_ammo_class: 0x004d7a28,
  weapon_table: 0x004d7a2c,
};

const WATCH_RANGES = [
  { id: "ui_subtemplate", start: 0x0048fd78, size: 0x588 },
  { id: "core_timing", start: 0x00480840, size: 0x80 },
  { id: "quest_results", start: 0x00482600, size: 0x128 },
  { id: "gameplay_timers", start: 0x00486fac, size: 0x94 },
  { id: "state_block", start: 0x0048718c, size: 0x100 },
  { id: "jinxed_timer", start: 0x004aaf1c, size: 0x04 },
  { id: "quest_stall", start: 0x004c3654, size: 0x04 },
];

const WATCH_SYMBOLS = {
  0x00480840: "frame_dt",
  0x00480844: "frame_dt_ms",
  0x00480850: "demo_trial_overlay_active",
  0x00480898: "demo_trial_overlay_alpha_ms",
  0x004808a4: "perk_lean_mean_exp_tick_timer_s",

  0x00482600: "quest_results_health_bonus_ms",
  0x00482700: "quest_results_unlock_weapon_id",
  0x00482704: "quest_results_unlock_perk_id",
  0x0048270c: "quest_results_final_time_ms",
  0x00482710: "quest_results_reveal_base_time_ms",
  0x00482714: "quest_results_reveal_health_bonus_ms",
  0x00482718: "quest_results_reveal_perk_bonus_s",
  0x00482720: "quest_results_reveal_total_time_ms",
  0x00482724: "quest_results_reveal_step_timer_ms",

  0x00486fac: "perk_pending_count",
  0x00486fb8: "survival_reward_weapon_guard_id",
  0x00486fcc: "creature_active_count",
  0x00486fd0: "quest_spawn_timeline",
  0x0048700d: "demo_mode_active",
  0x0048700e: "time_scale_active",
  0x00487010: "time_scale_factor",
  0x00487014: "bonus_reflex_boost_timer",
  0x00487018: "bonus_freeze_timer",
  0x0048701c: "bonus_weapon_power_up_timer",
  0x00487020: "bonus_energizer_timer",
  0x00487024: "bonus_double_xp_timer",
  0x0048703c: "bonus_spawn_guard",

  0x0048718c: "time_played_ms",
  0x00487198: "player_heading_turn_delta",
  0x0048719c: "player_alt_weapon_swap_cooldown_ms",
  0x00487244: "quest_stage_banner_timer_ms",
  0x00487248: "ui_elements_timeline",
  0x0048724c: "ui_transition_direction",
  0x00487268: "perk_doctor_target_creature_id",
  0x0048726c: "game_state_prev",
  0x00487270: "game_state_id",
  0x00487274: "game_state_pending",
  0x00487278: "ui_transition_alpha",
  0x00487284: "pause_keybind_help_alpha_ms",

  0x004aaf1c: "perk_jinxed_proc_timer_s",
  0x004c3654: "quest_spawn_stall_timer_ms",
};

let outFile = null;
let outWarned = false;
let exeModule = null;

const fnPtrs = {};
const dataPtrs = {};

let gameplayFrame = 0;
let uiFrame = 0;
let currentStateId = null;
let currentStatePending = null;
let currentStatePrev = null;

let lastCompactSnapshotAt = 0;
let lastFullSnapshotAt = 0;

let memEventsSec = 0;
let memEventsCount = 0;
let memEventsDropped = 0;

const uiRenderSeen = new Set();
const uiPrevByState = {};

let lastPerksCompact = null;
let lastQuestResultsCompact = null;
let lastQuestTimelineCompact = null;
let lastModeTickAt = {
  quest_mode_update: 0,
  rush_mode_update: 0,
  survival_update: 0,
  typo_gameplay_update_and_render: 0,
};

function openOutFile() {
  if (outFile) return;
  const mode = CONFIG.logMode === "append" ? "a" : "w";
  try {
    outFile = new File(CONFIG.outPath, mode);
  } catch (_) {
    outFile = null;
  }
}

function writeLine(obj) {
  if (!obj) return;
  if (obj.ts_iso == null) obj.ts_iso = nowIso();
  if (obj.ts_ms == null) obj.ts_ms = nowMs();

  const line = JSON.stringify(obj) + "\n";
  let wrote = false;
  try {
    openOutFile();
    if (outFile) {
      outFile.write(line);
      wrote = true;
    }
  } catch (_) {
    wrote = false;
  }

  if (!wrote && !outWarned) {
    outWarned = true;
    console.log("gameplay_state_capture: file logging unavailable, using console only");
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

function safeReadPtr(ptrVal) {
  try {
    return ptrVal.readPointer();
  } catch (_) {
    return null;
  }
}

function safeReadCString(ptrVal, maxLen) {
  if (!ptrVal) return null;
  try {
    const len = maxLen || 260;
    const out = [];
    for (let i = 0; i < len; i++) {
      const b = ptrVal.add(i).readU8();
      if (b === 0) break;
      out.push(b);
    }
    if (!out.length) return "";
    return String.fromCharCode.apply(null, out);
  } catch (_) {
    return null;
  }
}

function safeReadVec2(ptrVal) {
  if (!ptrVal) return null;
  const x = safeReadF32(ptrVal);
  const y = safeReadF32(ptrVal.add(4));
  if (x == null || y == null) return null;
  return { x: x, y: y };
}

function staticToRuntime(staticVa) {
  if (!exeModule) return null;
  try {
    return exeModule.base.add(ptr(staticVa).sub(LINK_BASE));
  } catch (_) {
    return null;
  }
}

function runtimeToStatic(address) {
  if (!exeModule || !address) return null;
  try {
    const mod = Process.findModuleByAddress(address);
    if (!mod) return null;
    if (String(mod.name).toLowerCase() !== String(exeModule.name).toLowerCase()) return null;
    const delta = address.sub(exeModule.base).toUInt32();
    return (0x00400000 + delta) >>> 0;
  } catch (_) {
    return null;
  }
}

function formatCaller(address) {
  if (!address) return null;
  try {
    const mod = Process.findModuleByAddress(address);
    if (!mod) return address.toString();
    const off = address.sub(mod.base).toUInt32();
    return mod.name + "+0x" + off.toString(16);
  } catch (_) {
    return null;
  }
}

function maybeBacktrace(context) {
  if (!CONFIG.includeBacktrace) return null;
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 10)
      .map((a) => formatCaller(a) || a.toString());
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

function readPlayerCompact(playerIndex) {
  const clipU32 = readPlayerU32("player_clip_size", playerIndex);
  const ammoU32 = readPlayerU32("player_ammo", playerIndex);
  const reloadActiveU32 = readPlayerU32("player_reload_active", playerIndex);

  return {
    index: playerIndex,
    pos_x: readPlayerF32("player_pos_x", playerIndex),
    pos_y: readPlayerF32("player_pos_y", playerIndex),
    move_dx: readPlayerF32("player_move_dx", playerIndex),
    move_dy: readPlayerF32("player_move_dy", playerIndex),
    health: readPlayerF32("player_health", playerIndex),
    aim_x: readPlayerF32("player_aim_x", playerIndex),
    aim_y: readPlayerF32("player_aim_y", playerIndex),
    aim_heading: readPlayerF32("player_aim_heading", playerIndex),
    weapon_id: readPlayerI32("player_weapon_id", playerIndex),
    clip_size_i32: clipU32 == null ? null : (clipU32 | 0),
    clip_size_f32: clipU32 == null ? null : u32ToF32(clipU32),
    ammo_i32: ammoU32 == null ? null : (ammoU32 | 0),
    ammo_f32: ammoU32 == null ? null : u32ToF32(ammoU32),
    reload_active_i32: reloadActiveU32 == null ? null : (reloadActiveU32 | 0),
    reload_active_f32: reloadActiveU32 == null ? null : u32ToF32(reloadActiveU32),
    reload_timer: readPlayerF32("player_reload_timer", playerIndex),
    reload_timer_max: readPlayerF32("player_reload_timer_max", playerIndex),
    shot_cooldown: readPlayerF32("player_shot_cooldown", playerIndex),
    spread_heat: readPlayerF32("player_spread_heat", playerIndex),
    muzzle_flash_alpha: readPlayerF32("player_muzzle_flash_alpha", playerIndex),
    low_health_timer: readPlayerF32("player_low_health_timer", playerIndex),
    speed_bonus_timer: readPlayerF32("player_speed_bonus_timer", playerIndex),
    shield_timer: readPlayerF32("player_shield_timer", playerIndex),
    fire_bullets_timer: readPlayerF32("player_fire_bullets_timer", playerIndex),
    experience: readPlayerI32("player_experience", playerIndex),
    level: readPlayerI32("player_level", playerIndex),
    perk_timers: {
      hot_tempered: readPlayerF32("player_hot_tempered_timer", playerIndex),
      man_bomb: readPlayerF32("player_man_bomb_timer", playerIndex),
      living_fortress: readPlayerF32("player_living_fortress_timer", playerIndex),
      fire_cough: readPlayerF32("player_fire_cough_timer", playerIndex),
    },
    alt_weapon: {
      weapon_id: readPlayerI32("player_alt_weapon_id", playerIndex),
      clip_size_i32: readPlayerI32("player_alt_clip_size", playerIndex),
      reload_active_i32: readPlayerI32("player_alt_reload_active", playerIndex),
      ammo_i32: readPlayerI32("player_alt_ammo", playerIndex),
      reload_timer: readPlayerF32("player_alt_reload_timer", playerIndex),
      shot_cooldown: readPlayerF32("player_alt_shot_cooldown", playerIndex),
      reload_timer_max: readPlayerF32("player_alt_reload_timer_max", playerIndex),
    },
  };
}

function readPlayersCompact() {
  const out = [];
  for (let i = 0; i < CONFIG.playerCount; i++) {
    out.push(readPlayerCompact(i));
  }
  return out;
}

function readQuestResultsCompact() {
  return {
    health_bonus_ms: readDataI32("quest_results_health_bonus_ms"),
    unlock_weapon_id: readDataI32("quest_results_unlock_weapon_id"),
    unlock_perk_id: readDataI32("quest_results_unlock_perk_id"),
    final_time_ms: readDataI32("quest_results_final_time_ms"),
    reveal_base_time_ms: readDataI32("quest_results_reveal_base_time_ms"),
    reveal_health_bonus_ms: readDataI32("quest_results_reveal_health_bonus_ms"),
    reveal_perk_bonus_s: readDataI32("quest_results_reveal_perk_bonus_s"),
    reveal_total_time_ms: readDataI32("quest_results_reveal_total_time_ms"),
    reveal_step_timer_ms: readDataI32("quest_results_reveal_step_timer_ms"),
  };
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
    ui_elements_timeline: readDataF32("ui_elements_timeline"),
    ui_transition_direction_i32: readDataI32("ui_transition_direction"),
    ui_transition_alpha: readDataF32("ui_transition_alpha"),

    demo_mode_active: readDataU32("demo_mode_active"),
    time_scale_active: readDataU32("time_scale_active"),
    time_scale_factor: readDataF32("time_scale_factor"),
    demo_trial_overlay_active: readDataU32("demo_trial_overlay_active"),
    demo_trial_overlay_alpha_ms: readDataI32("demo_trial_overlay_alpha_ms"),
    pause_keybind_help_alpha_ms: readDataI32("pause_keybind_help_alpha_ms"),

    bonus_spawn_guard: readDataU32("bonus_spawn_guard"),
    bonus_reflex_boost_timer: readDataF32("bonus_reflex_boost_timer"),
    bonus_freeze_timer: readDataF32("bonus_freeze_timer"),
    bonus_weapon_power_up_timer: readDataF32("bonus_weapon_power_up_timer"),
    bonus_energizer_timer: readDataF32("bonus_energizer_timer"),
    bonus_double_xp_timer: readDataF32("bonus_double_xp_timer"),

    perk_pending_count: readDataI32("perk_pending_count"),
    perk_jinxed_proc_timer_s: readDataF32("perk_jinxed_proc_timer_s"),
    perk_lean_mean_exp_tick_timer_s: readDataF32("perk_lean_mean_exp_tick_timer_s"),
    perk_doctor_target_creature_id: readDataI32("perk_doctor_target_creature_id"),

    survival_reward_weapon_guard_id: readDataI32("survival_reward_weapon_guard_id"),
    quest_spawn_count: readDataI32("quest_spawn_count"),
    quest_spawn_timeline: readDataI32("quest_spawn_timeline"),
    quest_spawn_stall_timer_ms: readDataI32("quest_spawn_stall_timer_ms"),
    quest_transition_timer_ms: readDataI32("quest_transition_timer_ms"),
    quest_stage_banner_timer_ms: readDataI32("quest_stage_banner_timer_ms"),

    creature_active_count: readDataI32("creature_active_count"),
    player_heading_turn_delta: readDataF32("player_heading_turn_delta"),
    player_alt_weapon_swap_cooldown_ms: readDataI32("player_alt_weapon_swap_cooldown_ms"),
    time_played_ms: readDataI32("time_played_ms"),
  };
}

function readWeaponEntry(weaponId) {
  const table = dataPtrs.weapon_table;
  const ammoClass = dataPtrs.weapon_ammo_class;
  if (!table || !ammoClass || weaponId == null || weaponId < 0) return null;
  const base = table.add(weaponId * STRIDES.weapon);
  const ammoPtr = ammoClass.add(weaponId * STRIDES.weapon);
  return {
    weapon_id: weaponId,
    name: safeReadCString(base, 0x40),
    unlocked: safeReadU8(base.add(0x40)),
    ammo_class: safeReadS32(ammoPtr),
    clip_size_i32: safeReadS32(base.add(0x44)),
    shot_cooldown: safeReadF32(base.add(0x48)),
    reload_time: safeReadF32(base.add(0x4c)),
    spread_heat: safeReadF32(base.add(0x50)),
    shot_sfx_base_id: safeReadS32(base.add(0x58)),
    shot_sfx_variants: safeReadS32(base.add(0x5c)),
    reload_sfx_id: safeReadS32(base.add(0x60)),
    hud_icon_id: safeReadS32(base.add(0x64)),
    flags: safeReadU8(base.add(0x68)),
    projectile_meta: safeReadF32(base.add(0x6c)),
    damage_scale: safeReadF32(base.add(0x70)),
    pellet_count: safeReadS32(base.add(0x74)),
  };
}

function readProjectileEntry(index) {
  const basePtr = dataPtrs.projectile_pool;
  if (!basePtr || index == null || index < 0) return null;
  const base = basePtr.add(index * STRIDES.projectile);
  return {
    index: index,
    active: safeReadU8(base),
    angle: safeReadF32(base.add(0x04)),
    pos: safeReadVec2(base.add(0x08)),
    vel: safeReadVec2(base.add(0x18)),
    type_id: safeReadS32(base.add(0x20)),
    life_timer: safeReadF32(base.add(0x24)),
    speed_scale: safeReadF32(base.add(0x2c)),
    damage_pool: safeReadF32(base.add(0x30)),
    hit_radius: safeReadF32(base.add(0x34)),
    base_damage: safeReadF32(base.add(0x38)),
    owner_id: safeReadS32(base.add(0x3c)),
  };
}

function readUiSubtemplateBlocks() {
  const start = dataPtrs.ui_subtemplate_start;
  if (!start) return null;

  const out = [];
  for (let block = 0; block < 6; block++) {
    const base = start.add(block * STRIDES.uiBlock);
    const slots = [];
    for (let slot = 0; slot < 8; slot++) {
      const s = base.add(slot * STRIDES.uiSlot);
      slots.push({
        slot: slot,
        x: safeReadF32(s),
        y: safeReadF32(s.add(4)),
        field_0x08: safeReadF32(s.add(8)),
        field_0x0c: safeReadF32(s.add(12)),
        field_0x10: safeReadF32(s.add(16)),
        field_0x14: safeReadF32(s.add(20)),
        field_0x18: safeReadF32(s.add(24)),
      });
    }
    out.push({
      block: block + 1,
      static_base: toHex((DATA.ui_subtemplate_start + block * STRIDES.uiBlock) >>> 0, 8),
      texture_handle: safeReadS32(base.add(0xe0)),
      quad_mode: safeReadS32(base.add(0xe4)),
      slots: slots,
    });
  }
  return out;
}

function hashU32Array(u32) {
  let h = 0x811c9dc5;
  for (let i = 0; i < u32.length; i++) {
    h ^= u32[i] >>> 0;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function readUiRangeBuffer() {
  const start = dataPtrs.ui_subtemplate_start;
  if (!start) return null;
  const size = DATA.ui_subtemplate_end_excl - DATA.ui_subtemplate_start;
  try {
    return start.readByteArray(size);
  } catch (_) {
    return null;
  }
}

function diffUiRange(prevBuf, nextBuf, maxChanges) {
  if (!prevBuf || !nextBuf) return [];
  const prev = new Uint32Array(prevBuf);
  const next = new Uint32Array(nextBuf);
  const changes = [];
  const limit = Math.max(1, maxChanges | 0);

  const count = Math.min(prev.length, next.length);
  for (let i = 0; i < count; i++) {
    const a = prev[i] >>> 0;
    const b = next[i] >>> 0;
    if (a === b) continue;

    const off = i * 4;
    changes.push({
      offset: off,
      static_va: toHex((DATA.ui_subtemplate_start + off) >>> 0, 8),
      old_u32: a,
      new_u32: b,
      old_f32: u32ToF32(a),
      new_f32: u32ToF32(b),
      decode: decodeUiOffset(off),
    });

    if (changes.length >= limit) break;
  }

  return changes;
}

function decodeUiOffset(offset) {
  if (offset < 0 || offset >= (DATA.ui_subtemplate_end_excl - DATA.ui_subtemplate_start)) {
    return null;
  }

  const block = Math.floor(offset / STRIDES.uiBlock) + 1;
  const blockOffset = offset % STRIDES.uiBlock;

  const out = {
    block: block,
    block_offset: blockOffset,
  };

  // Block 7 is not a menu-item template block; it contains adjacent UI globals.
  if (block === 7) {
    if (blockOffset === 0x00) out.field = "ui_cursor_anim_timer";
    else if (blockOffset === 0x04) out.field = "ui_cursor_pulse_phase";
    else if (blockOffset === 0x08) out.field = "ui_aim_enhancement_anim_timer";
    else if (blockOffset === 0x0c) out.field = "ui_aim_enhancement_pulse_phase";
    else if (blockOffset === 0x10) out.field = "quest_kill_progress_ratio";
    if (out.field) return out;
  }

  if (blockOffset < 0xe0) {
    const slot = Math.floor(blockOffset / STRIDES.uiSlot);
    const slotOff = blockOffset % STRIDES.uiSlot;
    let field = null;
    if (slotOff === 0x00) field = "x";
    else if (slotOff === 0x04) field = "y";
    else if (slotOff === 0x08) field = "field_0x08";
    else if (slotOff === 0x0c) field = "field_0x0c";
    else if (slotOff === 0x10) field = "field_0x10";
    else if (slotOff === 0x14) field = "field_0x14";
    else if (slotOff === 0x18) field = "field_0x18";

    out.slot = slot;
    out.slot_offset = slotOff;
    out.slot_field = field;
    return out;
  }

  if (blockOffset === 0xe0) {
    out.field = "texture_handle";
  } else if (blockOffset === 0xe4) {
    out.field = "quad_mode";
  }

  return out;
}

function isInterestingUiState(stateId) {
  return CONFIG.uiRenderStates.has(stateId);
}

function updateCurrentStateFromMemory() {
  currentStatePrev = readDataI32("game_state_prev");
  currentStateId = readDataI32("game_state_id");
  currentStatePending = readDataI32("game_state_pending");
}

function compactSnapshot(reason, extra) {
  const obj = {
    event: "snapshot_compact",
    reason: reason,
    gameplay_frame: gameplayFrame,
    ui_frame: uiFrame,
    globals: readGameplayGlobalsCompact(),
    players: readPlayersCompact(),
  };
  if (extra) Object.assign(obj, extra);
  writeLine(obj);
}

function fullSnapshot(reason, extra) {
  const obj = {
    event: "snapshot_full",
    reason: reason,
    gameplay_frame: gameplayFrame,
    ui_frame: uiFrame,
    globals: readGameplayGlobalsCompact(),
    players: readPlayersCompact(),
    quest_results: readQuestResultsCompact(),
    ui_subtemplate_blocks: readUiSubtemplateBlocks(),
  };
  if (extra) Object.assign(obj, extra);
  writeLine(obj);
}

function maybeEmitPeriodicSnapshots(tag) {
  const t = nowMs();

  if (t - lastCompactSnapshotAt >= CONFIG.snapshotIntervalMs) {
    lastCompactSnapshotAt = t;
    compactSnapshot(tag || "interval");
  }

  if (t - lastFullSnapshotAt >= CONFIG.fullSnapshotIntervalMs) {
    lastFullSnapshotAt = t;
    fullSnapshot(tag || "interval_full");
  }
}

function captureUiDelta(reason) {
  const state = currentStateId;
  if (!isInterestingUiState(state)) return;
  if (uiFrame % CONFIG.uiDeltaEveryFrames !== 0) return;

  const nextBuf = readUiRangeBuffer();
  if (!nextBuf) return;

  const prevBuf = uiPrevByState[state] || null;
  uiPrevByState[state] = nextBuf;

  const nextU32 = new Uint32Array(nextBuf);
  const nextHash = hashU32Array(nextU32);

  if (!prevBuf) {
    writeLine({
      event: "ui_subtemplate_baseline",
      reason: reason,
      state_id: state,
      ui_frame: uiFrame,
      hash_u32: toHex(nextHash, 8),
      blocks: readUiSubtemplateBlocks(),
    });
    return;
  }

  const changes = diffUiRange(prevBuf, nextBuf, CONFIG.maxUiDeltaChanges);
  if (!changes.length) return;

  const changedBlocks = {};
  for (let i = 0; i < changes.length; i++) {
    const d = changes[i].decode;
    if (d && d.block != null) changedBlocks[d.block] = true;
  }

  const allBlocks = readUiSubtemplateBlocks();
  const blockSubset = [];
  if (allBlocks) {
    for (let i = 0; i < allBlocks.length; i++) {
      const block = allBlocks[i];
      if (changedBlocks[block.block]) blockSubset.push(block);
    }
  }

  writeLine({
    event: "ui_subtemplate_delta",
    reason: reason,
    state_id: state,
    ui_frame: uiFrame,
    hash_u32: toHex(nextHash, 8),
    change_count: changes.length,
    changes: changes,
    changed_blocks: blockSubset,
  });
}

function resolveWatchRange(staticVa) {
  if (staticVa == null) return null;
  for (let i = 0; i < WATCH_RANGES.length; i++) {
    const r = WATCH_RANGES[i];
    if (staticVa >= r.start && staticVa < (r.start + r.size)) return r;
  }
  return null;
}

function rateLimitMemEvent() {
  const sec = Math.floor(nowMs() / 1000);
  if (sec !== memEventsSec) {
    if (memEventsDropped > 0) {
      writeLine({
        event: "mem_watch_dropped",
        dropped: memEventsDropped,
        second_epoch: memEventsSec,
      });
      memEventsDropped = 0;
    }
    memEventsSec = sec;
    memEventsCount = 0;
  }

  memEventsCount += 1;
  if (memEventsCount > CONFIG.maxMemEventsPerSec) {
    memEventsDropped += 1;
    return false;
  }

  return true;
}

function normalizeMemOperation(operation) {
  const op = String(operation || "").toLowerCase();
  if (op === "w" || op === "write") return "write";
  if (op === "r" || op === "read") return "read";
  if (op === "x" || op === "execute") return "execute";
  return op || "unknown";
}

function maybeEmitModeTick(name) {
  const t = nowMs();
  const last = lastModeTickAt[name] || 0;
  if (t - last < CONFIG.modeTickMs) return;
  lastModeTickAt[name] = t;

  writeLine({
    event: "mode_tick",
    mode_fn: name,
    state_id: currentStateId,
    state_pending: currentStatePending,
    globals: readGameplayGlobalsCompact(),
    player0: readPlayerCompact(0),
  });
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
      writeLine({
        event: "game_state_set",
        target_state: this._targetState,
        before: this._before,
        after: {
          prev: currentStatePrev,
          id: currentStateId,
          pending: currentStatePending,
        },
        caller: this._caller,
        backtrace: this._bt,
      });
      fullSnapshot("game_state_set", { target_state: this._targetState });
    },
  });

  attachHook("ui_menu_assets_init", fnPtrs.ui_menu_assets_init, {
    onLeave() {
      updateCurrentStateFromMemory();
      fullSnapshot("after_ui_menu_assets_init");
    },
  });

  attachHook("ui_menu_layout_init", fnPtrs.ui_menu_layout_init, {
    onLeave() {
      updateCurrentStateFromMemory();
      fullSnapshot("after_ui_menu_layout_init");
    },
  });

  attachHook("ui_elements_update_and_render", fnPtrs.ui_elements_update_and_render, {
    onEnter() {
      uiFrame += 1;
      uiRenderSeen.clear();
    },
    onLeave() {
      updateCurrentStateFromMemory();
      captureUiDelta("ui_elements_update_and_render");
      maybeEmitPeriodicSnapshots("ui_elements_update_and_render");
    },
  });

  attachHook("ui_element_render", fnPtrs.ui_element_render, {
    onEnter(args) {
      if (!isInterestingUiState(currentStateId)) return;
      const elem = args[0];
      const key = uiFrame + ":" + elem.toString();
      if (uiRenderSeen.has(key)) return;
      uiRenderSeen.add(key);

      const elemStatic = runtimeToStatic(elem);
      writeLine({
        event: "ui_element_render_input",
        state_id: currentStateId,
        ui_frame: uiFrame,
        element_ptr: elem.toString(),
        element_static_va: elemStatic == null ? null : toHex(elemStatic, 8),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      });
    },
  });

  attachHook("ui_menu_item_update", fnPtrs.ui_menu_item_update, {
    onEnter(args) {
      const itemPtr = args[1];
      const itemStatic = runtimeToStatic(itemPtr);
      if (itemStatic == null) return;

      const inUiSubtemplate =
        itemStatic >= DATA.ui_subtemplate_start && itemStatic < DATA.ui_subtemplate_end_excl;
      if (!inUiSubtemplate) return;

      const off = itemStatic - DATA.ui_subtemplate_start;
      writeLine({
        event: "ui_menu_item_update_subtemplate_ptr",
        state_id: currentStateId,
        ui_frame: uiFrame,
        item_ptr: itemPtr.toString(),
        item_static_va: toHex(itemStatic, 8),
        item_offset: off,
        decode: decodeUiOffset(off),
        pos_ptr: args[0] ? args[0].toString() : null,
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      });
    },
  });

  attachHook("ui_button_update", fnPtrs.ui_button_update, {
    onEnter(args) {
      if (!isInterestingUiState(currentStateId)) return;
      if (uiFrame % 30 !== 0) return;
      writeLine({
        event: "ui_button_update_tick",
        state_id: currentStateId,
        ui_frame: uiFrame,
        button_ptr: args[1] ? args[1].toString() : null,
      });
    },
  });

  attachHook("gameplay_update_and_render", fnPtrs.gameplay_update_and_render, {
    onEnter() {
      gameplayFrame += 1;
      updateCurrentStateFromMemory();
      maybeEmitPeriodicSnapshots("gameplay_update_and_render");
    },
  });

  attachHook("quest_mode_update", fnPtrs.quest_mode_update, {
    onEnter() {
      updateCurrentStateFromMemory();
      maybeEmitModeTick("quest_mode_update");
    },
  });

  attachHook("rush_mode_update", fnPtrs.rush_mode_update, {
    onEnter() {
      updateCurrentStateFromMemory();
      maybeEmitModeTick("rush_mode_update");
    },
  });

  attachHook("survival_update", fnPtrs.survival_update, {
    onEnter() {
      updateCurrentStateFromMemory();
      maybeEmitModeTick("survival_update");
    },
  });

  attachHook("typo_gameplay_update_and_render", fnPtrs.typo_gameplay_update_and_render, {
    onEnter() {
      updateCurrentStateFromMemory();
      maybeEmitModeTick("typo_gameplay_update_and_render");
    },
  });

  attachHook("player_fire_weapon", fnPtrs.player_fire_weapon, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      this._ctx = {
        player_index: playerIndex,
        before: readPlayerCompact(playerIndex >= 0 ? playerIndex : 0),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave() {
      const ctx = this._ctx;
      if (!ctx) return;
      const idx = ctx.player_index >= 0 ? ctx.player_index : 0;
      writeLine({
        event: "player_fire_weapon",
        player_index: ctx.player_index,
        before: ctx.before,
        after: readPlayerCompact(idx),
        caller: ctx.caller,
      });
    },
  });

  attachHook("weapon_assign_player", fnPtrs.weapon_assign_player, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      const weaponId = args[1].toInt32();
      this._ctx = {
        player_index: playerIndex,
        weapon_id: weaponId,
        before: readPlayerCompact(playerIndex),
        weapon: readWeaponEntry(weaponId),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave() {
      const ctx = this._ctx;
      if (!ctx) return;
      writeLine({
        event: "weapon_assign_player",
        player_index: ctx.player_index,
        weapon_id: ctx.weapon_id,
        weapon: ctx.weapon,
        before: ctx.before,
        after: readPlayerCompact(ctx.player_index),
        caller: ctx.caller,
      });
      compactSnapshot("weapon_assign_player", {
        player_index: ctx.player_index,
        weapon_id: ctx.weapon_id,
      });
    },
  });

  attachHook("bonus_apply", fnPtrs.bonus_apply, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      const entry = args[1];
      this._ctx = {
        player_index: playerIndex,
        bonus_ptr: entry ? entry.toString() : null,
        bonus_id: entry ? safeReadS32(entry) : null,
        entry_state: entry ? safeReadS32(entry.add(4)) : null,
        amount_i32: entry ? safeReadS32(entry.add(0x18)) : null,
        amount_f32: entry ? safeReadF32(entry.add(0x18)) : null,
        before: readPlayerCompact(playerIndex),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave() {
      const ctx = this._ctx;
      if (!ctx) return;
      writeLine({
        event: "bonus_apply",
        player_index: ctx.player_index,
        bonus_ptr: ctx.bonus_ptr,
        bonus_id: ctx.bonus_id,
        entry_state: ctx.entry_state,
        amount_i32: ctx.amount_i32,
        amount_f32: ctx.amount_f32,
        before: ctx.before,
        after: readPlayerCompact(ctx.player_index),
        globals: readGameplayGlobalsCompact(),
        caller: ctx.caller,
      });
      compactSnapshot("bonus_apply", {
        player_index: ctx.player_index,
        bonus_id: ctx.bonus_id,
      });
    },
  });

  attachHook("player_take_damage", fnPtrs.player_take_damage, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      this._ctx = {
        player_index: playerIndex,
        damage_f32: argAsF32(args[1]),
        before: readPlayerCompact(playerIndex),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave() {
      const ctx = this._ctx;
      if (!ctx) return;
      const after = readPlayerCompact(ctx.player_index);
      let healthDelta = null;
      if (ctx.before && after && ctx.before.health != null && after.health != null) {
        healthDelta = after.health - ctx.before.health;
      }
      writeLine({
        event: "player_take_damage",
        player_index: ctx.player_index,
        damage_f32: ctx.damage_f32,
        health_delta: healthDelta,
        before: ctx.before,
        after: after,
        caller: ctx.caller,
      });
    },
  });

  attachHook("projectile_spawn", fnPtrs.projectile_spawn, {
    onEnter(args) {
      this._ctx = {
        pos: safeReadVec2(args[0]),
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
      writeLine({
        event: "projectile_spawn",
        index: idx,
        pos: ctx.pos,
        angle_f32: ctx.angle_f32,
        requested_type_id: ctx.requested_type_id,
        owner_id: ctx.owner_id,
        actual: spawned,
        type_overridden:
          spawned && spawned.type_id != null
            ? spawned.type_id !== ctx.requested_type_id
            : null,
        caller: ctx.caller,
      });
    },
  });

  attachHook("projectile_update", fnPtrs.projectile_update, {
    onEnter() {
      if (gameplayFrame % 30 !== 0) return;
      writeLine({
        event: "projectile_update_tick",
        gameplay_frame: gameplayFrame,
        state_id: currentStateId,
      });
    },
  });

  attachHook("perks_update_effects", fnPtrs.perks_update_effects, {
    onLeave() {
      const compact = {
        perk_jinxed_proc_timer_s: readDataF32("perk_jinxed_proc_timer_s"),
        perk_lean_mean_exp_tick_timer_s: readDataF32("perk_lean_mean_exp_tick_timer_s"),
        perk_doctor_target_creature_id: readDataI32("perk_doctor_target_creature_id"),
        perk_pending_count: readDataI32("perk_pending_count"),
      };
      if (lastPerksCompact && shallowEqual(lastPerksCompact, compact)) return;
      lastPerksCompact = copyObject(compact);
      writeLine({
        event: "perks_update_effects_delta",
        compact: compact,
        player0: readPlayerCompact(0),
      });
    },
  });

  attachHook("quest_spawn_timeline_update", fnPtrs.quest_spawn_timeline_update, {
    onLeave() {
      const compact = {
        quest_spawn_count: readDataI32("quest_spawn_count"),
        quest_spawn_timeline: readDataI32("quest_spawn_timeline"),
        quest_spawn_stall_timer_ms: readDataI32("quest_spawn_stall_timer_ms"),
        creature_active_count: readDataI32("creature_active_count"),
        quest_transition_timer_ms: readDataI32("quest_transition_timer_ms"),
      };
      if (lastQuestTimelineCompact && shallowEqual(lastQuestTimelineCompact, compact)) return;
      lastQuestTimelineCompact = copyObject(compact);
      writeLine({ event: "quest_spawn_timeline_delta", compact: compact });
    },
  });

  attachHook("quest_results_screen_update", fnPtrs.quest_results_screen_update, {
    onEnter() {
      const compact = readQuestResultsCompact();
      if (lastQuestResultsCompact && shallowEqual(lastQuestResultsCompact, compact)) return;
      lastQuestResultsCompact = copyObject(compact);
      writeLine({
        event: "quest_results_reveal_delta",
        compact: compact,
        globals: readGameplayGlobalsCompact(),
      });
    },
  });

  attachHook("quest_failed_screen_update", fnPtrs.quest_failed_screen_update, {
    onEnter() {
      if (uiFrame % 20 !== 0) return;
      writeLine({
        event: "quest_failed_screen_tick",
        state_id: currentStateId,
        globals: readGameplayGlobalsCompact(),
      });
    },
  });

  attachHook("demo_trial_overlay_render", fnPtrs.demo_trial_overlay_render, {
    onEnter() {
      writeLine({
        event: "demo_trial_overlay_render",
        overlay_active: readDataU32("demo_trial_overlay_active"),
        overlay_alpha_ms: readDataI32("demo_trial_overlay_alpha_ms"),
      });
    },
  });

  attachHook("ui_render_keybind_help", fnPtrs.ui_render_keybind_help, {
    onEnter() {
      writeLine({
        event: "ui_render_keybind_help",
        alpha_ms: readDataI32("pause_keybind_help_alpha_ms"),
        state_id: currentStateId,
      });
    },
  });

  attachHook("bonus_hud_slot_activate", fnPtrs.bonus_hud_slot_activate, {
    onEnter(args) {
      this._ctx = {
        label_ptr: args[0] ? args[0].toString() : null,
        label: args[0] ? safeReadCString(args[0], 80) : null,
        icon_id: args[1] ? args[1].toInt32() : null,
        timer_ptr: args[2] ? args[2].toString() : null,
        alt_timer_ptr: args[3] ? args[3].toString() : null,
      };
    },
    onLeave() {
      if (!this._ctx) return;
      writeLine({
        event: "bonus_hud_slot_activate",
        args: this._ctx,
        globals: readGameplayGlobalsCompact(),
      });
    },
  });

  attachHook("bonus_hud_slot_update_and_render", fnPtrs.bonus_hud_slot_update_and_render, {
    onEnter() {
      if (uiFrame % 20 !== 0) return;
      writeLine({
        event: "bonus_hud_slot_update_tick",
        state_id: currentStateId,
        globals: {
          bonus_reflex_boost_timer: readDataF32("bonus_reflex_boost_timer"),
          bonus_freeze_timer: readDataF32("bonus_freeze_timer"),
          bonus_weapon_power_up_timer: readDataF32("bonus_weapon_power_up_timer"),
          bonus_energizer_timer: readDataF32("bonus_energizer_timer"),
          bonus_double_xp_timer: readDataF32("bonus_double_xp_timer"),
        },
      });
    },
  });

  attachHook("ui_render_hud", fnPtrs.ui_render_hud, {
    onEnter() {
      if (gameplayFrame % 20 !== 0) return;
      writeLine({
        event: "ui_render_hud_tick",
        state_id: currentStateId,
        player0: readPlayerCompact(0),
      });
    },
  });

  attachHook("hud_update_and_render", fnPtrs.hud_update_and_render, {
    onEnter() {
      if (gameplayFrame % 20 !== 0) return;
      writeLine({
        event: "hud_update_and_render_tick",
        state_id: currentStateId,
        ui_transition_alpha: readDataF32("ui_transition_alpha"),
      });
    },
  });

  attachHook("player_update", fnPtrs.player_update, {
    onEnter(args) {
      const idx = args[0].toInt32();
      if (idx !== 0) return;
      if (gameplayFrame % 20 !== 0) return;
      writeLine({
        event: "player_update_tick",
        player0: readPlayerCompact(0),
      });
    },
  });

  attachHook("creature_update_all", fnPtrs.creature_update_all, {
    onEnter() {
      if (gameplayFrame % 20 !== 0) return;
      writeLine({
        event: "creature_update_all_tick",
        creature_active_count: readDataI32("creature_active_count"),
        perk_doctor_target_creature_id: readDataI32("perk_doctor_target_creature_id"),
      });
    },
  });

  attachHook("creature_spawn_template", fnPtrs.creature_spawn_template, {
    onEnter(args) {
      this._ctx = {
        template_id: args[0].toInt32(),
        pos: safeReadVec2(args[1]),
        heading: argAsF32(args[2]),
        caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
      };
    },
    onLeave(retval) {
      if (!this._ctx) return;
      writeLine({
        event: "creature_spawn_template",
        template_id: this._ctx.template_id,
        pos: this._ctx.pos,
        heading: this._ctx.heading,
        ret_ptr: retval ? retval.toString() : null,
        caller: this._ctx.caller,
      });
    },
  });

  attachHook("quest_start_selected", fnPtrs.quest_start_selected, {
    onEnter() {
      writeLine({
        event: "quest_start_selected",
        globals: readGameplayGlobalsCompact(),
      });
    },
  });

  if (CONFIG.enableSfxHooks) {
    attachHook("sfx_play", fnPtrs.sfx_play, {
      onEnter(args) {
        writeLine({
          event: "sfx_play",
          id_i32: args[0] ? args[0].toInt32() : null,
          id_f32: args[0] ? argAsF32(args[0]) : null,
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        });
      },
    });

    attachHook("sfx_play_panned", fnPtrs.sfx_play_panned, {
      onEnter(args) {
        writeLine({
          event: "sfx_play_panned",
          arg0_i32: args[0] ? args[0].toInt32() : null,
          arg0_f32: args[0] ? argAsF32(args[0]) : null,
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        });
      },
    });

    attachHook("sfx_play_exclusive", fnPtrs.sfx_play_exclusive, {
      onEnter(args) {
        writeLine({
          event: "sfx_play_exclusive",
          id_i32: args[0] ? args[0].toInt32() : null,
          id_f32: args[0] ? argAsF32(args[0]) : null,
          caller: CONFIG.includeCaller ? formatCaller(this.returnAddress) : null,
        });
      },
    });
  }
}

function installMemWatch() {
  if (!CONFIG.enableMemWatch) {
    writeLine({ event: "mem_watch_skip", reason: "disabled_by_config" });
    return;
  }

  if (typeof MemoryAccessMonitor === "undefined") {
    writeLine({ event: "mem_watch_skip", reason: "unavailable" });
    return;
  }

  const ranges = [];
  for (let i = 0; i < WATCH_RANGES.length; i++) {
    const r = WATCH_RANGES[i];
    const base = staticToRuntime(r.start);
    if (!base) continue;
    ranges.push({ base: base, size: r.size });
  }

  if (!ranges.length) {
    writeLine({ event: "mem_watch_skip", reason: "no_ranges" });
    return;
  }

  try {
    MemoryAccessMonitor.enable(ranges, {
      onAccess(details) {
        if (!details || !details.address) return;
        const operation = normalizeMemOperation(details.operation);
        if (CONFIG.memWatchWritesOnly && operation !== "write") return;
        if (!rateLimitMemEvent()) return;

        const staticVa = runtimeToStatic(details.address);
        if (staticVa == null) return;

        const range = resolveWatchRange(staticVa);
        if (!range) return;

        if (range.id === "ui_subtemplate" && !isInterestingUiState(currentStateId)) {
          return;
        }

        const valueU32 = safeReadU32(details.address);
        const valueF32 = valueU32 == null ? null : u32ToF32(valueU32);
        const symbol = WATCH_SYMBOLS[staticVa] || null;

        const evt = {
          event: "mem_watch_access",
          range: range.id,
          operation: operation,
          thread_id: details.threadId,
          address: details.address.toString(),
          static_va: toHex(staticVa, 8),
          symbol: symbol,
          value_u32: valueU32,
          value_f32: valueF32,
          state_id: currentStateId,
          state_pending: currentStatePending,
          ui_frame: uiFrame,
          gameplay_frame: gameplayFrame,
          from: details.from ? formatCaller(details.from) : null,
        };

        if (range.id === "ui_subtemplate") {
          evt.ui_decode = decodeUiOffset(staticVa - DATA.ui_subtemplate_start);
        }

        writeLine(evt);
      },
    });

    writeLine({
      event: "mem_watch_enabled",
      writes_only: CONFIG.memWatchWritesOnly,
      ranges: WATCH_RANGES,
    });
  } catch (e) {
    writeLine({ event: "mem_watch_error", error: String(e) });
  }
}

function resolvePointers() {
  for (const key in FN) {
    fnPtrs[key] = staticToRuntime(FN[key]);
  }
  for (const key in DATA) {
    dataPtrs[key] = staticToRuntime(DATA[key]);
  }
}

function startPeriodicSampler() {
  setInterval(function () {
    updateCurrentStateFromMemory();
    maybeEmitPeriodicSnapshots("interval_timer");
  }, Math.max(100, CONFIG.snapshotIntervalMs));
}

function main() {
  try {
    exeModule = Process.getModuleByName(GAME_MODULE);
  } catch (_) {
    exeModule = null;
  }

  if (!exeModule) {
    writeLine({ event: "error", error: "missing_module", module: GAME_MODULE });
    return;
  }

  resolvePointers();
  updateCurrentStateFromMemory();

  writeLine({
    event: "start",
    script: "gameplay_state_capture",
    out_path: CONFIG.outPath,
    config: {
      log_mode: CONFIG.logMode,
      include_caller: CONFIG.includeCaller,
      include_backtrace: CONFIG.includeBacktrace,
      snapshot_interval_ms: CONFIG.snapshotIntervalMs,
      full_snapshot_interval_ms: CONFIG.fullSnapshotIntervalMs,
      ui_delta_every_frames: CONFIG.uiDeltaEveryFrames,
      max_ui_delta_changes: CONFIG.maxUiDeltaChanges,
      ui_render_states: Array.from(CONFIG.uiRenderStates.values()),
      player_count: CONFIG.playerCount,
      enable_sfx_hooks: CONFIG.enableSfxHooks,
      enable_mem_watch: CONFIG.enableMemWatch,
      mem_watch_writes_only: CONFIG.memWatchWritesOnly,
      max_mem_events_per_sec: CONFIG.maxMemEventsPerSec,
      mode_tick_ms: CONFIG.modeTickMs,
    },
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
  });

  installHooks();
  installMemWatch();
  startPeriodicSampler();

  fullSnapshot("startup");
  writeLine({ event: "ready" });
}

main();
