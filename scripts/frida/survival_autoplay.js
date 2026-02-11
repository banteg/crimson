"use strict";

// Survival autoplay sidecar for differential capture sessions.
//
// Attach:
//   frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
//
// Behavior:
// - starts Survival automatically (config_game_mode=1 + game_state_set(9))
// - drives movement via grim.dll key-query overrides (bonus-priority kiting)
// - keeps native auto-aim path enabled (config_aim_scheme=5)
// - auto-picks perks in state 6
// - by default runs a single Survival session and stops automation on death

const DEFAULT_LOG_DIR = "C:\\share\\frida";
const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";
const LINK_BASE = ptr("0x00400000");

const WORLD_MIN = 32.0;
const WORLD_MAX = 992.0;
const WORLD_CENTER_X = 512.0;
const WORLD_CENTER_Y = 512.0;

const STRIDE = {
  player: 0x360,
  creature: 0x98,
  bonus: 0x1c,
};

const COUNTS = {
  creatures: 0x180,
  bonuses: 0x10,
};

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

function parseFloatEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const parsed = parseFloat(String(raw).trim());
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

function clamp(v, lo, hi) {
  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;
}

function clamp01(v) {
  return clamp(v, 0.0, 1.0);
}

function vec(x, y) {
  return { x: x, y: y };
}

function vAdd(a, b) {
  return { x: a.x + b.x, y: a.y + b.y };
}

function vSub(a, b) {
  return { x: a.x - b.x, y: a.y - b.y };
}

function vScale(a, s) {
  return { x: a.x * s, y: a.y * s };
}

function vLen(a) {
  return Math.sqrt(a.x * a.x + a.y * a.y);
}

function vNorm(a) {
  const m = vLen(a);
  if (m <= 1e-6) return { x: 0.0, y: 0.0 };
  return { x: a.x / m, y: a.y / m };
}

function vLerp(a, b, t) {
  return {
    x: a.x + (b.x - a.x) * t,
    y: a.y + (b.y - a.y) * t,
  };
}

function edgeDistance(p) {
  const d1 = p.x - WORLD_MIN;
  const d2 = WORLD_MAX - p.x;
  const d3 = p.y - WORLD_MIN;
  const d4 = WORLD_MAX - p.y;
  return Math.min(d1, d2, d3, d4);
}

function clampPoint(p) {
  return {
    x: clamp(p.x, WORLD_MIN, WORLD_MAX),
    y: clamp(p.y, WORLD_MIN, WORLD_MAX),
  };
}

const LOG_DIR = getEnv("CRIMSON_FRIDA_DIR") || DEFAULT_LOG_DIR;

const CONFIG = {
  outPath: joinPath(LOG_DIR, "survival_autoplay.jsonl"),

  autoStart: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_START", true),
  autoStartDelayMs: Math.max(0, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_START_DELAY_MS", 1000)),

  // Default: single run only. Avoid score-screen glitches from restart loops.
  autoRestartOnGameOver: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_RESTART", false),
  stopAfterDeath: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_STOP_AFTER_DEATH", true),
  restartDelayMs: Math.max(100, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_RESTART_DELAY_MS", 1200)),

  playerIndex: Math.max(0, Math.min(3, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PLAYER", 0))),
  forcePlayerCount: Math.max(1, Math.min(4, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PLAYER_COUNT", 1))),
  forceModeId: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_MODE", 1), // 1 = Survival

  // Use digital movement mode + native auto-aim.
  forceMoveMode: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_MOVE_MODE", 2),
  forceAimScheme: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_AIM_SCHEME", 5),

  enforceConfigEachFrame: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_ENFORCE_EACH_FRAME", true),
  keepDemoModeOff: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_DEMO_OFF", true),

  useInputOverride: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_INPUT_OVERRIDE", true),

  autoPickPerks: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_PERKS", true),
  pickPerkDelayMs: Math.max(0, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PERK_DELAY_MS", 120)),

  movementDeadzone: clamp(parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_DEADZONE", 0.30), 0.05, 0.9),
  calmThreatDistance: Math.max(20.0, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_CALM_THREAT", 180.0)),
  calmVectorThreshold: Math.max(0.01, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_CALM_VECTOR", 0.16)),
  threatRadius: Math.max(50.0, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_THREAT_RADIUS", 225.0)),
  dangerRadius: Math.max(20.0, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_DANGER_RADIUS", 90.0)),
  cornerMargin: Math.max(20.0, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_CORNER_MARGIN", 96.0)),
  bonusSeekRadius: Math.max(40.0, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_BONUS_RADIUS", 280.0)),
  bonusPriorityWeight: Math.max(0.0, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_BONUS_WEIGHT", 2.2)),
  rushMinFrames: Math.max(1, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_RUSH_FRAMES", 10)),
  rushProjectDist: Math.max(40.0, parseFloatEnv("CRIMSON_FRIDA_AUTOPLAY_RUSH_DIST", 180.0)),
  jitterHoldFrames: Math.max(0, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_JITTER_HOLD", 4)),
};

const FN = {
  perk_apply: 0x004055e0,
  gameplay_update_and_render: 0x0040aab0,
  game_over_screen_update: 0x0040ffc0,
  gameplay_reset_state: 0x00412dc0,
  game_state_set: 0x004461c0,
};

const FN_GRIM_RVA = {
  grim_is_key_active: 0x00006fe0,
  grim_was_key_pressed: 0x00007390,
};

const DATA = {
  frame_dt: 0x00480840,

  config_player_count: 0x0048035c,
  config_game_mode: 0x00480360,
  config_player_mode_flags: 0x00480364,
  config_aim_scheme: 0x0048038c,

  config_key_reload: 0x004807c4,

  perk_choice_ids: 0x004807e8,
  perk_selection_index: 0x0048089c,
  perk_pending_count: 0x00486fac,
  perk_choices_dirty: 0x00486fb0,

  creature_active_count: 0x00486fcc,
  bonus_pool: 0x00482948,

  demo_mode_active: 0x0048700d,
  ui_transition_direction: 0x0048724c,
  game_state_id: 0x00487270,
  game_state_pending: 0x00487274,

  player_pos_x: 0x004908c4,
  player_pos_y: 0x004908c8,
  player_health: 0x004908d4,

  player_move_key_forward: 0x00490bdc,
  player_move_key_backward: 0x00490be0,
  player_turn_key_left: 0x00490be4,
  player_turn_key_right: 0x00490be8,
  player_fire_key: 0x00490bec,

  creature_pool: 0x0049bf38,
};

let exeModule = null;
let grimModule = null;
let outFile = null;
let outWarned = false;

const fnPtrs = {};
const grimFnPtrs = {};
const dataPtrs = {};
const attached = {};

let fPerkApply = null;
let fGameStateSet = null;
let fGameplayResetState = null;

let grimIsKeyActiveOrig = null;
let grimWasKeyPressedOrig = null;

const RUN = {
  active: true,
  runComplete: false,
  restartScheduled: false,

  perkAppliedForCurrentScreen: false,
  lastPerkApplyMs: 0,
  lastStartMs: 0,
  perkPollTimer: null,
  perkPollExpireMs: 0,

  bindings: {
    up: 17,
    down: 31,
    left: 30,
    right: 32,
    fire: 0x100,
    reload: 0x102,
  },

  movement: {
    up: false,
    down: false,
    left: false,
    right: false,
    fire: true,
  },

  smoothDir: { x: 0.0, y: 0.0 },
  keyMask: 0,
  keyHoldTicks: 0,

  orbitSign: 1,
  lastOrbitEvalMs: 0,

  rushTicksLeft: 0,
  rushDir: { x: 0.0, y: 0.0 },

  syntheticDownByCode: {},
};

function resolveAbi() {
  if (Process.platform !== "windows") return null;
  if (Process.arch === "x64") return "win64";
  if (Process.arch === "ia32") return "mscdecl";
  return null;
}

function openOutFile() {
  if (outFile !== null) return;
  try {
    outFile = new File(CONFIG.outPath, "a");
  } catch (_) {
    outFile = null;
  }
}

function writeLog(obj) {
  const payload = Object.assign({ ts_ms: nowMs(), ts_iso: nowIso(), script: "survival_autoplay" }, obj);
  const line = JSON.stringify(payload) + "\n";
  let wrote = false;
  try {
    openOutFile();
    if (outFile) {
      outFile.write(line);
      wrote = true;
    }
  } catch (_) {}
  if (!wrote && !outWarned) {
    outWarned = true;
    console.log("survival_autoplay: file logging unavailable, console only");
  }
  console.log(line.trim());
}

function toRuntimePtr(staticVa) {
  if (!exeModule) return null;
  try {
    return exeModule.base.add(ptr(staticVa).sub(LINK_BASE));
  } catch (_) {
    return null;
  }
}

function toGrimRuntimePtr(rva) {
  if (!grimModule) return null;
  try {
    return grimModule.base.add(rva);
  } catch (_) {
    return null;
  }
}

function readS32Ptr(p) {
  if (!p) return null;
  try {
    return p.readS32();
  } catch (_) {
    return null;
  }
}

function readU8Ptr(p) {
  if (!p) return null;
  try {
    return p.readU8();
  } catch (_) {
    return null;
  }
}

function readF32Ptr(p) {
  if (!p) return null;
  try {
    return p.readFloat();
  } catch (_) {
    return null;
  }
}

function writeS32Ptr(p, value) {
  if (!p) return false;
  try {
    p.writeS32(value | 0);
    return true;
  } catch (_) {
    return false;
  }
}

function writeU8Ptr(p, value) {
  if (!p) return false;
  try {
    p.writeU8(value & 0xff);
    return true;
  } catch (_) {
    return false;
  }
}

function readS32(name) {
  return readS32Ptr(dataPtrs[name]);
}

function readF32(name) {
  return readF32Ptr(dataPtrs[name]);
}

function writeS32IfDifferent(name, value) {
  const p = dataPtrs[name];
  if (!p) return false;
  const cur = readS32Ptr(p);
  if (cur === (value | 0)) return false;
  return writeS32Ptr(p, value);
}

function playerDataPtr(name, playerIndex) {
  const base = dataPtrs[name];
  if (!base) return null;
  const idx = Math.max(0, Math.min(3, playerIndex | 0));
  return base.add(idx * STRIDE.player);
}

function readPlayerI32(name, playerIndex) {
  return readS32Ptr(playerDataPtr(name, playerIndex));
}

function readPlayerF32(name, playerIndex) {
  return readF32Ptr(playerDataPtr(name, playerIndex));
}

function writePlayerS32IfDifferent(name, playerIndex, value) {
  const p = playerDataPtr(name, playerIndex);
  if (!p) return false;
  const cur = readS32Ptr(p);
  if (cur === (value | 0)) return false;
  return writeS32Ptr(p, value);
}

function enforceAutoplayConfig(reason) {
  let changed = false;
  changed = writeS32IfDifferent("config_game_mode", CONFIG.forceModeId) || changed;
  changed = writeS32IfDifferent("config_player_count", CONFIG.forcePlayerCount) || changed;

  changed = writePlayerS32IfDifferent("config_player_mode_flags", CONFIG.playerIndex, CONFIG.forceMoveMode) || changed;
  changed = writePlayerS32IfDifferent("config_aim_scheme", CONFIG.playerIndex, CONFIG.forceAimScheme) || changed;

  if (CONFIG.keepDemoModeOff) {
    const demoPtr = dataPtrs.demo_mode_active;
    const demoVal = readU8Ptr(demoPtr);
    if (demoVal && writeU8Ptr(demoPtr, 0)) changed = true;
  }

  if (changed && reason !== "frame") {
    writeLog({
      event: "config_enforced",
      reason,
      game_mode: readS32("config_game_mode"),
      player_count: readS32("config_player_count"),
      move_mode: readPlayerI32("config_player_mode_flags", CONFIG.playerIndex),
      aim_scheme: readPlayerI32("config_aim_scheme", CONFIG.playerIndex),
    });
  }

  return changed;
}

function readCurrentBindings() {
  const idx = CONFIG.playerIndex;
  const up = readPlayerI32("player_move_key_forward", idx);
  const down = readPlayerI32("player_move_key_backward", idx);
  const left = readPlayerI32("player_turn_key_left", idx);
  const right = readPlayerI32("player_turn_key_right", idx);
  const fire = readPlayerI32("player_fire_key", idx);
  const reload = readS32("config_key_reload");

  if (up != null) RUN.bindings.up = up;
  if (down != null) RUN.bindings.down = down;
  if (left != null) RUN.bindings.left = left;
  if (right != null) RUN.bindings.right = right;
  if (fire != null) RUN.bindings.fire = fire;
  if (reload != null) RUN.bindings.reload = reload;
}

function getPlayerPos() {
  const x = readPlayerF32("player_pos_x", CONFIG.playerIndex);
  const y = readPlayerF32("player_pos_y", CONFIG.playerIndex);
  if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
  return { x: x, y: y };
}

function getPlayerHealth() {
  return readPlayerF32("player_health", CONFIG.playerIndex);
}

function collectCreatures() {
  const out = [];
  const base = dataPtrs.creature_pool;
  if (!base) return out;

  const limit = COUNTS.creatures;
  for (let i = 0; i < limit; i++) {
    const p = base.add(i * STRIDE.creature);
    const active = readU8Ptr(p.add(0x08));
    if (!active) continue;
    const health = readF32Ptr(p.add(0x24));
    if (!Number.isFinite(health) || health <= 0.0) continue;
    const x = readF32Ptr(p.add(0x14));
    const y = readF32Ptr(p.add(0x18));
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
    out.push({ x: x, y: y });
  }
  return out;
}

function collectBonuses() {
  const out = [];
  const base = dataPtrs.bonus_pool;
  if (!base) return out;

  for (let i = 0; i < COUNTS.bonuses; i++) {
    const p = base.add(i * STRIDE.bonus);
    const bonusId = readS32Ptr(p);
    const state = readS32Ptr(p.add(0x04));
    if (!Number.isFinite(bonusId) || bonusId <= 0) continue;
    if (!Number.isFinite(state) || state <= 0) continue;
    const x = readF32Ptr(p.add(0x10));
    const y = readF32Ptr(p.add(0x14));
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
    out.push({ id: bonusId | 0, x: x, y: y });
  }

  return out;
}

function nearestDistFrom(point, creatures) {
  let best = 1e9;
  for (let i = 0; i < creatures.length; i++) {
    const c = creatures[i];
    const dx = point.x - c.x;
    const dy = point.y - c.y;
    const d = Math.sqrt(dx * dx + dy * dy);
    if (d < best) best = d;
  }
  return best;
}

function projectedSafetyScore(point, creatures) {
  const p = clampPoint(point);
  const nearest = nearestDistFrom(p, creatures);
  const wall = edgeDistance(p);
  const centerDx = WORLD_CENTER_X - p.x;
  const centerDy = WORLD_CENTER_Y - p.y;
  const centerDist = Math.sqrt(centerDx * centerDx + centerDy * centerDy);
  let score = nearest * 1.7 + wall * 0.8 - centerDist * 0.2;
  if (wall < 50.0) score -= (50.0 - wall) * 1.8;
  return score;
}

function chooseRushDirection(pos, creatures) {
  let bestDir = { x: 0.0, y: 0.0 };
  let bestScore = -1e9;

  for (let i = 0; i < 16; i++) {
    const a = (Math.PI * 2.0 * i) / 16.0;
    const dir = { x: Math.cos(a), y: Math.sin(a) };
    const projected = clampPoint(vAdd(pos, vScale(dir, CONFIG.rushProjectDist)));
    const score = projectedSafetyScore(projected, creatures);
    if (score > bestScore) {
      bestScore = score;
      bestDir = dir;
    }
  }

  return bestDir;
}

function movementMaskFromDir(dir) {
  const dz = CONFIG.movementDeadzone;
  const x = Math.abs(dir.x) < dz ? 0.0 : dir.x;
  const y = Math.abs(dir.y) < dz ? 0.0 : dir.y;

  let mask = 0;
  if (y < 0.0) mask |= 1; // up
  if (y > 0.0) mask |= 2; // down
  if (x < 0.0) mask |= 4; // left
  if (x > 0.0) mask |= 8; // right
  return mask;
}

function updateMovementPlan() {
  if (!RUN.active || RUN.runComplete) {
    RUN.movement.up = false;
    RUN.movement.down = false;
    RUN.movement.left = false;
    RUN.movement.right = false;
    RUN.movement.fire = false;
    RUN.keyMask = 0;
    return;
  }

  const gameState = readS32("game_state_id");
  const health = getPlayerHealth();
  if (gameState !== 9 || !Number.isFinite(health) || health <= 0.0) {
    RUN.movement.up = false;
    RUN.movement.down = false;
    RUN.movement.left = false;
    RUN.movement.right = false;
    RUN.movement.fire = false;
    RUN.keyMask = 0;
    return;
  }

  const pos = getPlayerPos();
  if (!pos) return;

  const creatures = collectCreatures();
  const bonuses = collectBonuses();

  let repel = vec(0.0, 0.0);
  let nearest = 1e9;
  let nearestCreature = null;
  let dangerCount = 0;

  for (let i = 0; i < creatures.length; i++) {
    const c = creatures[i];
    const dx = pos.x - c.x;
    const dy = pos.y - c.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist < nearest) {
      nearest = dist;
      nearestCreature = c;
    }
    if (dist < CONFIG.dangerRadius) dangerCount += 1;

    if (dist < CONFIG.threatRadius && dist > 1e-4) {
      const away = { x: dx / dist, y: dy / dist };
      let w = (CONFIG.threatRadius - dist) / CONFIG.threatRadius;
      w = w * w;
      repel = vAdd(repel, vScale(away, w));
    }
  }

  let tangent = vec(0.0, 0.0);
  if (nearestCreature) {
    const away = vNorm(vSub(pos, nearestCreature));
    const perpA = { x: -away.y, y: away.x };
    const perpB = { x: away.y, y: -away.x };

    const t = nowMs();
    if (t - RUN.lastOrbitEvalMs > 700 || nearest < CONFIG.dangerRadius) {
      const scoreA = projectedSafetyScore(vAdd(pos, vScale(perpA, 96.0)), creatures);
      const scoreB = projectedSafetyScore(vAdd(pos, vScale(perpB, 96.0)), creatures);
      RUN.orbitSign = scoreA >= scoreB ? 1 : -1;
      RUN.lastOrbitEvalMs = t;
    }

    tangent = RUN.orbitSign > 0 ? perpA : perpB;
  }

  let bonusTarget = null;
  let bonusVec = vec(0.0, 0.0);
  let bestBonusScore = -1e9;
  for (let i = 0; i < bonuses.length; i++) {
    const b = bonuses[i];
    const dx = b.x - pos.x;
    const dy = b.y - pos.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    if (dist > CONFIG.bonusSeekRadius || dist <= 1e-4) continue;

    const hereSafety = projectedSafetyScore(pos, creatures);
    const thereSafety = projectedSafetyScore({ x: b.x, y: b.y }, creatures);
    const safetyGain = thereSafety - hereSafety;

    if (dangerCount >= 3 && safetyGain < -25.0 && dist > 120.0) continue;

    const proximity = (CONFIG.bonusSeekRadius - dist) / CONFIG.bonusSeekRadius;
    const score = proximity * CONFIG.bonusPriorityWeight + safetyGain * 0.01;
    if (score > bestBonusScore) {
      bestBonusScore = score;
      bonusTarget = b;
      bonusVec = vScale(vNorm({ x: dx, y: dy }), 1.0 + proximity);
    }
  }

  const toCenter = vSub(vec(WORLD_CENTER_X, WORLD_CENTER_Y), pos);
  const centerDist = vLen(toCenter);
  const centerDir = vNorm(toCenter);
  const wallDist = edgeDistance(pos);

  let centerWeight = 0.0;
  if (wallDist < CONFIG.cornerMargin) {
    centerWeight = 1.2;
  } else if (centerDist > 260.0) {
    centerWeight = 0.45;
  }
  if (wallDist < CONFIG.cornerMargin && dangerCount >= 2) centerWeight += 0.55;

  const tangentWeight = nearest < 140.0 ? 1.05 : 0.7;

  let desired = vec(0.0, 0.0);
  desired = vAdd(desired, vScale(repel, 1.8));
  desired = vAdd(desired, vScale(tangent, tangentWeight));
  if (bonusTarget) desired = vAdd(desired, vScale(bonusVec, 1.7));
  desired = vAdd(desired, vScale(centerDir, centerWeight));

  const trapped = dangerCount >= 4 || nearest < 70.0 || (wallDist < 75.0 && dangerCount >= 2);
  if (trapped && creatures.length > 0 && RUN.rushTicksLeft <= 0) {
    RUN.rushDir = chooseRushDirection(pos, creatures);
    RUN.rushTicksLeft = CONFIG.rushMinFrames;
    writeLog({ event: "rush_start", nearest_dist: nearest, danger_count: dangerCount });
  }

  if (RUN.rushTicksLeft > 0) {
    RUN.rushTicksLeft -= 1;
    desired = vAdd(vScale(RUN.rushDir, 2.0), vScale(centerDir, 0.45));
    if (bonusTarget) desired = vAdd(desired, vScale(bonusVec, 0.5));
  }

  if (!bonusTarget && RUN.rushTicksLeft <= 0 && nearest > CONFIG.calmThreatDistance && vLen(desired) < CONFIG.calmVectorThreshold) {
    desired = vec(0.0, 0.0);
  } else {
    desired = vNorm(desired);
  }

  const alpha = RUN.rushTicksLeft > 0 ? 0.7 : 0.35;
  let smooth = vLerp(RUN.smoothDir, desired, alpha);
  if (vLen(desired) < 1e-5) {
    smooth = vScale(RUN.smoothDir, 0.72);
    if (vLen(smooth) < 0.08) smooth = vec(0.0, 0.0);
  }
  RUN.smoothDir = vNorm(smooth);

  let nextMask = movementMaskFromDir(RUN.smoothDir);
  if (
    nextMask !== RUN.keyMask &&
    RUN.rushTicksLeft <= 0 &&
    !bonusTarget &&
    nearest > CONFIG.dangerRadius &&
    CONFIG.jitterHoldFrames > 0
  ) {
    if (RUN.keyHoldTicks < CONFIG.jitterHoldFrames) {
      RUN.keyHoldTicks += 1;
      nextMask = RUN.keyMask;
    } else {
      RUN.keyHoldTicks = 0;
    }
  } else {
    RUN.keyHoldTicks = 0;
  }

  RUN.keyMask = nextMask;

  RUN.movement.up = (nextMask & 1) !== 0;
  RUN.movement.down = (nextMask & 2) !== 0;
  RUN.movement.left = (nextMask & 4) !== 0;
  RUN.movement.right = (nextMask & 8) !== 0;
  RUN.movement.fire = creatures.length > 0;
}

function syntheticKeyDownForCode(code) {
  if (!RUN.active || RUN.runComplete || !CONFIG.useInputOverride) return null;
  const gameState = readS32("game_state_id");
  if (gameState !== 9) return null;

  const k = code | 0;
  if (k === RUN.bindings.up) return RUN.movement.up ? 1 : 0;
  if (k === RUN.bindings.down) return RUN.movement.down ? 1 : 0;
  if (k === RUN.bindings.left) return RUN.movement.left ? 1 : 0;
  if (k === RUN.bindings.right) return RUN.movement.right ? 1 : 0;
  if (k === RUN.bindings.fire) return RUN.movement.fire ? 1 : 0;

  return null;
}

function recordSyntheticDown(code, down) {
  RUN.syntheticDownByCode[String(code | 0)] = !!down;
}

function wasSyntheticPressed(code, down) {
  const key = String(code | 0);
  const prev = !!RUN.syntheticDownByCode[key];
  const cur = !!down;
  RUN.syntheticDownByCode[key] = cur;
  return cur && !prev ? 1 : 0;
}

function pickPerkChoice() {
  const selected = readS32("perk_selection_index");
  const choiceBase = dataPtrs.perk_choice_ids;
  if (!choiceBase) return null;

  function choiceAt(index) {
    if (index < 0 || index >= 7) return null;
    return readS32Ptr(choiceBase.add(index * 4));
  }

  if (selected != null && selected >= 0 && selected < 7) {
    const perkId = choiceAt(selected);
    if (perkId != null) return { perk_id: perkId, index: selected, source: "selected" };
  }

  for (let i = 0; i < 7; i++) {
    const perkId = choiceAt(i);
    if (perkId != null) return { perk_id: perkId, index: i, source: "fallback_first" };
  }

  return null;
}

function stopPerkPoll() {
  if (RUN.perkPollTimer !== null) {
    try {
      clearInterval(RUN.perkPollTimer);
    } catch (_) {}
    RUN.perkPollTimer = null;
  }
}

function startPerkPoll(reason) {
  if (!CONFIG.autoPickPerks) return;
  if (RUN.perkPollTimer !== null) return;

  RUN.perkPollExpireMs = nowMs() + 5000;
  RUN.perkPollTimer = setInterval(function () {
    if (!RUN.active || RUN.runComplete) {
      stopPerkPoll();
      return;
    }

    const state = readS32("game_state_id");
    if (state !== 6) {
      if (state === 9 || state === 7) stopPerkPoll();
      return;
    }

    applyPerkAndResume(reason);
    if (RUN.perkAppliedForCurrentScreen) {
      stopPerkPoll();
      return;
    }

    if (nowMs() >= RUN.perkPollExpireMs) {
      writeLog({ event: "perk_poll_timeout", reason });
      stopPerkPoll();
    }
  }, 40);
}

function applyPerkAndResume(reason) {
  if (!CONFIG.autoPickPerks || !fPerkApply) return false;

  const gameState = readS32("game_state_id");
  if (gameState !== 6) return false;

  if (RUN.perkAppliedForCurrentScreen) return false;

  const t = nowMs();
  if (t - RUN.lastPerkApplyMs < CONFIG.pickPerkDelayMs) return false;

  const pending = readS32("perk_pending_count");
  if (pending != null && pending < 0) return false;

  const pick = pickPerkChoice();
  if (!pick || pick.perk_id == null) {
    writeLog({ event: "perk_pick_skip", reason, pending, error: "no_choice" });
    return false;
  }

  try {
    fPerkApply(pick.perk_id | 0);
  } catch (e) {
    writeLog({ event: "perk_pick_error", reason, error: String(e) });
    return false;
  }

  if (pending != null && pending > 0) writeS32Ptr(dataPtrs.perk_pending_count, pending - 1);
  writeU8Ptr(dataPtrs.perk_choices_dirty, 1);
  writeS32Ptr(dataPtrs.ui_transition_direction, 0);
  writeS32Ptr(dataPtrs.game_state_pending, 9);

  RUN.perkAppliedForCurrentScreen = true;
  RUN.lastPerkApplyMs = t;

  writeLog({
    event: "perk_auto_apply",
    reason,
    perk_id: pick.perk_id,
    choice_index: pick.index,
    choice_source: pick.source,
    pending_before: pending,
    pending_after: pending == null ? null : Math.max(0, pending - 1),
  });

  return true;
}

function clearSyntheticInput() {
  RUN.movement.up = false;
  RUN.movement.down = false;
  RUN.movement.left = false;
  RUN.movement.right = false;
  RUN.movement.fire = false;
  RUN.keyMask = 0;
  RUN.keyHoldTicks = 0;
  RUN.smoothDir = { x: 0.0, y: 0.0 };
  RUN.syntheticDownByCode = {};
}

function startSurvival(reason) {
  RUN.runComplete = false;
  RUN.active = true;
  RUN.perkAppliedForCurrentScreen = false;
  RUN.rushTicksLeft = 0;
  stopPerkPoll();
  clearSyntheticInput();

  enforceAutoplayConfig(reason);

  try {
    if (fGameplayResetState) fGameplayResetState();
  } catch (e) {
    writeLog({ event: "start_error", reason, stage: "gameplay_reset_state", error: String(e) });
  }

  try {
    if (fGameStateSet) fGameStateSet(9);
  } catch (e) {
    writeLog({ event: "start_error", reason, stage: "game_state_set", error: String(e) });
    return false;
  }

  RUN.lastStartMs = nowMs();

  writeLog({
    event: "survival_start",
    reason,
    game_mode: readS32("config_game_mode"),
    player_count: readS32("config_player_count"),
    move_mode: readPlayerI32("config_player_mode_flags", CONFIG.playerIndex),
    aim_scheme: readPlayerI32("config_aim_scheme", CONFIG.playerIndex),
    game_state_id: readS32("game_state_id"),
  });

  return true;
}

function scheduleRestart(reason) {
  if (RUN.restartScheduled || !CONFIG.autoRestartOnGameOver) return;
  RUN.restartScheduled = true;

  writeLog({
    event: "survival_restart_scheduled",
    reason,
    delay_ms: CONFIG.restartDelayMs,
  });

  setTimeout(function () {
    RUN.restartScheduled = false;
    startSurvival("auto_restart_game_over");
  }, CONFIG.restartDelayMs);
}

function onDeathDetected(source) {
  if (RUN.runComplete) return;

  RUN.runComplete = true;
  RUN.perkAppliedForCurrentScreen = false;
  RUN.rushTicksLeft = 0;
  stopPerkPoll();

  if (CONFIG.stopAfterDeath) {
    RUN.active = false;
    clearSyntheticInput();
    writeLog({ event: "run_complete", source, action: "stopped" });
    return;
  }

  writeLog({ event: "run_complete", source, action: CONFIG.autoRestartOnGameOver ? "restart" : "idle" });
  if (CONFIG.autoRestartOnGameOver) scheduleRestart(source);
}

function attachOnce(name, addr, handlers) {
  if (!addr || attached[name]) return;
  attached[name] = true;
  try {
    Interceptor.attach(addr, handlers);
    writeLog({ event: "attach", name, addr: addr.toString() });
  } catch (e) {
    writeLog({ event: "attach_error", name, addr: addr.toString(), error: String(e) });
  }
}

function installGrimInputOverrides() {
  if (!CONFIG.useInputOverride) {
    writeLog({ event: "input_override_disabled" });
    return;
  }

  if (!grimFnPtrs.grim_is_key_active || !grimFnPtrs.grim_was_key_pressed) {
    writeLog({
      event: "input_override_skip",
      reason: "grim_functions_missing",
      has_is_key_active: !!grimFnPtrs.grim_is_key_active,
      has_was_key_pressed: !!grimFnPtrs.grim_was_key_pressed,
    });
    return;
  }

  const abi = resolveAbi();
  grimIsKeyActiveOrig = abi
    ? new NativeFunction(grimFnPtrs.grim_is_key_active, "int", ["int"], abi)
    : new NativeFunction(grimFnPtrs.grim_is_key_active, "int", ["int"]);
  grimWasKeyPressedOrig = abi
    ? new NativeFunction(grimFnPtrs.grim_was_key_pressed, "int", ["int"], abi)
    : new NativeFunction(grimFnPtrs.grim_was_key_pressed, "int", ["int"]);

  Interceptor.replace(
    grimFnPtrs.grim_is_key_active,
    new NativeCallback(function (keyCode) {
      const synthetic = syntheticKeyDownForCode(keyCode | 0);
      if (synthetic == null) return grimIsKeyActiveOrig(keyCode | 0);
      recordSyntheticDown(keyCode | 0, synthetic !== 0);
      return synthetic;
    }, "int", ["int"]),
  );

  Interceptor.replace(
    grimFnPtrs.grim_was_key_pressed,
    new NativeCallback(function (keyCode) {
      const synthetic = syntheticKeyDownForCode(keyCode | 0);
      if (synthetic == null) return grimWasKeyPressedOrig(keyCode | 0);
      return wasSyntheticPressed(keyCode | 0, synthetic !== 0);
    }, "int", ["int"]),
  );

  writeLog({ event: "input_override_installed" });
}

function main() {
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
    writeLog({ event: "error", error: "missing_module", module: GAME_MODULE });
    return;
  }

  for (const key in FN) fnPtrs[key] = toRuntimePtr(FN[key]);
  for (const key in FN_GRIM_RVA) grimFnPtrs[key] = toGrimRuntimePtr(FN_GRIM_RVA[key]);
  for (const key in DATA) dataPtrs[key] = toRuntimePtr(DATA[key]);

  const abi = resolveAbi();
  fPerkApply = fnPtrs.perk_apply
    ? abi
      ? new NativeFunction(fnPtrs.perk_apply, "void", ["int"], abi)
      : new NativeFunction(fnPtrs.perk_apply, "void", ["int"])
    : null;

  fGameStateSet = fnPtrs.game_state_set
    ? abi
      ? new NativeFunction(fnPtrs.game_state_set, "void", ["int"], abi)
      : new NativeFunction(fnPtrs.game_state_set, "void", ["int"])
    : null;

  fGameplayResetState = fnPtrs.gameplay_reset_state
    ? abi
      ? new NativeFunction(fnPtrs.gameplay_reset_state, "void", [], abi)
      : new NativeFunction(fnPtrs.gameplay_reset_state, "void", [])
    : null;

  writeLog({
    event: "start",
    config: CONFIG,
    process: { pid: Process.id, platform: Process.platform, arch: Process.arch },
    exe: { base: exeModule.base.toString(), size: exeModule.size, path: exeModule.path },
    grim: grimModule ? { base: grimModule.base.toString(), size: grimModule.size } : null,
    ptrs: {
      game_state_set: !!fnPtrs.game_state_set,
      gameplay_reset_state: !!fnPtrs.gameplay_reset_state,
      perk_apply: !!fnPtrs.perk_apply,
      gameplay_update_and_render: !!fnPtrs.gameplay_update_and_render,
      game_over_screen_update: !!fnPtrs.game_over_screen_update,
      grim_is_key_active: !!grimFnPtrs.grim_is_key_active,
      grim_was_key_pressed: !!grimFnPtrs.grim_was_key_pressed,
    },
    out_path: CONFIG.outPath,
  });

  if (!fGameStateSet || !fGameplayResetState || !fPerkApply) {
    writeLog({
      event: "error",
      error: "required_function_missing",
      has_game_state_set: !!fGameStateSet,
      has_gameplay_reset_state: !!fGameplayResetState,
      has_perk_apply: !!fPerkApply,
    });
    return;
  }

  installGrimInputOverrides();

  attachOnce("game_state_set", fnPtrs.game_state_set, {
    onEnter(args) {
      const nextState = args[0].toInt32();
      if (nextState === 6) {
        RUN.perkAppliedForCurrentScreen = false;
        startPerkPoll("state_6_enter");
      }
      if (nextState === 9) {
        RUN.perkAppliedForCurrentScreen = false;
        RUN.rushTicksLeft = 0;
        stopPerkPoll();
      }
      if (nextState !== 7) RUN.restartScheduled = false;
    },
  });

  attachOnce("gameplay_update_and_render", fnPtrs.gameplay_update_and_render, {
    onEnter() {
      if (RUN.active && CONFIG.enforceConfigEachFrame) enforceAutoplayConfig("frame");
      const health = getPlayerHealth();
      if (Number.isFinite(health) && health <= 0.0) onDeathDetected("health_zero");
      readCurrentBindings();
      updateMovementPlan();
      applyPerkAndResume("gameplay_tick");
    },
  });

  attachOnce("game_over_screen_update", fnPtrs.game_over_screen_update, {
    onEnter() {
      onDeathDetected("game_over_screen_update");
    },
  });

  if (CONFIG.autoStart) {
    setTimeout(function () {
      startSurvival("auto_start");
    }, CONFIG.autoStartDelayMs);
  } else {
    writeLog({ event: "auto_start_disabled" });
  }
}

main();
