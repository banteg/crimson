'use strict';

// Trace creature animation phase timing from the original game.
//
// Usage (attach, VM):
//   frida -n crimsonland.exe -l C:\share\frida\creature_anim_trace.js
//
// Output (JSONL):
//   C:\share\frida\creature_anim_trace.jsonl (or CRIMSON_FRIDA_DIR override)
//
// This captures a small sample of active creatures each `creature_update_all` call and logs:
//   - anim_phase before/after (via prev_phase tracking)
//   - observed delta (wrap-aware)
//   - predicted step using the decompiled formula from `creature_update_all`

const DEFAULT_LOG_DIR = 'C:\\share\\frida';

function getLogDir() {
  try {
    return Process.env.CRIMSON_FRIDA_DIR || DEFAULT_LOG_DIR;
  } catch (_) {
    return DEFAULT_LOG_DIR;
  }
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith('\\') || base.endsWith('/') ? '' : '\\';
  return base + sep + leaf;
}

const LOG_DIR = getLogDir();

function envInt(name, fallback) {
  try {
    const raw = Process.env[name];
    if (raw == null || raw === '') return fallback;
    const value = parseInt(raw, 0);
    return Number.isFinite(value) ? value : fallback;
  } catch (_) {
    return fallback;
  }
}

function envBool(name, fallback) {
  try {
    const raw = Process.env[name];
    if (raw == null || raw === '') return fallback;
    const lowered = String(raw).trim().toLowerCase();
    if (lowered === '1' || lowered === 'true' || lowered === 'yes') return true;
    if (lowered === '0' || lowered === 'false' || lowered === 'no') return false;
    return fallback;
  } catch (_) {
    return fallback;
  }
}

const CONFIG = {
  exeName: 'crimsonland.exe',
  linkBase: ptr('0x00400000'),

  logPath: joinPath(LOG_DIR, 'creature_anim_trace.jsonl'),
  logMode: 'append', // append | truncate
  logToConsole: false,

  // Sampling.
  everyNUpdates: 1, // 1 = every creature_update_all call
  maxUpdates: 0, // 0 = unlimited
  maxCreaturesPerTick: 8,

  // Filters (set to null to disable).
  // Optionally set via env vars:
  //   CRIMSON_ANIM_TYPE_ID=0
  //   CRIMSON_ANIM_CREATURE_INDEX=12
  //   CRIMSON_ANIM_ONLY_ALIVE=0
  trackTypeId: envInt('CRIMSON_ANIM_TYPE_ID', null), // e.g. 0 for zombie
  trackCreatureIndex: envInt('CRIMSON_ANIM_CREATURE_INDEX', null), // pool index
  onlyAlive: envBool('CRIMSON_ANIM_ONLY_ALIVE', true), // filters health > 0
};

const ADDR = {
  creature_update_all: 0x00426220,

  // Time globals.
  frame_dt: 0x00480840,
  frame_dt_ms: 0x00480844,
  game_time_ms: 0x00480848,

  // Pools / tables.
  creature_pool_base: 0x0049bf38,
  creature_type_table_base: 0x00482728,
};

const SIZES = {
  creature_stride: 0x98,
  creature_count: 0x180,
  creature_type_stride: 0x44,
};

const OFF = {
  creature_active_u8: 0x00,
  creature_pos_x_f32: 0x14,
  creature_pos_y_f32: 0x18,
  creature_vel_x_f32: 0x1c,
  creature_vel_y_f32: 0x20,
  creature_health_f32: 0x24,
  creature_size_f32: 0x34,
  creature_target_x_f32: 0x50,
  creature_target_y_f32: 0x54,
  creature_move_speed_f32: 0x5c,
  creature_type_id_i32: 0x6c,
  creature_flags_i32: 0x8c,
  creature_ai_mode_i32: 0x90,
  creature_anim_phase_f32: 0x94,

  type_anim_rate_f32: 0x34,
  type_base_frame_i32: 0x38,
  type_anim_flags_i32: 0x40,
};

let LOG = { file: null, ok: false };
let UPDATE_COUNT = 0;
let EVENT_COUNT = 0;

// prevPhase[index] = { phase, wrapLimit }
const prevPhase = {};

function nowIso() {
  return new Date().toISOString();
}

function initLog() {
  try {
    const mode = CONFIG.logMode === 'append' ? 'a' : 'w';
    LOG.file = new File(CONFIG.logPath, mode);
    LOG.ok = true;
  } catch (e) {
    console.log('[creature_anim_trace] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  obj.ts = nowIso();
  obj.seq = EVENT_COUNT++;
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  if (CONFIG.logToConsole) console.log(line);
}

function exePtr(staticVa) {
  const mod = Process.getModuleByName(CONFIG.exeName);
  if (!mod) return null;
  return mod.base.add(ptr(staticVa).sub(CONFIG.linkBase));
}

function safeReadU8(p) {
  try { return p.readU8(); } catch (_) { return null; }
}

function safeReadS32(p) {
  try { return p.readS32(); } catch (_) { return null; }
}

function safeReadF32(p) {
  try { return p.readFloat(); } catch (_) { return null; }
}

function creatureBase(idx) {
  const base = exePtr(ADDR.creature_pool_base);
  if (!base) return null;
  return base.add(idx * SIZES.creature_stride);
}

function readCreature(idx) {
  const b = creatureBase(idx);
  if (!b) return null;
  return {
    index: idx,
    active_u8: safeReadU8(b.add(OFF.creature_active_u8)),
    type_id_i32: safeReadS32(b.add(OFF.creature_type_id_i32)),
    flags_i32: safeReadS32(b.add(OFF.creature_flags_i32)),
    ai_mode_i32: safeReadS32(b.add(OFF.creature_ai_mode_i32)),
    pos_x_f32: safeReadF32(b.add(OFF.creature_pos_x_f32)),
    pos_y_f32: safeReadF32(b.add(OFF.creature_pos_y_f32)),
    vel_x_f32: safeReadF32(b.add(OFF.creature_vel_x_f32)),
    vel_y_f32: safeReadF32(b.add(OFF.creature_vel_y_f32)),
    target_x_f32: safeReadF32(b.add(OFF.creature_target_x_f32)),
    target_y_f32: safeReadF32(b.add(OFF.creature_target_y_f32)),
    health_f32: safeReadF32(b.add(OFF.creature_health_f32)),
    size_f32: safeReadF32(b.add(OFF.creature_size_f32)),
    move_speed_f32: safeReadF32(b.add(OFF.creature_move_speed_f32)),
    anim_phase_f32: safeReadF32(b.add(OFF.creature_anim_phase_f32)),
  };
}

function typeTableBase() {
  return exePtr(ADDR.creature_type_table_base);
}

function readTypeInfo(typeId) {
  const base = typeTableBase();
  if (!base) return null;
  if (typeId == null || typeId < 0) return null;
  const b = base.add(typeId * SIZES.creature_type_stride);
  return {
    anim_rate_f32: safeReadF32(b.add(OFF.type_anim_rate_f32)),
    base_frame_i32: safeReadS32(b.add(OFF.type_base_frame_i32)),
    anim_flags_i32: safeReadS32(b.add(OFF.type_anim_flags_i32)),
  };
}

function creatureAnimIsLongStrip(flags) {
  // long strip when (flags & 4) == 0 OR (flags & 0x40) != 0
  return (flags & 0x4) === 0 || (flags & 0x40) !== 0;
}

function computeLocalScale(creature) {
  // Matches `local_70` usage in `creature_update_all`.
  // It is only reduced in ai_mode == 5 when the link target is within 64 units.
  let scale = 1.0;
  if (!creature) return scale;
  if (creature.ai_mode_i32 !== 5) return scale;
  // In the native update loop, local_70 is computed before velocity integration.
  // `vel_x/vel_y` store the per-frame displacement (already multiplied by frame_dt),
  // so we reconstruct the pre-move position as `pos - vel`.
  const x = creature.pos_x_f32 != null && creature.vel_x_f32 != null ? (creature.pos_x_f32 - creature.vel_x_f32) : creature.pos_x_f32;
  const y = creature.pos_y_f32 != null && creature.vel_y_f32 != null ? (creature.pos_y_f32 - creature.vel_y_f32) : creature.pos_y_f32;
  const tx = creature.target_x_f32;
  const ty = creature.target_y_f32;
  if (x == null || y == null || tx == null || ty == null) return scale;
  const dx = tx - x;
  const dy = ty - y;
  const dist = Math.sqrt(dx * dx + dy * dy);
  if (dist <= 64.0) scale = dist * 0.015625; // dist / 64
  return scale;
}

function wrapDelta(prev, curr, limit) {
  if (prev == null || curr == null || limit == null) return null;
  let delta = curr - prev;
  // When wrapping occurs, curr will be much smaller than prev.
  if (delta < -0.001) {
    delta += limit;
  }
  return delta;
}

function predictStep(creature, typeInfo, frameDt) {
  if (!creature || !typeInfo) return null;
  const size = creature.size_f32;
  const moveSpeed = creature.move_speed_f32;
  const animRate = typeInfo.anim_rate_f32;
  const flags = creature.flags_i32;
  const aiMode = creature.ai_mode_i32;
  if (size == null || moveSpeed == null || animRate == null || frameDt == null) return null;
  if (size === 0.0) return 0.0;

  const longStrip = creatureAnimIsLongStrip(flags >>> 0);
  if (longStrip && aiMode === 7) return 0.0;

  const localScale = computeLocalScale(creature);
  const speedScale = 30.0 / size;
  const stripMul = longStrip ? 25.0 : 22.0;
  return animRate * moveSpeed * frameDt * speedScale * localScale * stripMul;
}

function main() {
  initLog();
  const exeMod = Process.getModuleByName(CONFIG.exeName);
  if (!exeMod) {
    writeLog({ event: 'error', error: 'missing_module', module: CONFIG.exeName });
    return;
  }

  const updatePtr = exePtr(ADDR.creature_update_all);
  const frameDtPtr = exePtr(ADDR.frame_dt);
  const frameDtMsPtr = exePtr(ADDR.frame_dt_ms);
  const gameTimeMsPtr = exePtr(ADDR.game_time_ms);
  const poolPtr = exePtr(ADDR.creature_pool_base);
  const typePtr = exePtr(ADDR.creature_type_table_base);

  if (!updatePtr || !frameDtPtr || !frameDtMsPtr || !gameTimeMsPtr || !poolPtr || !typePtr) {
    writeLog({
      event: 'error',
      error: 'missing_address',
      creature_update_all: !!updatePtr,
      frame_dt: !!frameDtPtr,
      frame_dt_ms: !!frameDtMsPtr,
      game_time_ms: !!gameTimeMsPtr,
      creature_pool_base: !!poolPtr,
      creature_type_table_base: !!typePtr,
    });
    return;
  }

  writeLog({
    event: 'start',
    exe_base: exeMod.base.toString(),
    logPath: CONFIG.logPath,
    config: CONFIG,
  });

  Interceptor.attach(updatePtr, {
    onLeave() {
      UPDATE_COUNT++;
      if (CONFIG.maxUpdates > 0 && UPDATE_COUNT > CONFIG.maxUpdates) return;
      if (CONFIG.everyNUpdates > 1 && (UPDATE_COUNT % CONFIG.everyNUpdates) !== 0) return;

      const frameDt = safeReadF32(frameDtPtr);
      const frameDtMs = safeReadS32(frameDtMsPtr);
      const gameTimeMs = safeReadS32(gameTimeMsPtr);

      let emitted = 0;
      for (let i = 0; i < SIZES.creature_count; i++) {
        if (CONFIG.trackCreatureIndex != null && i !== CONFIG.trackCreatureIndex) continue;

        const c = readCreature(i);
        if (!c) continue;
        if (!c.active_u8) continue;
        if (CONFIG.onlyAlive && !(c.health_f32 > 0.0)) continue;

        const typeId = c.type_id_i32;
        if (typeId == null) continue;
        if (CONFIG.trackTypeId != null && typeId !== CONFIG.trackTypeId) continue;

        const typeInfo = readTypeInfo(typeId);
        const flags = c.flags_i32;
        const longStrip = flags != null ? creatureAnimIsLongStrip(flags >>> 0) : null;
        const wrapLimit = longStrip ? 31.0 : 15.0;

        const prev = prevPhase[i] ? prevPhase[i].phase : null;
        const curr = c.anim_phase_f32;
        const delta = wrapDelta(prev, curr, wrapLimit);

        const stepPred = predictStep(c, typeInfo, frameDt);
        const error = delta != null && stepPred != null ? delta - stepPred : null;

        prevPhase[i] = { phase: curr, wrapLimit: wrapLimit };

        writeLog({
          event: 'creature_anim',
          update: UPDATE_COUNT,
          game_time_ms: gameTimeMs,
          frame_dt: frameDt,
          frame_dt_ms: frameDtMs,
          creature: c,
          type: typeInfo,
          derived: {
            long_strip: longStrip,
            wrap_limit: wrapLimit,
            local_scale: computeLocalScale(c),
            prev_phase: prev,
            delta_phase: delta,
            step_pred: stepPred,
            error: error,
          },
        });

        emitted++;
        if (CONFIG.trackCreatureIndex != null) break;
        if (CONFIG.maxCreaturesPerTick > 0 && emitted >= CONFIG.maxCreaturesPerTick) break;
      }
    },
  });
}

setImmediate(main);
