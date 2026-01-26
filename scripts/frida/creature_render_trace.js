'use strict';

// Trace creature_render_type draw calls (frame + color alpha) with a best-effort
// mapping back to a creature pool index.
//
// This is useful for validating death staging visuals:
//   - frame selection while hitbox_size ramps down (16..0)
//   - shadow-pass alpha vs main-pass alpha when hitbox_size goes negative
//
// Usage (attach, VM):
//   frida -n crimsonland.exe -l C:\share\frida\creature_render_trace.js
//
// Output (JSONL):
//   C:\share\frida\creature_render_trace.jsonl (or CRIMSON_FRIDA_DIR override)
//
// Env overrides:
//   CRIMSON_RENDER_TYPE_ID=2            # only log when creature_render_type(type_id) == 2
//   CRIMSON_RENDER_ONLY_DYING=1         # default true: only hitbox_size < 16.0
//   CRIMSON_RENDER_MAX_EVENTS=0         # 0 = unlimited
//   CRIMSON_RENDER_MATCH_EPS=0.75       # max per-field abs diff for draw->creature matching

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

function envFloat(name, fallback) {
  try {
    const raw = Process.env[name];
    if (raw == null || raw === '') return fallback;
    const value = parseFloat(raw);
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

const LOG_DIR = getLogDir();

const CONFIG = {
  exeName: 'crimsonland.exe',
  grimName: 'grim.dll',
  exeLinkBase: ptr('0x00400000'),

  logPath: joinPath(LOG_DIR, 'creature_render_trace.jsonl'),
  logMode: 'append', // append | truncate
  logToConsole: false,

  filterTypeId: envInt('CRIMSON_RENDER_TYPE_ID', null),
  onlyDying: envBool('CRIMSON_RENDER_ONLY_DYING', true),
  maxEvents: envInt('CRIMSON_RENDER_MAX_EVENTS', 0),
  matchEps: envFloat('CRIMSON_RENDER_MATCH_EPS', 0.75),
};

const ADDR = {
  creature_render_type: 0x00418b60,

  camera_offset_x: 0x00484fc8,
  camera_offset_y: 0x00484fcc,

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
  creature_hitbox_size_f32: 0x10,
  creature_pos_x_f32: 0x14,
  creature_pos_y_f32: 0x18,
  creature_health_f32: 0x24,
  creature_heading_f32: 0x2c,
  creature_size_f32: 0x34,
  creature_tint_r_f32: 0x3c,
  creature_tint_g_f32: 0x40,
  creature_tint_b_f32: 0x44,
  creature_tint_a_f32: 0x48,
  creature_type_id_s32: 0x6c,
  creature_flags_u32: 0x8c,
  creature_anim_phase_f32: 0x94,

  type_base_frame_s32: 0x38,
  type_anim_flags_u32: 0x40, // mirror flag in bit0
};

const GRIM_RVA = {
  grim_set_config_var: 0x06580, // (id:u32, value:u32)
  grim_set_color_ptr: 0x08040, // (float* rgba)
  grim_set_atlas_frame: 0x08230, // (atlas_size:i32, frame:i32)
  grim_set_rotation: 0x07f30, // (rotation:f32)
  grim_draw_quad: 0x08b10, // (x:f32, y:f32, w:f32, h:f32)
};

let LOG = { file: null, ok: false };
let EVENT_COUNT = 0;

// Per-thread render context while inside creature_render_type.
const ctxByTid = {};

function nowIso() {
  return new Date().toISOString();
}

function initLog() {
  try {
    const mode = CONFIG.logMode === 'append' ? 'a' : 'w';
    LOG.file = new File(CONFIG.logPath, mode);
    LOG.ok = true;
  } catch (e) {
    console.log('[creature_render_trace] Failed to open log: ' + e);
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
  return mod.base.add(ptr(staticVa).sub(CONFIG.exeLinkBase));
}

function grimPtr(rva) {
  const mod = Process.getModuleByName(CONFIG.grimName);
  if (!mod) return null;
  return mod.base.add(ptr(rva));
}

function safeReadU8(p) {
  try { return p.readU8(); } catch (_) { return null; }
}

function safeReadU32(p) {
  try { return p.readU32(); } catch (_) { return null; }
}

function safeReadS32(p) {
  try { return p.readS32(); } catch (_) { return null; }
}

function safeReadF32(p) {
  try { return p.readFloat(); } catch (_) { return null; }
}

function u32ToF32(u32) {
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  view.setUint32(0, u32 >>> 0, true);
  return view.getFloat32(0, true);
}

function argAsF32(arg) {
  // Interceptor passes args as NativePointer values. For x86 floats are 32-bit.
  return u32ToF32(arg.toUInt32());
}

function creatureBase(poolBase, idx) {
  return poolBase.add(idx * SIZES.creature_stride);
}

function readCreature(poolBase, idx) {
  const b = creatureBase(poolBase, idx);
  return {
    index: idx,
    active_u8: safeReadU8(b.add(OFF.creature_active_u8)),
    type_id_s32: safeReadS32(b.add(OFF.creature_type_id_s32)),
    flags_u32: safeReadU32(b.add(OFF.creature_flags_u32)),
    hitbox_size_f32: safeReadF32(b.add(OFF.creature_hitbox_size_f32)),
    pos_x_f32: safeReadF32(b.add(OFF.creature_pos_x_f32)),
    pos_y_f32: safeReadF32(b.add(OFF.creature_pos_y_f32)),
    size_f32: safeReadF32(b.add(OFF.creature_size_f32)),
    health_f32: safeReadF32(b.add(OFF.creature_health_f32)),
    heading_f32: safeReadF32(b.add(OFF.creature_heading_f32)),
    anim_phase_f32: safeReadF32(b.add(OFF.creature_anim_phase_f32)),
    tint_r_f32: safeReadF32(b.add(OFF.creature_tint_r_f32)),
    tint_g_f32: safeReadF32(b.add(OFF.creature_tint_g_f32)),
    tint_b_f32: safeReadF32(b.add(OFF.creature_tint_b_f32)),
    tint_a_f32: safeReadF32(b.add(OFF.creature_tint_a_f32)),
  };
}

function typeBase(typeTableBase, typeId) {
  return typeTableBase.add(typeId * SIZES.creature_type_stride);
}

function readTypeInfo(typeTableBase, typeId) {
  if (typeId == null || typeId < 0) return null;
  const b = typeBase(typeTableBase, typeId);
  return {
    base_frame_s32: safeReadS32(b.add(OFF.type_base_frame_s32)),
    anim_flags_u32: safeReadU32(b.add(OFF.type_anim_flags_u32)),
  };
}

function creatureAnimIsLongStrip(flagsU32) {
  const flags = flagsU32 >>> 0;
  return (flags & 0x4) === 0 || (flags & 0x40) !== 0;
}

function pingPongIdx(phase) {
  if (phase == null) return null;
  // Mirrors creature_render_type: idx = (__ftol(phase + 0.5) & 0x8000000f), then normalize negatives, then mirror >7.
  const raw = (phase + 0.5) | 0; // truncate toward 0
  let idx = (raw & 0x8000000f) | 0;
  if (idx < 0) idx = (((idx - 1) | 0xfffffff0) + 1) | 0;
  if (idx > 7) idx = 0x0f - idx;
  return idx;
}

function predictFrameAndAlpha({ passId, creature, typeInfo }) {
  if (!creature || !typeInfo) return null;
  const flags = creature.flags_u32 >>> 0;
  const longStrip = creatureAnimIsLongStrip(flags);
  const hitbox = creature.hitbox_size_f32;
  const phase = creature.anim_phase_f32;
  const tintA = creature.tint_a_f32;
  const baseFrame = typeInfo.base_frame_s32;
  const mirrorFlag = (typeInfo.anim_flags_u32 >>> 0) & 1;

  let frame = null;
  let alpha = null;

  if (passId === 1) {
    alpha = tintA != null ? tintA * 0.4 : null;
  } else if (passId === 5) {
    alpha = tintA != null ? tintA : null;
  }

  if (longStrip) {
    if (hitbox == null) return null;
    if (hitbox >= 16.0) {
      if (phase == null) return null;
      frame = (phase + 0.5) | 0;
      if (mirrorFlag && frame > 0x0f) frame = 0x1f - frame;
    } else if (hitbox >= 0.0) {
      if (baseFrame == null) return null;
      frame = ((baseFrame + 0x0f) - hitbox) | 0;
    } else {
      if (baseFrame == null) return null;
      frame = (baseFrame + 0x0f) | 0;
      if (alpha != null) {
        alpha += hitbox * (passId === 1 ? 0.5 : 0.1);
        if (alpha < 0.0) alpha = 0.0;
      }
    }
    if ((flags & 0x10) !== 0 && frame != null) frame = (frame + 0x20) | 0;
  } else {
    if (phase == null || baseFrame == null) return null;
    const idx = pingPongIdx(phase);
    if (idx == null) return null;
    frame = (baseFrame + 0x10 + idx) | 0;
    if (hitbox != null && hitbox < 0.0 && alpha != null) {
      alpha += hitbox * 0.1;
      if (alpha < 0.0) alpha = 0.0;
    }
  }

  if (passId === 5 && hitbox != null && hitbox < 0.0 && alpha != null) {
    // Main-pass corpse fade always uses hitbox_size * 0.1 (for both strip modes).
    // Long-strip corpse uses 0.5 only in the shadow pass.
    alpha = (tintA != null ? tintA : alpha) + hitbox * 0.1;
    if (alpha < 0.0) alpha = 0.0;
  }

  return { long_strip: longStrip, frame: frame, alpha: alpha };
}

function expectedDrawQuad(passId, creature, camera) {
  if (!creature || !camera) return null;
  const size = creature.size_f32;
  const x = creature.pos_x_f32;
  const y = creature.pos_y_f32;
  if (size == null || x == null || y == null) return null;
  if (passId === 1) {
    const half = size * 0.5 + 0.7;
    return { x: camera.x + x - half, y: camera.y + y - half, w: size * 1.07, h: size * 1.07 };
  }
  // Default to main-pass geometry (passId 5 in creature_render_type).
  const half = size * 0.5;
  return { x: camera.x + x - half, y: camera.y + y - half, w: size, h: size };
}

function maxAbsDiff(a, b) {
  if (a == null || b == null) return null;
  return Math.abs(a - b);
}

function findCreatureForDraw(poolBase, typeId, passId, quad, camera) {
  let best = null;
  const eps = CONFIG.matchEps;

  for (let idx = 0; idx < SIZES.creature_count; idx++) {
    const c = readCreature(poolBase, idx);
    if (!c || !c.active_u8) continue;
    if (c.type_id_s32 !== typeId) continue;
    if (CONFIG.onlyDying && !(c.hitbox_size_f32 < 16.0)) continue;

    const exp = expectedDrawQuad(passId, c, camera);
    if (!exp) continue;

    const dx = maxAbsDiff(quad.x, exp.x);
    const dy = maxAbsDiff(quad.y, exp.y);
    const dw = maxAbsDiff(quad.w, exp.w);
    const dh = maxAbsDiff(quad.h, exp.h);
    if (dx == null || dy == null || dw == null || dh == null) continue;
    const worst = Math.max(dx, dy, dw, dh);
    if (worst > eps) continue;

    if (!best || worst < best.worst) {
      best = { index: idx, worst: worst, expected: exp, creature: c };
    }
  }

  return best;
}

function ctxForTid(tid) {
  const key = String(tid);
  let ctx = ctxByTid[key];
  if (!ctx) {
    ctx = {
      depth: 0,
      type_id: null,
      pass_id: null, // grim_set_config_var(0x13)
      atlas: null, // { size, frame }
      color: null, // [r,g,b,a]
      rotation: null,
    };
    ctxByTid[key] = ctx;
  }
  return ctx;
}

function inCreatureRender(tid) {
  const ctx = ctxForTid(tid);
  return ctx.depth > 0;
}

function main() {
  initLog();
  const exeMod = Process.getModuleByName(CONFIG.exeName);
  const grimMod = Process.getModuleByName(CONFIG.grimName);
  if (!exeMod || !grimMod) {
    writeLog({ event: 'error', error: 'missing_module', exe: !!exeMod, grim: !!grimMod });
    return;
  }

  const renderPtr = exePtr(ADDR.creature_render_type);
  const poolPtr = exePtr(ADDR.creature_pool_base);
  const typePtr = exePtr(ADDR.creature_type_table_base);
  const camXPtr = exePtr(ADDR.camera_offset_x);
  const camYPtr = exePtr(ADDR.camera_offset_y);

  const setConfigVarPtr = grimPtr(GRIM_RVA.grim_set_config_var);
  const setColorPtr = grimPtr(GRIM_RVA.grim_set_color_ptr);
  const setAtlasFramePtr = grimPtr(GRIM_RVA.grim_set_atlas_frame);
  const setRotationPtr = grimPtr(GRIM_RVA.grim_set_rotation);
  const drawQuadPtr = grimPtr(GRIM_RVA.grim_draw_quad);

  if (!renderPtr || !poolPtr || !typePtr || !camXPtr || !camYPtr || !setConfigVarPtr || !setColorPtr || !setAtlasFramePtr || !setRotationPtr || !drawQuadPtr) {
    writeLog({
      event: 'error',
      error: 'missing_address',
      creature_render_type: !!renderPtr,
      creature_pool_base: !!poolPtr,
      creature_type_table_base: !!typePtr,
      camera_offset_x: !!camXPtr,
      camera_offset_y: !!camYPtr,
      grim_set_config_var: !!setConfigVarPtr,
      grim_set_color_ptr: !!setColorPtr,
      grim_set_atlas_frame: !!setAtlasFramePtr,
      grim_set_rotation: !!setRotationPtr,
      grim_draw_quad: !!drawQuadPtr,
    });
    return;
  }

  writeLog({
    event: 'start',
    exe_base: exeMod.base.toString(),
    grim_base: grimMod.base.toString(),
    logPath: CONFIG.logPath,
    config: CONFIG,
  });

  Interceptor.attach(renderPtr, {
    onEnter(args) {
      const tid = this.threadId;
      const ctx = ctxForTid(tid);
      ctx.depth++;
      ctx.type_id = args[0].toInt32();
      // Clear per-call state so we only use values produced during this render pass.
      ctx.pass_id = null;
      ctx.atlas = null;
      ctx.color = null;
      ctx.rotation = null;
    },
    onLeave() {
      const tid = this.threadId;
      const ctx = ctxForTid(tid);
      ctx.depth = Math.max(0, ctx.depth - 1);
      if (ctx.depth === 0) {
        ctx.type_id = null;
        ctx.pass_id = null;
        ctx.atlas = null;
        ctx.color = null;
        ctx.rotation = null;
      }
    },
  });

  Interceptor.attach(setConfigVarPtr, {
    onEnter(args) {
      const tid = this.threadId;
      if (!inCreatureRender(tid)) return;
      const id = args[0].toUInt32();
      const value = args[1].toUInt32();
      if (id !== 0x13) return;
      ctxForTid(tid).pass_id = value | 0;
    },
  });

  Interceptor.attach(setColorPtr, {
    onEnter(args) {
      const tid = this.threadId;
      if (!inCreatureRender(tid)) return;
      const p = args[0];
      try {
        const r = p.readFloat();
        const g = p.add(4).readFloat();
        const b = p.add(8).readFloat();
        const a = p.add(12).readFloat();
        ctxForTid(tid).color = [r, g, b, a];
      } catch (_) {}
    },
  });

  Interceptor.attach(setAtlasFramePtr, {
    onEnter(args) {
      const tid = this.threadId;
      if (!inCreatureRender(tid)) return;
      const atlasSize = args[0].toInt32();
      const frame = args[1].toInt32();
      ctxForTid(tid).atlas = { size: atlasSize, frame: frame };
    },
  });

  Interceptor.attach(setRotationPtr, {
    onEnter(args) {
      const tid = this.threadId;
      if (!inCreatureRender(tid)) return;
      ctxForTid(tid).rotation = argAsF32(args[0]);
    },
  });

  Interceptor.attach(drawQuadPtr, {
    onEnter(args) {
      if (CONFIG.maxEvents > 0 && EVENT_COUNT >= CONFIG.maxEvents) return;
      const tid = this.threadId;
      const ctx = ctxForTid(tid);
      if (!inCreatureRender(tid)) return;

      const typeId = ctx.type_id;
      if (typeId == null) return;
      if (CONFIG.filterTypeId != null && typeId !== CONFIG.filterTypeId) return;

      const quad = {
        x: argAsF32(args[0]),
        y: argAsF32(args[1]),
        w: argAsF32(args[2]),
        h: argAsF32(args[3]),
      };

      const passId = ctx.pass_id != null ? ctx.pass_id : -1;
      const passName = passId === 1 ? 'shadow' : (passId === 5 ? 'main' : String(passId));

      const cam = { x: safeReadF32(camXPtr) || 0.0, y: safeReadF32(camYPtr) || 0.0 };
      const match = findCreatureForDraw(poolPtr, typeId, passId, quad, cam);
      if (CONFIG.onlyDying && !match) return;

      const creature = match ? match.creature : null;
      const typeInfo = readTypeInfo(typePtr, typeId);
      const predicted = creature && typeInfo ? predictFrameAndAlpha({ passId: passId, creature: creature, typeInfo: typeInfo }) : null;

      writeLog({
        event: 'creature_draw',
        tid: tid,
        type_id: typeId,
        pass_id: passId,
        pass: passName,
        quad: quad,
        atlas: ctx.atlas,
        color: ctx.color,
        rotation: ctx.rotation,
        camera: cam,
        match: match ? { index: match.index, worst: match.worst, expected: match.expected } : null,
        creature: creature,
        type: typeInfo,
        predicted: predicted,
      });
    },
  });
}

setImmediate(main);

