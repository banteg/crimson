'use strict';

// fx_queue_render_trace.js - Trace corpse decal baking into the terrain render target.
//
// Goal:
//   Capture the exact runtime ordering + blending used when baking corpses into the
//   "ground" render target (terrain RT). This is the pass that can make corpses
//   look too dark if the shadow/imprint blend or ordering is wrong.
//
// Usage (attach-only, VM):
//   frida -n crimsonland.exe -l C:\share\frida\fx_queue_render_trace.js
//
// Output (JSONL):
//   C:\share\frida\fx_queue_render_trace.jsonl (or CRIMSON_FRIDA_DIR override)
//
// Env overrides:
//   CRIMSON_FXTRACE_INCLUDE_NON_ROTATED=1   # also log non-rotated FX queue draws
//   CRIMSON_FXTRACE_DUMP_ROTATED_QUEUE=1    # include rotated queue snapshot on enter (default 1)
//   CRIMSON_FXTRACE_BACKTRACE=1             # include fuzzy backtraces on draw calls (expensive)
//   CRIMSON_FXTRACE_MAX_EVENTS=20000        # stop writing after N events (0 = unlimited)
//   CRIMSON_FXTRACE_CONSOLE=1               # also print JSONL lines to console

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

  logPath: joinPath(LOG_DIR, 'fx_queue_render_trace.jsonl'),
  logMode: 'append', // append | truncate

  includeNonRotated: envBool('CRIMSON_FXTRACE_INCLUDE_NON_ROTATED', false),
  dumpRotatedQueue: envBool('CRIMSON_FXTRACE_DUMP_ROTATED_QUEUE', true),
  includeBacktrace: envBool('CRIMSON_FXTRACE_BACKTRACE', false),
  maxEvents: envInt('CRIMSON_FXTRACE_MAX_EVENTS', 0),
  logToConsole: envBool('CRIMSON_FXTRACE_CONSOLE', false),
};

const EXE_ADDR = {
  fx_queue_add_rotated: 0x00427840,
  fx_queue_render: 0x00427920,
};

const EXE_DATA = {
  fx_queue_count: 0x004aaf18,
  fx_queue_rotated_count: 0x004aaf3c,

  terrain_texture_failed: 0x004871c8,
  config_texture_scale: 0x004803b8,
  terrain_render_target: 0x0048f530,

  particles_texture: 0x0048f7ec,
  bodyset_texture: 0x0048f7dc,

  cv_terrainBodiesTransparency: 0x00480860, // void* cvar, float value at +0xc

  // Rotated queue storage (SoA / interleaved structs; see docs/structs/effects.md).
  fx_rotated_pos: 0x00490430, // {x,y} pairs, stride 8
  fx_rotated_scale: 0x004906a8, // float[count]
  fx_rotated_rotation: 0x0049669c, // float[count]
  fx_rotated_effect_id: 0x0049ba30, // int[count] (creature_type_id)
  fx_rotated_color: 0x0049bb38, // {r,g,b,a} quads, stride 16

  // Creature type table: corpse frame at +0x3c, stride 0x44.
  creature_type_corpse_frame: 0x00482764,
  creature_type_stride: 0x44,
};

const GRIM_RVA = {
  set_config_var: 0x06580, // (id:u32, value:u32)
  set_render_target: 0x06d50, // (target_index:i32)
  bind_texture: 0x07830, // (handle:i32, stage:i32)
  begin_batch: 0x07ac0,
  end_batch: 0x07b20,
  set_rotation: 0x07f30, // (radians:f32)
  set_color: 0x07f90, // (r,g,b,a:f32)
  set_color_ptr: 0x08040, // (float* rgba)
  set_uv: 0x08350, // (u0,v0,u1,v1:f32)
  draw_quad: 0x08b10, // (x,y,w,h:f32)
};

// grim.dll internals (from analysis/ghidra/maps/data_map.json; used for texture name resolution)
const GRIM_DATA_RVAS = {
  texture_slots: 0x5d404,
};

const RUNTIME = {
  enabled: true,
  includeBacktrace: CONFIG.includeBacktrace,
};

let LOG = { file: null, ok: false };
let SEQ = 0;
let FX_CALL_ID = 0;
let ATTACHED = false;

// Per-thread context while inside fx_queue_render.
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
    console.log('[fx_queue_render_trace] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  if (!RUNTIME.enabled) return;
  if (CONFIG.maxEvents > 0 && SEQ >= CONFIG.maxEvents) {
    RUNTIME.enabled = false;
    console.log('[fx_queue_render_trace] max events reached; disabling logging');
    return;
  }
  obj.ts = nowIso();
  obj.seq = SEQ++;
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

function safeReadS32(p) {
  try { return p.readS32(); } catch (_) { return null; }
}

function safeReadU32(p) {
  try { return p.readU32(); } catch (_) { return null; }
}

function safeReadF32(p) {
  try { return p.readFloat(); } catch (_) { return null; }
}

function safeReadPtr(p) {
  try { return p.readPointer(); } catch (_) { return null; }
}

function isReadable(p) {
  try {
    const r = Process.findRangeByAddress(p);
    return !!r && r.protection.indexOf('r') !== -1;
  } catch (_) {
    return false;
  }
}

function safeReadCString(p) {
  try {
    if (!p || p.isNull()) return null;
    if (!isReadable(p)) return null;
    return p.readCString();
  } catch (_) {
    return null;
  }
}

function getStackPointer(ctx) {
  if (!ctx) return null;
  if (ctx.esp !== undefined) return ctx.esp;
  if (ctx.sp !== undefined) return ctx.sp;
  return null;
}

function u32ToF32(u32) {
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  view.setUint32(0, u32 >>> 0, true);
  return view.getFloat32(0, true);
}

function readStackS32(invocation, offset) {
  try {
    const sp = getStackPointer(invocation.context);
    if (sp === null) return null;
    return sp.add(offset).readS32();
  } catch (_) {
    return null;
  }
}

function readStackU32(invocation, offset) {
  try {
    const sp = getStackPointer(invocation.context);
    if (sp === null) return null;
    return sp.add(offset).readU32();
  } catch (_) {
    return null;
  }
}

function readStackPtr(invocation, offset) {
  try {
    const sp = getStackPointer(invocation.context);
    if (sp === null) return null;
    return sp.add(offset).readPointer();
  } catch (_) {
    return null;
  }
}

function readStackF32(invocation, offset) {
  const u32 = readStackU32(invocation, offset);
  if (u32 === null) return null;
  return u32ToF32(u32);
}

function blendName(v) {
  const u = (v == null) ? null : (v >>> 0);
  const names = {
    0: 'ZERO?',
    1: 'ZERO',
    2: 'ONE',
    3: 'SRCCOLOR',
    4: 'INVSRCCOLOR',
    5: 'SRCALPHA',
    6: 'INVSRCALPHA',
    7: 'DSTALPHA',
    8: 'INVDSTALPHA',
    9: 'DSTCOLOR',
    10: 'INVDSTCOLOR',
    11: 'SRCALPHASAT',
  };
  return u != null && names[u] ? names[u] : null;
}

function filterName(v) {
  const u = (v == null) ? null : (v >>> 0);
  const names = { 1: 'POINT', 2: 'LINEAR', 3: 'ANISOTROPIC' };
  return u != null && names[u] ? names[u] : null;
}

function configVarName(id) {
  const u = (id == null) ? null : (id >>> 0);
  if (u === 0x12) return 'alphaBlendEnable';
  if (u === 0x13) return 'srcBlend';
  if (u === 0x14) return 'dstBlend';
  if (u === 0x15) return 'filter';
  return null;
}

function readTerrainBodiesTransparency() {
  const cvPtr = exePtr(EXE_DATA.cv_terrainBodiesTransparency);
  if (!cvPtr) return null;
  const cv = safeReadPtr(cvPtr);
  if (!cv || cv.isNull()) return null;
  return safeReadF32(cv.add(0x0c));
}

function readFxSnapshot() {
  const fxCountPtr = exePtr(EXE_DATA.fx_queue_count);
  const rotCountPtr = exePtr(EXE_DATA.fx_queue_rotated_count);
  const failedPtr = exePtr(EXE_DATA.terrain_texture_failed);
  const scalePtr = exePtr(EXE_DATA.config_texture_scale);
  const rtPtr = exePtr(EXE_DATA.terrain_render_target);
  const particlesPtr = exePtr(EXE_DATA.particles_texture);
  const bodysetPtr = exePtr(EXE_DATA.bodyset_texture);

  const fxCount = fxCountPtr ? safeReadS32(fxCountPtr) : null;
  const rotCount = rotCountPtr ? safeReadS32(rotCountPtr) : null;
  const terrainFailed = failedPtr ? safeReadU8(failedPtr) : null;
  const terrainScale = scalePtr ? safeReadF32(scalePtr) : null;
  const invScale = terrainScale ? (1.0 / terrainScale) : null;
  const rtHandle = rtPtr ? safeReadS32(rtPtr) : null;
  const particlesHandle = particlesPtr ? safeReadS32(particlesPtr) : null;
  const bodysetHandle = bodysetPtr ? safeReadS32(bodysetPtr) : null;

  return {
    fx_count: fxCount,
    rot_count: rotCount,
    terrain_texture_failed: terrainFailed,
    terrain_scale: terrainScale,
    inv_scale: invScale,
    terrain_render_target: rtHandle,
    particles_texture: particlesHandle,
    bodyset_texture: bodysetHandle,
    terrainBodiesTransparency: readTerrainBodiesTransparency(),
  };
}

function readRotatedEntry(idx) {
  const posBase = exePtr(EXE_DATA.fx_rotated_pos);
  const scaleBase = exePtr(EXE_DATA.fx_rotated_scale);
  const rotBase = exePtr(EXE_DATA.fx_rotated_rotation);
  const typeBase = exePtr(EXE_DATA.fx_rotated_effect_id);
  const colorBase = exePtr(EXE_DATA.fx_rotated_color);
  const corpseFrameBase = exePtr(EXE_DATA.creature_type_corpse_frame);

  if (!posBase || !scaleBase || !rotBase || !typeBase || !colorBase) return null;
  const i = idx | 0;
  if (i < 0) return null;

  const posPtr = posBase.add(i * 8);
  const colorPtr = colorBase.add(i * 16);

  const typeId = safeReadS32(typeBase.add(i * 4));
  let corpseFrame = null;
  if (corpseFrameBase && typeId != null && typeId >= 0) {
    corpseFrame = safeReadS32(corpseFrameBase.add(typeId * EXE_DATA.creature_type_stride));
  }

  const frame = corpseFrame == null ? null : (corpseFrame >>> 0);
  const uv = frame == null ? null : {
    u0: (frame % 4) * 0.25,
    v0: ((frame / 4) | 0) * 0.25,
    u1: ((frame % 4) * 0.25) + 0.25,
    v1: (((frame / 4) | 0) * 0.25) + 0.25,
  };

  return {
    idx: i,
    top_left_x: safeReadF32(posPtr),
    top_left_y: safeReadF32(posPtr.add(4)),
    scale: safeReadF32(scaleBase.add(i * 4)),
    rotation: safeReadF32(rotBase.add(i * 4)),
    creature_type_id: typeId,
    corpse_frame: corpseFrame,
    uv: uv,
    color: {
      r: safeReadF32(colorPtr),
      g: safeReadF32(colorPtr.add(4)),
      b: safeReadF32(colorPtr.add(8)),
      a: safeReadF32(colorPtr.add(12)),
    },
  };
}

function getGrimTextureEntryPtr(grimBase, handle) {
  if (!grimBase) return null;
  if (handle == null) return null;
  const h = handle | 0;
  if (h < 0 || h > 0xff) return null;
  const slotAddr = grimBase.add(GRIM_DATA_RVAS.texture_slots).add(h * 4);
  const entryPtr = safeReadPtr(slotAddr);
  if (!entryPtr || entryPtr.isNull()) return null;
  return entryPtr;
}

function getGrimTextureName(grimBase, handle) {
  const entryPtr = getGrimTextureEntryPtr(grimBase, handle);
  if (!entryPtr) return null;
  const namePtr = safeReadPtr(entryPtr);
  if (!namePtr || namePtr.isNull()) return null;
  return safeReadCString(namePtr);
}

function classifyBatch(ctx) {
  const tex0 = ctx.state.texture0;
  const src = ctx.state.srcBlend;
  const dst = ctx.state.dstBlend;
  const snap = ctx.snapshot;

  if (tex0 != null && snap && tex0 === snap.bodyset_texture) {
    if (src === 1 && dst === 6) return 'corpse_shadow';
    if (src === 5 && dst === 6) return 'corpse_color';
    return 'corpse_unknown_blend';
  }
  if (tex0 != null && snap && tex0 === snap.particles_texture) return 'fx_non_rotated';
  return 'unknown';
}

function backtraceAddrs(invocation, limit) {
  try {
    const bt = Thread.backtrace(invocation.context, Backtracer.FUZZY);
    const out = [];
    for (let i = 0; i < bt.length && i < limit; i++) {
      const a = bt[i];
      const m = Process.findModuleByAddress(a);
      if (m) out.push(m.name + '+' + a.sub(m.base));
      else out.push(a.toString());
    }
    return out;
  } catch (_) {
    return null;
  }
}

function attachOnce() {
  if (ATTACHED) return;
  const exeMod = Process.findModuleByName(CONFIG.exeName);
  const grimMod = Process.findModuleByName(CONFIG.grimName);
  if (!exeMod || !grimMod) return;

  const fxQueueRender = exePtr(EXE_ADDR.fx_queue_render);
  const fxQueueAddRot = exePtr(EXE_ADDR.fx_queue_add_rotated);

  const grimSetConfigVar = grimPtr(GRIM_RVA.set_config_var);
  const grimSetRenderTarget = grimPtr(GRIM_RVA.set_render_target);
  const grimBindTexture = grimPtr(GRIM_RVA.bind_texture);
  const grimBeginBatch = grimPtr(GRIM_RVA.begin_batch);
  const grimEndBatch = grimPtr(GRIM_RVA.end_batch);
  const grimSetRotation = grimPtr(GRIM_RVA.set_rotation);
  const grimSetColor = grimPtr(GRIM_RVA.set_color);
  const grimSetColorPtr = grimPtr(GRIM_RVA.set_color_ptr);
  const grimSetUv = grimPtr(GRIM_RVA.set_uv);
  const grimDrawQuad = grimPtr(GRIM_RVA.draw_quad);

  if (!fxQueueRender || !fxQueueAddRot) return;
  if (!grimSetConfigVar || !grimSetRenderTarget || !grimBindTexture || !grimBeginBatch || !grimEndBatch) return;
  if (!grimSetRotation || !grimSetColor || !grimSetColorPtr || !grimSetUv || !grimDrawQuad) return;

  ATTACHED = true;

  writeLog({
    event: 'init',
    frida: Frida.version,
    runtime: Script.runtime,
    process: { pid: Process.id, arch: Process.arch, pointer_size: Process.pointerSize },
    exe: { name: exeMod.name, base: exeMod.base.toString() },
    grim: { name: grimMod.name, base: grimMod.base.toString() },
    config: CONFIG,
  });

  // --- EXE hooks ---
  Interceptor.attach(fxQueueRender, {
    onEnter() {
      const tid = this.threadId;
      const fxCall = FX_CALL_ID++;
      const snapshot = readFxSnapshot();

      ctxByTid[tid] = {
        id: fxCall,
        tid: tid,
        snapshot: snapshot,
        state: {
          renderTarget: null,
          alphaBlendEnable: null,
          srcBlend: null,
          dstBlend: null,
          filter: null,
          texture0: null,
          texture0_name: null,
          uv: null,
          color: null,
          rotation: null,
          batch_index: -1,
          batch_type: null,
          batch_draw_index: 0,
        },
      };

      writeLog({
        event: 'fx_queue_render_enter',
        fx_call: fxCall,
        tid: tid,
        snapshot: snapshot,
      });

      if (CONFIG.dumpRotatedQueue && snapshot && snapshot.rot_count > 0) {
        const n = Math.min(snapshot.rot_count, 0x3f);
        const entries = [];
        for (let i = 0; i < n; i++) {
          const e = readRotatedEntry(i);
          if (e) entries.push(e);
        }
        writeLog({
          event: 'fx_queue_rotated_snapshot',
          fx_call: fxCall,
          tid: tid,
          count: n,
          entries: entries,
        });
      }
    },
    onLeave() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;

      writeLog({
        event: 'fx_queue_render_exit',
        fx_call: ctx.id,
        tid: tid,
        snapshot_after: readFxSnapshot(),
      });
      delete ctxByTid[tid];
    },
  });

  // Helps correlate enqueue vs bake; cheap and low-frequency (only on corpse adds).
  Interceptor.attach(fxQueueAddRot, {
    onEnter(args) {
      const tid = this.threadId;
      const rotCountPtr = exePtr(EXE_DATA.fx_queue_rotated_count);
      const idx = rotCountPtr ? safeReadS32(rotCountPtr) : null;
      this.__rot_idx = idx;

      const posPtr = args[0];
      const rgbaPtr = args[1];
      const rotation = u32ToF32(args[2].toUInt32());
      const scale = u32ToF32(args[3].toUInt32());
      const creatureTypeId = args[4].toInt32();

      const inRgba = rgbaPtr && !rgbaPtr.isNull() ? {
        r: safeReadF32(rgbaPtr),
        g: safeReadF32(rgbaPtr.add(4)),
        b: safeReadF32(rgbaPtr.add(8)),
        a: safeReadF32(rgbaPtr.add(12)),
      } : null;

      const pos = posPtr && !posPtr.isNull() ? {
        x: safeReadF32(posPtr),
        y: safeReadF32(posPtr.add(4)),
      } : null;

      writeLog({
        event: 'fx_queue_add_rotated_enter',
        tid: tid,
        idx: idx,
        pos: pos,
        rgba_in: inRgba,
        rotation: rotation,
        scale: scale,
        creature_type_id: creatureTypeId,
        terrainBodiesTransparency: readTerrainBodiesTransparency(),
      });
    },
    onLeave(retval) {
      const tid = this.threadId;
      const ok = retval ? retval.toInt32() : 0;
      const idx = this.__rot_idx;
      const stored = (ok === 1 && idx != null) ? readRotatedEntry(idx) : null;
      writeLog({
        event: 'fx_queue_add_rotated_exit',
        tid: tid,
        ok: ok,
        idx: idx,
        stored: stored,
      });
    },
  });

  // --- grim.dll hooks (only log when inside fx_queue_render on the same thread) ---
  Interceptor.attach(grimSetRenderTarget, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      const targetIndex = readStackS32(this, 4);
      ctx.state.renderTarget = targetIndex;
      writeLog({
        event: 'grim_set_render_target',
        fx_call: ctx.id,
        tid: tid,
        target: targetIndex,
        terrain_render_target: ctx.snapshot ? ctx.snapshot.terrain_render_target : null,
      });
    },
  });

  Interceptor.attach(grimSetConfigVar, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      const id = readStackU32(this, 4);
      const value = readStackU32(this, 8);
      if (id == null || value == null) return;
      const name = configVarName(id);

      if (id === 0x12) ctx.state.alphaBlendEnable = value & 0xff;
      if (id === 0x13) ctx.state.srcBlend = value | 0;
      if (id === 0x14) ctx.state.dstBlend = value | 0;
      if (id === 0x15) ctx.state.filter = value | 0;

      writeLog({
        event: 'grim_set_config_var',
        fx_call: ctx.id,
        tid: tid,
        id: id >>> 0,
        id_hex: '0x' + (id >>> 0).toString(16),
        name: name,
        value: value >>> 0,
        value_hex: '0x' + (value >>> 0).toString(16),
        value_name: (id === 0x13 || id === 0x14) ? blendName(value) : (id === 0x15 ? filterName(value) : null),
      });
    },
  });

  Interceptor.attach(grimBindTexture, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      const handle = readStackS32(this, 4);
      const stage = readStackS32(this, 8);
      if (handle == null || stage == null) return;
      if (stage === 0) {
        ctx.state.texture0 = handle;
        ctx.state.texture0_name = getGrimTextureName(grimMod.base, handle);
      }
      writeLog({
        event: 'grim_bind_texture',
        fx_call: ctx.id,
        tid: tid,
        handle: handle,
        stage: stage,
        name: stage === 0 ? (ctx.state.texture0_name || null) : null,
      });
    },
  });

  Interceptor.attach(grimSetUv, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      const u0 = readStackF32(this, 4);
      const v0 = readStackF32(this, 8);
      const u1 = readStackF32(this, 12);
      const v1 = readStackF32(this, 16);
      if (u0 == null || v0 == null || u1 == null || v1 == null) return;
      ctx.state.uv = { u0: u0, v0: v0, u1: u1, v1: v1 };
    },
  });

  Interceptor.attach(grimSetColor, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      const r = readStackF32(this, 4);
      const g = readStackF32(this, 8);
      const b = readStackF32(this, 12);
      const a = readStackF32(this, 16);
      if (r == null || g == null || b == null || a == null) return;
      ctx.state.color = { r: r, g: g, b: b, a: a };
    },
  });

  Interceptor.attach(grimSetColorPtr, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      const p = readStackPtr(this, 4);
      if (!p || p.isNull()) return;
      ctx.state.color = {
        r: safeReadF32(p),
        g: safeReadF32(p.add(4)),
        b: safeReadF32(p.add(8)),
        a: safeReadF32(p.add(12)),
      };
    },
  });

  Interceptor.attach(grimSetRotation, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      const radians = readStackF32(this, 4);
      if (radians == null) return;
      ctx.state.rotation = radians;
    },
  });

  Interceptor.attach(grimBeginBatch, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      ctx.state.batch_index += 1;
      ctx.state.batch_draw_index = 0;
      ctx.state.batch_type = classifyBatch(ctx);
      if (!CONFIG.includeNonRotated && ctx.state.batch_type === 'fx_non_rotated') return;
      writeLog({
        event: 'grim_begin_batch',
        fx_call: ctx.id,
        tid: tid,
        batch_index: ctx.state.batch_index,
        batch_type: ctx.state.batch_type,
        state: {
          rt: ctx.state.renderTarget,
          tex0: ctx.state.texture0,
          tex0_name: ctx.state.texture0_name || null,
          blend: { src: ctx.state.srcBlend, src_name: blendName(ctx.state.srcBlend), dst: ctx.state.dstBlend, dst_name: blendName(ctx.state.dstBlend) },
          filter: ctx.state.filter,
          filter_name: filterName(ctx.state.filter),
        },
      });
    },
  });

  Interceptor.attach(grimEndBatch, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;
      if (!CONFIG.includeNonRotated && ctx.state.batch_type === 'fx_non_rotated') return;
      writeLog({
        event: 'grim_end_batch',
        fx_call: ctx.id,
        tid: tid,
        batch_index: ctx.state.batch_index,
        batch_type: ctx.state.batch_type,
        draws: ctx.state.batch_draw_index,
      });
    },
  });

  Interceptor.attach(grimDrawQuad, {
    onEnter() {
      const tid = this.threadId;
      const ctx = ctxByTid[tid];
      if (!ctx) return;

      const batchType = ctx.state.batch_type || classifyBatch(ctx);
      if (!CONFIG.includeNonRotated && batchType === 'fx_non_rotated') return;

      const x = readStackF32(this, 4);
      const y = readStackF32(this, 8);
      const w = readStackF32(this, 12);
      const h = readStackF32(this, 16);

      const drawIndex = ctx.state.batch_draw_index++;

      const evt = {
        event: 'grim_draw_quad',
        fx_call: ctx.id,
        tid: tid,
        batch_index: ctx.state.batch_index,
        batch_type: batchType,
        draw_index: drawIndex,
        xywh: { x: x, y: y, w: w, h: h },
        state: {
          rt: ctx.state.renderTarget,
          tex0: ctx.state.texture0,
          tex0_name: ctx.state.texture0_name || null,
          uv: ctx.state.uv,
          color: ctx.state.color,
          rotation: ctx.state.rotation,
          blend: { src: ctx.state.srcBlend, src_name: blendName(ctx.state.srcBlend), dst: ctx.state.dstBlend, dst_name: blendName(ctx.state.dstBlend) },
        },
      };

      if (RUNTIME.includeBacktrace) evt.bt = backtraceAddrs(this, 10);
      writeLog(evt);
    },
  });
}

// Public REPL helpers (Frida REPL evaluates in this JS runtime).
globalThis.fxTraceEnable = function (on) {
  RUNTIME.enabled = !!on;
  writeLog({ event: 'runtime_toggle', enabled: RUNTIME.enabled });
};

globalThis.fxTraceBacktrace = function (on) {
  RUNTIME.includeBacktrace = !!on;
  writeLog({ event: 'runtime_toggle', includeBacktrace: RUNTIME.includeBacktrace });
};

globalThis.dumpRotatedQueue = function () {
  const snap = readFxSnapshot();
  const entries = [];
  const n = snap && snap.rot_count ? Math.min(snap.rot_count, 0x3f) : 0;
  for (let i = 0; i < n; i++) {
    const e = readRotatedEntry(i);
    if (e) entries.push(e);
  }
  writeLog({ event: 'dump_rotated_queue', snapshot: snap, entries: entries });
};

// Start
initLog();
writeLog({ event: 'start', frida: Frida.version, runtime: Script.runtime });
setInterval(attachOnce, 250);
attachOnce();
