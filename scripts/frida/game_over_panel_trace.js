'use strict';

// game_over_panel_trace.js - Focused runtime trace for state 7 (game-over UI panel geometry).
//
// Usage (from repo root, Windows VM):
//   frida -n crimsonland.exe -l scripts\frida\game_over_panel_trace.js
//
// Output (JSONL):
//   C:\share\frida\game_over_panel_trace.jsonl
//
// Env overrides:
//   CRIMSON_FRIDA_DIR=...                      # log dir (default C:\share\frida)
//   CRIMSON_FRIDA_MODULE=crimsonland.exe       # module name
//   CRIMSON_FRIDA_LINK_BASE=0x00400000         # static image base
//   CRIMSON_GAME_OVER_TRACE_CONSOLE=1          # mirror JSONL to console
//   CRIMSON_GAME_OVER_TRACE_MAX_EVENTS=20000   # stop after N events (0 = unlimited)
//
// REPL helpers:
//   mark("name")
//   enable(0|1)

const DEFAULT_LOG_DIR = 'C:\\share\\frida';

function getEnv(name) {
  try {
    return Process.env[name];
  } catch (_) {
    return undefined;
  }
}

function envInt(name, fallback) {
  try {
    const raw = getEnv(name);
    if (raw == null || raw === '') return fallback;
    const parsed = parseInt(String(raw).trim(), 0);
    return Number.isFinite(parsed) ? parsed : fallback;
  } catch (_) {
    return fallback;
  }
}

function envBool(name, fallback) {
  try {
    const raw = getEnv(name);
    if (raw == null || raw === '') return fallback;
    const lowered = String(raw).trim().toLowerCase();
    if (lowered === '1' || lowered === 'true' || lowered === 'yes') return true;
    if (lowered === '0' || lowered === 'false' || lowered === 'no') return false;
    return fallback;
  } catch (_) {
    return fallback;
  }
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith('\\') || base.endsWith('/') ? '' : '\\';
  return base + sep + leaf;
}

function nowIso() {
  return new Date().toISOString();
}

function isReadable(p) {
  try {
    if (!p || p.isNull()) return false;
    const r = Process.findRangeByAddress(p);
    return !!r && r.protection.indexOf('r') !== -1;
  } catch (_) {
    return false;
  }
}

function safeReadU8(p) {
  try { return isReadable(p) ? p.readU8() : null; } catch (_) { return null; }
}
function safeReadS32(p) {
  try { return isReadable(p) ? p.readS32() : null; } catch (_) { return null; }
}
function safeReadF32(p) {
  try { return isReadable(p) ? p.readFloat() : null; } catch (_) { return null; }
}

const CONFIG = {
  logDir: getEnv('CRIMSON_FRIDA_DIR') || DEFAULT_LOG_DIR,
  logPath: null,
  logToConsole: envBool('CRIMSON_GAME_OVER_TRACE_CONSOLE', false),
  maxEvents: envInt('CRIMSON_GAME_OVER_TRACE_MAX_EVENTS', 0),
  exeName: getEnv('CRIMSON_FRIDA_MODULE') || 'crimsonland.exe',
};
CONFIG.logPath = joinPath(CONFIG.logDir, 'game_over_panel_trace.jsonl');

let LINK_BASE = ptr('0x00400000');
{
  const raw = getEnv('CRIMSON_FRIDA_LINK_BASE') || getEnv('CRIMSON_FRIDA_IMAGE_BASE');
  if (raw) {
    const parsed = parseInt(String(raw).trim(), 0);
    if (Number.isFinite(parsed)) LINK_BASE = ptr(parsed);
  }
}

const EXE_ADDR = {
  game_over_screen_update: 0x0040ffc0,
  ui_draw_textured_quad: 0x00417ae0,
};

const EXE_DATA_RVA = {
  config_screen_width: 0x080504,
  config_screen_height: 0x080508,
  config_windowed: 0x08050c,
  ui_screen_phase: 0x087234,
  ui_elements_timeline: 0x087248,
  ui_transition_direction: 0x08724c,
  ui_transition_alpha: 0x087278,
  game_state_id: 0x087270,
  game_state_pending: 0x087274,
};

const EXE_VA = {
  // ui_menu_layout_init clone used by game-over flow.
  game_over_panel_element: 0x0048cc84,
};

const LOG = { ok: false, file: null };
const RUN_ID = nowIso() + '_' + Math.floor(Math.random() * 1e9).toString(16);
const RUNTIME = { enabled: true };
let SEQ = 0;

function initLog() {
  try {
    LOG.file = new File(CONFIG.logPath, 'a');
    LOG.ok = true;
  } catch (e) {
    console.log('[game_over_panel_trace] failed to open log: ' + e);
  }
}

function writeLog(obj) {
  if (!RUNTIME.enabled) return;
  if (CONFIG.maxEvents > 0 && SEQ >= CONFIG.maxEvents) {
    RUNTIME.enabled = false;
    console.log('[game_over_panel_trace] max events reached; disabling logging');
    return;
  }
  obj.ts = nowIso();
  obj.seq = SEQ++;
  obj.run_id = RUN_ID;
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  if (CONFIG.logToConsole) console.log(line);
}

globalThis.enable = function enable(v) {
  RUNTIME.enabled = v ? true : false;
  writeLog({ event: 'toggle', enabled: RUNTIME.enabled });
  return RUNTIME.enabled;
};

globalThis.mark = function mark(label) {
  writeLog({ event: 'mark', label: String(label) });
};

function exePtr(exeModule, staticVa) {
  if (!exeModule) return null;
  try {
    return exeModule.base.add(ptr(staticVa).sub(LINK_BASE));
  } catch (_) {
    return null;
  }
}

function exeRvaPtr(exeModule, rva) {
  if (!exeModule) return null;
  try {
    return exeModule.base.add(ptr(rva));
  } catch (_) {
    return null;
  }
}

function readExeState(exeModule) {
  return {
    res: {
      w: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.config_screen_width)),
      h: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.config_screen_height)),
      windowed: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.config_windowed)),
    },
    ui: {
      phase: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.ui_screen_phase)),
      timeline: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.ui_elements_timeline)),
      dir: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.ui_transition_direction)),
      alpha: safeReadF32(exeRvaPtr(exeModule, EXE_DATA_RVA.ui_transition_alpha)),
    },
    game: {
      state_id: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.game_state_id)),
      state_pending: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.game_state_pending)),
    },
  };
}

function bboxFromPoints(points) {
  if (!points || points.length === 0) return null;
  let minX = points[0][0];
  let minY = points[0][1];
  let maxX = minX;
  let maxY = minY;
  for (let i = 1; i < points.length; i++) {
    const x = points[i][0];
    const y = points[i][1];
    if (x < minX) minX = x;
    if (y < minY) minY = y;
    if (x > maxX) maxX = x;
    if (y > maxY) maxY = y;
  }
  return [minX, minY, maxX, maxY];
}

function mergeBboxes(bboxes) {
  const valid = (bboxes || []).filter((b) => Array.isArray(b) && b.length === 4);
  if (valid.length === 0) return null;
  let minX = valid[0][0];
  let minY = valid[0][1];
  let maxX = valid[0][2];
  let maxY = valid[0][3];
  for (let i = 1; i < valid.length; i++) {
    const b = valid[i];
    if (b[0] < minX) minX = b[0];
    if (b[1] < minY) minY = b[1];
    if (b[2] > maxX) maxX = b[2];
    if (b[3] > maxY) maxY = b[3];
  }
  return [minX, minY, maxX, maxY];
}

function applyTransform(x, y, tx, ty, renderMode, matrix) {
  if (renderMode === 0 && matrix) {
    const m00 = matrix[0];
    const m01 = matrix[1];
    const m10 = matrix[2];
    const m11 = matrix[3];
    return [x * m00 + y * m01 + tx, x * m10 + y * m11 + ty];
  }
  return [x + tx, y + ty];
}

function readQuad(elementPtr, quadOffset, tx, ty, renderMode, matrix) {
  const quadPtr = elementPtr.add(quadOffset);
  const local = [];
  const world = [];
  for (let i = 0; i < 4; i++) {
    const v = quadPtr.add(i * 0x1c);
    const x = safeReadF32(v);
    const y = safeReadF32(v.add(4));
    if (x == null || y == null) {
      local.push(null);
      world.push(null);
      continue;
    }
    local.push([x, y]);
    world.push(applyTransform(x, y, tx, ty, renderMode, matrix));
  }
  const localPts = local.filter((p) => Array.isArray(p));
  const worldPts = world.filter((p) => Array.isArray(p));
  return {
    local_vertices: local,
    world_vertices: world,
    local_bbox: bboxFromPoints(localPts),
    world_bbox: bboxFromPoints(worldPts),
  };
}

function readPanelElement(exeModule) {
  const elementPtr = exePtr(exeModule, EXE_VA.game_over_panel_element);
  if (!elementPtr) return null;

  const active = safeReadU8(elementPtr.add(0x00));
  const renderMode = safeReadS32(elementPtr.add(0x04));
  const slideX = safeReadF32(elementPtr.add(0x08));
  const slideY = safeReadF32(elementPtr.add(0x0c));
  const posX = safeReadF32(elementPtr.add(0x18));
  const posY = safeReadF32(elementPtr.add(0x1c));
  const textureHandle = safeReadS32(elementPtr.add(0x11c));
  const quadMode = safeReadS32(elementPtr.add(0x120));
  const rotM00 = safeReadF32(elementPtr.add(0x304));
  const rotM01 = safeReadF32(elementPtr.add(0x308));
  const rotM10 = safeReadF32(elementPtr.add(0x30c));
  const rotM11 = safeReadF32(elementPtr.add(0x310));

  if (
    active == null ||
    renderMode == null ||
    slideX == null ||
    slideY == null ||
    posX == null ||
    posY == null
  ) {
    return null;
  }

  const tx = posX + slideX;
  const ty = posY + slideY;
  const matrix = (rotM00 == null || rotM01 == null || rotM10 == null || rotM11 == null)
    ? null
    : [rotM00, rotM01, rotM10, rotM11];

  const quadOffsets = [0x3c];
  if (quadMode === 8) {
    quadOffsets.push(0x74);
    quadOffsets.push(0xac);
  }
  const quads = quadOffsets.map((off) => readQuad(elementPtr, off, tx, ty, renderMode, matrix));

  return {
    ptr: elementPtr.toString(),
    active: active,
    render_mode: renderMode,
    slide_x: slideX,
    slide_y: slideY,
    pos_x: posX,
    pos_y: posY,
    translated_x: tx,
    translated_y: ty,
    texture_handle: textureHandle,
    quad_mode: quadMode,
    matrix: matrix,
    quads: quads,
    union_bbox_world: mergeBboxes(quads.map((q) => q.world_bbox)),
  };
}

function main() {
  initLog();

  const exeMod = Process.findModuleByName(CONFIG.exeName);
  if (!exeMod) {
    console.log('[game_over_panel_trace] module not found: ' + CONFIG.exeName);
    return;
  }

  const gameOverUpdate = exePtr(exeMod, EXE_ADDR.game_over_screen_update);
  const uiDrawTexturedQuad = exePtr(exeMod, EXE_ADDR.ui_draw_textured_quad);
  if (!gameOverUpdate) {
    console.log('[game_over_panel_trace] failed to resolve game_over_screen_update');
    return;
  }

  const ctxByTid = {};
  function getCtx(tid) {
    const key = String(tid);
    if (!ctxByTid[key]) {
      ctxByTid[key] = { depth: 0, frame: 0 };
    }
    return ctxByTid[key];
  }

  writeLog({
    event: 'init',
    frida: { version: Frida.version, runtime: Script.runtime },
    process: { pid: Process.id, arch: Process.arch, pointer_size: Process.pointerSize },
    exe: { name: exeMod.name, base: exeMod.base.toString(), link_base: LINK_BASE.toString() },
    addresses: {
      game_over_screen_update: gameOverUpdate.toString(),
      ui_draw_textured_quad: uiDrawTexturedQuad ? uiDrawTexturedQuad.toString() : null,
      game_over_panel_element: exePtr(exeMod, EXE_VA.game_over_panel_element).toString(),
    },
    config: CONFIG,
    state: readExeState(exeMod),
    panel: readPanelElement(exeMod),
  });

  Interceptor.attach(gameOverUpdate, {
    onEnter() {
      const ctx = getCtx(this.threadId);
      ctx.depth += 1;
      if (ctx.depth === 1) {
        ctx.frame += 1;
        writeLog({
          event: 'game_over_begin',
          tid: this.threadId,
          frame: ctx.frame,
          state: readExeState(exeMod),
          panel: readPanelElement(exeMod),
        });
      }
    },
    onLeave() {
      const ctx = getCtx(this.threadId);
      if (ctx.depth === 1) {
        writeLog({
          event: 'game_over_end',
          tid: this.threadId,
          frame: ctx.frame,
          state: readExeState(exeMod),
          panel: readPanelElement(exeMod),
        });
      }
      if (ctx.depth > 0) ctx.depth -= 1;
    },
  });

  if (uiDrawTexturedQuad) {
    Interceptor.attach(uiDrawTexturedQuad, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        if (ctx.depth <= 0) return;
        writeLog({
          event: 'textured_quad',
          tid: this.threadId,
          frame: ctx.frame,
          x: args[0].toInt32(),
          y: args[1].toInt32(),
          w: args[2].toInt32(),
          h: args[3].toInt32(),
          texture_handle: args[4].toInt32(),
          state: readExeState(exeMod),
        });
      },
    });
  }
}

main();
