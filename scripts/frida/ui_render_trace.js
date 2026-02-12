'use strict';

// ui_render_trace.js - Capture UI rendering inputs at runtime (menus/panels/widgets) for layout parity.
//
// Usage (attach-only, VM):
//   frida -n crimsonland.exe -l C:\share\frida\ui_render_trace.js
//
// Output (JSONL):
//   C:\share\frida\ui_render_trace.jsonl (or CRIMSON_FRIDA_DIR override)
//
// Env overrides:
//   CRIMSON_FRIDA_DIR=...                 # log dir (default C:\share\frida)
//   CRIMSON_UI_TRACE_CONSOLE=1            # also print JSONL to console
//   CRIMSON_UI_TRACE_MAX_EVENTS=200000    # stop after N events (0 = unlimited)
//   CRIMSON_UI_TRACE_BACKTRACE=1          # include FUZZY backtraces on draw calls (expensive)
//   CRIMSON_UI_TRACE_VERTS=1              # include full vertex dumps on submit calls (default 1)
//   CRIMSON_FRIDA_LINK_BASE=0x00400000    # image base for EXE VA -> runtime mapping (rare)
//   CRIMSON_FRIDA_MODULE=crimsonland.exe  # EXE module name (rare)
//
// REPL helpers:
//   mark("main_menu")  # write a marker event into the log
//   enable(0|1)        # disable/enable logging without detaching

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

function nowMs() {
  return Date.now();
}

function resolveAbi() {
  if (Process.platform !== 'windows') return null;
  if (Process.arch === 'x64') return 'win64';
  if (Process.arch === 'ia32') return 'mscdecl';
  return null;
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
function safeReadU32(p) {
  try { return isReadable(p) ? p.readU32() : null; } catch (_) { return null; }
}
function safeReadF32(p) {
  try { return isReadable(p) ? p.readFloat() : null; } catch (_) { return null; }
}
function safeReadPtr(p) {
  try { return isReadable(p) ? p.readPointer() : null; } catch (_) { return null; }
}
function safeReadCString(p, limit) {
  try {
    if (!isReadable(p)) return null;
    return (limit != null) ? p.readCString(limit) : p.readCString();
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

function readStackU32(invocation, offset) {
  try {
    const sp = getStackPointer(invocation.context);
    if (sp === null) return null;
    return sp.add(offset).readU32();
  } catch (_) {
    return null;
  }
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

const CONFIG = {
  logDir: getEnv('CRIMSON_FRIDA_DIR') || DEFAULT_LOG_DIR,
  logPath: null, // set below
  logToConsole: envBool('CRIMSON_UI_TRACE_CONSOLE', false),
  maxEvents: envInt('CRIMSON_UI_TRACE_MAX_EVENTS', 0),
  includeBacktrace: envBool('CRIMSON_UI_TRACE_BACKTRACE', false),
  includeVerts: envBool('CRIMSON_UI_TRACE_VERTS', true),

  autoMark: envBool('CRIMSON_UI_TRACE_AUTOMARK', true),
  autoMarkIntervalMs: envInt('CRIMSON_UI_TRACE_AUTOMARK_MS', 250),
  autoMarkTextLimit: envInt('CRIMSON_UI_TRACE_AUTOMARK_TEXTS', 8),

  exeName: getEnv('CRIMSON_FRIDA_MODULE') || 'crimsonland.exe',
  grimName: 'grim.dll',
};

CONFIG.logPath = joinPath(CONFIG.logDir, 'ui_render_trace.jsonl');

let LINK_BASE = ptr('0x00400000');
{
  const raw = getEnv('CRIMSON_FRIDA_LINK_BASE') || getEnv('CRIMSON_FRIDA_IMAGE_BASE');
  if (raw) {
    const parsed = parseInt(String(raw).trim(), 0);
    if (Number.isFinite(parsed)) LINK_BASE = ptr(parsed);
  }
}

// --- EXE addresses (static VAs; Crimsonland v1.9.93) ---
const EXE_ADDR = {
  ui_elements_update_and_render: 0x0041a530,
  ui_element_render: 0x00446c40,

  // Widget helpers (render + state; good scope anchors).
  ui_draw_textured_quad: 0x00417ae0,
  ui_draw_progress_bar: 0x0041a6d0,
  ui_button_update: 0x0043e830,
  ui_menu_item_update: 0x0043e5e0,
  ui_checkbox_update: 0x0043dc80,
  ui_scrollbar_update: 0x0043def0,
  ui_text_input_update: 0x0043ecf0,
  ui_text_input_render: 0x004413a0,
  ui_list_widget_update: 0x0043efc0,
  ui_update_notice_update: 0x00442150,
};

// --- EXE globals (RVAs from analysis/ghidra/maps/data_map.json) ---
const EXE_DATA_RVA = {
  config_screen_width: 0x080504,
  config_screen_height: 0x080508,
  config_windowed: 0x08050c,

  screen_width_f: 0x071140,

  frame_dt_ms: 0x080844,
  game_time_ms: 0x080848,

  ui_elements_timeline: 0x087248,
  ui_transition_direction: 0x08724c,
  ui_transition_alpha: 0x087278,

  game_state_prev: 0x08726c,
  game_state_id: 0x087270,
  game_state_pending: 0x087274,

  // UI element pointer table (41 pointers: 0xA4 bytes).
  ui_element_table_end: 0x08f168,
  ui_element_table_count: 41,
};

// --- Grim2D RVAs (grim.dll; from analysis/ghidra/maps/name_map.json) ---
const GRIM_RVA = {
  // Textures/state
  get_texture_handle: 0x07740,
  bind_texture: 0x07830,
  set_config_var: 0x06580,
  set_color: 0x07f90,
  set_color_ptr: 0x08040,
  set_uv: 0x08350,
  set_uv_point: 0x083a0,
  set_atlas_frame: 0x08230,
  set_sub_rect: 0x082c0,
  set_rotation: 0x07f30,

  // UI primitives
  draw_rect_filled: 0x078e0,
  draw_rect_outline: 0x08f10,
  draw_quad: 0x08b10,
  draw_quad_xy: 0x08720,
  draw_quad_rotated_matrix: 0x08750,
  draw_quad_points: 0x09080,

  // Vertex submission
  submit_vertices_offset: 0x08680,
  submit_vertices_transform: 0x085c0,
  submit_vertices_offset_color: 0x08430,
  submit_vertices_transform_color: 0x084e0,

  // Text
  draw_text_mono: 0x092b0,
  draw_text_small: 0x09730,
};

// --- Logging ---
const LOG = { ok: false, file: null };
const RUNTIME = { enabled: true };
const RUN_ID = nowIso() + '_' + Math.floor(Math.random() * 1e9).toString(16);
let SEQ = 0;

function initLog() {
  try {
    LOG.file = new File(CONFIG.logPath, 'a');
    LOG.ok = true;
  } catch (e) {
    console.log('[ui_render_trace] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  if (!RUNTIME.enabled) return;
  if (CONFIG.maxEvents > 0 && SEQ >= CONFIG.maxEvents) {
    RUNTIME.enabled = false;
    console.log('[ui_render_trace] max events reached; disabling logging');
    return;
  }
  obj.ts = nowIso();
  obj.seq = SEQ++;
  obj.run_id = RUN_ID;
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  if (CONFIG.logToConsole) console.log(line);
}

// Public REPL helpers (Frida REPL evaluates in this JS runtime).
globalThis.enable = function enable(v) {
  RUNTIME.enabled = v ? true : false;
  writeLog({ event: 'toggle', enabled: RUNTIME.enabled });
  return RUNTIME.enabled;
};

globalThis.mark = function mark(label) {
  const exeMod = Process.findModuleByName(CONFIG.exeName);
  writeLog({ event: 'mark', label: String(label), state: exeMod ? readExeState(exeMod) : null });
};

function fnv1a32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    // h *= 16777619 (FNV prime), modulo 2^32
    h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return ('00000000' + h.toString(16)).slice(-8);
}

function sanitizeText(s) {
  if (!s) return null;
  // Normalize for stable screen fingerprints (ignore variable numbers).
  let out = String(s);
  out = out.replace(/\s+/g, ' ').trim();
  out = out.replace(/[0-9]+/g, '#');
  if (!out) return null;
  if (out.length > 120) out = out.slice(0, 120);
  return out;
}

// --- Address helpers ---
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

function grimPtr(grimModule, rva) {
  if (!grimModule) return null;
  try {
    return grimModule.base.add(ptr(rva));
  } catch (_) {
    return null;
  }
}

// --- UI element table (stable element index mapping) ---
let UI_TABLE = { ok: false, ptrs: [], indexByPtr: {} };

function refreshUiTable(exeModule) {
  const base = exeRvaPtr(exeModule, EXE_DATA_RVA.ui_element_table_end);
  if (!base) return false;

  const ptrs = [];
  const indexByPtr = {};
  for (let i = 0; i < EXE_DATA_RVA.ui_element_table_count; i++) {
    const p = safeReadPtr(base.add(i * Process.pointerSize));
    if (!p || p.isNull()) continue;
    const key = p.toString();
    ptrs.push({ index: i, ptr: key });
    indexByPtr[key] = i;
  }

  UI_TABLE = { ok: true, ptrs: ptrs, indexByPtr: indexByPtr };
  writeLog({ event: 'ui_table', count: ptrs.length, table_end: base.toString(), ptrs: ptrs });
  return true;
}

function getUiElementIndex(elementPtr) {
  if (!elementPtr) return null;
  const key = elementPtr.toString();
  if (UI_TABLE.ok && UI_TABLE.indexByPtr[key] !== undefined) return UI_TABLE.indexByPtr[key];
  return null;
}

function collectUiActiveSignature(exeModule) {
  const base = exeRvaPtr(exeModule, EXE_DATA_RVA.ui_element_table_end);
  if (!base) return [];

  const out = [];
  for (let i = 0; i < EXE_DATA_RVA.ui_element_table_count; i++) {
    const p = safeReadPtr(base.add(i * Process.pointerSize));
    if (!p || p.isNull()) continue;
    const active = safeReadU8(p.add(0x00));
    if (!active) continue;
    out.push({
      index: i,
      ptr: p.toString(),
      tex: safeReadS32(p.add(0x11c)),
      overlay_tex: safeReadS32(p.add(0x204)),
      quad_mode: safeReadS32(p.add(0x120)),
      on_activate: (safeReadPtr(p.add(0x34)) || ptr('0')).toString(),
      custom_render: (safeReadPtr(p.add(0x38)) || ptr('0')).toString(),
    });
  }
  return out;
}

// --- Runtime state snapshot helpers ---
function readExeState(exeModule) {
  const out = {};
  const w = safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.config_screen_width));
  const h = safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.config_screen_height));
  out.res = {
    w: w,
    h: h,
    windowed: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.config_windowed)),
    screen_width_f: safeReadF32(exeRvaPtr(exeModule, EXE_DATA_RVA.screen_width_f)),
  };
  out.time = {
    frame_dt_ms: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.frame_dt_ms)),
    game_time_ms: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.game_time_ms)),
  };
  out.ui = {
    timeline: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.ui_elements_timeline)),
    dir: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.ui_transition_direction)),
    alpha: safeReadF32(exeRvaPtr(exeModule, EXE_DATA_RVA.ui_transition_alpha)),
  };
  out.game = {
    state_prev: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.game_state_prev)),
    state_id: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.game_state_id)),
    state_pending: safeReadS32(exeRvaPtr(exeModule, EXE_DATA_RVA.game_state_pending)),
  };
  return out;
}

// --- Draw-state tracking (minimal; enough for UI reconstruction) ---
const textureNames = {}; // handle -> name (best-effort; only after attach)
const ctxByTid = {};
let UI_FRAME = 0;

function getCtx(tid) {
  const key = String(tid);
  if (!ctxByTid[key]) {
    ctxByTid[key] = {
      ui_depth: 0,
      ui_frame: 0,
      scope_stack: [],
      element_ptr: null,
      element_index: null,
      frame_texts: [],
      frame_text_set: {},
      draw: {
        texture0: null,
        uv: null,
        color: null,
        config: {},
        atlas: null,
        sub_rect: null,
        rotation: null,
      },
    };
  }
  return ctxByTid[key];
}

function pushScope(ctx, scope) {
  ctx.scope_stack.push(scope);
}

function popScope(ctx, expectedKind) {
  const s = ctx.scope_stack.pop();
  if (!s) return;
  if (expectedKind && s.kind !== expectedKind) {
    // Keep going; we prefer not to throw in a trace script.
    writeLog({ event: 'scope_mismatch', expected: expectedKind, got: s.kind });
  }
}

function inUiScope(ctx) {
  return ctx.ui_depth > 0 || ctx.scope_stack.length > 0 || ctx.element_ptr !== null;
}

function decodeColorU32(argb) {
  if (argb == null) return null;
  const u = argb >>> 0;
  return {
    a: (u >>> 24) & 0xff,
    r: (u >>> 16) & 0xff,
    g: (u >>> 8) & 0xff,
    b: u & 0xff,
    u32: u,
  };
}

function readF32x2(p) {
  if (!p) return null;
  const x = safeReadF32(p);
  const y = safeReadF32(p.add(4));
  if (x == null || y == null) return null;
  return [x, y];
}

function readF32x4(p) {
  if (!p) return null;
  const a = safeReadF32(p);
  const b = safeReadF32(p.add(4));
  const c = safeReadF32(p.add(8));
  const d = safeReadF32(p.add(12));
  if (a == null || b == null || c == null || d == null) return null;
  return [a, b, c, d];
}

function readVertex(p) {
  if (!p) return null;
  const x = safeReadF32(p.add(0));
  const y = safeReadF32(p.add(4));
  const z = safeReadF32(p.add(8));
  const rhw = safeReadF32(p.add(12));
  const col = safeReadU32(p.add(16));
  const u = safeReadF32(p.add(20));
  const v = safeReadF32(p.add(24));
  if (x == null || y == null) return null;
  return { x: x, y: y, z: z, rhw: rhw, uv: (u != null && v != null) ? [u, v] : null, color: decodeColorU32(col) };
}

function readVertices(vertsPtr, count) {
  if (!vertsPtr || count == null) return null;
  const n = Math.max(0, Math.min(count | 0, 64)); // safety cap
  const out = [];
  for (let i = 0; i < n; i++) {
    const v = readVertex(vertsPtr.add(i * 0x1c));
    out.push(v);
  }
  return out;
}

// --- ui_button_t (from third_party/headers/crimsonland_types.h; stable enough for traces) ---
function readUiButton(buttonPtr) {
  if (!buttonPtr) return null;
  const labelPtr = safeReadPtr(buttonPtr.add(0));
  return {
    ptr: buttonPtr.toString(),
    label: labelPtr ? safeReadCString(labelPtr, 128) : null,
    hovered: safeReadU8(buttonPtr.add(4)),
    activated: safeReadU8(buttonPtr.add(5)),
    enabled: safeReadU8(buttonPtr.add(6)),
    hover_anim: safeReadS32(buttonPtr.add(8)),
    click_anim: safeReadS32(buttonPtr.add(12)),
    alpha: safeReadF32(buttonPtr.add(16)),
    force_small: safeReadU8(buttonPtr.add(20)),
    force_wide: safeReadU8(buttonPtr.add(21)),
  };
}

// ui_element_t fields (offsets based on docs/mechanics/systems/ui-elements.md; best-effort only).
function readUiElementSummary(elementPtr) {
  if (!elementPtr) return null;
  return {
    ptr: elementPtr.toString(),
    active: safeReadU8(elementPtr.add(0x00)),
    ready: safeReadU8(elementPtr.add(0x01)),
    disabled: safeReadU8(elementPtr.add(0x02)),
    render_mode: safeReadS32(elementPtr.add(0x04)),
    slide: [safeReadF32(elementPtr.add(0x08)), safeReadF32(elementPtr.add(0x0c))],
    timeline: { start_ms: safeReadS32(elementPtr.add(0x10)), end_ms: safeReadS32(elementPtr.add(0x14)) },
    pos: [safeReadF32(elementPtr.add(0x18)), safeReadF32(elementPtr.add(0x1c))],
    bounds: [
      safeReadF32(elementPtr.add(0x20)),
      safeReadF32(elementPtr.add(0x24)),
      safeReadF32(elementPtr.add(0x28)),
      safeReadF32(elementPtr.add(0x2c)),
    ],
    on_activate: (safeReadPtr(elementPtr.add(0x34)) || ptr('0')).toString(),
    custom_render: (safeReadPtr(elementPtr.add(0x38)) || ptr('0')).toString(),
    texture_handle: safeReadS32(elementPtr.add(0x11c)),
    quad_mode: safeReadS32(elementPtr.add(0x120)),
    overlay_texture_handle: safeReadS32(elementPtr.add(0x204)),
    hover_amount: safeReadS32(elementPtr.add(0x2f8)),
    time_since_ready: safeReadS32(elementPtr.add(0x2fc)),
    render_scale: safeReadF32(elementPtr.add(0x300)),
    rot: readF32x4(elementPtr.add(0x304)),
    direction_flag: safeReadS32(elementPtr.add(0x314)),
  };
}

// --- Hook install ---
let ATTACHED = false;

function attachOnce() {
  if (ATTACHED) return;
  const exeMod = Process.findModuleByName(CONFIG.exeName);
  const grimMod = Process.findModuleByName(CONFIG.grimName);
  if (!exeMod || !grimMod) return;

  initLog();

  // Resolve EXE hooks.
  const uiElementsUpdateAndRender = exePtr(exeMod, EXE_ADDR.ui_elements_update_and_render);
  const uiElementRender = exePtr(exeMod, EXE_ADDR.ui_element_render);
  const uiDrawTexturedQuad = exePtr(exeMod, EXE_ADDR.ui_draw_textured_quad);
  const uiDrawProgressBar = exePtr(exeMod, EXE_ADDR.ui_draw_progress_bar);
  const uiButtonUpdate = exePtr(exeMod, EXE_ADDR.ui_button_update);
  const uiMenuItemUpdate = exePtr(exeMod, EXE_ADDR.ui_menu_item_update);
  const uiCheckboxUpdate = exePtr(exeMod, EXE_ADDR.ui_checkbox_update);
  const uiScrollbarUpdate = exePtr(exeMod, EXE_ADDR.ui_scrollbar_update);
  const uiTextInputUpdate = exePtr(exeMod, EXE_ADDR.ui_text_input_update);
  const uiTextInputRender = exePtr(exeMod, EXE_ADDR.ui_text_input_render);
  const uiListWidgetUpdate = exePtr(exeMod, EXE_ADDR.ui_list_widget_update);
  const uiUpdateNoticeUpdate = exePtr(exeMod, EXE_ADDR.ui_update_notice_update);

  // Resolve Grim hooks.
  const grimGetTextureHandle = grimPtr(grimMod, GRIM_RVA.get_texture_handle);
  const grimBindTexture = grimPtr(grimMod, GRIM_RVA.bind_texture);
  const grimSetConfigVar = grimPtr(grimMod, GRIM_RVA.set_config_var);
  const grimSetColor = grimPtr(grimMod, GRIM_RVA.set_color);
  const grimSetColorPtr = grimPtr(grimMod, GRIM_RVA.set_color_ptr);
  const grimSetUv = grimPtr(grimMod, GRIM_RVA.set_uv);
  const grimSetUvPoint = grimPtr(grimMod, GRIM_RVA.set_uv_point);
  const grimSetAtlasFrame = grimPtr(grimMod, GRIM_RVA.set_atlas_frame);
  const grimSetSubRect = grimPtr(grimMod, GRIM_RVA.set_sub_rect);
  const grimSetRotation = grimPtr(grimMod, GRIM_RVA.set_rotation);

  const grimDrawRectFilled = grimPtr(grimMod, GRIM_RVA.draw_rect_filled);
  const grimDrawRectOutline = grimPtr(grimMod, GRIM_RVA.draw_rect_outline);
  const grimDrawQuad = grimPtr(grimMod, GRIM_RVA.draw_quad);
  const grimDrawQuadXy = grimPtr(grimMod, GRIM_RVA.draw_quad_xy);
  const grimDrawQuadRotMat = grimPtr(grimMod, GRIM_RVA.draw_quad_rotated_matrix);
  const grimDrawQuadPoints = grimPtr(grimMod, GRIM_RVA.draw_quad_points);

  const grimSubmitOffset = grimPtr(grimMod, GRIM_RVA.submit_vertices_offset);
  const grimSubmitTransform = grimPtr(grimMod, GRIM_RVA.submit_vertices_transform);
  const grimSubmitOffsetColor = grimPtr(grimMod, GRIM_RVA.submit_vertices_offset_color);
  const grimSubmitTransformColor = grimPtr(grimMod, GRIM_RVA.submit_vertices_transform_color);

  const grimDrawTextMono = grimPtr(grimMod, GRIM_RVA.draw_text_mono);
  const grimDrawTextSmall = grimPtr(grimMod, GRIM_RVA.draw_text_small);

  // Soft validation: if core hooks are missing, bail (wrong build).
  if (!uiElementsUpdateAndRender || !uiElementRender) return;
  if (!grimBindTexture || !grimSubmitOffset || !grimSubmitTransform) return;

  ATTACHED = true;

  refreshUiTable(exeMod);

  let lastAutoMarkKey = null;
  let lastAutoMarkAtMs = 0;
  let lastAutoResKey = null;

  function maybeAutoMark(ctx) {
    if (!CONFIG.autoMark) return;
    const t = nowMs();
    if (t - lastAutoMarkAtMs < CONFIG.autoMarkIntervalMs) return;
    lastAutoMarkAtMs = t;

    const state = readExeState(exeMod);
    if (!state || !state.res || !state.game) return;

    const resKey = `${state.res.w}x${state.res.h}:${state.res.windowed ? 'win' : 'fs'}`;
    if (lastAutoResKey && resKey !== lastAutoResKey) {
      writeLog({ event: 'auto_mark', kind: 'resolution_change', from: lastAutoResKey, to: resKey, state: state });
    }
    lastAutoResKey = resKey;

    const active = collectUiActiveSignature(exeMod);
    const texts = (ctx && ctx.frame_texts) ? ctx.frame_texts.slice(0, CONFIG.autoMarkTextLimit) : [];

    const fingerprintObj = {
      res: resKey,
      state_id: state.game.state_id,
      active: active,
      texts: texts,
    };
    const key = fnv1a32(JSON.stringify(fingerprintObj));
    if (key === lastAutoMarkKey) return;
    lastAutoMarkKey = key;

    const title = texts.length > 0 ? texts[0] : null;
    const label = title ? `state_${state.game.state_id}:${title}` : `state_${state.game.state_id}`;
    writeLog({
      event: 'auto_mark',
      kind: 'screen',
      key: key,
      label: label,
      state: state,
      active: active,
      texts: texts,
    });
  }

  writeLog({
    event: 'init',
    frida: { version: Frida.version, runtime: Script.runtime },
    process: { pid: Process.id, arch: Process.arch, pointer_size: Process.pointerSize },
    exe: { name: exeMod.name, base: exeMod.base.toString(), link_base: LINK_BASE.toString() },
    grim: { name: grimMod.name, base: grimMod.base.toString() },
    config: CONFIG,
    state: readExeState(exeMod),
  });

  // --- Scope anchors (EXE) ---
  Interceptor.attach(uiElementsUpdateAndRender, {
    onEnter() {
      const ctx = getCtx(this.threadId);
      ctx.ui_depth += 1;
      if (ctx.ui_depth === 1) {
        UI_FRAME += 1;
        ctx.ui_frame = UI_FRAME;
        ctx.frame_texts = [];
        ctx.frame_text_set = {};
        writeLog({ event: 'ui_frame_begin', tid: this.threadId, ui_frame: ctx.ui_frame, state: readExeState(exeMod) });
      }
      pushScope(ctx, { kind: 'ui_elements', ui_frame: ctx.ui_frame });
    },
    onLeave() {
      const ctx = getCtx(this.threadId);
      popScope(ctx, 'ui_elements');
      if (ctx.ui_depth > 0) ctx.ui_depth -= 1;
      if (ctx.ui_depth === 0) {
        writeLog({ event: 'ui_frame_end', tid: this.threadId, ui_frame: ctx.ui_frame });
        maybeAutoMark(ctx);
      }
    },
  });

  Interceptor.attach(uiElementRender, {
    onEnter(args) {
      const ctx = getCtx(this.threadId);
      const elementPtr = args[0];
      ctx.element_ptr = elementPtr;
      ctx.element_index = getUiElementIndex(elementPtr);
      pushScope(ctx, { kind: 'ui_element', ptr: elementPtr.toString(), index: ctx.element_index, ui_frame: ctx.ui_frame });
      writeLog({
        event: 'ui_element_begin',
        tid: this.threadId,
        ui_frame: ctx.ui_frame,
        element: { ptr: elementPtr.toString(), index: ctx.element_index, snapshot: readUiElementSummary(elementPtr) },
        state_id: safeReadS32(exeRvaPtr(exeMod, EXE_DATA_RVA.game_state_id)),
      });
    },
    onLeave() {
      const ctx = getCtx(this.threadId);
      popScope(ctx, 'ui_element');
      ctx.element_ptr = null;
      ctx.element_index = null;
    },
  });

  function hookScopeOnly(name, ptrFn, argReader) {
    if (!ptrFn) return;
    Interceptor.attach(ptrFn, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        const payload = argReader ? argReader(args, this) : null;
        pushScope(ctx, { kind: name, payload: payload });
        writeLog({
          event: 'scope_begin',
          tid: this.threadId,
          ui_frame: ctx.ui_frame,
          scope: name,
          payload: payload,
          state_id: safeReadS32(exeRvaPtr(exeMod, EXE_DATA_RVA.game_state_id)),
        });
      },
      onLeave(retval) {
        const ctx = getCtx(this.threadId);
        const top = ctx.scope_stack.length > 0 ? ctx.scope_stack[ctx.scope_stack.length - 1] : null;
        popScope(ctx, name);
        writeLog({
          event: 'scope_end',
          tid: this.threadId,
          ui_frame: ctx.ui_frame,
          scope: name,
          ret: retval ? retval.toInt32() : null,
          payload: top ? top.payload : null,
        });
      },
    });
  }

  hookScopeOnly('ui_draw_textured_quad', uiDrawTexturedQuad, (args) => {
    return {
      texture_id: args[0].toInt32(),
      x: args[1].toInt32(),
      y: args[2].toInt32(),
      w: args[3].toInt32(),
      h: args[4].toInt32(),
    };
  });

  hookScopeOnly('ui_draw_progress_bar', uiDrawProgressBar, (args, inv) => {
    const xy = readF32x2(args[0]);
    const rgba = args[3] ? [safeReadF32(args[3].add(0)), safeReadF32(args[3].add(4)), safeReadF32(args[3].add(8)), safeReadF32(args[3].add(12))] : null;
    // width/ratio are f32-by-value on ia32; read from stack for correctness.
    return { xy: xy, width: readStackF32(inv, 8), ratio: readStackF32(inv, 12), rgba: rgba };
  });

  // UI widgets: record inputs for "what screen is this" reconstruction.
  hookScopeOnly('ui_button_update', uiButtonUpdate, (args) => {
    return { xy: readF32x2(args[0]), button: readUiButton(args[1]) };
  });
  hookScopeOnly('ui_menu_item_update', uiMenuItemUpdate, (args) => {
    return { xy: readF32x2(args[0]), item_ptr: args[1] ? args[1].toString() : null };
  });
  hookScopeOnly('ui_checkbox_update', uiCheckboxUpdate, (args) => {
    return { xy: readF32x2(args[0]), checkbox_ptr: args[1] ? args[1].toString() : null };
  });
  hookScopeOnly('ui_scrollbar_update', uiScrollbarUpdate, (args) => {
    return { xy: readF32x2(args[0]), state_ptr: args[1] ? args[1].toString() : null };
  });
  hookScopeOnly('ui_text_input_update', uiTextInputUpdate, (args) => {
    return { xy: readF32x2(args[0]), input_state_ptr: args[1] ? args[1].toString() : null };
  });
  hookScopeOnly('ui_text_input_render', uiTextInputRender, (args, inv) => {
    // void ui_text_input_render(void *input_state, float y, float alpha)
    return { input_state_ptr: args[0] ? args[0].toString() : null, y: readStackF32(inv, 8), alpha: readStackF32(inv, 12) };
  });
  hookScopeOnly('ui_list_widget_update', uiListWidgetUpdate, (args) => {
    return { xy: readF32x2(args[0]), list_ptr: args[1] ? args[1].toString() : null };
  });
  hookScopeOnly('ui_update_notice_update', uiUpdateNoticeUpdate, (args, inv) => {
    return { xy: readF32x2(args[0]), alpha: readStackF32(inv, 8) };
  });

  // --- Grim hooks (only log when we appear to be in UI scope) ---
  if (grimGetTextureHandle) {
    Interceptor.attach(grimGetTextureHandle, {
      onEnter(args) {
        this._name = args[0] ? safeReadCString(args[0], 256) : null;
      },
      onLeave(retval) {
        const handle = retval ? retval.toInt32() : null;
        if (handle == null) return;
        if (this._name) textureNames[String(handle)] = this._name;
        writeLog({ event: 'texture_handle', handle: handle, name: this._name });
      },
    });
  }

  if (grimBindTexture) {
    Interceptor.attach(grimBindTexture, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        const handle = args[0].toInt32();
        const stage = args[1].toInt32();
        if (stage === 0) ctx.draw.texture0 = handle;
        if (!inUiScope(ctx)) return;
        writeLog({
          event: 'grim_bind_texture',
          tid: this.threadId,
          ui_frame: ctx.ui_frame,
          handle: handle,
          stage: stage,
          name: textureNames[String(handle)] || null,
          element: ctx.element_ptr ? { ptr: ctx.element_ptr.toString(), index: ctx.element_index } : null,
        });
      },
    });
  }

  if (grimSetConfigVar) {
    Interceptor.attach(grimSetConfigVar, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        const id = args[0].toUInt32();
        const value = args[1].toUInt32();
        ctx.draw.config[String(id)] = value;
        if (!inUiScope(ctx)) return;
        writeLog({ event: 'grim_set_config_var', tid: this.threadId, ui_frame: ctx.ui_frame, id: id, value: value });
      },
    });
  }

  if (grimSetColor) {
    Interceptor.attach(grimSetColor, {
      onEnter() {
        const ctx = getCtx(this.threadId);
        const rgba = [
          readStackF32(this, 4),
          readStackF32(this, 8),
          readStackF32(this, 12),
          readStackF32(this, 16),
        ];
        ctx.draw.color = rgba;
        if (!inUiScope(ctx)) return;
        writeLog({ event: 'grim_set_color', tid: this.threadId, ui_frame: ctx.ui_frame, rgba: rgba });
      },
    });
  }

  if (grimSetColorPtr) {
    Interceptor.attach(grimSetColorPtr, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        const rgba = args[0] ? [safeReadF32(args[0].add(0)), safeReadF32(args[0].add(4)), safeReadF32(args[0].add(8)), safeReadF32(args[0].add(12))] : null;
        ctx.draw.color = rgba;
        if (!inUiScope(ctx)) return;
        writeLog({ event: 'grim_set_color_ptr', tid: this.threadId, ui_frame: ctx.ui_frame, rgba: rgba });
      },
    });
  }

  if (grimSetUv) {
    Interceptor.attach(grimSetUv, {
      onEnter() {
        const ctx = getCtx(this.threadId);
        const uv = [
          readStackF32(this, 4),
          readStackF32(this, 8),
          readStackF32(this, 12),
          readStackF32(this, 16),
        ];
        ctx.draw.uv = uv;
        if (!inUiScope(ctx)) return;
        writeLog({ event: 'grim_set_uv', tid: this.threadId, ui_frame: ctx.ui_frame, uv: uv });
      },
    });
  }

  if (grimSetUvPoint) {
    Interceptor.attach(grimSetUvPoint, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        if (!inUiScope(ctx)) return;
        writeLog({
          event: 'grim_set_uv_point',
          tid: this.threadId,
          ui_frame: ctx.ui_frame,
          index: args[0].toInt32(),
          uv: [readStackF32(this, 8), readStackF32(this, 12)],
        });
      },
    });
  }

  if (grimSetAtlasFrame) {
    Interceptor.attach(grimSetAtlasFrame, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        ctx.draw.atlas = { atlas_size: args[0].toInt32(), frame: args[1].toInt32() };
        if (!inUiScope(ctx)) return;
        writeLog({ event: 'grim_set_atlas_frame', tid: this.threadId, ui_frame: ctx.ui_frame, atlas: ctx.draw.atlas });
      },
    });
  }

  if (grimSetSubRect) {
    Interceptor.attach(grimSetSubRect, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        ctx.draw.sub_rect = { atlas_size: args[0].toInt32(), width: args[1].toInt32(), height: args[2].toInt32(), frame: args[3].toInt32() };
        if (!inUiScope(ctx)) return;
        writeLog({ event: 'grim_set_sub_rect', tid: this.threadId, ui_frame: ctx.ui_frame, sub_rect: ctx.draw.sub_rect });
      },
    });
  }

  if (grimSetRotation) {
    Interceptor.attach(grimSetRotation, {
      onEnter() {
        const ctx = getCtx(this.threadId);
        ctx.draw.rotation = readStackF32(this, 4);
        if (!inUiScope(ctx)) return;
        writeLog({ event: 'grim_set_rotation', tid: this.threadId, ui_frame: ctx.ui_frame, radians: ctx.draw.rotation });
      },
    });
  }

  function logDrawCall(invocation, evt) {
    const ctx = getCtx(invocation.threadId);
    if (!inUiScope(ctx)) return;
    evt.tid = invocation.threadId;
    evt.ui_frame = ctx.ui_frame;
    evt.state_id = safeReadS32(exeRvaPtr(exeMod, EXE_DATA_RVA.game_state_id));
    evt.element = ctx.element_ptr ? { ptr: ctx.element_ptr.toString(), index: ctx.element_index } : null;
    evt.scope = ctx.scope_stack.length > 0 ? ctx.scope_stack[ctx.scope_stack.length - 1].kind : null;
    evt.draw_state = {
      texture0: ctx.draw.texture0,
      texture0_name: ctx.draw.texture0 != null ? (textureNames[String(ctx.draw.texture0)] || null) : null,
      uv: ctx.draw.uv,
      color: ctx.draw.color,
      rotation: ctx.draw.rotation,
      atlas: ctx.draw.atlas,
      sub_rect: ctx.draw.sub_rect,
      // UI mostly uses these, and logging the full config map per draw bloats traces.
      config: {
        0x13: ctx.draw.config['19'] !== undefined ? ctx.draw.config['19'] : null,
        0x14: ctx.draw.config['20'] !== undefined ? ctx.draw.config['20'] : null,
        0x15: ctx.draw.config['21'] !== undefined ? ctx.draw.config['21'] : null,
      },
    };
    if (CONFIG.includeBacktrace) evt.backtrace = backtraceAddrs(invocation, 10);
    writeLog(evt);
  }

  if (grimDrawRectFilled) {
    Interceptor.attach(grimDrawRectFilled, {
      onEnter(args) {
        logDrawCall(this, {
          event: 'grim_draw_rect_filled',
          xy: readF32x2(args[0]),
          w: readStackF32(this, 8),
          h: readStackF32(this, 12),
        });
      },
    });
  }

  if (grimDrawRectOutline) {
    Interceptor.attach(grimDrawRectOutline, {
      onEnter(args) {
        logDrawCall(this, {
          event: 'grim_draw_rect_outline',
          xy: readF32x2(args[0]),
          w: readStackF32(this, 8),
          h: readStackF32(this, 12),
        });
      },
    });
  }

  if (grimDrawQuad) {
    Interceptor.attach(grimDrawQuad, {
      onEnter() {
        logDrawCall(this, {
          event: 'grim_draw_quad',
          x: readStackF32(this, 4),
          y: readStackF32(this, 8),
          w: readStackF32(this, 12),
          h: readStackF32(this, 16),
        });
      },
    });
  }

  if (grimDrawQuadXy) {
    Interceptor.attach(grimDrawQuadXy, {
      onEnter(args) {
        logDrawCall(this, {
          event: 'grim_draw_quad_xy',
          xy: readF32x2(args[0]),
          w: readStackF32(this, 8),
          h: readStackF32(this, 12),
        });
      },
    });
  }

  if (grimDrawQuadRotMat) {
    Interceptor.attach(grimDrawQuadRotMat, {
      onEnter() {
        logDrawCall(this, {
          event: 'grim_draw_quad_rotated_matrix',
          x: readStackF32(this, 4),
          y: readStackF32(this, 8),
          w: readStackF32(this, 12),
          h: readStackF32(this, 16),
        });
      },
    });
  }

  if (grimDrawQuadPoints) {
    Interceptor.attach(grimDrawQuadPoints, {
      onEnter() {
        logDrawCall(this, {
          event: 'grim_draw_quad_points',
          p0: [readStackF32(this, 4), readStackF32(this, 8)],
          p1: [readStackF32(this, 12), readStackF32(this, 16)],
          p2: [readStackF32(this, 20), readStackF32(this, 24)],
          p3: [readStackF32(this, 28), readStackF32(this, 32)],
        });
      },
    });
  }

  function hookSubmit(name, ptrFn, hasMatrix, hasColor) {
    if (!ptrFn) return;
    Interceptor.attach(ptrFn, {
      onEnter(args) {
        const ctx = getCtx(this.threadId);
        if (!inUiScope(ctx)) return;
        const vertsPtr = args[0];
        const count = args[1].toInt32();
        const offsetPtr = args[2];
        const matrixPtr = hasMatrix ? args[3] : null;
        const colorPtr = hasColor ? args[hasMatrix ? 4 : 3] : null;

        const evt = {
          event: 'grim_submit_vertices',
          kind: name,
          count: count,
          verts_ptr: vertsPtr ? vertsPtr.toString() : null,
          offset_ptr: offsetPtr ? offsetPtr.toString() : null,
          offset: readF32x2(offsetPtr),
          matrix_ptr: matrixPtr ? matrixPtr.toString() : null,
          matrix: hasMatrix ? readF32x4(matrixPtr) : null,
          color_ptr: colorPtr ? colorPtr.toString() : null,
          color: colorPtr ? decodeColorU32(safeReadU32(colorPtr)) : null,
        };

        if (CONFIG.includeVerts) evt.verts = readVertices(vertsPtr, count);
        logDrawCall(this, evt);
      },
    });
  }

  hookSubmit('offset', grimSubmitOffset, false, false);
  hookSubmit('transform', grimSubmitTransform, true, false);
  hookSubmit('offset_color', grimSubmitOffsetColor, false, true);
  hookSubmit('transform_color', grimSubmitTransformColor, true, true);

  if (grimDrawTextMono) {
    Interceptor.attach(grimDrawTextMono, {
      onEnter() {
        const ctx = getCtx(this.threadId);
        if (!inUiScope(ctx)) return;
        const rawText = safeReadCString(readStackPtr(this, 12), 512);
        const s = sanitizeText(rawText);
        if (s && ctx.frame_texts.length < CONFIG.autoMarkTextLimit && !ctx.frame_text_set[s]) {
          ctx.frame_text_set[s] = 1;
          ctx.frame_texts.push(s);
        }
        logDrawCall(this, {
          event: 'grim_draw_text',
          font: 'mono',
          x: readStackF32(this, 4),
          y: readStackF32(this, 8),
          text: rawText,
        });
      },
    });
  }

  if (grimDrawTextSmall) {
    Interceptor.attach(grimDrawTextSmall, {
      onEnter() {
        const ctx = getCtx(this.threadId);
        if (!inUiScope(ctx)) return;
        const rawText = safeReadCString(readStackPtr(this, 12), 512);
        const s = sanitizeText(rawText);
        if (s && ctx.frame_texts.length < CONFIG.autoMarkTextLimit && !ctx.frame_text_set[s]) {
          ctx.frame_text_set[s] = 1;
          ctx.frame_texts.push(s);
        }
        logDrawCall(this, {
          event: 'grim_draw_text',
          font: 'small',
          x: readStackF32(this, 4),
          y: readStackF32(this, 8),
          text: rawText,
        });
      },
    });
  }
}

setImmediate(() => {
  // Wait for both modules. Some sessions attach early in startup.
  const timer = setInterval(() => {
    try {
      attachOnce();
      if (ATTACHED) clearInterval(timer);
    } catch (e) {
      console.log('[ui_render_trace] attach error: ' + e);
    }
  }, 50);
});
