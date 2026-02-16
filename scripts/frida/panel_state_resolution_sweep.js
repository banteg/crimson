'use strict';

// panel_state_resolution_sweep.js
//
// Goal:
// - Force the game through panel-heavy UI states automatically.
// - Capture panel element geometry + text draw calls for each state.
// - Write logs into a resolution-specific file so each launcher resolution
//   run produces an isolated artifact.
//
// Attach:
//   frida -n crimsonland.exe -l C:\share\frida\panel_state_resolution_sweep.js
//
// Typical workflow:
// 1) Start launcher, pick resolution.
// 2) Attach this script.
// 3) Press "Start Game".
// 4) Script auto-sweeps states and logs capture rows.
//
// Output (JSONL):
//   C:\share\frida\panel_state_resolution_capture_<WIDTH>x<HEIGHT>_<RUNID>.jsonl
//
// Optional env:
//   CRIMSON_FRIDA_DIR=C:\share\frida
//   CRIMSON_FRIDA_MODULE=crimsonland.exe
//   CRIMSON_FRIDA_LINK_BASE=0x00400000
//   CRIMSON_PANEL_SWEEP_STATES=0,1,2,3,4,11,14,15,16,17,20,26,5,6,7,8,12,21
//   CRIMSON_PANEL_SWEEP_START_DELAY_MS=1800
//   CRIMSON_PANEL_SWEEP_ENTER_TIMEOUT_MS=3500
//   CRIMSON_PANEL_SWEEP_SETTLE_MS=300
//   CRIMSON_PANEL_SWEEP_DWELL_MS=1200
//   CRIMSON_PANEL_SWEEP_MAX_UNIQUE_PANELS=1200
//   CRIMSON_PANEL_SWEEP_MAX_UNIQUE_TEXTS=1800
//   CRIMSON_PANEL_SWEEP_ZERO_SIGNAL_RETRIES=1
//   CRIMSON_PANEL_SWEEP_CONSOLE=1

const DEFAULT_LOG_DIR = 'C:\\share\\frida';
const DEFAULT_EXE_MODULE = 'crimsonland.exe';
const DEFAULT_GRIM_MODULE = 'grim.dll';

const DEFAULT_SWEEP_STATES = [0, 1, 2, 3, 4, 11, 14, 15, 16, 17, 20, 26, 5, 6, 7, 8, 12, 21];

const STATE_LABELS = {
  0: 'main_menu',
  1: 'play_menu',
  2: 'options_menu',
  3: 'controls_menu',
  4: 'statistics',
  5: 'pause_overlay',
  6: 'perk_selection',
  7: 'game_over',
  8: 'quest_results',
  9: 'gameplay',
  10: 'quit_transition',
  11: 'quest_select',
  12: 'quest_failed',
  13: 'highscore_variant_legacy',
  14: 'high_scores',
  15: 'weapons_database',
  16: 'perks_database',
  17: 'credits',
  18: 'typo_gameplay',
  19: 'unknown_19',
  20: 'mods_menu',
  21: 'final_quest_end_note',
  22: 'plugin_runtime',
  23: 'unknown_23',
  24: 'legacy_demo_branch',
  25: 'pending_sentinel',
  26: 'alien_zookeeper',
};

const ADDR = {
  game_state_set: 0x004461c0,
  ui_elements_update_and_render: 0x0041a530,
  ui_element_render: 0x00446c40,

  game_state_prev: 0x0048726c,
  game_state_id: 0x00487270,
  game_state_pending: 0x00487274,
  ui_elements_timeline: 0x00487248,
  ui_transition_direction: 0x0048724c,
  ui_transition_alpha: 0x00487278,

  config_screen_width: 0x00480504,
  config_screen_height: 0x00480508,
  config_windowed: 0x0048050c,

  ui_element_table_base: 0x0048f168,
};

const GRIM_RVA = {
  draw_text_mono: 0x092b0,
  draw_text_small: 0x09730,
};

const UI_ELEMENT_TABLE_COUNT = 41;
const UI_OFF = {
  active: 0x00,
  ready: 0x01,
  disabled: 0x02,
  render_mode: 0x04,
  slide_x: 0x08,
  slide_y: 0x0c,
  start_ms: 0x10,
  end_ms: 0x14,
  pos_x: 0x18,
  pos_y: 0x1c,
  bounds_l: 0x20,
  bounds_t: 0x24,
  bounds_r: 0x28,
  bounds_b: 0x2c,
  custom_render: 0x38,
  texture_handle: 0x11c,
  quad_mode: 0x120,
  overlay_texture_handle: 0x204,
  hover_amount: 0x2f8,
  time_since_ready: 0x2fc,
  render_scale: 0x300,
  direction_flag: 0x314,
  quad0: 0x3c,
  quad_stride: 0x1c,
};

function getEnv(name, fallback) {
  try {
    const raw = Process.env[name];
    return raw == null || raw === '' ? fallback : raw;
  } catch (_) {
    return fallback;
  }
}

function getIntEnv(name, fallback) {
  const raw = getEnv(name, null);
  if (raw == null) return fallback;
  const parsed = parseInt(String(raw).trim(), 0);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function getBoolEnv(name, fallback) {
  const raw = getEnv(name, null);
  if (raw == null) return fallback;
  const s = String(raw).trim().toLowerCase();
  if (s === '1' || s === 'true' || s === 'yes' || s === 'on') return true;
  if (s === '0' || s === 'false' || s === 'no' || s === 'off') return false;
  return fallback;
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith('\\') || base.endsWith('/') ? '' : '\\';
  return base + sep + leaf;
}

function parseStateList(raw, fallback) {
  if (raw == null) return fallback.slice();
  const seen = {};
  const out = [];
  const parts = String(raw)
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (let i = 0; i < parts.length; i++) {
    const v = parseInt(parts[i], 0);
    if (!Number.isFinite(v)) continue;
    const key = String(v | 0);
    if (seen[key]) continue;
    seen[key] = 1;
    out.push(v | 0);
  }
  return out.length > 0 ? out : fallback.slice();
}

const CONFIG = {
  logDir: getEnv('CRIMSON_FRIDA_DIR', DEFAULT_LOG_DIR),
  exeModuleName: getEnv('CRIMSON_FRIDA_MODULE', DEFAULT_EXE_MODULE),
  grimModuleName: getEnv('CRIMSON_FRIDA_GRIM_MODULE', DEFAULT_GRIM_MODULE),
  sweepStates: parseStateList(getEnv('CRIMSON_PANEL_SWEEP_STATES', null), DEFAULT_SWEEP_STATES),

  startDelayMs: Math.max(0, getIntEnv('CRIMSON_PANEL_SWEEP_START_DELAY_MS', 1800)),
  enterTimeoutMs: Math.max(500, getIntEnv('CRIMSON_PANEL_SWEEP_ENTER_TIMEOUT_MS', 3500)),
  settleMs: Math.max(0, getIntEnv('CRIMSON_PANEL_SWEEP_SETTLE_MS', 300)),
  dwellMs: Math.max(200, getIntEnv('CRIMSON_PANEL_SWEEP_DWELL_MS', 1200)),

  maxUniquePanelsPerState: Math.max(64, getIntEnv('CRIMSON_PANEL_SWEEP_MAX_UNIQUE_PANELS', 1200)),
  maxUniqueTextsPerState: Math.max(64, getIntEnv('CRIMSON_PANEL_SWEEP_MAX_UNIQUE_TEXTS', 1800)),
  zeroSignalRetries: Math.max(0, getIntEnv('CRIMSON_PANEL_SWEEP_ZERO_SIGNAL_RETRIES', 1)),
  logToConsole: getBoolEnv('CRIMSON_PANEL_SWEEP_CONSOLE', false),
};

let LINK_BASE = ptr('0x00400000');
{
  const raw = getEnv('CRIMSON_FRIDA_LINK_BASE', null) || getEnv('CRIMSON_FRIDA_IMAGE_BASE', null);
  if (raw != null) {
    const parsed = parseInt(String(raw).trim(), 0);
    if (Number.isFinite(parsed)) LINK_BASE = ptr(parsed);
  }
}

const RUN_ID = nowIsoCompact() + '_' + Math.floor(Math.random() * 0x100000000).toString(16).padStart(8, '0');

let attached = false;
let exeModule = null;
let grimModule = null;
let baseExe = null;
let baseGrim = null;
let gameStateSetFn = null;

let outFile = null;
let outPath = null;
let outResKey = null;
let outWarned = false;
const outPathsByResolution = {};
const pendingRows = [];
const MAX_PENDING_ROWS = 4096;

let uiFrameSeq = 0;
let uiElementIndexByPtr = {};

let latestSnapshot = null;
let latestSnapshotMs = 0;

const selfStateSetWindow = {
  target: null,
  untilMs: 0,
};

const sweep = {
  phase: 'waiting_boot',
  phaseSinceMs: 0,
  startEligibleAtMs: 0,
  currentIndex: -1,
  currentTarget: null,
  currentStats: null,
  results: [],
  done: false,
};

function nowMs() {
  return Date.now();
}

function nowIso() {
  return new Date().toISOString();
}

function nowIsoCompact() {
  return nowIso().replace(/[:-]/g, '').replace(/\..+$/, '').replace('T', '_');
}

function labelForState(stateId) {
  const key = String(stateId | 0);
  return STATE_LABELS[key] || ('state_' + key);
}

function round3(v) {
  if (v == null || !Number.isFinite(v)) return null;
  return Math.round(v * 1000) / 1000;
}

function keyNum(v) {
  if (v == null || !Number.isFinite(v)) return 'null';
  return (Math.round(v * 1000) / 1000).toFixed(3);
}

function staticPtr(staticVa) {
  if (!baseExe) return null;
  try {
    return baseExe.add(ptr(staticVa).sub(LINK_BASE));
  } catch (_) {
    return null;
  }
}

function grimPtr(rva) {
  if (!baseGrim) return null;
  try {
    return baseGrim.add(ptr(rva));
  } catch (_) {
    return null;
  }
}

function safeReadS32(p) {
  try {
    return p ? p.readS32() : null;
  } catch (_) {
    return null;
  }
}

function safeReadU8(p) {
  try {
    return p ? p.readU8() : null;
  } catch (_) {
    return null;
  }
}

function safeReadF32(p) {
  try {
    return p ? p.readFloat() : null;
  } catch (_) {
    return null;
  }
}

function safeReadPtr(p) {
  try {
    return p ? p.readPointer() : null;
  } catch (_) {
    return null;
  }
}

function safeReadCString(p, limit) {
  try {
    if (!p || p.isNull()) return null;
    return limit == null ? p.readCString() : p.readCString(limit);
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

function readStackPtr(invocation, offset) {
  try {
    const sp = getStackPointer(invocation.context);
    if (!sp) return null;
    return sp.add(offset).readPointer();
  } catch (_) {
    return null;
  }
}

function readStackF32(invocation, offset) {
  try {
    const sp = getStackPointer(invocation.context);
    if (!sp) return null;
    return sp.add(offset).readFloat();
  } catch (_) {
    return null;
  }
}

function sanitizeText(raw) {
  if (raw == null) return null;
  let s = String(raw);
  if (!s) return null;
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s.charAt(i);
    const code = s.charCodeAt(i);
    if (ch === '\ufffd') break;
    if (code < 0x20) {
      if (ch === ' ' || ch === '\t') {
        out.push(' ');
      } else {
        break;
      }
      continue;
    }
    if (code > 0x7e) break;
    out.push(ch);
    if (out.length >= 256) break;
  }
  s = out.join('').replace(/\s+/g, ' ').trim();
  if (s.length === 0) return null;
  return s;
}

function readRuntimeSnapshot() {
  if (!baseExe) return null;
  return {
    res: {
      w: safeReadS32(staticPtr(ADDR.config_screen_width)),
      h: safeReadS32(staticPtr(ADDR.config_screen_height)),
      windowed: safeReadS32(staticPtr(ADDR.config_windowed)),
    },
    game: {
      state_prev: safeReadS32(staticPtr(ADDR.game_state_prev)),
      state_id: safeReadS32(staticPtr(ADDR.game_state_id)),
      state_pending: safeReadS32(staticPtr(ADDR.game_state_pending)),
    },
    ui: {
      timeline: safeReadS32(staticPtr(ADDR.ui_elements_timeline)),
      direction: safeReadS32(staticPtr(ADDR.ui_transition_direction)),
      alpha: safeReadF32(staticPtr(ADDR.ui_transition_alpha)),
    },
  };
}

function snapshotNow() {
  const snap = readRuntimeSnapshot();
  if (snap) {
    latestSnapshot = snap;
    latestSnapshotMs = nowMs();
  }
  return snap;
}

function resolutionKeyOf(snapshot) {
  if (!snapshot || !snapshot.res) return 'unknown';
  const w = snapshot.res.w;
  const h = snapshot.res.h;
  if (!Number.isFinite(w) || !Number.isFinite(h) || w <= 0 || h <= 0) return 'unknown';
  return String(w | 0) + 'x' + String(h | 0);
}

function openOutputForResolution(resKey) {
  if (outResKey === resKey && outFile) return;
  const filename = 'panel_state_resolution_capture_' + resKey + '_' + RUN_ID + '.jsonl';
  const path = joinPath(CONFIG.logDir, filename);
  let newFile = null;
  try {
    newFile = new File(path, 'w');
  } catch (_) {
    newFile = null;
  }
  outFile = newFile;
  outPath = path;
  outResKey = resKey;
  outPathsByResolution[resKey] = path;
  outWarned = false;
  console.log('[panel_state_resolution_sweep] output: ' + path);

  if (outFile && pendingRows.length > 0) {
    for (let i = 0; i < pendingRows.length; i++) {
      try {
        outFile.write(pendingRows[i] + '\n');
      } catch (_) {
        break;
      }
    }
    pendingRows.length = 0;
  }
}

function maybeRotateOutput(snapshot) {
  const key = resolutionKeyOf(snapshot);
  if (key === 'unknown') return;
  if (outResKey !== key || !outFile) openOutputForResolution(key);
}

function writeEvent(event) {
  const payload = Object.assign(
    {
      ts_ms: nowMs(),
      ts_iso: nowIso(),
      script: 'panel_state_resolution_sweep',
      run_id: RUN_ID,
      ui_frame: uiFrameSeq,
    },
    event,
  );

  const snap = latestSnapshot || readRuntimeSnapshot();
  if (snap) {
    payload.resolution = snap.res;
    payload.state = snap.game;
    payload.ui = snap.ui;
  }
  if (outPath) payload.log_path = outPath;

  const line = JSON.stringify(payload);
  let wrote = false;

  try {
    if (outFile) {
      outFile.write(line + '\n');
      wrote = true;
    } else if (pendingRows.length < MAX_PENDING_ROWS) {
      pendingRows.push(line);
    }
  } catch (_) {}

  if (!wrote && !outWarned) {
    outWarned = true;
    console.log('[panel_state_resolution_sweep] file logging unavailable; console fallback');
  }

  if (CONFIG.logToConsole || !wrote) console.log(line);
}

function refreshUiElementIndexMap() {
  if (!baseExe) return;
  const tableBase = staticPtr(ADDR.ui_element_table_base);
  if (!tableBase) return;
  const map = {};
  for (let i = 0; i < UI_ELEMENT_TABLE_COUNT; i++) {
    const slot = tableBase.add(i * Process.pointerSize);
    const elemPtr = safeReadPtr(slot);
    if (!elemPtr || elemPtr.isNull()) continue;
    map[elemPtr.toString()] = i;
  }
  uiElementIndexByPtr = map;
}

function uiElementIndex(ptrValue) {
  if (!ptrValue) return null;
  const key = ptrValue.toString();
  if (uiElementIndexByPtr[key] !== undefined) return uiElementIndexByPtr[key];
  refreshUiElementIndexMap();
  return uiElementIndexByPtr[key] !== undefined ? uiElementIndexByPtr[key] : null;
}

function readUiQuadPoints(elementPtr) {
  if (!elementPtr) return null;
  const out = [];
  const q0 = elementPtr.add(UI_OFF.quad0);
  for (let i = 0; i < 4; i++) {
    const v = q0.add(i * UI_OFF.quad_stride);
    out.push([safeReadF32(v), safeReadF32(v.add(4))]);
  }
  return out;
}

function bboxFromPoints(points) {
  if (!Array.isArray(points)) return null;
  let minX = null;
  let minY = null;
  let maxX = null;
  let maxY = null;
  for (let i = 0; i < points.length; i++) {
    const p = points[i];
    if (!Array.isArray(p) || p.length !== 2) continue;
    const x = p[0];
    const y = p[1];
    if (!Number.isFinite(x) || !Number.isFinite(y)) continue;
    if (minX == null || x < minX) minX = x;
    if (minY == null || y < minY) minY = y;
    if (maxX == null || x > maxX) maxX = x;
    if (maxY == null || y > maxY) maxY = y;
  }
  if (minX == null || minY == null || maxX == null || maxY == null) return null;
  return [round3(minX), round3(minY), round3(maxX), round3(maxY)];
}

function readUiElementSnapshot(elementPtr) {
  if (!elementPtr) return null;

  const slideX = safeReadF32(elementPtr.add(UI_OFF.slide_x));
  const slideY = safeReadF32(elementPtr.add(UI_OFF.slide_y));
  const posX = safeReadF32(elementPtr.add(UI_OFF.pos_x));
  const posY = safeReadF32(elementPtr.add(UI_OFF.pos_y));

  const quadLocal = readUiQuadPoints(elementPtr);
  const quadWorldApprox = [];
  for (let i = 0; i < quadLocal.length; i++) {
    const q = quadLocal[i];
    if (!Array.isArray(q) || q.length !== 2 || q[0] == null || q[1] == null) {
      quadWorldApprox.push([null, null]);
      continue;
    }
    const wx = (q[0] || 0) + (posX || 0) + (slideX || 0);
    const wy = (q[1] || 0) + (posY || 0) + (slideY || 0);
    quadWorldApprox.push([round3(wx), round3(wy)]);
  }

  return {
    ptr: elementPtr.toString(),
    index: uiElementIndex(elementPtr),
    active: safeReadU8(elementPtr.add(UI_OFF.active)),
    ready: safeReadU8(elementPtr.add(UI_OFF.ready)),
    disabled: safeReadU8(elementPtr.add(UI_OFF.disabled)),
    render_mode: safeReadS32(elementPtr.add(UI_OFF.render_mode)),
    slide: [round3(slideX), round3(slideY)],
    timeline: {
      start_ms: safeReadS32(elementPtr.add(UI_OFF.start_ms)),
      end_ms: safeReadS32(elementPtr.add(UI_OFF.end_ms)),
    },
    pos: [round3(posX), round3(posY)],
    bounds: [
      round3(safeReadF32(elementPtr.add(UI_OFF.bounds_l))),
      round3(safeReadF32(elementPtr.add(UI_OFF.bounds_t))),
      round3(safeReadF32(elementPtr.add(UI_OFF.bounds_r))),
      round3(safeReadF32(elementPtr.add(UI_OFF.bounds_b))),
    ],
    custom_render: (safeReadPtr(elementPtr.add(UI_OFF.custom_render)) || ptr('0')).toString(),
    texture_handle: safeReadS32(elementPtr.add(UI_OFF.texture_handle)),
    quad_mode: safeReadS32(elementPtr.add(UI_OFF.quad_mode)),
    overlay_texture_handle: safeReadS32(elementPtr.add(UI_OFF.overlay_texture_handle)),
    hover_amount: safeReadS32(elementPtr.add(UI_OFF.hover_amount)),
    time_since_ready: safeReadS32(elementPtr.add(UI_OFF.time_since_ready)),
    render_scale: round3(safeReadF32(elementPtr.add(UI_OFF.render_scale))),
    direction_flag: safeReadS32(elementPtr.add(UI_OFF.direction_flag)),
    quad_local: quadLocal.map((q) => [round3(q[0]), round3(q[1])]),
    quad_local_bbox: bboxFromPoints(quadLocal),
    quad_world_approx: quadWorldApprox,
    quad_world_approx_bbox: bboxFromPoints(quadWorldApprox),
  };
}

function shouldCaptureCurrentState() {
  if (sweep.phase !== 'capture') return false;
  const stats = sweep.currentStats;
  if (!stats) return false;
  const snap = latestSnapshot;
  if (!snap || !snap.game) return false;
  return snap.game.state_id === stats.target_state;
}

function panelDedupKey(element) {
  return [
    element.index == null ? 'idx?' : String(element.index),
    String(element.render_mode),
    String(element.texture_handle),
    String(element.overlay_texture_handle),
    String(element.quad_mode),
    keyNum(element.pos[0]),
    keyNum(element.pos[1]),
    keyNum(element.slide[0]),
    keyNum(element.slide[1]),
    keyNum(element.bounds[0]),
    keyNum(element.bounds[1]),
    keyNum(element.bounds[2]),
    keyNum(element.bounds[3]),
    keyNum(element.render_scale),
  ].join('|');
}

function textDedupKey(font, x, y, text) {
  return [font, keyNum(x), keyNum(y), text].join('|');
}

function resolveAbi() {
  if (Process.platform !== 'windows') return null;
  if (Process.arch === 'x64') return 'win64';
  if (Process.arch === 'ia32') return 'mscdecl';
  return null;
}

function requestStateSet(stateId) {
  if (!gameStateSetFn) return false;
  selfStateSetWindow.target = stateId | 0;
  selfStateSetWindow.untilMs = nowMs() + 750;
  try {
    gameStateSetFn(stateId | 0);
    return true;
  } catch (e) {
    writeEvent({
      event: 'error',
      where: 'request_state_set',
      state_id: stateId | 0,
      error: String(e),
    });
    return false;
  }
}

function beginNextState() {
  sweep.currentIndex += 1;
  if (sweep.currentIndex >= CONFIG.sweepStates.length) {
    sweep.done = true;
    sweep.phase = 'done';
    sweep.phaseSinceMs = nowMs();
    writeEvent({
      event: 'sweep_done',
      states_total: CONFIG.sweepStates.length,
      results: sweep.results,
      output_files: outPathsByResolution,
    });
    requestStateSet(0);
    return;
  }

  const target = CONFIG.sweepStates[sweep.currentIndex] | 0;
  sweep.currentTarget = target;
  sweep.currentStats = {
    target_state: target,
    target_label: labelForState(target),
    attempt: 1,
    retries: 0,
    request_ts_ms: nowMs(),
    entered_ts_ms: null,
    capture_start_ts_ms: null,
    capture_end_ts_ms: null,
    enter_elapsed_ms: null,
    capture_elapsed_ms: null,
    result: 'pending',
    result_note: null,
    frames: 0,
    unique_panel_count: 0,
    unique_text_count: 0,
    panel_duplicates: 0,
    text_duplicates: 0,
    panel_dropped: 0,
    text_dropped: 0,
    sample_texts: [],
    panel_keys: {},
    text_keys: {},
  };

  const ok = requestStateSet(target);
  sweep.phase = 'wait_enter';
  sweep.phaseSinceMs = nowMs();
  writeEvent({
    event: 'state_request',
    target_state: target,
    target_label: labelForState(target),
    request_ok: ok,
  });
}

function resetCaptureAccumulators(stats) {
  stats.entered_ts_ms = null;
  stats.capture_start_ts_ms = null;
  stats.capture_end_ts_ms = null;
  stats.enter_elapsed_ms = null;
  stats.capture_elapsed_ms = null;
  stats.result = 'pending';
  stats.result_note = null;
  stats.frames = 0;
  stats.unique_panel_count = 0;
  stats.unique_text_count = 0;
  stats.panel_duplicates = 0;
  stats.text_duplicates = 0;
  stats.panel_dropped = 0;
  stats.text_dropped = 0;
  stats.sample_texts = [];
  stats.panel_keys = {};
  stats.text_keys = {};
}

function endCurrentState(result, note) {
  const stats = sweep.currentStats;
  if (!stats) return;

  const zeroSignalCaptured =
    result === 'captured' &&
    stats.frames === 0 &&
    stats.unique_panel_count === 0 &&
    stats.unique_text_count === 0;

  if (zeroSignalCaptured && stats.retries < CONFIG.zeroSignalRetries) {
    stats.retries += 1;
    stats.attempt += 1;
    resetCaptureAccumulators(stats);
    stats.request_ts_ms = nowMs();
    const ok = requestStateSet(stats.target_state);
    sweep.phase = 'wait_enter';
    sweep.phaseSinceMs = nowMs();
    writeEvent({
      event: 'state_retry',
      target_state: stats.target_state,
      target_label: stats.target_label,
      reason: 'zero_signal_capture',
      retry: stats.retries,
      attempt: stats.attempt,
      request_ok: ok,
    });
    return;
  }

  stats.result = result;
  stats.result_note = note || null;
  if (stats.entered_ts_ms != null) stats.enter_elapsed_ms = stats.entered_ts_ms - stats.request_ts_ms;
  if (stats.capture_start_ts_ms != null && stats.capture_end_ts_ms != null) {
    stats.capture_elapsed_ms = stats.capture_end_ts_ms - stats.capture_start_ts_ms;
  }

  const row = {
    target_state: stats.target_state,
    target_label: stats.target_label,
    attempt: stats.attempt,
    retries: stats.retries,
    request_ts_ms: stats.request_ts_ms,
    entered_ts_ms: stats.entered_ts_ms,
    capture_start_ts_ms: stats.capture_start_ts_ms,
    capture_end_ts_ms: stats.capture_end_ts_ms,
    enter_elapsed_ms: stats.enter_elapsed_ms,
    capture_elapsed_ms: stats.capture_elapsed_ms,
    result: stats.result,
    result_note: stats.result_note,
    frames: stats.frames,
    unique_panel_count: stats.unique_panel_count,
    unique_text_count: stats.unique_text_count,
    panel_duplicates: stats.panel_duplicates,
    text_duplicates: stats.text_duplicates,
    panel_dropped: stats.panel_dropped,
    text_dropped: stats.text_dropped,
    sample_texts: stats.sample_texts,
  };

  sweep.results.push(row);
  writeEvent(
    Object.assign(
      {
        event: 'state_result',
      },
      row,
    ),
  );

  sweep.currentTarget = null;
  sweep.currentStats = null;
  sweep.phase = 'advance';
  sweep.phaseSinceMs = nowMs();
}

function mainTick() {
  if (!attached || sweep.done) return;

  const snap = snapshotNow();
  maybeRotateOutput(snap);

  if (!snap || !snap.game) return;

  if (sweep.phase === 'waiting_boot') {
    if (snap.game.state_id == null) return;
    if (sweep.startEligibleAtMs === 0) {
      sweep.startEligibleAtMs = nowMs() + CONFIG.startDelayMs;
      writeEvent({
        event: 'boot_detected',
        start_delay_ms: CONFIG.startDelayMs,
        start_at_ms: sweep.startEligibleAtMs,
      });
      return;
    }
    if (nowMs() < sweep.startEligibleAtMs) return;
    sweep.phase = 'advance';
    sweep.phaseSinceMs = nowMs();
    writeEvent({
      event: 'sweep_begin',
      states: CONFIG.sweepStates,
      state_labels: CONFIG.sweepStates.map((id) => labelForState(id)),
    });
    return;
  }

  if (sweep.phase === 'advance') {
    beginNextState();
    return;
  }

  if (sweep.phase === 'wait_enter') {
    const stats = sweep.currentStats;
    if (!stats) {
      sweep.phase = 'advance';
      sweep.phaseSinceMs = nowMs();
      return;
    }

    if (snap.game.state_id === stats.target_state) {
      stats.entered_ts_ms = nowMs();
      sweep.phase = 'settle';
      sweep.phaseSinceMs = nowMs();
      writeEvent({
        event: 'state_entered',
        target_state: stats.target_state,
        target_label: stats.target_label,
      });
      return;
    }

    if (nowMs() - sweep.phaseSinceMs > CONFIG.enterTimeoutMs) {
      endCurrentState('enter_timeout', 'state did not become active before timeout');
      return;
    }
    return;
  }

  if (sweep.phase === 'settle') {
    const stats = sweep.currentStats;
    if (!stats) {
      sweep.phase = 'advance';
      sweep.phaseSinceMs = nowMs();
      return;
    }
    if (nowMs() - sweep.phaseSinceMs < CONFIG.settleMs) return;

    stats.capture_start_ts_ms = nowMs();
    sweep.phase = 'capture';
    sweep.phaseSinceMs = nowMs();
    writeEvent({
      event: 'capture_begin',
      target_state: stats.target_state,
      target_label: stats.target_label,
      dwell_ms: CONFIG.dwellMs,
    });
    return;
  }

  if (sweep.phase === 'capture') {
    const stats = sweep.currentStats;
    if (!stats) {
      sweep.phase = 'advance';
      sweep.phaseSinceMs = nowMs();
      return;
    }

    if (snap.game.state_id !== stats.target_state) {
      stats.capture_end_ts_ms = nowMs();
      endCurrentState('left_state', 'state changed before dwell window elapsed');
      return;
    }

    if (nowMs() - sweep.phaseSinceMs >= CONFIG.dwellMs) {
      stats.capture_end_ts_ms = nowMs();
      endCurrentState('captured', null);
    }
    return;
  }
}

function installHooks() {
  const gameStateSetPtr = staticPtr(ADDR.game_state_set);
  const uiUpdateAndRenderPtr = staticPtr(ADDR.ui_elements_update_and_render);
  const uiElementRenderPtr = staticPtr(ADDR.ui_element_render);
  const grimDrawTextMonoPtr = grimPtr(GRIM_RVA.draw_text_mono);
  const grimDrawTextSmallPtr = grimPtr(GRIM_RVA.draw_text_small);

  if (!gameStateSetPtr || !uiUpdateAndRenderPtr || !uiElementRenderPtr) {
    writeEvent({
      event: 'error',
      where: 'install_hooks',
      reason: 'required pointers unavailable',
    });
    return false;
  }

  const abi = resolveAbi();
  gameStateSetFn = abi
    ? new NativeFunction(gameStateSetPtr, 'void', ['int'], abi)
    : new NativeFunction(gameStateSetPtr, 'void', ['int']);

  Interceptor.attach(gameStateSetPtr, {
    onEnter(args) {
      const target = args[0].toInt32();
      const ts = nowMs();
      const fromSelf = selfStateSetWindow.target === target && ts <= selfStateSetWindow.untilMs;
      writeEvent({
        event: 'game_state_set_call',
        target_state: target,
        target_label: labelForState(target),
        from_self: fromSelf,
      });
    },
  });

  Interceptor.attach(uiUpdateAndRenderPtr, {
    onEnter() {
      uiFrameSeq += 1;
      snapshotNow();

      if (shouldCaptureCurrentState() && sweep.currentStats) {
        sweep.currentStats.frames += 1;
        if (sweep.currentStats.frames <= 4 || sweep.currentStats.frames % 20 === 0) {
          writeEvent({
            event: 'capture_frame',
            target_state: sweep.currentStats.target_state,
            frame_in_state: sweep.currentStats.frames,
          });
        }
      }
    },
  });

  Interceptor.attach(uiElementRenderPtr, {
    onEnter(args) {
      if (!shouldCaptureCurrentState()) return;
      const stats = sweep.currentStats;
      if (!stats) return;

      if (stats.unique_panel_count >= CONFIG.maxUniquePanelsPerState) {
        stats.panel_dropped += 1;
        return;
      }

      const element = readUiElementSnapshot(args[0]);
      if (!element) return;

      const key = panelDedupKey(element);
      if (stats.panel_keys[key]) {
        stats.panel_duplicates += 1;
        return;
      }
      stats.panel_keys[key] = 1;
      stats.unique_panel_count += 1;

      writeEvent({
        event: 'panel_element',
        target_state: stats.target_state,
        target_label: stats.target_label,
        element: element,
      });
    },
  });

  function attachTextHook(ptrFn, fontName) {
    if (!ptrFn) return;
    Interceptor.attach(ptrFn, {
      onEnter() {
        if (!shouldCaptureCurrentState()) return;
        const stats = sweep.currentStats;
        if (!stats) return;

        if (stats.unique_text_count >= CONFIG.maxUniqueTextsPerState) {
          stats.text_dropped += 1;
          return;
        }

        const x = readStackF32(this, 4);
        const y = readStackF32(this, 8);
        const textPtr = readStackPtr(this, 12);
        const text = sanitizeText(safeReadCString(textPtr, 512));
        if (!text) return;

        const key = textDedupKey(fontName, x, y, text);
        if (stats.text_keys[key]) {
          stats.text_duplicates += 1;
          return;
        }
        stats.text_keys[key] = 1;
        stats.unique_text_count += 1;

        if (stats.sample_texts.length < 20) stats.sample_texts.push(text);

        writeEvent({
          event: 'panel_text',
          target_state: stats.target_state,
          target_label: stats.target_label,
          font: fontName,
          x: round3(x),
          y: round3(y),
          text: text,
        });
      },
    });
  }

  attachTextHook(grimDrawTextMonoPtr, 'mono');
  attachTextHook(grimDrawTextSmallPtr, 'small');
  return true;
}

function attachOnce() {
  if (attached) return;
  const exe = Process.findModuleByName(CONFIG.exeModuleName);
  const grim = Process.findModuleByName(CONFIG.grimModuleName);
  if (!exe || !grim) return;

  exeModule = exe;
  grimModule = grim;
  baseExe = exe.base;
  baseGrim = grim.base;

  snapshotNow();
  maybeRotateOutput(latestSnapshot);
  refreshUiElementIndexMap();

  attached = installHooks();
  if (!attached) return;

  sweep.phase = 'waiting_boot';
  sweep.phaseSinceMs = nowMs();

  writeEvent({
    event: 'start',
    frida: { version: Frida.version, runtime: Script.runtime },
    process: {
      pid: Process.id,
      arch: Process.arch,
      pointer_size: Process.pointerSize,
      platform: Process.platform,
    },
    modules: {
      exe: { name: exeModule.name, base: exeModule.base.toString(), path: exeModule.path },
      grim: { name: grimModule.name, base: grimModule.base.toString(), path: grimModule.path },
    },
    config: CONFIG,
    link_base: LINK_BASE.toString(),
    addresses: ADDR,
    grim_rva: GRIM_RVA,
  });
}

globalThis.panelSweepStatus = function panelSweepStatus() {
  return {
    run_id: RUN_ID,
    attached: attached,
    phase: sweep.phase,
    current_index: sweep.currentIndex,
    current_target: sweep.currentTarget,
    current_target_label: sweep.currentTarget == null ? null : labelForState(sweep.currentTarget),
    completed: sweep.done,
    results: sweep.results,
    out_paths: outPathsByResolution,
    last_snapshot_age_ms: latestSnapshotMs === 0 ? null : nowMs() - latestSnapshotMs,
    snapshot: latestSnapshot,
  };
};

globalThis.panelSweepStop = function panelSweepStop(reason) {
  if (sweep.done) return true;
  sweep.done = true;
  sweep.phase = 'done';
  sweep.phaseSinceMs = nowMs();
  writeEvent({
    event: 'sweep_stopped',
    reason: reason == null ? 'manual_stop' : String(reason),
    results: sweep.results,
    output_files: outPathsByResolution,
  });
  return true;
};

globalThis.mark = function mark(label) {
  writeEvent({
    event: 'mark',
    label: String(label),
  });
};

setImmediate(() => {
  const attachTimer = setInterval(() => {
    try {
      attachOnce();
      if (attached) clearInterval(attachTimer);
    } catch (e) {
      console.log('[panel_state_resolution_sweep] attach error: ' + e);
    }
  }, 50);

  setInterval(() => {
    try {
      if (attached) refreshUiElementIndexMap();
    } catch (_) {}
  }, 250);

  setInterval(() => {
    try {
      mainTick();
    } catch (e) {
      writeEvent({
        event: 'error',
        where: 'main_tick',
        error: String(e),
      });
    }
  }, 50);
});
