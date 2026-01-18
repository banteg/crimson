'use strict';

const CONFIG_PATH = "Z:\\grim_hooks_targets.json";

const DEFAULT_CONFIG = {
  options: {
    module: "grim.dll",
    out_path: "Z:\\grim_hits.log",
    json_path: "Z:\\grim_hits.jsonl",
    log_json: true,
    console_log: false,
    log_mode: "truncate",
    log_interval_ms: 5000,
    trace: {
      mode: "callsite", // off | first | callsite | all
      first: 1,
      callsite_limit: 3,
    },
    draw_state: true,
    include_state_in_text: false,
    frame_boundary: ["grim_flush_batch"],
    frame_summary_top: 12,
    player_unknown_tracker: {
      enabled: false,
      exe_module: "crimsonland.exe",
      exe_link_base: "0x00400000",
      player_health_base: "0x004908d4",
      player_stride: 0x360,
      prepad: 0x20,
      interval_ms: 250,
      report_every_ms: 5000,
      top_n: 15,
      player_index: 0,
    },
  },
  targets: {
    grim_apply_config: { rva: "0x05D40" },
    grim_init_system: { rva: "0x05EB0" },
    grim_apply_settings: { rva: "0x06020" },
    grim_check_device: { rva: "0x05CB0" },
    grim_get_error_text: { rva: "0x06CA0", ret: "cstring" },

    grim_create_texture: {
      rva: "0x075D0",
      args: ["name:cstring", "width:i32", "height:i32"],
      state: { last_texture_create: ["name", "width", "height"] },
    },
    grim_load_texture: {
      rva: "0x076E0",
      args: ["name:cstring", "path:cstring"],
      state: { last_texture_load: ["name", "path"] },
    },
    grim_validate_texture: { rva: "0x07750", args: ["handle:i32"] },
    grim_destroy_texture: {
      rva: "0x07700",
      args: ["handle:i32"],
      resource: { kind: "texture", id: "handle", op: "destroy" },
    },
    grim_recreate_texture: { rva: "0x07790", args: ["handle:i32"] },
    grim_get_texture_handle: {
      rva: "0x07740",
      args: ["name:cstring"],
      ret: "i32",
      resource: { kind: "texture", id: "ret", props: { name: "name" } },
    },
    grim_bind_texture: {
      rva: "0x07830",
      args: ["handle:i32", "stage:i32"],
      state: {
        texture: "handle",
        texture_stage: { index: "stage", value: "handle" },
      },
    },

    grim_set_render_state: {
      rva: "0x06580",
      args: ["state:u32", "value:u32"],
      state: {
        render_state: { index: "state", value: "value" },
      },
    },

    grim_set_uv: {
      rva: "0x08350",
      args: ["u0:f32", "v0:f32", "u1:f32", "v1:f32"],
      state: { uv: ["u0", "v0", "u1", "v1"] },
    },
    grim_set_uv_point: {
      rva: "0x083A0",
      args: ["index:i32", "u:f32", "v:f32"],
      state: { uv_points: { index: "index", value: ["u", "v"] } },
    },

    grim_set_color_ptr: {
      rva: "0x08040",
      args: [{ name: "rgba", mem: "f32[4]" }],
      state: { color: "rgba" },
    },
    grim_set_color: {
      rva: "0x07F90",
      args: ["r:f32", "g:f32", "b:f32", "a:f32"],
      state: { color: ["r", "g", "b", "a"] },
    },
    grim_set_color_slot: {
      rva: "0x081C0",
      args: ["index:i32", "r:f32", "g:f32", "b:f32", "a:f32"],
      state: { color_slots: { index: "index", value: ["r", "g", "b", "a"] } },
    },

    grim_draw_quad: {
      rva: "0x08B10",
      role: "draw",
      args: ["x:f32", "y:f32", "w:f32", "h:f32"],
    },
    grim_draw_quad_xy: {
      rva: "0x08720",
      role: "draw",
      args: [{ name: "xy", mem: "f32[2]" }, "w:f32", "h:f32"],
    },
    grim_draw_quad_rotated_matrix: {
      rva: "0x08750",
      role: "draw",
      args: ["x:f32", "y:f32", "w:f32", "h:f32"],
    },

    grim_flush_batch: { rva: "0x083C0", role: "frame_boundary" },
  },
};

function readFileText(path) {
  try {
    const f = new File(path, "r");
    const data = f.readAll();
    f.close();
    if (data === null || data === undefined) return null;
    if (typeof data === "string") return data;
    if (data instanceof ArrayBuffer) {
      const u8 = new Uint8Array(data);
      let s = "";
      for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
      return s;
    }
    if (data.buffer && data.byteLength !== undefined) {
      const u8 = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      let s = "";
      for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
      return s;
    }
  } catch (e) {}
  return null;
}

function parseRva(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    if (value.startsWith("0x") || value.startsWith("0X")) return parseInt(value, 16);
    return parseInt(value, 10);
  }
  return null;
}

function mergeShallow(a, b) {
  const out = {};
  for (const k in a) out[k] = a[k];
  if (b && typeof b === "object") {
    for (const k in b) out[k] = b[k];
  }
  return out;
}

function parseArgSpec(spec) {
  if (typeof spec === "string") {
    const parts = spec.split(":");
    if (parts.length === 2) {
      return { name: parts[0], type: parts[1] };
    }
    return { name: null, type: spec };
  }
  if (spec && typeof spec === "object") {
    return {
      name: spec.name || null,
      type: spec.type || spec.t || (spec.mem ? "mem" : "ptr"),
      mem: spec.mem,
    };
  }
  return { name: null, type: "ptr" };
}

function normalizeTargets(rawTargets) {
  const out = {};
  for (const key in rawTargets) {
    const entry = rawTargets[key];
    if (entry === null || entry === undefined) continue;
    if (typeof entry === "number" || typeof entry === "string") {
      out[key] = { name: key, rva: parseRva(entry) };
      continue;
    }
    const target = mergeShallow({ name: key }, entry);
    target.rva = parseRva(target.rva);
    target.args = (target.args || []).map(parseArgSpec);
    out[key] = target;
  }
  return out;
}

function loadConfig(path) {
  const text = readFileText(path);
  if (!text) return DEFAULT_CONFIG;
  try {
    const parsed = JSON.parse(text);
    const cfg = mergeShallow(DEFAULT_CONFIG, parsed);
    cfg.options = mergeShallow(DEFAULT_CONFIG.options, parsed.options || {});
    cfg.options.trace = mergeShallow(DEFAULT_CONFIG.options.trace, (parsed.options || {}).trace || {});
    cfg.targets = normalizeTargets(parsed.targets || DEFAULT_CONFIG.targets);
    return cfg;
  } catch (e) {
    return DEFAULT_CONFIG;
  }
}

function findBase(moduleName) {
  if (Process.findModuleByName) {
    const mod = Process.findModuleByName(moduleName);
    return mod ? mod.base : null;
  }
  if (Module.findBaseAddress) {
    return Module.findBaseAddress(moduleName);
  }
  if (Module.getBaseAddress) {
    try { return Module.getBaseAddress(moduleName); } catch (e) { return null; }
  }
  return null;
}

function safeGetModule(name) {
  if (Process.findModuleByName) {
    const mod = Process.findModuleByName(name);
    if (mod) return mod;
  }
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      if (mods[i].name === name) return mods[i];
    }
  } catch (e) {}
  return null;
}

function toRuntimePtr(moduleName, staticVa, linkBase) {
  const mod = safeGetModule(moduleName);
  if (!mod) return null;
  if (staticVa === null || staticVa === undefined) return null;
  const link = ptr(linkBase);
  return mod.base.add(ptr(staticVa).sub(link));
}

function normalizePlayerTracker(raw) {
  const defaults = DEFAULT_CONFIG.options.player_unknown_tracker || {};
  const cfg = mergeShallow(defaults, raw || {});
  cfg.enabled = !!cfg.enabled;
  cfg.exe_module = cfg.exe_module || "crimsonland.exe";
  cfg.exe_link_base = parseRva(cfg.exe_link_base) || 0x00400000;
  cfg.player_health_base = parseRva(cfg.player_health_base) || 0x004908d4;
  cfg.player_stride = parseRva(cfg.player_stride) || 0x360;
  cfg.prepad = parseRva(cfg.prepad) || 0x20;
  cfg.interval_ms = parseRva(cfg.interval_ms) || 250;
  cfg.report_every_ms = parseRva(cfg.report_every_ms) || 5000;
  cfg.top_n = parseRva(cfg.top_n) || 15;
  cfg.player_index = parseRva(cfg.player_index) || 0;
  return cfg;
}

function formatAddress(addr) {
  if (!addr) return "0x0";
  try {
    const mod = Process.findModuleByAddress(addr);
    if (mod) {
      const off = addr.sub(mod.base);
      return mod.name + "+0x" + off.toString(16);
    }
  } catch (e) {}
  return addr.toString();
}

function getThisPtr(ctx) {
  if (!ctx) return null;
  if (ctx.ecx !== undefined) return ctx.ecx;
  if (ctx.rcx !== undefined) return ctx.rcx;
  if (ctx.x0 !== undefined) return ctx.x0;
  return null;
}

function u32ToF32(u32) {
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  view.setUint32(0, u32, true);
  return view.getFloat32(0, true);
}

function safeReadCString(ptrVal) {
  try {
    if (typeof ptrVal.readCString === "function") return ptrVal.readCString();
    if (typeof ptrVal.readUtf8String === "function") return ptrVal.readUtf8String();
    return null;
  } catch (e) { return null; }
}

function safeReadUtf16(ptrVal) {
  try {
    if (typeof ptrVal.readUtf16String === "function") return ptrVal.readUtf16String();
    return null;
  } catch (e) { return null; }
}

const MEM_READERS = {
  i8: { size: 1, read: (p) => p.readS8() },
  u8: { size: 1, read: (p) => p.readU8() },
  i16: { size: 2, read: (p) => p.readS16() },
  u16: { size: 2, read: (p) => p.readU16() },
  i32: { size: 4, read: (p) => p.readS32() },
  u32: { size: 4, read: (p) => p.readU32() },
  f32: { size: 4, read: (p) => p.readFloat() },
  f64: { size: 8, read: (p) => p.readDouble() },
  ptr: { size: Process.pointerSize, read: (p) => p.readPointer() },
};

function rangeInfo(ptrVal) {
  try {
    if (!Process.findRangeByAddress) return null;
    const range = Process.findRangeByAddress(ptrVal);
    if (!range) return null;
    return {
      base: range.base ? range.base.toString() : null,
      size: range.size,
      protection: range.protection || null,
      file: range.file ? range.file.path : null,
    };
  } catch (e) {
    return null;
  }
}

function readMemRaw(type, count, ptrVal) {
  const reader = MEM_READERS[type];
  if (!reader) return null;
  const out = [];
  let cur = ptrVal;
  for (let i = 0; i < count; i++) {
    try {
      out.push(reader.read(cur));
    } catch (e) {
      out.push(null);
    }
    cur = cur.add(reader.size);
  }
  return count === 1 ? out[0] : out;
}

function isAllNull(value) {
  if (value === null || value === undefined) return true;
  if (!Array.isArray(value)) return value === null;
  return value.length > 0 && value.every((entry) => entry === null);
}

function readMem(memSpec, ptrVal) {
  const info = { ptr: ptrVal || null, value: null, range: null };
  if (!ptrVal || ptrVal.isNull()) return info;
  const parsed = /^(\w+)(?:\[(\d+)\])?$/.exec(memSpec);
  if (!parsed) return info;
  const type = parsed[1];
  const count = parsed[2] ? parseInt(parsed[2], 10) : 1;
  info.range = rangeInfo(ptrVal);
  info.value = readMemRaw(type, count, ptrVal);
  if (isAllNull(info.value)) {
    try {
      const nextPtr = ptrVal.readPointer();
      const derefRange = rangeInfo(nextPtr);
      const derefValue = readMemRaw(type, count, nextPtr);
      info.deref = { ptr: nextPtr, value: derefValue, range: derefRange };
    } catch (e) {}
  }
  return info;
}

function decodeArg(spec, arg) {
  if (!spec) return arg;
  if (spec.mem) return readMem(spec.mem, arg);
  const type = spec.type || "ptr";
  switch (type) {
    case "i8": return arg.toInt32() << 24 >> 24;
    case "u8": return arg.toUInt32() & 0xff;
    case "i16": return arg.toInt32() << 16 >> 16;
    case "u16": return arg.toUInt32() & 0xffff;
    case "i32": return arg.toInt32();
    case "u32": return arg.toUInt32();
    case "f32": return u32ToF32(arg.toUInt32());
    case "bool": return arg.toInt32() !== 0;
    case "cstring": return safeReadCString(arg);
    case "utf16":
    case "wstr": return safeReadUtf16(arg);
    case "ptr":
    default:
      return arg;
  }
}

function decodeArgs(target, args) {
  const specs = target.args || [];
  const decoded = [];
  const named = {};
  for (let i = 0; i < specs.length; i++) {
    const spec = specs[i];
    const arg = args[i];
    const value = decodeArg(spec, arg);
    decoded.push(value);
    if (spec && spec.name) named[spec.name] = value;
  }
  return { list: decoded, named: named };
}

function decodeRet(target, retval) {
  if (!target.ret) return null;
  const spec = parseArgSpec(target.ret);
  return decodeArg(spec, retval);
}

function resolveValue(spec, decodedArgs, retVal) {
  if (spec === null || spec === undefined) return null;
  if (spec === "ret") return retVal;
  if (typeof spec === "number") return decodedArgs.list[spec];
  if (typeof spec === "string") {
    if (decodedArgs.named && decodedArgs.named[spec] !== undefined) return decodedArgs.named[spec];
    if (spec.startsWith("arg")) {
      const idx = parseInt(spec.slice(3), 10);
      if (!isNaN(idx)) return decodedArgs.list[idx];
    }
    return spec;
  }
  if (Array.isArray(spec)) return spec.map((entry) => resolveValue(entry, decodedArgs, retVal));
  if (typeof spec === "object") {
    if (spec.value !== undefined) return resolveValue(spec.value, decodedArgs, retVal);
  }
  return null;
}

function applyState(target, decodedArgs, retVal) {
  const stateSpec = target.state;
  if (!stateSpec || typeof stateSpec !== "object") return;
  for (const key in stateSpec) {
    const spec = stateSpec[key];
    if (spec && typeof spec === "object" && spec.index !== undefined) {
      const idx = resolveValue(spec.index, decodedArgs, retVal);
      const valueSpec = spec.value !== undefined ? spec.value : spec;
      const value = resolveValue(valueSpec, decodedArgs, retVal);
      if (idx === null || idx === undefined) continue;
      if (!state[key] || typeof state[key] !== "object") state[key] = {};
      state[key][idx] = value;
    } else {
      state[key] = resolveValue(spec, decodedArgs, retVal);
    }
  }
}

function applyResource(target, decodedArgs, retVal) {
  const resource = target.resource;
  if (!resource || typeof resource !== "object") return;
  const kind = resource.kind || "resource";
  const op = resource.op || "set";
  const idSpec = resource.id !== undefined ? resource.id : "ret";
  const id = resolveValue(idSpec, decodedArgs, retVal);
  if (id === null || id === undefined) return;
  if (!resources[kind]) resources[kind] = {};
  const table = resources[kind];
  const idKey = id.toString();
  if (op === "destroy" || op === "delete" || op === "release") {
    delete table[idKey];
    return;
  }
  const info = { id: id };
  if (resource.props) {
    for (const key in resource.props) {
      info[key] = resolveValue(resource.props[key], decodedArgs, retVal);
    }
  }
  info.updated_at = new Date().toISOString();
  table[idKey] = info;
}

function normalizeJson(value) {
  if (value === null || value === undefined) return value;
  if (value instanceof NativePointer) return value.toString();
  if (value instanceof Int64 || value instanceof UInt64) return value.toString();
  if (Array.isArray(value)) return value.map(normalizeJson);
  if (typeof value === "object") {
    const out = {};
    for (const k in value) out[k] = normalizeJson(value[k]);
    return out;
  }
  return value;
}

function formatValue(value) {
  if (value === null || value === undefined) return "null";
  if (value instanceof NativePointer) return value.toString();
  if (value instanceof Int64 || value instanceof UInt64) return value.toString();
  if (Array.isArray(value)) return JSON.stringify(normalizeJson(value));
  if (typeof value === "object") return JSON.stringify(normalizeJson(value));
  return String(value);
}

function describeArgs(target, decoded) {
  if (!decoded || !decoded.list || decoded.list.length === 0) return "";
  const specs = target.args || [];
  const parts = [];
  for (let i = 0; i < decoded.list.length; i++) {
    const spec = specs[i];
    const value = decoded.list[i];
    if (spec && spec.name) {
      parts.push(spec.name + "=" + formatValue(value));
    } else {
      parts.push(formatValue(value));
    }
  }
  return parts.join(", ");
}

function summarizeCounts(countsMap, limit) {
  const entries = [];
  for (const k in countsMap) entries.push([k, countsMap[k]]);
  entries.sort((a, b) => b[1] - a[1]);
  const out = {};
  for (let i = 0; i < entries.length && i < limit; i++) out[entries[i][0]] = entries[i][1];
  return out;
}

const config = loadConfig(CONFIG_PATH);
const options = config.options;
const targets = config.targets;
const moduleName = options.module;
const traceDefaults = options.trace || { mode: "callsite", first: 1, callsite_limit: 3 };
const frameBoundaryNames = Array.isArray(options.frame_boundary)
  ? options.frame_boundary
  : [options.frame_boundary];
const playerTracker = normalizePlayerTracker(options.player_unknown_tracker);

let outText = null;
let outJson = null;
const logMode = options.log_mode === "append" ? "a" : "w";
try { outText = new File(options.out_path, logMode); } catch (e) {}
if (options.log_json) {
  try { outJson = new File(options.json_path, logMode); } catch (e) {}
}

function log(line) {
  const msg = new Date().toISOString() + " " + line;
  if (options.console_log) {
    console.log(msg);
  }
  if (outText) { outText.write(msg + "\n"); outText.flush(); }
}

function emit(event) {
  if (!outJson) return;
  try {
    outJson.write(JSON.stringify(normalizeJson(event)) + "\n");
    outJson.flush();
  } catch (e) {}
}

function makeKnownPlayerOffsetPredicate() {
  const knownSingles = new Set([
    -0x1b,
    -0x14, -0x10, -0x0c, -0x08, -0x04,
    0x00, 0x08, 0x10,
    0x2c, 0x30,
    0x38, 0x3c,
    0x44,
    0x70,
    0x78, 0x7c, 0x80, 0x84,
    0x88, 0x90,
    0x294,
    0x29c, 0x2a0, 0x2a4, 0x2a8,
    0x2ac, 0x2b0, 0x2b4,
    0x2b8,
    0x2d8, 0x2dc, 0x2e0, 0x2e4,
    0x2ec,
    0x2f0, 0x2f4, 0x2f8,
    0x2fc,
    0x300, 0x304,
    0x32c, 0x330, 0x334, 0x338,
  ]);

  const knownRanges = [
    { start: 0x94, end: 0x293 },
  ];

  return function isKnown(off) {
    if (knownSingles.has(off)) return true;
    for (let i = 0; i < knownRanges.length; i++) {
      const r = knownRanges[i];
      if (off >= r.start && off <= r.end) return true;
    }
    return false;
  };
}

class UnknownFieldTracker {
  constructor(opts) {
    this.base = opts.base;
    this.prepad = opts.prepad;
    this.size = opts.size;
    this.isKnownOffset = opts.isKnownOffset;
    this.prev = null;
    this.counts = new Map();
    this.last = new Map();
  }

  _bump(off, u32) {
    const cur = this.counts.get(off) || 0;
    this.counts.set(off, cur + 1);
    this.last.set(off, { u32: u32 >>> 0, f32: u32ToF32(u32 >>> 0) });
  }

  snapshot() {
    const start = this.base.sub(this.prepad);
    const total = this.prepad + this.size;
    let bytes;
    try {
      bytes = start.readByteArray(total);
    } catch (e) {
      return;
    }

    const cur = new Uint8Array(bytes);
    if (this.prev === null) {
      this.prev = cur;
      return;
    }

    for (let i = 0; i + 4 <= cur.length; i += 4) {
      let diff = false;
      for (let j = 0; j < 4; j++) {
        if (cur[i + j] !== this.prev[i + j]) { diff = true; break; }
      }
      if (!diff) continue;
      const off = i - this.prepad;
      if (this.isKnownOffset(off)) continue;
      const u32 = (cur[i] | (cur[i + 1] << 8) | (cur[i + 2] << 16) | (cur[i + 3] << 24)) >>> 0;
      this._bump(off, u32);
    }

    this.prev = cur;
  }

  reportTop(n) {
    const arr = [];
    for (const [off, cnt] of this.counts.entries()) {
      const last = this.last.get(off);
      arr.push({ off, cnt, last });
    }
    arr.sort((a, b) => b.cnt - a.cnt);
    return arr.slice(0, n);
  }
}

let playerTrackerState = null;

function startPlayerUnknownTracker() {
  if (!playerTracker.enabled) return;
  const basePtr = toRuntimePtr(playerTracker.exe_module, playerTracker.player_health_base, playerTracker.exe_link_base);
  if (!basePtr) {
    log("player_unknown_tracker_error: player base unavailable");
    emit({ type: "player_unknown_tracker_error", ts: new Date().toISOString(), reason: "player base unavailable" });
    return;
  }

  const playerBase = basePtr.add(playerTracker.player_index * playerTracker.player_stride);
  const isKnown = makeKnownPlayerOffsetPredicate();
  playerTrackerState = new UnknownFieldTracker({
    base: playerBase,
    prepad: playerTracker.prepad,
    size: playerTracker.player_stride,
    isKnownOffset: isKnown,
  });

  log("player_unknown_tracker_start base=" + playerBase);
  emit({
    type: "player_unknown_tracker_start",
    ts: new Date().toISOString(),
    player_index: playerTracker.player_index,
    base: playerBase.toString(),
    interval_ms: playerTracker.interval_ms,
    report_every_ms: playerTracker.report_every_ms,
  });

  let lastReport = Date.now();
  setInterval(() => {
    if (!playerTrackerState) return;
    playerTrackerState.snapshot();
    const now = Date.now();
    if (now - lastReport >= playerTracker.report_every_ms) {
      lastReport = now;
      const top = playerTrackerState.reportTop(playerTracker.top_n);
      emit({
        type: "player_unknown_tracker_report",
        ts: new Date().toISOString(),
        player_index: playerTracker.player_index,
        top: top,
      });
    }
  }, playerTracker.interval_ms);
}

const state = {};
const resources = {};
const counts = {};
let frameCounts = {};
let frameIndex = 0;
let frameStartMs = 0;
const traceCounts = {};
const traceCallsites = {};
let hooked = false;

function resolveTraceConfig(target) {
  if (!target.trace) return traceDefaults;
  if (typeof target.trace === "string") return mergeShallow(traceDefaults, { mode: target.trace });
  if (typeof target.trace === "object") return mergeShallow(traceDefaults, target.trace);
  return traceDefaults;
}

function shouldTrace(target, callsite) {
  const traceCfg = target._trace;
  if (!traceCfg || traceCfg.mode === "off") return false;
  if (traceCfg.mode === "all") return true;
  if (traceCfg.mode === "first") {
    const count = traceCounts[target.name] || 0;
    if (count < traceCfg.first) {
      traceCounts[target.name] = count + 1;
      return true;
    }
    return false;
  }
  if (traceCfg.mode === "callsite") {
    if (!traceCallsites[target.name]) traceCallsites[target.name] = {};
    const map = traceCallsites[target.name];
    if (callsite && map[callsite]) return false;
    if (Object.keys(map).length >= traceCfg.callsite_limit) return false;
    if (callsite) map[callsite] = 1;
    return true;
  }
  return false;
}

function isFrameBoundary(name, target) {
  if (target.role === "frame_boundary") return true;
  return frameBoundaryNames.indexOf(name) !== -1;
}

function snapshotState() {
  const out = {};
  for (const k in state) out[k] = state[k];
  return out;
}

function emitFrameSummary(triggerName) {
  const now = Date.now();
  const duration = frameStartMs ? (now - frameStartMs) : 0;
  const summary = {
    type: "frame",
    frame: frameIndex,
    duration_ms: duration,
    trigger: triggerName,
    counts: summarizeCounts(frameCounts, options.frame_summary_top),
  };
  log("frame " + frameIndex + " duration_ms=" + duration + " counts=" + JSON.stringify(summary.counts));
  emit(summary);
  frameIndex += 1;
  frameStartMs = now;
  frameCounts = {};
}

function tryHook() {
  const base = findBase(moduleName);
  if (!base) return;
  hooked = true;
  clearInterval(waiter);

  frameStartMs = Date.now();
  log(moduleName + " base=" + base);
  emit({ type: "base", module: moduleName, base: base.toString() });

  for (const name in targets) {
    const target = targets[name];
    if (!target || target.rva === null || target.rva === undefined) continue;
    target.name = name;
    target._trace = resolveTraceConfig(target);

    const addr = base.add(target.rva);
    counts[name] = 0;
    frameCounts[name] = 0;

    Interceptor.attach(addr, {
      onEnter(args) {
        const callsite = formatAddress(this.returnAddress);
        const thisPtr = getThisPtr(this.context);
        const decodedArgs = decodeArgs(target, args);

        this.__name = name;
        this.__callsite = callsite;
        this.__thisPtr = thisPtr;
        this.__decodedArgs = decodedArgs;

        counts[name] += 1;
        frameCounts[name] = (frameCounts[name] || 0) + 1;

        applyState(target, decodedArgs, null);
        applyResource(target, decodedArgs, null);

        const doTrace = shouldTrace(target, callsite);
        this.__trace = doTrace;

        if (doTrace) {
          const argsText = describeArgs(target, decodedArgs);
          let line = "hit " + name + " @ " + addr + " callsite=" + callsite;
          if (thisPtr) line += " this=" + thisPtr;
          if (argsText) line += " args=[" + argsText + "]";
          if (target.role === "draw" && options.draw_state && options.include_state_in_text) {
            line += " state=" + JSON.stringify(normalizeJson(snapshotState()));
          }
          log(line);

          const event = {
            type: "call",
            name: name,
            addr: addr.toString(),
            callsite: callsite,
            this: thisPtr ? thisPtr.toString() : null,
            args: decodedArgs.list,
          };
          if (target.role === "draw" && options.draw_state) {
            event.state = snapshotState();
            if (state.texture !== undefined && resources.texture) {
              const key = String(state.texture);
              event.texture = resources.texture[key] || null;
            }
          }
          emit(event);
        }

        if (isFrameBoundary(name, target) && options.frame_summary_top > 0) {
          emitFrameSummary(name);
        }
      },
      onLeave(retval) {
        const decodedArgs = this.__decodedArgs || { list: [], named: {} };
        const retVal = decodeRet(target, retval);

        applyState(target, decodedArgs, retVal);
        applyResource(target, decodedArgs, retVal);

        if (target.force_return !== undefined) {
          const force = target.force_return;
          const value = typeof force === "object" && force.value !== undefined ? force.value : force;
          try { retval.replace(ptr(value)); } catch (e) {}
          log("force return " + name + " -> " + value);
          emit({ type: "force_return", name: name, value: value });
        }

        if (retVal !== null && retVal !== undefined && this.__trace) {
          const line = "ret " + name + " callsite=" + (this.__callsite || "") + " value=" + formatValue(retVal);
          log(line);
          emit({ type: "ret", name: name, callsite: this.__callsite || null, ret: retVal });
        }
      },
    });
  }

  log("hooks installed: " + Object.keys(targets).length);
}

startPlayerUnknownTracker();

const waiter = setInterval(() => { if (!hooked) tryHook(); }, 200);
setInterval(() => {
  if (!hooked) return;
  log("counts " + JSON.stringify(counts));
  emit({ type: "counts", counts: counts });
}, options.log_interval_ms);
