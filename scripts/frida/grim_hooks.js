'use strict';

const MODULE = "grim.dll";
const OUT_PATH = "Z:\\grim_hits.log";
const TARGETS_PATH = "Z:\\grim_hooks_targets.json";

const DEFAULT_TARGETS = {
  grim_apply_config:     0x05D40,
  grim_init_system:      0x05EB0,
  grim_apply_settings:   0x06020,
  grim_check_device:     0x05CB0,
  grim_get_error_text:   0x06CA0,
  grim_create_texture:   0x075D0,
  grim_load_texture:     0x076E0,
  grim_validate_texture: 0x07750,
  grim_destroy_texture:  0x07700,
  grim_recreate_texture: 0x07790,
  grim_flush_batch:      0x083C0,
};

let out = null;
try { out = new File(OUT_PATH, "a"); } catch (e) {}

function log(line) {
  const msg = new Date().toISOString() + " " + line;
  console.log(msg);
  if (out) { out.write(msg + "\n"); out.flush(); }
}

const counts = {};
let hooked = false;
const targets = loadTargets();

function findBase() {
  if (Process.findModuleByName) {
    const mod = Process.findModuleByName(MODULE);
    return mod ? mod.base : null;
  }
  if (Module.findBaseAddress) {
    return Module.findBaseAddress(MODULE);
  }
  if (Module.getBaseAddress) {
    try { return Module.getBaseAddress(MODULE); } catch (e) { return null; }
  }
  return null;
}

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

function normalizeTargets(value) {
  if (!value) return null;
  if (Array.isArray(value)) {
    const out = {};
    for (const entry of value) {
      if (!entry || !entry.name) continue;
      out[entry.name] = Number(entry.rva);
    }
    return out;
  }
  if (value.targets && Array.isArray(value.targets)) {
    return normalizeTargets(value.targets);
  }
  if (typeof value === "object") {
    const out = {};
    for (const key in value) {
      out[key] = Number(value[key]);
    }
    return out;
  }
  return null;
}

function loadTargets() {
  const text = readFileText(TARGETS_PATH);
  if (!text) return DEFAULT_TARGETS;
  try {
    const parsed = JSON.parse(text);
    return normalizeTargets(parsed) || DEFAULT_TARGETS;
  } catch (e) {
    return DEFAULT_TARGETS;
  }
}

function tryHook() {
  const base = findBase();
  if (!base) return;
  hooked = true;
  clearInterval(waiter);

  log("grim.dll base=" + base);

  for (const name in targets) {
    const addr = base.add(targets[name]);
    counts[name] = 0;
    Interceptor.attach(addr, {
      onEnter() {
        counts[name]++;
        if (counts[name] === 1) {
          log("hit " + name + " @ " + addr);
        }
      }
    });
  }

  log("hooks installed: " + Object.keys(targets).length);
}

const waiter = setInterval(() => { if (!hooked) tryHook(); }, 200);
setInterval(() => { if (hooked) log("counts " + JSON.stringify(counts)); }, 5000);
