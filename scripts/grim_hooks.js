'use strict';

const OUT_PATH = "Z:\\grim_hits.log";
const MODULE = "grim.dll";

const TARGETS = {
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

function tryHook() {
  const base = findBase();
  if (!base) return;
  hooked = true;
  clearInterval(waiter);

  log("grim.dll base=" + base);

  for (const name in TARGETS) {
    const addr = base.add(TARGETS[name]);
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

  log("hooks installed: " + Object.keys(TARGETS).length);
}

const waiter = setInterval(() => { if (!hooked) tryHook(); }, 200);
setInterval(() => { if (hooked) log("counts " + JSON.stringify(counts)); }, 5000);
