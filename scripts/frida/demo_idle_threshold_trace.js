'use strict';

// Measures how long it takes for the menu idle timer to start the demo/attract loop.
//
// Usage (Windows VM):
//   frida -n crimsonland.exe -l C:\share\frida\demo_idle_threshold_trace.js
//
// Notes:
// - Addresses are for the repo's PE (1.9.93-gog) with link base 0x00400000.
// - This tracer auto-enables demo/shareware behavior by patching game_is_full_version() to return 0,
//   so the attract loop triggers on retail builds too.
// - Disable the patch with: CRIMSON_FRIDA_DEMO_PATCH=0
// - For other builds, override addresses via:
//     CRIMSON_FRIDA_ADDRS="demo_mode_start=0x401000,ui_elements_max_timeline=0x402000"
//     CRIMSON_FRIDA_LINK_BASE="0x00400000"

const DEFAULT_LOG_DIR = 'C:\\share\\frida';
const DEFAULT_GAME_MODULE = 'crimsonland.exe';

function getEnv(key) {
  try {
    return Process.env[key] || null;
  } catch (_) {
    return null;
  }
}

function parseBoolEnv(key, defaultValue) {
  const raw = getEnv(key);
  if (raw === null) return defaultValue;
  const value = String(raw).trim().toLowerCase();
  if (value === '0' || value === 'false' || value === 'no') return false;
  if (value === '1' || value === 'true' || value === 'yes') return true;
  return defaultValue;
}

function getLogDir() {
  return getEnv('CRIMSON_FRIDA_DIR') || DEFAULT_LOG_DIR;
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith('\\') || base.endsWith('/') ? '' : '\\';
  return base + sep + leaf;
}

const LOG_DIR = getLogDir();

const CONFIG = {
  pollIntervalMs: 100,
  logPath: joinPath(LOG_DIR, 'demo_idle_threshold_trace.jsonl'),
  enableDemoPatch: parseBoolEnv('CRIMSON_FRIDA_DEMO_PATCH', true),
  demoPatchForceValue: 0, // 0 = demo/shareware behavior, 1 = full version
  demoPatchKeepConfigPatched: true,
  demoPatchKeepConfigIntervalMs: 1000,
};

const GAME_MODULE =
  getEnv('CRIMSON_FRIDA_MODULE') ||
  (Process.mainModule && Process.mainModule.name ? Process.mainModule.name : DEFAULT_GAME_MODULE);

let LINK_BASE = ptr('0x00400000');

const ADDR = {
  demo_mode_start: 0x00403390,
  ui_elements_max_timeline: 0x00446190,

  game_is_full_version: 0x0041df40,
  config_full_version: 0x00480791,

  demo_mode_active: 0x0048700d,
  ui_elements_timeline: 0x00487248,
  game_state_id: 0x00487270,
};

let LOG = { file: null, ok: false };
let ADDR_OVERRIDES = { raw: null, applied: {}, errors: [] };

function initLog() {
  try {
    LOG.file = new File(CONFIG.logPath, 'a');
    LOG.ok = true;
  } catch (e) {
    console.log('[!] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  console.log(line);
}

function formatHex32(n) {
  if (n === null || n === undefined) return null;
  const v = Number(n);
  if (!Number.isFinite(v)) return null;
  return '0x' + (v >>> 0).toString(16).padStart(8, '0');
}

function exePtr(staticVa) {
  let mod = null;
  try {
    mod = Process.getModuleByName(GAME_MODULE);
  } catch (_) {
    return null;
  }
  if (!mod) return null;
  try {
    return mod.base.add(ptr(staticVa).sub(LINK_BASE));
  } catch (_) {
    return null;
  }
}

function parseAddrOverrides(raw) {
  const out = { raw: raw, overrides: {}, errors: [] };
  if (!raw) return out;

  const text = String(raw).trim();
  if (!text) return out;

  if (text.startsWith('{')) {
    try {
      const obj = JSON.parse(text);
      if (obj && typeof obj === 'object') {
        for (const key in obj) {
          const v = obj[key];
          const parsed = typeof v === 'number' ? v : parseInt(String(v).trim(), 0);
          if (!Number.isFinite(parsed)) {
            out.errors.push({ key: key, error: 'not_a_number', value: v });
            continue;
          }
          out.overrides[key] = parsed;
        }
      }
    } catch (e) {
      out.errors.push({ error: 'json_parse', message: String(e) });
    }
    return out;
  }

  const parts = text
    .split(/[;,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq < 1) {
      out.errors.push({ error: 'bad_pair', value: part });
      continue;
    }
    const key = part.slice(0, eq).trim();
    const valueText = part.slice(eq + 1).trim();
    const parsed = parseInt(valueText, 0);
    if (!Number.isFinite(parsed)) {
      out.errors.push({ key: key, error: 'not_a_number', value: valueText });
      continue;
    }
    out.overrides[key] = parsed;
  }
  return out;
}

function applyAddrOverrides(addrMap, parsed) {
  const applied = {};
  if (!parsed || !parsed.overrides) return applied;
  for (const key in parsed.overrides) {
    if (!(key in addrMap)) continue;
    addrMap[key] = parsed.overrides[key];
    applied[key] = addrMap[key];
  }
  return applied;
}

function maybeOverrideLinkBase() {
  const raw = getEnv('CRIMSON_FRIDA_LINK_BASE') || getEnv('CRIMSON_FRIDA_IMAGE_BASE');
  if (!raw) return;
  const parsed = parseInt(String(raw).trim(), 0);
  if (!Number.isFinite(parsed)) return;
  LINK_BASE = ptr(parsed);
}

function resolveAbi() {
  if (Process.platform !== 'windows') return null;
  if (Process.arch === 'x64') return 'win64';
  if (Process.arch === 'ia32') return 'mscdecl';
  return null;
}

function patchReturnValue(addr, value) {
  const v = value ? 1 : 0;
  let bytes = null;

  if (Process.arch === 'ia32') {
    bytes = v === 0
      ? [0x33, 0xc0, 0xc3] // xor eax, eax; ret
      : [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]; // mov eax, 1; ret
  } else if (Process.arch === 'x64') {
    bytes = v === 0
      ? [0x48, 0x31, 0xc0, 0xc3] // xor rax, rax; ret
      : [0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00, 0xc3]; // mov rax, 1; ret
  } else {
    return { ok: false, error: 'unsupported_arch', arch: Process.arch };
  }

  try {
    Memory.patchCode(addr, bytes.length, (code) => {
      code.writeByteArray(bytes);
    });
    return { ok: true, method: 'asm_patch', value: v };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function readS32(staticVa) {
  const addr = exePtr(staticVa);
  if (!addr) return null;
  try {
    return addr.readS32();
  } catch (_) {
    return null;
  }
}

function readU8(staticVa) {
  const addr = exePtr(staticVa);
  if (!addr) return null;
  try {
    return addr.readU8();
  } catch (_) {
    return null;
  }
}

function writeU8(staticVa, value) {
  const addr = exePtr(staticVa);
  if (!addr) return { ok: false, error: 'addr_unavailable' };
  try {
    addr.writeU8(value & 0xff);
    return { ok: true, addr: addr.toString(), value: value & 0xff };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function demoPatchApply() {
  if (!CONFIG.enableDemoPatch) {
    writeLog({ event: 'demo_patch', enabled: false });
    return;
  }

  const forceValue = CONFIG.demoPatchForceValue | 0;
  writeLog({ event: 'demo_patch', enabled: true, force_value: forceValue });

  const addrIsFull = exePtr(ADDR.game_is_full_version);
  if (!addrIsFull) {
    writeLog({ event: 'demo_patch_error', target: 'game_is_full_version', error: 'addr_unavailable' });
  } else {
    let replaced = false;
    try {
      Interceptor.replace(
        addrIsFull,
        new NativeCallback(function () {
          return forceValue;
        }, 'int', [])
      );
      replaced = true;
      writeLog({
        event: 'demo_patch_applied',
        target: 'game_is_full_version',
        method: 'interceptor_replace',
        addr: addrIsFull.toString(),
        value: forceValue,
      });
    } catch (e) {
      writeLog({
        event: 'demo_patch_error',
        target: 'game_is_full_version',
        method: 'interceptor_replace',
        addr: addrIsFull.toString(),
        error: String(e),
      });
    }

    if (!replaced) {
      const patched = patchReturnValue(addrIsFull, forceValue);
      if (patched.ok) {
        writeLog({
          event: 'demo_patch_applied',
          target: 'game_is_full_version',
          method: patched.method,
          addr: addrIsFull.toString(),
          value: forceValue,
        });
      } else {
        writeLog({
          event: 'demo_patch_error',
          target: 'game_is_full_version',
          method: 'asm_patch',
          addr: addrIsFull.toString(),
          error: patched.error || 'unknown',
          arch: patched.arch || null,
        });
      }
    }
  }

  const writeConfig = writeU8(ADDR.config_full_version, forceValue);
  if (writeConfig.ok) {
    writeLog({
      event: 'demo_patch_applied',
      target: 'config_full_version',
      method: 'write_u8',
      addr: writeConfig.addr,
      value: writeConfig.value,
    });
  } else {
    writeLog({
      event: 'demo_patch_error',
      target: 'config_full_version',
      method: 'write_u8',
      error: writeConfig.error || 'unknown',
    });
  }

  if (CONFIG.demoPatchKeepConfigPatched) {
    setInterval(() => {
      const current = readU8(ADDR.config_full_version);
      if (current !== null && current !== (forceValue & 0xff)) {
        writeU8(ADDR.config_full_version, forceValue);
      }
    }, parseInt(CONFIG.demoPatchKeepConfigIntervalMs, 10) || 1000);
  }
}

function main() {
  initLog();
  maybeOverrideLinkBase();
  const parsedOverrides = parseAddrOverrides(getEnv('CRIMSON_FRIDA_ADDRS'));
  ADDR_OVERRIDES = {
    raw: parsedOverrides.raw,
    applied: applyAddrOverrides(ADDR, parsedOverrides),
    errors: parsedOverrides.errors,
  };

  const t0 = Date.now();
  let uiReadyMs = null;

  let exeMod = null;
  try {
    exeMod = Process.getModuleByName(GAME_MODULE);
  } catch (_) {
    // ignore
  }

  const ptrs = {};
  const addrs = {};
  const staticAddrs = {};
  for (const key in ADDR) {
    ptrs[key] = exePtr(ADDR[key]);
    addrs[key] = ptrs[key] ? ptrs[key].toString() : null;
    staticAddrs[key] = formatHex32(ADDR[key]);
  }

  writeLog({
    event: 'start',
    config: CONFIG,
    frida: { version: Frida.version, runtime: Script.runtime },
    process: { pid: Process.id, platform: Process.platform, arch: Process.arch },
    module: GAME_MODULE,
    link_base: LINK_BASE.toString(),
    addr_overrides: {
      applied: ADDR_OVERRIDES.applied,
      errors: ADDR_OVERRIDES.errors,
    },
    t0_ms: t0,
    exe: exeMod
      ? {
          base: exeMod.base.toString(),
          size: exeMod.size,
          path: exeMod.path,
        }
      : null,
    static_addrs: staticAddrs,
    addrs: addrs,
  });

  demoPatchApply();

  const addrDemoStart = ptrs.demo_mode_start;
  const addrMaxTimeline = ptrs.ui_elements_max_timeline;

  if (!addrDemoStart) {
    writeLog({ event: 'error', target: 'demo_mode_start', error: 'addr_unavailable' });
    return;
  }
  if (!addrMaxTimeline) {
    writeLog({ event: 'error', target: 'ui_elements_max_timeline', error: 'addr_unavailable' });
    return;
  }

  const abi = resolveAbi();
  const uiMaxTimeline = abi
    ? new NativeFunction(addrMaxTimeline, 'int', [], abi)
    : new NativeFunction(addrMaxTimeline, 'int', []);

  const pollIntervalMs = parseInt(CONFIG.pollIntervalMs, 10) || 100;
  setInterval(() => {
    const now = Date.now();
    const timeline = readS32(ADDR.ui_elements_timeline);
    let maxTimeline = null;
    try {
      maxTimeline = uiMaxTimeline();
    } catch (_) {
      // ignore
    }
    if (uiReadyMs === null && timeline !== null && maxTimeline !== null && timeline >= maxTimeline) {
      uiReadyMs = now;
      writeLog({
        event: 'ui_ready',
        t_ms: now,
        dt_since_start_ms: now - t0,
        ui_elements_timeline: timeline,
        ui_elements_max_timeline: maxTimeline,
      });
    }
  }, pollIntervalMs);

  Interceptor.attach(addrDemoStart, {
    onEnter() {
      const now = Date.now();
      const stateId = readS32(ADDR.game_state_id);
      const demoActive = readU8(ADDR.demo_mode_active);
      const timeline = readS32(ADDR.ui_elements_timeline);
      let maxTimeline = null;
      try {
        maxTimeline = uiMaxTimeline();
      } catch (_) {
        // ignore
      }

      writeLog({
        event: 'demo_mode_start',
        t_ms: now,
        dt_since_start_ms: now - t0,
        dt_since_ui_ready_ms: uiReadyMs === null ? null : now - uiReadyMs,
        game_state_id: stateId,
        demo_mode_active: demoActive,
        ui_elements_timeline: timeline,
        ui_elements_max_timeline: maxTimeline,
      });
    },
  });
}

main();
