'use strict';

// Crimsonland v1.9.8: force main-menu balloons easter egg.
//
// The original game gates balloons behind real-world dates:
// - Sep 12
// - Nov 8
// - Dec 18
//
// This script bypasses the date check by:
// 1) Setting the global "show balloons" flag.
// 2) Loading `balloon.tga` into Grim's texture cache (so the menu code can resolve the handle).
//
// Usage (attach):
//   frida -n crimsonland.exe -l C:\share\frida\force_balloons_198.js
// Attach only: spawning via frida -f is unstable on this VM.

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

const CONFIG = {
  retryIntervalMs: 500,
  waitLogEveryMs: 2000,
  logWait: false,
  keepApplied: true,
  logPath: joinPath(LOG_DIR, 'force_balloons_198.jsonl'),
};

const GAME_MODULE = 'crimsonland.exe';

// Static VAs for Crimsonland v1.9.8 (link base 0x00400000).
const LINK_BASE = {
  'crimsonland.exe': ptr('0x00400000'),
};

const ADDR = {
  // Globals
  grim_interface_ptr: 0x0047e54c, // DAT_0047e54c
  balloons_enabled_flag: 0x004a83b0, // DAT_004a83b0 (byte)

  // Functions
  texture_get_or_load: 0x00429e50, // sub_429e50(name, filename) -> handle (i32)
};

let LOG = { file: null, ok: false };
let fTextureGetOrLoad = null;
let appliedCount = 0;
let lastWaitReason = null;
let lastWaitLogTs = 0;
let lastHandle = null;

function nowMs() {
  return Date.now();
}

function initLog() {
  try {
    LOG.file = new File(CONFIG.logPath, 'a');
    LOG.ok = true;
  } catch (e) {
    console.log('[!] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  obj.ts = nowMs();
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  console.log(line);
}

function resolveAbi() {
  if (Process.platform !== 'windows') return null;
  if (Process.arch === 'x64') return 'win64';
  if (Process.arch === 'ia32') return 'mscdecl';
  return null;
}

function exePtr(staticVa) {
  let mod = null;
  try {
    mod = Process.getModuleByName(GAME_MODULE);
  } catch (_) {
    return null;
  }
  if (!mod) return null;
  const linkBase = LINK_BASE[GAME_MODULE];
  if (!linkBase) return null;
  try {
    return mod.base.add(ptr(staticVa).sub(linkBase));
  } catch (_) {
    return null;
  }
}

function isReadable(p) {
  try {
    const range = Process.findRangeByAddress(p);
    return !!range && range.protection.indexOf('r') !== -1;
  } catch (_) {
    return false;
  }
}

function readPtrSafe(p) {
  try {
    return p.readPointer();
  } catch (_) {
    return null;
  }
}

function resolveFunctions() {
  if (fTextureGetOrLoad) return true;
  const p = exePtr(ADDR.texture_get_or_load);
  if (!p) return false;
  const abi = resolveAbi();

  // int __cdecl texture_get_or_load(const char* name, const char* filename)
  fTextureGetOrLoad = abi
    ? new NativeFunction(p, 'int', ['pointer', 'pointer'], abi)
    : new NativeFunction(p, 'int', ['pointer', 'pointer']);
  return true;
}

function grimReady() {
  const pIface = exePtr(ADDR.grim_interface_ptr);
  if (!pIface || !isReadable(pIface)) return false;
  const iface = readPtrSafe(pIface);
  if (!iface) return false;
  return !iface.isNull();
}

function maybeLogWait(reason) {
  if (!CONFIG.logWait) return;
  const now = nowMs();
  if (reason === lastWaitReason && (now - lastWaitLogTs) < CONFIG.waitLogEveryMs) return;
  lastWaitReason = reason;
  lastWaitLogTs = now;
  writeLog({ event: 'wait', reason: reason });
}

function forceOnce() {
  if (!resolveFunctions()) {
    maybeLogWait('resolve_functions_failed');
    return false;
  }
  if (!grimReady()) {
    maybeLogWait('grim_interface_not_ready');
    return false;
  }

  const pFlag = exePtr(ADDR.balloons_enabled_flag);
  if (!pFlag) {
    writeLog({ event: 'error', error: 'balloons_flag_unavailable' });
    return false;
  }

  try {
    pFlag.writeU8(1);
  } catch (e) {
    writeLog({ event: 'error', error: 'write_flag_failed', detail: String(e) });
    return false;
  }

  // Load balloon texture once (or keep retrying if the resource pack isn't ready yet).
  if (lastHandle === null || lastHandle === -1) {
    const name = Memory.allocUtf8String('balloon');
    const file = Memory.allocUtf8String('balloon.tga');

    let handle = -1;
    try {
      handle = fTextureGetOrLoad(name, file) | 0;
    } catch (e) {
      writeLog({ event: 'error', error: 'texture_load_call_failed', detail: String(e) });
      return false;
    }

    if (lastHandle !== handle) {
      lastHandle = handle;
      appliedCount += 1;
      const pLoad = exePtr(ADDR.texture_get_or_load);
      writeLog({
        event: 'forced',
        handle: handle,
        applied_count: appliedCount,
        flag_addr: pFlag.toString(),
        load_fn: pLoad ? pLoad.toString() : null,
      });
    }
  }

  return lastHandle !== -1;
}

function main() {
  initLog();
  writeLog({ event: 'start', config: CONFIG, arch: Process.arch, platform: Process.platform });

  const timerId = setInterval(() => {
    // Keep trying so you can attach at the launcher or after startup.
    const ok = forceOnce();
    if (ok && !CONFIG.keepApplied) {
      clearInterval(timerId);
      writeLog({ event: 'done', handle: lastHandle });
    }
  }, CONFIG.retryIntervalMs);
}

main();
