'use strict';

// Forces shareware/demo behavior by patching game_is_full_version() to return 0.
// Usage:
//   frida -n crimsonland.exe -l C:\share\frida\demo_shareware.js
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
  forceValue: 0, // 0 = demo/shareware behavior, 1 = full version
  logCalls: false,
  autoStartDemo: false,
  autoStartDelayMs: 1200,
  logPath: joinPath(LOG_DIR, 'demo_shareware.jsonl'),
};

const GAME_MODULE = 'crimsonland.exe';

const LINK_BASE = {
  'crimsonland.exe': ptr('0x00400000'),
};

const ADDR = {
  game_is_full_version: 0x0041df40,
  demo_mode_start: 0x00403390,
};

let LOG = { file: null, ok: false };
let callCount = 0;
let fDemoModeStart = null;

function resolveAbi() {
  if (Process.platform !== 'windows') return null;
  if (Process.arch === 'x64') return 'win64';
  if (Process.arch === 'ia32') return 'mscdecl';
  return null;
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
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  console.log(line);
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

function resolveDemoStart() {
  if (fDemoModeStart) return true;
  const addr = exePtr(ADDR.demo_mode_start);
  if (!addr) return false;
  const abi = resolveAbi();
  fDemoModeStart = abi
    ? new NativeFunction(addr, 'int', [], abi)
    : new NativeFunction(addr, 'int', []);
  return true;
}

function maybeStartDemo() {
  if (!CONFIG.autoStartDemo) return;
  if (!resolveDemoStart()) {
    writeLog({ event: 'demo_mode_start_error', error: 'resolve_failed' });
    return;
  }
  try {
    const result = fDemoModeStart();
    writeLog({ event: 'demo_mode_start', result: result });
  } catch (e) {
    writeLog({ event: 'demo_mode_start_error', error: String(e) });
  }
}

function patchSharewareGate() {
  const addr = exePtr(ADDR.game_is_full_version);
  if (!addr) {
    writeLog({ event: 'error', error: 'module_or_address_unavailable' });
    return;
  }

  Interceptor.replace(
    addr,
    new NativeCallback(function () {
      callCount += 1;
      if (CONFIG.logCalls) {
        writeLog({ event: 'call', count: callCount, ret: CONFIG.forceValue });
      }
      return CONFIG.forceValue;
    }, 'int', [])
  );

  writeLog({
    event: 'patched',
    addr: addr.toString(),
    force_value: CONFIG.forceValue,
  });

  if (CONFIG.autoStartDemo) {
    setTimeout(maybeStartDemo, CONFIG.autoStartDelayMs);
  }
}

function main() {
  initLog();
  writeLog({ event: 'start', config: CONFIG, module: GAME_MODULE });
  patchSharewareGate();
}

main();
