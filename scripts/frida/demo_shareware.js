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
  keepConfigPatched: true,
  keepConfigIntervalMs: 1000,
  logPath: joinPath(LOG_DIR, 'demo_shareware.jsonl'),
};

const GAME_MODULE = 'crimsonland.exe';

const LINK_BASE = {
  'crimsonland.exe': ptr('0x00400000'),
};

const ADDR = {
  game_is_full_version: 0x0041df40,
  demo_mode_start: 0x00403390,
  config_full_version: 0x00480791,
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

function readConfigFullVersion() {
  const addr = exePtr(ADDR.config_full_version);
  if (!addr) return null;
  try {
    return addr.readU8();
  } catch (_) {
    return null;
  }
}

function writeConfigFullVersion(value) {
  const addr = exePtr(ADDR.config_full_version);
  if (!addr) {
    writeLog({ event: 'config_full_version_error', error: 'addr_unavailable' });
    return false;
  }
  try {
    addr.writeU8(value & 0xff);
    writeLog({ event: 'config_full_version_set', value: value, addr: addr.toString() });
    return true;
  } catch (e) {
    writeLog({ event: 'config_full_version_error', error: String(e) });
    return false;
  }
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
    writeLog({ event: 'patch_asm_error', error: 'unsupported_arch', arch: Process.arch });
    return false;
  }

  try {
    Memory.patchCode(addr, bytes.length, (code) => {
      code.writeByteArray(bytes);
    });
    writeLog({ event: 'patched_asm', addr: addr.toString(), value: v, arch: Process.arch });
    return true;
  } catch (e) {
    writeLog({ event: 'patch_asm_error', addr: addr.toString(), error: String(e) });
    return false;
  }
}

function patchSharewareGate() {
  const addr = exePtr(ADDR.game_is_full_version);
  if (!addr) {
    writeLog({ event: 'error', error: 'module_or_address_unavailable' });
    writeConfigFullVersion(CONFIG.forceValue);
    return;
  }

  let hooked = false;
  let patchedAsm = false;
  try {
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
    hooked = true;
    writeLog({
      event: 'patched',
      addr: addr.toString(),
      force_value: CONFIG.forceValue,
    });
  } catch (e) {
    writeLog({
      event: 'patch_error',
      addr: addr.toString(),
      error: String(e),
    });
  }

  if (!hooked) {
    patchedAsm = patchReturnValue(addr, CONFIG.forceValue);
  }

  if (!hooked && !patchedAsm) {
    writeConfigFullVersion(CONFIG.forceValue);
  } else {
    // Keep config in sync too; some code reads the flag directly.
    writeConfigFullVersion(CONFIG.forceValue);
  }

  if (CONFIG.keepConfigPatched) {
    setInterval(() => {
      const current = readConfigFullVersion();
      if (current !== null && current !== (CONFIG.forceValue & 0xff)) {
        writeConfigFullVersion(CONFIG.forceValue);
      }
    }, CONFIG.keepConfigIntervalMs);
  }

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
