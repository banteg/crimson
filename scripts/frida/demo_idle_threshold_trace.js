'use strict';

// Measures how long it takes for the menu idle timer to start the demo/attract loop.
//
// Usage (Windows VM):
//   frida -n crimsonland.exe -l C:\share\frida\demo_idle_threshold_trace.js
//
// Notes:
// - Addresses are for the repo's PE (1.9.93-gog) with link base 0x00400000.
// - This is expected to work on demo builds where the attract loop is enabled.

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
  pollIntervalMs: 100,
  logPath: joinPath(LOG_DIR, 'demo_idle_threshold_trace.jsonl'),
};

const GAME_MODULE = 'crimsonland.exe';

const LINK_BASE = {
  'crimsonland.exe': ptr('0x00400000'),
};

const ADDR = {
  demo_mode_start: 0x00403390,
  ui_elements_max_timeline: 0x00446190,

  demo_mode_active: 0x0048700d,
  ui_elements_timeline: 0x00487248,
  game_state_id: 0x00487270,
};

let LOG = { file: null, ok: false };

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

function resolveAbi() {
  if (Process.platform !== 'windows') return null;
  if (Process.arch === 'x64') return 'win64';
  if (Process.arch === 'ia32') return 'mscdecl';
  return null;
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

function main() {
  initLog();

  const t0 = Date.now();
  let uiReadyMs = null;

  const addrDemoStart = exePtr(ADDR.demo_mode_start);
  const addrMaxTimeline = exePtr(ADDR.ui_elements_max_timeline);

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

  writeLog({
    event: 'start',
    config: CONFIG,
    module: GAME_MODULE,
    t0_ms: t0,
    addrs: {
      demo_mode_start: addrDemoStart.toString(),
      ui_elements_max_timeline: addrMaxTimeline.toString(),
    },
  });

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

