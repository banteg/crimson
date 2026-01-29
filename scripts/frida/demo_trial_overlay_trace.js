'use strict';

// Logs demo trial overlay renders + key globals (time/mode/quest stage).
//
// Usage (Windows VM):
//   frida -n crimsonland.exe -l C:\share\frida\demo_trial_overlay_trace.js
//
// Notes:
// - Addresses are for the repo's PE (1.9.93-gog) with link base 0x00400000.
// - This hook is intended for demo builds; the retail build may never render the overlay.

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
  logBacktrace: false,
  backtraceLimit: 12,
  logPath: joinPath(LOG_DIR, 'demo_trial_overlay_trace.jsonl'),
};

const GAME_MODULE = 'crimsonland.exe';

const LINK_BASE = {
  'crimsonland.exe': ptr('0x00400000'),
};

const DEMO_TOTAL_PLAY_TIME_MS = 2400000;
const DEMO_QUEST_GRACE_TIME_MS = 300000;

const ADDR = {
  demo_trial_overlay_render: 0x004047c0,

  config_game_mode: 0x00480360,
  demo_trial_elapsed_ms: 0x0048084c,
  game_sequence_id: 0x00485794,
  quest_stage_major: 0x00487004,
  quest_stage_minor: 0x00487008,
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

function readS32(staticVa) {
  const addr = exePtr(staticVa);
  if (!addr) return null;
  try {
    return addr.readS32();
  } catch (_) {
    return null;
  }
}

function readVec2f(ptrArg) {
  try {
    const x = ptrArg.readFloat();
    const y = ptrArg.add(4).readFloat();
    return { x: x, y: y };
  } catch (_) {
    return null;
  }
}

function hookOverlayRender() {
  const addr = exePtr(ADDR.demo_trial_overlay_render);
  if (!addr) {
    writeLog({ event: 'hook_error', target: 'demo_trial_overlay_render', error: 'addr_unavailable' });
    return;
  }

  writeLog({ event: 'hook', target: 'demo_trial_overlay_render', addr: addr.toString() });

  Interceptor.attach(addr, {
    onEnter(args) {
      const modeId = readS32(ADDR.config_game_mode);
      const usedMs = readS32(ADDR.game_sequence_id);
      const graceMs = readS32(ADDR.demo_trial_elapsed_ms);
      const questMajor = readS32(ADDR.quest_stage_major);
      const questMinor = readS32(ADDR.quest_stage_minor);
      const gameStateId = readS32(ADDR.game_state_id);

      const xy = readVec2f(args[0]);

      const used = usedMs === null ? null : Math.max(0, usedMs);
      const grace = graceMs === null ? null : Math.max(0, graceMs);
      const remainingMs =
        grace !== null && grace > 0
          ? Math.max(0, DEMO_QUEST_GRACE_TIME_MS - grace)
          : used !== null
            ? Math.max(0, DEMO_TOTAL_PLAY_TIME_MS - used)
            : null;

      const tierLocked =
        modeId === 3 &&
        questMajor !== null &&
        questMinor !== null &&
        (questMajor > 1 || questMinor > 10);

      const evt = {
        event: 'demo_trial_overlay_render',
        t_ms: Date.now(),
        mode_id: modeId,
        game_state_id: gameStateId,
        quest_stage_major: questMajor,
        quest_stage_minor: questMinor,
        game_sequence_id_ms: usedMs,
        demo_trial_elapsed_ms: graceMs,
        remaining_ms: remainingMs,
        tier_locked: tierLocked,
        xy: xy,
      };

      if (CONFIG.logBacktrace) {
        try {
          const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .map((s) => s.toString())
            .slice(0, CONFIG.backtraceLimit);
          evt.backtrace = bt;
        } catch (_) {
          // ignore
        }
      }

      writeLog(evt);
    },
  });
}

function main() {
  initLog();
  writeLog({ event: 'start', config: CONFIG, module: GAME_MODULE });

  hookOverlayRender();
}

main();
