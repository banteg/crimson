'use strict';

// Logs demo trial overlay renders + key globals (time/mode/quest stage).
//
// Usage (Windows VM):
//   frida -n crimsonland.exe -l C:\share\frida\demo_trial_overlay_trace.js
//
// Notes:
// - Addresses are for the repo's PE (1.9.93-gog) with link base 0x00400000.
// - This hook is intended for demo builds; the retail build may never render the overlay.
// - For other builds, override addresses via:
//     CRIMSON_FRIDA_ADDRS="demo_trial_overlay_render=0x401000,game_sequence_get=0x402000"
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
  // Optional: if you're running the retail binary (which may never render the overlay),
  // set this to true to force "demo" behavior only for the main gameplay loop's
  // shareware gate checks (avoids a global game_is_full_version() -> 0 patch).
  forceDemoInGameplayLoop: false,
  // Optional: force the demo playtime (ms) only for gameplay_update_and_render's calls
  // to game_sequence_get(). Useful to trigger the overlay without waiting ~40 minutes.
  // Note: this does not force demo gates by itself; pair with forceDemoInGameplayLoop.
  forcePlaytimeMs: null,
  // Optional: log at most once per N milliseconds (0 = log every call).
  minOverlayLogIntervalMs: 0,
  logFullVersionCalls: false,
  logBacktrace: false,
  backtraceLimit: 12,
  logPath: joinPath(LOG_DIR, 'demo_trial_overlay_trace.jsonl'),
};

const GAME_MODULE =
  getEnv('CRIMSON_FRIDA_MODULE') ||
  (Process.mainModule && Process.mainModule.name ? Process.mainModule.name : DEFAULT_GAME_MODULE);

let LINK_BASE = ptr('0x00400000');

const DEMO_TOTAL_PLAY_TIME_MS = 2400000;
const DEMO_QUEST_GRACE_TIME_MS = 300000;

const ADDR = {
  game_is_full_version: 0x0041df40,
  game_sequence_get: 0x0041df60,
  gameplay_update_and_render: 0x0040aab0,
  gameplay_update_and_render_end: 0x0040b5d0, // start of next function

  demo_trial_overlay_render: 0x004047c0,

  config_game_mode: 0x00480360,
  demo_trial_elapsed_ms: 0x0048084c,
  game_sequence_id: 0x00485794,
  quest_stage_major: 0x00487004,
  quest_stage_minor: 0x00487008,
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

function buildStartEvent() {
  let mod = null;
  try {
    mod = Process.getModuleByName(GAME_MODULE);
  } catch (_) {
    // ignore
  }

  const addrs = {};
  for (const key in ADDR) {
    const addr = exePtr(ADDR[key]);
    addrs[key] = addr ? addr.toString() : null;
  }

  const staticAddrs = {};
  for (const key in ADDR) {
    staticAddrs[key] = formatHex32(ADDR[key]);
  }

  return {
    event: 'start',
    t0_ms: Date.now(),
    config: CONFIG,
    frida: { version: Frida.version, runtime: Script.runtime },
    process: { pid: Process.id, platform: Process.platform, arch: Process.arch },
    module: GAME_MODULE,
    link_base: LINK_BASE.toString(),
    addr_overrides: {
      applied: ADDR_OVERRIDES.applied,
      errors: ADDR_OVERRIDES.errors,
    },
    exe: mod
      ? {
          base: mod.base.toString(),
          size: mod.size,
          path: mod.path,
        }
      : null,
    static_addrs: staticAddrs,
    addrs: addrs,
  };
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

function ptrInRange(p, start, end) {
  if (!p || !start || !end) return false;
  try {
    return p.compare(start) >= 0 && p.compare(end) < 0;
  } catch (_) {
    return false;
  }
}

function hookGameIsFullVersion() {
  const addr = exePtr(ADDR.game_is_full_version);
  if (!addr) {
    writeLog({ event: 'hook_error', target: 'game_is_full_version', error: 'addr_unavailable' });
    return;
  }

  const gameplayStart = exePtr(ADDR.gameplay_update_and_render);
  const gameplayEnd = exePtr(ADDR.gameplay_update_and_render_end);
  if (!gameplayStart || !gameplayEnd) {
    writeLog({
      event: 'hook_error',
      target: 'gameplay_update_and_render_range',
      error: 'addr_unavailable',
    });
  }

  writeLog({ event: 'hook', target: 'game_is_full_version', addr: addr.toString() });

  let forcedCount = 0;

  Interceptor.attach(addr, {
    onLeave(retval) {
      const callsite = this.returnAddress;

      if (CONFIG.logFullVersionCalls) {
        writeLog({
          event: 'game_is_full_version_call',
          callsite: callsite ? callsite.toString() : null,
          retval: retval.toInt32(),
          in_gameplay_loop: callsite ? ptrInRange(callsite, gameplayStart, gameplayEnd) : null,
        });
      }

      if (!CONFIG.forceDemoInGameplayLoop) return;
      if (!callsite) return;

      if (ptrInRange(callsite, gameplayStart, gameplayEnd)) {
        retval.replace(0);
        if (forcedCount === 0) {
          writeLog({
            event: 'forced_demo_gate',
            target: 'game_is_full_version',
            callsite: callsite.toString(),
          });
        }
        forcedCount += 1;
      }
    },
  });
}

function hookGameSequenceGet() {
  if (CONFIG.forcePlaytimeMs === null || CONFIG.forcePlaytimeMs === undefined) return;

  const addr = exePtr(ADDR.game_sequence_get);
  if (!addr) {
    writeLog({ event: 'hook_error', target: 'game_sequence_get', error: 'addr_unavailable' });
    return;
  }

  const gameplayStart = exePtr(ADDR.gameplay_update_and_render);
  const gameplayEnd = exePtr(ADDR.gameplay_update_and_render_end);
  if (!gameplayStart || !gameplayEnd) {
    writeLog({
      event: 'hook_error',
      target: 'gameplay_update_and_render_range',
      error: 'addr_unavailable',
    });
  }

  const forcedValue = parseInt(CONFIG.forcePlaytimeMs, 10);
  if (!Number.isFinite(forcedValue)) {
    writeLog({ event: 'hook_error', target: 'forcePlaytimeMs', error: 'not_a_number', value: CONFIG.forcePlaytimeMs });
    return;
  }

  writeLog({
    event: 'hook',
    target: 'game_sequence_get',
    addr: addr.toString(),
    force_playtime_ms: forcedValue,
  });

  let forcedCount = 0;

  Interceptor.attach(addr, {
    onLeave(retval) {
      const callsite = this.returnAddress;
      if (!callsite) return;
      if (!ptrInRange(callsite, gameplayStart, gameplayEnd)) return;

      retval.replace(forcedValue);
      if (forcedCount === 0) {
        writeLog({ event: 'forced_playtime', callsite: callsite.toString(), playtime_ms: forcedValue });
      }
      forcedCount += 1;
    },
  });
}

function hookOverlayRender() {
  const addr = exePtr(ADDR.demo_trial_overlay_render);
  if (!addr) {
    writeLog({ event: 'hook_error', target: 'demo_trial_overlay_render', error: 'addr_unavailable' });
    return;
  }

  writeLog({ event: 'hook', target: 'demo_trial_overlay_render', addr: addr.toString() });

  let lastLogMs = 0;

  Interceptor.attach(addr, {
    onEnter(args) {
      const nowMs = Date.now();
      const minIntervalMs = parseInt(CONFIG.minOverlayLogIntervalMs, 10) || 0;
      if (minIntervalMs > 0 && lastLogMs > 0 && nowMs - lastLogMs < minIntervalMs) {
        return;
      }

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
        t_ms: nowMs,
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
      lastLogMs = nowMs;
    },
  });
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
  writeLog(buildStartEvent());

  if (CONFIG.forceDemoInGameplayLoop || CONFIG.logFullVersionCalls) {
    hookGameIsFullVersion();
  }
  if (CONFIG.forcePlaytimeMs !== null && CONFIG.forcePlaytimeMs !== undefined) {
    hookGameSequenceGet();
  }

  hookOverlayRender();
}

main();
