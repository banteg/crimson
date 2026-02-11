"use strict";

// Survival auto-aim/fire sidecar for differential capture sessions.
//
// Attach:
//   frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
//
// Behavior:
// - does NOT auto-start Survival
// - does NOT inject movement input
// - does NOT auto-pick perks
// - only enforces the selected control mode for native auto aim/fire

const DEFAULT_LOG_DIR = "C:\\share\\frida";
const GAME_MODULE = "crimsonland.exe";
const LINK_BASE = ptr("0x00400000");

function getEnv(key) {
  try {
    return Process.env[key] || null;
  } catch (_) {
    return null;
  }
}

function parseIntEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const parsed = parseInt(String(raw).trim(), 0);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBoolEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const text = String(raw).trim().toLowerCase();
  if (text === "1" || text === "true" || text === "yes" || text === "on") return true;
  if (text === "0" || text === "false" || text === "no" || text === "off") return false;
  return fallback;
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith("\\") || base.endsWith("/") ? "" : "\\";
  return base + sep + leaf;
}

function nowMs() {
  return Date.now();
}

function nowIso() {
  return new Date().toISOString();
}

const LOG_DIR = getEnv("CRIMSON_FRIDA_DIR") || DEFAULT_LOG_DIR;

const CONFIG = {
  outPath: joinPath(LOG_DIR, "survival_autoplay.jsonl"),

  playerIndex: Math.max(0, Math.min(3, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PLAYER", 0))),
  forcePlayerCount: Math.max(1, Math.min(4, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PLAYER_COUNT", 1))),

  // Keep this enabled if you always want the menu/game mode pre-selected to Survival.
  enforceModeId: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_ENFORCE_MODE", true),
  forceModeId: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_MODE", 1), // 1 = Survival

  // Native computer-assisted control mode for aim/fire only.
  // Defaults chosen to avoid movement injection while preserving native auto target/fire behavior.
  forceMoveMode: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_MOVE_MODE", 5),
  forceAimScheme: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_AIM_SCHEME", 5),
  disableMovement: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_DISABLE_MOVEMENT", true),

  enforceConfigEachFrame: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_ENFORCE_EACH_FRAME", true),
  keepDemoModeOff: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_DEMO_OFF", true),
};

const FN = {
  gameplay_update_and_render: 0x0040aab0,
};

const DATA = {
  config_player_count: 0x0048035c,
  config_game_mode: 0x00480360,
  config_player_mode_flags: 0x00480364,
  config_aim_scheme: 0x0048038c,

  demo_mode_active: 0x0048700d,
  game_state_id: 0x00487270,

  player_pos_x: 0x004908c4,
  player_pos_y: 0x004908c8,
  player_move_dx: 0x004908cc,
  player_move_dy: 0x004908d0,
};

const STRIDE = {
  player: 0x360,
};

let exeModule = null;
let outFile = null;
let outWarned = false;

const fnPtrs = {};
const dataPtrs = {};
const attached = {};
const RUN = {
  framePosX: null,
  framePosY: null,
};

function openOutFile() {
  if (outFile !== null) return;
  try {
    outFile = new File(CONFIG.outPath, "a");
  } catch (_) {
    outFile = null;
  }
}

function writeLog(obj) {
  const payload = Object.assign({ ts_ms: nowMs(), ts_iso: nowIso(), script: "survival_autoplay" }, obj);
  const line = JSON.stringify(payload) + "\n";
  let wrote = false;
  try {
    openOutFile();
    if (outFile) {
      outFile.write(line);
      wrote = true;
    }
  } catch (_) {}
  if (!wrote && !outWarned) {
    outWarned = true;
    console.log("survival_autoplay: file logging unavailable, console only");
  }
  console.log(line.trim());
}

function toRuntimePtr(staticVa) {
  if (!exeModule) return null;
  try {
    return exeModule.base.add(ptr(staticVa).sub(LINK_BASE));
  } catch (_) {
    return null;
  }
}

function readS32Ptr(p) {
  if (!p) return null;
  try {
    return p.readS32();
  } catch (_) {
    return null;
  }
}

function readU8Ptr(p) {
  if (!p) return null;
  try {
    return p.readU8();
  } catch (_) {
    return null;
  }
}

function readF32Ptr(p) {
  if (!p) return null;
  try {
    return p.readFloat();
  } catch (_) {
    return null;
  }
}

function writeS32Ptr(p, value) {
  if (!p) return false;
  try {
    p.writeS32(value | 0);
    return true;
  } catch (_) {
    return false;
  }
}

function writeU8Ptr(p, value) {
  if (!p) return false;
  try {
    p.writeU8(value & 0xff);
    return true;
  } catch (_) {
    return false;
  }
}

function writeF32Ptr(p, value) {
  if (!p) return false;
  try {
    p.writeFloat(Number(value));
    return true;
  } catch (_) {
    return false;
  }
}

function readS32(name) {
  return readS32Ptr(dataPtrs[name]);
}

function writeS32IfDifferent(name, value) {
  const p = dataPtrs[name];
  if (!p) return false;
  const cur = readS32Ptr(p);
  if (cur === (value | 0)) return false;
  return writeS32Ptr(p, value);
}

function playerDataPtr(name, playerIndex) {
  const base = dataPtrs[name];
  if (!base) return null;
  const idx = Math.max(0, Math.min(3, playerIndex | 0));
  return base.add(idx * STRIDE.player);
}

function readPlayerI32(name, playerIndex) {
  return readS32Ptr(playerDataPtr(name, playerIndex));
}

function readPlayerF32(name, playerIndex) {
  return readF32Ptr(playerDataPtr(name, playerIndex));
}

function writePlayerS32IfDifferent(name, playerIndex, value) {
  const p = playerDataPtr(name, playerIndex);
  if (!p) return false;
  const cur = readS32Ptr(p);
  if (cur === (value | 0)) return false;
  return writeS32Ptr(p, value);
}

function writePlayerF32(name, playerIndex, value) {
  return writeF32Ptr(playerDataPtr(name, playerIndex), value);
}

function capturePlayerPosForFrame() {
  RUN.framePosX = null;
  RUN.framePosY = null;
  if (!CONFIG.disableMovement) return;
  if (readS32("game_state_id") !== 9) return;

  const x = readPlayerF32("player_pos_x", CONFIG.playerIndex);
  const y = readPlayerF32("player_pos_y", CONFIG.playerIndex);
  if (!Number.isFinite(x) || !Number.isFinite(y)) return;

  RUN.framePosX = x;
  RUN.framePosY = y;
}

function suppressPlayerMovementForFrame() {
  if (!CONFIG.disableMovement) return;
  if (!Number.isFinite(RUN.framePosX) || !Number.isFinite(RUN.framePosY)) return;
  if (readS32("game_state_id") !== 9) return;

  writePlayerF32("player_pos_x", CONFIG.playerIndex, RUN.framePosX);
  writePlayerF32("player_pos_y", CONFIG.playerIndex, RUN.framePosY);
  writePlayerF32("player_move_dx", CONFIG.playerIndex, 0.0);
  writePlayerF32("player_move_dy", CONFIG.playerIndex, 0.0);
}

function enforceAssistConfig(reason) {
  let changed = false;

  changed = writeS32IfDifferent("config_player_count", CONFIG.forcePlayerCount) || changed;
  if (CONFIG.enforceModeId) {
    changed = writeS32IfDifferent("config_game_mode", CONFIG.forceModeId) || changed;
  }

  changed = writePlayerS32IfDifferent("config_player_mode_flags", CONFIG.playerIndex, CONFIG.forceMoveMode) || changed;
  changed = writePlayerS32IfDifferent("config_aim_scheme", CONFIG.playerIndex, CONFIG.forceAimScheme) || changed;

  if (CONFIG.keepDemoModeOff) {
    const demoPtr = dataPtrs.demo_mode_active;
    const demoVal = readU8Ptr(demoPtr);
    if (demoVal && writeU8Ptr(demoPtr, 0)) changed = true;
  }

  if (changed || reason !== "frame") {
    writeLog({
      event: "config_enforced",
      reason,
      game_state_id: readS32("game_state_id"),
      game_mode: readS32("config_game_mode"),
      player_count: readS32("config_player_count"),
      move_mode: readPlayerI32("config_player_mode_flags", CONFIG.playerIndex),
      aim_scheme: readPlayerI32("config_aim_scheme", CONFIG.playerIndex),
    });
  }
}

function attachOnce(name, addr, handlers) {
  if (!addr || attached[name]) return;
  attached[name] = true;
  try {
    Interceptor.attach(addr, handlers);
    writeLog({ event: "attach", name, addr: addr.toString() });
  } catch (e) {
    writeLog({ event: "attach_error", name, addr: addr.toString(), error: String(e) });
  }
}

function main() {
  try {
    exeModule = Process.getModuleByName(GAME_MODULE);
  } catch (_) {
    exeModule = null;
  }

  if (!exeModule) {
    writeLog({ event: "error", error: "missing_module", module: GAME_MODULE });
    return;
  }

  for (const key in FN) fnPtrs[key] = toRuntimePtr(FN[key]);
  for (const key in DATA) dataPtrs[key] = toRuntimePtr(DATA[key]);

  writeLog({
    event: "start",
    config: CONFIG,
    process: { pid: Process.id, platform: Process.platform, arch: Process.arch },
    exe: { base: exeModule.base.toString(), size: exeModule.size, path: exeModule.path },
    ptrs: {
      gameplay_update_and_render: !!fnPtrs.gameplay_update_and_render,
      config_player_mode_flags: !!dataPtrs.config_player_mode_flags,
      config_aim_scheme: !!dataPtrs.config_aim_scheme,
    },
    out_path: CONFIG.outPath,
  });

  enforceAssistConfig("startup");

  if (CONFIG.enforceConfigEachFrame && fnPtrs.gameplay_update_and_render) {
    attachOnce("gameplay_update_and_render", fnPtrs.gameplay_update_and_render, {
      onEnter() {
        capturePlayerPosForFrame();
        enforceAssistConfig("frame");
      },
      onLeave() {
        suppressPlayerMovementForFrame();
      },
    });
  } else {
    writeLog({
      event: "frame_enforce_disabled",
      enforceConfigEachFrame: CONFIG.enforceConfigEachFrame,
      has_gameplay_update_and_render: !!fnPtrs.gameplay_update_and_render,
    });
  }
}

main();
