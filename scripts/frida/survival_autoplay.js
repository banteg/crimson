"use strict";

// Survival autoplay sidecar for differential capture sessions.
//
// Attach:
//   frida -n crimsonland.exe -l C:\share\frida\survival_autoplay.js
//
// This script intentionally avoids replacing core input APIs. Instead it:
// - forces Survival mode (config_game_mode = 1),
// - forces player 1 control flags to native "Computer" paths
//   (config_player_mode_flags[0] = 5, config_aim_scheme[0] = 5),
// - starts/restarts runs via gameplay_reset_state + game_state_set(9),
// - auto-applies one perk per perk-selection screen and returns to gameplay.

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
  autoStart: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_START", true),
  autoStartDelayMs: Math.max(0, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_START_DELAY_MS", 1000)),
  autoRestartOnGameOver: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_RESTART", true),
  restartDelayMs: Math.max(100, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_RESTART_DELAY_MS", 1200)),
  enforceConfigEachFrame: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_ENFORCE_EACH_FRAME", true),
  playerIndex: Math.max(0, Math.min(3, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PLAYER", 0))),
  forcePlayerCount: Math.max(1, Math.min(4, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PLAYER_COUNT", 1))),
  forceModeId: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_MODE", 1), // 1 = Survival
  forceMoveMode: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_MOVE_MODE", 5), // 5 = Computer
  forceAimScheme: parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_AIM_SCHEME", 5), // 5 = Computer
  autoPickPerks: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_PERKS", true),
  pickPerkDelayMs: Math.max(0, parseIntEnv("CRIMSON_FRIDA_AUTOPLAY_PERK_DELAY_MS", 120)),
  keepDemoModeOff: parseBoolEnv("CRIMSON_FRIDA_AUTOPLAY_DEMO_OFF", true),
};

const FN = {
  perk_apply: 0x004055e0,
  gameplay_update_and_render: 0x0040aab0,
  game_over_screen_update: 0x0040ffc0,
  gameplay_reset_state: 0x00412dc0,
  game_state_set: 0x004461c0,
  perk_selection_screen_update: 0x00405be0,
};

const DATA = {
  config_player_count: 0x0048035c,
  config_game_mode: 0x00480360,
  config_player_mode_flags: 0x00480364,
  config_aim_scheme: 0x0048038c,
  perk_choice_ids: 0x004807e8, // int[7]
  perk_selection_index: 0x0048089c,
  perk_pending_count: 0x00486fac,
  perk_choices_dirty: 0x00486fb0,
  demo_mode_active: 0x0048700d,
  ui_transition_direction: 0x0048724c,
  game_state_id: 0x00487270,
  game_state_pending: 0x00487274,
};

let exeModule = null;
let outFile = null;
let outWarned = false;
const fnPtrs = {};
const dataPtrs = {};
const attached = {};

let fPerkApply = null;
let fGameStateSet = null;
let fGameplayResetState = null;

const RUN = {
  restartScheduled: false,
  perkAppliedForCurrentScreen: false,
  lastPerkApplyMs: 0,
  lastStartMs: 0,
};

function resolveAbi() {
  if (Process.platform !== "windows") return null;
  if (Process.arch === "x64") return "win64";
  if (Process.arch === "ia32") return "mscdecl";
  return null;
}

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

function writeS32Ptr(p, value) {
  if (!p) return false;
  try {
    p.writeS32(value | 0);
    return true;
  } catch (_) {
    return false;
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

function writeU8Ptr(p, value) {
  if (!p) return false;
  try {
    p.writeU8(value & 0xff);
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

function playerConfigPtr(name, playerIndex) {
  const base = dataPtrs[name];
  if (!base) return null;
  const idx = Math.max(0, Math.min(3, playerIndex | 0));
  return base.add(idx * 4);
}

function writePlayerS32IfDifferent(name, playerIndex, value) {
  const p = playerConfigPtr(name, playerIndex);
  if (!p) return false;
  const cur = readS32Ptr(p);
  if (cur === (value | 0)) return false;
  return writeS32Ptr(p, value);
}

function enforceAutoplayConfig(reason) {
  let changed = false;
  changed = writeS32IfDifferent("config_game_mode", CONFIG.forceModeId) || changed;
  changed = writeS32IfDifferent("config_player_count", CONFIG.forcePlayerCount) || changed;
  changed = writePlayerS32IfDifferent("config_player_mode_flags", CONFIG.playerIndex, CONFIG.forceMoveMode) || changed;
  changed = writePlayerS32IfDifferent("config_aim_scheme", CONFIG.playerIndex, CONFIG.forceAimScheme) || changed;
  if (CONFIG.keepDemoModeOff) {
    const demoPtr = dataPtrs.demo_mode_active;
    const demoVal = readU8Ptr(demoPtr);
    if (demoVal && writeU8Ptr(demoPtr, 0)) changed = true;
  }
  if (changed && reason !== "frame") {
    writeLog({
      event: "config_enforced",
      reason,
      game_mode: readS32("config_game_mode"),
      player_count: readS32("config_player_count"),
      move_mode: readS32Ptr(playerConfigPtr("config_player_mode_flags", CONFIG.playerIndex)),
      aim_scheme: readS32Ptr(playerConfigPtr("config_aim_scheme", CONFIG.playerIndex)),
    });
  }
  return changed;
}

function pickPerkChoice() {
  const selected = readS32("perk_selection_index");
  const choiceBase = dataPtrs.perk_choice_ids;
  if (!choiceBase) return null;

  function choiceAt(index) {
    if (index < 0 || index >= 7) return null;
    return readS32Ptr(choiceBase.add(index * 4));
  }

  if (selected != null && selected >= 0 && selected < 7) {
    const perkId = choiceAt(selected);
    if (perkId != null) return { perk_id: perkId, index: selected, source: "selected" };
  }
  for (let i = 0; i < 7; i++) {
    const perkId = choiceAt(i);
    if (perkId != null) return { perk_id: perkId, index: i, source: "fallback_first" };
  }
  return null;
}

function applyPerkAndResume(reason) {
  if (!CONFIG.autoPickPerks || !fPerkApply) return false;
  const gameState = readS32("game_state_id");
  if (gameState !== 6) return false;
  if (RUN.perkAppliedForCurrentScreen) return false;
  const now = nowMs();
  if (now - RUN.lastPerkApplyMs < CONFIG.pickPerkDelayMs) return false;

  const pending = readS32("perk_pending_count");
  if (pending == null || pending <= 0) return false;

  const pick = pickPerkChoice();
  if (!pick || pick.perk_id == null) {
    writeLog({ event: "perk_pick_skip", reason, pending, error: "no_choice" });
    return false;
  }

  try {
    fPerkApply(pick.perk_id | 0);
  } catch (e) {
    writeLog({ event: "perk_pick_error", reason, error: String(e) });
    return false;
  }

  if (pending > 0) writeS32Ptr(dataPtrs.perk_pending_count, pending - 1);
  writeU8Ptr(dataPtrs.perk_choices_dirty, 1);
  writeS32Ptr(dataPtrs.ui_transition_direction, 0);
  writeS32Ptr(dataPtrs.game_state_pending, 9);

  RUN.perkAppliedForCurrentScreen = true;
  RUN.lastPerkApplyMs = now;
  writeLog({
    event: "perk_auto_apply",
    reason,
    perk_id: pick.perk_id,
    choice_index: pick.index,
    choice_source: pick.source,
    pending_before: pending,
    pending_after: Math.max(0, pending - 1),
  });
  return true;
}

function startSurvival(reason) {
  enforceAutoplayConfig(reason);
  try {
    if (fGameplayResetState) fGameplayResetState();
  } catch (e) {
    writeLog({ event: "start_error", reason, stage: "gameplay_reset_state", error: String(e) });
  }
  try {
    if (fGameStateSet) fGameStateSet(9);
  } catch (e) {
    writeLog({ event: "start_error", reason, stage: "game_state_set", error: String(e) });
    return false;
  }
  RUN.lastStartMs = nowMs();
  RUN.perkAppliedForCurrentScreen = false;
  writeLog({
    event: "survival_start",
    reason,
    game_mode: readS32("config_game_mode"),
    player_count: readS32("config_player_count"),
    game_state_id: readS32("game_state_id"),
  });
  return true;
}

function scheduleRestart(reason) {
  if (RUN.restartScheduled || !CONFIG.autoRestartOnGameOver) return;
  RUN.restartScheduled = true;
  writeLog({
    event: "survival_restart_scheduled",
    reason,
    delay_ms: CONFIG.restartDelayMs,
    game_state_id: readS32("game_state_id"),
  });
  setTimeout(function () {
    RUN.restartScheduled = false;
    startSurvival("auto_restart_game_over");
  }, CONFIG.restartDelayMs);
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

  for (const key in FN) {
    fnPtrs[key] = toRuntimePtr(FN[key]);
  }
  for (const key in DATA) {
    dataPtrs[key] = toRuntimePtr(DATA[key]);
  }

  const abi = resolveAbi();
  fPerkApply = fnPtrs.perk_apply
    ? abi
      ? new NativeFunction(fnPtrs.perk_apply, "void", ["int"], abi)
      : new NativeFunction(fnPtrs.perk_apply, "void", ["int"])
    : null;
  fGameStateSet = fnPtrs.game_state_set
    ? abi
      ? new NativeFunction(fnPtrs.game_state_set, "void", ["int"], abi)
      : new NativeFunction(fnPtrs.game_state_set, "void", ["int"])
    : null;
  fGameplayResetState = fnPtrs.gameplay_reset_state
    ? abi
      ? new NativeFunction(fnPtrs.gameplay_reset_state, "void", [], abi)
      : new NativeFunction(fnPtrs.gameplay_reset_state, "void", [])
    : null;

  writeLog({
    event: "start",
    config: CONFIG,
    process: { pid: Process.id, platform: Process.platform, arch: Process.arch },
    exe: { base: exeModule.base.toString(), size: exeModule.size, path: exeModule.path },
    ptrs: {
      game_state_set: !!fnPtrs.game_state_set,
      gameplay_reset_state: !!fnPtrs.gameplay_reset_state,
      perk_apply: !!fnPtrs.perk_apply,
      perk_selection_screen_update: !!fnPtrs.perk_selection_screen_update,
      game_over_screen_update: !!fnPtrs.game_over_screen_update,
      gameplay_update_and_render: !!fnPtrs.gameplay_update_and_render,
    },
    out_path: CONFIG.outPath,
  });

  if (!fGameStateSet || !fGameplayResetState || !fPerkApply) {
    writeLog({
      event: "error",
      error: "required_function_missing",
      has_game_state_set: !!fGameStateSet,
      has_gameplay_reset_state: !!fGameplayResetState,
      has_perk_apply: !!fPerkApply,
    });
    return;
  }

  attachOnce("game_state_set", fnPtrs.game_state_set, {
    onEnter(args) {
      const nextState = args[0].toInt32();
      if (nextState === 6) RUN.perkAppliedForCurrentScreen = false;
      if (nextState === 9) RUN.perkAppliedForCurrentScreen = false;
      if (nextState !== 7) RUN.restartScheduled = false;
    },
  });

  attachOnce("gameplay_update_and_render", fnPtrs.gameplay_update_and_render, {
    onEnter() {
      if (CONFIG.enforceConfigEachFrame) enforceAutoplayConfig("frame");
    },
  });

  attachOnce("perk_selection_screen_update", fnPtrs.perk_selection_screen_update, {
    onLeave() {
      applyPerkAndResume("perk_selection_screen_update");
    },
  });

  attachOnce("game_over_screen_update", fnPtrs.game_over_screen_update, {
    onEnter() {
      scheduleRestart("game_over_screen_update");
    },
  });

  if (CONFIG.autoStart) {
    setTimeout(function () {
      startSurvival("auto_start");
    }, CONFIG.autoStartDelayMs);
  } else {
    writeLog({ event: "auto_start_disabled" });
  }
}

main();
