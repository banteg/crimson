"use strict";

// Trace runtime contract for thunk_FUN_00452f1d (0x00452f1d).
//
// Goal:
// - capture real call shape (stack/register pointer candidates)
// - capture caller/callee static addresses under ASLR
// - record before/after vec2-like pointer contents when readable
//
// Usage (attach):
//   frida -n crimsonland.exe -l C:\share\frida\thunk_452f1d_trace.js
// Attach only: spawning via frida -f is unstable on this VM.

const DEFAULT_LOG_DIR = "C:\\share\\frida";
const LINK_BASE = {
  "crimsonland.exe": ptr("0x00400000"),
  "grim.dll": ptr("0x10000000"),
};

const ADDR = {
  thunk_452f1d: 0x00452f1d,
  thunk_callback_ptr: 0x00479658,
  frame_dt_ms: 0x00480844,
  game_state_id: 0x00487270,
  creature_update_tick: 0x004aaf58,
};

function getEnv(key) {
  try {
    return Process.env[key] || null;
  } catch (_) {
    return null;
  }
}

function parseBoolEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const text = String(raw).trim().toLowerCase();
  if (text === "1" || text === "true" || text === "yes" || text === "on") return true;
  if (text === "0" || text === "false" || text === "no" || text === "off") return false;
  return fallback;
}

function parseIntEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const parsed = parseInt(String(raw).trim(), 0);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith("\\") || base.endsWith("/") ? "" : "\\";
  return base + sep + leaf;
}

function nowIso() {
  return new Date().toISOString();
}

function toHex(value, width) {
  if (value == null) return null;
  let hex = (value >>> 0).toString(16);
  while (hex.length < width) hex = "0" + hex;
  return "0x" + hex;
}

function moduleByAddress(address) {
  try {
    return Process.findModuleByAddress(address);
  } catch (_) {
    return null;
  }
}

function runtimeToStatic(address) {
  if (!address) return null;
  const mod = moduleByAddress(address);
  if (!mod) return null;
  const link = LINK_BASE[String(mod.name || "").toLowerCase()];
  if (!link) return null;
  try {
    return link.add(address.sub(mod.base)).toString();
  } catch (_) {
    return null;
  }
}

function moduleOffset(address) {
  if (!address) return null;
  const mod = moduleByAddress(address);
  if (!mod) return null;
  try {
    return {
      module: mod.name,
      offset: "0x" + address.sub(mod.base).toString(16),
    };
  } catch (_) {
    return { module: mod.name, offset: null };
  }
}

function staticToRuntime(staticVa) {
  const mod = Process.getModuleByName("crimsonland.exe");
  if (!mod) return null;
  return mod.base.add(ptr(staticVa).sub(LINK_BASE["crimsonland.exe"]));
}

function safeReadS32(address) {
  try {
    return address.readS32();
  } catch (_) {
    return null;
  }
}

function safeReadPointer(address) {
  try {
    return address.readPointer();
  } catch (_) {
    return null;
  }
}

function safeReadFloat(address) {
  try {
    return address.readFloat();
  } catch (_) {
    return null;
  }
}

function safeInt32(retval) {
  try {
    return retval.toInt32();
  } catch (_) {
    return null;
  }
}

function safeSymbol(address) {
  try {
    return DebugSymbol.fromAddress(address).toString();
  } catch (_) {
    return null;
  }
}

function safeBacktrace(context, maxFrames) {
  try {
    const frames = Thread.backtrace(context, Backtracer.ACCURATE);
    const out = [];
    for (let i = 0; i < frames.length && i < maxFrames; i++) {
      const frame = frames[i];
      out.push({
        runtime: frame.toString(),
        static: runtimeToStatic(frame),
        symbol: safeSymbol(frame),
      });
    }
    return out;
  } catch (_) {
    return null;
  }
}

function sampleVec2(address) {
  if (!address || address.isNull()) return null;
  const x = safeReadFloat(address);
  const y = safeReadFloat(address.add(4));
  if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
  if (Math.abs(x) > 20000.0 || Math.abs(y) > 20000.0) return null;
  return { x, y };
}

const CONFIG = {
  logPath: joinPath(getEnv("CRIMSON_FRIDA_DIR") || DEFAULT_LOG_DIR, "thunk_452f1d_trace.jsonl"),
  logMode: String(getEnv("CRIMSON_THUNK_TRACE_APPEND") || "").trim() === "1" ? "append" : "truncate",
  logToConsole: parseBoolEnv("CRIMSON_THUNK_TRACE_CONSOLE", true),
  maxEvents: Math.max(0, parseIntEnv("CRIMSON_THUNK_TRACE_MAX_EVENTS", 0)),
  includeBacktrace: parseBoolEnv("CRIMSON_THUNK_TRACE_BT", false),
  backtraceMaxFrames: Math.max(1, parseIntEnv("CRIMSON_THUNK_TRACE_BT_FRAMES", 12)),
};

let LOG = { file: null, ok: false };
let EVENT_COUNT = 0;
let SEQ = 0;

function initLog() {
  try {
    const mode = CONFIG.logMode === "append" ? "a" : "w";
    LOG.file = new File(CONFIG.logPath, mode);
    LOG.ok = true;
  } catch (e) {
    console.log("[thunk_452f1d_trace] failed to open log: " + e);
    LOG.ok = false;
  }
}

function writeLog(obj) {
  const line = JSON.stringify(obj);
  if (LOG.ok) {
    LOG.file.write(line + "\n");
    LOG.file.flush();
  }
  if (CONFIG.logToConsole) console.log(line);
}

function stateSnapshot() {
  const frameDtMsPtr = staticToRuntime(ADDR.frame_dt_ms);
  const gameStatePtr = staticToRuntime(ADDR.game_state_id);
  const creatureTickPtr = staticToRuntime(ADDR.creature_update_tick);
  return {
    frame_dt_ms: frameDtMsPtr ? safeReadS32(frameDtMsPtr) : null,
    game_state_id: gameStatePtr ? safeReadS32(gameStatePtr) : null,
    creature_update_tick: creatureTickPtr ? safeReadS32(creatureTickPtr) : null,
  };
}

function readThunkCallbackTarget() {
  const callbackPtr = staticToRuntime(ADDR.thunk_callback_ptr);
  if (!callbackPtr) return null;
  const target = safeReadPointer(callbackPtr);
  if (!target) return null;
  return {
    runtime: target.toString(),
    static: runtimeToStatic(target),
    symbol: safeSymbol(target),
    module_offset: moduleOffset(target),
  };
}

function collectPointerCandidates(context) {
  const esp = context.esp;
  const stackArg0 = esp ? safeReadPointer(esp.add(4)) : null;
  const stackArg1 = esp ? safeReadPointer(esp.add(8)) : null;
  const stackArg2 = esp ? safeReadPointer(esp.add(12)) : null;
  const out = [
    { source: "stack_arg0", ptr: stackArg0 },
    { source: "stack_arg1", ptr: stackArg1 },
    { source: "stack_arg2", ptr: stackArg2 },
    { source: "eax", ptr: context.eax || null },
    { source: "ecx", ptr: context.ecx || null },
    { source: "edx", ptr: context.edx || null },
  ];
  return out;
}

function sampleCandidates(candidates) {
  const out = [];
  for (let i = 0; i < candidates.length; i++) {
    const entry = candidates[i];
    const p = entry.ptr;
    if (!p || p.isNull()) continue;
    const vec = sampleVec2(p);
    out.push({
      source: entry.source,
      ptr: p.toString(),
      static: runtimeToStatic(p),
      module_offset: moduleOffset(p),
      vec2: vec,
    });
  }
  return out;
}

function main() {
  initLog();
  const thunkPtr = staticToRuntime(ADDR.thunk_452f1d);
  if (!thunkPtr) {
    writeLog({ event: "error", ts: nowIso(), reason: "thunk_address_unresolved" });
    return;
  }

  writeLog({
    event: "start",
    ts: nowIso(),
    log_path: CONFIG.logPath,
    thunk_runtime: thunkPtr.toString(),
    thunk_static: toHex(ADDR.thunk_452f1d, 8),
    thunk_callback_ptr_static: toHex(ADDR.thunk_callback_ptr, 8),
    config: {
      max_events: CONFIG.maxEvents,
      include_backtrace: CONFIG.includeBacktrace,
      backtrace_max_frames: CONFIG.backtraceMaxFrames,
    },
  });

  Interceptor.attach(thunkPtr, {
    onEnter(args) {
      SEQ += 1;
      this.seq = SEQ;
      this.callerRuntime = this.returnAddress;
      this.callerStatic = runtimeToStatic(this.returnAddress);
      this.callerSymbol = safeSymbol(this.returnAddress);
      this.callerModuleOffset = moduleOffset(this.returnAddress);
      this.beforeState = stateSnapshot();
      this.callbackTargetBefore = readThunkCallbackTarget();
      this.candidates = collectPointerCandidates(this.context);
      this.beforeCandidates = sampleCandidates(this.candidates);
      this.backtrace = CONFIG.includeBacktrace
        ? safeBacktrace(this.context, CONFIG.backtraceMaxFrames)
        : null;
    },
    onLeave(retval) {
      const event = {
        event: "thunk_452f1d_call",
        ts: nowIso(),
        seq: this.seq,
        caller: {
          runtime: this.callerRuntime ? this.callerRuntime.toString() : null,
          static: this.callerStatic,
          symbol: this.callerSymbol,
          module_offset: this.callerModuleOffset,
        },
        ret_i32: safeInt32(retval),
        state_before: this.beforeState || null,
        state_after: stateSnapshot(),
        callback_target_before: this.callbackTargetBefore || null,
        callback_target_after: readThunkCallbackTarget(),
        pointer_candidates_before: this.beforeCandidates || [],
        pointer_candidates_after: sampleCandidates(this.candidates || []),
      };
      if (this.backtrace) event.backtrace = this.backtrace;
      writeLog(event);

      EVENT_COUNT += 1;
      if (CONFIG.maxEvents > 0 && EVENT_COUNT >= CONFIG.maxEvents) {
        writeLog({ event: "stop", ts: nowIso(), reason: "max_events", count: EVENT_COUNT });
        Interceptor.detachAll();
      }
    },
  });
}

main();
