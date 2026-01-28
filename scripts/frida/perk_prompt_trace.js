"use strict";

// Trace perk prompt globals (origin/bounds/timer) and UI timeline while playing.
//
// Attach only (VM):
//   frida -n crimsonland.exe -l C:\share\frida\perk_prompt_trace.js
//
// Optional env:
//   CRIMSON_FRIDA_DIR=... (log dir; default C:\share\frida)
//   CRIMSON_PERK_PROMPT_TRACE_TICK_MS=100 (poll interval)
//   CRIMSON_PERK_PROMPT_TRACE_FORCE_MS=1000 (force snapshot log interval)
//   CRIMSON_PERK_PROMPT_TRACE_ALL=1 (log every tick)
//   CRIMSON_PERK_PROMPT_TRACE_EPS=0.0005 (float change epsilon)

const DEFAULT_LOG_DIR = "C:\\share\\frida";

function getLogDir() {
    try {
        return Process.env.CRIMSON_FRIDA_DIR || DEFAULT_LOG_DIR;
    } catch (_) {
        return DEFAULT_LOG_DIR;
    }
}

function joinPath(base, leaf) {
    if (!base) return leaf;
    const sep = base.endsWith("\\") || base.endsWith("/") ? "" : "\\";
    return base + sep + leaf;
}

function readBoolEnv(name) {
    try {
        const val = Process.env[name];
        if (!val) return false;
        return val === "1" || val.toLowerCase() === "true";
    } catch (_) {
        return false;
    }
}

function readNumberEnv(name, fallback) {
    try {
        const val = Process.env[name];
        if (!val) return fallback;
        const parsed = Number(val);
        return Number.isFinite(parsed) ? parsed : fallback;
    } catch (_) {
        return fallback;
    }
}

const LOG_DIR = getLogDir();
const OUT_PATH = joinPath(LOG_DIR, "perk_prompt_trace.jsonl");

const GAME_MODULE = "crimsonland.exe";

// RVAs derived from analysis/ghidra/maps/data_map.json (Crimsonland v1.9.93).
const DATA_RVAS = {
    perk_pending_count: 0x086fac,
    perk_prompt_origin_x: 0x08f224,
    perk_prompt_origin_y: 0x08f228,
    perk_prompt_bounds_min_x: 0x08f248,
    perk_prompt_bounds_min_y: 0x08f24c,
    perk_prompt_bounds_max_x: 0x08f280,
    perk_prompt_bounds_max_y: 0x08f284,
    perk_prompt_timer: 0x08f524,
    ui_elements_timeline: 0x087248,
    ui_transition_direction: 0x08724c,
    game_state_id: 0x087270,
    game_state_pending: 0x087274,
};

const TICK_INTERVAL_MS = readNumberEnv("CRIMSON_PERK_PROMPT_TRACE_TICK_MS", 100);
const FORCE_LOG_INTERVAL_MS = readNumberEnv("CRIMSON_PERK_PROMPT_TRACE_FORCE_MS", 1000);
const LOG_EVERY_TICK = readBoolEnv("CRIMSON_PERK_PROMPT_TRACE_ALL");
const FLOAT_EPSILON = readNumberEnv("CRIMSON_PERK_PROMPT_TRACE_EPS", 0.0005);

let outFile = null;
let outWarned = false;

let baseExe = null;
let lastSnapshot = null;
let lastLogMs = 0;

const counts = {
    tick: 0,
    snapshots: 0,
};

function nowMs() {
    return Date.now();
}

function openOutFile() {
    if (outFile !== null) return;
    try {
        outFile = new File(OUT_PATH, "a");
    } catch (_) {
        outFile = null;
    }
}

function writeLine(obj) {
    obj.ts = nowMs();
    const line = JSON.stringify(obj) + "\n";
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
        console.log("perk_prompt_trace: file logging unavailable, console only");
    }
    console.log(line.trim());
    counts.snapshots += 1;
}

function isReadable(ptrVal) {
    try {
        const range = Process.findRangeByAddress(ptrVal);
        return !!range && range.protection.indexOf("r") !== -1;
    } catch (_) {
        return false;
    }
}

function safeReadI32(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readS32();
    } catch (_) {
        return null;
    }
}

function safeReadF32(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readFloat();
    } catch (_) {
        return null;
    }
}

function resolveExeRva(rva) {
    return baseExe.add(rva);
}

function snapshot() {
    const snap = {
        tag: "perk_prompt",
        base_exe: baseExe.toString(),
        state: {
            game_state_id: safeReadI32(resolveExeRva(DATA_RVAS.game_state_id)),
            game_state_pending: safeReadI32(resolveExeRva(DATA_RVAS.game_state_pending)),
            ui_timeline: safeReadI32(resolveExeRva(DATA_RVAS.ui_elements_timeline)),
            ui_dir: safeReadI32(resolveExeRva(DATA_RVAS.ui_transition_direction)),
            perk_pending_count: safeReadI32(resolveExeRva(DATA_RVAS.perk_pending_count)),
        },
        prompt: {
            origin_x: safeReadF32(resolveExeRva(DATA_RVAS.perk_prompt_origin_x)),
            origin_y: safeReadF32(resolveExeRva(DATA_RVAS.perk_prompt_origin_y)),
            bounds_min_x: safeReadF32(resolveExeRva(DATA_RVAS.perk_prompt_bounds_min_x)),
            bounds_min_y: safeReadF32(resolveExeRva(DATA_RVAS.perk_prompt_bounds_min_y)),
            bounds_max_x: safeReadF32(resolveExeRva(DATA_RVAS.perk_prompt_bounds_max_x)),
            bounds_max_y: safeReadF32(resolveExeRva(DATA_RVAS.perk_prompt_bounds_max_y)),
            timer: safeReadI32(resolveExeRva(DATA_RVAS.perk_prompt_timer)),
        },
    };
    return snap;
}

function approxChangedFloat(a, b) {
    if (a === null || b === null) return a !== b;
    return Math.abs(a - b) > FLOAT_EPSILON;
}

function changedSnapshot(prev, next) {
    if (!prev) return true;
    const pa = prev.prompt;
    const pb = next.prompt;
    const sa = prev.state;
    const sb = next.state;

    if (sa.game_state_id !== sb.game_state_id) return true;
    if (sa.game_state_pending !== sb.game_state_pending) return true;
    if (sa.ui_timeline !== sb.ui_timeline) return true;
    if (sa.ui_dir !== sb.ui_dir) return true;
    if (sa.perk_pending_count !== sb.perk_pending_count) return true;
    if (pa.timer !== pb.timer) return true;

    if (approxChangedFloat(pa.origin_x, pb.origin_x)) return true;
    if (approxChangedFloat(pa.origin_y, pb.origin_y)) return true;
    if (approxChangedFloat(pa.bounds_min_x, pb.bounds_min_x)) return true;
    if (approxChangedFloat(pa.bounds_min_y, pb.bounds_min_y)) return true;
    if (approxChangedFloat(pa.bounds_max_x, pb.bounds_max_x)) return true;
    if (approxChangedFloat(pa.bounds_max_y, pb.bounds_max_y)) return true;

    return false;
}

function tick() {
    counts.tick += 1;

    const snap = snapshot();
    const t = nowMs();
    const shouldLog = LOG_EVERY_TICK || changedSnapshot(lastSnapshot, snap) || t - lastLogMs >= FORCE_LOG_INTERVAL_MS;
    if (shouldLog) {
        lastSnapshot = snap;
        lastLogMs = t;
        writeLine(snap);
    }
}

function start() {
    const exe = Process.findModuleByName(GAME_MODULE);
    if (!exe) {
        console.log("perk_prompt_trace: missing module", GAME_MODULE);
        return;
    }
    baseExe = exe.base;

    writeLine({
        tag: "start",
        module: GAME_MODULE,
        base_exe: baseExe.toString(),
        tick_ms: TICK_INTERVAL_MS,
        force_ms: FORCE_LOG_INTERVAL_MS,
        eps: FLOAT_EPSILON,
        log_every_tick: LOG_EVERY_TICK,
    });

    tick();
    setInterval(tick, TICK_INTERVAL_MS);
}

setImmediate(start);

