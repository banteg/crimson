"use strict";

// Trace screen fade + UI transition globals across game modes.
// Attach only (VM): frida -n crimsonland.exe -l C:\share\frida\screen_fade_trace.js
// Optional env:
//   CRIMSON_FRIDA_DIR=... (log dir)
//   CRIMSON_FADE_TRACE_TICK_MS=100 (poll interval)
//   CRIMSON_FADE_TRACE_FORCE_MS=1000 (force snapshot log interval)
//   CRIMSON_FADE_TRACE_ALL=1 (log every tick)
//   CRIMSON_FADE_TRACE_EPS=0.0005 (float change epsilon)
//   CRIMSON_FADE_TRACE_ALPHA_MIN=0.001 (min alpha to log fade draw)

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
const OUT_PATHS = [joinPath(LOG_DIR, "screen_fade_trace.jsonl")];

const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";

const EXE_RVAS = {
    ui_elements_update_and_render: 0x1a530,
    game_state_set: 0x461c0,
};

const GRIM_RVAS = {
    grim_draw_fullscreen_color: 0x079b0,
};

const DATA_RVAS = {
    config_game_mode: 0x80360,
    ui_screen_phase: 0x87234,
    render_pass_mode: 0x87240,
    ui_elements_timeline: 0x87248,
    ui_transition_direction: 0x8724c,
    screen_fade_ramp_flag: 0x8702c,
    screen_fade_alpha: 0x87264,
    game_state_prev: 0x8726c,
    game_state_id: 0x87270,
    game_state_pending: 0x87274,
    ui_transition_alpha: 0x87278,
};

const GAME_MODE_NAMES = {
    1: "survival",
    2: "rush",
    3: "quests",
    4: "typ-o-shooter",
    8: "tutorial",
};

const TICK_INTERVAL_MS = readNumberEnv("CRIMSON_FADE_TRACE_TICK_MS", 100);
const FORCE_LOG_INTERVAL_MS = readNumberEnv("CRIMSON_FADE_TRACE_FORCE_MS", 1000);
const LOG_EVERY_TICK = readBoolEnv("CRIMSON_FADE_TRACE_ALL");
const FLOAT_EPSILON = readNumberEnv("CRIMSON_FADE_TRACE_EPS", 0.0005);
const FADE_ALPHA_MIN = readNumberEnv("CRIMSON_FADE_TRACE_ALPHA_MIN", 0.001);

const attached = {};
const outFiles = {};
let outWarned = false;
let lastBaseExe = null;
let lastBaseGrim = null;

let lastSnapshot = null;
let lastLogMs = 0;
let lastFadeLogMs = 0;
let lastFade = null;

const counts = {
    tick: 0,
    ui_elements_update_and_render: 0,
    game_state_set: 0,
    grim_draw_fullscreen_color: 0,
    snapshots: 0,
    fade_draw_logged: 0,
};

const TRACKED_KEYS = [
    "fade_alpha",
    "fade_ramp",
    "ui_timeline",
    "ui_dir",
    "ui_alpha",
    "ui_phase",
    "render_pass_mode",
    "game_state_prev",
    "game_state_id",
    "game_state_pending",
    "config_game_mode",
];

const FLOAT_KEYS = {
    fade_alpha: true,
    ui_alpha: true,
};

function nowMs() {
    return Date.now();
}

function openOutFiles() {
    for (let i = 0; i < OUT_PATHS.length; i++) {
        const path = OUT_PATHS[i];
        if (outFiles[path]) continue;
        try {
            outFiles[path] = new File(path, "a");
        } catch (_) {
            outFiles[path] = null;
        }
    }
}

function writeLine(obj) {
    obj.ts = nowMs();
    const line = JSON.stringify(obj) + "\n";
    let wrote = false;

    try {
        openOutFiles();
        for (const path in outFiles) {
            const f = outFiles[path];
            if (!f) continue;
            try {
                f.write(line);
                wrote = true;
            } catch (_) {}
        }
    } catch (_) {}

    if (!wrote && !outWarned) {
        outWarned = true;
        console.log("screen_fade_trace: file logging unavailable, console only");
    }
    console.log(line.trim());
}

function summary() {
    writeLine({
        tag: "summary",
        counts: counts,
        base_exe: lastBaseExe ? lastBaseExe.toString() : null,
        base_grim: lastBaseGrim ? lastBaseGrim.toString() : null,
    });
}

function isReadable(ptrVal) {
    try {
        const range = Process.findRangeByAddress(ptrVal);
        return !!range && range.protection.indexOf("r") !== -1;
    } catch (_) {
        return false;
    }
}

function safeReadU8(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readU8();
    } catch (_) {
        return null;
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

function safeReadFloat(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readFloat();
    } catch (_) {
        return null;
    }
}

function normalizePtr(value) {
    if (value === null || value === undefined) return null;
    if (value.add && typeof value.add === "function") return value;
    if (typeof value === "string" || typeof value === "number") {
        try {
            return ptr(value);
        } catch (_) {
            return null;
        }
    }
    try {
        if (value.toString) return ptr(value.toString());
    } catch (_) {}
    return null;
}

function findModuleBase(name) {
    let base = null;
    try {
        const mod = Process.findModuleByName(name);
        if (mod && mod.base) base = mod.base;
    } catch (_) {}
    return base;
}

const floatBuf = new ArrayBuffer(4);
const floatU32 = new Uint32Array(floatBuf);
const floatF32 = new Float32Array(floatBuf);

function bitsToFloat(u32) {
    floatU32[0] = u32 >>> 0;
    return floatF32[0];
}

function readArgFloat(args, idx) {
    if (!args || args[idx] === undefined) return null;
    try {
        return bitsToFloat(args[idx].toUInt32());
    } catch (_) {
        return null;
    }
}

function valueChanged(key, prev, next) {
    if (prev === null || prev === undefined || next === null || next === undefined) {
        return prev !== next;
    }
    if (FLOAT_KEYS[key]) {
        if (!isFinite(prev) || !isFinite(next)) return prev !== next;
        return Math.abs(prev - next) > FLOAT_EPSILON;
    }
    return prev !== next;
}

function diffSnapshot(prev, cur) {
    const changes = {};
    for (let i = 0; i < TRACKED_KEYS.length; i++) {
        const key = TRACKED_KEYS[i];
        const prevVal = prev ? prev[key] : null;
        const curVal = cur ? cur[key] : null;
        if (!prev || valueChanged(key, prevVal, curVal)) {
            changes[key] = { from: prevVal, to: curVal };
        }
    }
    return changes;
}

function readSnapshot(exeBase) {
    const snapshot = {
        fade_alpha: safeReadFloat(exeBase.add(DATA_RVAS.screen_fade_alpha)),
        fade_ramp: safeReadU8(exeBase.add(DATA_RVAS.screen_fade_ramp_flag)),
        ui_timeline: safeReadI32(exeBase.add(DATA_RVAS.ui_elements_timeline)),
        ui_dir: safeReadU8(exeBase.add(DATA_RVAS.ui_transition_direction)),
        ui_alpha: safeReadFloat(exeBase.add(DATA_RVAS.ui_transition_alpha)),
        ui_phase: safeReadI32(exeBase.add(DATA_RVAS.ui_screen_phase)),
        render_pass_mode: safeReadU8(exeBase.add(DATA_RVAS.render_pass_mode)),
        game_state_prev: safeReadI32(exeBase.add(DATA_RVAS.game_state_prev)),
        game_state_id: safeReadI32(exeBase.add(DATA_RVAS.game_state_id)),
        game_state_pending: safeReadI32(exeBase.add(DATA_RVAS.game_state_pending)),
        config_game_mode: safeReadU8(exeBase.add(DATA_RVAS.config_game_mode)),
    };
    return snapshot;
}

function recordSnapshot(tag, extra, force) {
    if (!lastBaseExe) return;
    const snapshot = readSnapshot(lastBaseExe);
    const changes = diffSnapshot(lastSnapshot, snapshot);
    const now = nowMs();
    const changed = Object.keys(changes).length > 0;
    const shouldLog = force || LOG_EVERY_TICK || changed || now - lastLogMs >= FORCE_LOG_INTERVAL_MS;
    lastSnapshot = snapshot;
    if (!shouldLog) return;
    lastLogMs = now;
    counts.snapshots += 1;
    writeLine({
        tag: tag,
        mode_name: snapshot.config_game_mode === null ? null : (GAME_MODE_NAMES[snapshot.config_game_mode] || null),
        snapshot: snapshot,
        changes: changed ? changes : null,
        extra: extra || null,
    });
}

function maybeLogFadeDraw(r, g, b, a) {
    if (a === null || a === undefined) return;
    if (Math.abs(a) < FADE_ALPHA_MIN) return;
    const now = nowMs();
    let changed = true;
    if (lastFade) {
        const dr = r !== null ? Math.abs(r - lastFade.r) : 0;
        const dg = g !== null ? Math.abs(g - lastFade.g) : 0;
        const db = b !== null ? Math.abs(b - lastFade.b) : 0;
        const da = a !== null ? Math.abs(a - lastFade.a) : 0;
        changed = dr > FLOAT_EPSILON || dg > FLOAT_EPSILON || db > FLOAT_EPSILON || da > FLOAT_EPSILON;
    }
    if (!changed && now - lastFadeLogMs < FORCE_LOG_INTERVAL_MS) return;
    lastFade = { r: r, g: g, b: b, a: a };
    lastFadeLogMs = now;
    counts.fade_draw_logged += 1;
    const snapshot = lastBaseExe ? readSnapshot(lastBaseExe) : null;
    writeLine({
        tag: "fade_draw",
        rgba: { r: r, g: g, b: b, a: a },
        mode_name: snapshot && snapshot.config_game_mode !== null ? (GAME_MODE_NAMES[snapshot.config_game_mode] || null) : null,
        snapshot: snapshot,
    });
}

function hookUiElementsUpdateAndRender(addr) {
    Interceptor.attach(addr, {
        onLeave: function () {
            counts.ui_elements_update_and_render += 1;
            recordSnapshot("ui_elements_update_and_render", { source: "ui_elements_update_and_render" }, false);
        },
    });
}

function hookGameStateSet(addr) {
    Interceptor.attach(addr, {
        onEnter: function (args) {
            counts.game_state_set += 1;
            const a0 = args[0] ? args[0].toInt32() : null;
            const a1 = args[1] ? args[1].toInt32() : null;
            const a2 = args[2] ? args[2].toInt32() : null;
            const a3 = args[3] ? args[3].toInt32() : null;
            let caller = null;
            try {
                caller = DebugSymbol.fromAddress(this.returnAddress).toString();
            } catch (_) {}
            recordSnapshot(
                "game_state_set",
                { args: [a0, a1, a2, a3], caller: caller },
                true,
            );
        },
    });
}

function hookGrimDrawFullscreenColor(addr) {
    Interceptor.attach(addr, {
        onEnter: function (args) {
            counts.grim_draw_fullscreen_color += 1;
            const r = readArgFloat(args, 0);
            const g = readArgFloat(args, 1);
            const b = readArgFloat(args, 2);
            const a = readArgFloat(args, 3);
            maybeLogFadeDraw(r, g, b, a);
        },
    });
}

function attachOnce(key, addr, hookFn) {
    if (attached[key]) return;
    attached[key] = true;
    try {
        hookFn(addr);
        writeLine({ tag: "attach", name: key, addr: addr.toString() });
    } catch (e) {
        writeLine({ tag: "attach_error", name: key, addr: addr.toString(), err: String(e) });
    }
}

function attachByRva(exeBase, grimBase) {
    if (exeBase) {
        attachOnce(
            "ui_elements_update_and_render",
            exeBase.add(EXE_RVAS.ui_elements_update_and_render),
            hookUiElementsUpdateAndRender,
        );
        attachOnce("game_state_set", exeBase.add(EXE_RVAS.game_state_set), hookGameStateSet);
    }
    if (grimBase) {
        attachOnce(
            "grim_draw_fullscreen_color",
            grimBase.add(GRIM_RVAS.grim_draw_fullscreen_color),
            hookGrimDrawFullscreenColor,
        );
    }
}

function tick() {
    counts.tick += 1;
    const exeBase = normalizePtr(findModuleBase(GAME_MODULE));
    const grimBase = normalizePtr(findModuleBase(GRIM_MODULE));
    lastBaseExe = exeBase;
    lastBaseGrim = grimBase;
    attachByRva(exeBase, grimBase);
    recordSnapshot("tick", { source: "timer" }, false);
}

writeLine({
    tag: "start",
    arch: Process.arch,
    pointer_size: Process.pointerSize,
    log_dir: LOG_DIR,
});
setInterval(summary, 4000);
setInterval(tick, TICK_INTERVAL_MS);
tick();
