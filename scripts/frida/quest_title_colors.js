"use strict";

const GRIM_MODULE = "grim.dll";
const EXE_MODULE = "crimsonland.exe";
const OUT_PATHS = [
    "Z:\\quest_title_colors.jsonl",
    "C:\\Temp\\quest_title_colors.jsonl",
];
const EXE_GRIM_INTERFACE_RVA = 0x8083c;

const LOG_ALL_TEXT = false;
const LOG_FIRST_N = 8;
const SUMMARY_INTERVAL_MS = 4000;

// grim.dll RVAs from grim_hooks_targets + decomp addresses
const GRIM_RVAS = {
    set_color: 0x07f90,
    set_color_ptr: 0x08040,
    draw_text_mono: 0x092b0,
    draw_text_mono_fmt: 0x09940,
};

const DEFAULT_COLOR = { r: 1, g: 1, b: 1, a: 1 };
let last_color = { r: DEFAULT_COLOR.r, g: DEFAULT_COLOR.g, b: DEFAULT_COLOR.b, a: DEFAULT_COLOR.a };
const outFiles = {};
let outWarned = false;
let loggedFirst = 0;
const counts = {
    set_color: 0,
    set_color_ptr: 0,
    draw_text_mono: 0,
    draw_text_mono_fmt: 0,
};
const attached = {};

function openOutFiles() {
    for (let i = 0; i < OUT_PATHS.length; i++) {
        const path = OUT_PATHS[i];
        if (outFiles[path]) continue;
        try {
            outFiles[path] = new File(path, "a");
        } catch (e) {
            outFiles[path] = null;
        }
    }
}

function writeLine(obj) {
    const line = JSON.stringify(obj) + "\n";
    try {
        openOutFiles();
        let wrote = false;
        for (const path in outFiles) {
            const f = outFiles[path];
            if (!f) continue;
            try {
                f.write(line);
                wrote = true;
            } catch (e) {}
        }
        if (!wrote && !outWarned) {
            outWarned = true;
            console.log("quest_title_colors: file logging unavailable, console only");
        }
    } catch (e) {
        // Fall back to console only.
    }
    console.log(line.trim());
}

function getStackPointer(ctx) {
    if (ctx.esp !== undefined) return ctx.esp;
    if (ctx.sp !== undefined) return ctx.sp;
    return null;
}

function isReadable(ptrVal) {
    try {
        const range = Process.findRangeByAddress(ptrVal);
        return !!range && range.protection.indexOf("r") !== -1;
    } catch (e) {
        return false;
    }
}

function safeReadFloat(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return Memory.readFloat(ptrVal);
    } catch (e) {
        return null;
    }
}

function safeReadCString(ptrVal, maxLen) {
    try {
        if (ptrVal.isNull()) return null;
        if (!isReadable(ptrVal)) return null;
        if (maxLen !== undefined) return ptrVal.readCString(maxLen);
        return ptrVal.readCString();
    } catch (e) {
        try {
            if (!ptrVal.isNull() && isReadable(ptrVal)) return ptrVal.readUtf8String();
        } catch (e2) {}
    }
    return null;
}

function shouldLogText(text) {
    if (!text) return false;
    if (LOG_ALL_TEXT) return true;
    if (LOG_FIRST_N > 0 && loggedFirst < LOG_FIRST_N) return true;
    if (text.indexOf("Land Hostile") !== -1) return true;
    if (/^\d+\.\d+$/.test(text)) return true;
    return false;
}

function logDraw(tag, text, x, y) {
    const msg = {
        tag: tag,
        text: text,
        color: last_color,
    };
    if (x !== null && x !== undefined) msg.x = x;
    if (y !== null && y !== undefined) msg.y = y;
    msg.ts = Date.now();
    if (LOG_FIRST_N > 0 && loggedFirst < LOG_FIRST_N) loggedFirst += 1;
    writeLine(msg);
}

function hookSetColor(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.set_color += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const r = safeReadFloat(sp.add(4));
            const g = safeReadFloat(sp.add(8));
            const b = safeReadFloat(sp.add(12));
            const a = safeReadFloat(sp.add(16));
            if (r === null || g === null || b === null || a === null) return;
            last_color = { r: r, g: g, b: b, a: a };
        },
    });
}

function hookSetColorPtr(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.set_color_ptr += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const ptrVal = Memory.readPointer(sp.add(4));
            if (ptrVal.isNull()) return;
            const r = safeReadFloat(ptrVal.add(0));
            const g = safeReadFloat(ptrVal.add(4));
            const b = safeReadFloat(ptrVal.add(8));
            const a = safeReadFloat(ptrVal.add(12));
            if (r === null || g === null || b === null || a === null) return;
            last_color = { r: r, g: g, b: b, a: a };
        },
    });
}

function hookDrawTextMono(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.draw_text_mono += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const x = safeReadFloat(sp.add(4));
            const y = safeReadFloat(sp.add(8));
            const textPtr = Memory.readPointer(sp.add(12));
            const text = safeReadCString(textPtr, 256);
            if (!shouldLogText(text)) return;
            logDraw("draw_text_mono", text, x, y);
        },
    });
}

function hookDrawTextMonoFmt(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.draw_text_mono_fmt += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const textPtr = Memory.readPointer(sp.add(12));
            const fmt = safeReadCString(textPtr, 64);
            if (!fmt) return;
            if (fmt.indexOf("%d.%d") === -1 && fmt.indexOf("%d.%d%c") === -1) return;
            logDraw("draw_text_mono_fmt", fmt, null, null);
        },
    });
}

function hookByRvas() {
    const grimBase = Module.findBaseAddress(GRIM_MODULE);
    const exeBase = Module.findBaseAddress(EXE_MODULE);

    if (!grimBase) {
        console.log("Waiting for grim.dll...");
        setTimeout(hookByRvas, 1000);
        return;
    }

    const tryAttach = function(name, addr, hookFn) {
        if (!addr || addr.isNull()) return;
        const key = name + ":" + addr.toString();
        if (attached[key]) return;
        attached[key] = true;
        hookFn(addr);
        console.log("hook " + name + ": " + addr);
    };

    console.log("grim.dll base: " + grimBase);
    tryAttach("set_color", grimBase.add(GRIM_RVAS.set_color), hookSetColor);
    tryAttach("set_color_ptr", grimBase.add(GRIM_RVAS.set_color_ptr), hookSetColorPtr);
    tryAttach("draw_text_mono", grimBase.add(GRIM_RVAS.draw_text_mono), hookDrawTextMono);
    tryAttach("draw_text_mono_fmt", grimBase.add(GRIM_RVAS.draw_text_mono_fmt), hookDrawTextMonoFmt);

    if (exeBase) {
        const ifacePtrAddr = exeBase.add(EXE_GRIM_INTERFACE_RVA);
        try {
            const iface = Memory.readPointer(ifacePtrAddr);
            if (!iface.isNull()) {
                const vtable = Memory.readPointer(iface);
                tryAttach("set_color(vtable)", Memory.readPointer(vtable.add(0x114)), hookSetColor);
                tryAttach("set_color_ptr(vtable)", Memory.readPointer(vtable.add(0x110)), hookSetColorPtr);
                tryAttach("draw_text_mono(vtable)", Memory.readPointer(vtable.add(0x13c)), hookDrawTextMono);
                tryAttach("draw_text_mono_fmt(vtable)", Memory.readPointer(vtable.add(0x140)), hookDrawTextMonoFmt);
            }
        } catch (e) {
            // Ignore and rely on RVAs.
        }
    }

    console.log("Hooks installed. Trigger quest overlay to capture title colors.");
}

setInterval(function() {
    writeLine({
        tag: "summary",
        ts: Date.now(),
        counts: counts,
        last_color: last_color,
    });
}, SUMMARY_INTERVAL_MS);

hookByRvas();
