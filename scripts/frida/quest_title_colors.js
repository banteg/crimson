"use strict";

const GRIM_MODULE = "grim.dll";
const EXE_MODULE = "crimsonland.exe";
const OUT_PATH = "Z:\\quest_title_colors.jsonl";

// grim.dll RVAs from grim_hooks_targets + decomp addresses
const GRIM_RVAS = {
    set_color: 0x07f90,
    set_color_ptr: 0x08040,
    draw_text_mono: 0x092b0,
    draw_text_mono_fmt: 0x09940,
};

const DEFAULT_COLOR = { r: 1, g: 1, b: 1, a: 1 };
let last_color = { r: DEFAULT_COLOR.r, g: DEFAULT_COLOR.g, b: DEFAULT_COLOR.b, a: DEFAULT_COLOR.a };
let outFile = null;

function openOutFile() {
    if (outFile) return;
    try {
        outFile = new File(OUT_PATH, "a");
    } catch (e) {
        outFile = null;
    }
}

function writeLine(obj) {
    const line = JSON.stringify(obj) + "\n";
    try {
        openOutFile();
        if (outFile) outFile.write(line);
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
    writeLine(msg);
}

function hookSetColor(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
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
    if (!grimBase) {
        console.log("Waiting for grim.dll...");
        setTimeout(hookByRvas, 1000);
        return;
    }

    const setColorAddr = grimBase.add(GRIM_RVAS.set_color);
    const setColorPtrAddr = grimBase.add(GRIM_RVAS.set_color_ptr);
    const drawMonoAddr = grimBase.add(GRIM_RVAS.draw_text_mono);
    const drawMonoFmtAddr = grimBase.add(GRIM_RVAS.draw_text_mono_fmt);

    console.log("grim.dll base: " + grimBase);
    console.log("hook set_color: " + setColorAddr);
    console.log("hook set_color_ptr: " + setColorPtrAddr);
    console.log("hook draw_text_mono: " + drawMonoAddr);
    console.log("hook draw_text_mono_fmt: " + drawMonoFmtAddr);

    hookSetColor(setColorAddr);
    hookSetColorPtr(setColorPtrAddr);
    hookDrawTextMono(drawMonoAddr);
    hookDrawTextMonoFmt(drawMonoFmtAddr);

    console.log("Hooks installed. Trigger quest overlay to capture title colors.");
}

hookByRvas();
