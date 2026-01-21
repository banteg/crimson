"use strict";

const GRIM_MODULE = "grim.dll";
const EXE_MODULE = "crimsonland.exe";
const EXE_GRIM_INTERFACE_RVA = 0x8083c;

const OUT_PATHS = [
    "Z:\\quest_title_colors.jsonl",
];

// grim.dll RVAs (1.9.93)
const GRIM_RVAS = {
    set_config_var: 0x06580,
    set_color: 0x07f90,
    set_color_ptr: 0x08040,
    draw_text_mono: 0x092b0,
    draw_text_mono_fmt: 0x09940,
};

const LOG_ALL_TEXT = true; // set false to reduce spam
const LOG_FIRST_N = 12;
const SUMMARY_INTERVAL_MS = 4000;

const DEFAULT_COLOR = { r: 1, g: 1, b: 1, a: 1 };
let last_color = { r: DEFAULT_COLOR.r, g: DEFAULT_COLOR.g, b: DEFAULT_COLOR.b, a: DEFAULT_COLOR.a };
let last_scale = null;
let logged_first = 0;

const counts = {
    set_config_var: 0,
    set_color: 0,
    set_color_ptr: 0,
    draw_text_mono: 0,
    draw_text_mono_fmt: 0,
};

const attached = {};
let lastBases = { grim: null, exe: null };
const outFiles = {};
let outWarned = false;

function nowMs() {
    return Date.now();
}

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
            } catch (e) {}
        }
    } catch (e) {}

    if (!wrote && !outWarned) {
        outWarned = true;
        console.log("quest_title_colors: file logging unavailable, console only");
    }
    console.log(line.trim());
}

function summary() {
    writeLine({
        tag: "summary",
        counts: counts,
        last_color: last_color,
        last_scale: last_scale,
        grim_base: lastBases.grim,
        exe_base: lastBases.exe,
    });
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
        return ptrVal.readFloat();
    } catch (e) {
        return null;
    }
}

function safeReadI32(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readS32();
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
    if (LOG_FIRST_N > 0 && logged_first < LOG_FIRST_N) return true;
    if (text.indexOf("Land Hostile") !== -1) return true;
    if (/^\d+\.\d+$/.test(text)) return true;
    return false;
}

function bumpFirst() {
    if (LOG_FIRST_N > 0 && logged_first < LOG_FIRST_N) {
        logged_first += 1;
    }
}

function attachOnce(name, addr, hookFn) {
    if (!addr || addr.isNull()) return;
    const key = name + ":" + addr.toString();
    if (attached[key]) return;
    attached[key] = true;
    try {
        hookFn(addr);
        writeLine({ tag: "attach", name: name, addr: addr.toString() });
    } catch (e) {
        writeLine({ tag: "attach_error", name: name, addr: addr.toString(), err: String(e) });
    }
}

function hookSetConfigVar(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.set_config_var += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const state = safeReadI32(sp.add(4));
            const value = safeReadI32(sp.add(8));
            if (state === null || value === null) return;
            if (state === 0x18) {
                const asFloat = safeReadFloat(sp.add(8));
                last_scale = asFloat;
                writeLine({ tag: "config_var", state: state, value: value, as_float: asFloat });
            }
        },
    });
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
            const ptrVal = sp.add(4).readPointer();
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
            const textPtr = sp.add(12).readPointer();
            const text = safeReadCString(textPtr, 256);
            if (!shouldLogText(text)) return;
            bumpFirst();
            writeLine({
                tag: "draw_text_mono",
                text: text,
                x: x,
                y: y,
                color: last_color,
                scale: last_scale,
                ret: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function hookDrawTextMonoFmt(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.draw_text_mono_fmt += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const x = safeReadFloat(sp.add(4));
            const y = safeReadFloat(sp.add(8));
            const fmtPtr = sp.add(12).readPointer();
            const fmt = safeReadCString(fmtPtr, 64);
            const a0 = safeReadI32(sp.add(16));
            const a1 = safeReadI32(sp.add(20));
            const text = fmt && fmt.indexOf("%d") !== -1 && a0 !== null && a1 !== null
                ? (a0 + "." + a1)
                : null;
            if (!shouldLogText(text || fmt)) return;
            bumpFirst();
            writeLine({
                tag: "draw_text_mono_fmt",
                fmt: fmt,
                text: text,
                args: [a0, a1],
                x: x,
                y: y,
                color: last_color,
                scale: last_scale,
                ret: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function findModuleBase(name) {
    let base = null;
    try {
        const mod = Process.findModuleByName(name);
        if (mod && mod.base) {
            base = mod.base;
        }
    } catch (e) {
        base = null;
    }
    if (base) return base;
    const lower = name.toLowerCase();
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
        const m = mods[i];
        const modName = (m.name || "").toLowerCase();
        if (modName === lower || modName.indexOf(lower) !== -1) {
            return m.base;
        }
        const path = (m.path || "").toLowerCase();
        if (path.indexOf(lower) !== -1) {
            return m.base;
        }
    }
    return null;
}

function normalizePtr(value) {
    if (value === null || value === undefined) return null;
    if (value.add && typeof value.add === "function") return value;
    if (typeof value === "string" || typeof value === "number") {
        try {
            return ptr(value);
        } catch (e) {
            return null;
        }
    }
    try {
        if (value.toString) return ptr(value.toString());
    } catch (e) {}
    return null;
}

function attachByRva() {
    const grimBase = normalizePtr(findModuleBase(GRIM_MODULE));
    if (!grimBase) return false;

    attachOnce("set_config_var", grimBase.add(GRIM_RVAS.set_config_var), hookSetConfigVar);
    attachOnce("set_color", grimBase.add(GRIM_RVAS.set_color), hookSetColor);
    attachOnce("set_color_ptr", grimBase.add(GRIM_RVAS.set_color_ptr), hookSetColorPtr);
    attachOnce("draw_text_mono", grimBase.add(GRIM_RVAS.draw_text_mono), hookDrawTextMono);
    attachOnce("draw_text_mono_fmt", grimBase.add(GRIM_RVAS.draw_text_mono_fmt), hookDrawTextMonoFmt);

    return true;
}

function attachByVtable() {
    const exeBase = normalizePtr(findModuleBase(EXE_MODULE));
    if (!exeBase) return false;
    const ifacePtrAddr = exeBase.add(EXE_GRIM_INTERFACE_RVA);
    let iface = null;
    try {
        iface = ifacePtrAddr.readPointer();
    } catch (e) {
        return false;
    }
    if (!iface || iface.isNull()) return false;

    let vtable = null;
    try {
        vtable = iface.readPointer();
    } catch (e) {
        return false;
    }
    if (!vtable || vtable.isNull()) return false;

    attachOnce("set_config_var(vtable)", vtable.add(0x20).readPointer(), hookSetConfigVar);
    attachOnce("set_color(vtable)", vtable.add(0x114).readPointer(), hookSetColor);
    attachOnce("set_color_ptr(vtable)", vtable.add(0x110).readPointer(), hookSetColorPtr);
    attachOnce("draw_text_mono(vtable)", vtable.add(0x13c).readPointer(), hookDrawTextMono);
    attachOnce("draw_text_mono_fmt(vtable)", vtable.add(0x140).readPointer(), hookDrawTextMonoFmt);

    return true;
}

function tick() {
    const grimBase = normalizePtr(findModuleBase(GRIM_MODULE));
    const exeBase = normalizePtr(findModuleBase(EXE_MODULE));
    lastBases.grim = grimBase ? grimBase.toString() : null;
    lastBases.exe = exeBase ? exeBase.toString() : null;
    if (grimBase) attachByRva();
    if (exeBase) attachByVtable();
}

writeLine({ tag: "start", arch: Process.arch, pointer_size: Process.pointerSize });
setInterval(summary, SUMMARY_INTERVAL_MS);
setInterval(tick, 1000);

tick();
