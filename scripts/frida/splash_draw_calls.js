"use strict";

const GRIM_MODULE = "grim.dll";

const OUT_PATHS = [
    "Z:\\splash_draw_calls.jsonl",
];

const GRIM_RVAS = {
    get_texture_handle: 0x07740,
    load_texture: 0x076E0,
    bind_texture: 0x07830,
    set_config_var: 0x06580,
    set_color: 0x07f90,
    set_color_ptr: 0x08040,
    set_uv: 0x08350,
    set_uv_point: 0x083a0,
    draw_quad: 0x08b10,
    draw_quad_xy: 0x08720,
    draw_quad_rotated_matrix: 0x08750,
    flush_batch: 0x083c0,
};

const SPLASH_TEXTURES = {
    backplasma: true,
    cl_logo: true,
    loading: true,
    logo_esrb: true,
    mockup: true,
};

const MAX_FRAMES = 6;
const MAX_EVENTS = 4000;
const SUMMARY_INTERVAL_MS = 4000;
const LOG_ONLY_SPLASH_TEXTURES = false;

const DEFAULT_COLOR = { r: 1, g: 1, b: 1, a: 1 };
let last_color = { r: DEFAULT_COLOR.r, g: DEFAULT_COLOR.g, b: DEFAULT_COLOR.b, a: DEFAULT_COLOR.a };
let last_uv = null;
let last_uv_points = {};
let last_scale = null;
let last_texture = null;
let last_texture_stage = null;

let frame_index = 0;
let event_count = 0;

const counts = {
    get_texture_handle: 0,
    load_texture: 0,
    bind_texture: 0,
    set_config_var: 0,
    set_color: 0,
    set_color_ptr: 0,
    set_uv: 0,
    set_uv_point: 0,
    draw_quad: 0,
    draw_quad_xy: 0,
    draw_quad_rotated_matrix: 0,
    flush_batch: 0,
};

const texture_names = {};
const attached = {};
const outFiles = {};
let outWarned = false;
let lastBase = null;

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
        console.log("splash_draw_calls: file logging unavailable, console only");
    }
    console.log(line.trim());
}

function summary() {
    writeLine({
        tag: "summary",
        counts: counts,
        frame: frame_index,
        last_texture: last_texture,
        last_texture_name: texture_names[String(last_texture)] || null,
        last_color: last_color,
        last_uv: last_uv,
        last_scale: last_scale,
        base: lastBase ? lastBase.toString() : null,
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

function safeReadPointer(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readPointer();
    } catch (e) {
        return null;
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

function safeReadCString(ptrVal) {
    try {
        if (ptrVal.isNull()) return null;
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readCString();
    } catch (e) {
        try {
            if (!ptrVal.isNull() && isReadable(ptrVal)) return ptrVal.readUtf8String();
        } catch (e2) {}
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

function shouldLogTexture(name) {
    if (!name) return true;
    if (!LOG_ONLY_SPLASH_TEXTURES) return true;
    return !!SPLASH_TEXTURES[name];
}

function shouldLog() {
    if (frame_index > MAX_FRAMES) return false;
    if (event_count >= MAX_EVENTS) return false;
    return true;
}

function bumpEvent() {
    event_count += 1;
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

function hookGetTextureHandle(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.get_texture_handle += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const namePtr = safeReadPointer(sp.add(4));
            this.__tex_name = safeReadCString(namePtr);
        },
        onLeave: function(retval) {
            const name = this.__tex_name;
            const handle = retval ? retval.toInt32() : 0;
            if (name && handle) {
                texture_names[String(handle)] = name;
                if (shouldLog() && shouldLogTexture(name)) {
                    bumpEvent();
                    writeLine({
                        tag: "texture_handle",
                        name: name,
                        handle: handle,
                    });
                }
            }
        },
    });
}

function hookLoadTexture(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.load_texture += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const namePtr = safeReadPointer(sp.add(4));
            const pathPtr = safeReadPointer(sp.add(8));
            const name = safeReadCString(namePtr);
            const path = safeReadCString(pathPtr);
            if (shouldLog() && shouldLogTexture(name)) {
                bumpEvent();
                writeLine({ tag: "load_texture", name: name, path: path });
            }
        },
    });
}

function hookBindTexture(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.bind_texture += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const handle = safeReadI32(sp.add(4));
            const stage = safeReadI32(sp.add(8));
            last_texture = handle;
            last_texture_stage = stage;
            const name = texture_names[String(handle)];
            if (shouldLog() && shouldLogTexture(name)) {
                bumpEvent();
                writeLine({
                    tag: "bind_texture",
                    handle: handle,
                    name: name || null,
                    stage: stage,
                });
            }
        },
    });
}

function hookSetConfigVar(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.set_config_var += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const state = safeReadI32(sp.add(4));
            const value = safeReadI32(sp.add(8));
            if (state === 0x18) {
                const asFloat = safeReadFloat(sp.add(8));
                last_scale = asFloat;
            }
            if (shouldLog() && state === 0x18) {
                bumpEvent();
                writeLine({ tag: "config_var", state: state, value: value, as_float: last_scale });
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
            const ptrVal = safeReadPointer(sp.add(4));
            if (!ptrVal) return;
            const r = safeReadFloat(ptrVal.add(0));
            const g = safeReadFloat(ptrVal.add(4));
            const b = safeReadFloat(ptrVal.add(8));
            const a = safeReadFloat(ptrVal.add(12));
            if (r === null || g === null || b === null || a === null) return;
            last_color = { r: r, g: g, b: b, a: a };
        },
    });
}

function hookSetUv(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.set_uv += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const u0 = safeReadFloat(sp.add(4));
            const v0 = safeReadFloat(sp.add(8));
            const u1 = safeReadFloat(sp.add(12));
            const v1 = safeReadFloat(sp.add(16));
            if (u0 === null || v0 === null || u1 === null || v1 === null) return;
            last_uv = { u0: u0, v0: v0, u1: u1, v1: v1 };
        },
    });
}

function hookSetUvPoint(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.set_uv_point += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const index = safeReadI32(sp.add(4));
            const u = safeReadFloat(sp.add(8));
            const v = safeReadFloat(sp.add(12));
            if (index === null || u === null || v === null) return;
            last_uv_points[index] = { u: u, v: v };
        },
    });
}

function logDraw(tag, x, y, w, h, callsite) {
    if (!shouldLog()) return;
    const name = texture_names[String(last_texture)];
    if (!shouldLogTexture(name)) return;
    bumpEvent();
    writeLine({
        tag: tag,
        frame: frame_index,
        x: x,
        y: y,
        w: w,
        h: h,
        texture: last_texture,
        texture_name: name || null,
        texture_stage: last_texture_stage,
        color: last_color,
        uv: last_uv,
        uv_points: last_uv_points,
        scale: last_scale,
        callsite: callsite,
    });
}

function hookDrawQuad(addr, tag) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts[tag] += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const x = safeReadFloat(sp.add(4));
            const y = safeReadFloat(sp.add(8));
            const w = safeReadFloat(sp.add(12));
            const h = safeReadFloat(sp.add(16));
            logDraw(tag, x, y, w, h, this.returnAddress ? this.returnAddress.toString() : null);
        },
    });
}

function hookDrawQuadXY(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.draw_quad_xy += 1;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const xyPtr = safeReadPointer(sp.add(4));
            const w = safeReadFloat(sp.add(8));
            const h = safeReadFloat(sp.add(12));
            let x = null;
            let y = null;
            if (xyPtr) {
                x = safeReadFloat(xyPtr);
                y = safeReadFloat(xyPtr.add(4));
            }
            logDraw("draw_quad_xy", x, y, w, h, this.returnAddress ? this.returnAddress.toString() : null);
        },
    });
}

function hookFlushBatch(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.flush_batch += 1;
            if (frame_index <= MAX_FRAMES) {
                writeLine({ tag: "frame_boundary", frame: frame_index });
            }
            frame_index += 1;
        },
    });
}

function attachByRva(base) {
    attachOnce("get_texture_handle", base.add(GRIM_RVAS.get_texture_handle), hookGetTextureHandle);
    attachOnce("load_texture", base.add(GRIM_RVAS.load_texture), hookLoadTexture);
    attachOnce("bind_texture", base.add(GRIM_RVAS.bind_texture), hookBindTexture);
    attachOnce("set_config_var", base.add(GRIM_RVAS.set_config_var), hookSetConfigVar);
    attachOnce("set_color", base.add(GRIM_RVAS.set_color), hookSetColor);
    attachOnce("set_color_ptr", base.add(GRIM_RVAS.set_color_ptr), hookSetColorPtr);
    attachOnce("set_uv", base.add(GRIM_RVAS.set_uv), hookSetUv);
    attachOnce("set_uv_point", base.add(GRIM_RVAS.set_uv_point), hookSetUvPoint);
    attachOnce("draw_quad", base.add(GRIM_RVAS.draw_quad), (addr) => hookDrawQuad(addr, "draw_quad"));
    attachOnce("draw_quad_xy", base.add(GRIM_RVAS.draw_quad_xy), hookDrawQuadXY);
    attachOnce(
        "draw_quad_rotated_matrix",
        base.add(GRIM_RVAS.draw_quad_rotated_matrix),
        (addr) => hookDrawQuad(addr, "draw_quad_rotated_matrix"),
    );
    attachOnce("flush_batch", base.add(GRIM_RVAS.flush_batch), hookFlushBatch);
}

function tick() {
    const base = normalizePtr(findModuleBase(GRIM_MODULE));
    lastBase = base;
    if (base) attachByRva(base);
}

writeLine({ tag: "start", arch: Process.arch, pointer_size: Process.pointerSize });
setInterval(summary, SUMMARY_INTERVAL_MS);
setInterval(tick, 500);
tick();
