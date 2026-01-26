"use strict";

// Capture camera/terrain scaling details for diagnosing scroll/scale mismatch.
// Attach only (VM): frida -n crimsonland.exe -l C:\share\frida\camera_scale_trace.js

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

const LOG_DIR = getLogDir();
const OUT_PATHS = [joinPath(LOG_DIR, "camera_scale_trace.jsonl")];

const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";

const EXE_RVAS = {
    camera_update: 0x409500,
    terrain_render: 0x4188a0,
    grim_interface_ptr: 0x8083c,
};

const DATA_RVAS = {
    config_player_count: 0x8035c,
    config_texture_scale: 0x803b8,
    config_screen_width: 0x80504,
    config_screen_height: 0x80508,
    terrain_texture_width: 0x8f534,
    terrain_texture_height: 0x8f538,
    camera_offset_x: 0x84fc8,
    camera_offset_y: 0x84fcc,
    camera_shake_offset_x: 0x871d8,
    camera_shake_offset_y: 0x871dc,
    camera_shake_timer: 0x871e0,
    camera_shake_pulses: 0x871e4,
    render_overlay_player_index: 0xaaf0c,
    player_pos_x: 0x908c4,
    player_pos_y: 0x908c8,
};

const PLAYER_STRIDE = 0x360;

const GRIM_RVAS = {
    get_texture_handle: 0x07740,
    bind_texture: 0x07830,
    set_uv: 0x08350,
};

const SUMMARY_INTERVAL_MS = 4000;

const attached = {};
const outFiles = {};
let outWarned = false;
let lastBaseExe = null;
let lastBaseGrim = null;
let ifaceLogged = false;

const inTerrainRender = {};
const textureNames = {};

const counts = {
    camera_update: 0,
    terrain_render: 0,
    set_uv: 0,
    bind_texture: 0,
    iface_set_uv: 0,
    iface_bind_texture: 0,
    get_texture_handle: 0,
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
            } catch (_) {}
        }
    } catch (_) {}

    if (!wrote && !outWarned) {
        outWarned = true;
        console.log("camera_scale_trace: file logging unavailable, console only");
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
        } catch (_) {}
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
        if (mod && mod.base) base = mod.base;
    } catch (e) {}
    return base;
}

function readPlayerPos(exeBase, index) {
    if (!exeBase || index === null || index === undefined) return null;
    const base = exeBase.add(DATA_RVAS.player_pos_x + index * PLAYER_STRIDE);
    const x = safeReadFloat(base);
    const y = safeReadFloat(base.add(4));
    return { index: index, x: x, y: y };
}

function readGlobals(exeBase) {
    if (!exeBase) return {};
    const out = {};
    out.config_player_count = safeReadI32(exeBase.add(DATA_RVAS.config_player_count));
    out.texture_scale = safeReadFloat(exeBase.add(DATA_RVAS.config_texture_scale));
    out.screen_width = safeReadI32(exeBase.add(DATA_RVAS.config_screen_width));
    out.screen_height = safeReadI32(exeBase.add(DATA_RVAS.config_screen_height));
    out.terrain_width = safeReadI32(exeBase.add(DATA_RVAS.terrain_texture_width));
    out.terrain_height = safeReadI32(exeBase.add(DATA_RVAS.terrain_texture_height));
    out.camera_offset_x = safeReadFloat(exeBase.add(DATA_RVAS.camera_offset_x));
    out.camera_offset_y = safeReadFloat(exeBase.add(DATA_RVAS.camera_offset_y));
    out.camera_shake_offset_x = safeReadFloat(exeBase.add(DATA_RVAS.camera_shake_offset_x));
    out.camera_shake_offset_y = safeReadFloat(exeBase.add(DATA_RVAS.camera_shake_offset_y));
    out.camera_shake_timer = safeReadFloat(exeBase.add(DATA_RVAS.camera_shake_timer));
    out.camera_shake_pulses = safeReadI32(exeBase.add(DATA_RVAS.camera_shake_pulses));
    out.render_overlay_player_index = safeReadI32(exeBase.add(DATA_RVAS.render_overlay_player_index));
    out.player0 = readPlayerPos(exeBase, 0);
    out.player1 = readPlayerPos(exeBase, 1);
    return out;
}

function computeTerrainUv(globals) {
    if (!globals) return null;
    const w = globals.terrain_width;
    const h = globals.terrain_height;
    const sw = globals.screen_width;
    const sh = globals.screen_height;
    const ox = globals.camera_offset_x;
    const oy = globals.camera_offset_y;
    if (w === null || h === null || sw === null || sh === null || ox === null || oy === null) return null;
    if (w === 0 || h === 0) return null;
    const u0 = -ox / w;
    const v0 = -oy / h;
    const u1 = u0 + sw / w;
    const v1 = v0 + sh / h;
    return { u0: u0, v0: v0, u1: u1, v1: v1 };
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

function hookCameraUpdate(addr, exeBase) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.camera_update += 1;
            this.__pre = readGlobals(exeBase);
        },
        onLeave: function() {
            const post = readGlobals(exeBase);
            const uv = computeTerrainUv(post);
            writeLine({
                tag: "camera_update",
                pre: this.__pre || null,
                post: post,
                uv_pred: uv,
            });
        },
    });
}

function hookTerrainRender(addr, exeBase) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.terrain_render += 1;
            const globals = readGlobals(exeBase);
            inTerrainRender[this.threadId] = globals;
            writeLine({
                tag: "terrain_render_enter",
                thread_id: this.threadId,
                globals: globals,
                uv_pred: computeTerrainUv(globals),
            });
        },
        onLeave: function() {
            writeLine({
                tag: "terrain_render_exit",
                thread_id: this.threadId,
            });
            delete inTerrainRender[this.threadId];
        },
    });
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
                textureNames[String(handle)] = name;
                writeLine({ tag: "texture_handle", name: name, handle: handle });
            }
        },
    });
}

function hookBindTexture(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.bind_texture += 1;
            if (!inTerrainRender[this.threadId]) return;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const handle = safeReadI32(sp.add(4));
            const stage = safeReadI32(sp.add(8));
            const name = textureNames[String(handle)];
            writeLine({
                tag: "bind_texture",
                thread_id: this.threadId,
                handle: handle,
                stage: stage,
                name: name || null,
            });
        },
    });
}

function hookSetUv(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.set_uv += 1;
            const globals = inTerrainRender[this.threadId];
            if (!globals) return;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const u0 = safeReadFloat(sp.add(4));
            const v0 = safeReadFloat(sp.add(8));
            const u1 = safeReadFloat(sp.add(12));
            const v1 = safeReadFloat(sp.add(16));
            writeLine({
                tag: "terrain_uv",
                thread_id: this.threadId,
                u0: u0,
                v0: v0,
                u1: u1,
                v1: v1,
                uv_pred: computeTerrainUv(globals),
            });
        },
    });
}

function hookIfaceBindTexture(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.iface_bind_texture += 1;
            if (!inTerrainRender[this.threadId]) return;
            const handle = args[0] ? args[0].toInt32() : null;
            const stage = args[1] ? args[1].toInt32() : null;
            const name = textureNames[String(handle)];
            writeLine({
                tag: "iface_bind_texture",
                thread_id: this.threadId,
                handle: handle,
                stage: stage,
                name: name || null,
                ecx: this.context.ecx !== undefined ? this.context.ecx.toString() : null,
            });
        },
    });
}

function hookIfaceSetUv(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.iface_set_uv += 1;
            const globals = inTerrainRender[this.threadId];
            if (!globals) return;
            const sp = getStackPointer(this.context);
            if (sp === null) return;
            const u0 = safeReadFloat(sp.add(4));
            const v0 = safeReadFloat(sp.add(8));
            const u1 = safeReadFloat(sp.add(12));
            const v1 = safeReadFloat(sp.add(16));
            writeLine({
                tag: "iface_set_uv",
                thread_id: this.threadId,
                u0: u0,
                v0: v0,
                u1: u1,
                v1: v1,
                uv_pred: computeTerrainUv(globals),
            });
        },
    });
}

function attachInterface(exeBase) {
    const ifacePtr = safeReadPointer(exeBase.add(EXE_RVAS.grim_interface_ptr));
    if (!ifacePtr || ifacePtr.isNull()) return;
    const vtablePtr = safeReadPointer(ifacePtr);
    if (!vtablePtr || vtablePtr.isNull()) return;
    const bindPtr = safeReadPointer(vtablePtr.add(0xc4));
    const uvPtr = safeReadPointer(vtablePtr.add(0x100));
    if (!ifaceLogged) {
        ifaceLogged = true;
        writeLine({
            tag: "iface_ptr",
            iface: ifacePtr.toString(),
            vtable: vtablePtr.toString(),
            bind_ptr: bindPtr ? bindPtr.toString() : null,
            uv_ptr: uvPtr ? uvPtr.toString() : null,
        });
    }
    if (bindPtr && !bindPtr.isNull()) {
        attachOnce("iface_bind_texture", bindPtr, hookIfaceBindTexture);
    }
    if (uvPtr && !uvPtr.isNull()) {
        attachOnce("iface_set_uv", uvPtr, hookIfaceSetUv);
    }
}

function attachByRva(exeBase, grimBase) {
    if (exeBase) {
        attachOnce("camera_update", exeBase.add(EXE_RVAS.camera_update), (addr) => hookCameraUpdate(addr, exeBase));
        attachOnce("terrain_render", exeBase.add(EXE_RVAS.terrain_render), (addr) => hookTerrainRender(addr, exeBase));
        attachInterface(exeBase);
    }
    if (grimBase) {
        attachOnce("get_texture_handle", grimBase.add(GRIM_RVAS.get_texture_handle), hookGetTextureHandle);
        attachOnce("bind_texture", grimBase.add(GRIM_RVAS.bind_texture), hookBindTexture);
        attachOnce("set_uv", grimBase.add(GRIM_RVAS.set_uv), hookSetUv);
    }
}

function tick() {
    const exeBase = normalizePtr(findModuleBase(GAME_MODULE));
    const grimBase = normalizePtr(findModuleBase(GRIM_MODULE));
    lastBaseExe = exeBase;
    lastBaseGrim = grimBase;
    if (exeBase || grimBase) attachByRva(exeBase, grimBase);
}

writeLine({ tag: "start", arch: Process.arch, pointer_size: Process.pointerSize });
setInterval(summary, SUMMARY_INTERVAL_MS);
setInterval(tick, 500);
tick();
