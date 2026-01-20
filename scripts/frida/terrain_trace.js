"use strict";

const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";

const OUT_PATHS = [
    "Z:\\terrain_trace.jsonl",
];

const EXE_RVAS = {
    terrain_generate: 0x17b80,
    terrain_render: 0x188a0,
    grim_interface_ptr: 0x8083c,
};

const DATA_RVAS = {
    config_texture_scale: 0x803b8,
    config_screen_width: 0x80504,
    config_screen_height: 0x80508,
    terrain_render_target: 0x8f530,
    terrain_texture_width: 0x8f534,
    terrain_texture_height: 0x8f538,
    terrain_textures_base: 0x8f548,
    camera_offset_x: 0x84fc8,
    camera_offset_y: 0x84fcc,
};

const GRIM_RVAS = {
    get_texture_handle: 0x07740,
    bind_texture: 0x07830,
    set_uv: 0x08350,
};

const SUMMARY_INTERVAL_MS = 4000;

const texture_names = {};
const attached = {};
const outFiles = {};
let outWarned = false;
let lastBaseExe = null;
let lastBaseGrim = null;
let ifaceLogged = false;

const inTerrainRender = {};

const counts = {
    terrain_generate: 0,
    terrain_render: 0,
    set_uv: 0,
    bind_texture: 0,
    get_texture_handle: 0,
    iface_set_uv: 0,
    iface_bind_texture: 0,
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
            } catch (e) {}
        }
    } catch (e) {}

    if (!wrote && !outWarned) {
        outWarned = true;
        console.log("terrain_trace: file logging unavailable, console only");
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
        if (mod && mod.base) base = mod.base;
    } catch (e) {}
    return base;
}

function readGlobals(base) {
    const out = {};
    if (!base) return out;
    out.texture_scale = safeReadFloat(base.add(DATA_RVAS.config_texture_scale));
    out.screen_width = safeReadI32(base.add(DATA_RVAS.config_screen_width));
    out.screen_height = safeReadI32(base.add(DATA_RVAS.config_screen_height));
    out.terrain_width = safeReadI32(base.add(DATA_RVAS.terrain_texture_width));
    out.terrain_height = safeReadI32(base.add(DATA_RVAS.terrain_texture_height));
    out.terrain_render_target = safeReadI32(base.add(DATA_RVAS.terrain_render_target));
    out.camera_offset_x = safeReadFloat(base.add(DATA_RVAS.camera_offset_x));
    out.camera_offset_y = safeReadFloat(base.add(DATA_RVAS.camera_offset_y));
    return out;
}

function readTerrainHandles(base) {
    const out = [];
    if (!base) return out;
    const basePtr = base.add(DATA_RVAS.terrain_textures_base);
    for (let i = 0; i < 8; i++) {
        const handle = safeReadI32(basePtr.add(i * 4));
        if (handle === null) continue;
        const name = texture_names[String(handle)];
        out.push({ index: i, handle: handle, name: name || null });
    }
    return out;
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

function hookTerrainGenerate(addr, exeBase) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.terrain_generate += 1;
            const desc = args[0];
            const base = exeBase;
            const indices = {
                base: safeReadI32(desc.add(0x10)),
                overlay: safeReadI32(desc.add(0x14)),
                detail: safeReadI32(desc.add(0x18)),
            };
            writeLine({
                tag: "terrain_generate",
                desc: desc ? desc.toString() : null,
                indices: indices,
                globals: readGlobals(base),
                textures: readTerrainHandles(base),
            });
        },
    });
}

function hookTerrainRender(addr, exeBase) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.terrain_render += 1;
            inTerrainRender[this.threadId] = true;
            writeLine({
                tag: "terrain_render_enter",
                thread_id: this.threadId,
                globals: readGlobals(exeBase),
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
                texture_names[String(handle)] = name;
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
            const name = texture_names[String(handle)];
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
            if (!inTerrainRender[this.threadId]) return;
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
            const name = texture_names[String(handle)];
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
            if (!inTerrainRender[this.threadId]) return;
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
            });
        },
    });
}

function attachInterface(exeBase) {
    const ifacePtr = safeReadPointer(exeBase.add(EXE_RVAS.grim_interface_ptr));
    if (!ifacePtr || ifacePtr.isNull()) return;
    const bindPtr = safeReadPointer(ifacePtr.add(0xc4));
    const uvPtr = safeReadPointer(ifacePtr.add(0x100));
    if (!ifaceLogged) {
        ifaceLogged = true;
        writeLine({
            tag: "iface_ptr",
            iface: ifacePtr.toString(),
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
        attachOnce(
            "terrain_generate",
            exeBase.add(EXE_RVAS.terrain_generate),
            (addr) => hookTerrainGenerate(addr, exeBase),
        );
        attachOnce(
            "terrain_render",
            exeBase.add(EXE_RVAS.terrain_render),
            (addr) => hookTerrainRender(addr, exeBase),
        );
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
