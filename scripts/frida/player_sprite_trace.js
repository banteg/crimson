"use strict";

// Capture trooper sprite UV indices during player_render_overlays.
// Attach only (VM): frida -n crimsonland.exe -l C:\share\frida\player_sprite_trace.js

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
const OUT_PATHS = [joinPath(LOG_DIR, "player_sprite_trace.jsonl")];

const EXE_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";

const EXE_RVAS = {
    player_render_overlays: 0x28390,
};

const DATA_RVAS = {
    render_overlay_player_index: 0xaaf0c,
};

const GRIM_RVAS = {
    get_texture_handle: 0x07740,
    bind_texture: 0x07830,
    set_uv: 0x08350,
    set_rotation: 0x07f30,
    draw_quad: 0x08b10,
};

const attached = {};
const outFiles = {};
let outWarned = false;

const state = {
    textureStage: {},
    trooperHandle: null,
    currentUv: null,
    currentRotation: null,
};

const inPlayerRender = {};
const drawSeq = {};

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
        console.log("player_sprite_trace: file logging unavailable, console only");
    }
    console.log(line.trim());
}

function resolvePtr(moduleName, rva) {
    try {
        const mod = Process.getModuleByName(moduleName);
        return mod.base.add(ptr(rva));
    } catch (_) {
        return null;
    }
}

function safeReadS32(ptrVal) {
    try {
        return ptrVal.readS32();
    } catch (_) {
        return null;
    }
}

function uvIndex8(u0, v0) {
    if (u0 == null || v0 == null) return null;
    const step = 1.0 / 8.0;
    const eps = 1e-4;
    const col = Math.floor((u0 + eps) / step);
    const row = Math.floor((v0 + eps) / step);
    if (col < 0 || col > 7 || row < 0 || row > 7) return null;
    return row * 8 + col;
}

function inPlayer(tid) {
    return !!inPlayerRender[tid];
}

function currentTexture() {
    const handle = state.textureStage[0];
    if (handle == null) return null;
    return handle;
}

function handleNameMatch(name) {
    if (!name) return false;
    const lower = name.toLowerCase();
    return lower.includes("trooper");
}

function main() {
    const exeBase = Process.findModuleByName(EXE_MODULE);
    const grimBase = Process.findModuleByName(GRIM_MODULE);
    if (!exeBase || !grimBase) {
        writeLine({
            tag: "error",
            error: "missing_module",
            exe: !!exeBase,
            grim: !!grimBase,
        });
        return;
    }

    const playerRender = resolvePtr(EXE_MODULE, EXE_RVAS.player_render_overlays);
    const renderIndexPtr = resolvePtr(EXE_MODULE, DATA_RVAS.render_overlay_player_index);
    const getTextureHandle = resolvePtr(GRIM_MODULE, GRIM_RVAS.get_texture_handle);
    const bindTexture = resolvePtr(GRIM_MODULE, GRIM_RVAS.bind_texture);
    const setUv = resolvePtr(GRIM_MODULE, GRIM_RVAS.set_uv);
    const setRotation = resolvePtr(GRIM_MODULE, GRIM_RVAS.set_rotation);
    const drawQuad = resolvePtr(GRIM_MODULE, GRIM_RVAS.draw_quad);

    if (!playerRender || !getTextureHandle || !bindTexture || !setUv || !setRotation || !drawQuad) {
        writeLine({
            tag: "error",
            error: "missing_function",
            player_render: !!playerRender,
            get_texture_handle: !!getTextureHandle,
            bind_texture: !!bindTexture,
            set_uv: !!setUv,
            set_rotation: !!setRotation,
            draw_quad: !!drawQuad,
        });
        return;
    }

    writeLine({
        tag: "start",
        exe_base: exeBase.base.toString(),
        grim_base: grimBase.base.toString(),
        out_path: OUT_PATHS[0],
    });

    if (!attached.player_render_overlays) {
        Interceptor.attach(playerRender, {
            onEnter() {
                inPlayerRender[this.threadId] = true;
                drawSeq[this.threadId] = 0;
            },
            onLeave() {
                delete inPlayerRender[this.threadId];
                delete drawSeq[this.threadId];
            },
        });
        attached.player_render_overlays = true;
    }

    if (!attached.get_texture_handle) {
        Interceptor.attach(getTextureHandle, {
            onEnter(args) {
                this.name = args[0].readCString();
            },
            onLeave(retval) {
                if (!this.name) return;
                if (handleNameMatch(this.name)) {
                    state.trooperHandle = retval.toInt32();
                    writeLine({
                        tag: "texture_handle",
                        name: this.name,
                        handle: state.trooperHandle,
                    });
                }
            },
        });
        attached.get_texture_handle = true;
    }

    if (!attached.bind_texture) {
        Interceptor.attach(bindTexture, {
            onEnter(args) {
                const handle = args[0].toInt32();
                const stage = args[1].toInt32();
                state.textureStage[stage] = handle;
            },
        });
        attached.bind_texture = true;
    }

    if (!attached.set_uv) {
        Interceptor.attach(setUv, {
            onEnter(args) {
                state.currentUv = {
                    u0: args[0].readFloat(),
                    v0: args[1].readFloat(),
                    u1: args[2].readFloat(),
                    v1: args[3].readFloat(),
                };
                const tid = this.threadId;
                if (!inPlayer(tid)) return;
                const handle = currentTexture();
                if (handle == null || state.trooperHandle == null || handle !== state.trooperHandle) return;
                const idx = uvIndex8(state.currentUv.u0, state.currentUv.v0);
                writeLine({
                    tag: "set_uv",
                    thread: tid,
                    uv: state.currentUv,
                    uv_index: idx,
                });
            },
        });
        attached.set_uv = true;
    }

    if (!attached.set_rotation) {
        Interceptor.attach(setRotation, {
            onEnter(args) {
                state.currentRotation = args[0].readFloat();
            },
        });
        attached.set_rotation = true;
    }

    if (!attached.draw_quad) {
        Interceptor.attach(drawQuad, {
            onEnter(args) {
                const tid = this.threadId;
                if (!inPlayer(tid)) return;
                const handle = currentTexture();
                if (handle == null || state.trooperHandle == null || handle !== state.trooperHandle) return;
                const seq = (drawSeq[tid] || 0) + 1;
                drawSeq[tid] = seq;
                const idx = state.currentUv ? uvIndex8(state.currentUv.u0, state.currentUv.v0) : null;
                const overlayIndex = renderIndexPtr ? safeReadS32(renderIndexPtr) : null;
                writeLine({
                    tag: "draw",
                    thread: tid,
                    seq: seq,
                    player_index: overlayIndex,
                    uv: state.currentUv,
                    uv_index: idx,
                    rotation: state.currentRotation,
                    quad: {
                        x: args[0].readFloat(),
                        y: args[1].readFloat(),
                        w: args[2].readFloat(),
                        h: args[3].readFloat(),
                    },
                });
            },
        });
        attached.draw_quad = true;
    }
}

setImmediate(main);
