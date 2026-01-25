"use strict";

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

const LOG_DIR = getLogDir();
const OUT_PATHS = [joinPath(LOG_DIR, "options_panel_trace.jsonl")];

const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";

const UI_ELEMENT_TABLE_COUNT = 41;

const EXE_RVAS = {
    ui_element_set_rect: 0x419ba0,
    ui_element_load: 0x419d00,
    ui_element_render: 0x46c40,
    ui_element_update: 0x46900,
    ui_elements_update_and_render: 0x1a530,
    ui_menu_main_click_options: 0x47370,
    options_update: 0x4475d0,
};

const DATA_RVAS = {
    ui_elements_timeline: 0x87248,
    ui_transition_direction: 0x8724c,
    game_state_id: 0x87270,
    game_state_pending: 0x87274,
    ui_element_table_base: 0x8f168,
    config_fx_detail_flag0: 0x480356,
    config_screen_width: 0x480504,
    config_screen_height: 0x480508,
    screen_width_f: 0x471140,
    options_panel_elem: 0x488b50,
};

const GRIM_RVAS = {
    bind_texture: 0x07830,
    set_color: 0x07f90,
    set_color_ptr: 0x08040,
    draw_quad_xy: 0x08720,
    draw_quad: 0x08b10,
    draw_rect_outline: 0x08f10,
    draw_quad_points: 0x09080,
};

const UI_OFFSETS = {
    enable: 0x0,
    clicked: 0x1,
    update_disabled: 0x2,
    render_mode: 0x4,
    slide_x: 0x8,
    start_time_ms: 0x10,
    end_time_ms: 0x14,
    pos_x: 0x18,
    pos_y: 0x1c,
    quad0_x: 0x3c,
    quad0_y: 0x40,
    quad2_x: 0x44,
    quad2_y: 0x48,
    field_0x34: 0x34,
};

const OPTIONS_STATE_IDS = { 2: true };

const LOG_ALL_UI_RENDERS = true;
const LOG_ALL_UI_DRAWS = true;

const SUMMARY_INTERVAL_MS = 4000;
const RENDER_LOG_THROTTLE_MS = 350;
const OPTIONS_LOG_THROTTLE_MS = 500;
const CAPTURE_WINDOW_MS = 5000;

const attached = {};
const outFiles = {};
let outWarned = false;
let lastBaseExe = null;
let lastBaseGrim = null;

let uiTablePtrToIndex = {};
const elemInfo = {};
const renderStacks = {};
const threadState = {};

let captureUntilMs = 0;
let lastOptionsLogMs = 0;
const lastRenderLogMs = {};

const counts = {
    ui_element_load: 0,
    ui_element_set_rect: 0,
    ui_element_render: 0,
    ui_elements_update_and_render: 0,
    ui_menu_main_click_options: 0,
    options_update: 0,
    grim_set_color: 0,
    grim_set_color_ptr: 0,
    grim_bind_texture: 0,
    grim_draw_quad_xy: 0,
    grim_draw_quad: 0,
    grim_draw_rect_outline: 0,
    grim_draw_quad_points: 0,
    ui_draw_logged: 0,
    ui_shadow_logged: 0,
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
        console.log("options_panel_trace: file logging unavailable, console only");
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

function safeReadPointer(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readPointer();
    } catch (_) {
        return null;
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

function safeReadUtf8(ptrVal) {
    try {
        if (!ptrVal || ptrVal.isNull()) return null;
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readUtf8String();
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

function getThreadState(tid) {
    if (!threadState[tid]) {
        threadState[tid] = {
            color: { r: null, g: null, b: null, a: null },
            texture: null,
            stage: null,
        };
    }
    return threadState[tid];
}

function uiIndexOf(elemPtr) {
    if (!elemPtr || elemPtr.isNull()) return -1;
    const key = elemPtr.toString();
    const idx = uiTablePtrToIndex[key];
    return idx === undefined ? -1 : idx;
}

function refreshUiTable(exeBase) {
    uiTablePtrToIndex = {};
    if (!exeBase) return;
    const tableBase = exeBase.add(DATA_RVAS.ui_element_table_base);
    for (let i = 0; i < UI_ELEMENT_TABLE_COUNT; i++) {
        const p = safeReadPointer(tableBase.add(i * 4));
        if (!p || p.isNull()) continue;
        uiTablePtrToIndex[p.toString()] = i;
    }
}

function readGlobals(exeBase) {
    const out = {};
    if (!exeBase) return out;
    out.timeline = safeReadI32(exeBase.add(DATA_RVAS.ui_elements_timeline));
    out.dir = safeReadU8(exeBase.add(DATA_RVAS.ui_transition_direction));
    out.state_id = safeReadI32(exeBase.add(DATA_RVAS.game_state_id));
    out.state_pending = safeReadI32(exeBase.add(DATA_RVAS.game_state_pending));
    out.fx_detail = safeReadU8(exeBase.add(DATA_RVAS.config_fx_detail_flag0));
    out.config_screen_width = safeReadI32(exeBase.add(DATA_RVAS.config_screen_width));
    out.config_screen_height = safeReadI32(exeBase.add(DATA_RVAS.config_screen_height));
    out.screen_width_f = safeReadFloat(exeBase.add(DATA_RVAS.screen_width_f));
    return out;
}

function readUiElementFields(elemPtr) {
    if (!elemPtr || elemPtr.isNull()) return null;
    return {
        enable: safeReadU8(elemPtr.add(UI_OFFSETS.enable)),
        clicked: safeReadU8(elemPtr.add(UI_OFFSETS.clicked)),
        update_disabled: safeReadU8(elemPtr.add(UI_OFFSETS.update_disabled)),
        render_mode: safeReadI32(elemPtr.add(UI_OFFSETS.render_mode)),
        slide_x: safeReadFloat(elemPtr.add(UI_OFFSETS.slide_x)),
        start_time_ms: safeReadI32(elemPtr.add(UI_OFFSETS.start_time_ms)),
        end_time_ms: safeReadI32(elemPtr.add(UI_OFFSETS.end_time_ms)),
        pos_x: safeReadFloat(elemPtr.add(UI_OFFSETS.pos_x)),
        pos_y: safeReadFloat(elemPtr.add(UI_OFFSETS.pos_y)),
        quad0_x: safeReadFloat(elemPtr.add(UI_OFFSETS.quad0_x)),
        quad0_y: safeReadFloat(elemPtr.add(UI_OFFSETS.quad0_y)),
        quad2_x: safeReadFloat(elemPtr.add(UI_OFFSETS.quad2_x)),
        quad2_y: safeReadFloat(elemPtr.add(UI_OFFSETS.quad2_y)),
        field_0x34: safeReadI32(elemPtr.add(UI_OFFSETS.field_0x34)),
    };
}

function readUiElementAddrs(elemPtr) {
    if (!elemPtr || elemPtr.isNull()) return null;
    return {
        enable: elemPtr.add(UI_OFFSETS.enable).toString(),
        clicked: elemPtr.add(UI_OFFSETS.clicked).toString(),
        update_disabled: elemPtr.add(UI_OFFSETS.update_disabled).toString(),
        render_mode: elemPtr.add(UI_OFFSETS.render_mode).toString(),
        slide_x: elemPtr.add(UI_OFFSETS.slide_x).toString(),
        start_time_ms: elemPtr.add(UI_OFFSETS.start_time_ms).toString(),
        end_time_ms: elemPtr.add(UI_OFFSETS.end_time_ms).toString(),
        pos_x: elemPtr.add(UI_OFFSETS.pos_x).toString(),
        pos_y: elemPtr.add(UI_OFFSETS.pos_y).toString(),
        quad0_x: elemPtr.add(UI_OFFSETS.quad0_x).toString(),
        quad0_y: elemPtr.add(UI_OFFSETS.quad0_y).toString(),
        quad2_x: elemPtr.add(UI_OFFSETS.quad2_x).toString(),
        quad2_y: elemPtr.add(UI_OFFSETS.quad2_y).toString(),
        field_0x34: elemPtr.add(UI_OFFSETS.field_0x34).toString(),
    };
}

function readRectFromFields(fields) {
    if (!fields) return null;
    const w = fields.quad2_x !== null && fields.quad0_x !== null ? fields.quad2_x - fields.quad0_x : null;
    const h = fields.quad2_y !== null && fields.quad0_y !== null ? fields.quad2_y - fields.quad0_y : null;
    return { w: w, h: h };
}

function readBaseFromFields(fields) {
    if (!fields) return null;
    const x = (fields.pos_x || 0) + (fields.slide_x || 0) + (fields.quad0_x || 0);
    const y = (fields.pos_y || 0) + (fields.quad0_y || 0);
    return { x: x, y: y };
}

function markCaptureWindow() {
    captureUntilMs = nowMs() + CAPTURE_WINDOW_MS;
}

function shouldCapture(g) {
    const now = nowMs();
    if (now < captureUntilMs) return true;
    if (!g) return false;
    if (g.state_id !== null && OPTIONS_STATE_IDS[g.state_id]) return true;
    if (g.state_pending !== null && OPTIONS_STATE_IDS[g.state_pending]) return true;
    return false;
}

function isPanelCandidate(elemPtr, info) {
    if (!elemPtr || elemPtr.isNull()) return false;
    const elemStr = elemPtr.toString();
    if (lastBaseExe) {
        const optPtr = lastBaseExe.add(DATA_RVAS.options_panel_elem).toString();
        if (elemStr === optPtr) return true;
    }
    if (info && info.is_panel) return true;
    if (info && info.rect && info.rect.w !== null && info.rect.h !== null) {
        if (info.rect.w >= 120 && info.rect.h >= 60) return true;
    }
    return false;
}

function pushRenderStack(tid, entry) {
    if (!renderStacks[tid]) renderStacks[tid] = [];
    renderStacks[tid].push(entry);
}

function popRenderStack(tid) {
    const stack = renderStacks[tid];
    if (!stack || stack.length === 0) return null;
    return stack.pop();
}

function currentRender(tid) {
    const stack = renderStacks[tid];
    if (!stack || stack.length === 0) return null;
    return stack[stack.length - 1];
}

function isShadowColor(color) {
    if (!color) return false;
    if (color.r === null || color.g === null || color.b === null || color.a === null) return false;
    return color.r <= 0.05 && color.g <= 0.05 && color.b <= 0.05 && color.a <= 0.8;
}

function near(value, target, eps) {
    if (value === null || value === undefined) return false;
    return Math.abs(value - target) <= eps;
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

function hookMenuOptions(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.ui_menu_main_click_options += 1;
            markCaptureWindow();
            writeLine({
                tag: "menu_click",
                which: "options",
                caller: this.returnAddress ? this.returnAddress.toString() : null,
                globals: readGlobals(lastBaseExe),
            });
        },
    });
}

function hookUiElementLoad(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.ui_element_load += 1;
            const elem = args[0];
            const path = safeReadUtf8(args[1]);
            if (!elem) return;
            const elemStr = elem.toString();
            const info = elemInfo[elemStr] || {};
            if (path) info.path = path;
            info.is_panel = !!(path && path.toLowerCase().indexOf("panel") !== -1);
            elemInfo[elemStr] = info;
            writeLine({
                tag: "ui_load",
                elem: elemStr,
                idx: uiIndexOf(elem),
                path: path,
                is_panel: info.is_panel,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function hookUiElementSetRect(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.ui_element_set_rect += 1;
            const elem = args[0];
            const elemStr = elem ? elem.toString() : null;
            const width = readArgFloat(args, 1);
            const height = readArgFloat(args, 2);
            const offsetPtr = args[3];
            const offsetX = offsetPtr ? safeReadFloat(offsetPtr) : null;
            const offsetY = offsetPtr ? safeReadFloat(offsetPtr.add(4)) : null;

            if (elemStr) {
                const info = elemInfo[elemStr] || {};
                info.rect = { w: width, h: height, off_x: offsetX, off_y: offsetY };
                elemInfo[elemStr] = info;
            }

            writeLine({
                tag: "ui_set_rect",
                elem: elemStr,
                idx: elem ? uiIndexOf(elem) : -1,
                width: width,
                height: height,
                offset_ptr: offsetPtr ? offsetPtr.toString() : null,
                offset: { x: offsetX, y: offsetY },
                elem_addrs: elem ? readUiElementAddrs(elem) : null,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function hookUiElementRender(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.ui_element_render += 1;
            const elem = args[0];
            const elemStr = elem ? elem.toString() : null;
            const info = elemStr ? elemInfo[elemStr] : null;
            const g = readGlobals(lastBaseExe);
            const capture = shouldCapture(g);
            const isPanel = isPanelCandidate(elem, info);

            this._render_elem = elem;
            this._render_elem_str = elemStr;
            this._render_info = info;
            this._render_is_panel = isPanel;
            this._render_capture = capture;

            const fields = isPanel || LOG_ALL_UI_DRAWS || LOG_ALL_UI_RENDERS ? readUiElementFields(elem) : null;
            if (fields) {
                this._render_fields = fields;
            }

            if (capture && (isPanel || LOG_ALL_UI_RENDERS)) {
                const now = nowMs();
                const last = lastRenderLogMs[elemStr] || 0;
                if (now - last >= RENDER_LOG_THROTTLE_MS) {
                    lastRenderLogMs[elemStr] = now;
                    writeLine({
                        tag: "ui_render",
                        elem: elemStr,
                        idx: elem ? uiIndexOf(elem) : -1,
                        path: info ? info.path || null : null,
                        is_panel: isPanel,
                        fields: fields,
                        rect: readRectFromFields(fields),
                        base_xy: readBaseFromFields(fields),
                        elem_addrs: elem ? readUiElementAddrs(elem) : null,
                        globals: g,
                        caller: this.returnAddress ? this.returnAddress.toString() : null,
                    });
                }
            }

            if (elemStr && (isPanel || LOG_ALL_UI_DRAWS)) {
                pushRenderStack(this.threadId, {
                    elem: elemStr,
                    idx: elem ? uiIndexOf(elem) : -1,
                    info: info,
                    fields: fields,
                });
            }
        },
        onLeave: function() {
            if (this._render_elem_str && (this._render_is_panel || LOG_ALL_UI_DRAWS)) {
                popRenderStack(this.threadId);
            }
        },
    });
}

function hookUiElementsUpdateAndRender(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.ui_elements_update_and_render += 1;
        },
    });
}

function hookOptionsUpdate(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            this._options_caller = this.returnAddress ? this.returnAddress.toString() : null;
        },
        onLeave: function() {
            counts.options_update += 1;
            const now = nowMs();
            if (now - lastOptionsLogMs < OPTIONS_LOG_THROTTLE_MS) return;
            lastOptionsLogMs = now;
            if (!lastBaseExe) return;
            const g = readGlobals(lastBaseExe);
            if (!shouldCapture(g)) return;
            const elem = lastBaseExe.add(DATA_RVAS.options_panel_elem);
            const elemStr = elem.toString();
            const info = elemInfo[elemStr] || {};
            const fields = readUiElementFields(elem);
            writeLine({
                tag: "options_update",
                elem: elemStr,
                idx: uiIndexOf(elem),
                path: info.path || null,
                fields: fields,
                rect: readRectFromFields(fields),
                base_xy: readBaseFromFields(fields),
                elem_addrs: readUiElementAddrs(elem),
                globals: g,
                caller: this._options_caller,
            });
        },
    });
}

function hookGrimSetColor(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.grim_set_color += 1;
            const r = readArgFloat(args, 0);
            const g = readArgFloat(args, 1);
            const b = readArgFloat(args, 2);
            const a = readArgFloat(args, 3);
            const state = getThreadState(this.threadId);
            state.color = { r: r, g: g, b: b, a: a };
        },
    });
}

function hookGrimSetColorPtr(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.grim_set_color_ptr += 1;
            const rgbaPtr = args[0];
            const r = rgbaPtr ? safeReadFloat(rgbaPtr) : null;
            const g = rgbaPtr ? safeReadFloat(rgbaPtr.add(4)) : null;
            const b = rgbaPtr ? safeReadFloat(rgbaPtr.add(8)) : null;
            const a = rgbaPtr ? safeReadFloat(rgbaPtr.add(12)) : null;
            const state = getThreadState(this.threadId);
            state.color = { r: r, g: g, b: b, a: a };
        },
    });
}

function hookGrimBindTexture(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.grim_bind_texture += 1;
            const handle = args[0] ? args[0].toInt32() : null;
            const stage = args[1] ? args[1].toInt32() : null;
            const state = getThreadState(this.threadId);
            state.texture = handle;
            state.stage = stage;
        },
    });
}

function logDrawEvent(kind, data) {
    if (kind === "shadow") counts.ui_shadow_logged += 1;
    else counts.ui_draw_logged += 1;
    writeLine(data);
}

function maybeLogDraw(kind, payload) {
    const render = currentRender(payload.thread_id);
    if (!render) return;
    if (!LOG_ALL_UI_DRAWS && !render) return;

    const fields = render.fields;
    const base = readBaseFromFields(fields);
    let dx = null;
    let dy = null;
    if (base && payload.x !== null && payload.y !== null) {
        dx = payload.x - base.x;
        dy = payload.y - base.y;
    }

    const state = getThreadState(payload.thread_id);
    const shadowColor = isShadowColor(state.color);
    const shadowOffset = dx !== null && dy !== null && near(dx, 7.0, 1.0) && near(dy, 7.0, 1.0);
    const isShadow = shadowColor || shadowOffset;

    logDrawEvent(isShadow ? "shadow" : "draw", {
        tag: isShadow ? "ui_shadow_draw" : "ui_draw",
        elem: render.elem,
        idx: render.idx,
        path: render.info ? render.info.path || null : null,
        kind: kind,
        x: payload.x,
        y: payload.y,
        w: payload.w,
        h: payload.h,
        points: payload.points || null,
        dx: dx,
        dy: dy,
        color: state.color,
        texture: state.texture,
        texture_stage: state.stage,
        base_xy: base,
        caller: payload.caller,
    });
}

function hookGrimDrawQuadXY(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.grim_draw_quad_xy += 1;
            const render = currentRender(this.threadId);
            if (!render) return;
            const xyPtr = args[0];
            const x = xyPtr ? safeReadFloat(xyPtr) : null;
            const y = xyPtr ? safeReadFloat(xyPtr.add(4)) : null;
            const w = readArgFloat(args, 1);
            const h = readArgFloat(args, 2);
            maybeLogDraw("draw_quad_xy", {
                thread_id: this.threadId,
                x: x,
                y: y,
                w: w,
                h: h,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function hookGrimDrawQuad(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.grim_draw_quad += 1;
            const render = currentRender(this.threadId);
            if (!render) return;
            const x = readArgFloat(args, 0);
            const y = readArgFloat(args, 1);
            const w = readArgFloat(args, 2);
            const h = readArgFloat(args, 3);
            maybeLogDraw("draw_quad", {
                thread_id: this.threadId,
                x: x,
                y: y,
                w: w,
                h: h,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function hookGrimDrawRectOutline(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.grim_draw_rect_outline += 1;
            const render = currentRender(this.threadId);
            if (!render) return;
            const xyPtr = args[0];
            const x = xyPtr ? safeReadFloat(xyPtr) : null;
            const y = xyPtr ? safeReadFloat(xyPtr.add(4)) : null;
            const w = readArgFloat(args, 1);
            const h = readArgFloat(args, 2);
            maybeLogDraw("draw_rect_outline", {
                thread_id: this.threadId,
                x: x,
                y: y,
                w: w,
                h: h,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function hookGrimDrawQuadPoints(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.grim_draw_quad_points += 1;
            const render = currentRender(this.threadId);
            if (!render) return;
            const pts = [];
            for (let i = 0; i < 8; i++) {
                pts.push(readArgFloat(args, i));
            }
            let x = null;
            let y = null;
            if (pts[0] !== null && pts[2] !== null) {
                x = Math.min(pts[0], pts[2], pts[4], pts[6]);
            }
            if (pts[1] !== null && pts[3] !== null) {
                y = Math.min(pts[1], pts[3], pts[5], pts[7]);
            }
            maybeLogDraw("draw_quad_points", {
                thread_id: this.threadId,
                x: x,
                y: y,
                w: null,
                h: null,
                points: pts,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
            });
        },
    });
}

function attachExeHooks(exeBase) {
    attachOnce("ui_element_load", exeBase.add(EXE_RVAS.ui_element_load), hookUiElementLoad);
    attachOnce("ui_element_set_rect", exeBase.add(EXE_RVAS.ui_element_set_rect), hookUiElementSetRect);
    attachOnce("ui_element_render", exeBase.add(EXE_RVAS.ui_element_render), hookUiElementRender);
    attachOnce("ui_elements_update_and_render", exeBase.add(EXE_RVAS.ui_elements_update_and_render), hookUiElementsUpdateAndRender);
    attachOnce("ui_menu_main_click_options", exeBase.add(EXE_RVAS.ui_menu_main_click_options), hookMenuOptions);
    attachOnce("options_update", exeBase.add(EXE_RVAS.options_update), hookOptionsUpdate);
}

function attachGrimHooks(grimBase) {
    attachOnce("grim_set_color", grimBase.add(GRIM_RVAS.set_color), hookGrimSetColor);
    attachOnce("grim_set_color_ptr", grimBase.add(GRIM_RVAS.set_color_ptr), hookGrimSetColorPtr);
    attachOnce("grim_bind_texture", grimBase.add(GRIM_RVAS.bind_texture), hookGrimBindTexture);
    attachOnce("grim_draw_quad_xy", grimBase.add(GRIM_RVAS.draw_quad_xy), hookGrimDrawQuadXY);
    attachOnce("grim_draw_quad", grimBase.add(GRIM_RVAS.draw_quad), hookGrimDrawQuad);
    attachOnce("grim_draw_rect_outline", grimBase.add(GRIM_RVAS.draw_rect_outline), hookGrimDrawRectOutline);
    attachOnce("grim_draw_quad_points", grimBase.add(GRIM_RVAS.draw_quad_points), hookGrimDrawQuadPoints);
}

function tick() {
    const exeBase = normalizePtr(findModuleBase(GAME_MODULE));
    const grimBase = normalizePtr(findModuleBase(GRIM_MODULE));
    lastBaseExe = exeBase;
    lastBaseGrim = grimBase;
    if (exeBase) {
        refreshUiTable(exeBase);
        attachExeHooks(exeBase);
    }
    if (grimBase) attachGrimHooks(grimBase);
}

writeLine({
    tag: "start",
    arch: Process.arch,
    pointer_size: Process.pointerSize,
    log_dir: LOG_DIR,
    exe_rvas: EXE_RVAS,
    data_rvas: DATA_RVAS,
    grim_rvas: GRIM_RVAS,
    ui_offsets: UI_OFFSETS,
    log_all_ui_renders: LOG_ALL_UI_RENDERS,
    log_all_ui_draws: LOG_ALL_UI_DRAWS,
});

setInterval(summary, SUMMARY_INTERVAL_MS);
setInterval(tick, 100);

// Initial sweep
markCaptureWindow();
tick();
