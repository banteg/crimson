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

const LOG_DIR = getLogDir();
const OUT_PATHS = [joinPath(LOG_DIR, "menu_logo_pivot_trace.jsonl")];

const GAME_MODULE = "crimsonland.exe";

const UI_ELEMENT_TABLE_COUNT = 41;

const EXE_RVAS = {
    ui_element_update: 0x46900,
    ui_element_render: 0x46c40,
    ui_elements_update_and_render: 0x1a530,
    game_state_set: 0x461c0,
    cb_main_menu_play: 0x47400,
    cb_main_menu_options: 0x47370,
    cb_main_menu_quit: 0x47450,
};

const DATA_RVAS = {
    ui_elements_timeline: 0x87248,
    ui_transition_direction: 0x8724c,
    game_state_id: 0x87270,
    game_state_pending: 0x87274,
    ui_element_table_base: 0x8f168,
};

const attached = {};
const outFiles = {};
let outWarned = false;
let lastBaseExe = null;

let uiTablePtrToIndex = {};

const counts = {
    ui_element_update: 0,
    ui_element_render: 0,
    ui_elements_update_and_render: 0,
    logo_updates_logged: 0,
    cb_main_menu_play: 0,
    cb_main_menu_options: 0,
    cb_main_menu_quit: 0,
    game_state_set: 0,
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
        console.log("menu_logo_pivot_trace: file logging unavailable, console only");
    }
    console.log(line.trim());
}

function summary() {
    writeLine({
        tag: "summary",
        counts: counts,
        base_exe: lastBaseExe ? lastBaseExe.toString() : null,
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

function readGlobals(exeBase) {
    const out = {};
    if (!exeBase) return out;
    out.timeline = safeReadI32(exeBase.add(DATA_RVAS.ui_elements_timeline));
    out.dir = safeReadU8(exeBase.add(DATA_RVAS.ui_transition_direction));
    out.state_id = safeReadI32(exeBase.add(DATA_RVAS.game_state_id));
    out.state_pending = safeReadI32(exeBase.add(DATA_RVAS.game_state_pending));
    return out;
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

function isLogoElement(elemPtr) {
    if (!lastBaseExe) return false;
    if (!elemPtr || elemPtr.isNull()) return false;
    const p0 = safeReadPointer(lastBaseExe.add(DATA_RVAS.ui_element_table_base));
    if (!p0 || p0.isNull()) return false;
    return p0.toString() === elemPtr.toString();
}

function uiIndexOf(elemPtr) {
    if (!elemPtr || elemPtr.isNull()) return -1;
    const key = elemPtr.toString();
    const idx = uiTablePtrToIndex[key];
    return idx === undefined ? -1 : idx;
}

function readTransform(elemPtr) {
    const m00 = safeReadFloat(elemPtr.add(0x304));
    const m01 = safeReadFloat(elemPtr.add(0x308));
    const m10 = safeReadFloat(elemPtr.add(0x30c));
    const m11 = safeReadFloat(elemPtr.add(0x310));
    let angle = null;
    if (m00 !== null && m10 !== null) angle = Math.atan2(m10, m00);
    return {
        m00: m00,
        m01: m01,
        m10: m10,
        m11: m11,
        angle_rad: angle,
        angle_deg: angle !== null ? (angle * 180.0) / Math.PI : null,
    };
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

function hookMenuCallback(addr, name, pendingState) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts[name] += 1;
            writeLine({
                tag: "menu_click",
                which: name,
                pending_state: pendingState,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
                globals: readGlobals(lastBaseExe),
            });
        },
    });
}

function hookGameStateSet(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.game_state_set += 1;
            const nextState = args[0] ? args[0].toInt32() : null;
            writeLine({
                tag: "game_state_set",
                next_state: nextState,
                caller: this.returnAddress ? this.returnAddress.toString() : null,
                globals: readGlobals(lastBaseExe),
            });
        },
    });
}

function hookUiElementsUpdateAndRender(addr) {
    Interceptor.attach(addr, {
        onEnter: function() {
            counts.ui_elements_update_and_render += 1;
            const g = readGlobals(lastBaseExe);
            if (g.timeline !== null && g.timeline <= 350) {
                writeLine({
                    tag: "ui_tick",
                    globals: g,
                });
            }
        },
    });
}

function hookUiElementUpdate(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.ui_element_update += 1;
            this.elem = args[0];
            this.idx = uiIndexOf(this.elem);
            if (this.idx === -1 && isLogoElement(this.elem)) this.idx = 0;
        },
        onLeave: function() {
            if (this.idx !== 0) return;

            const g = readGlobals(lastBaseExe);
            const t = g.timeline;
            const tr = readTransform(this.elem);
            const angle = tr.angle_rad;
            const shouldLog =
                (t !== null && t <= 350) || (angle !== null && Math.abs(angle) >= 0.0005);
            if (!shouldLog) return;

            counts.logo_updates_logged += 1;
            writeLine({
                tag: "logo_update",
                idx: this.idx,
                elem: this.elem ? this.elem.toString() : null,
                start_time_ms: safeReadI32(this.elem.add(0x10)),
                end_time_ms: safeReadI32(this.elem.add(0x14)),
                enable_byte: safeReadU8(this.elem.add(0x0)),
                clicked_byte: safeReadU8(this.elem.add(0x1)),
                update_disabled: safeReadU8(this.elem.add(0x2)),
                render_mode: safeReadI32(this.elem.add(0x4)),
                transform: tr,
                globals: g,
            });
        },
    });
}

function hookUiElementRender(addr) {
    Interceptor.attach(addr, {
        onEnter: function(args) {
            counts.ui_element_render += 1;
            const elem = args[0];
            let idx = uiIndexOf(elem);
            if (idx !== 0 && !(idx === -1 && isLogoElement(elem))) return;
            idx = 0;
            const g = readGlobals(lastBaseExe);
            if (g.timeline !== null && g.timeline <= 350) {
                writeLine({
                    tag: "logo_render",
                    idx: idx,
                    elem: elem ? elem.toString() : null,
                    transform: readTransform(elem),
                    globals: g,
                });
            }
        },
    });
}

function attachByRva(exeBase) {
    if (!exeBase) return;
    attachOnce("ui_elements_update_and_render", exeBase.add(EXE_RVAS.ui_elements_update_and_render), hookUiElementsUpdateAndRender);
    attachOnce("ui_element_update", exeBase.add(EXE_RVAS.ui_element_update), hookUiElementUpdate);
    attachOnce("ui_element_render", exeBase.add(EXE_RVAS.ui_element_render), hookUiElementRender);
    attachOnce("game_state_set", exeBase.add(EXE_RVAS.game_state_set), hookGameStateSet);
    attachOnce(
        "cb_main_menu_play",
        exeBase.add(EXE_RVAS.cb_main_menu_play),
        (addr) => hookMenuCallback(addr, "cb_main_menu_play", 1),
    );
    attachOnce(
        "cb_main_menu_options",
        exeBase.add(EXE_RVAS.cb_main_menu_options),
        (addr) => hookMenuCallback(addr, "cb_main_menu_options", 2),
    );
    attachOnce(
        "cb_main_menu_quit",
        exeBase.add(EXE_RVAS.cb_main_menu_quit),
        (addr) => hookMenuCallback(addr, "cb_main_menu_quit", 10),
    );
}

function tick() {
    const exeBase = normalizePtr(findModuleBase(GAME_MODULE));
    lastBaseExe = exeBase;
    if (!exeBase) return;
    refreshUiTable(exeBase);
    attachByRva(exeBase);
}

writeLine({ tag: "start", arch: Process.arch, pointer_size: Process.pointerSize, log_dir: LOG_DIR });
setInterval(summary, 4000);
setInterval(tick, 100);
tick();
