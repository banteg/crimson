"use strict";

/**
 * ground_dump.js - Frida script to dump the ground render target texture
 *
 * Usage:
 *   frida -n crimsonland.exe -l ground_dump.js
 *
 * Behavior:
 *   Automatically dumps the "ground" render-target texture after every
 *   `terrain_generate()` call (i.e. whenever a new level terrain is created).
 *
 * Output:
 *   Writes raw BGRA pixel data to C:\share\frida\ground_dump_<timestamp>.raw
 *   Logs events to C:\share\frida\ground_dump.jsonl
 */

const DEFAULT_OUT_DIR = "C:\\share\\frida";

function getOutDir() {
    try {
        return Process.env.CRIMSON_FRIDA_DIR || DEFAULT_OUT_DIR;
    } catch (_) {
        return DEFAULT_OUT_DIR;
    }
}

function joinPath(base, leaf) {
    if (!base) return leaf;
    const sep = base.endsWith("\\") || base.endsWith("/") ? "" : "\\";
    return base + sep + leaf;
}

const OUT_DIR = getOutDir();
const LOG_PATH = joinPath(OUT_DIR, "ground_dump.jsonl");

let logFile = null;
let logWarned = false;

function nowMs() {
    return Date.now();
}

function openLogFile() {
    if (logFile) return logFile;
    try {
        logFile = new File(LOG_PATH, "a");
    } catch (e) {
        logFile = null;
    }
    return logFile;
}

function writeLine(obj) {
    obj.ts = nowMs();
    const line = JSON.stringify(obj) + "\n";
    let wrote = false;
    try {
        const f = openLogFile();
        if (f) {
            f.write(line);
            f.flush();
            wrote = true;
        }
    } catch (e) {}

    if (!wrote && !logWarned) {
        logWarned = true;
        console.log("ground_dump: file logging unavailable, console only");
    }
    console.log(line.trim());
}

// Module names
const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";
const D3D8_MODULE = "d3d8.dll";

// EXE data RVAs (from terrain_trace.js and terrain.md)
const EXE_RVAS = {
    terrain_generate: 0x17b80,
    terrain_render: 0x188a0,
    grim_interface_ptr: 0x8083c,
    // From `analysis/ghidra/maps/name_map.json` (crt_srand @ 0x00461739).
    crt_srand: 0x61739,
    // From `analysis/ghidra/maps/name_map.json` (crt_rand @ 0x00461746).
    crt_rand: 0x61746,
};

const DATA_RVAS = {
    terrain_render_target: 0x8f530,  // int handle to "ground" RT
    terrain_texture_width: 0x8f534,
    terrain_texture_height: 0x8f538,
    terrain_texture_failed: 0x8f52c, // byte flag
    config_texture_scale: 0x803b8,
};

// Grim2D vtable offsets
const GRIM_VTABLE_OFFSETS = {
    set_render_target: 0x30,   // int set_render_target(int target_index)
    get_texture_handle: 0xc0,  // int get_texture_handle(char* name)
    bind_texture: 0xc4,        // void bind_texture(int handle, int stage)
};

// Grim internal RVAs
const GRIM_RVAS = {
    set_render_target: 0x06d50,
    get_texture_handle: 0x07740,
};

// D3D8 vtable offsets (IDirect3DDevice8)
const D3D8_DEVICE_VTABLE = {
    QueryInterface: 0,
    AddRef: 1,
    Release: 2,
    // ...
    // Verified against `third_party/headers/d3d8.h`:
    // CreateImageSurface = 27, CopyRects = 28, GetRenderTarget = 32.
    CreateImageSurface: 27,  // HRESULT CreateImageSurface(UINT w, UINT h, D3DFORMAT fmt, IDirect3DSurface8** ppSurf)
    CopyRects: 28,           // HRESULT CopyRects(IDirect3DSurface8* pSrc, CONST RECT*, DWORD, IDirect3DSurface8* pDest, CONST POINT*)
    GetRenderTarget: 32,     // HRESULT GetRenderTarget(IDirect3DSurface8** ppRT)
    GetDepthStencilSurface: 33,
};

// D3D8 vtable offsets (IDirect3DTexture8)
const D3D8_TEXTURE_VTABLE = {
    // IDirect3DTexture8::GetSurfaceLevel(UINT Level, IDirect3DSurface8** ppSurfaceLevel)
    // Verified against `third_party/headers/d3d8.h`.
    GetSurfaceLevel: 15,
};

// D3D8 vtable offsets (IDirect3DSurface8)
const D3D8_SURFACE_VTABLE = {
    QueryInterface: 0,
    AddRef: 1,
    Release: 2,
    GetDevice: 3,
    SetPrivateData: 4,
    GetPrivateData: 5,
    FreePrivateData: 6,
    GetContainer: 7,
    GetDesc: 8,    // HRESULT GetDesc(D3DSURFACE_DESC* pDesc)
    LockRect: 9,   // HRESULT LockRect(D3DLOCKED_RECT* pLockedRect, CONST RECT*, DWORD Flags)
    UnlockRect: 10, // HRESULT UnlockRect()
};

// D3D8 constants
const D3DFMT_A8R8G8B8 = 21;
const D3DFMT_X8R8G8B8 = 22;
const D3DFMT_R5G6B5 = 23;
const D3DFMT_A1R5G5B5 = 25;
const D3DFMT_X1R5G5B5 = 24;
const D3DLOCK_READONLY = 0x10;
const D3DPOOL_SCRATCH = 3;

// State
let exeBase = null;
let grimBase = null;
let grimInterface = null;
let grimVtable = null;
let d3dDevice = null;
let attached = false;

let currentRenderTarget = -1;  // -1 = backbuffer
let terrainRtHandle = null;
let dumpCount = 0;

// RNG seed tracking
let lastSrandSeed = null;
let seedAtGenerate = null;
let lastTerrainGenerateInfo = null;

// Helpers
function log(msg) {
    writeLine({ tag: "log", msg: msg });
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

function safeReadI32(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readS32();
    } catch (e) {
        return null;
    }
}

function safeReadU8(ptrVal) {
    try {
        if (!isReadable(ptrVal)) return null;
        return ptrVal.readU8();
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

function findModuleBase(name) {
    try {
        const mod = Process.findModuleByName(name);
        return mod ? mod.base : null;
    } catch (e) {
        return null;
    }
}

// Read terrain globals from EXE
function readTerrainGlobals() {
    if (!exeBase) return null;
    return {
        terrain_render_target: safeReadI32(exeBase.add(DATA_RVAS.terrain_render_target)),
        terrain_texture_width: safeReadI32(exeBase.add(DATA_RVAS.terrain_texture_width)),
        terrain_texture_height: safeReadI32(exeBase.add(DATA_RVAS.terrain_texture_height)),
        terrain_texture_failed: safeReadU8(exeBase.add(DATA_RVAS.terrain_texture_failed)),
        config_texture_scale: safeReadFloat(exeBase.add(DATA_RVAS.config_texture_scale)),
    };
}

// Get the Grim2D interface pointer and vtable
function getGrimInterface() {
    if (!exeBase) return null;
    const ifacePtr = safeReadPointer(exeBase.add(EXE_RVAS.grim_interface_ptr));
    if (!ifacePtr || ifacePtr.isNull()) return null;
    const vtablePtr = safeReadPointer(ifacePtr);
    if (!vtablePtr || vtablePtr.isNull()) return null;
    return { iface: ifacePtr, vtable: vtablePtr };
}

// Grim2D internal RVAs for D3D state (from analysis/ghidra/maps/data_map.json)
const GRIM_DATA_RVAS = {
    d3d_device: 0x59dbc,            // LPDIRECT3DDEVICE8 grim_d3d_device
    render_target_surface: 0x5a48c, // IDirect3DSurface8* current offscreen RT surface
    backbuffer_surface: 0x5c900,    // IDirect3DSurface8* cached backbuffer surface
    texture_slots: 0x5d404,         // Texture slot table (array of texture struct pointers)
};

// Find the D3D8 device pointer from grim.dll internals
function findD3DDevice() {
    if (!grimBase) return null;

    // Primary location from Ghidra analysis: grim_d3d_device at 0x10059dbc
    const devicePtrAddr = grimBase.add(GRIM_DATA_RVAS.d3d_device);
    const devicePtr = safeReadPointer(devicePtrAddr);

    if (devicePtr && !devicePtr.isNull()) {
        // Verify it looks like a D3D device by checking vtable
        const vtable = safeReadPointer(devicePtr);
        if (vtable && !vtable.isNull()) {
            // Check if GetRenderTarget method pointer is in d3d8.dll
            const getRTPtr = safeReadPointer(vtable.add(D3D8_DEVICE_VTABLE.GetRenderTarget * 4));
            if (getRTPtr) {
                try {
                    const mod = Process.findModuleByAddress(getRTPtr);
                    if (mod && mod.name.toLowerCase() === "d3d8.dll") {
                        return devicePtr;
                    }
                } catch (e) {}
            }
        }
        // Even if validation fails, the pointer might still be valid
        return devicePtr;
    }

    return null;
}

// Call a D3D8 device vtable method
function callD3DMethod(device, vtableIndex, args) {
    if (!device) return null;
    const vtable = device.readPointer();
    const methodPtr = vtable.add(vtableIndex * 4).readPointer();

    // Build NativeFunction - all D3D8 methods use stdcall on x86
    const argTypes = args.map(() => "pointer");
    const fn = new NativeFunction(methodPtr, "int", ["pointer"].concat(argTypes), "stdcall");

    return fn(device, ...args);
}

// Get the current render target surface
function getCurrentRenderTarget(device) {
    const ppSurface = Memory.alloc(4);
    const hr = callD3DMethod(device, D3D8_DEVICE_VTABLE.GetRenderTarget, [ppSurface]);
    if (hr !== 0) return null;
    return ppSurface.readPointer();
}

// Get surface description
function getSurfaceDesc(surface) {
    // D3DSURFACE_DESC is 32 bytes:
    // DWORD Format (4), DWORD Type (4), DWORD Usage (4), DWORD Pool (4),
    // DWORD Size (4), DWORD MultiSampleType (4), UINT Width (4), UINT Height (4)
    const desc = Memory.alloc(32);
    const vtable = surface.readPointer();
    const getDescPtr = vtable.add(D3D8_SURFACE_VTABLE.GetDesc * 4).readPointer();
    const getDesc = new NativeFunction(getDescPtr, "int", ["pointer", "pointer"], "stdcall");
    const hr = getDesc(surface, desc);
    if (hr !== 0) return null;
    return {
        format: desc.readU32(),
        type: desc.add(4).readU32(),
        usage: desc.add(8).readU32(),
        pool: desc.add(12).readU32(),
        size: desc.add(16).readU32(),
        multiSampleType: desc.add(20).readU32(),
        width: desc.add(24).readU32(),
        height: desc.add(28).readU32(),
    };
}

// Create a lockable scratch surface
function createScratchSurface(device, width, height, format) {
    const ppSurface = Memory.alloc(4);
    // CreateImageSurface(UINT Width, UINT Height, D3DFORMAT Format, IDirect3DSurface8** ppSurface)
    const vtable = device.readPointer();
    const createPtr = vtable.add(D3D8_DEVICE_VTABLE.CreateImageSurface * 4).readPointer();
    const create = new NativeFunction(createPtr, "int", ["pointer", "uint", "uint", "uint", "pointer"], "stdcall");
    const hr = create(device, width, height, format, ppSurface);
    if (hr !== 0) return null;
    return ppSurface.readPointer();
}

// Safe wrapper that catches access violations (for dgVoodoo compatibility)
function createScratchSurfaceSafe(device, width, height, format) {
    try {
        const vtable = device.readPointer();
        writeLine({
            tag: "dump_debug",
            msg: "createScratchSurface",
            device: device.toString(),
            vtable: vtable.toString(),
        });

        const createPtr = vtable.add(D3D8_DEVICE_VTABLE.CreateImageSurface * 4).readPointer();
        writeLine({
            tag: "dump_debug",
            msg: "CreateImageSurface ptr",
            ptr: createPtr.toString(),
        });

        // Check if the method pointer looks valid
        const range = Process.findRangeByAddress(createPtr);
        if (!range || range.protection.indexOf("x") === -1) {
            writeLine({ tag: "dump_debug", msg: "CreateImageSurface ptr not executable" });
            return null;
        }

        const ppSurface = Memory.alloc(4);
        const create = new NativeFunction(createPtr, "int", ["pointer", "uint", "uint", "uint", "pointer"], "stdcall");
        const hr = create(device, width, height, format, ppSurface);

        writeLine({ tag: "dump_debug", msg: "CreateImageSurface returned", hr: hr });

        if (hr !== 0) return null;
        return ppSurface.readPointer();
    } catch (e) {
        writeLine({ tag: "dump_debug", msg: "createScratchSurface exception", error: String(e) });
        return null;
    }
}

// Copy from render target to scratch surface
function copyRects(device, srcSurface, dstSurface) {
    // CopyRects(pSrcSurf, pSrcRects, cRects, pDestSurf, pDestPoints)
    // Pass NULL for rects/points to copy entire surface
    const vtable = device.readPointer();
    const copyPtr = vtable.add(D3D8_DEVICE_VTABLE.CopyRects * 4).readPointer();
    const copy = new NativeFunction(copyPtr, "int", ["pointer", "pointer", "pointer", "uint", "pointer", "pointer"], "stdcall");
    const hr = copy(device, srcSurface, ptr(0), 0, dstSurface, ptr(0));
    return hr === 0;
}

// Lock surface and read pixels
function lockAndReadSurface(surface, width, height, format) {
    // D3DLOCKED_RECT: INT Pitch (4), void* pBits (4)
    const lockedRect = Memory.alloc(8);
    const vtable = surface.readPointer();

    const lockPtr = vtable.add(D3D8_SURFACE_VTABLE.LockRect * 4).readPointer();
    const lock = new NativeFunction(lockPtr, "int", ["pointer", "pointer", "pointer", "uint"], "stdcall");
    const hr = lock(surface, lockedRect, ptr(0), D3DLOCK_READONLY);
    if (hr !== 0) return null;

    const pitch = lockedRect.readS32();
    const pBits = lockedRect.add(4).readPointer();

    // Determine bytes per pixel
    let bpp = 4;  // default ARGB
    if (format === D3DFMT_R5G6B5 || format === D3DFMT_A1R5G5B5 || format === D3DFMT_X1R5G5B5) {
        bpp = 2;
    }

    // Read pixel data
    const dataSize = height * pitch;
    let pixelData;
    try {
        pixelData = pBits.readByteArray(dataSize);
    } catch (e) {
        pixelData = null;
    }

    // Unlock
    const unlockPtr = vtable.add(D3D8_SURFACE_VTABLE.UnlockRect * 4).readPointer();
    const unlock = new NativeFunction(unlockPtr, "int", ["pointer"], "stdcall");
    unlock(surface);

    // CopyRects + LockRect frequently returns a padded pitch; pack rows so the `.raw`
    // file is tightly packed (ImageMagick/etc don't know our pitch).
    let packed = pixelData;
    const rowBytes = width * bpp;
    if (pixelData && pitch > 0 && rowBytes > 0 && pitch !== rowBytes) {
        try {
            const src = new Uint8Array(pixelData);
            const out = new Uint8Array(rowBytes * height);
            for (let y = 0; y < height; y++) {
                const srcOff = y * pitch;
                const dstOff = y * rowBytes;
                out.set(src.subarray(srcOff, srcOff + rowBytes), dstOff);
            }
            packed = out.buffer;
        } catch (e) {
            // If packing fails, fall back to raw locked bytes (may appear garbled).
            packed = pixelData;
        }
    }

    return { data: packed, pitch: pitch, bpp: bpp, row_bytes: rowBytes };
}

// Release a D3D COM object
function releaseSurface(surface) {
    if (!surface || surface.isNull()) return;
    const vtable = surface.readPointer();
    const releasePtr = vtable.add(2 * 4).readPointer();  // IUnknown::Release is vtable[2]
    const release = new NativeFunction(releasePtr, "uint", ["pointer"], "stdcall");
    release(surface);
}

function getGrimTextureEntryPtr(handle) {
    if (!grimBase) return null;
    if (handle === null || handle === undefined) return null;
    if (handle < 0 || handle > 0xff) return null; // 0x400 bytes / 4 = 256 slots

    const slotAddr = grimBase.add(GRIM_DATA_RVAS.texture_slots).add(handle * 4);
    const entryPtr = safeReadPointer(slotAddr);
    if (!entryPtr || entryPtr.isNull()) return null;
    return entryPtr;
}

function getGrimTextureD3DTexturePtr(entryPtr) {
    if (!entryPtr || entryPtr.isNull()) return null;
    const texPtr = safeReadPointer(entryPtr.add(4));
    if (!texPtr || texPtr.isNull()) return null;
    return texPtr;
}

function getTextureSurfaceLevel(texPtr, level) {
    if (!texPtr || texPtr.isNull()) return null;
    const vtable = texPtr.readPointer();
    const fnPtr = vtable.add(D3D8_TEXTURE_VTABLE.GetSurfaceLevel * 4).readPointer();
    const getSurfaceLevel = new NativeFunction(fnPtr, "int", ["pointer", "uint", "pointer"], "stdcall");

    const ppSurface = Memory.alloc(4);
    const hr = getSurfaceLevel(texPtr, level >>> 0, ppSurface);
    if (hr !== 0) return null;
    return ppSurface.readPointer();
}

// Main dump function
function dumpGroundTexture() {
    writeLine({ tag: "dump_start" });

    // Refresh state
    exeBase = findModuleBase(GAME_MODULE);
    grimBase = findModuleBase(GRIM_MODULE);

    if (!exeBase || !grimBase) {
        writeLine({ tag: "dump_error", error: "modules not found" });
        return { success: false, error: "modules not found" };
    }

    const globals = readTerrainGlobals();

    if (globals.terrain_texture_failed) {
        writeLine({ tag: "dump_error", error: "terrain texture failed", globals: globals });
        return { success: false, error: "terrain texture failed" };
    }

    if (!d3dDevice) {
        d3dDevice = findD3DDevice();
    }

    writeLine({
        tag: "dump_debug",
        d3d_device: d3dDevice ? d3dDevice.toString() : null,
        globals: globals,
    });

    if (!d3dDevice) {
        writeLine({ tag: "dump_error", error: "d3d device not found" });
        return { success: false, error: "d3d device not found" };
    }

    const targetHandle = globals.terrain_render_target;
    const entryPtr = getGrimTextureEntryPtr(targetHandle);
    const texPtr = entryPtr ? getGrimTextureD3DTexturePtr(entryPtr) : null;
    const entryIsRt = entryPtr ? safeReadU8(entryPtr.add(8)) : null;
    const entryW = entryPtr ? safeReadI32(entryPtr.add(0xc)) : null;
    const entryH = entryPtr ? safeReadI32(entryPtr.add(0x10)) : null;

    if (!entryPtr || !texPtr) {
        writeLine({
            tag: "dump_error",
            error: "terrain render target handle not resolvable via grim_texture_slots",
            terrain_render_target: targetHandle,
            entry_ptr: entryPtr ? entryPtr.toString() : null,
            tex_ptr: texPtr ? texPtr.toString() : null,
        });
        return { success: false, error: "terrain render target handle not resolvable" };
    }

    let rtSurface = getTextureSurfaceLevel(texPtr, 0);
    if (!rtSurface) {
        // Last-ditch: dump whatever render target is currently bound.
        rtSurface = getCurrentRenderTarget(d3dDevice);
    }

    if (!rtSurface) {
        writeLine({ tag: "dump_error", error: "could not resolve a render target surface" });
        return { success: false, error: "could not resolve a render target surface" };
    }

    writeLine({
        tag: "dump_debug",
        terrain_render_target: targetHandle,
        slot_entry: entryPtr.toString(),
        slot_entry_is_rt: entryIsRt,
        slot_entry_w: entryW,
        slot_entry_h: entryH,
        d3d_texture: texPtr.toString(),
        rt_surface: rtSurface.toString(),
    });

    // Get surface description
    const desc = getSurfaceDesc(rtSurface);
    if (!desc) {
        releaseSurface(rtSurface);
        writeLine({ tag: "dump_error", error: "GetDesc failed" });
        return { success: false, error: "GetDesc failed" };
    }

    writeLine({
        tag: "dump_debug",
        desc: desc,
    });

    // Try to lock the RT surface directly first (works for some surface types)
    let pixels = lockAndReadSurface(rtSurface, desc.width, desc.height, desc.format);

    if (!pixels || !pixels.data) {
        writeLine({ tag: "dump_debug", msg: "Direct lock failed, trying scratch surface" });

        // Create scratch surface and copy
        const scratchSurface = createScratchSurfaceSafe(d3dDevice, desc.width, desc.height, desc.format);
        if (!scratchSurface) {
            releaseSurface(rtSurface);
            writeLine({ tag: "dump_error", error: "CreateImageSurface failed" });
            return { success: false, error: "CreateImageSurface failed" };
        }

        // Copy render target to scratch
        if (!copyRects(d3dDevice, rtSurface, scratchSurface)) {
            releaseSurface(scratchSurface);
            releaseSurface(rtSurface);
            writeLine({ tag: "dump_error", error: "CopyRects failed" });
            return { success: false, error: "CopyRects failed" };
        }

        // Lock and read pixels from scratch
        pixels = lockAndReadSurface(scratchSurface, desc.width, desc.height, desc.format);
        releaseSurface(scratchSurface);
    }

    if (!pixels || !pixels.data) {
        releaseSurface(rtSurface);
        writeLine({ tag: "dump_error", error: "LockRect failed" });
        return { success: false, error: "LockRect failed" };
    }

    releaseSurface(rtSurface);

    // Write to file
    const timestamp = Date.now();
    const rawPath = joinPath(OUT_DIR, "ground_dump_" + timestamp + ".raw");

    try {
        const rawFile = new File(rawPath, "wb");
        rawFile.write(pixels.data);
        rawFile.close();
    } catch (e) {
        writeLine({ tag: "dump_error", error: "file write failed: " + e });
        return { success: false, error: "file write failed: " + e };
    }

    dumpCount += 1;

    // Log dump metadata to JSONL
    writeLine({
        tag: "dump",
        dump_index: dumpCount,
        raw_path: rawPath,
        seed_srand: lastSrandSeed,
        seed_at_generate: seedAtGenerate,
        terrain_generate: lastTerrainGenerateInfo,
        width: desc.width,
        height: desc.height,
        format: desc.format,
        format_name: formatName(desc.format),
        pitch: pixels.pitch,
        bpp: pixels.bpp,
        row_bytes: pixels.row_bytes !== undefined ? pixels.row_bytes : null,
        data_size: pixels.data.byteLength || null,
        globals: globals,
        convert_cmd: "magick -size " + desc.width + "x" + desc.height + " -depth 8 BGRA:" + rawPath + " ground.png",
    });

    return {
        success: true,
        rawPath: rawPath,
        width: desc.width,
        height: desc.height,
        format: desc.format,
        seed: seedAtGenerate,
        lastSrandSeed: lastSrandSeed,
    };
}

function formatName(fmt) {
    switch (fmt) {
        case D3DFMT_A8R8G8B8: return "A8R8G8B8";
        case D3DFMT_X8R8G8B8: return "X8R8G8B8";
        case D3DFMT_R5G6B5: return "R5G6B5";
        case D3DFMT_A1R5G5B5: return "A1R5G5B5";
        case D3DFMT_X1R5G5B5: return "X1R5G5B5";
        default: return "unknown";
    }
}

// Hook MSVCRT srand to capture RNG seed
function hookSrand() {
    // Crimsonland has its own CRT rand/srand implementation in the EXE.
    // Prefer that over msvcrt, otherwise we will miss the terrain seed.
    if (exeBase) {
        const addr = exeBase.add(EXE_RVAS.crt_srand);
        writeLine({ tag: "attach", name: "crt_srand", addr: addr.toString() });
        Interceptor.attach(addr, {
            onEnter: function (args) {
                const seed = args[0].toUInt32();
                lastSrandSeed = seed;
                writeLine({ tag: "crt_srand", seed: seed, seed_hex: "0x" + seed.toString(16) });
            },
        });
        return;
    }

    // Fallback: try msvcrt.dll (useful in other environments/builds).
    const msvcrt = Process.findModuleByName("msvcrt.dll");
    if (msvcrt) {
        const srandAddr = msvcrt.findExportByName("srand");
        if (srandAddr) {
            writeLine({ tag: "attach", name: "srand", addr: srandAddr.toString() });
            Interceptor.attach(srandAddr, {
                onEnter: function (args) {
                    const seed = args[0].toUInt32();
                    lastSrandSeed = seed;
                    writeLine({ tag: "srand", seed: seed, seed_hex: "0x" + seed.toString(16) });
                },
            });
            return;
        }
    }

    writeLine({ tag: "warning", msg: "Could not find crt_srand/srand to hook" });
}

// Hook terrain_generate to dump after generation completes
function hookTerrainGenerate() {
    if (!exeBase) return;

    const addr = exeBase.add(EXE_RVAS.terrain_generate);
    writeLine({ tag: "attach", name: "terrain_generate", addr: addr.toString() });

    Interceptor.attach(addr, {
        onEnter: function (args) {
            // Capture the seed at the moment terrain_generate is called
            seedAtGenerate = lastSrandSeed;
            const desc = args[0];
            const indices = desc && !desc.isNull() ? {
                tex0_index: safeReadI32(desc.add(0x10)),
                tex1_index: safeReadI32(desc.add(0x14)),
                tex2_index: safeReadI32(desc.add(0x18)),
            } : null;

            lastTerrainGenerateInfo = {
                desc: desc ? desc.toString() : null,
                indices: indices,
                seed: seedAtGenerate,
                seed_hex: seedAtGenerate !== null ? "0x" + seedAtGenerate.toString(16) : null,
            };
            writeLine({
                tag: "terrain_generate_enter",
                ...lastTerrainGenerateInfo,
            });
        },
        onLeave: function (retval) {
            writeLine({ tag: "terrain_generate_exit" });
            // Always dump: every `terrain_generate()` call corresponds to a new terrain texture.
            // Run the dump from this hooked thread to avoid D3D thread-affinity issues.
            try {
                dumpGroundTexture();
            } catch (e) {
                writeLine({ tag: "dump_error", error: "auto-dump after terrain_generate failed: " + String(e) });
            }
        },
    });
}

// Hook grim_set_render_target to track RT state
function hookSetRenderTarget() {
    if (!grimBase) return;

    const addr = grimBase.add(GRIM_RVAS.set_render_target);
    writeLine({ tag: "attach", name: "set_render_target", addr: addr.toString() });

    Interceptor.attach(addr, {
        onEnter: function (args) {
            // First arg is 'this' (ECX in thiscall), actual target is on stack
            // But this is a regular cdecl function, so args[0] is target_index
            // Actually looking at the vtable it takes target_index directly
            // Need to read from stack for cdecl
            const sp = this.context.esp;
            const targetIndex = sp.add(4).readS32();
            currentRenderTarget = targetIndex;

            if (targetIndex !== -1) {
                // Switching to a render target
                const globals = readTerrainGlobals();
                if (globals && globals.terrain_render_target === targetIndex) {
                    terrainRtHandle = targetIndex;
                }
            }
        },
    });
}

// Alternative D3D device capture via CreateDevice hook (unused, kept for reference)
function hookD3DCreateDevice() {
    const d3d8 = findModuleBase(D3D8_MODULE);
    if (!d3d8) return;

    // Find Direct3DCreate8 export
    // We need to hook IDirect3D8::CreateDevice which is called via vtable
    // For simplicity, scan for device pointer when grim calls D3D methods
}

// Initialization
function init() {
    exeBase = findModuleBase(GAME_MODULE);
    grimBase = findModuleBase(GRIM_MODULE);

    if (!exeBase) {
        writeLine({ tag: "waiting", module: GAME_MODULE });
        const waiter = setInterval(function () {
            exeBase = findModuleBase(GAME_MODULE);
            grimBase = findModuleBase(GRIM_MODULE);
            if (exeBase && grimBase) {
                clearInterval(waiter);
                finishInit();
            }
        }, 200);
    } else {
        finishInit();
    }
}

function finishInit() {
    const grim = getGrimInterface();
    if (grim) {
        grimInterface = grim.iface;
        grimVtable = grim.vtable;
    }

    d3dDevice = findD3DDevice();

    writeLine({
        tag: "init",
        exe_base: exeBase ? exeBase.toString() : null,
        grim_base: grimBase ? grimBase.toString() : null,
        grim_interface: grimInterface ? grimInterface.toString() : null,
        grim_vtable: grimVtable ? grimVtable.toString() : null,
        d3d_device: d3dDevice ? d3dDevice.toString() : null,
    });

    hookSrand();
    hookTerrainGenerate();
    hookSetRenderTarget();

    const globals = readTerrainGlobals();
    writeLine({ tag: "terrain_state", globals: globals });

    attached = true;
    writeLine({ tag: "ready", auto_dump: true });
}

// Start
writeLine({ tag: "start", arch: Process.arch, pointer_size: Process.pointerSize });
init();
