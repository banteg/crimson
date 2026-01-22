'use strict';

// Mod API runtime probe for Crimsonland (Frida 17.5.2+).
//
// Goal: confirm mod API vtable slots (log/cvar/texture/sound/music/key/exec + unknowns)
// and capture arguments/returns in one pass while running mods.
//
// Usage (attach):
//   frida -n crimsonland.exe -l C:\\share\\frida\\mod_api_probe.js
//
// Recommended runtime flow:
//   - Start Crimsonland normally.
//   - Open Mods menu, select "Null Mod" and/or "CrimsonRoks".
//   - Enter the mod screen so it runs its update loop.
//
// Output: JSONL written to CONFIG.logPath.

const DEFAULT_LOG_DIR = 'C:\\share\\frida';

function getLogDir() {
  try {
    return Process.env.CRIMSON_FRIDA_DIR || DEFAULT_LOG_DIR;
  } catch (_) {
    return DEFAULT_LOG_DIR;
  }
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith('\\') || base.endsWith('/') ? '' : '\\';
  return base + sep + leaf;
}

const LOG_DIR = getLogDir();

const CONFIG = {
  logPath: joinPath(LOG_DIR, 'crimsonland_mod_api.jsonl'),
  logMode: 'truncate', // truncate | append
  logToConsole: false,
  sendToHost: false,
  includeBacktrace: false,
  backtraceMaxFrames: 10,
  pollIntervalMs: 250,
  vtableScanMax: 0x100, // bytes
  hookUnknownOffsets: true,
};

const LINK_BASE = {
  'crimsonland.exe': 0x00400000,
};

const ADDR = {
  mod_api_context: 0x00481a80,      // DAT_00481a80
  plugin_interface_ptr: 0x004824d4, // DAT_004824d4
};

const MOD_API_KNOWN = {
  0x00: { name: 'api_log', args: ['cstr'] },
  0x04: { name: 'api_find_cvar', args: ['cstr'], ret: 'ptr' },
  0x1c: { name: 'api_fn_0x1c', args: ['f32', 'f32', 'f32', 'f32'] },
  0x28: { name: 'api_load_texture', args: ['cstr'], ret: 'i32' },
  0x2c: { name: 'api_free_texture', args: ['i32'] },
  0x58: { name: 'api_load_sound', args: ['cstr'], ret: 'i32' },
  0x5c: { name: 'api_free_sound', args: ['i32'] },
  0x64: { name: 'api_load_music', args: ['cstr'], ret: 'i32' },
  0x68: { name: 'api_free_music', args: ['i32'] },
  0x74: { name: 'api_key_query', args: ['i32'], ret: 'i32' },
  0x84: { name: 'api_exec_command', args: ['cstr'] },
};

const MOD_IFACE_VTBL = {
  0x00: { name: 'mod_on_enter', args: [] },
  0x04: { name: 'mod_on_exit', args: [] },
  0x08: { name: 'mod_on_update', args: ['i32'], ret: 'i32' },
};

let logFile = null;
let hookedTargets = new Set();
let modApiHooked = false;
let modIfaceHookedPtr = ptr('0');
let lastModApiVtable = ptr('0');
let eventSeq = 0;

function initLog() {
  if (logFile) return;
  try {
    const mode = CONFIG.logMode === 'append' ? 'a' : 'w';
    logFile = new File(CONFIG.logPath, mode);
  } catch (e) {
    console.log('[!] Failed to open log file:', e);
  }
}

function logEvent(obj) {
  obj.seq = ++eventSeq;
  obj.ts = Date.now();
  const line = JSON.stringify(obj);
  if (logFile) {
    logFile.write(line + '\n');
    logFile.flush();
  }
  if (CONFIG.logToConsole) console.log(line);
  if (CONFIG.sendToHost) send(obj);
}

function u32ToFloat(u) {
  const tmp = Memory.alloc(4);
  tmp.writeU32(u >>> 0);
  return tmp.readFloat();
}

function safeReadUtf8(p, maxLen) {
  try {
    if (p.isNull()) return null;
    return p.readUtf8String(maxLen || 260);
  } catch (e) {
    return null;
  }
}

function addrToSymbol(p) {
  try {
    const sym = DebugSymbol.fromAddress(p);
    if (sym && sym.name) return sym.toString();
  } catch (e) {
    // ignore
  }
  return null;
}

function moduleFor(p) {
  try {
    const m = Process.findModuleByAddress(p);
    return m ? m.name : null;
  } catch (e) {
    return null;
  }
}

function vaToPtr(moduleName, va) {
  const mod = Process.getModuleByName(moduleName);
  return mod.base.add(va - LINK_BASE[moduleName]);
}

function ptrInModule(p, moduleName) {
  const mod = Process.getModuleByName(moduleName);
  return p.compare(mod.base) >= 0 && p.compare(mod.base.add(mod.size)) < 0;
}

function decodeArgs(args, spec) {
  const out = [];
  for (let i = 0; i < spec.length; i++) {
    const t = spec[i];
    const a = args[i];
    if (t === 'i32') {
      out.push(a.toInt32());
    } else if (t === 'u32') {
      out.push(a.toUInt32());
    } else if (t === 'f32') {
      out.push(u32ToFloat(a.toUInt32()));
    } else if (t === 'cstr') {
      const s = safeReadUtf8(a);
      out.push(s !== null ? s : a.toString());
    } else if (t === 'ptr') {
      out.push(a.toString());
    } else {
      out.push(a.toString());
    }
  }
  return out;
}

function decodeUnknownArgs(args, count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    const a = args[i];
    const raw = a.toString();
    const asStr = safeReadUtf8(a);
    out.push({ raw, str: asStr });
  }
  return out;
}

function decodeRet(retType, retval) {
  if (!retType) return { raw: retval.toString() };
  if (retType === 'i32') return { i32: retval.toInt32() };
  if (retType === 'u32') return { u32: retval.toUInt32() };
  if (retType === 'f32') return { f32: u32ToFloat(retval.toUInt32()) };
  if (retType === 'ptr') return { ptr: retval.toString() };
  return { raw: retval.toString() };
}

function snapshotVtable(vtblPtr, maxBytes) {
  const entries = [];
  for (let off = 0; off <= maxBytes; off += 4) {
    const fn = vtblPtr.add(off).readPointer();
    if (fn.isNull()) continue;
    entries.push({
      off: '0x' + off.toString(16),
      fn: fn.toString(),
      module: moduleFor(fn),
      symbol: addrToSymbol(fn),
    });
  }
  logEvent({
    kind: 'mod_api_vtable_snapshot',
    vtbl: vtblPtr.toString(),
    entries,
  });
}

function hookVtableEntry(vtblPtr, offset, entry, kind) {
  const fnPtr = vtblPtr.add(offset).readPointer();
  if (fnPtr.isNull()) return;
  const key = fnPtr.toString();
  if (hookedTargets.has(key)) return;
  hookedTargets.add(key);

  const name = entry && entry.name ? entry.name : `vtbl_0x${offset.toString(16)}`;
  const argSpec = entry && entry.args ? entry.args : null;
  const retSpec = entry && entry.ret ? entry.ret : null;

  Interceptor.attach(fnPtr, {
    onEnter(args) {
      this._callMeta = {
        kind,
        name,
        offset: '0x' + offset.toString(16),
        target: fnPtr.toString(),
        targetModule: moduleFor(fnPtr),
        caller: this.returnAddress ? this.returnAddress.toString() : null,
        callerSymbol: this.returnAddress ? addrToSymbol(this.returnAddress) : null,
        threadId: this.threadId,
      };
      if (argSpec) {
        this._callMeta.args = decodeArgs(args, argSpec);
      } else {
        this._callMeta.args = decodeUnknownArgs(args, 6);
      }
      if (CONFIG.includeBacktrace && this.context) {
        const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
          .slice(0, CONFIG.backtraceMaxFrames)
          .map(p => p.toString());
        this._callMeta.backtrace = bt;
      }
    },
    onLeave(retval) {
      if (!this._callMeta) return;
      this._callMeta.ret = decodeRet(retSpec, retval);
      if (name === 'api_find_cvar') {
        try {
          const p = ptr(retval);
          if (!p.isNull()) {
            const vU32 = p.add(8).readU32();
            this._callMeta.ret.cvar_value_u32 = vU32;
            this._callMeta.ret.cvar_value_f32 = u32ToFloat(vU32);
          }
        } catch (e) {
          // ignore
        }
      }
      logEvent(this._callMeta);
    },
  });
}

function hookModApi() {
  const ctxPtr = vaToPtr('crimsonland.exe', ADDR.mod_api_context);
  const vtbl = ctxPtr.readPointer();
  if (vtbl.isNull()) return false;
  if (!ptrInModule(vtbl, 'crimsonland.exe')) return false;
  if (!lastModApiVtable.equals(vtbl)) {
    lastModApiVtable = vtbl;
    snapshotVtable(vtbl, CONFIG.vtableScanMax);
  }

  for (const offStr of Object.keys(MOD_API_KNOWN)) {
    const off = parseInt(offStr, 10);
    hookVtableEntry(vtbl, off, MOD_API_KNOWN[off], 'mod_api_call');
  }

  if (CONFIG.hookUnknownOffsets) {
    for (let off = 0; off <= CONFIG.vtableScanMax; off += 4) {
      if (MOD_API_KNOWN[off]) continue;
      hookVtableEntry(vtbl, off, null, 'mod_api_call');
    }
  }

  return true;
}

function hookModInterface() {
  const ifacePtrAddr = vaToPtr('crimsonland.exe', ADDR.plugin_interface_ptr);
  const ifacePtr = ifacePtrAddr.readPointer();
  if (ifacePtr.isNull()) return false;
  if (ifacePtr.equals(modIfaceHookedPtr)) return true;

  const vtbl = ifacePtr.readPointer();
  if (vtbl.isNull()) return false;

  modIfaceHookedPtr = ifacePtr;
  for (const offStr of Object.keys(MOD_IFACE_VTBL)) {
    const off = parseInt(offStr, 10);
    hookVtableEntry(vtbl, off, MOD_IFACE_VTBL[off], 'mod_iface_call');
  }

  logEvent({
    kind: 'mod_iface_attach',
    iface: ifacePtr.toString(),
    vtbl: vtbl.toString(),
  });
  return true;
}

function main() {
  initLog();
  logEvent({
    kind: 'startup',
    frida: Frida.version,
    runtime: Script.runtime,
    pid: Process.id,
    arch: Process.arch,
  });

  try {
    const obs = Process.attachModuleObserver({
      onAdded(m) {
        if (m.name.toLowerCase().includes('cl_nullmod') || m.name.toLowerCase().includes('cl_crimsonroks')) {
          logEvent({ kind: 'mod_module_load', name: m.name, base: m.base.toString(), size: m.size });
        }
      },
    });
  } catch (e) {
    // attachModuleObserver may not be supported in older runtimes
  }

  const timer = setInterval(() => {
    if (!modApiHooked) {
      modApiHooked = hookModApi();
    } else {
      // keep snapshot fresh if vtable changes
      hookModApi();
    }
    hookModInterface();
  }, CONFIG.pollIntervalMs);
}

setImmediate(main);
