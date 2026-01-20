'use strict';

// Capture Grim2D atlas UV selection at runtime.
// Focus: particles atlas cutting (grid8 vs grid16, clamps, manual UVs).
//
// Usage (attach):
//   frida -n crimsonland.exe -l Z:\atlas_uv_capture.js
// Usage (spawn):
//   frida -f "C:\\Crimsonland\\crimsonland.exe" -l Z:\atlas_uv_capture.js
//   # then in REPL: %resume

const CONFIG = {
  exeName: 'crimsonland.exe',
  grimName: 'grim.dll',
  exeLinkBase: ptr('0x00400000'),
  grimLinkBase: ptr('0x10000000'),

  logPath: 'Z:\\crimsonland_atlas_uv.jsonl',
  logMode: 'append', // append | truncate
  logToConsole: false,

  includeCaller: true,

  // When true, only log events while particles texture is bound.
  onlyParticles: true,
};

const ADDR = {
  particles_texture: 0x0048f7ec,
  bonus_texture: 0x0048f7f0,
  projs_texture: 0x0048f7d4,
};

const GRIM_RVA = {
  bind_texture: 0x07830,
  set_atlas_frame: 0x08230,
  set_sub_rect: 0x082c0,
  set_uv: 0x08350,
  set_uv_point: 0x083a0,
};

const GRIM_UV = {
  u0: 0x1005b290,
  v0: 0x1005b294,
  u1: 0x1005b298,
  v1: 0x1005b29c,
};

const SESSION_ID = Date.now().toString(16) + '-' + Math.floor(Math.random() * 0xfffff).toString(16);

let LOG = { file: null, ok: false };
let hooked = false;

const STATE = {
  boundTextures: {},
  exeBase: null,
  grimBase: null,
  exePtrs: {},
  grimUv: {},
};

function nowIso() {
  return new Date().toISOString();
}

function initLog() {
  try {
    const mode = CONFIG.logMode === 'append' ? 'a' : 'w';
    LOG.file = new File(CONFIG.logPath, mode);
    LOG.ok = true;
  } catch (e) {
    console.log('[atlas_uv_capture] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  obj.session_id = SESSION_ID;
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  if (CONFIG.logToConsole) console.log(line);
}

function safeModule(name) {
  try {
    return Process.getModuleByName(name);
  } catch (_) {
    return null;
  }
}

function toRuntimePtr(moduleBase, linkBase, staticVa) {
  return moduleBase.add(ptr(staticVa).sub(linkBase));
}

function safeReadS32(p) {
  try { return p.readS32(); } catch (_) { return null; }
}

function safeReadF32(p) {
  try { return p.readFloat(); } catch (_) { return null; }
}

function getHandles() {
  const out = {
    particles: null,
    bonuses: null,
    projs: null,
  };
  if (!STATE.exePtrs.particles_texture) return out;
  out.particles = safeReadS32(STATE.exePtrs.particles_texture);
  out.bonuses = safeReadS32(STATE.exePtrs.bonus_texture);
  out.projs = safeReadS32(STATE.exePtrs.projs_texture);
  return out;
}

function labelForHandle(handle, handles) {
  if (handle == null) return null;
  if (handles.particles !== null && handle === handles.particles) return 'particles';
  if (handles.bonuses !== null && handle === handles.bonuses) return 'bonuses';
  if (handles.projs !== null && handle === handles.projs) return 'projs';
  return null;
}

function shouldLogForHandle(handle, handles) {
  if (!CONFIG.onlyParticles) return true;
  if (handles.particles === null) return false;
  return handle === handles.particles;
}

function readUv() {
  return {
    u0: safeReadF32(STATE.grimUv.u0),
    v0: safeReadF32(STATE.grimUv.v0),
    u1: safeReadF32(STATE.grimUv.u1),
    v1: safeReadF32(STATE.grimUv.v1),
  };
}

function formatCaller(addr) {
  if (!CONFIG.includeCaller || !addr) return null;
  const sym = DebugSymbol.fromAddress(addr);
  if (!sym || !sym.moduleName) return addr.toString();
  const offset = sym.address ? sym.address.sub(Module.getBaseAddress(sym.moduleName)) : null;
  return sym.moduleName + (offset ? '+' + offset.toString() : '');
}

function hookBindTexture() {
  const addr = STATE.grimBase.add(GRIM_RVA.bind_texture);
  Interceptor.attach(addr, {
    onEnter(args) {
      const handle = args[0].toInt32();
      const stage = args[1].toInt32();
      STATE.boundTextures[stage] = handle;

      const handles = getHandles();
      const label = labelForHandle(handle, handles);
      if (!shouldLogForHandle(handle, handles)) return;

      writeLog({
        event: 'bind_texture',
        ts: nowIso(),
        handle,
        stage,
        label,
        caller: formatCaller(this.returnAddress),
      });
    }
  });
}

function hookAtlasFrame() {
  const addr = STATE.grimBase.add(GRIM_RVA.set_atlas_frame);
  Interceptor.attach(addr, {
    onEnter(args) {
      this.atlas_size = args[0].toInt32();
      this.frame = args[1].toInt32();
      this.handle = STATE.boundTextures[0] ?? null;
      const handles = getHandles();
      this.label = labelForHandle(this.handle, handles);
      this.shouldLog = shouldLogForHandle(this.handle, handles);
      this.caller = formatCaller(this.returnAddress);
    },
    onLeave() {
      if (!this.shouldLog) return;
      const uv = readUv();
      writeLog({
        event: 'set_atlas_frame',
        ts: nowIso(),
        atlas_size: this.atlas_size,
        frame: this.frame,
        handle: this.handle,
        label: this.label,
        uv,
        caller: this.caller,
      });
    }
  });
}

function hookSubRect() {
  const addr = STATE.grimBase.add(GRIM_RVA.set_sub_rect);
  Interceptor.attach(addr, {
    onEnter(args) {
      this.atlas_size = args[0].toInt32();
      this.width = args[1].toInt32();
      this.height = args[2].toInt32();
      this.frame = args[3].toInt32();
      this.handle = STATE.boundTextures[0] ?? null;
      const handles = getHandles();
      this.label = labelForHandle(this.handle, handles);
      this.shouldLog = shouldLogForHandle(this.handle, handles);
      this.caller = formatCaller(this.returnAddress);
    },
    onLeave() {
      if (!this.shouldLog) return;
      const uv = readUv();
      writeLog({
        event: 'set_sub_rect',
        ts: nowIso(),
        atlas_size: this.atlas_size,
        width: this.width,
        height: this.height,
        frame: this.frame,
        handle: this.handle,
        label: this.label,
        uv,
        caller: this.caller,
      });
    }
  });
}

function hookSetUv() {
  const addr = STATE.grimBase.add(GRIM_RVA.set_uv);
  Interceptor.attach(addr, {
    onEnter(args) {
      const handle = STATE.boundTextures[0] ?? null;
      const handles = getHandles();
      if (!shouldLogForHandle(handle, handles)) return;
      writeLog({
        event: 'set_uv',
        ts: nowIso(),
        u0: args[0].readFloat(),
        v0: args[1].readFloat(),
        u1: args[2].readFloat(),
        v1: args[3].readFloat(),
        handle,
        label: labelForHandle(handle, handles),
        caller: formatCaller(this.returnAddress),
      });
    }
  });
}

function hookSetUvPoint() {
  const addr = STATE.grimBase.add(GRIM_RVA.set_uv_point);
  Interceptor.attach(addr, {
    onEnter(args) {
      const handle = STATE.boundTextures[0] ?? null;
      const handles = getHandles();
      if (!shouldLogForHandle(handle, handles)) return;
      writeLog({
        event: 'set_uv_point',
        ts: nowIso(),
        index: args[0].toInt32(),
        u: args[1].readFloat(),
        v: args[2].readFloat(),
        handle,
        label: labelForHandle(handle, handles),
        caller: formatCaller(this.returnAddress),
      });
    }
  });
}

function installHooks() {
  STATE.exeBase = safeModule(CONFIG.exeName);
  STATE.grimBase = safeModule(CONFIG.grimName);
  if (!STATE.exeBase || !STATE.grimBase) return false;

  STATE.exePtrs.particles_texture = toRuntimePtr(STATE.exeBase.base, CONFIG.exeLinkBase, ADDR.particles_texture);
  STATE.exePtrs.bonus_texture = toRuntimePtr(STATE.exeBase.base, CONFIG.exeLinkBase, ADDR.bonus_texture);
  STATE.exePtrs.projs_texture = toRuntimePtr(STATE.exeBase.base, CONFIG.exeLinkBase, ADDR.projs_texture);

  STATE.grimUv.u0 = toRuntimePtr(STATE.grimBase.base, CONFIG.grimLinkBase, GRIM_UV.u0);
  STATE.grimUv.v0 = toRuntimePtr(STATE.grimBase.base, CONFIG.grimLinkBase, GRIM_UV.v0);
  STATE.grimUv.u1 = toRuntimePtr(STATE.grimBase.base, CONFIG.grimLinkBase, GRIM_UV.u1);
  STATE.grimUv.v1 = toRuntimePtr(STATE.grimBase.base, CONFIG.grimLinkBase, GRIM_UV.v1);

  hookBindTexture();
  hookAtlasFrame();
  hookSubRect();
  hookSetUv();
  hookSetUvPoint();

  writeLog({
    event: 'hooks_installed',
    ts: nowIso(),
    exe_base: STATE.exeBase.base.toString(),
    grim_base: STATE.grimBase.base.toString(),
  });
  return true;
}

initLog();

const waiter = setInterval(function () {
  if (hooked) return;
  if (installHooks()) {
    hooked = true;
    clearInterval(waiter);
  }
}, 200);
