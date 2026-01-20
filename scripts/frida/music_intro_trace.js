'use strict';

// Trace where the intro music starts/stops by logging backtraces for
// sfx_play_exclusive / sfx_mute_all calls.
//
// Usage (attach):
//   frida -n crimsonland.exe -l Z:\music_intro_trace.js
// Usage (spawn):
//   frida -f "C:\\Crimsonland\\crimsonland.exe" -l Z:\music_intro_trace.js
//   # then in REPL: %resume

const CONFIG = {
  exeName: 'crimsonland.exe',
  linkBase: ptr('0x00400000'),
  logPaths: ['Z:\\music_intro_trace.jsonl'],
  logToConsole: true,
  maxFrames: 12,
};

const ADDR = {
  music_load_track: 0x0043c8d0,
  sfx_play_exclusive: 0x0043d460,
  sfx_mute_all: 0x0043d550,
};

const trackIdToName = {};
let introTrackId = null;

const LOG = { files: [], ok: false, warned: false };

function exePtr(mod, staticVa) {
  return mod.base.add(ptr(staticVa).sub(CONFIG.linkBase));
}

function nowIso() {
  return new Date().toISOString();
}

function initLog() {
  for (const path of CONFIG.logPaths) {
    try {
      const f = new File(path, 'a');
      LOG.files.push(f);
      LOG.ok = true;
    } catch (_) {}
  }
}

function writeLog(obj) {
  obj.ts = nowIso();
  const line = JSON.stringify(obj);
  if (LOG.ok) {
    for (const f of LOG.files) f.write(line + '\n');
  } else if (!LOG.warned) {
    LOG.warned = true;
    console.log('[music_intro_trace] File logging unavailable, console only.');
  }
  if (CONFIG.logToConsole) console.log(line);
}

function isReadable(ptrVal) {
  try {
    const range = Process.findRangeByAddress(ptrVal);
    return !!range && range.protection.indexOf('r') !== -1;
  } catch (_) {
    return false;
  }
}

function safeReadUtf8(ptrVal) {
  try {
    if (ptrVal.isNull()) return null;
    if (!isReadable(ptrVal)) return null;
    return ptrVal.readUtf8String();
  } catch (_) {
    return null;
  }
}

function staticVa(addr, mod) {
  if (!mod) return null;
  return ptr(CONFIG.linkBase).add(addr.sub(mod.base)).toString();
}

function buildBacktrace(context) {
  const frames = [];
  const addrs = Thread.backtrace(context, Backtracer.ACCURATE)
    .slice(0, CONFIG.maxFrames);
  for (const addr of addrs) {
    const mod = Process.findModuleByAddress(addr);
    const sym = DebugSymbol.fromAddress(addr);
    frames.push({
      address: addr.toString(),
      module: mod ? mod.name : null,
      offset: mod ? addr.sub(mod.base).toString() : null,
      static_va: mod ? staticVa(addr, mod) : null,
      symbol: sym && sym.name ? sym.name : null,
    });
  }
  return frames;
}

function hookMusicLoadTrack(addr) {
  Interceptor.attach(addr, {
    onEnter(args) {
      this._path = safeReadUtf8(args[0]);
    },
    onLeave(retval) {
      const id = retval.toInt32();
      if (this._path) {
        trackIdToName[id] = this._path;
        if (this._path.indexOf('intro.ogg') !== -1) {
          introTrackId = id;
        }
      }
      writeLog({
        tag: 'music_load_track',
        track_id: id,
        path: this._path,
      });
    },
  });
}

function hookTrackCall(tag, addr) {
  Interceptor.attach(addr, {
    onEnter(args) {
      const trackId = args[0].toInt32();
      const name = trackIdToName[trackId] || null;
      const isIntro = introTrackId !== null && trackId === introTrackId;
      writeLog({
        tag,
        track_id: trackId,
        track_name: name,
        intro_track_id: introTrackId,
        interesting: isIntro,
        return_address: this.returnAddress ? this.returnAddress.toString() : null,
        backtrace: buildBacktrace(this.context),
      });
    },
  });
}

function attachAll() {
  const mod = Process.findModuleByName(CONFIG.exeName);
  if (!mod) {
    writeLog({ tag: 'error', error: 'exe_not_found', exe: CONFIG.exeName });
    return;
  }
  writeLog({ tag: 'start', base: mod.base.toString(), arch: Process.arch });
  hookMusicLoadTrack(exePtr(mod, ADDR.music_load_track));
  hookTrackCall('sfx_play_exclusive', exePtr(mod, ADDR.sfx_play_exclusive));
  hookTrackCall('sfx_mute_all', exePtr(mod, ADDR.sfx_mute_all));
}

setImmediate(() => {
  initLog();
  attachAll();
});
