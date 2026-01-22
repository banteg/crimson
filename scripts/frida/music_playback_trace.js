'use strict';

// Usage:
//   frida -n crimsonland.exe -l C:\share\frida\music_playback_trace.js
//   frida -f "C:\\Crimsonland\\crimsonland.exe" -l C:\share\frida\music_playback_trace.js
//   # then in REPL: %resume

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
  exeName: 'crimsonland.exe',
  linkBase: ptr('0x00400000'),
  logPaths: [joinPath(LOG_DIR, 'music_playback_trace.jsonl')],
  logToConsole: true,
};

const ADDR = {
  music_load_track: 0x0043c8d0,
  music_queue_track: 0x0043c960,
  sfx_play: 0x0043d120,
  sfx_play_exclusive: 0x0043d460,
  sfx_mute_all: 0x0043d550,
};

const trackIdToName = {};
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
    console.log('[music_playback_trace] File logging unavailable, console only.');
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

function hookMusicLoadTrack(addr) {
  Interceptor.attach(addr, {
    onEnter(args) {
      const path = safeReadUtf8(args[0]);
      this._path = path;
    },
    onLeave(retval) {
      const id = retval.toInt32();
      if (this._path) trackIdToName[id] = this._path;
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
      writeLog({
        tag,
        track_id: trackId,
        track_name: trackIdToName[trackId] || null,
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
  const musicLoadPtr = exePtr(mod, ADDR.music_load_track);
  hookMusicLoadTrack(musicLoadPtr);
  hookTrackCall('music_queue_track', exePtr(mod, ADDR.music_queue_track));
  hookTrackCall('sfx_play', exePtr(mod, ADDR.sfx_play));
  hookTrackCall('sfx_play_exclusive', exePtr(mod, ADDR.sfx_play_exclusive));
  hookTrackCall('sfx_mute_all', exePtr(mod, ADDR.sfx_mute_all));
}

setImmediate(() => {
  initLog();
  attachAll();
});
