'use strict';

// Logs the quest entry count for "The Spanking Of The Dead" builder.
//
// Usage (attach):
//   frida -n crimsonland.exe -l C:\\share\\frida\\quest_spanking_count.js
// Attach only: spawning via frida -f is unstable on this VM.

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
  target: {
    name: 'quest_build_the_spanking_of_the_dead',
    va: 0x004358a0,
  },
  logPath: joinPath(LOG_DIR, 'crimsonland_quest_counts.jsonl'),
  logMode: 'append', // append | truncate
  logToConsole: true,
  stopAfterFirst: true,
};

function exePtr(staticVa) {
  const mod = Process.getModuleByName(CONFIG.exeName);
  if (!mod) return null;
  return mod.base.add(ptr(staticVa).sub(CONFIG.linkBase));
}

function nowIso() {
  return new Date().toISOString();
}

let LOG = { file: null, ok: false };

function initLog() {
  try {
    const mode = CONFIG.logMode === 'append' ? 'a' : 'w';
    LOG.file = new File(CONFIG.logPath, mode);
    LOG.ok = true;
  } catch (e) {
    console.log('[quest_count] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  if (CONFIG.logToConsole) console.log(line);
}

function main() {
  initLog();
  const targetPtr = exePtr(CONFIG.target.va);
  if (!targetPtr) {
    writeLog({ event: 'error', error: 'module_not_found', module: CONFIG.exeName });
    return;
  }

  writeLog({
    event: 'start',
    target: CONFIG.target.name,
    va: '0x' + CONFIG.target.va.toString(16),
    addr: targetPtr.toString(),
    ts: nowIso(),
  });

  Interceptor.attach(targetPtr, {
    onEnter(args) {
      this.entriesPtr = args[0];
      this.countPtr = args[1];
    },
    onLeave() {
      let count = null;
      try {
        count = this.countPtr.readS32();
      } catch (e) {
        writeLog({ event: 'error', error: 'read_count_failed', detail: '' + e });
        return;
      }
      writeLog({
        event: 'quest_count',
        target: CONFIG.target.name,
        count,
        entries: this.entriesPtr ? this.entriesPtr.toString() : null,
        ts: nowIso(),
      });
      if (CONFIG.stopAfterFirst) {
        Interceptor.detachAll();
      }
    },
  });
}

main();
