'use strict';

// Logs quest builder metadata + spawn entries whenever a quest builder runs.
//
// Usage (attach):
//   frida -n crimsonland.exe -l Z:\quest_build_dump.js
// Usage (spawn):
//   frida -f "C:\\Crimsonland\\crimsonland.exe" -l Z:\quest_build_dump.js
//   # then in REPL: %resume

const CONFIG = {
  exeName: 'crimsonland.exe',
  linkBase: ptr('0x00400000'),
  logPath: 'Z:\\crimsonland_quest_builds.jsonl',
  logMode: 'append', // append | truncate
  logToConsole: true,
  dumpEntries: true,
  maxEntries: 2048,
};

const ADDR = {
  quest_selected_meta: 0x00484730,
  quest_stage_major: 0x00487004,
  quest_stage_minor: 0x00487008,
  config_full_version: 0x00480790,
  config_player_count: 0x0048035c,
};

const META_STRIDE = 0x2c;
const ENTRY_STRIDE = 24;

const BUILDERS = [
  { va: 0x004343e0, name: 'quest_build_fallback', level: null, title: null },
  { va: 0x00434480, name: 'quest_build_nagolipoli', level: '5.9', title: 'Nagolipoli' },
  { va: 0x00434860, name: 'quest_build_monster_blues', level: '5.8', title: 'Monster Blues' },
  { va: 0x004349c0, name: 'quest_build_the_gathering', level: '5.10', title: 'The Gathering' },
  { va: 0x00434ca0, name: 'quest_build_army_of_three', level: '5.7', title: 'Army of Three' },
  { va: 0x00434f00, name: 'quest_build_knee_deep_in_the_dead', level: '5.5', title: 'Knee-deep in the Dead' },
  { va: 0x00435120, name: 'quest_build_the_gang_wars', level: '5.4', title: 'The Gang Wars' },
  { va: 0x004352d0, name: 'quest_build_the_fortress', level: '5.3', title: 'The Fortress' },
  { va: 0x00435480, name: 'quest_build_cross_fire', level: '5.6', title: 'Cross Fire' },
  { va: 0x00435610, name: 'quest_build_the_beating', level: '5.1', title: 'The Beating' },
  { va: 0x004358a0, name: 'quest_build_the_spanking_of_the_dead', level: '5.2', title: 'The Spanking Of The Dead' },
  { va: 0x00435a30, name: 'quest_build_hidden_evil', level: '3.4', title: 'Hidden Evil' },
  { va: 0x00435bd0, name: 'quest_build_land_hostile', level: '1.1', title: 'Land Hostile' },
  { va: 0x00435cc0, name: 'quest_build_minor_alien_breach', level: '1.2', title: 'Minor Alien Breach' },
  { va: 0x00435ea0, name: 'quest_build_alien_squads', level: '1.8', title: 'Alien Squads' },
  { va: 0x004360a0, name: 'quest_build_zombie_masters', level: '3.10', title: 'Zombie Masters' },
  { va: 0x00436120, name: 'quest_build_8_legged_terror', level: '1.10', title: '8-legged Terror' },
  { va: 0x00436200, name: 'quest_build_ghost_patrols', level: '2.9', title: 'Ghost Patrols' },
  { va: 0x00436350, name: 'quest_build_the_random_factor', level: '1.6', title: 'The Random Factor' },
  { va: 0x00436440, name: 'quest_build_spider_wave_syndrome', level: '1.7', title: 'Spider Wave Syndrome' },
  { va: 0x004364a0, name: 'quest_build_nesting_grounds', level: '1.9', title: 'Nesting Grounds' },
  { va: 0x00436720, name: 'quest_build_alien_dens', level: '1.5', title: 'Alien Dens' },
  { va: 0x00436820, name: 'quest_build_arachnoid_farm', level: '2.3', title: 'Arachnoid Farm' },
  { va: 0x004369a0, name: 'quest_build_gauntlet', level: '4.7', title: 'Gauntlet' },
  { va: 0x00436c10, name: 'quest_build_syntax_terror', level: '4.8', title: 'Syntax Terror' },
  { va: 0x00436d70, name: 'quest_build_spider_spawns', level: '2.2', title: 'Spider Spawns' },
  { va: 0x00436ee0, name: 'quest_build_two_fronts', level: '2.4', title: 'Two Fronts' },
  { va: 0x00437060, name: 'quest_build_survival_of_the_fastest', level: '2.7', title: 'Survival Of The Fastest' },
  { va: 0x004373c0, name: 'quest_build_spideroids', level: '2.10', title: 'Spideroids' },
  { va: 0x004374a0, name: 'quest_build_evil_zombies_at_large', level: '2.6', title: 'Evil Zombies At Large' },
  { va: 0x004375a0, name: 'quest_build_everred_pastures', level: '2.1', title: 'Everred Pastures' },
  { va: 0x00437710, name: 'quest_build_lizard_kings', level: '3.2', title: 'Lizard Kings' },
  { va: 0x00437810, name: 'quest_build_sweep_stakes', level: '2.5', title: 'Sweep Stakes' },
  { va: 0x00437920, name: 'quest_build_deja_vu', level: '3.9', title: 'Deja vu' },
  { va: 0x00437a00, name: 'quest_build_target_practice', level: '1.3', title: 'Target Practice' },
  { va: 0x00437af0, name: 'quest_build_major_alien_breach', level: '4.1', title: 'Major Alien Breach' },
  { va: 0x00437ba0, name: 'quest_build_land_of_lizards', level: '2.8', title: 'Land Of Lizards' },
  { va: 0x00437c70, name: 'quest_build_the_lizquidation', level: '3.6', title: 'The Lizquidation' },
  { va: 0x00437d70, name: 'quest_build_zombie_time', level: '4.2', title: 'Zombie Time' },
  { va: 0x00437e10, name: 'quest_build_frontline_assault', level: '1.4', title: 'Frontline Assault' },
  { va: 0x00437f30, name: 'quest_build_the_collaboration', level: '4.4', title: 'The Collaboration' },
  { va: 0x00438050, name: 'quest_build_the_blighting', level: '3.1', title: 'The Blighting' },
  { va: 0x004382c0, name: 'quest_build_the_annihilation', level: '4.9', title: 'The Annihilation' },
  { va: 0x004383e0, name: 'quest_build_the_massacre', level: '4.5', title: 'The Massacre' },
  { va: 0x004384a0, name: 'quest_build_the_killing', level: '3.3', title: 'The Killing' },
  { va: 0x00438700, name: 'quest_build_lizard_zombie_pact', level: '4.3', title: 'Lizard Zombie Pact' },
  { va: 0x00438840, name: 'quest_build_lizard_raze', level: '3.8', title: 'Lizard Raze' },
  { va: 0x00438940, name: 'quest_build_surrounded_by_reptiles', level: '3.5', title: 'Surrounded By Reptiles' },
  { va: 0x00438a40, name: 'quest_build_the_unblitzkrieg', level: '4.6', title: 'The Unblitzkrieg' },
  { va: 0x00438e10, name: 'quest_build_the_end_of_all', level: '4.10', title: 'The End of All' },
  { va: 0x004390d0, name: 'quest_build_spiders_inc', level: '3.7', title: 'Spiders Inc.' },
];

function exePtr(staticVa) {
  const mod = Process.getModuleByName(CONFIG.exeName);
  if (!mod) return null;
  return mod.base.add(ptr(staticVa).sub(CONFIG.linkBase));
}

function nowIso() {
  return new Date().toISOString();
}

function hexPad(value, width) {
  let hex = value.toString(16);
  while (hex.length < width) hex = '0' + hex;
  return hex;
}

let LOG = { file: null, ok: false };

function initLog() {
  try {
    const mode = CONFIG.logMode === 'append' ? 'a' : 'w';
    LOG.file = new File(CONFIG.logPath, mode);
    LOG.ok = true;
  } catch (e) {
    console.log('[quest_build_dump] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  if (CONFIG.logToConsole) console.log(line);
}

function safeReadPointer(ptr) {
  try {
    return ptr.readPointer();
  } catch (_) {
    return null;
  }
}

function safeReadUtf8(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try {
    return ptr.readUtf8String();
  } catch (_) {
    return null;
  }
}

function safeReadS32(ptr) {
  try {
    return ptr.readS32();
  } catch (_) {
    return null;
  }
}

function safeReadU32(ptr) {
  try {
    return ptr.readU32();
  } catch (_) {
    return null;
  }
}

function readStage() {
  const majorPtr = exePtr(ADDR.quest_stage_major);
  const minorPtr = exePtr(ADDR.quest_stage_minor);
  if (!majorPtr || !minorPtr) return null;
  const major = safeReadS32(majorPtr);
  const minor = safeReadS32(minorPtr);
  if (major == null || minor == null) return null;
  return { major, minor, level: `${major}.${minor}` };
}

function readConfig() {
  const fullPtr = exePtr(ADDR.config_full_version);
  const countPtr = exePtr(ADDR.config_player_count);
  const fullVersion = fullPtr ? safeReadS32(fullPtr) : null;
  const playerCount = countPtr ? safeReadS32(countPtr) : null;
  return {
    full_version: fullVersion,
    player_count: playerCount,
  };
}

function readMeta(index) {
  const base = exePtr(ADDR.quest_selected_meta);
  if (!base) return null;
  if (index == null || index < 0) return null;
  const entryPtr = base.add(index * META_STRIDE);
  const namePtr = safeReadPointer(entryPtr.add(0x0c));
  return {
    index,
    ptr: entryPtr.toString(),
    tier: safeReadS32(entryPtr.add(0x00)),
    quest_index: safeReadS32(entryPtr.add(0x04)),
    time_limit_ms: safeReadS32(entryPtr.add(0x08)),
    name_ptr: namePtr ? namePtr.toString() : null,
    name: safeReadUtf8(namePtr),
    terrain_id: safeReadS32(entryPtr.add(0x10)),
    builder_ptr: (() => {
      const ptr = safeReadPointer(entryPtr.add(0x1c));
      return ptr ? ptr.toString() : null;
    })(),
    unlock_perk_id: safeReadS32(entryPtr.add(0x20)),
    unlock_weapon_id: safeReadS32(entryPtr.add(0x24)),
    start_weapon_id: safeReadS32(entryPtr.add(0x28)),
  };
}

function stageToIndex(stage) {
  if (!stage) return null;
  if (stage.major < 1 || stage.minor < 1) return null;
  return (stage.major - 1) * 10 + (stage.minor - 1);
}

function readEntry(entriesPtr, idx) {
  const base = entriesPtr.add(idx * ENTRY_STRIDE);
  const x = base.readFloat();
  const y = base.add(4).readFloat();
  const heading = base.add(8).readFloat();
  const spawnId = base.add(12).readU32();
  const triggerMs = base.add(16).readU32();
  const count = base.add(20).readU32();
  return {
    index: idx + 1,
    x,
    y,
    heading,
    spawn_id: spawnId,
    spawn_id_hex: '0x' + hexPad(spawnId, 2),
    trigger_ms: triggerMs,
    count,
  };
}

function attachBuilder(builder) {
  const targetPtr = exePtr(builder.va);
  if (!targetPtr) {
    writeLog({
      event: 'error',
      error: 'builder_not_found',
      builder: builder.name,
      va: '0x' + hexPad(builder.va, 8),
      ts: nowIso(),
    });
    return;
  }

  Interceptor.attach(targetPtr, {
    onEnter(args) {
      this.builder = builder;
      this.entriesPtr = args[0];
      this.countPtr = args[1];
      this.stage = readStage();
      this.stageIndex = stageToIndex(this.stage);
      this.meta = readMeta(this.stageIndex);
      this.config = readConfig();
      this.startTs = nowIso();
    },
    onLeave() {
      let count = null;
      try {
        count = this.countPtr.readS32();
      } catch (_) {
        count = null;
      }
      let entries = null;
      let truncated = false;
      if (CONFIG.dumpEntries && this.entriesPtr && count != null) {
        const safeCount = Math.max(0, count);
        const limit = Math.min(safeCount, CONFIG.maxEntries);
        entries = [];
        for (let i = 0; i < limit; i++) {
          try {
            entries.push(readEntry(this.entriesPtr, i));
          } catch (_) {
            entries.push({ index: i + 1, error: 'read_failed' });
          }
        }
        truncated = safeCount > limit;
      }
      writeLog({
        event: 'quest_build',
        ts: nowIso(),
        builder: {
          name: this.builder.name,
          level: this.builder.level,
          title: this.builder.title,
          va: '0x' + hexPad(this.builder.va, 8),
          addr: (() => {
            const ptr = exePtr(this.builder.va);
            return ptr ? ptr.toString() : null;
          })(),
        },
        stage: this.stage,
        stage_index: this.stageIndex,
        meta: this.meta,
        config: this.config,
        entries_ptr: this.entriesPtr ? this.entriesPtr.toString() : null,
        entry_count: count,
        entries_truncated: truncated,
        entries,
      });
    },
  });
}

function main() {
  initLog();
  writeLog({ event: 'start', ts: nowIso(), logPath: CONFIG.logPath });
  for (const builder of BUILDERS) {
    attachBuilder(builder);
  }
}

main();
