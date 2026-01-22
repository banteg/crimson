'use strict';

// Logs creature_spawn_template calls with heading vs. nearest player angle.
//
// Usage (attach):
//   frida -n crimsonland.exe -l C:\share\frida\spawn_heading_probe.js
// Usage (spawn):
//   frida -f "C:\\Crimsonland\\crimsonland.exe" -l C:\share\frida\spawn_heading_probe.js
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
  logPath: joinPath(LOG_DIR, 'crimsonland_spawn_heading.jsonl'),
  logMode: 'append', // append | truncate
  logToConsole: true,
  maxEvents: 0, // 0 = unlimited
  headingRandomSentinel: -100.0,
  headingRandomEpsilon: 0.01,
  maxPlayers: 2,
};

const ADDR = {
  creature_spawn_template: 0x00430af0,
  player_pos_x: 0x004908c4,
  player_pos_y: 0x004908c8,
  player_health_base: 0x004908d4,
  player_stride: 0x360,
  config_player_count: 0x0048035c,
  config_game_mode: 0x00480360,
  quest_stage_major: 0x00487004,
  quest_stage_minor: 0x00487008,
  quest_selected_builder: 0x0048474c,
};

function exePtr(staticVa) {
  const mod = Process.getModuleByName(CONFIG.exeName);
  if (!mod) return null;
  return mod.base.add(ptr(staticVa).sub(CONFIG.linkBase));
}

function nowIso() {
  return new Date().toISOString();
}

function u32ToF32(u) {
  const buf = new ArrayBuffer(4);
  const dv = new DataView(buf);
  dv.setUint32(0, u >>> 0, true);
  return dv.getFloat32(0, true);
}

function argAsF32(arg) {
  return u32ToF32(arg.toUInt32());
}

let LOG = { file: null, ok: false };
let EVENT_COUNT = 0;

function initLog() {
  try {
    const mode = CONFIG.logMode === 'append' ? 'a' : 'w';
    LOG.file = new File(CONFIG.logPath, mode);
    LOG.ok = true;
  } catch (e) {
    console.log('[spawn_heading_probe] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  if (CONFIG.logToConsole) console.log(line);
}

function safeReadS32(ptr) {
  try {
    return ptr.readS32();
  } catch (_) {
    return null;
  }
}

function safeReadFloat(ptr) {
  try {
    return ptr.readFloat();
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
  const countPtr = exePtr(ADDR.config_player_count);
  const modePtr = exePtr(ADDR.config_game_mode);
  const playerCount = countPtr ? safeReadS32(countPtr) : null;
  const gameMode = modePtr ? safeReadS32(modePtr) : null;
  return { player_count: playerCount, game_mode: gameMode };
}

function readPlayers(limit) {
  const players = [];
  const basePos = exePtr(ADDR.player_pos_x);
  const baseHealth = exePtr(ADDR.player_health_base);
  if (!basePos || !baseHealth) return players;
  const count = limit != null ? limit : CONFIG.maxPlayers;
  for (let i = 0; i < count; i++) {
    const healthPtr = baseHealth.add(i * ADDR.player_stride);
    const health = safeReadFloat(healthPtr);
    if (health == null || health <= 0) continue;
    const x = safeReadFloat(basePos.add(i * ADDR.player_stride));
    const y = safeReadFloat(basePos.add(i * ADDR.player_stride + 4));
    if (x == null || y == null) continue;
    players.push({ index: i, x, y, health });
  }
  return players;
}

function pickNearest(spawn, players) {
  let best = null;
  for (const player of players) {
    const dx = player.x - spawn.x;
    const dy = player.y - spawn.y;
    const dist2 = dx * dx + dy * dy;
    if (!best || dist2 < best.dist2) {
      best = { player, dx, dy, dist2 };
    }
  }
  if (!best) return null;
  const angle = Math.atan2(best.dy, best.dx);
  return {
    player: best.player,
    dx: best.dx,
    dy: best.dy,
    dist2: best.dist2,
    angle,
  };
}

function wrapAngle(rad) {
  let value = rad;
  while (value > Math.PI) value -= Math.PI * 2;
  while (value < -Math.PI) value += Math.PI * 2;
  return value;
}

function readBuilderPointer() {
  const ptrAddr = exePtr(ADDR.quest_selected_builder);
  if (!ptrAddr) return null;
  try {
    const builderPtr = ptrAddr.readPointer();
    const mod = Process.getModuleByName(CONFIG.exeName);
    if (!mod) return { addr: builderPtr.toString() };
    const offset = builderPtr.sub(mod.base).toInt32();
    const staticVa = ptr(CONFIG.linkBase).add(offset);
    return { addr: builderPtr.toString(), static_va: staticVa.toString() };
  } catch (_) {
    return null;
  }
}

function main() {
  initLog();
  const targetPtr = exePtr(ADDR.creature_spawn_template);
  if (!targetPtr) {
    writeLog({ event: 'error', error: 'spawn_template_not_found', ts: nowIso() });
    return;
  }

  writeLog({ event: 'start', ts: nowIso(), logPath: CONFIG.logPath });

  Interceptor.attach(targetPtr, {
    onEnter(args) {
      const templateId = args[0].toInt32();
      const posPtr = args[1];
      const heading = argAsF32(args[2]);
      const x = safeReadFloat(posPtr);
      const y = safeReadFloat(posPtr.add(4));
      if (x == null || y == null) return;

      const config = readConfig();
      const stage = readStage();
      const playerLimit = config.player_count != null ? config.player_count : CONFIG.maxPlayers;
      const players = readPlayers(Math.max(playerLimit, CONFIG.maxPlayers));
      const nearest = pickNearest({ x, y }, players);

      const headingIsRandom = Math.abs(heading - CONFIG.headingRandomSentinel) <= CONFIG.headingRandomEpsilon;
      let delta = null;
      let angleToPlayer = null;
      if (!headingIsRandom && nearest) {
        angleToPlayer = nearest.angle;
        delta = wrapAngle(heading - angleToPlayer);
      }

      const builderPtr = readBuilderPointer();

      writeLog({
        event: 'spawn_template',
        ts: nowIso(),
        template_id: templateId,
        pos: { x, y },
        heading,
        heading_is_random: headingIsRandom,
        angle_to_player: angleToPlayer,
        heading_delta: delta,
        nearest_player: nearest
          ? {
              index: nearest.player.index,
              x: nearest.player.x,
              y: nearest.player.y,
              dist2: nearest.dist2,
            }
          : null,
        players,
        stage,
        config,
        builder: builderPtr,
      });

      EVENT_COUNT += 1;
      if (CONFIG.maxEvents > 0 && EVENT_COUNT >= CONFIG.maxEvents) {
        Interceptor.detachAll();
      }
    },
  });
}

main();
