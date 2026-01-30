"use strict";

// Switch weapons with [ and ] and log weapon-related events.
// Attach only (VM): frida -n crimsonland.exe -l C:\share\frida\weapon_switch_trace.js
// Output: C:\share\frida\weapon_switch_trace.jsonl (or CRIMSON_FRIDA_DIR override)

const DEFAULT_LOG_DIR = "C:\\share\\frida";

function getEnv(key) {
  try {
    return Process.env[key] || null;
  } catch (_) {
    return null;
  }
}

function getLogDir() {
  return getEnv("CRIMSON_FRIDA_DIR") || DEFAULT_LOG_DIR;
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith("\\") || base.endsWith("/") ? "" : "\\";
  return base + sep + leaf;
}

function parseIntEnv(key, fallback) {
  const raw = getEnv(key);
  if (!raw) return fallback;
  const parsed = parseInt(String(raw).trim(), 0);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseOptionalIntEnv(key) {
  const raw = getEnv(key);
  if (!raw) return null;
  const parsed = parseInt(String(raw).trim(), 0);
  return Number.isFinite(parsed) ? parsed : null;
}

const LOG_DIR = getLogDir();
const OUT_PATHS = [joinPath(LOG_DIR, "weapon_switch_trace.jsonl")];

const GAME_MODULE = "crimsonland.exe";
const GRIM_MODULE = "grim.dll";

const CONFIG = {
  playerIndex: parseInt(getEnv("CRIMSON_FRIDA_PLAYER") || "0", 10) || 0,
  weaponMax: parseInt(getEnv("CRIMSON_FRIDA_WEAPON_MAX") || "53", 10) || 53,
  skipLocked: getEnv("CRIMSON_FRIDA_SKIP_LOCKED") !== "0",
  fallbackWeapon: getEnv("CRIMSON_FRIDA_FALLBACK_WEAPON") !== "0",
  logAllSfx: getEnv("CRIMSON_FRIDA_SFX_ALL") !== "0",
  snapshotEvents: getEnv("CRIMSON_FRIDA_SNAPSHOT_EVENTS") === "1",
  oracle: getEnv("CRIMSON_FRIDA_ORACLE") === "1",
  oracleEvery: parseIntEnv("CRIMSON_FRIDA_ORACLE_EVERY", 1),
  oraclePlayerCount: parseIntEnv("CRIMSON_FRIDA_ORACLE_PLAYER_COUNT", 1),
  oracleCreatureLimit: parseIntEnv("CRIMSON_FRIDA_ORACLE_CREATURE_LIMIT", 64),
  creatureLastHitOffset: parseOptionalIntEnv("CRIMSON_FRIDA_CREATURE_LAST_HIT_OFF"),
  keyPrev: 0x1a, // DIK_LBRACKET
  keyNext: 0x1b, // DIK_RBRACKET
};

const ADDR = {
  gameplay_update_and_render: 0x0040aab0,
  survival_gameplay_update_and_render: 0x004457c0,
  weapon_assign_player: 0x00452d40,
  player_fire_weapon: 0x00444980,
  bonus_apply: 0x00409890,
  projectile_spawn: 0x00420440,
  fx_spawn_secondary_projectile: 0x00420360,
  fx_spawn_particle: 0x00420130,
  fx_spawn_particle_slow: 0x00420240,
  effect_spawn: 0x0042e120,
  sfx_play: 0x0043d120,
  sfx_play_panned: 0x0043d260,
  sfx_play_exclusive: 0x0043d460,
  creatures_apply_radius_damage: 0x00420600,
  creature_apply_damage: 0x004207c0,
  projectile_update: 0x00420b90,
};

const DATA = {
  player_health: 0x004908d4,
  player_experience: 0x0049095c,
  player_level: 0x00490964,
  player_weapon_id: 0x00490b70,
  player_clip_size: 0x00490b74,
  player_reload_active: 0x00490b78,
  player_ammo: 0x00490b7c,
  player_reload_timer: 0x00490b80,
  player_shot_cooldown: 0x00490b84,
  player_reload_timer_max: 0x00490b88,
  player_alt_weapon_id: 0x00490b8c,
  player_spread_heat: 0x00490b68,
  player_hot_tempered_timer: 0x0049094c,
  player_man_bomb_timer: 0x00490950,
  player_living_fortress_timer: 0x00490954,
  player_fire_cough_timer: 0x00490958,
  player_speed_bonus_timer: 0x00490bc4,
  player_shield_timer: 0x00490bc8,
  player_fire_bullets_timer: 0x00490bcc,
  weapon_ammo_class: 0x004d7a28,
  weapon_table: 0x004d7a2c,
  creature_pool: 0x0049bf38,
  creature_active_count: 0x00486fcc,
  projectile_pool: 0x004926b8,
  secondary_projectile_pool: 0x00495ad8,
  bonus_pool: 0x00482948,
  bonus_reflex_boost_timer: 0x00487014,
  bonus_freeze_timer: 0x00487018,
  bonus_weapon_power_up_timer: 0x0048701c,
  bonus_energizer_timer: 0x00487020,
  bonus_double_xp_timer: 0x00487024,
};

const GRIM_RVAS = {
  grim_is_key_down: 0x00007320,
};

const LINK_BASE_DEFAULT = ptr("0x00400000");
let LINK_BASE = LINK_BASE_DEFAULT;

const outFiles = {};
let outWarned = false;

const weaponStride = 0x7c;
const playerStride = 0x360;
const creatureStride = 0x98;
const creatureCount = 0x180;
const projectileStride = 0x40;
const secondaryProjectileStride = 0x2c;
const bonusStride = 0x1c;
const bonusCount = 0x10;

const attached = {};
const keyState = {};
const fireContextByTid = {};
const assignContextByTid = {};
const updateContextByTid = {};
const projectileByIndex = new Map();
const projectileTypeToWeapon = new Map();
let pendingInitialWeapon = false;
const oracleState = {
  frame: 0,
  lastXp: {},
  lastLevel: {},
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
    console.log("weapon_switch_trace: file logging unavailable, console only");
  }
  console.log(line.trim());
}

function parseAddrOverrides(raw) {
  const out = { raw: raw, overrides: {}, errors: [] };
  if (!raw) return out;

  const text = String(raw).trim();
  if (!text) return out;

  if (text.startsWith("{")) {
    try {
      const obj = JSON.parse(text);
      if (obj && typeof obj === "object") {
        for (const key in obj) {
          const v = obj[key];
          const parsed = typeof v === "number" ? v : parseInt(String(v).trim(), 0);
          if (!Number.isFinite(parsed)) {
            out.errors.push({ key: key, error: "not_a_number", value: v });
            continue;
          }
          out.overrides[key] = parsed;
        }
      }
    } catch (e) {
      out.errors.push({ error: "json_parse", message: String(e) });
    }
    return out;
  }

  const parts = text
    .split(/[;,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq < 1) {
      out.errors.push({ error: "bad_pair", value: part });
      continue;
    }
    const key = part.slice(0, eq).trim();
    const valueText = part.slice(eq + 1).trim();
    const parsed = parseInt(valueText, 0);
    if (!Number.isFinite(parsed)) {
      out.errors.push({ key: key, error: "not_a_number", value: valueText });
      continue;
    }
    out.overrides[key] = parsed;
  }
  return out;
}

function applyAddrOverrides(addrMap, parsed) {
  const applied = {};
  if (!parsed || !parsed.overrides) return applied;
  for (const key in parsed.overrides) {
    if (!(key in addrMap)) continue;
    addrMap[key] = parsed.overrides[key];
    applied[key] = addrMap[key];
  }
  return applied;
}

function maybeOverrideLinkBase() {
  const raw = getEnv("CRIMSON_FRIDA_LINK_BASE") || getEnv("CRIMSON_FRIDA_IMAGE_BASE");
  if (!raw) return;
  const parsed = parseInt(String(raw).trim(), 0);
  if (!Number.isFinite(parsed)) return;
  LINK_BASE = ptr(parsed);
}

function exePtr(exeModule, addr) {
  if (!exeModule) return null;
  try {
    return exeModule.base.add(ptr(addr).sub(LINK_BASE));
  } catch (_) {
    return null;
  }
}

function grimPtr(grimModule, rva) {
  if (!grimModule) return null;
  try {
    return grimModule.base.add(ptr(rva));
  } catch (_) {
    return null;
  }
}

function safeReadU8(ptrVal) {
  try {
    return ptrVal.readU8();
  } catch (_) {
    return null;
  }
}

function safeReadS32(ptrVal) {
  try {
    return ptrVal.readS32();
  } catch (_) {
    return null;
  }
}

function safeReadF32(ptrVal) {
  try {
    return ptrVal.readFloat();
  } catch (_) {
    return null;
  }
}

function u32ToF32(u32) {
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  view.setUint32(0, u32 >>> 0, true);
  return view.getFloat32(0, true);
}

function argAsF32(arg) {
  if (!arg) return null;
  return u32ToF32(arg.toUInt32());
}

function readFixedCString(ptrVal, maxLen) {
  if (!ptrVal) return null;
  try {
    const bytes = [];
    for (let i = 0; i < maxLen; i++) {
      const b = ptrVal.add(i).readU8();
      if (b === 0) break;
      bytes.push(b);
    }
    if (!bytes.length) return "";
    return String.fromCharCode.apply(null, bytes);
  } catch (_) {
    return null;
  }
}

function readVec2(ptrVal) {
  if (!ptrVal) return null;
  const x = safeReadF32(ptrVal);
  const y = safeReadF32(ptrVal.add(4));
  if (x == null || y == null) return null;
  return { x: x, y: y };
}

function weaponEntryPtr(weaponTable, weaponId) {
  if (!weaponTable) return null;
  return weaponTable.add(weaponId * weaponStride);
}

function weaponSnapshot(weaponTable, weaponAmmoClass, weaponId) {
  const entry = weaponEntryPtr(weaponTable, weaponId);
  if (!entry) return null;

  const ammoClass = weaponAmmoClass
    ? safeReadS32(weaponAmmoClass.add(weaponId * weaponStride))
    : null;
  const name = readFixedCString(entry, 0x40);
  const unlocked = safeReadU8(entry.add(0x40));
  const clipSize = safeReadS32(entry.add(0x44));
  const shotCooldown = safeReadF32(entry.add(0x48));
  const reloadTime = safeReadF32(entry.add(0x4c));
  const spreadHeat = safeReadF32(entry.add(0x50));
  const shotSfxBaseId = safeReadS32(entry.add(0x58));
  const shotSfxVariantCount = safeReadS32(entry.add(0x5c));
  const reloadSfxId = safeReadS32(entry.add(0x60));
  const hudIconId = safeReadS32(entry.add(0x64));
  const flags = safeReadU8(entry.add(0x68));
  const projectileMeta = safeReadF32(entry.add(0x6c));
  const damageScale = safeReadF32(entry.add(0x70));
  const pelletCount = safeReadS32(entry.add(0x74));

  const shotSfxRange =
    shotSfxBaseId != null && shotSfxVariantCount != null
      ? [shotSfxBaseId, shotSfxBaseId + Math.max(0, shotSfxVariantCount - 1)]
      : null;

  const iconIndex = hudIconId;
  const iconFrame = hudIconId != null ? hudIconId * 2 : null;

  return {
    weapon_id: weaponId,
    weapon_id_hex: "0x" + weaponId.toString(16),
    name: name,
    unlocked: unlocked,
    ammo_class: ammoClass,
    clip_size: clipSize,
    shot_cooldown: shotCooldown,
    reload_time: reloadTime,
    spread_heat: spreadHeat,
    shot_sfx_base_id: shotSfxBaseId,
    shot_sfx_variant_count: shotSfxVariantCount,
    shot_sfx_range: shotSfxRange,
    reload_sfx_id: reloadSfxId,
    hud_icon_id: hudIconId,
    hud_icon_index: iconIndex,
    hud_icon_frame: iconFrame,
    flags: flags,
    flag_muzzle_flash: flags != null ? (flags & 0x1) !== 0 : null,
    flag_small_crosshair: flags != null ? (flags & 0x4) !== 0 : null,
    flag_hide_crosshair: flags != null ? (flags & 0x8) !== 0 : null,
    projectile_meta: projectileMeta,
    damage_scale: damageScale,
    pellet_count: pelletCount,
  };
}

function playerAddr(base, playerIndex) {
  if (!base) return null;
  return base.add(playerIndex * playerStride);
}

function readPlayerInt(dataPtr, playerIndex) {
  const addr = playerAddr(dataPtr, playerIndex);
  if (!addr) return null;
  return safeReadS32(addr);
}

function readPlayerF32(dataPtr, playerIndex) {
  const addr = playerAddr(dataPtr, playerIndex);
  if (!addr) return null;
  return safeReadF32(addr);
}

function readBonusTimers(dataPtrs) {
  return {
    reflex_boost: safeReadF32(dataPtrs.bonus_reflex_boost_timer),
    freeze: safeReadF32(dataPtrs.bonus_freeze_timer),
    weapon_power_up: safeReadF32(dataPtrs.bonus_weapon_power_up_timer),
    energizer: safeReadF32(dataPtrs.bonus_energizer_timer),
    double_xp: safeReadF32(dataPtrs.bonus_double_xp_timer),
  };
}

function readBonusEntry(entryPtr) {
  if (!entryPtr) return null;
  return {
    bonus_id: safeReadS32(entryPtr),
    state: safeReadS32(entryPtr.add(0x04)),
    time_left: safeReadF32(entryPtr.add(0x08)),
    time_max: safeReadF32(entryPtr.add(0x0c)),
    pos: readVec2(entryPtr.add(0x10)),
    amount: safeReadF32(entryPtr.add(0x18)),
  };
}

function readCreatureSnapshot(creatureBase, index, lastHitOffset) {
  if (!creatureBase) return null;
  const base = creatureBase.add(index * creatureStride);
  const stateFlag = safeReadU8(base.add(0x08));
  if (!stateFlag) return null;
  const snapshot = {
    index: index,
    state_flag: stateFlag,
    collision_flag: safeReadU8(base.add(0x09)),
    pos: readVec2(base.add(0x14)),
    health: safeReadF32(base.add(0x24)),
    hit_flash_timer: safeReadF32(base.add(0x38)),
    flags: safeReadS32(base.add(0x8c)),
    type_id: safeReadS32(base.add(0x6c)),
    target_player: safeReadS32(base.add(0x70)),
  };
  if (lastHitOffset != null) {
    snapshot.last_hit_owner = safeReadS32(base.add(lastHitOffset));
  }
  return snapshot;
}

function readProjectileSnapshot(projectileBase, index) {
  if (!projectileBase) return null;
  const base = projectileBase.add(index * projectileStride);
  return {
    active: safeReadU8(base),
    angle: safeReadF32(base.add(0x04)),
    pos: readVec2(base.add(0x08)),
    vel: readVec2(base.add(0x18)),
    type_id: safeReadS32(base.add(0x20)),
    life_timer: safeReadF32(base.add(0x24)),
    speed_scale: safeReadF32(base.add(0x2c)),
    damage_pool: safeReadF32(base.add(0x30)),
    hit_radius: safeReadF32(base.add(0x34)),
    base_damage: safeReadF32(base.add(0x38)),
    owner_id: safeReadS32(base.add(0x3c)),
  };
}

function readSecondaryProjectileSnapshot(secondaryBase, index) {
  if (!secondaryBase) return null;
  const base = secondaryBase.add(index * secondaryProjectileStride);
  return {
    active: safeReadU8(base),
    angle: safeReadF32(base.add(0x04)),
    speed: safeReadF32(base.add(0x08)),
    pos: readVec2(base.add(0x0c)),
    vel: readVec2(base.add(0x14)),
    type_id: safeReadS32(base.add(0x1c)),
    lifetime: safeReadF32(base.add(0x20)),
    target_id: safeReadS32(base.add(0x24)),
  };
}

function keyWasPressed(grimIsKeyDown, key) {
  if (!grimIsKeyDown) return false;
  const down = grimIsKeyDown(key) !== 0;
  const prev = !!keyState[key];
  keyState[key] = down;
  return down && !prev;
}

function pickNextWeapon(weaponTable, weaponAmmoClass, currentId, direction) {
  const maxId = CONFIG.weaponMax;
  let next = currentId;
  for (let i = 0; i < maxId; i++) {
    next += direction;
    if (next < 1) next = maxId;
    if (next > maxId) next = 1;
    if (!CONFIG.skipLocked) return next;
    const snap = weaponSnapshot(weaponTable, weaponAmmoClass, next);
    if (snap && snap.unlocked) return next;
  }
  return null;
}

function mapOwnerToPlayer(ownerId) {
  if (ownerId === -1 || ownerId === -100) return 0;
  if (ownerId === -2) return 1;
  if (ownerId === -3) return 2;
  return null;
}

function main() {
  maybeOverrideLinkBase();
  const ADDR_OVERRIDES = parseAddrOverrides(getEnv("CRIMSON_FRIDA_ADDRS"));
  const appliedAddrs = applyAddrOverrides(ADDR, ADDR_OVERRIDES);

  let exeModule = null;
  let grimModule = null;
  try {
    exeModule = Process.getModuleByName(GAME_MODULE);
  } catch (_) {}
  try {
    grimModule = Process.getModuleByName(GRIM_MODULE);
  } catch (_) {}

  if (!exeModule) {
    writeLine({ event: "error", error: "missing_module", module: GAME_MODULE });
    return;
  }

  const addrs = {};
  for (const key in ADDR) {
    addrs[key] = exePtr(exeModule, ADDR[key]);
  }

  const dataPtrs = {};
  for (const key in DATA) {
    dataPtrs[key] = exePtr(exeModule, DATA[key]);
  }

  const grimIsKeyDownPtr = grimPtr(grimModule, GRIM_RVAS.grim_is_key_down);
  const grimIsKeyDown = grimIsKeyDownPtr
    ? new NativeFunction(grimIsKeyDownPtr, "int", ["uint"])
    : null;

  const weaponAssignPlayerPtr = addrs.weapon_assign_player;
  const weaponAssignPlayer = weaponAssignPlayerPtr
    ? new NativeFunction(weaponAssignPlayerPtr, "void", ["int", "int"])
    : null;

  writeLine({
    event: "start",
    config: CONFIG,
    frida: { version: Frida.version, runtime: Script.runtime },
    process: { pid: Process.id, platform: Process.platform, arch: Process.arch },
    module: GAME_MODULE,
    link_base: LINK_BASE.toString(),
    addr_overrides: { applied: appliedAddrs, errors: ADDR_OVERRIDES.errors },
    exe: { base: exeModule.base.toString(), size: exeModule.size, path: exeModule.path },
    grim: grimModule ? { base: grimModule.base.toString(), size: grimModule.size } : null,
    out_path: OUT_PATHS[0],
  });

  function logWeaponSnapshot(tag, weaponId, extra) {
    const snap = weaponSnapshot(dataPtrs.weapon_table, dataPtrs.weapon_ammo_class, weaponId);
    writeLine(Object.assign({ event: tag, weapon: snap }, extra || {}));
  }

  function snapshotForEvent(weaponId) {
    if (!CONFIG.snapshotEvents || weaponId == null) return null;
    return weaponSnapshot(dataPtrs.weapon_table, dataPtrs.weapon_ammo_class, weaponId);
  }

  function currentWeaponId(playerIndex) {
    const idx = playerIndex != null ? playerIndex : CONFIG.playerIndex;
    return readPlayerInt(dataPtrs.player_weapon_id, idx);
  }

  function resolveWeaponContext(opts) {
    const fireCtx = opts && opts.fireCtx ? opts.fireCtx : null;
    const assignCtx = opts && opts.assignCtx ? opts.assignCtx : null;
    const ownerId = opts && opts.ownerId != null ? opts.ownerId : null;

    if (fireCtx && fireCtx.weapon_id != null) {
      return { weapon_id: fireCtx.weapon_id, weapon_source: "fire" };
    }
    if (assignCtx && assignCtx.weapon_id != null) {
      return { weapon_id: assignCtx.weapon_id, weapon_source: "swap" };
    }
    if (ownerId != null) {
      const ownerPlayer = mapOwnerToPlayer(ownerId);
      if (ownerPlayer != null) {
        const wid = currentWeaponId(ownerPlayer);
        if (wid != null) {
          return { weapon_id: wid, weapon_source: "owner_player" };
        }
      }
    }
    if (CONFIG.fallbackWeapon) {
      const wid = currentWeaponId(CONFIG.playerIndex);
      if (wid != null) {
        return { weapon_id: wid, weapon_source: "current_weapon" };
      }
    }
    return { weapon_id: null, weapon_source: null };
  }

  function handleWeaponSwitch() {
    if (!grimIsKeyDown || !weaponAssignPlayer) return;
    const playerIndex = CONFIG.playerIndex;
    const currentId = readPlayerInt(dataPtrs.player_weapon_id, playerIndex);
    if (currentId == null) return;
    if (pendingInitialWeapon && currentId > 0) {
      pendingInitialWeapon = false;
      logWeaponSnapshot("weapon_initial", currentId, { player_index: playerIndex });
    }
    let direction = 0;
    if (keyWasPressed(grimIsKeyDown, CONFIG.keyPrev)) direction = -1;
    if (keyWasPressed(grimIsKeyDown, CONFIG.keyNext)) direction = 1;
    if (!direction) return;

    const nextId = pickNextWeapon(dataPtrs.weapon_table, dataPtrs.weapon_ammo_class, currentId, direction);
    if (nextId == null || nextId === currentId) {
      writeLine({
        event: "weapon_switch_failed",
        player_index: playerIndex,
        from: currentId,
        direction: direction,
      });
      return;
    }
    weaponAssignPlayer(playerIndex, nextId);
    logWeaponSnapshot("weapon_assign", nextId, {
      player_index: playerIndex,
      source: "script_switch",
    });
    logWeaponSnapshot("weapon_switch", nextId, {
      player_index: playerIndex,
      from: currentId,
      to: nextId,
      direction: direction,
    });
  }

  function captureOracleFrame(source) {
    if (!CONFIG.oracle) return;
    oracleState.frame += 1;
    if (CONFIG.oracleEvery > 1 && oracleState.frame % CONFIG.oracleEvery !== 0) return;

    const playerCount = Math.max(1, CONFIG.oraclePlayerCount | 0);
    const players = [];
    for (let i = 0; i < playerCount; i++) {
      const xp = readPlayerInt(dataPtrs.player_experience, i);
      const level = readPlayerInt(dataPtrs.player_level, i);
      const lastXp = oracleState.lastXp[i];
      const lastLevel = oracleState.lastLevel[i];
      const xpDelta = xp != null && lastXp != null ? xp - lastXp : null;
      oracleState.lastXp[i] = xp;
      oracleState.lastLevel[i] = level;
      if (lastLevel != null && level != null && level > lastLevel) {
        writeLine({
          event: "level_up",
          player_index: i,
          from_level: lastLevel,
          to_level: level,
          xp: xp,
        });
      }
      players.push({
        index: i,
        health: readPlayerF32(dataPtrs.player_health, i),
        weapon_id: readPlayerInt(dataPtrs.player_weapon_id, i),
        clip_size: readPlayerInt(dataPtrs.player_clip_size, i),
        ammo: readPlayerInt(dataPtrs.player_ammo, i),
        reload_active: readPlayerInt(dataPtrs.player_reload_active, i),
        reload_timer: readPlayerF32(dataPtrs.player_reload_timer, i),
        reload_timer_max: readPlayerF32(dataPtrs.player_reload_timer_max, i),
        shot_cooldown: readPlayerF32(dataPtrs.player_shot_cooldown, i),
        spread_heat: readPlayerF32(dataPtrs.player_spread_heat, i),
        xp: xp,
        xp_delta: xpDelta,
        level: level,
        perk_timers: {
          hot_tempered: readPlayerF32(dataPtrs.player_hot_tempered_timer, i),
          man_bomb: readPlayerF32(dataPtrs.player_man_bomb_timer, i),
          living_fortress: readPlayerF32(dataPtrs.player_living_fortress_timer, i),
          fire_cough: readPlayerF32(dataPtrs.player_fire_cough_timer, i),
        },
        bonus_timers: {
          speed_bonus: readPlayerF32(dataPtrs.player_speed_bonus_timer, i),
          shield: readPlayerF32(dataPtrs.player_shield_timer, i),
          fire_bullets: readPlayerF32(dataPtrs.player_fire_bullets_timer, i),
        },
      });
    }

    const creatures = [];
    const creatureLimit = CONFIG.oracleCreatureLimit | 0;
    if (creatureLimit !== 0 && dataPtrs.creature_pool) {
      for (let i = 0; i < creatureCount; i++) {
        const snapshot = readCreatureSnapshot(
          dataPtrs.creature_pool,
          i,
          CONFIG.creatureLastHitOffset
        );
        if (!snapshot) continue;
        creatures.push(snapshot);
        if (creatureLimit > 0 && creatures.length >= creatureLimit) break;
      }
    }

    writeLine({
      event: "oracle_frame",
      source: source,
      frame: oracleState.frame,
      players: players,
      creature_active_count: safeReadS32(dataPtrs.creature_active_count),
      creatures: creatures,
      bonus_timers: readBonusTimers(dataPtrs),
    });
  }

  function attachOnce(key, addr, hookFn) {
    if (!addr || attached[key]) return;
    attached[key] = true;
    try {
      Interceptor.attach(addr, hookFn);
      writeLine({ event: "attach", name: key, addr: addr.toString() });
    } catch (e) {
      writeLine({ event: "attach_error", name: key, addr: addr.toString(), error: String(e) });
    }
  }

  attachOnce("gameplay_update_and_render", addrs.gameplay_update_and_render, {
    onEnter() {
      captureOracleFrame("gameplay_update_and_render");
      handleWeaponSwitch();
    },
  });

  attachOnce("survival_gameplay_update_and_render", addrs.survival_gameplay_update_and_render, {
    onEnter() {
      captureOracleFrame("survival_gameplay_update_and_render");
      handleWeaponSwitch();
    },
  });

  attachOnce("weapon_assign_player", addrs.weapon_assign_player, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      const weaponId = args[1].toInt32();
      assignContextByTid[this.threadId] = { player_index: playerIndex, weapon_id: weaponId };
      logWeaponSnapshot("weapon_assign", weaponId, { player_index: playerIndex });
    },
    onLeave() {
      delete assignContextByTid[this.threadId];
    },
  });

  attachOnce("player_fire_weapon", addrs.player_fire_weapon, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      const resolvedPlayer = playerIndex >= 0 ? playerIndex : CONFIG.playerIndex;
      const weaponId = readPlayerInt(dataPtrs.player_weapon_id, resolvedPlayer);
      const clipSize = readPlayerInt(dataPtrs.player_clip_size, resolvedPlayer);
      const ammo = readPlayerInt(dataPtrs.player_ammo, resolvedPlayer);
      fireContextByTid[this.threadId] = {
        player_index: resolvedPlayer,
        weapon_id: weaponId,
      };
      writeLine({
        event: "weapon_fire",
        player_index: resolvedPlayer,
        weapon_id: weaponId,
        clip_size: clipSize,
        ammo: ammo,
      });
    },
    onLeave() {
      delete fireContextByTid[this.threadId];
    },
  });

  attachOnce("bonus_apply", addrs.bonus_apply, {
    onEnter(args) {
      const playerIndex = args[0].toInt32();
      const entryPtr = args[1];
      this._bonusInfo = {
        player_index: playerIndex,
        entry: readBonusEntry(entryPtr),
      };
    },
    onLeave() {
      if (!this._bonusInfo) return;
      writeLine({
        event: "bonus_apply",
        player_index: this._bonusInfo.player_index,
        entry: this._bonusInfo.entry,
        bonus_timers: readBonusTimers(dataPtrs),
      });
      this._bonusInfo = null;
    },
  });

  attachOnce("projectile_update", addrs.projectile_update, {
    onEnter() {
      updateContextByTid[this.threadId] = true;
    },
    onLeave() {
      delete updateContextByTid[this.threadId];
    },
  });

  attachOnce("projectile_spawn", addrs.projectile_spawn, {
    onEnter(args) {
      const pos = readVec2(args[0]);
      const angle = argAsF32(args[1]);
      const typeId = args[2].toInt32();
      const ownerId = args[3].toInt32();
      const fireCtx = fireContextByTid[this.threadId];
      const ctx = resolveWeaponContext({ fireCtx: fireCtx, ownerId: ownerId });
      this._projInfo = {
        pos: pos,
        angle: angle,
        type_id: typeId,
        owner_id: ownerId,
        weapon_id: ctx.weapon_id,
        weapon_source: ctx.weapon_source,
      };
    },
    onLeave(retval) {
      const info = this._projInfo || {};
      const idx = retval.toInt32();
      projectileByIndex.set(idx, {
        type_id: info.type_id,
        weapon_id: info.weapon_id,
        owner_id: info.owner_id,
      });
      if (info.weapon_id != null && info.weapon_source !== "current_weapon") {
        projectileTypeToWeapon.set(info.type_id, info.weapon_id);
      }
      writeLine({
        event: "projectile_spawn",
        index: idx,
        type_id: info.type_id,
        owner_id: info.owner_id,
        weapon_id: info.weapon_id,
        weapon_source: info.weapon_source,
        weapon_snapshot: snapshotForEvent(info.weapon_id),
        projectile_snapshot: readProjectileSnapshot(dataPtrs.projectile_pool, idx),
        pos: info.pos,
        angle: info.angle,
      });
      this._projInfo = null;
    },
  });

  attachOnce("fx_spawn_secondary_projectile", addrs.fx_spawn_secondary_projectile, {
    onEnter(args) {
      const pos = readVec2(args[0]);
      const angle = argAsF32(args[1]);
      const typeId = args[2].toInt32();
      const fireCtx = fireContextByTid[this.threadId];
      const assignCtx = assignContextByTid[this.threadId];
      const ctx = resolveWeaponContext({ fireCtx: fireCtx, assignCtx: assignCtx });
      this._secInfo = {
        pos: pos,
        angle: angle,
        type_id: typeId,
        weapon_id: ctx.weapon_id,
        weapon_source: ctx.weapon_source,
      };
    },
    onLeave(retval) {
      const info = this._secInfo || {};
      writeLine({
        event: "secondary_projectile_spawn",
        index: retval.toInt32(),
        type_id: info.type_id,
        weapon_id: info.weapon_id,
        weapon_source: info.weapon_source,
        weapon_snapshot: snapshotForEvent(info.weapon_id),
        secondary_snapshot: readSecondaryProjectileSnapshot(
          dataPtrs.secondary_projectile_pool,
          retval.toInt32()
        ),
        pos: info.pos,
        angle: info.angle,
      });
      this._secInfo = null;
    },
  });

  attachOnce("fx_spawn_particle", addrs.fx_spawn_particle, {
    onEnter(args) {
      const pos = readVec2(args[0]);
      const angle = argAsF32(args[1]);
      const intensity = argAsF32(args[3]);
      const fireCtx = fireContextByTid[this.threadId];
      const assignCtx = assignContextByTid[this.threadId];
      const ctx = resolveWeaponContext({ fireCtx: fireCtx, assignCtx: assignCtx });
      writeLine({
        event: "particle_spawn",
        slow: false,
        weapon_id: ctx.weapon_id,
        weapon_source: ctx.weapon_source,
        weapon_snapshot: snapshotForEvent(ctx.weapon_id),
        pos: pos,
        angle: angle,
        intensity: intensity,
      });
    },
  });

  attachOnce("fx_spawn_particle_slow", addrs.fx_spawn_particle_slow, {
    onEnter(args) {
      const pos = readVec2(args[0]);
      const angle = argAsF32(args[1]);
      const fireCtx = fireContextByTid[this.threadId];
      const assignCtx = assignContextByTid[this.threadId];
      const ctx = resolveWeaponContext({ fireCtx: fireCtx, assignCtx: assignCtx });
      writeLine({
        event: "particle_spawn",
        slow: true,
        weapon_id: ctx.weapon_id,
        weapon_source: ctx.weapon_source,
        weapon_snapshot: snapshotForEvent(ctx.weapon_id),
        pos: pos,
        angle: angle,
      });
    },
  });

  attachOnce("effect_spawn", addrs.effect_spawn, {
    onEnter(args) {
      const effectId = args[0].toInt32();
      const pos = readVec2(args[1]);
      const fireCtx = fireContextByTid[this.threadId];
      const assignCtx = assignContextByTid[this.threadId];
      const ctx = resolveWeaponContext({ fireCtx: fireCtx, assignCtx: assignCtx });
      const inUpdate = !!updateContextByTid[this.threadId];
      let source = ctx.weapon_source;
      if (!source && inUpdate) {
        source = "projectile_update";
      }
      writeLine({
        event: "effect_spawn",
        effect_id: effectId,
        weapon_id: ctx.weapon_id,
        weapon_source: ctx.weapon_source,
        weapon_snapshot: snapshotForEvent(ctx.weapon_id),
        source: source,
        pos: pos,
      });
    },
  });

  function logSfx(event, sfxId) {
    const fireCtx = fireContextByTid[this.threadId];
    const assignCtx = assignContextByTid[this.threadId];
    const ctx = resolveWeaponContext({ fireCtx: fireCtx, assignCtx: assignCtx });
    if (!ctx.weapon_id && !CONFIG.logAllSfx) return;
    writeLine({
      event: event,
      sfx_id: sfxId,
      weapon_id: ctx.weapon_id,
      weapon_source: ctx.weapon_source,
      weapon_snapshot: snapshotForEvent(ctx.weapon_id),
      source: ctx.weapon_source,
    });
  }

  attachOnce("sfx_play", addrs.sfx_play, {
    onEnter(args) {
      logSfx.call(this, "sfx_play", args[0].toInt32());
    },
  });

  attachOnce("sfx_play_exclusive", addrs.sfx_play_exclusive, {
    onEnter(args) {
      logSfx.call(this, "sfx_play_exclusive", args[0].toInt32());
    },
  });

  attachOnce("sfx_play_panned", addrs.sfx_play_panned, {
    onEnter(args) {
      logSfx.call(this, "sfx_play_panned", args[0].toInt32());
    },
  });

  attachOnce("creature_apply_damage", addrs.creature_apply_damage, {
    onEnter(args) {
      const creatureId = args[0].toInt32();
      const damage = argAsF32(args[1]);
      const damageType = args[2].toInt32();
      const inUpdate = !!updateContextByTid[this.threadId];
      const guessedWeapon = projectileTypeToWeapon.get(damageType) || null;
      writeLine({
        event: "creature_damage",
        creature_id: creatureId,
        damage: damage,
        damage_type: damageType,
        weapon_id_guess: guessedWeapon,
        source: inUpdate ? "projectile_update" : null,
      });
    },
  });

  attachOnce("creatures_apply_radius_damage", addrs.creatures_apply_radius_damage, {
    onEnter(args) {
      const pos = readVec2(args[0]);
      const radius = argAsF32(args[1]);
      const damage = argAsF32(args[2]);
      const damageType = args[3].toInt32();
      const inUpdate = !!updateContextByTid[this.threadId];
      const guessedWeapon = projectileTypeToWeapon.get(damageType) || null;
      writeLine({
        event: "creature_damage_radius",
        pos: pos,
        radius: radius,
        damage: damage,
        damage_type: damageType,
        weapon_id_guess: guessedWeapon,
        source: inUpdate ? "projectile_update" : null,
      });
    },
  });

  const initialWeapon = readPlayerInt(dataPtrs.player_weapon_id, CONFIG.playerIndex);
  if (initialWeapon != null && initialWeapon > 0) {
    logWeaponSnapshot("weapon_initial", initialWeapon, { player_index: CONFIG.playerIndex });
  } else {
    pendingInitialWeapon = true;
  }
}

main();
