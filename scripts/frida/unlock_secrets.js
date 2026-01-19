'use strict';

// Unlocks/cycles secret weapons for Player 0.

const CONFIG = {
  // Secret weapon IDs to cycle through
  // 32: RayGun
  // 40: Plague Sphreader Gun
  // 41: Bubblegun
  // 42: Rainbow Gun
  // 43: Grim Weapon
  // 49: Transmutator
  // 50: Blaster R-300
  // 51: Lighting Rifle
  // 52: Nuke Launcher
  secretWeaponIds: [32, 40, 41, 42, 43, 49, 50, 51, 52],
  cycleIntervalMs: 5000,
  logPath: 'Z:\\crimsonland_unlock_secrets.jsonl',
};

const LINK_BASE = {
  'crimsonland.exe': ptr('0x00400000'),
};

const ADDR = {
  weapon_assign_player: 0x00452d40, // FUN_00452d40
  player_health_base: 0x004908d4, // DAT_004908d4
};

function exePtr(staticVa) {
  const mod = Process.getModuleByName('crimsonland.exe');
  if (!mod) return null;
  return mod.base.add(ptr(staticVa).sub(LINK_BASE['crimsonland.exe']));
}

function nowIso() {
  return new Date().toISOString();
}

let LOG = { file: null, ok: false };

function initLog() {
  try {
    LOG.file = new File(CONFIG.logPath, 'w');
    LOG.ok = true;
  } catch (e) {
    console.log('[!] Failed to open log: ' + e);
  }
}

function writeLog(obj) {
  const line = JSON.stringify(obj);
  if (LOG.ok) LOG.file.write(line + '\n');
  console.log(line);
}

// Native function wrapper
let fWeaponAssignPlayer = null;

function resolveFunctions() {
  const p = exePtr(ADDR.weapon_assign_player);
  if (!p) return false;
  
  // void __fastcall weapon_assign_player(int player_idx, int weapon_id)
  // fastcall: ecx=arg0, edx=arg1
  fWeaponAssignPlayer = new NativeFunction(p, 'void', ['int', 'int'], 'fastcall');
  return true;
}

function playerExists(idx) {
  const base = exePtr(ADDR.player_health_base);
  if (!base) return false;
  const p = base.add(idx * 0x360);
  try {
    const health = p.readFloat();
    return health > 0;
  } catch (_) {
    return false;
  }
}

function main() {
  initLog();
  if (!resolveFunctions()) {
    writeLog({ event: 'error', error: 'failed_to_resolve_functions' });
    return;
  }

  writeLog({ event: 'start', config: CONFIG });

  let currentIdx = 0;

  setInterval(() => {
    if (!playerExists(0)) {
        // writeLog({ event: 'wait_for_player' });
        return;
    }

    const weaponId = CONFIG.secretWeaponIds[currentIdx];
    writeLog({ event: 'assign_weapon', player_index: 0, weapon_id: weaponId });

    try {
      fWeaponAssignPlayer(0, weaponId);
      writeLog({ event: 'assign_success', weapon_id: weaponId });
    } catch (e) {
      writeLog({ event: 'assign_error', error: '' + e });
    }

    currentIdx = (currentIdx + 1) % CONFIG.secretWeaponIds.length;
  }, CONFIG.cycleIntervalMs);
}

main();
