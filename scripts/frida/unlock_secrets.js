'use strict';

// Unlocks/cycles secret weapons for Player 0.

const CONFIG = {
  // Secret weapon IDs to cycle through (in-code ids; 0 is dummy/none)
  // 33: RayGun
  // 41: Plague Sphreader Gun
  // 42: Bubblegun
  // 43: Rainbow Gun
  // 44: Grim Weapon
  // 50: Transmutator
  // 51: Blaster R-300
  // 52: Lighting Rifle
  // 53: Nuke Launcher
  secretWeaponIds: [33, 41, 42, 43, 44, 50, 51, 52, 53],
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

function resolveAbi() {
  if (Process.platform !== 'windows') return null;
  if (Process.arch === 'x64') return 'win64';
  if (Process.arch === 'ia32') return 'mscdecl';
  return null;
}

function resolveFunctions() {
  const p = exePtr(ADDR.weapon_assign_player);
  if (!p) return false;
  
  // void __cdecl weapon_assign_player(int player_idx, int weapon_id)
  const abi = resolveAbi();
  fWeaponAssignPlayer = abi
    ? new NativeFunction(p, 'void', ['int', 'int'], abi)
    : new NativeFunction(p, 'void', ['int', 'int']);
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
