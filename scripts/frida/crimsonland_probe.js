'use strict';

// Crimsonland v1.9.93 (crimsonland.exe + grim.dll) runtime probe helpers.
//
// Goals:
// - Confirm what we "think" we know (struct offsets, IDs, call patterns) by logging
//   concrete runtime values.
// - Surface what we *don't* know by tracking which player-struct offsets change often
//   outside the current "known" map.
//
// Usage (attach):
//   frida -p <pid> -l Z:\\crimsonland_probe.js
// Usage (spawn early):
//   frida -f "C:\\Crimsonland\\crimsonland.exe" -l Z:\\crimsonland_probe.js
//   # then in REPL: %resume
//
// Tip: edit CONFIG.logPath to a writable location in the VM.

const CONFIG = {
  // Where to write JSONL logs. If opening fails, we fall back to console-only.
  logPath: 'Z:\\crimsonland_frida_hits.jsonl',

  // If true, also send() every event to the host.
  sendToHost: false,

  // If true, also print JSONL to the Frida console.
  logToConsole: false,

  // Light caller info: include the immediate return address symbol.
  includeCaller: true,

  // Expensive: full backtraces. Keep off unless you need it.
  includeBacktrace: false,
  backtraceMaxFrames: 12,

  // Hook high-level gameplay events (spawn, damage, weapon swap, SFX).
  hookGameplay: true,

  // Hook some resource calls (texture loads).
  hookResources: true,

  // Hook Win32 file IO for game-relevant extensions (CreateFileW/A).
  hookWin32FileIO: false,
  fileIoExts: ['.paq', '.jaz', '.dat', '.ogg', '.wav', '.ini', '.cfg'],

  // Hook grim.dll vtable methods (validated/backlog set). Runs once interface pointer is live.
  hookGrimVtable: true,

  // Keep grim vtable hooks fairly low-noise by default.
  hotWindowMs: 2000,
  hotWindowAutoStart: false,
  grimVtableTargets: {
    // Backlog / low callsite validation targets (from docs/grim2d-api.md + docs/grim2d-runtime-validation.md)
    0x000: { name: 'grim_release', args: [] },
    0x004: { name: 'grim_set_paused', args: ['i32'] },
    0x008: { name: 'grim_get_version', args: [] },
    0x00C: { name: 'grim_check_device', args: [] },
    0x010: { name: 'grim_apply_config', args: [] },
    0x014: { name: 'grim_init_system', args: [] },
    0x018: { name: 'grim_shutdown', args: [] },
    0x01C: { name: 'grim_apply_settings', args: [] },
    0x024: { name: 'grim_get_config_var', args: ['ptr', 'i32'] },
    0x028: { name: 'grim_get_error_text', args: [] },

    0x034: { name: 'grim_get_time_ms', args: [] },
    0x038: { name: 'grim_set_time_ms', args: ['i32'] },
    0x03C: { name: 'grim_get_frame_dt', args: [] },
    0x040: { name: 'grim_get_fps', args: [] },

    0x048: { name: 'grim_was_key_pressed', args: ['i32'] },
    0x04C: { name: 'grim_flush_input', args: [] },
    0x050: { name: 'grim_get_key_char', args: [] },
    0x054: { name: 'grim_set_key_char_buffer', args: ['ptr', 'ptr', 'i32'] },

    0x05C: { name: 'grim_was_mouse_button_pressed', args: ['i32'] },
    0x060: { name: 'grim_get_mouse_wheel_delta', args: [] },
    0x064: { name: 'grim_set_mouse_pos', args: ['f32', 'f32'] },
    0x068: { name: 'grim_get_mouse_x', args: [] },
    0x06C: { name: 'grim_get_mouse_y', args: [] },
    0x070: { name: 'grim_get_mouse_dx', args: [] },
    0x074: { name: 'grim_get_mouse_dy', args: [] },
    0x078: { name: 'grim_get_mouse_dx_indexed', args: ['i32'] },
    0x07C: { name: 'grim_get_mouse_dy_indexed', args: ['i32'] },

    0x088: { name: 'grim_get_slot_float', args: ['i32'] },
    0x08C: { name: 'grim_get_slot_int', args: ['i32'] },
    0x090: { name: 'grim_set_slot_float', args: ['i32', 'f32'] },
    0x094: { name: 'grim_set_slot_int', args: ['i32', 'i32'] },

    0x0B0: { name: 'grim_recreate_texture', args: ['i32'] },
    0x0B4: { name: 'grim_load_texture', args: ['cstr', 'cstr'] },
    0x0B8: { name: 'grim_validate_texture', args: ['i32'] },
    0x0BC: { name: 'grim_destroy_texture', args: ['i32'] },
    0x0C0: { name: 'grim_get_texture_handle', args: ['cstr'] },
    0x0C4: { name: 'grim_bind_texture', args: ['i32', 'i32'] },

    0x0E8: { name: 'grim_begin_batch', args: [] },
    0x0EC: { name: 'grim_flush_batch', args: [] },
    0x0F0: { name: 'grim_end_batch', args: [] },

    // Core draw/state calls are very hot; only log inside the hot-window.
    0x020: { name: 'grim_set_render_state', args: ['i32', 'i32'], hot: true },
    0x114: { name: 'grim_set_color', args: ['f32','f32','f32','f32'], hot: true },
    0x11C: { name: 'grim_draw_quad', args: ['f32','f32','f32','f32'], hot: true },
  },

  // Periodic player-struct unknown-field tracker.
  playerUnknownFieldTracking: {
    enabled: true,
    playerIndex: 0,
    intervalMs: 250,
    reportEveryMs: 5000,
    topN: 15,
  },

  // Print a one-time sanity summary at startup.
  printStartupSummary: true,

  // String decode heuristics (texture names, etc).
  stringMaxLen: 260,
  stringQualityMin: 0.85,
};

const SESSION_ID = Date.now().toString(16) + '-' + Math.floor(Math.random() * 0xfffff).toString(16);

// Link-time image bases used by the static maps in the archive.
// These are needed to convert static VAs (0x004xxxxx / 0x100xxxxx) into runtime pointers under ASLR.
const LINK_BASE = {
  'crimsonland.exe': ptr('0x00400000'),
  'grim.dll': ptr('0x10000000'),
};

// Known addresses from docs/data_map.json (static VAs).
const ADDR = {
  // crimsonland.exe globals
  grim_interface_ptr: 0x0048083c, // DAT_0048083c
  player_health_base: 0x004908d4, // DAT_004908d4
  projectile_pool_base: 0x004926b8, // DAT_004926b8
  creature_pool_base: 0x0049bf38, // DAT_0049bf38
  weapon_table_base: 0x004d7a2c, // DAT_004d7a2c (name buffer start)
  weapon_ammo_class_base: 0x004d7a28, // DAT_004d7a28

  // crimsonland.exe functions (static VAs from analysis/ghidra/maps/name_map.json)
  grim_load_interface: 0x0041dc80,
  crimsonland_main: 0x0042c450,
  texture_get_or_load: 0x0042a670,
  texture_get_or_load_alt: 0x0042a700,

  bonus_apply: 0x00409890,
  weapon_table_init: 0x004519b0,
  weapon_assign_player: 0x00452d40,
  player_take_damage: 0x00425e50,

  projectile_spawn: 0x00420440,
  creature_spawn: 0x00428240,

  sfx_play: 0x0043d120,
  sfx_play_panned: 0x0043d260,
  sfx_play_exclusive: 0x0043d460,
};

// Struct sizing facts from docs.
const SIZES = {
  player_stride: 0x360,
  projectile_stride: 0x40,
  projectile_count: 0x60,
  creature_stride: 0x98,
  creature_count: 0x180,
  weapon_stride: 0x7c,
};

// ---------------------------
// Utility helpers
// ---------------------------

function nowIso() {
  return new Date().toISOString();
}

function safeGetModule(name) {
  const want = name.toLowerCase();
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    if (mods[i].name.toLowerCase() === want) return mods[i];
  }
  return null;
}

function toRuntimePtr(moduleName, staticVa) {
  const mod = safeGetModule(moduleName);
  if (!mod) return null;
  const link = LINK_BASE[moduleName];
  if (!link) throw new Error('Missing LINK_BASE for ' + moduleName);
  return mod.base.add(ptr(staticVa).sub(link));
}

function tryReadU8(p) {
  try { return p.readU8(); } catch (_) { return null; }
}
function tryReadS32(p) {
  try { return p.readS32(); } catch (_) { return null; }
}
function tryReadU32(p) {
  try { return p.readU32(); } catch (_) { return null; }
}
function tryReadFloat(p) {
  try { return p.readFloat(); } catch (_) { return null; }
}
function tryReadPtr(p) {
  try { return p.readPointer(); } catch (_) { return null; }
}
function tryReadAnsi(p, maxLen) {
  try {
    if (p.isNull()) return null;
    if (typeof p.readCString === 'function') return p.readCString(maxLen);
    if (typeof p.readUtf8String === 'function') return p.readUtf8String(maxLen);
    return null;
  } catch (_) {
    return null;
  }
}
function tryReadUtf16(p, maxLen) {
  try {
    if (p.isNull()) return null;
    if (typeof p.readUtf16String === 'function') return p.readUtf16String(maxLen);
    return null;
  } catch (_) {
    return null;
  }
}

function stringQuality(str) {
  if (!str) return 0;
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 32 && code < 127) || code === 9) printable++;
  }
  return printable / str.length;
}

function scoreString(str, quality) {
  if (!str) return 0;
  let score = quality;
  const lower = str.toLowerCase();
  if (lower.indexOf("\\") >= 0 || lower.indexOf("/") >= 0) score += 0.2;
  if (lower.indexOf(".") >= 0) score += 0.1;
  if (lower.endsWith(".jaz") || lower.endsWith(".jpg") || lower.endsWith(".png") || lower.endsWith(".tga")) {
    score += 0.4;
  }
  if (str.length < 3) score -= 0.2;
  if (str.length > 260) score -= 0.3;
  return score;
}

function pickBestString(candidates) {
  if (!candidates.length) return null;
  candidates.sort((a, b) => b.score - a.score);
  return candidates[0];
}

function readBestString(ptrArg, maxLen) {
  const candidates = [];
  const directAnsi = tryReadAnsi(ptrArg, maxLen);
  if (directAnsi && directAnsi.length) {
    const quality = stringQuality(directAnsi);
    candidates.push({
      value: directAnsi,
      via: 'ansi',
      ptr: ptrArg,
      ptr2: null,
      quality,
      score: scoreString(directAnsi, quality),
    });
  }

  const directUtf16 = tryReadUtf16(ptrArg, maxLen);
  if (directUtf16 && directUtf16.length) {
    const quality = stringQuality(directUtf16);
    candidates.push({
      value: directUtf16,
      via: 'utf16',
      ptr: ptrArg,
      ptr2: null,
      quality,
      score: scoreString(directUtf16, quality),
    });
  }

  const ptr2 = tryReadPtr(ptrArg);
  if (ptr2 && !ptr2.isNull()) {
    const indirectAnsi = tryReadAnsi(ptr2, maxLen);
    if (indirectAnsi && indirectAnsi.length) {
      const quality = stringQuality(indirectAnsi);
      candidates.push({
        value: indirectAnsi,
        via: 'ansi*',
        ptr: ptrArg,
        ptr2,
        quality,
        score: scoreString(indirectAnsi, quality),
      });
    }
    const indirectUtf16 = tryReadUtf16(ptr2, maxLen);
    if (indirectUtf16 && indirectUtf16.length) {
      const quality = stringQuality(indirectUtf16);
      candidates.push({
        value: indirectUtf16,
        via: 'utf16*',
        ptr: ptrArg,
        ptr2,
        quality,
        score: scoreString(indirectUtf16, quality),
      });
    }
  }

  const best = pickBestString(candidates);
  if (!best) {
    return {
      name: null,
      name_via: null,
      name_ptr: ptrArg ? ptrArg.toString() : null,
      name_ptr2: null,
      name_quality: null,
      name_score: null,
      name_len: null,
    };
  }

  const ok =
    best.quality >= CONFIG.stringQualityMin &&
    best.value.length <= CONFIG.stringMaxLen;

  return {
    name: ok ? best.value : null,
    name_via: best.via,
    name_ptr: best.ptr ? best.ptr.toString() : null,
    name_ptr2: best.ptr2 ? best.ptr2.toString() : null,
    name_quality: best.quality,
    name_score: best.score,
    name_len: best.value.length,
    name_raw: ok ? null : best.value,
  };
}

function u32ToF32(u) {
  const buf = new ArrayBuffer(4);
  const dv = new DataView(buf);
  dv.setUint32(0, u >>> 0, true);
  return dv.getFloat32(0, true);
}

function argAsI32(arg) {
  return arg.toInt32();
}

function argAsU32(arg) {
  return arg.toUInt32();
}

function argAsF32(arg) {
  // Interceptor passes stack args as NativePointer. For x86, floats are 32-bit values.
  return u32ToF32(arg.toUInt32());
}

function isReadablePtr(p) {
  if (p.isNull()) return false;
  try {
    return Process.findRangeByAddress(p) !== null;
  } catch (_) {
    return false;
  }
}

function formatArgGuess(arg) {
  // Useful when a signature is uncertain: show interpretations.
  const u = arg.toUInt32();
  const i = arg.toInt32();
  const f = u32ToF32(u);
  const p = ptr(u);
  const ptrOk = isReadablePtr(p);

  let s = null;
  if (ptrOk) {
    s = tryReadAnsi(p, 80);
  }

  return {
    raw_u32: u >>> 0,
    raw_hex: '0x' + (u >>> 0).toString(16),
    as_i32: i,
    as_f32: f,
    as_ptr: ptrOk ? p.toString() : null,
    as_cstr: s,
  };
}

// ---------------------------
// Logging
// ---------------------------

let LOG = {
  file: null,
  ok: false,
};

function initLogFile() {
  try {
    LOG.file = new File(CONFIG.logPath, 'a');
    LOG.ok = true;
    writeLine({ event: 'log_open', ts: nowIso(), path: CONFIG.logPath });
  } catch (e) {
    LOG.file = null;
    LOG.ok = false;
    console.log('[!] Failed to open logPath=' + CONFIG.logPath + ' : ' + e);
  }
}

function writeLine(obj) {
  // JSONL
  if (!obj.session_id) obj.session_id = SESSION_ID;
  const line = JSON.stringify(obj);
  if (LOG.ok && LOG.file) {
    try {
      LOG.file.write(line + '\n');
      // Flush frequently; JSONL is small and we want minimal loss on crash.
      if (typeof LOG.file.flush === 'function') {
        LOG.file.flush();
      }
    } catch (e) {
      console.log('[!] log write failed: ' + e);
      LOG.ok = false;
    }
  }
  if (CONFIG.logToConsole) {
    console.log(line);
  }
  if (CONFIG.sendToHost) {
    try { send(obj); } catch (_) {}
  }
}

function symbolicate(addr) {
  try {
    return DebugSymbol.fromAddress(addr).toString();
  } catch (_) {
    return addr.toString();
  }
}

function captureBacktrace(context) {
  try {
    const frames = Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, CONFIG.backtraceMaxFrames)
      .map(symbolicate);
    return frames;
  } catch (_) {
    return null;
  }
}

// ---------------------------
// Domain helpers: structs
// ---------------------------

function exePtr(staticVa) {
  return toRuntimePtr('crimsonland.exe', staticVa);
}

function playerBase(playerIndex) {
  const base = exePtr(ADDR.player_health_base);
  if (!base) return null;
  return base.add(playerIndex * SIZES.player_stride);
}

function readPlayer(playerIndex) {
  const b = playerBase(playerIndex);
  if (!b) return null;

  // Negative offsets live before player_health base.
  const posX = tryReadFloat(b.sub(0x10));
  const posY = tryReadFloat(b.sub(0x0c));
  const deathTimer = tryReadFloat(b.sub(0x14));
  const moveDx = tryReadFloat(b.sub(0x08));
  const moveDy = tryReadFloat(b.sub(0x04));
  const plagueActive = tryReadU8(b.sub(0x1b));

  const out = {
    index: playerIndex,
    base: b.toString(),
    health_f32: tryReadFloat(b.add(0x00)),
    heading_f32: tryReadFloat(b.add(0x08)),
    size_f32: tryReadFloat(b.add(0x10)),

    pos: [posX, posY],
    move: [moveDx, moveDy],
    death_timer: deathTimer,
    plaguebearer_active_u8: plagueActive,

    aim: [tryReadFloat(b.add(0x2c)), tryReadFloat(b.add(0x30))],

    speed_mult_f32: tryReadFloat(b.add(0x38)),
    weapon_reset_latch_i32: tryReadS32(b.add(0x3c)),
    move_speed_f32: tryReadFloat(b.add(0x44)),
    move_phase_f32: tryReadFloat(b.add(0x70)),

    xp_i32: tryReadS32(b.add(0x88)),
    level_i32: tryReadS32(b.add(0x90)),

    spread_heat_f32: tryReadFloat(b.add(0x294)),

    weapon_id_i32: tryReadS32(b.add(0x29c)),
    clip_size_i32: tryReadS32(b.add(0x2a0)),
    reload_active_i32: tryReadS32(b.add(0x2a4)),
    ammo_i32: tryReadS32(b.add(0x2a8)),

    reload_timer_f32: tryReadFloat(b.add(0x2ac)),
    shot_cooldown_f32: tryReadFloat(b.add(0x2b0)),
    reload_timer_max_f32: tryReadFloat(b.add(0x2b4)),

    alt_weapon_id_i32: tryReadS32(b.add(0x2b8)),

    muzzle_flash_alpha_f32: tryReadFloat(b.add(0x2d8)),
    aim_heading_f32: tryReadFloat(b.add(0x2dc)),

    low_health_timer_f32: tryReadFloat(b.add(0x2ec)),

    speed_bonus_timer_f32: tryReadFloat(b.add(0x2f0)),
    shield_timer_f32: tryReadFloat(b.add(0x2f4)),
    fire_bullets_timer_f32: tryReadFloat(b.add(0x2f8)),

    auto_target_i32: tryReadS32(b.add(0x2fc)),
  };

  return out;
}

function dumpPlayer(playerIndex) {
  const p = readPlayer(playerIndex);
  writeLine({ event: 'dump_player', ts: nowIso(), player: p });
  return p;
}

function projectileBase(idx) {
  const base = exePtr(ADDR.projectile_pool_base);
  if (!base) return null;
  return base.add(idx * SIZES.projectile_stride);
}

function readProjectile(idx) {
  const b = projectileBase(idx);
  if (!b) return null;
  return {
    index: idx,
    base: b.toString(),
    active_u8: tryReadU8(b.add(0x00)),
    angle_f32: tryReadFloat(b.add(0x04)),
    pos: [tryReadFloat(b.add(0x08)), tryReadFloat(b.add(0x0c))],
    origin: [tryReadFloat(b.add(0x10)), tryReadFloat(b.add(0x14))],
    vel: [tryReadFloat(b.add(0x18)), tryReadFloat(b.add(0x1c))],
    type_id_i32: tryReadS32(b.add(0x20)),
    life_timer_f32: tryReadFloat(b.add(0x24)),
    speed_scale_f32: tryReadFloat(b.add(0x2c)),
    damage_pool_f32: tryReadFloat(b.add(0x30)),
    hit_radius_f32: tryReadFloat(b.add(0x34)),
    base_damage_f32: tryReadFloat(b.add(0x38)),
    owner_id_i32: tryReadS32(b.add(0x3c)),
  };
}

function dumpProjectile(idx) {
  const p = readProjectile(idx);
  writeLine({ event: 'dump_projectile', ts: nowIso(), projectile: p });
  return p;
}

function creatureBase(idx) {
  const base = exePtr(ADDR.creature_pool_base);
  if (!base) return null;
  return base.add(idx * SIZES.creature_stride);
}

function readCreature(idx) {
  const b = creatureBase(idx);
  if (!b) return null;
  return {
    index: idx,
    base: b.toString(),
    active_u8: tryReadU8(b.add(0x00)),
    phase_seed_f32: tryReadFloat(b.add(0x04)),
    state_flag_u8: tryReadU8(b.add(0x08)),
    collision_flag_u8: tryReadU8(b.add(0x09)),
    collision_timer_f32: tryReadFloat(b.add(0x0c)),
    hitbox_size_f32: tryReadFloat(b.add(0x10)),
    pos: [tryReadFloat(b.add(0x14)), tryReadFloat(b.add(0x18))],
    vel: [tryReadFloat(b.add(0x1c)), tryReadFloat(b.add(0x20))],
    health_f32: tryReadFloat(b.add(0x24)),
    max_health_f32: tryReadFloat(b.add(0x28)),
    heading_f32: tryReadFloat(b.add(0x2c)),
    target_heading_f32: tryReadFloat(b.add(0x30)),
    size_f32: tryReadFloat(b.add(0x34)),
    hit_flash_timer_f32: tryReadFloat(b.add(0x38)),
    tint: [tryReadFloat(b.add(0x3c)), tryReadFloat(b.add(0x40)), tryReadFloat(b.add(0x44)), tryReadFloat(b.add(0x48))],
    force_target_i32: tryReadS32(b.add(0x4c)),
    target: [tryReadFloat(b.add(0x50)), tryReadFloat(b.add(0x54))],
    contact_damage_f32: tryReadFloat(b.add(0x58)),
    move_speed_f32: tryReadFloat(b.add(0x5c)),
    attack_cooldown_f32: tryReadFloat(b.add(0x60)),
    reward_value_f32: tryReadFloat(b.add(0x64)),
    type_id_i32: tryReadS32(b.add(0x6c)),
    target_player_i32: tryReadS32(b.add(0x70)),
    link_index_i32: tryReadS32(b.add(0x78)),
    flags_i32: tryReadS32(b.add(0x8c)),
    ai_mode_i32: tryReadS32(b.add(0x90)),
    anim_phase_f32: tryReadFloat(b.add(0x94)),
  };
}

function dumpCreature(idx) {
  const c = readCreature(idx);
  writeLine({ event: 'dump_creature', ts: nowIso(), creature: c });
  return c;
}

function weaponEntryPtrGuess(weaponId) {
  const base = exePtr(ADDR.weapon_table_base);
  if (!base) return null;
  const stride = SIZES.weapon_stride;

  const candA = base.add(weaponId * stride);
  const candB = base.add((weaponId + 1) * stride);

  const nameA = tryReadAnsi(candA, 0x40);
  const nameB = tryReadAnsi(candB, 0x40);

  function looksLikeName(s) {
    if (!s) return false;
    // Heuristic: at least 3 printable chars, mostly ASCII.
    if (s.length < 3) return false;
    let ok = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 0x20 && c <= 0x7e) ok++;
    }
    return ok / Math.max(1, s.length) > 0.9;
  }

  const aOk = looksLikeName(nameA);
  const bOk = looksLikeName(nameB);

  if (bOk && !aOk) return { ptr: candB, scheme: 'weapon_id+1', name: nameB, alt: { ptr: candA, name: nameA } };
  if (aOk && !bOk) return { ptr: candA, scheme: 'weapon_id', name: nameA, alt: { ptr: candB, name: nameB } };

  // If both (or neither) look plausible, return both.
  return {
    ptr: candB,
    scheme: bOk ? 'weapon_id+1' : (aOk ? 'weapon_id' : 'unknown'),
    name: bOk ? nameB : nameA,
    alt: { ptr: candA, name: nameA, ptr2: candB, name2: nameB },
  };
}

function readWeaponEntryByPtr(entryPtr) {
  if (!entryPtr) return null;
  const ammoClassBase = exePtr(ADDR.weapon_ammo_class_base);
  const base = exePtr(ADDR.weapon_table_base);
  if (!ammoClassBase || !base) return null;

  const stride = SIZES.weapon_stride;

  // Compute index from base address if possible.
  let index = null;
  try {
    index = entryPtr.sub(base).toInt32() / stride;
  } catch (_) {
    index = null;
  }

  const ammoClassPtr = entryPtr.sub(0x04);

  return {
    entry_ptr: entryPtr.toString(),
    table_index_guess: index,
    ammo_class_i32: tryReadS32(ammoClassPtr),
    name: tryReadAnsi(entryPtr, 0x40),
    unlocked_u8: tryReadU8(entryPtr.add(0x40)),
    clip_size_i32: tryReadS32(entryPtr.add(0x44)),
    shot_cooldown_f32: tryReadFloat(entryPtr.add(0x48)),
    reload_time_f32: tryReadFloat(entryPtr.add(0x4c)),
    spread_heat_f32: tryReadFloat(entryPtr.add(0x50)),
    shot_sfx_base_i32: tryReadS32(entryPtr.add(0x58)),
    shot_sfx_count_i32: tryReadS32(entryPtr.add(0x5c)),
    reload_sfx_i32: tryReadS32(entryPtr.add(0x60)),
    hud_icon_id_i32: tryReadS32(entryPtr.add(0x64)),
    flags_u8: tryReadU8(entryPtr.add(0x68)),
    projectile_meta_f32: tryReadFloat(entryPtr.add(0x6c)),
    damage_scale_f32: tryReadFloat(entryPtr.add(0x70)),
    pellet_count_i32: tryReadS32(entryPtr.add(0x74)),
  };
}

function dumpWeapon(weaponId) {
  const guess = weaponEntryPtrGuess(weaponId);
  const entry = readWeaponEntryByPtr(guess ? guess.ptr : null);
  writeLine({ event: 'dump_weapon', ts: nowIso(), weapon_id: weaponId, guess, entry });
  return entry;
}

// ---------------------------
// Unknown-field tracker (player struct)
// ---------------------------

function makeKnownPlayerOffsetPredicate() {
  // Known offsets from docs/player-struct.md.
  // We mark known ranges so that frequent changes outside them are highlighted.

  const knownSingles = new Set([
    -0x1b,
    -0x14, -0x10, -0x0c, -0x08, -0x04,
    0x00, 0x08, 0x10,
    0x2c, 0x30,
    0x38, 0x3c,
    0x44,
    0x70,
    0x78, 0x7c, 0x80, 0x84,
    0x88, 0x90,
    0x294,
    0x29c, 0x2a0, 0x2a4, 0x2a8,
    0x2ac, 0x2b0, 0x2b4,
    0x2b8,
    0x2d8, 0x2dc, 0x2e0, 0x2e4,
    0x2ec,
    0x2f0, 0x2f4, 0x2f8,
    0x2fc,
    0x300, 0x304,
    0x32c, 0x330, 0x334, 0x338,
  ]);

  // Known big range: perk counts table at 0x94..0x293 (inclusive).
  const knownRanges = [
    { start: 0x94, end: 0x293 },
  ];

  return function isKnown(off) {
    if (knownSingles.has(off)) return true;
    for (let i = 0; i < knownRanges.length; i++) {
      const r = knownRanges[i];
      if (off >= r.start && off <= r.end) return true;
    }
    return false;
  };
}

class UnknownFieldTracker {
  constructor(opts) {
    this.name = opts.name;
    this.base = opts.base;      // pointer to player_health base
    this.prepad = opts.prepad;  // bytes before base to include
    this.size = opts.size;      // bytes after base to include
    this.isKnownOffset = opts.isKnownOffset;

    this.prev = null;           // Uint8Array
    this.counts = new Map();    // offset(int) -> count
    this.last = new Map();      // offset(int) -> {u32,f32}
    this.lastReportAt = 0;
  }

  _bump(off, u32) {
    const cur = this.counts.get(off) || 0;
    this.counts.set(off, cur + 1);
    this.last.set(off, { u32: u32 >>> 0, f32: u32ToF32(u32 >>> 0) });
  }

  snapshot() {
    const start = this.base.sub(this.prepad);
    const total = this.prepad + this.size;

    let bytes;
    try {
      bytes = start.readByteArray(total);
    } catch (_) {
      return;
    }

    const cur = new Uint8Array(bytes);
    if (this.prev === null) {
      this.prev = cur;
      return;
    }

    // Compare 4-byte chunks (most fields are 32-bit floats/ints).
    // Note: this will miss 1-byte flags unless they flip alongside other bytes.
    for (let i = 0; i + 4 <= cur.length; i += 4) {
      let diff = false;
      for (let j = 0; j < 4; j++) {
        if (cur[i + j] !== this.prev[i + j]) { diff = true; break; }
      }
      if (!diff) continue;

      const off = i - this.prepad; // relative to player_health base
      if (this.isKnownOffset(off)) continue;

      // Extract u32 from current bytes.
      const u32 = (cur[i] | (cur[i + 1] << 8) | (cur[i + 2] << 16) | (cur[i + 3] << 24)) >>> 0;
      this._bump(off, u32);
    }

    this.prev = cur;
  }

  reportTop(n) {
    const arr = [];
    for (const [off, cnt] of this.counts.entries()) {
      const last = this.last.get(off);
      arr.push({ off, cnt, last });
    }
    arr.sort((a, b) => b.cnt - a.cnt);
    return arr.slice(0, n);
  }
}

let gPlayerTracker = null;

function startPlayerUnknownTracker() {
  const cfg = CONFIG.playerUnknownFieldTracking;
  if (!cfg.enabled) return;

  const b = playerBase(cfg.playerIndex);
  if (!b) {
    writeLine({ event: 'player_unknown_tracker_error', ts: nowIso(), error: 'player base unavailable' });
    return;
  }

  const isKnown = makeKnownPlayerOffsetPredicate();
  gPlayerTracker = new UnknownFieldTracker({
    name: 'player' + cfg.playerIndex,
    base: b,
    prepad: 0x20,
    size: SIZES.player_stride,
    isKnownOffset: isKnown,
  });

  writeLine({
    event: 'player_unknown_tracker_start',
    ts: nowIso(),
    player_index: cfg.playerIndex,
    base: b.toString(),
    interval_ms: cfg.intervalMs,
    report_every_ms: cfg.reportEveryMs,
  });

  let lastReport = Date.now();

  setInterval(function () {
    if (!gPlayerTracker) return;
    gPlayerTracker.snapshot();

    const now = Date.now();
    if (now - lastReport >= cfg.reportEveryMs) {
      lastReport = now;
      const top = gPlayerTracker.reportTop(cfg.topN);
      writeLine({ event: 'player_unknown_tracker_report', ts: nowIso(), player_index: cfg.playerIndex, top });
    }
  }, cfg.intervalMs);
}

// ---------------------------
// Hook helpers
// ---------------------------

function attachAtVa(moduleName, staticVa, name, handlers) {
  const fn = toRuntimePtr(moduleName, staticVa);
  if (!fn) {
    writeLine({ event: 'hook_error', ts: nowIso(), name, error: 'module not loaded: ' + moduleName });
    return null;
  }

  try {
    Interceptor.attach(fn, handlers);
    writeLine({ event: 'hook_ok', ts: nowIso(), module: moduleName, name, static_va: '0x' + staticVa.toString(16), runtime: fn.toString() });
    return fn;
  } catch (e) {
    writeLine({ event: 'hook_error', ts: nowIso(), name, static_va: '0x' + staticVa.toString(16), runtime: fn.toString(), error: '' + e });
    return null;
  }
}

function attachAtPtr(fnPtr, name, handlers) {
  try {
    Interceptor.attach(fnPtr, handlers);
    writeLine({ event: 'hook_ok', ts: nowIso(), name, runtime: fnPtr.toString() });
    return fnPtr;
  } catch (e) {
    writeLine({ event: 'hook_error', ts: nowIso(), name, runtime: fnPtr.toString(), error: '' + e });
    return null;
  }
}

// ---------------------------
// Grim2D vtable hooking
// ---------------------------

let gGrimHooksInstalled = false;
let gHotWindowUntil = 0;

function hotWindowActive() {
  return Date.now() <= gHotWindowUntil;
}

function startHotWindow(ms) {
  const windowMs = ms || CONFIG.hotWindowMs;
  if (!windowMs || windowMs <= 0) return;
  gHotWindowUntil = Date.now() + windowMs;
  writeLine({ event: 'hot_window_start', ts: nowIso(), window_ms: windowMs });
}

function readGrimInterfacePtr() {
  const g = exePtr(ADDR.grim_interface_ptr);
  if (!g) return null;
  const p = tryReadPtr(g);
  if (!p || p.isNull()) return null;
  return p;
}

function installGrimVtableHooks() {
  if (!CONFIG.hookGrimVtable) return;
  if (gGrimHooksInstalled) return;

  const iface = readGrimInterfacePtr();
  if (!iface) return;

  const vtbl = tryReadPtr(iface);
  if (!vtbl) return;

  const grimMod = safeGetModule('grim.dll');
  if (!grimMod) {
    // In practice iface/vtbl should imply grim.dll is loaded, but be defensive.
    writeLine({ event: 'grim_vtable_wait', ts: nowIso(), reason: 'grim.dll module not found yet', iface: iface.toString(), vtbl: vtbl.toString() });
    return;
  }

  // Install hooks for selected offsets.
  const targets = CONFIG.grimVtableTargets;
  const installed = [];

  if (CONFIG.hotWindowAutoStart) {
    startHotWindow(CONFIG.hotWindowMs);
  }

  for (const offHex in targets) {
    const off = parseInt(offHex, 10);
    const spec = targets[offHex];

    if (spec.hot) continue;

    const fnPtr = tryReadPtr(vtbl.add(off));
    if (!fnPtr) continue;

    // Sanity: function pointer should be inside grim.dll .text range.
    const inGrim = fnPtr.compare(grimMod.base) >= 0 && fnPtr.compare(grimMod.base.add(grimMod.size)) < 0;

    const hookName = `grim.vtbl+0x${off.toString(16)}:${spec.name}`;

    attachAtPtr(fnPtr, hookName, {
      onEnter(args) {
        if (spec.hot && !hotWindowActive()) {
          this._skip = true;
          return;
        }
        this._skip = false;
        this._evt = {
          event: 'grim_vtbl_call',
          ts: nowIso(),
          offset: off,
          offset_hex: '0x' + off.toString(16),
          name: spec.name,
          fn: fnPtr.toString(),
          fn_in_grim: inGrim,
        };

        if (CONFIG.includeCaller) {
          this._evt.caller = symbolicate(this.returnAddress);
        }
        if (CONFIG.includeBacktrace) {
          this._evt.backtrace = captureBacktrace(this.context);
        }

        // Decode args if we have a rough idea.
        const decoded = [];
        for (let i = 0; i < spec.args.length; i++) {
          const t = spec.args[i];
          if (t === 'i32') decoded.push(argAsI32(args[i]));
          else if (t === 'u32') decoded.push(argAsU32(args[i]));
          else if (t === 'f32') decoded.push(argAsF32(args[i]));
          else if (t === 'ptr') decoded.push(args[i].toString());
          else if (t === 'cstr') decoded.push(tryReadAnsi(args[i], 256));
          else decoded.push(formatArgGuess(args[i]));
        }
        this._evt.args = decoded;
      },
      onLeave(retval) {
        if (this._skip) return;
        // For now, always log return value as a guess object (covers int/float confusion).
        this._evt.ret = formatArgGuess(retval);
        writeLine(this._evt);
      },
    });

    installed.push({ off, name: spec.name, fn: fnPtr.toString(), in_grim: inGrim });
  }

  gGrimHooksInstalled = true;
  writeLine({
    event: 'grim_vtable_hooks_installed',
    ts: nowIso(),
    iface: iface.toString(),
    vtbl: vtbl.toString(),
    grim_base: grimMod.base.toString(),
    grim_size: grimMod.size,
    installed,
  });
}

function pollForGrimInterface() {
  if (!CONFIG.hookGrimVtable) return;
  const timer = setInterval(function () {
    if (gGrimHooksInstalled) {
      clearInterval(timer);
      return;
    }
    installGrimVtableHooks();
  }, 250);
}

// ---------------------------
// Gameplay hooks
// ---------------------------

function hookGameplay() {
  if (!CONFIG.hookGameplay) return;

  attachAtVa('crimsonland.exe', ADDR.player_take_damage, 'player_take_damage', {
    onEnter(args) {
      const playerIdx = argAsI32(args[0]);
      const dmg = argAsF32(args[1]);
      const before = readPlayer(playerIdx);

      this._evt = {
        event: 'player_take_damage',
        ts: nowIso(),
        player_index: playerIdx,
        damage_f32: dmg,
        before,
      };

      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
      if (CONFIG.includeBacktrace) this._evt.backtrace = captureBacktrace(this.context);
    },
    onLeave(retval) {
      const playerIdx = this._evt.player_index;
      const after = readPlayer(playerIdx);
      this._evt.after = after;

      // Quick heuristic: did health actually change?
      const hb = this._evt.before ? this._evt.before.health_f32 : null;
      const ha = after ? after.health_f32 : null;
      if (hb !== null && ha !== null) {
        this._evt.health_delta = ha - hb;
      }

      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.projectile_spawn, 'projectile_spawn', {
    onEnter(args) {
      this._pos = [tryReadFloat(args[0]), tryReadFloat(args[0].add(4))];
      this._angle = argAsF32(args[1]);
      this._typeId = argAsI32(args[2]);
      this._ownerId = argAsI32(args[3]);

      // For Fire Bullets validation we care about the owner's timer.
      let ownerFireTimer = null;
      if (this._ownerId <= -1 && this._ownerId >= -4) {
        // Owner IDs: docs mention -1..-3 etc for players. Map to player index 0..3.
        const playerIdx = Math.abs(this._ownerId) - 1;
        const p = readPlayer(playerIdx);
        ownerFireTimer = p ? p.fire_bullets_timer_f32 : null;
      }

      this._evt = {
        event: 'projectile_spawn',
        ts: nowIso(),
        pos: this._pos,
        angle_f32: this._angle,
        requested_type_id: this._typeId,
        owner_id: this._ownerId,
        owner_fire_bullets_timer: ownerFireTimer,
      };

      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
      if (CONFIG.includeBacktrace) this._evt.backtrace = captureBacktrace(this.context);
    },
    onLeave(retval) {
      const idx = retval.toInt32();
      this._evt.return_index = idx;
      this._evt.spawned = readProjectile(idx);

      // Confirm any type override.
      if (this._evt.spawned) {
        this._evt.actual_type_id = this._evt.spawned.type_id_i32;
        this._evt.type_overridden = (this._evt.actual_type_id !== this._evt.requested_type_id);
      }

      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.creature_spawn, 'creature_spawn', {
    onEnter(args) {
      const posPtr = args[0];
      const rgbaPtr = args[1];
      const typeId = argAsI32(args[2]);

      const pos = [tryReadFloat(posPtr), tryReadFloat(posPtr.add(4))];
      const tint = [tryReadFloat(rgbaPtr), tryReadFloat(rgbaPtr.add(4)), tryReadFloat(rgbaPtr.add(8)), tryReadFloat(rgbaPtr.add(12))];

      this._evt = {
        event: 'creature_spawn',
        ts: nowIso(),
        type_id: typeId,
        pos,
        tint,
      };

      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
      if (CONFIG.includeBacktrace) this._evt.backtrace = captureBacktrace(this.context);
    },
    onLeave(retval) {
      const idx = retval.toInt32();
      this._evt.return_index = idx;
      this._evt.spawned = readCreature(idx);
      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.weapon_assign_player, 'weapon_assign_player', {
    onEnter(args) {
      const playerIdx = argAsI32(args[0]);
      const weaponId = argAsI32(args[1]);
      this._evt = {
        event: 'weapon_assign_player',
        ts: nowIso(),
        player_index: playerIdx,
        weapon_id: weaponId,
        player_before: readPlayer(playerIdx),
        weapon_entry: dumpWeapon(weaponId),
      };

      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      const playerIdx = this._evt.player_index;
      this._evt.player_after = readPlayer(playerIdx);
      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.weapon_table_init, 'weapon_table_init', {
    onEnter(args) {
      this._evt = { event: 'weapon_table_init', ts: nowIso() };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      // Dump a handful of entries to validate the indexing scheme.
      const sample = [];
      for (let id = 0; id < 8; id++) {
        const guess = weaponEntryPtrGuess(id);
        sample.push({ weapon_id: id, guess, entry: readWeaponEntryByPtr(guess ? guess.ptr : null) });
      }
      this._evt.sample = sample;
      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.bonus_apply, 'bonus_apply', {
    onEnter(args) {
      const playerIdx = argAsI32(args[0]);
      const bonusPtr = args[1];

      // We don't fully trust bonus_entry layout yet; dump first 0x40 bytes.
      let dump = null;
      try {
        const bytes = bonusPtr.readByteArray(0x40);
        dump = hexdump(bytes, { offset: 0, length: 0x40, header: false, ansi: false });
      } catch (_) {
        dump = null;
      }

      this._evt = {
        event: 'bonus_apply',
        ts: nowIso(),
        player_index: playerIdx,
        bonus_ptr: bonusPtr.toString(),
        bonus_entry_hex: dump,
        player_before: readPlayer(playerIdx),
      };

      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
      if (CONFIG.includeBacktrace) this._evt.backtrace = captureBacktrace(this.context);
    },
    onLeave(retval) {
      const playerIdx = this._evt.player_index;
      this._evt.player_after = readPlayer(playerIdx);
      writeLine(this._evt);
    },
  });

  // Audio / SFX hooks (useful for sfx-id-map / sfx-usage)
  attachAtVa('crimsonland.exe', ADDR.sfx_play, 'sfx_play', {
    onEnter(args) {
      const guess = formatArgGuess(args[0]);
      this._evt = { event: 'sfx_play', ts: nowIso(), sfx_id_guess: guess };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      this._evt.ret = formatArgGuess(retval);
      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.sfx_play_panned, 'sfx_play_panned', {
    onEnter(args) {
      // signature is uncertain in the map; print both int/float interpretations.
      const guess = formatArgGuess(args[0]);
      this._evt = { event: 'sfx_play_panned', ts: nowIso(), arg0: guess };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      this._evt.ret = formatArgGuess(retval);
      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.sfx_play_exclusive, 'sfx_play_exclusive', {
    onEnter(args) {
      const guess = formatArgGuess(args[0]);
      this._evt = { event: 'sfx_play_exclusive', ts: nowIso(), sfx_id_guess: guess };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      writeLine(this._evt);
    },
  });

  // Grim interface loader (helps align with docs/grim2d-api.md)
  attachAtVa('crimsonland.exe', ADDR.grim_load_interface, 'grim_load_interface', {
    onEnter(args) {
      const dllName = tryReadAnsi(args[0], 256);
      this._evt = { event: 'grim_load_interface', ts: nowIso(), dll_name: dllName, dll_name_ptr: args[0].toString() };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      this._evt.ret = formatArgGuess(retval);
      const iface = readGrimInterfacePtr();
      this._evt.grim_iface_ptr_after = iface ? iface.toString() : null;
      writeLine(this._evt);

      // Try immediately after load.
      installGrimVtableHooks();
    },
  });
}

function hookResources() {
  if (!CONFIG.hookResources) return;

  // texture_get_or_load(char* name) -> int handle
  attachAtVa('crimsonland.exe', ADDR.texture_get_or_load, 'texture_get_or_load', {
    onEnter(args) {
      const decoded = readBestString(args[0], CONFIG.stringMaxLen);
      this._evt = { event: 'texture_get_or_load', ts: nowIso(), name: decoded.name, ...decoded };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      this._evt.ret = formatArgGuess(retval);
      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.texture_get_or_load_alt, 'texture_get_or_load_alt', {
    onEnter(args) {
      const decoded = readBestString(args[0], CONFIG.stringMaxLen);
      this._evt = { event: 'texture_get_or_load_alt', ts: nowIso(), name: decoded.name, ...decoded };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
    },
    onLeave(retval) {
      this._evt.ret = formatArgGuess(retval);
      writeLine(this._evt);
    },
  });

  attachAtVa('crimsonland.exe', ADDR.crimsonland_main, 'crimsonland_main', {
    onEnter(args) {
      this._evt = { event: 'crimsonland_main_enter', ts: nowIso() };
      if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
      writeLine(this._evt);
    },
    onLeave(retval) {
      writeLine({ event: 'crimsonland_main_leave', ts: nowIso(), ret: formatArgGuess(retval) });
    },
  });
}

// ---------------------------
// Win32 helper hooks (optional)
// ---------------------------

function hookWin32FileIO() {
  if (!CONFIG.hookWin32FileIO) return;

  const k32 = safeGetModule('kernel32.dll');
  if (!k32) {
    writeLine({ event: 'win32_fileio_skip', ts: nowIso(), reason: 'kernel32.dll not found' });
    return;
  }

  function shouldLogPath(path) {
    if (!path) return false;
    const lower = path.toLowerCase();
    for (let i = 0; i < CONFIG.fileIoExts.length; i++) {
      const ext = CONFIG.fileIoExts[i];
      if (lower.endsWith(ext)) return true;
    }
    return false;
  }

  const createFileW = k32.findExportByName('CreateFileW');
  if (createFileW) {
    attachAtPtr(createFileW, 'CreateFileW', {
      onEnter(args) {
        const path = tryReadUtf16(args[0], 520);
        if (!shouldLogPath(path)) {
          this._skip = true;
          return;
        }
        this._skip = false;
        this._evt = {
          event: 'CreateFileW',
          ts: nowIso(),
          path,
          desired_access: args[1].toUInt32(),
          share_mode: args[2].toUInt32(),
          creation_disposition: args[4].toUInt32(),
          flags: args[5].toUInt32(),
        };
        if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
      },
      onLeave(retval) {
        if (this._skip) return;
        this._evt.ret = formatArgGuess(retval);
        writeLine(this._evt);
      },
    });
  }

  const createFileA = k32.findExportByName('CreateFileA');
  if (createFileA) {
    attachAtPtr(createFileA, 'CreateFileA', {
      onEnter(args) {
        const path = tryReadAnsi(args[0], 520);
        if (!shouldLogPath(path)) {
          this._skip = true;
          return;
        }
        this._skip = false;
        this._evt = {
          event: 'CreateFileA',
          ts: nowIso(),
          path,
          desired_access: args[1].toUInt32(),
          share_mode: args[2].toUInt32(),
          creation_disposition: args[4].toUInt32(),
          flags: args[5].toUInt32(),
        };
        if (CONFIG.includeCaller) this._evt.caller = symbolicate(this.returnAddress);
      },
      onLeave(retval) {
        if (this._skip) return;
        this._evt.ret = formatArgGuess(retval);
        writeLine(this._evt);
      },
    });
  }
}

// ---------------------------
// Startup sanity
// ---------------------------

function printStartupSummary() {
  const exe = safeGetModule('crimsonland.exe');
  const grim = safeGetModule('grim.dll');

  const summary = {
    event: 'startup_summary',
    ts: nowIso(),
    arch: Process.arch,
    platform: Process.platform,
    pointer_size: Process.pointerSize,
    exe: exe ? { name: exe.name, base: exe.base.toString(), size: exe.size } : null,
    grim: grim ? { name: grim.name, base: grim.base.toString(), size: grim.size } : null,
  };

  // Validate that key global regions look readable.
  function chk(name, staticVa, bytes) {
    const p = exePtr(staticVa);
    const ok = p ? (Process.findRangeByAddress(p) !== null) : false;
    const r = p ? Process.findRangeByAddress(p) : null;
    return { name, static_va: '0x' + staticVa.toString(16), runtime: p ? p.toString() : null, readable: ok, range: r ? { base: r.base.toString(), size: r.size, protection: r.protection } : null, bytes };
  }

  summary.checks = [
    chk('grim_interface_ptr', ADDR.grim_interface_ptr, 4),
    chk('player_health_base', ADDR.player_health_base, 0x20),
    chk('projectile_pool_base', ADDR.projectile_pool_base, SIZES.projectile_stride * SIZES.projectile_count),
    chk('creature_pool_base', ADDR.creature_pool_base, SIZES.creature_stride * SIZES.creature_count),
    chk('weapon_table_base', ADDR.weapon_table_base, SIZES.weapon_stride * 64),
  ];

  writeLine(summary);
}

// ---------------------------
// Public REPL helpers
// ---------------------------

function dumpGrimInterface() {
  const iface = readGrimInterfacePtr();
  if (!iface) {
    writeLine({ event: 'dump_grim_iface', ts: nowIso(), iface: null });
    return null;
  }
  const vtbl = tryReadPtr(iface);
  writeLine({ event: 'dump_grim_iface', ts: nowIso(), iface: iface.toString(), vtbl: vtbl ? vtbl.toString() : null });
  return iface;
}

function hookGrimNow() {
  installGrimVtableHooks();
}

// Optional: find *who* is reading/writing a specific player-struct offset.
// Workflow:
//  1) Let the unknown-field tracker report a hot unknown offset (e.g. off=0x1a4).
//  2) In the Frida REPL, run: watchPlayerOffset(0, 0x1a4, 4)
//     (playerIndex=0, off=0x1a4, size=4)
//  3) Do the in-game action that triggers it; watch the 'mem_access' events.
//  4) stopWatchPlayerOffset()
let gMemWatchEnabled = false;

function watchPlayerOffset(playerIndex, offset, size) {
  if (typeof MemoryAccessMonitor === 'undefined') {
    writeLine({ event: 'mem_watch_error', ts: nowIso(), error: 'MemoryAccessMonitor is not available in this Frida build' });
    return;
  }
  const b = playerBase(playerIndex);
  if (!b) {
    writeLine({ event: 'mem_watch_error', ts: nowIso(), error: 'player base unavailable', playerIndex, offset });
    return;
  }
  const addr = b.add(offset);
  const range = { base: addr, size: size };
  try {
    MemoryAccessMonitor.enable([range], {
      onAccess(details) {
        // details.operation: 'read' | 'write'
        // details.from: instruction pointer
        // details.address: accessed address
        writeLine({
          event: 'mem_access',
          ts: nowIso(),
          kind: 'player_offset',
          playerIndex,
          offset,
          size,
          operation: details.operation,
          address: details.address ? details.address.toString() : null,
          from: details.from ? symbolicate(details.from) : null,
          threadId: details.threadId,
        });
      },
    });
    gMemWatchEnabled = true;
    writeLine({ event: 'mem_watch_start', ts: nowIso(), kind: 'player_offset', playerIndex, offset, size, addr: addr.toString() });
  } catch (e) {
    writeLine({ event: 'mem_watch_error', ts: nowIso(), error: '' + e, playerIndex, offset, size });
  }
}

function stopWatchPlayerOffset() {
  if (typeof MemoryAccessMonitor === 'undefined') return;
  if (!gMemWatchEnabled) return;
  try {
    MemoryAccessMonitor.disable();
  } catch (_) {}
  gMemWatchEnabled = false;
  writeLine({ event: 'mem_watch_stop', ts: nowIso(), kind: 'player_offset' });
}

function help() {
  console.log('\nREPL helpers:' +
    '\n  dumpPlayer(0)' +
    '\n  dumpProjectile(0)' +
    '\n  dumpCreature(0)' +
    '\n  dumpWeapon(0)' +
    '\n  dumpGrimInterface()' +
    '\n  hookGrimNow()' +
    '\n  startHotWindow(2000)          // log hot grim calls for N ms' +
    '\n  watchPlayerOffset(0, 0x1a4, 4)    // monitor read/write accesses to player0+0x1a4' +
    '\n  stopWatchPlayerOffset()' +
    '\n');
}

// Expose a few helpers in the REPL.
// (Frida's REPL evaluates inside the same JS runtime.)
globalThis.dumpPlayer = dumpPlayer;
globalThis.dumpProjectile = dumpProjectile;
globalThis.dumpCreature = dumpCreature;
globalThis.dumpWeapon = dumpWeapon;
globalThis.dumpGrimInterface = dumpGrimInterface;
globalThis.hookGrimNow = hookGrimNow;
globalThis.startHotWindow = startHotWindow;
globalThis.watchPlayerOffset = watchPlayerOffset;
globalThis.stopWatchPlayerOffset = stopWatchPlayerOffset;
globalThis.help = help;

// ---------------------------
// Main
// ---------------------------

function main() {
  initLogFile();
  if (CONFIG.printStartupSummary) printStartupSummary();

  // Hooks
  hookGameplay();
  hookResources();
  hookWin32FileIO();

  // Grim vtable hooks: poll until interface pointer exists.
  pollForGrimInterface();

  // Unknown-field tracker
  startPlayerUnknownTracker();

  writeLine({ event: 'probe_ready', ts: nowIso() });
  help();
}

main();
