// Input-only bot and parity runner. No state mutation or score submission.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { compare } from "./compare.mjs";
import {
  CORE,
  index,
  loadCore,
  init,
  state,
  field,
  config,
  record,
  refusal,
  step,
  names,
  decode,
  fieldRanges,
  firstDifference,
  QUEST_BYTES,
  CL_BUILD_1_9_8,
  clBuild,
} from "./engine.mjs";

const out = path.resolve(
  process.argv[2] ?? fileURLToPath(new URL("build", CORE)),
);
const native = path.join(out, "native/core"),
  wasm = path.join(out, "wasm/core.wasm");
const e = loadCore(wasm);
const terminal = new Set([7, 8, 12]);
// The corpus is rewritten whole: the gate and game checks read every stream here.
const fixtures = path.join(out, "fixtures");
fs.rmSync(fixtures, { recursive: true, force: true });
fs.mkdirSync(fixtures, { recursive: true });

// Movement schemes (`MovementControlType`) and aim schemes (`AimScheme`, -1 stored as 7).
const MOVE = { relative: 1, static: 2, pad: 3, pointClick: 4, computer: 5 };
const AIM = { mouse: 0, keyboard: 1, joystick: 2, mouseRelative: 3, pad: 4, computer: 5, unknown: 7 };
// Mouse aim sends a world point; dual action pad aim sends the stick's reach.
const MOUSE = { move: MOVE.pad, aim: AIM.mouse },
  PAD = { move: MOVE.pad, aim: AIM.pad };
const keyed = (move) => move === MOVE.relative || move === MOVE.static;
const schemeFlags = ({ move, aim }) => 0x100 | (move << 9) | 0x1000 | (aim << 13) | (keyed(move) ? 8 : 0);
const TURN = 0.15;
const wrap = (angle) => Math.atan2(Math.sin(angle), Math.cos(angle));

// The tick's axes and flags for `scheme`, steering along (mx, my) when moving and aiming at (wx, wy).
function encodeControls(scheme, { x, y, heading, aimHeading, mx, my, wx, wy, moving }) {
  const { move, aim } = scheme;
  let flags = schemeFlags(scheme);
  let moveX = mx,
    moveY = my;
  if (move === MOVE.relative && moving) {
    const turn = wrap(Math.atan2(my, mx) + Math.PI / 2 - heading);
    if (turn > TURN) flags |= 128;
    if (turn < -TURN) flags |= 64;
    if (Math.abs(turn) < 1) flags |= 16;
  } else if (move === MOVE.static && moving) {
    if (my < -0.38) flags |= 16;
    if (my > 0.38) flags |= 32;
    if (mx < -0.38) flags |= 64;
    if (mx > 0.38) flags |= 128;
  } else if (move === MOVE.pointClick) {
    [moveX, moveY] = moving ? [x + mx * 80, y + my * 80] : [-1, -1];
  }
  if (move !== MOVE.pad && move !== MOVE.pointClick) moveX = moveY = 0;
  let aimX = 0,
    aimY = 0;
  if (aim === AIM.mouse) [aimX, aimY] = [wx, wy];
  else if (aim === AIM.pad) [aimX, aimY] = [wx - x, wy - y];
  else if (aim === AIM.mouseRelative) {
    const n = Math.hypot(wx - x, wy - y) || 1;
    [aimX, aimY] = [200 + ((wx - x) / n) * 25, 200 + ((wy - y) / n) * 25];
  } else if (aim !== AIM.computer) {
    const turn = wrap(Math.atan2(wy - y, wx - x) + Math.PI / 2 - aimHeading);
    if (turn > TURN) flags |= 1 << 19;
    if (turn < -TURN) flags |= 1 << 18;
  }
  return [moveX, moveY, aimX, aimY, flags];
}

// Perk ids (`PerkId` in src/crimson/perks) that ranked-rules fixes or the 1.9.8 rules touch.
const PERK = {
  pyrokinetic: 6,
  instantWinner: 7,
  alternateWeapon: 9,
  hotTempered: 31,
  fireCough: 54,
  plaguebearer: 10,
  evilEyes: 11,
  ammoManiac: 12,
  radioactive: 13,
  infernalContract: 24,
  doctor: 29,
  regeneration: 38,
  pyromaniac: 39,
  highlander: 41,
  jinxed: 42,
  greaterRegeneration: 45,
  deathClock: 47,
  myFavouriteWeapon: 48,
  bandage: 49,
  angryReloader: 50,
};
// Man Bomb, Fire Cough, Living Fortress and Tough Reloader, which 1.9.8 lacks: a 1.9.8 menu never offers them.
const ABSENT_1_9_8 = new Set([53, 54, 55, 56]);
const PERK_COUNTS = names.filter((n) => n.startsWith("players[0].perk_counts[")).length;
// FIRE_BULLETS_KEY_DOWN_FLAG in src/crimson/replay/types.py: the G key.
const G_KEY = 131072;

// Snapshot byte offsets of the creature fields the bot reads every tick.
const CREATURES = Array.from({ length: 384 }, (_, c) =>
  Object.fromEntries(
    ["active", "health", "pos_x", "pos_y", "dot_tick_timer", "type_id"].map((f) => [f, index.get(`creatures[${c}].${f}`) * 4]),
  ),
);

// What a 1.9.8 run's coverage reads of each snapshot, to tell which of the 1.9.8 rules and bugs
// (docs/rewrite/rules-1.9.8.md) a step reached.
const at = (name) => index.get(name) * 4;
const PROJECTILES = Array.from({ length: names.filter((n) => /^projectiles\[\d+\]\.active$/.test(n)).length }, (_, i) =>
  Object.fromEntries(
    ["active", "fields.type_id", "fields.owner_id", "fields.origin_x", "fields.origin_y"].map((f) => [
      f,
      at(`projectiles[${i}].${f}`),
    ]),
  ),
);
const BONUS_IDS = Array.from({ length: 16 }, (_, b) => at(`bonuses[${b}].bonus_id`));
const AI_MODES = CREATURES.map((_, c) => at(`creatures[${c}].ai_mode`));
// A bonus carrier's flags, and the bonus its death drops, in the low half of its `link_index` (`bonus_args`).
const CARRIERS = CREATURES.map((_, c) => [at(`creatures[${c}].flags`), at(`creatures[${c}].link_index`)]);
// Each creature's `phase_seed`, drawn when its slot is handed out (`creature_alloc_slot`) and kept for its life: a
// slot freed and handed out again within one step most likely holds another seed.
const SEEDS = CREATURES.map((_, c) => at(`creatures[${c}].phase_seed`));
const CREATURE_FLAG_BONUS_ON_DEATH = 0x400;
// `CreatureAiMode`: flanking, which a creature turns to when its tether breaks, and the two tethered modes.
const FLANK_PLAYER = 0,
  TETHERED = new Set([4, 5]);
// `ProjectileTemplateId` in src/crimson/projectiles/types.py: Angry Reloader's ring, and the Fire Bullets shot.
const PLASMA_MINIGUN = 0x0b,
  FIRE_BULLETS = 0x2d;
// `CreatureTypeId.LIZARD`; `WeaponId.PISTOL`, and the flame and rocket weapons whose holder rerolls a Fire Bullets drop.
const LIZARD = 1,
  PISTOL = 1,
  FLAME_OR_ROCKET = new Set([8, 12, 13, 15, 16, 17, 18, 32]);
// How far from a player their shots start: the muzzle's 16 units (`native_fire_muzzle_pos`) and a step's walk.
const MUZZLE_REACH = 32;

function look198(s, players) {
  const u = (offset) => s.readUInt32LE(offset),
    f = (offset) => s.readFloatLE(offset),
    perk = (id) => u(at(`players[0].perk_counts[${id}]`)),
    each = (read) => Array.from({ length: players }, (_, p) => read(p));
  const radioactive = perk(PERK.radioactive),
    jinxed = perk(PERK.jinxed),
    favourite = perk(PERK.myFavouriteWeapon);
  return {
    radioactive,
    jinxed,
    contract: perk(PERK.infernalContract),
    favourite,
    ammoManiac: perk(PERK.ammoManiac),
    angry: perk(PERK.angryReloader),
    freeze: f(at("globals.bonus_freeze_timer")),
    jinxedTimer: f(at("globals.perk_jinxed_proc_timer_s")),
    kills: u(at("globals.creature_kill_count")),
    choices: Array.from({ length: 7 }, (_, i) => u(at(`globals.perk_choice_ids[${i}]`))),
    health: each((p) => f(at(`players[${p}].health`))),
    pos: each((p) => [f(at(`players[${p}].pos_x`)), f(at(`players[${p}].pos_y`))]),
    weapons: each((p) => u(at(`players[${p}].weapon_id`))),
    // Each player's clip, and their weapon's in the weapon table.
    clip: each((p) => f(at(`players[${p}].clip_size`))),
    tableClip: each((p) => u(at(`weapons[${u(at(`players[${p}].weapon_id`))}].clip_size`))),
    reloadMax: each((p) => f(at(`players[${p}].reload_timer_max`))),
    fireBullets: each((p) => f(at(`players[${p}].fire_bullets_timer`))),
    projectiles: PROJECTILES.map((p) => [
      u(p.active),
      u(p["fields.type_id"]),
      s.readInt32LE(p["fields.owner_id"]),
      f(p["fields.origin_x"]),
      f(p["fields.origin_y"]),
    ]),
    bonuses: BONUS_IDS.map(u),
    // Creatures only matter to Radioactive, Jinxed and My Favourite Weapon: the last, the bonus a carrier drops and
    // its seed.
    creatures:
      radioactive || jinxed || favourite
        ? CREATURES.map((c, i) => [
            u(c.active),
            f(c.health),
            f(c.dot_tick_timer),
            u(c.type_id),
            u(AI_MODES[i]),
            u(CARRIERS[i][0]) & CREATURE_FLAG_BONUS_ON_DEATH ? u(CARRIERS[i][1]) & 0xffff : 0,
            u(SEEDS[i]),
          ])
        : [],
  };
}

// What one step of a 1.9.8 run reached, and how it played, from the snapshots before and after it and its commands.
// The matrix's end checks the counts: outcomes no run may show, then what some run must reach.
function observe198(b, a, commands, cov) {
  const ownersFresh = new Map(),
    playerShots = [];
  let ring = 0,
    active = 0;
  a.projectiles.forEach(([live, type, owner, x, y], i) => {
    if (!live) return;
    active++;
    cov.last_projectile_slot = Math.max(cov.last_projectile_slot, i);
    // A shot is new where the slot held none, or another, of another type or from another origin.
    const [wasLive, wasType, , wasX, wasY] = b.projectiles[i];
    if (wasLive && wasType === type && wasX === x && wasY === y) return;
    ring += type === PLASMA_MINIGUN;
    const fresh = ownersFresh.get(owner) ?? new Set();
    ownersFresh.set(owner, fresh.add(type === FIRE_BULLETS));
    if (owner < 0) playerShots.push({ type, x, y });
  });
  cov.peak_projectiles = Math.max(cov.peak_projectiles, active);
  // R1: an owner's Fire Bullets shot beside another of its shots.
  cov.add_on_volleys += [...ownersFresh.values()].filter((fresh) => fresh.size === 2).length;
  // R5: Angry Reloader's ring (7 shots and up) while a player's reload is 0.5 s or shorter.
  cov.angry_short_rings += Number(b.angry > 0 && ring >= 7 && a.reloadMax.some((max) => max <= 0.5));
  // R2: while a player, dead or alive, holds a flame or rocket weapon through the step, Fire Bullets rerolls: no
  // drop of it, and drops of the other bonuses show the reroll was due.
  const dropped = a.bonuses.filter((id, i) => id && id !== b.bonuses[i]);
  if (b.weapons.some((w, p) => FLAME_OR_ROCKET.has(w) && FLAME_OR_ROCKET.has(a.weapons[p]))) {
    cov.flame_or_rocket_fire_bullets_drops += dropped.filter((id) => id === BONUS.fireBullets).length;
    cov.flame_or_rocket_drops += dropped.filter((id) => id !== BONUS.fireBullets).length;
  }
  // R4: a menu the step opened never offers the perks 1.9.8 lacks.
  if (commands.some(([type]) => type === 2)) {
    cov.menus++;
    cov.absent_perk_offers += a.choices.filter((id) => ABSENT_1_9_8.has(id)).length;
  }
  // Bug 13: new shots starting at one player's muzzle, and no other's, while only the other player's Fire Bullets
  // timer runs: 1.9.8's bugs add Fire Bullets shots to them, the fixes none.
  const timer = (p) => [b.fireBullets[p], a.fireBullets[p]];
  a.pos.forEach((own, q) => {
    const other = a.pos[1 - q];
    if (!other || !timer(1 - q).every((left) => left > 0) || timer(q).some((left) => left > 0)) return;
    const near = (shot, [x, y]) => Math.hypot(shot.x - x, shot.y - y) < MUZZLE_REACH;
    const shots = playerShots.filter((shot) => near(shot, own) && !near(shot, other));
    if (shots.some((shot) => shot.type === FIRE_BULLETS)) cov.other_timer_add_ons++;
    else if (shots.length) cov.other_timer_plain_shots++;
  });
  if (b.favourite) {
    // Bug 59: Ammo Maniac taken while My Favourite Weapon is held reassigns each player's weapon, whose clip, the
    // table's and Ammo Maniac's quarter, keeps the perk's 2 only under the fixes.
    if (a.ammoManiac > b.ammoManiac)
      a.clip.forEach((clip, p) => {
        const table = a.tableClip[p];
        cov.favourite_reassignments++;
        cov.favourite_clip_bonus_kept += Number(clip === table + Math.max(1, Math.trunc(table * 0.25)) + 2);
      });
    // Bug 60: kills while a player holds the Pistol, and the Weapon drops they bring, which the perk refuses unless
    // 1.9.8's bugs are kept. A Weapon carrier's own drop (`creature_handle_death`) ignores the perk in both builds:
    // one from a carrier alive before the step whose slot no longer holds it alive after (its seed, still carrying),
    // since a kill that frees the slot at once, during Freeze say, lets a spawn later in the same frame take it.
    if (b.weapons.includes(PISTOL)) {
      const carried = b.creatures.filter(([live, health, , , , bonus, seed], c) => {
        const [still, left, , , , carries, kept] = a.creatures[c];
        const alive = still && left > 0 && carries === bonus && kept === seed;
        return live && health > 0 && bonus === BONUS.weapon && !alive;
      }).length;
      cov.favourite_pistol_kills += a.kills - b.kills;
      cov.favourite_pistol_weapon_drops += Math.max(0, dropped.filter((id) => id === BONUS.weapon).length - carried);
    }
  }
  // Bug 57: Jinxed's proc (its timer rising) during Freeze, and the creatures it sets to -1 health, which only 1.9.8's
  // bugs kill.
  if (b.jinxed > 0 && b.freeze > 0 && a.freeze > 0 && a.jinxedTimer > b.jinxedTimer) {
    cov.jinxed_freeze_procs++;
    cov.jinxed_freeze_kills += a.creatures.filter(
      ([live, health], c) => live && b.creatures[c][0] && b.creatures[c][1] !== -1 && health === -1,
    ).length;
  }
  // Bug 58: Infernal Contract taken while player one is dead, which only 1.9.8's bugs bring back, at 0.1 health: the
  // step plays on after the pick, so a creature can take that again, but the fixes leave a dead player's health alone.
  if (a.contract > b.contract && b.health[0] <= 0) {
    cov.contract_dead_player_one++;
    cov.contract_charges += Number(a.health[0] !== b.health[0]);
  }
  if (b.radioactive) {
    a.creatures.forEach(([live, health, dot, type, mode], c) => {
      const [wasLive, wasHealth, wasDot, , wasMode] = b.creatures[c];
      if (!live || !wasLive) return;
      // R6: a lizard the pulse (its timer back at 0.5, and at most 30 health off) kills.
      cov.radioactive_lizard_kills += Number(
        type === LIZARD && wasHealth > 0 && health <= 0 && wasHealth - health <= 30 && dot === 0.5,
      );
      // Bug 56: the pulse's timer ran out on a creature already at zero health or below. The fixes leave it alone;
      // 1.9.8's bugs burn it, as when its tether broke this step (tethered before, flanking after): the tether's 1000
      // damage comes before the pulse in the creature's own update, so one with 1000 health or less was dead when
      // the pulse (its timer back at 0.5) came. A creature pulsed alive in its update dies to its leader's death only
      // on a later step.
      cov.radioactive_dying_skips += Number(health <= 0 && dot < 0 && dot < wasDot);
      cov.radioactive_corpse_pulses += Number(
        TETHERED.has(wasMode) && mode === FLANK_PLAYER && wasHealth <= 1000 && dot === 0.5 && wasDot !== 0.5,
      );
    });
  }
}

// `hunt` steers a bot towards fixed behaviour: `prefer` lists perks to pick when offered, most wanted first, or gives
// that list for the players' views; `gKey` holds G at times; `skip` lists bonuses the bot neither goes for nor steps
// on; `evade` is how near a creature comes before the bot turns away (210 by default); `still` lists players who
// do not move.
// `scheme` is each player's controls, or one for all of them.
function play(cfg, bot, limit, scheme, hunt = {}) {
  init(e, cfg);
  const players = cfg.readUInt32LE(48);
  const schemes = Array.isArray(scheme) ? scheme : Array(players).fill(scheme);
  const records = [],
    coverage = {
      weapons: new Set(),
      perks: new Set(),
      bonuses: new Set(),
      fire_bullets_volleys: new Set(),
      menu: 0,
      // Menus opened while a player lay dead, by the survivor.
      survivor_menu: 0,
      reload: 0,
      max_commands: 0,
      peak_creatures: 0,
      stall: false,
      transitions: false,
      run_down: 0,
    };
  // A 1.9.8 run also counts what it reached of the 1.9.8 rules and bugs (observe198).
  const rules198 = clBuild(cfg) === CL_BUILD_1_9_8 && {
    preserve_bugs: cfg.readUInt32LE(44),
    add_on_volleys: 0,
    peak_projectiles: 0,
    last_projectile_slot: -1,
    flame_or_rocket_drops: 0,
    flame_or_rocket_fire_bullets_drops: 0,
    menus: 0,
    absent_perk_offers: 0,
    other_timer_add_ons: 0,
    other_timer_plain_shots: 0,
    angry_short_rings: 0,
    radioactive_lizard_kills: 0,
    radioactive_dying_skips: 0,
    radioactive_corpse_pulses: 0,
    jinxed_freeze_procs: 0,
    jinxed_freeze_kills: 0,
    contract_dead_player_one: 0,
    contract_charges: 0,
    favourite_reassignments: 0,
    favourite_clip_bonus_kept: 0,
    favourite_pistol_kills: 0,
    favourite_pistol_weapon_drops: 0,
  };
  if (rules198) coverage.rules_1_9_8 = rules198;
  const summary = () => {
    state(e);
    return {
      pending: field(e, "globals.game_state_pending"),
      xp: field(e, "players[0].experience"),
      health: field(e, "players[0].health", true),
      elapsed_ms: field(e, "globals.run_elapsed_ms"),
      timeline_ms: field(e, "globals.quest_spawn_timeline"),
      rng: field(e, "globals.rng"),
    };
  };
  let pickNext = false,
    final;
  const mode = cfg.readUInt32LE(4);
  for (let tick = 0; tick < limit; tick++) {
    const snapshot = state(e);
    const f = (name) => field(e, name, true),
      u = (name) => field(e, name);
    let active = 0;
    for (const c of CREATURES)
      if (snapshot.readUInt32LE(c.active) && snapshot.readFloatLE(c.health) > 0) active++;
    coverage.peak_creatures = Math.max(active, coverage.peak_creatures);
    coverage.stall ||= u("globals.quest_spawn_stall_timer_ms") > 0;
    const transition = u("globals.quest_transition_timer_ms");
    coverage.transitions ||= transition > 0 && transition < 0x80000000;
    for (const name of [
      "reflex_boost",
      "freeze",
      "weapon_power_up",
      "energizer",
      "double_xp",
    ]) {
      if (f(`globals.bonus_${name}_timer`) > 0) coverage.bonuses.add(name);
    }
    // Each player steers by its own surroundings; the second player circles the other way.
    const views = Array.from({ length: players }, (_, p) => {
      const x = f(`players[${p}].pos_x`),
        y = f(`players[${p}].pos_y`);
      coverage.weapons.add(u(`players[${p}].weapon_id`));
      let nearest = Infinity,
        target;
      for (const c of CREATURES) {
        if (!snapshot.readUInt32LE(c.active) || snapshot.readFloatLE(c.health) <= 0)
          continue;
        const cx = snapshot.readFloatLE(c.pos_x),
          cy = snapshot.readFloatLE(c.pos_y),
          d = Math.hypot(cx - x, cy - y);
        if (d < nearest) {
          nearest = d;
          target = [cx, cy];
        }
      }
      let mx = 0,
        my = 0;
      if (bot) {
        if (target && nearest < (hunt.evade ?? 210)) {
          mx = x - target[0];
          my = y - target[1];
        } else {
          mx = -(y - 512) * (p ? -1 : 1);
          my = (x - 512) * (p ? -1 : 1);
          if (Math.hypot(mx, my) < 100) mx = 1;
        }
        if (x < 140) mx = Math.abs(mx) + 180;
        if (x > 884) mx = -Math.abs(mx) - 180;
        if (y < 140) my = Math.abs(my) + 180;
        if (y > 884) my = -Math.abs(my) - 180;
        if ((bot === 2 || bot === 4) && nearest > 120) {
          let distance = 300,
            pickup;
          for (let b = 0; b < 16; b++) {
            const bonus = u(`bonuses[${b}].bonus_id`);
            if (!bonus || u(`bonuses[${b}].picked`) !== 0 || hunt.skip?.includes(bonus))
              continue;
            const bx = f(`bonuses[${b}].time.pos_x`),
              by = f(`bonuses[${b}].time.pos_y`),
              d = Math.hypot(bx - x, by - y);
            if (d < distance) {
              distance = d;
              pickup = [bx, by];
            }
          }
          if (pickup) {
            mx = pickup[0] - x;
            my = pickup[1] - y;
          }
        }
        // The bot steps away from a bonus it skips.
        for (let b = 0; hunt.skip && b < 16; b++) {
          if (!hunt.skip.includes(u(`bonuses[${b}].bonus_id`)) || u(`bonuses[${b}].picked`) !== 0) continue;
          const dx = x - f(`bonuses[${b}].time.pos_x`),
            dy = y - f(`bonuses[${b}].time.pos_y`),
            d = Math.hypot(dx, dy);
          if (d > 0 && d < 60) [mx, my] = bot === 2 || bot === 4 ? [dx, dy] : [-dx, -dy];
        }
        // A player the hunt holds still only aims and shoots.
        const n = hunt.still?.includes(p) ? Infinity : Math.hypot(mx, my);
        mx = (bot === 2 || bot === 4 ? mx : -mx) / n;
        my = (bot === 2 || bot === 4 ? my : -my) / n;
      }
      const [wx, wy] = target ?? [x, y - 60];
      return {
        x,
        y,
        health: f(`players[${p}].health`),
        heading: f(`players[${p}].heading`),
        aimHeading: f(`players[${p}].aim_heading`),
        mx,
        my,
        wx,
        wy,
        target,
      };
    });
    let commands = [];
    // The perk screen pauses the run: a pick follows the tick that opened the menu, and a tick without one cancels it.
    const menuOpen = pickNext;
    pickNext = false;
    if (
      bot &&
      views.some((v) => v.health > 0) &&
      mode !== 2 &&
      u("globals.perk_pending_count") >= (bot === 4 ? 2 : 1)
    ) {
      if (menuOpen) {
        let choice = 0;
        const prefer = typeof hunt.prefer === "function" ? hunt.prefer(views) : hunt.prefer;
        if (prefer) {
          const offered = [0, 1, 2, 3, 4].map((i) => u(`globals.perk_choice_ids[${i}]`));
          choice = Math.max(0, offered.indexOf(prefer.find((id) => offered.includes(id))));
        }
        if (bot === 4) {
          while (
            choice < 4 &&
            [8, 15].includes(u(`globals.perk_choice_ids[${choice}]`))
          )
            choice++;
        }
        // The batch picks, then opens the menu again for the next pending perk.
        commands = bot === 4 ? [[1, choice], [2, 0]] : [[1, choice]];
        pickNext = bot === 4;
      } else {
        commands = [[2, 0]];
        pickNext = true;
        coverage.menu++;
        coverage.survivor_menu += Number(views.some((v) => v.health <= 0));
      }
    }
    coverage.max_commands = Math.max(coverage.max_commands, commands.length);
    // Coverage names the perks the step applied, read from the counts it raised.
    const perkCounts = () => Array.from({ length: PERK_COUNTS }, (_, i) => u(`players[0].perk_counts[${i}]`));
    const countsBefore = commands.length && perkCounts();
    const inputs = views.map((view, p) => {
      // The players reload at different times.
      const reload = bot && (tick + p * 61) % 137 === 0;
      coverage.reload += Number(reload);
      const [moveX, moveY, aimX, aimY, flags] = encodeControls(schemes[p], { ...view, moving: Boolean(bot) });
      return [
        moveX,
        moveY,
        aimX,
        aimY,
        flags |
          (bot && view.target ? 1 : 0) |
          (reload ? 65536 : 0) |
          (hunt.gKey && tick % 211 < 30 ? G_KEY : 0),
      ];
    });
    const fireBullets = players === 1 && f("players[0].fire_bullets_timer") > 1 / 60;
    const shotsBefore = u("globals.highscore_record_shots_fired");
    const before198 = rules198 && look198(snapshot, players);
    const r = record(inputs, commands);
    if (!step(e, r)) throw Error(`Bot rejected tick ${tick} in mode ${mode}: ${refusal(e)}`);
    records.push(r);
    final = summary();
    if (rules198) observe198(before198, look198(state(e), players), commands, rules198);
    const emitted = u("globals.highscore_record_shots_fired") - shotsBefore;
    if (fireBullets && emitted > 0) coverage.fire_bullets_volleys.add(emitted);
    if (countsBefore)
      perkCounts().forEach((count, id) => {
        if (count > countsBefore[id]) coverage.perks.add(id);
      });
    if (terminal.has(final.pending)) {
      // The run-down: the game simulates until its UI timeline runs out, then refuses input.
      const idle = record(views.map((view, p) => encodeControls(schemes[p], { ...view, moving: false })));
      while (step(e, idle)) {
        records.push(idle);
        if (++coverage.run_down > 40) throw Error("Run-down did not end");
      }
      final = summary();
      break;
    }
  }
  for (const key of ["weapons", "perks", "bonuses", "fire_bullets_volleys"])
    coverage[key] = [...coverage[key]].sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
  return { input: Buffer.concat([cfg, ...records]), records, final, coverage };
}

// `records`: one record, or a run whose records up to the last one are accepted. Both builds give `reason`; the
// native host reads at most 16 commands, so it stops at a longer tick itself (exit 4).
function rejects(label, cfg, records, reason, expected = 5) {
  console.log(`Checking rejection: ${label}`);
  const run = [records].flat();
  init(e, cfg);
  for (const r of run.slice(0, -1)) if (!step(e, r)) throw Error(`WASM refused the lead-in of ${label}: ${refusal(e)}`);
  if (step(e, run.at(-1))) throw Error(`WASM accepted ${label}`);
  if (refusal(e) !== reason) throw Error(`WASM refused ${label} for "${refusal(e)}", not "${reason}"`);
  const n = spawnSync(native, [], {
    input: Buffer.concat([cfg, ...run]),
    // A lead-in prints a snapshot for each of its ticks.
    maxBuffer: 1 << 30,
    timeout: 60000,
  });
  if (n.status !== expected || (expected === 5 && !n.stderr.includes(`: ${reason} (`)))
    throw Error(`Native ${label}: status=${n.status} signal=${n.signal} error=${n.error?.message} stdout=${n.stdout.length} ${n.stderr}`);
}

const normal = config(1);
rejects("NaN", normal, record([NaN, 0, 512, 512, schemeFlags(MOUSE)]), "malformed input");
rejects("infinite aim", normal, record([0, 0, Infinity, 512, schemeFlags(MOUSE)]), "malformed input");
rejects("unknown flags", normal, record([0, 0, 512, 512, schemeFlags(MOUSE) | 0x100000]), "malformed input");
rejects("unsupported movement scheme", normal, record([0, 0, 512, 512, schemeFlags({ ...PAD, move: 6 })]), "malformed input");
rejects("unsupported aim scheme", normal, record([0, 0, 512, 512, schemeFlags({ ...MOUSE, aim: 6 })]), "malformed input");
rejects("movement scheme without presence", normal, record([0, 0, 512, 512, schemeFlags(MOUSE) & ~0x100]), "malformed input");
rejects("aim scheme without presence", normal, record([0, 0, 512, 512, schemeFlags(PAD) & ~0x1000]), "malformed input");
rejects("movement key without presence", normal, record([0, 0, 512, 512, schemeFlags(MOUSE) | 16]), "malformed input");
rejects(
  "perk without entitlement",
  normal,
  record([0, 0, 512, 512, schemeFlags(MOUSE)], [[1, 0]]),
  "perk_pick without an open perk menu",
);
rejects(
  "menu without entitlement",
  normal,
  record([0, 0, 512, 512, schemeFlags(MOUSE)], [[2, 0]]),
  "perk_menu_open without a pending perk",
);
rejects(
  "Rush perk command",
  config(2),
  record([0, 0, 512, 512, schemeFlags(MOUSE)], [[2, 0]]),
  "perk command in Rush",
);
rejects(
  "Rush perk pick",
  config(2),
  record([0, 0, 512, 512, schemeFlags(MOUSE)], [[1, 0]]),
  "perk command in Rush",
);
rejects(
  "malformed second player's input",
  config(1, 1, 1, { players: 2 }),
  record([[0, 0, 512, 512, schemeFlags(MOUSE)], [0, NaN, 512, 512, schemeFlags(PAD)]]),
  "malformed input",
);
rejects("unknown command", normal, record([0, 0, 512, 512, schemeFlags(MOUSE)], [[99, 0]]), "unknown command");
rejects(
  "command count overflow",
  normal,
  record([0, 0, 512, 512, schemeFlags(MOUSE)], Array(17).fill([2, 0])),
  "more than 16 commands",
  4,
);

// A large vector still passes through the game's direction/speed cap.
function displacement(magnitude) {
  init(e, normal);
  for (let i = 0; i < 90; i++)
    if (!step(e, record([magnitude, 0, 512, 512, schemeFlags(MOUSE)])))
      throw Error("Movement probe");
  state(e);
  return [
    field(e, "players[0].pos_x", true),
    field(e, "players[0].pos_y", true),
    field(e, "players[0].move_speed", true),
  ];
}
if (JSON.stringify(displacement(1)) !== JSON.stringify(displacement(100)))
  throw Error("Large vector speeds up movement");

// A config that never starts: WASM refuses its init and the native host exits 3.
function unstartable(label, head) {
  let refused = false;
  try {
    init(e, head);
  } catch {
    refused = true;
  }
  const n = spawnSync(native, [], { input: head, timeout: 60000 });
  if (!refused || n.status !== 3) throw Error(`${label} started: wasm=${!refused} native=${n.status}`);
}
// A run of no players or more than two.
for (const players of [0, 3]) unstartable(`A ${players}-player run`, config(1, 1, 1, { players }));
// A malformed custom quest.
unstartable("An empty custom quest", Buffer.concat([config(3, 0, 0), Buffer.alloc(QUEST_BYTES)]));
// A build other than 1.9.93 and 1.9.8, and 1.9.8 under the rules-1 profile, which predates it.
for (const [build, rules] of [[0, 2], [10992, 2], [CL_BUILD_1_9_8, 1]])
  unstartable(`A build ${build} run under rules ${rules}`, config(1, 1, 1, { clBuild: build, rules }));

// A custom quest's table, as checks/replay.py writes it from a recipe; its scenario starts the quest at stage 0.0.
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "custom-quest-"));
function quest(recipe) {
  const file = path.join(scratch, `${path.basename(recipe)}.bin`);
  const args = ["run", "--no-sync", "python", fileURLToPath(new URL("checks/replay.py", CORE)), "--recipe"];
  const made = spawnSync("uv", [...args, fileURLToPath(new URL(`../src/crimson/quests/dsl/${recipe}`, CORE)), "--out", file]);
  if (made.status !== 0) throw Error(`${recipe}: ${made.stderr}`);
  return fs.readFileSync(file);
}

// A supported custom quest: slow zombie waves, one fixed starting weapon, and Fire Bullets as
// the only timed pickup. The bot still earns and collects it through ordinary input. Disable
// offerable perks (except the mandatory fallback) so extra perk shots cannot mask volley counts.
function pelletQuest(weapon) {
  const q = Buffer.alloc(QUEST_BYTES);
  [weapon, 0, 1, 0, 60, 0x3ffc, 0xffffff7e, 0x3ffffff, 0xfffffffc, 3]
    .forEach((v, i) => q.writeUInt32LE(v, i * 4));
  for (let i = 0; i < 60; i++) {
    const at = 40 + i * 24, angle = i * Math.PI / 3;
    q.writeFloatLE(512 + 400 * Math.cos(angle), at);
    q.writeFloatLE(512 + 400 * Math.sin(angle), at + 4);
    q.writeFloatLE(angle, at + 8);
    q.writeInt32LE(0x42, at + 12); // ZOMBIE_SMALL_WHITE
    q.writeInt32LE(1000 + i * 2000, at + 16);
    q.writeInt32LE(1, at + 20);
  }
  return q;
}

// `BonusId` in src/crimson/bonuses.
const BONUS = { weapon: 3, freeze: 11, medikit: 12, fireBullets: 14 };
// A custom quest for a hunter: its starting weapon, the drops and perks it keeps (every other one disabled but Points
// and the mandatory fallback perk), and `waves` of `[template, count]` taking turns around the arena, one every
// `every` ms.
function huntQuest(weapon, bonuses, perks, waves, every) {
  const q = Buffer.alloc(QUEST_BYTES);
  // The disabled-id mask that keeps `ids` out of `mask`.
  const kept = (ids, mask) => ids.reduce((m, id) => m & ~(1 << id), mask);
  const count = 80;
  [weapon, 2, 5, 1, count, kept(bonuses, 0x7ffc), kept(perks.filter((id) => id < 32), 0xffffff7e),
    kept(perks.filter((id) => id >= 32).map((id) => id - 32), 0x3ffffff), 0, 0]
    .forEach((v, i) => q.writeUInt32LE(v >>> 0, i * 4));
  for (let i = 0; i < count; i++) {
    const at = 40 + i * 24, angle = i * 2.4, [template, copies] = waves[i % waves.length];
    q.writeFloatLE(512 + 450 * Math.cos(angle), at);
    q.writeFloatLE(512 + 450 * Math.sin(angle), at + 4);
    q.writeFloatLE(angle, at + 8);
    q.writeInt32LE(template, at + 12);
    q.writeInt32LE(1000 + i * every, at + 16);
    q.writeInt32LE(copies, at + 20);
  }
  return q;
}
// Zombies (ZOMBIE_SMALL_WHITE), lone lizards (LIZARD_RANDOM), which only 1.9.8's Radioactive kills, and a lizard grid
// (FORMATION_GRID_LIZARD_WHITE), whose 27 lizards die with their leader: Radioactive pays again for one it burns on
// that frame under 1.9.8's bugs (bug 56).
const HUNT_WAVES = [[0x42, 3], [0x2e, 2], [0x42, 3], [0x16, 1]];

// [name, config arguments, bot, tick limit, controls, hunt]; a `quest` option plays that custom quest.
const scenarios = [
  ["rules1-survival", [1, 1, 1, { seed: 44, rules: 1 }], 2, 12000, MOUSE],
  ["rules1-coop", [1, 1, 1, { seed: 41, players: 2, rules: 1 }], 2, 12000, [PAD, MOUSE]],
  ["rules1-coop-legacy-reload", [1, 1, 1, { seed: 41, players: 2, rules: 1, legacyCoopReload: 1 }], 2, 12000, [PAD, MOUSE]],
  ["rush-idle", [2], false, 6000, PAD],
  ["rush-bot", [2], true, 30000, MOUSE],
  ["rush-evade", [2, 1, 1, { seed: 1337 }], 2, 30000, PAD],
  ["survival-idle", [1], false, 10000, MOUSE],
  ["survival-bot", [1], true, 30000, PAD],
  ["survival-evade", [1], 2, 30000, MOUSE],
  ["survival-evade-1337", [1, 1, 1, { seed: 1337 }], 2, 30000, PAD],
  ["survival-command-batches", [1, 1, 1, { seed: 1337 }], 4, 30000, MOUSE],
  // A Hardcore box left ticked toughens the milestone waves, and a quest retry count eases them, only under the
  // original's bugs (bug 38).
  ["survival-hardcore", [1, 1, 1, { seed: 22, hardcore: 1 }], 2, 30000, { move: MOVE.static, aim: AIM.mouse }],
  ["survival-retry", [1, 1, 1, { seed: 22, retry: 3 }], 2, 30000, { move: MOVE.static, aim: AIM.mouse }],
  [
    "survival-hunt-jinxed",
    [1, 1, 1, { seed: 28 }],
    2,
    30000,
    PAD,
    { prefer: [PERK.jinxed, PERK.pyrokinetic, PERK.evilEyes, PERK.doctor], gKey: true },
  ],
  [
    "survival-hunt-highlander",
    [1, 1, 1, { seed: 106 }],
    2,
    30000,
    MOUSE,
    {
      // Death Clock comes last: once owned, the game stops offering the Regenerations.
      prefer: [PERK.highlander, PERK.regeneration, PERK.greaterRegeneration, PERK.bandage, PERK.deathClock],
    },
  ],
  ["survival-relative-keyboard", [1, 1, 1, { seed: 21 }], 2, 30000, { move: MOVE.relative, aim: AIM.keyboard }],
  ["survival-static-mouse", [1, 1, 1, { seed: 22 }], 2, 30000, { move: MOVE.static, aim: AIM.mouse }],
  ["survival-static-joystick", [1, 1, 1, { seed: 23 }], 2, 30000, { move: MOVE.static, aim: AIM.joystick }],
  ["survival-computer", [1, 1, 1, { seed: 24 }], false, 30000, { move: MOVE.computer, aim: AIM.computer }],
  ["rush-unknown-aim", [2, 1, 1, { seed: 25 }], 2, 30000, { move: MOVE.pad, aim: AIM.unknown }],
  ["quest-point-click", [3, 2, 3, { seed: 26 }], true, 30000, { move: MOVE.pointClick, aim: AIM.mouseRelative }],
];
for (const [weapon, name] of [[30, "gauss"], [10, "multi-plasma"]]) {
  for (const rules of [1, 2])
    scenarios.push([`fire-bullets-${name}-rules${rules}`,
      [3, 0, 0, { seed: 1, rules, quest: pelletQuest(weapon) }], 2, 12000, MOUSE]);
  scenarios.push([`fire-bullets-${name}-1.9.8`,
    [3, 0, 0, { seed: 1, clBuild: CL_BUILD_1_9_8, quest: pelletQuest(weapon) }], 2, 12000, MOUSE]);
}
for (let major = 1; major <= 5; major++)
  for (let minor = 1; minor <= 10; minor++)
    scenarios.push([`quest-${major}.${minor}`, [3, major, minor], true, 30000, minor % 2 ? PAD : MOUSE]);
scenarios.push(
  ["custom-crosswind", [3, 0, 0, { seed: 31, quest: quest("examples/crosswind.quest") }], true, 30000, PAD],
  ["custom-closing-circle", [3, 0, 0, { seed: 32, quest: quest("examples/closing-circle.quest") }], true, 30000, MOUSE],
  ["custom-1.1", [3, 0, 0, { seed: 33, quest: quest("stock/1.1.quest") }], true, 30000, MOUSE],
  [
    "custom-formation-parade",
    [3, 0, 0, { seed: 34, quest: quest("examples/formation-parade.quest") }],
    true,
    30000,
    PAD,
  ],
);
// Two players, each with their own controls: the second's keys, axes and cursor are its own. The hunter prefers the
// perks whose co-op fixes the ranked rules carry.
scenarios.push(
  ["coop-survival-extra-choices", [1, 1, 1, { seed: 2, players: 2 }], 2, 20000, [MOUSE, PAD],
    { prefer: [43, 21] }],
  ["coop-survival-independent-timers", [1, 1, 1, { seed: 44, players: 2 }], 2, 30000, [MOUSE, PAD],
    { prefer: [PERK.hotTempered, PERK.fireCough, PERK.alternateWeapon] }],
  ["coop-survival", [1, 1, 1, { seed: 41, players: 2 }], 2, 30000, [PAD, MOUSE]],
  ["coop-rush", [2, 1, 1, { seed: 42, players: 2 }], 2, 30000, [MOUSE, { move: MOVE.relative, aim: AIM.keyboard }]],
  ["coop-quest-2.4", [3, 2, 4, { seed: 43, players: 2 }], true, 30000, [{ move: MOVE.static, aim: AIM.joystick }, { move: MOVE.pointClick, aim: AIM.mouseRelative }]],
  [
    "coop-survival-hunt",
    [1, 1, 1, { seed: 44, players: 2 }],
    2,
    30000,
    [MOUSE, PAD],
    { prefer: [PERK.jinxed, PERK.regeneration, PERK.plaguebearer, PERK.pyromaniac, PERK.greaterRegeneration] },
  ],
  [
    "coop-survival-plague",
    [1, 1, 1, { seed: 53, players: 2 }],
    2,
    30000,
    [MOUSE, PAD],
    { prefer: [PERK.plaguebearer, PERK.pyromaniac, PERK.jinxed, PERK.regeneration] },
  ],
  // Under the ranked rules this run fills the effect pool (original bug 39's overflow) as frozen creatures
  // shatter: overflow entries free at their own times and leave decals, which co-op rollbacks must restore and
  // bake (checks/game_coop.mjs).
  ["coop-survival-effects", [1, 1, 1, { seed: 22, players: 2 }], 2, 20000, [PAD, MOUSE]],
  // A co-op quest completed: its end tune, which co-op music waits to confirm.
  ["coop-quest-1.1", [3, 1, 1, { seed: 46, players: 2 }], true, 30000, [PAD, MOUSE]],
);
// The 1.9.8 rules (docs/rewrite/rules-1.9.8.md), each run under 1.9.8's own bugs and again under their fixes. The
// hunters prefer the perks whose rules or bugs 1.9.8 changes and pick up Fire Bullets, which 1.9.8 adds to each shot.
const V1_9_8 = { clBuild: CL_BUILD_1_9_8 };
const DROPS_1_9_8 = [BONUS.freeze, BONUS.medikit, BONUS.fireBullets];
scenarios.push(
  ["1.9.8-survival", [1, 1, 1, { ...V1_9_8, seed: 44 }], 2, 30000, MOUSE],
  ["1.9.8-rush", [2, 1, 1, { ...V1_9_8, seed: 1337 }], 2, 30000, PAD],
  ["1.9.8-quest-1.5", [3, 1, 5, V1_9_8], true, 30000, PAD],
  ["1.9.8-quest-3.3", [3, 3, 3, V1_9_8], true, 30000, MOUSE],
  ["1.9.8-quest-5.10", [3, 5, 10, V1_9_8], true, 30000, PAD],
  // Hardcore: Gauntlet's larger rings, its zombie groups grown by eight and tougher creatures from faster nests.
  ["1.9.8-quest-4.7-hardcore", [3, 4, 7, { ...V1_9_8, hardcore: 1 }], true, 30000, MOUSE],
  // G does nothing in 1.9.8.
  [
    "1.9.8-survival-hunt",
    [1, 1, 1, { ...V1_9_8, seed: 28 }],
    2,
    30000,
    PAD,
    { prefer: [PERK.myFavouriteWeapon, PERK.ammoManiac, PERK.radioactive, PERK.jinxed, PERK.angryReloader], gKey: true },
  ],
  // Under the fixes, two players fill the 64-slot projectile pool.
  ["1.9.8-coop-survival", [1, 1, 1, { ...V1_9_8, seed: 44, players: 2 }], 2, 30000, [MOUSE, PAD],
    { prefer: [PERK.jinxed, PERK.radioactive, PERK.angryReloader, PERK.myFavouriteWeapon, PERK.infernalContract] }],
  // The Pulse Gun, the one weapon whose reload (0.1 s) is under the 0.5 s Angry Reloader gate 1.9.8 lacks, with no
  // Weapon drops to replace it; Freeze for Jinxed (bug 57); creatures let near for Radioactive, which kills lizards
  // and, as a grid leader's death kills its lizards, has a pulse due on one: 1.9.8's bugs burn it again and the
  // fixes leave it (bug 56).
  [
    "1.9.8-pulse-hunt",
    [3, 0, 0, { ...V1_9_8, seed: 55, quest: huntQuest(19, DROPS_1_9_8,
      [PERK.angryReloader, PERK.radioactive, PERK.jinxed], HUNT_WAVES, 2500) }],
    2,
    30000,
    MOUSE,
    { prefer: [PERK.angryReloader, PERK.radioactive, PERK.jinxed], evade: 90 },
  ],
  // The Pistol kept, stepping around Weapon drops, for My Favourite Weapon, which in 1.9.8 lets the Pistol's forced
  // Weapon drops through (bug 60); then Ammo Maniac, whose reassignment loses the perk's clip bonus (bug 59).
  [
    "1.9.8-favourite-hunt",
    [3, 0, 0, { ...V1_9_8, seed: 63, quest: huntQuest(1, DROPS_1_9_8,
      [PERK.myFavouriteWeapon, PERK.ammoManiac], [[0x42, 2], [0x2e, 1]], 3000) }],
    2,
    30000,
    PAD,
    { prefer: [PERK.myFavouriteWeapon, PERK.ammoManiac], skip: [BONUS.weapon] },
  ],
  // Two players: each one's Fire Bullets adds to their own shots only, unless 1.9.8's bugs are kept (bug 13). Player
  // one stands to die, and Infernal Contract, taken only then, brings them back in 1.9.8 (bug 58).
  [
    "1.9.8-coop-hunt",
    [3, 0, 0, { ...V1_9_8, seed: 62, players: 2, quest: huntQuest(5, DROPS_1_9_8,
      [PERK.infernalContract, PERK.radioactive, PERK.jinxed], HUNT_WAVES, 2000) }],
    2,
    30000,
    [MOUSE, PAD],
    {
      prefer: ([one]) => one.health > 0 ? [PERK.radioactive, PERK.jinxed, PERK.instantWinner] : [PERK.infernalContract],
      evade: 90,
      still: [0],
    },
  ],
);
scenarios.push([
  "quest-settings",
  [3, 1, 1, { seed: 2345, detail: 0, violence: 1, hardcore: 1, retry: 3, friendly: 1, usage: true }],
  true,
  30000,
  PAD,
]);
// Every field except the Shock Chain slot's starting value, which the host sets
// from the bug policy at run start (bug 32).
const POLICY_FREE = fieldRanges((n) => n !== "globals.shock_chain_projectile_id");
const twin = loadCore(wasm);

// Whether the ranked rules play `run`'s own input to the same state on every tick.
// The bot reads only state, so its ranked run would be this run again.
function rankedPlaysAlike(run, cfg) {
  const { config: original, records } = decode(run.input);
  init(e, original);
  init(twin, cfg);
  for (let tick = -1; tick < records.length; tick++) {
    if (tick >= 0 && step(e, records[tick]) !== step(twin, records[tick])) return false;
    if (firstDifference(state(e), state(twin), POLICY_FREE) >= 0) return false;
  }
  return true;
}

const report = {
  guards: "17 native/WASM rejection probes; unstartable player counts, custom quest and builds; large-vector speed cap",
  cases: [],
};
// Each scenario plays under the original's bugs, and again under the documented
// fixes of the ranked rules wherever those change the run.
for (const [scenario, [mode, major, minor, options], bot, limit, scheme, hunt] of scenarios) {
  console.log(`${scenario}: generating input stream`);
  const head = (preserveBugs) => {
    const cfg = config(mode, major, minor, { ...options, preserveBugs, legacyCoopReload: preserveBugs ? 0 : (options?.legacyCoopReload ?? 0) });
    return options?.quest ? Buffer.concat([cfg, options.quest]) : cfg;
  };
  const runs = [[scenario, play(head(1), bot, limit, scheme, hunt)]];
  const ranked = head(0);
  if (rankedPlaysAlike(runs[0][1], ranked)) console.log(`${scenario}: the ranked rules play the same run`);
  else runs.push([`${scenario}-ranked`, play(ranked, bot, limit, scheme, hunt)]);
  for (const [name, run] of runs) {
    if (scenario.startsWith("fire-bullets-")) {
      const gauss = scenario.includes("-gauss-");
      const fixed = options.rules === 2 && run.input.readUInt32LE(44) === 0;
      // 1.9.8 keeps the weapon's own shots, six Gauss Shotgun pellets or five Multi-Plasma shots, and adds a Fire
      // Bullets shot to each.
      const expected = options.clBuild === CL_BUILD_1_9_8 ? (gauss ? 12 : 10) : fixed ? (gauss ? 6 : 5) : (gauss ? 1 : 3);
      if (JSON.stringify(run.coverage.fire_bullets_volleys) !== JSON.stringify([expected]))
        throw Error(`${name}: expected Fire Bullets volleys of ${expected}, got ${run.coverage.fire_bullets_volleys}`);
    }
    fs.writeFileSync(path.join(fixtures, `${name}.rsi`), run.input);
    console.log(`${name}: comparing ${run.input.length} input bytes`);
    const parity = await compare(run.input, native, wasm);
    report.cases.push({ name, ...parity, final: run.final, coverage: run.coverage });
    fs.writeFileSync(path.join(out, "report.json"), JSON.stringify(report, null, 2) + "\n");
    console.log(`${name}: ${parity.ticks} ticks, terminal ${run.final.pending}, native/WASM + reset passed`);
  }
}
// A pick needs the menu the tick before opened: not in the opening tick itself, and not after a cancel. A menu
// request after a pick needs a perk the pick left pending.
{
  const name = "survival-bot-ranked";
  const cfg = config(1, 1, 1, { preserveBugs: 0 });
  const records = play(cfg, true, 30000, PAD, {}).records;
  const opened = records.findIndex((r) => r.readUInt32LE(20) === 1 && r.readInt32LE(24) === 2);
  if (opened < 0) throw Error(`${name} never opened the perk menu`);
  const withCommands = (r, commands) => record([0, 4, 8, 12].map((at) => r.readFloatLE(at)).concat(r.readUInt32LE(16)), commands);
  const unopened = "perk_pick without an open perk menu";
  rejects(
    "pick outside the offered slots",
    cfg,
    [...records.slice(0, opened + 1), withCommands(records[opened + 1], [[1, 6]])],
    "perk_pick of a choice that is not offered",
  );
  rejects("pick in the tick that opens the menu", cfg, [...records.slice(0, opened), withCommands(records[opened], [[2, 0], [1, 0]])], unopened);
  rejects(
    "pick after a cancel",
    cfg,
    [...records.slice(0, opened + 1), withCommands(records[opened + 1], []), withCommands(records[opened + 1], [[1, 0]])],
    unopened,
  );
  rejects(
    "menu after the pick that spent the last perk",
    cfg,
    [...records.slice(0, opened + 1), withCommands(records[opened + 1], [[1, 0], [2, 0]])],
    "perk_menu_open without a pending perk",
  );
}
if (!report.cases.some((c) => c.coverage.survivor_menu > 0))
  throw Error("No perk menu opened by a surviving player");
if (!report.cases.some((c) => c.coverage.max_commands > 1))
  throw Error("No ordered command batch covered");
if (!report.cases.some((c) => c.final.pending === 8))
  throw Error("No quest completion covered");
if (!report.cases.some((c) => c.name.startsWith("custom-") && c.final.pending === 8))
  throw Error("No custom quest completion covered");
fs.rmSync(scratch, { recursive: true });
if (!report.cases.some((c) => c.final.pending === 12))
  throw Error("No quest failure covered");
if (!report.cases.some((c) => c.final.pending === 7))
  throw Error("No game over covered");
// The 1.9.8 rules and bugs in the streams (observe198), under the bug policy given (1 keeps 1.9.8's bugs, 0 fixes
// them) where the two decide it apart: what no 1.9.8 run may show, then what some run must reach.
const cases198 = report.cases
  .filter((c) => c.coverage.rules_1_9_8)
  .map((c) => ({ name: c.name, ...c.coverage.rules_1_9_8 }));
const underPolicy = (policy) => (policy === undefined ? "" : policy ? " under its bugs" : " under the fixes");
const runs = (shows, policy) =>
  cases198.filter((c) => shows(c) && (policy === undefined || c.preserve_bugs === policy));
const shown = [
  ["projectile slot past 64 used", (c) => c.last_projectile_slot >= 64],
  ["perk menu offering a perk 1.9.8 lacks", (c) => c.absent_perk_offers],
  ["Fire Bullets drop while a flame or rocket weapon is held", (c) => c.flame_or_rocket_fire_bullets_drops],
  ["Fire Bullets shot on the other player's timer", (c) => c.other_timer_add_ons, 0],
  ["Radioactive pulse left to a dying creature", (c) => c.radioactive_dying_skips, 1],
  ["Radioactive pulse burning a creature already dead", (c) => c.radioactive_corpse_pulses, 0],
  ["Jinxed kill during Freeze", (c) => c.jinxed_freeze_kills, 0],
  [
    "Infernal Contract leaving a dead player one's health alone",
    (c) => c.contract_charges < c.contract_dead_player_one,
    1,
  ],
  ["Infernal Contract changing a dead player one's health", (c) => c.contract_charges, 0],
  ["reassigned clip keeping My Favourite Weapon's 2", (c) => c.favourite_clip_bonus_kept, 1],
  ["reassigned clip losing My Favourite Weapon's 2", (c) => c.favourite_clip_bonus_kept < c.favourite_reassignments, 0],
  ["Weapon drop while a Pistol holder has My Favourite Weapon", (c) => c.favourite_pistol_weapon_drops, 0],
].flatMap(([what, shows, policy]) =>
  runs(shows, policy).map((c) => `${c.name}: a 1.9.8 ${what}${underPolicy(policy)}`),
);
if (shown.length) throw Error(shown.join("\n"));
// Several of these only one stream reaches (a corpse pulse, a pulse left to a dying creature, Infernal Contract, Ammo
// Maniac with My Favourite Weapon, Fire Bullets on the other player's timer), so a change that only moves its bots
// loses them. All are named at once, as a defect that loses one can move a hunt off another.
const missed = [
  ["Fire Bullets shot added beside another", (c) => c.add_on_volleys],
  ["full 64-slot projectile pool", (c) => c.peak_projectiles === 64],
  ["perk menu", (c) => c.menus],
  ["drop of another bonus while a flame or rocket weapon is held", (c) => c.flame_or_rocket_drops],
  ["Fire Bullets shot on the other player's timer", (c) => c.other_timer_add_ons, 1],
  ["shot without Fire Bullets while only the other player's timer runs", (c) => c.other_timer_plain_shots, 0],
  ["Angry Reloader ring on a short reload", (c) => c.angry_short_rings],
  ["Radioactive lizard kill", (c) => c.radioactive_lizard_kills],
  ["Radioactive pulse burning a creature already dead", (c) => c.radioactive_corpse_pulses, 1],
  ["Radioactive pulse left to a dying creature", (c) => c.radioactive_dying_skips, 0],
  ["Jinxed kill during Freeze", (c) => c.jinxed_freeze_kills, 1],
  ["Jinxed proc during Freeze", (c) => c.jinxed_freeze_procs, 0],
  ["Infernal Contract with player one dead", (c) => c.contract_dead_player_one, 1],
  ["Infernal Contract with player one dead", (c) => c.contract_dead_player_one, 0],
  ["Ammo Maniac reassignment with My Favourite Weapon", (c) => c.favourite_reassignments, 1],
  ["Ammo Maniac reassignment with My Favourite Weapon", (c) => c.favourite_reassignments, 0],
  ["Weapon drop while a Pistol holder has My Favourite Weapon", (c) => c.favourite_pistol_weapon_drops, 1],
  ["Pistol holder's kill with My Favourite Weapon", (c) => c.favourite_pistol_kills, 0],
].flatMap(([what, reached, policy]) => (runs(reached, policy).length ? [] : [`${what}${underPolicy(policy)}`]));
if (missed.length)
  throw Error(
    "No 1.9.8 run covered these (a coverage loss, not necessarily a defect, where the bots only took another path; " +
      `retune or reseed the hunt that reached it):\n${missed.join("\n")}`,
  );
console.log(
  `Passed ${report.cases.length} scenarios; ${path.join(out, "report.json")}`,
);
