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

// Perk ids (`PerkId` in src/crimson/perks) that ranked-rules fixes touch.
const PERK = {
  pyrokinetic: 6,
  plaguebearer: 10,
  evilEyes: 11,
  doctor: 29,
  regeneration: 38,
  pyromaniac: 39,
  highlander: 41,
  jinxed: 42,
  greaterRegeneration: 45,
  deathClock: 47,
  bandage: 49,
};
const PERK_COUNTS = names.filter((n) => n.startsWith("players[0].perk_counts[")).length;
// FIRE_BULLETS_KEY_DOWN_FLAG in src/crimson/replay/types.py: the G key.
const G_KEY = 131072;

// Snapshot byte offsets of the creature fields the bot reads every tick.
const CREATURES = Array.from({ length: 384 }, (_, c) =>
  Object.fromEntries(
    ["active", "health", "pos_x", "pos_y"].map((f) => [f, index.get(`creatures[${c}].${f}`) * 4]),
  ),
);

// `hunt` steers a bot towards fixed behaviour: `prefer` lists perks to pick when offered, most wanted first; `gKey` holds G at times.
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
        if (target && nearest < 210) {
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
            if (!u(`bonuses[${b}].bonus_id`) || u(`bonuses[${b}].picked`) !== 0)
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
        const n = Math.hypot(mx, my);
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
        if (hunt.prefer) {
          const offered = [0, 1, 2, 3, 4].map((i) => u(`globals.perk_choice_ids[${i}]`));
          choice = Math.max(0, offered.indexOf(hunt.prefer.find((id) => offered.includes(id))));
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
    const r = record(inputs, commands);
    if (!step(e, r)) throw Error(`Bot rejected tick ${tick} in mode ${mode}: ${refusal(e)}`);
    records.push(r);
    final = summary();
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
  for (const key of ["weapons", "perks", "bonuses"])
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

// A run of no players or more than two never starts.
for (const players of [0, 3]) {
  const head = config(1, 1, 1, { players });
  let refused = false;
  try {
    init(e, head);
  } catch {
    refused = true;
  }
  const n = spawnSync(native, [], { input: head, timeout: 60000 });
  if (!refused || n.status !== 3) throw Error(`A ${players}-player run started: wasm=${!refused} native=${n.status}`);
}

// A malformed custom quest never starts: WASM refuses its init and the native host exits 3.
{
  const empty = Buffer.concat([config(3, 0, 0), Buffer.alloc(QUEST_BYTES)]);
  let refused = false;
  try {
    init(e, empty);
  } catch {
    refused = true;
  }
  const n = spawnSync(native, [], { input: empty, timeout: 60000 });
  if (!refused || n.status !== 3) throw Error(`An empty custom quest started: wasm=${!refused} native=${n.status}`);
}

// A custom quest's table, as checks/replay.py writes it from a recipe; its scenario starts the quest at stage 0.0.
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "custom-quest-"));
function quest(recipe) {
  const file = path.join(scratch, `${path.basename(recipe)}.bin`);
  const args = ["run", "--no-sync", "python", fileURLToPath(new URL("checks/replay.py", CORE)), "--recipe"];
  const made = spawnSync("uv", [...args, fileURLToPath(new URL(`../src/crimson/quests/dsl/${recipe}`, CORE)), "--out", file]);
  if (made.status !== 0) throw Error(`${recipe}: ${made.stderr}`);
  return fs.readFileSync(file);
}

// [name, config arguments, bot, tick limit, controls, hunt]; a `quest` option plays that custom quest.
const scenarios = [
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
  // Under the ranked rules this run fills the effect pool early (original bug 39's overflow), which co-op
  // rollbacks must restore (checks/game_coop.mjs).
  ["coop-survival-effects", [1, 1, 1, { seed: 44, players: 2 }], 2, 6000, [PAD, MOUSE]],
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
  guards: "17 native/WASM rejection probes; unstartable player counts and custom quest; large-vector speed cap",
  cases: [],
};
// Each scenario plays under the original's bugs, and again under the documented
// fixes of the ranked rules wherever those change the run.
for (const [scenario, [mode, major, minor, options], bot, limit, scheme, hunt] of scenarios) {
  console.log(`${scenario}: generating input stream`);
  const head = (preserveBugs) => {
    const cfg = config(mode, major, minor, { ...options, preserveBugs });
    return options?.quest ? Buffer.concat([cfg, options.quest]) : cfg;
  };
  const runs = [[scenario, play(head(1), bot, limit, scheme, hunt)]];
  const ranked = head(0);
  if (rankedPlaysAlike(runs[0][1], ranked)) console.log(`${scenario}: the ranked rules play the same run`);
  else runs.push([`${scenario}-ranked`, play(ranked, bot, limit, scheme, hunt)]);
  for (const [name, run] of runs) {
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
console.log(
  `Passed ${report.cases.length} scenarios; ${path.join(out, "report.json")}`,
);
