// Input-only bot and parity runner. No state mutation or score submission.
import fs from "node:fs";
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
  step,
} from "./engine.mjs";

const out = path.resolve(
  process.argv[2] ?? fileURLToPath(new URL("build", CORE)),
);
const native = path.join(out, "native/core"),
  wasm = path.join(out, "wasm/core.wasm");
const e = loadCore(wasm);
const terminal = new Set([7, 8, 12]);
const fixtures = path.join(out, "fixtures");
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
  evilEyes: 11,
  doctor: 29,
  regeneration: 38,
  highlander: 41,
  jinxed: 42,
  greaterRegeneration: 45,
  deathClock: 47,
  bandage: 49,
};
// FIRE_BULLETS_KEY_DOWN_FLAG in src/crimson/replay/types.py: the G key.
const G_KEY = 131072;

// Snapshot byte offsets of the creature fields the bot reads every tick.
const CREATURES = Array.from({ length: 384 }, (_, c) =>
  Object.fromEntries(
    ["active", "health", "pos_x", "pos_y"].map((f) => [f, index.get(`creatures[${c}].${f}`) * 4]),
  ),
);

// `hunt` steers a bot towards fixed behaviour: `prefer` lists perks to pick when offered, `gKey` holds G at times.
function play(cfg, bot, limit, scheme, hunt = {}) {
  init(e, cfg);
  const records = [],
    coverage = {
      weapons: new Set(),
      perks: new Set(),
      bonuses: new Set(),
      menu: 0,
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
    const x = f("players[0].pos_x"),
      y = f("players[0].pos_y"),
      health = f("players[0].health");
    let nearest = Infinity,
      target,
      active = 0;
    for (const c of CREATURES) {
      if (!snapshot.readUInt32LE(c.active) || snapshot.readFloatLE(c.health) <= 0)
        continue;
      active++;
      const cx = snapshot.readFloatLE(c.pos_x),
        cy = snapshot.readFloatLE(c.pos_y),
        d = Math.hypot(cx - x, cy - y);
      if (d < nearest) {
        nearest = d;
        target = [cx, cy];
      }
    }
    coverage.peak_creatures = Math.max(active, coverage.peak_creatures);
    coverage.weapons.add(u("players[0].weapon_id"));
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
    let mx = 0,
      my = 0;
    if (bot) {
      if (target && nearest < 210) {
        mx = x - target[0];
        my = y - target[1];
      } else {
        mx = -(y - 512);
        my = x - 512;
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
    let commands = [];
    if (
      bot &&
      health > 0 &&
      mode !== 2 &&
      u("globals.perk_pending_count") >= (bot === 4 ? 2 : 1)
    ) {
      if (pickNext) {
        let choice = 0;
        if (hunt.prefer) {
          const offered = [0, 1, 2, 3, 4].map((i) => u(`globals.perk_choice_ids[${i}]`));
          choice = Math.max(0, offered.findIndex((id) => hunt.prefer.includes(id)));
        }
        if (bot === 4) {
          while (
            choice < 4 &&
            [8, 15].includes(u(`globals.perk_choice_ids[${choice}]`))
          )
            choice++;
        }
        commands =
          bot === 4
            ? [
                [1, choice],
                [1, 0],
              ]
            : [[1, 0]];
        coverage.perks.add(u(`globals.perk_choice_ids[${choice}]`));
        pickNext = false;
      } else {
        commands = [[2, 0]];
        pickNext = true;
        coverage.menu++;
      }
    }
    coverage.max_commands = Math.max(coverage.max_commands, commands.length);
    const reload = bot && tick % 137 === 0;
    coverage.reload += Number(reload);
    const [wx, wy] = target ?? [x, y - 60];
    const view = {
      x,
      y,
      heading: f("players[0].heading"),
      aimHeading: f("players[0].aim_heading"),
      mx,
      my,
      wx,
      wy,
    };
    const [moveX, moveY, aimX, aimY, flags] = encodeControls(scheme, { ...view, moving: Boolean(bot) });
    const r = record(
      [
        moveX,
        moveY,
        aimX,
        aimY,
        flags |
          (bot && target ? 1 : 0) |
          (reload ? 65536 : 0) |
          (hunt.gKey && tick % 211 < 30 ? G_KEY : 0),
      ],
      commands,
    );
    if (!step(e, r)) throw Error(`Bot rejected tick ${tick} in mode ${mode}`);
    records.push(r);
    final = summary();
    if (terminal.has(final.pending)) {
      // The run-down: the game simulates until its UI timeline runs out, then refuses input.
      const idle = record(encodeControls(scheme, { ...view, moving: false }));
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
  return { input: Buffer.concat([cfg, ...records]), final, coverage };
}

function rejects(label, cfg, r, expected = 5) {
  console.log(`Checking rejection: ${label}`);
  init(e, cfg);
  if (step(e, r)) throw Error(`WASM accepted ${label}`);
  const n = spawnSync(native, [], {
    input: Buffer.concat([cfg, r]),
    maxBuffer: 1048576,
    timeout: 10000,
  });
  if (n.status !== expected)
    throw Error(`Native ${label}: status=${n.status} signal=${n.signal} error=${n.error?.message} stdout=${n.stdout.length} ${n.stderr}`);
}

const normal = config(1);
rejects("NaN", normal, record([NaN, 0, 512, 512, schemeFlags(MOUSE)]));
rejects("infinite aim", normal, record([0, 0, Infinity, 512, schemeFlags(MOUSE)]));
rejects("unknown flags", normal, record([0, 0, 512, 512, schemeFlags(MOUSE) | 0x100000]));
rejects("unsupported movement scheme", normal, record([0, 0, 512, 512, schemeFlags({ ...PAD, move: 6 })]));
rejects("unsupported aim scheme", normal, record([0, 0, 512, 512, schemeFlags({ ...MOUSE, aim: 6 })]));
rejects("movement scheme without presence", normal, record([0, 0, 512, 512, schemeFlags(MOUSE) & ~0x100]));
rejects("aim scheme without presence", normal, record([0, 0, 512, 512, schemeFlags(PAD) & ~0x1000]));
rejects("movement key without presence", normal, record([0, 0, 512, 512, schemeFlags(MOUSE) | 16]));
rejects(
  "perk without entitlement",
  normal,
  record([0, 0, 512, 512, schemeFlags(MOUSE)], [[1, 0]]),
);
rejects(
  "menu without entitlement",
  normal,
  record([0, 0, 512, 512, schemeFlags(MOUSE)], [[2, 0]]),
);
rejects(
  "Rush perk command",
  config(2),
  record([0, 0, 512, 512, schemeFlags(MOUSE)], [[2, 0]]),
);
rejects("unknown command", normal, record([0, 0, 512, 512, schemeFlags(MOUSE)], [[99, 0]]));
rejects(
  "command count overflow",
  normal,
  record([0, 0, 512, 512, schemeFlags(MOUSE)], Array(17).fill([2, 0])),
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

// [name, config arguments, bot, tick limit, controls, hunt]; every scenario runs under both bug policies.
const scenarios = [
  ["rush-idle", [2], false, 6000, PAD],
  ["rush-bot", [2], true, 30000, MOUSE],
  ["rush-evade", [2, 1, 1, { seed: 1337 }], 2, 30000, PAD],
  ["survival-idle", [1], false, 10000, MOUSE],
  ["survival-bot", [1], true, 30000, PAD],
  ["survival-evade", [1], 2, 30000, MOUSE],
  ["survival-evade-1337", [1, 1, 1, { seed: 1337 }], 2, 30000, PAD],
  ["survival-command-batches", [1, 1, 1, { seed: 1337 }], 4, 30000, MOUSE],
  [
    "survival-hunt-jinxed",
    [1, 1, 1, { seed: 7 }],
    2,
    30000,
    PAD,
    { prefer: [PERK.jinxed, PERK.pyrokinetic, PERK.evilEyes, PERK.doctor], gKey: true },
  ],
  [
    "survival-hunt-highlander",
    [1, 1, 1, { seed: 10 }],
    2,
    30000,
    MOUSE,
    {
      prefer: [PERK.highlander, PERK.deathClock, PERK.regeneration, PERK.greaterRegeneration, PERK.bandage],
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
scenarios.push([
  "quest-settings",
  [3, 1, 1, { seed: 2345, detail: 0, violence: 1, hardcore: 1, retry: 3, friendly: 1, usage: true }],
  true,
  30000,
  PAD,
]);
// The original's bugs, and the documented fixes of the ranked rules.
const policies = [
  ["", 1],
  ["-ranked", 0],
];
const report = {
  guards: "13 native/WASM rejection probes; large-vector speed cap",
  cases: [],
};
for (const [scenario, [mode, major, minor, options], bot, limit, scheme, hunt] of scenarios)
  for (const [suffix, preserveBugs] of policies) {
  const name = scenario + suffix;
  const cfg = config(mode, major, minor, { ...options, preserveBugs });
  console.log(`${name}: generating input stream`);
  const run = play(cfg, bot, limit, scheme, hunt);
  const filename = path.join(fixtures, `${name}.rsi`);
  fs.writeFileSync(filename, run.input);
  console.log(`${name}: comparing ${run.input.length} input bytes`);
  const parity = await compare(run.input, native, wasm);
  const result = { name, ...parity, final: run.final, coverage: run.coverage };
  report.cases.push(result);
  fs.writeFileSync(
    path.join(out, "report.json"),
    JSON.stringify(report, null, 2) + "\n",
  );
  console.log(
    `${name}: ${parity.ticks} ticks, terminal ${run.final.pending}, native/WASM + reset passed`,
  );
  }
if (!report.cases.some((c) => c.coverage.max_commands > 1))
  throw Error("No ordered command batch covered");
if (!report.cases.some((c) => c.final.pending === 8))
  throw Error("No quest completion covered");
if (!report.cases.some((c) => c.final.pending === 12))
  throw Error("No quest failure covered");
if (!report.cases.some((c) => c.final.pending === 7))
  throw Error("No game over covered");
console.log(
  `Passed ${report.cases.length} scenarios; ${path.join(out, "report.json")}`,
);
