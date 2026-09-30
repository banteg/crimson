// Input-only bot and parity runner. No state mutation or score submission.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { compare } from "./compare.mjs";
import {
  HERE,
  loadCore,
  init,
  state,
  field,
  config,
  record,
  step,
} from "./engine.mjs";

const out = path.resolve(
  process.argv[2] ?? fileURLToPath(new URL("build", HERE)),
);
const native = path.join(out, "native/core"),
  wasm = path.join(out, "wasm/core.wasm");
const e = loadCore(wasm);
const terminal = new Set([7, 8, 12]);
const fixtures = path.join(out, "fixtures");
fs.mkdirSync(fixtures, { recursive: true });

function play(cfg, bot, limit) {
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
    };
  let pickNext = false,
    final;
  const mode = cfg.readUInt32LE(4);
  for (let tick = 0; tick < limit; tick++) {
    state(e);
    const f = (name) => field(e, name, true),
      u = (name) => field(e, name);
    const x = f("players[0].pos_x"),
      y = f("players[0].pos_y"),
      health = f("players[0].health");
    let nearest = Infinity,
      target,
      active = 0;
    for (let c = 0; c < 384; c++) {
      if (!u(`creatures[${c}].active`) || f(`creatures[${c}].health`) <= 0)
        continue;
      active++;
      const cx = f(`creatures[${c}].pos_x`),
        cy = f(`creatures[${c}].pos_y`),
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
          if (!u(`bonuses[${b}].bonus_id`) || u(`bonuses[${b}].state`) !== 0)
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
    const r = record(
      [
        mx,
        my,
        target?.[0] ?? x,
        target?.[1] ?? y - 60,
        38656 | (bot && target ? 1 : 0) | (reload ? 65536 : 0),
      ],
      commands,
    );
    if (!step(e, r)) throw Error(`Bot rejected tick ${tick} in mode ${mode}`);
    records.push(r);
    state(e);
    final = {
      pending: u("globals.game_state_pending"),
      xp: u("players[0].experience"),
      health: f("players[0].health"),
      elapsed_ms: u("globals.survival_elapsed_ms"),
      timeline_ms: u("globals.quest_spawn_timeline"),
      rng: u("globals.rng"),
    };
    if (terminal.has(final.pending)) {
      if (step(e, r)) throw Error("Accepted input after terminal state");
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
    throw Error(`Native ${label}: ${n.status} ${n.stderr}`);
}

const normal = config(1);
rejects("NaN", normal, record([NaN, 0, 512, 512, 38656]));
rejects("infinite aim", normal, record([0, 0, Infinity, 512, 38656]));
rejects("unknown flags", normal, record([0, 0, 512, 512, 38656 | 0x100000]));
rejects("unsupported movement scheme", normal, record([0, 0, 512, 512, 38144]));
rejects(
  "perk without entitlement",
  normal,
  record([0, 0, 512, 512, 38656], [[1, 0]]),
);
rejects(
  "menu without entitlement",
  normal,
  record([0, 0, 512, 512, 38656], [[2, 0]]),
);
rejects(
  "Rush perk command",
  config(2),
  record([0, 0, 512, 512, 38656], [[2, 0]]),
);
rejects("unknown command", normal, record([0, 0, 512, 512, 38656], [[99, 0]]));
rejects(
  "command count overflow",
  normal,
  record([0, 0, 512, 512, 38656], Array(17).fill([2, 0])),
  4,
);

// A large vector still passes through the game's direction/speed cap.
function displacement(magnitude) {
  init(e, normal);
  for (let i = 0; i < 90; i++)
    if (!step(e, record([magnitude, 0, 512, 512, 38656])))
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

const scenarios = [
  ["rush-idle", config(2), false, 6000],
  ["rush-bot", config(2), true, 30000],
  ["rush-evade", config(2, 1, 1, { seed: 1337 }), 2, 30000],
  ["survival-idle", config(1), false, 10000],
  ["survival-bot", config(1), true, 30000],
  ["survival-evade", config(1), 2, 30000],
  ["survival-evade-1337", config(1, 1, 1, { seed: 1337 }), 2, 30000],
  ["survival-command-batches", config(1, 1, 1, { seed: 1337 }), 4, 30000],
];
for (let major = 1; major <= 5; major++)
  for (let minor = 1; minor <= 10; minor++) {
    scenarios.push([
      `quest-${major}.${minor}`,
      config(3, major, minor),
      true,
      30000,
    ]);
  }
scenarios.push([
  "quest-settings",
  config(3, 1, 1, {
    seed: 2345,
    detail: 0,
    violence: 1,
    hardcore: 1,
    retry: 3,
    friendly: 1,
    usage: true,
  }),
  true,
  30000,
]);
const report = {
  rules: "recovered-spike-v1",
  guards: "9 native/WASM rejection probes; large-vector speed cap",
  cases: [],
};
for (const [name, cfg, bot, limit] of scenarios) {
  console.log(`${name}: generating input stream`);
  const run = play(cfg, bot, limit);
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
