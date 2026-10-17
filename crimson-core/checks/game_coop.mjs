// The co-op engine (host/coop.inc) headless, over every co-op stream of the
// corpus (docs/rewrite/network-coop.md, Phase A). Each stream's perk commands
// become the players' requests: the opener alternates between the players, some
// menus both open in the same tick, and some requests must drop (no perk to
// pick, or the menu already open). Then:
// 1. the engine with both players local plays the stream as the plain run does,
//    snapshot for snapshot, and gives each tick's state hash and bake digest;
// 2. again, with forced rollbacks: every so often player two's record arrives up
//    to 12 ticks late, the ticks before it running on a stand-in (another record,
//    the real one, or the engine's guess), and the run goes back up to 12 ticks
//    on its own, into each open perk menu and every so often anywhere; each tick,
//    once confirmed, has the hash and bake digest of (1).
// Corrupting each family of fields the hash covers changes it, and the corpus
// covers opens by both players, same-tick opens, dropped requests, a survivor's
// menu, rollbacks into an open menu and the effect overflow inside a rollback.
//
//   node crimson-core/checks/game_coop.mjs [game.wasm] [corpus directory]
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { CORE, decode, field, init, INPUT_BYTES, names, record, state, step } from "./engine.mjs";
import { loadGame } from "./game_compare.mjs";

const [wasm = new URL("build/game/game.wasm", CORE).pathname, corpus = new URL("build/fixtures", CORE).pathname] =
  process.argv.slice(2);
const streams = fs
  .readdirSync(corpus)
  .filter((f) => /^coop-.*\.rsi$/.test(f))
  .sort();
assert.ok(streams.length, "no co-op streams: run checks/matrix.mjs");

// The engine's records (host/coop.inc CoopInput): an input, then the request.
const OPEN = 8;
const DELAY = 2;
// Forced rollbacks: a stand-in record every ALTER ticks, a rollback on its own every RESTORE.
const ALTER = 29,
  RESTORE = 97,
  LEAD = 12;
// CoopStats, in order.
const STATS = [
  "ticks",
  "resimulated",
  "rollbacks",
  "max_depth",
  "predictions",
  "mispredictions",
  "stalls",
  "opens_one",
  "opens_two",
  "double_opens",
  "dropped_opens",
  "survivor_menus",
  "overflow_rollbacks",
  "slot_bytes",
];
const stats = (g) => {
  const words = new Int32Array(g.memory.buffer, g.game_coop_stats(), STATS.length);
  return Object.fromEntries(STATS.map((name, i) => [name, words[i]]));
};
const prng = (s) => () => ((s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x9e3779b9) | 0) >>> 0) / 2 ** 32;

const plain = loadGame(wasm),
  solo = loadGame(wasm);
const coverage = Object.fromEntries(STATS.slice(7, 13).map((name) => [name, 0]));
let overflowSeen = null,
  menuRestores = 0;

// The players' requests for each tick, from the stream's commands and the
// plain run's states (a request no perk could answer drops).
function requests(run) {
  init(plain, run.config);
  const mode = run.config.readUInt32LE(4);
  const valid = [];
  let ticks = 0;
  for (const r of run.records) {
    state(plain);
    const alive = [0, 1].some((p) => field(plain, `players[${p}].health`, true) > 0);
    valid.push(mode !== 2 && alive && field(plain, "globals.perk_pending_count") > 0);
    if (!step(plain, r)) break;
    ticks++;
    if (plain.game_effects_active() > 0 && !overflowSeen) overflowSeen = { run, ticks };
  }
  const cmd = run.records.map(() => [0, 0]),
    opens = [];
  let menus = 0,
    picker = -1;
  run.records.forEach((r, t) => {
    const count = r.readUInt32LE(2 * INPUT_BYTES);
    const [type, argument] = count ? [r.readInt32LE(2 * INPUT_BYTES + 4), r.readInt32LE(2 * INPUT_BYTES + 8)] : [0];
    assert.ok(count <= 1, "a co-op stream takes one command a tick");
    const menuOpen = picker >= 0;
    if (type === 2) {
      // Every third menu both players open; the rest alternate.
      picker = menus % 3 === 2 ? 0 : menus % 2;
      cmd[t][picker] = OPEN;
      if (menus % 3 === 2) cmd[t][1] = OPEN;
      menus++;
      opens.push(t);
      return;
    }
    if (type === 1) cmd[t][picker] = argument + 1;
    // The partner's request while the menu is open drops, every fourth menu.
    if (menuOpen && menus % 4 === 1) cmd[t][1 - picker] = OPEN;
    else if (!menuOpen && t < ticks && !valid[t] && t % 50 === 0) cmd[t][(t / 50) % 2] = OPEN;
    picker = -1;
  });
  return { cmd, ticks, opens };
}

const write = (g, at, r, seat, cmd) => {
  const memory = new Uint8Array(g.memory.buffer);
  memory.set(r.subarray(seat * INPUT_BYTES, (seat + 1) * INPUT_BYTES), at);
  memory[at + INPUT_BYTES] = cmd;
};
function start(g, run, cmd, rmax) {
  init(g, run.config);
  assert.equal(g.game_coop_start(-1, DELAY, rmax, 1), 1);
  for (let t = 0; t < DELAY; t++)
    for (const seat of [0, 1]) write(g, g.game_coop_seed(seat, t), run.records[t], seat, cmd[t][seat]);
}
// Both players' records for the ticks the engine takes, up to the stream's end.
function produce(g, run, cmd, after = () => {}) {
  for (let t = g.game_coop_produced() + 1; t < run.records.length; t++) {
    for (const seat of [0, 1]) write(g, g.game_coop_input_for(seat), run.records[t], seat, cmd[t][seat]);
    if (g.game_coop_produce(0) < 0) return;
    after(t);
  }
}
const SNAPSHOT = names.length;
const canonical = (g) => Buffer.from(g.memory.buffer, g.portable_output(), g.game_coop_canonical() * 4);
function sameSnapshot(expected, actual, tick) {
  if (!expected.subarray(0, SNAPSHOT * 4).equals(actual.subarray(0, SNAPSHOT * 4))) {
    let i = 0;
    while (expected.readUInt32LE(i * 4) === actual.readUInt32LE(i * 4)) i++;
    assert.fail(`tick ${tick}: ${names[i]} ${expected.readUInt32LE(i * 4)} != ${actual.readUInt32LE(i * 4)}`);
  }
}

// (1): the solo engine against the plain run, tick for tick.
function oracle(run, cmd, ticks) {
  init(plain, run.config);
  start(solo, run, cmd, 0);
  const hashes = [],
    bakes = [];
  let plainMs = 0,
    soloMs = 0;
  for (let t = 0; t < ticks; t++) {
    let at = performance.now();
    assert.equal(step(plain, run.records[t]), 1);
    plainMs += performance.now() - at;
    at = performance.now();
    produce(solo, run, cmd);
    assert.equal(solo.game_coop_advance(1, 0), 1, `tick ${t} did not run`);
    soloMs += performance.now() - at;
    assert.equal(solo.game_coop_confirmed(), t);
    sameSnapshot(canonical(plain), canonical(solo), t);
    hashes.push(solo.game_coop_hash_at(t));
    bakes.push(solo.game_coop_bake_at(t));
  }
  // Past the stream, a neutral tick runs in both or, after the run's end, in neither.
  const neutral = record([
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
  ]);
  if (ticks === run.records.length) {
    for (const seat of [0, 1]) write(solo, solo.game_coop_input_for(seat), neutral, seat, 0);
    assert.equal(solo.game_coop_produce(0), ticks);
  }
  assert.equal(solo.game_coop_advance(1, 0), step(plain, neutral), "the engine and the plain run part at the end");
  return { hashes, bakes, plainMs, soloMs, stats: stats(solo) };
}

// (2): forced rollbacks, every confirmed tick against (1).
function rollbacks(run, cmd, ticks, opens, expected) {
  start(solo, run, cmd, LEAD);
  const random = prng(run.records.length);
  const late = new Map(); // tick -> the tick the engine reaches before its real record arrives
  let seen = -1,
    restores = 0,
    restoreMs = 0,
    nextRestore = RESTORE,
    menu = 0;
  const at = performance.now();
  const check = () => {
    const confirmed = solo.game_coop_confirmed();
    assert.ok(solo.game_coop_next() - (confirmed + 1) <= LEAD, "ran past the lead");
    for (let t = seen + 1; t <= confirmed; t++) {
      assert.equal(solo.game_coop_hash_at(t), expected.hashes[t], `tick ${t}: hash`);
      assert.equal(solo.game_coop_bake_at(t), expected.bakes[t], `tick ${t}: bake`);
    }
    seen = Math.max(seen, confirmed);
  };
  const deliver = (t) => {
    write(solo, solo.game_coop_input_for(1), run.records[t], 1, cmd[t][1]);
    assert.equal(solo.game_coop_deliver(1, t, 1), 1);
    late.delete(t);
  };
  while (solo.game_coop_confirmed() < ticks - 1) {
    produce(solo, run, cmd, (t) => {
      if (t % ALTER) return;
      // Player two's record comes late: a stand-in runs in its place (elsewhere, firing or not, sometimes
      // asking for the menu), or the real one (a guess that holds), or none, and the engine guesses.
      const kind = (t / ALTER) % 3,
        r = Buffer.from(run.records[t]);
      if (kind === 0) {
        r.writeFloatLE(-r.readFloatLE(INPUT_BYTES), INPUT_BYTES);
        r.writeFloatLE(r.readFloatLE(INPUT_BYTES + 8) + 37, INPUT_BYTES + 8);
        r.writeUInt32LE(r.readUInt32LE(INPUT_BYTES + 16) ^ 1, INPUT_BYTES + 16);
      }
      write(solo, solo.game_coop_input_for(1), r, 1, kind === 0 && t % (2 * ALTER) === 0 ? OPEN : cmd[t][1]);
      assert.equal(solo.game_coop_deliver(1, t, kind === 2 ? -1 : 0), 1);
      late.set(t, t + 1 + Math.floor(random() * LEAD));
    });
    for (const [t, due] of late) if (solo.game_coop_next() >= due) deliver(t);
    const next = solo.game_coop_next();
    // Back to the tick after each menu opened, the menu open in the state restored, and every so often to any.
    while (menu < opens.length && opens[menu] + 1 + LEAD < next) menu++;
    const opened = menu < opens.length && opens[menu] + 1 < next;
    const target = opened ? opens[menu++] + 1 : next >= nextRestore ? next - 1 - Math.floor(random() * LEAD) : -1;
    if (target >= 0) {
      const begin = performance.now();
      assert.equal(solo.game_coop_restore(target), 1);
      restoreMs += performance.now() - begin;
      restores++;
      if (opened) menuRestores++;
      else nextRestore = next + RESTORE;
      seen = Math.min(seen, solo.game_coop_confirmed());
    }
    const confirmed = solo.game_coop_confirmed();
    solo.game_coop_advance(1, 0);
    check();
    // Held up (the lead, or a perk menu waiting on the stand-in): the real records arrive.
    if (solo.game_coop_next() === next && solo.game_coop_confirmed() === confirmed) {
      assert.ok(late.size, `stalled at tick ${next}`);
      for (const t of [...late.keys()]) deliver(t);
    }
  }
  assert.equal(solo.game_coop_next(), ticks);
  return { ms: performance.now() - at, restores, restoreMs, stats: stats(solo) };
}

// Each field family the hash covers changes it.
function corruptions(g) {
  for (const kind of [0, 1, 2, 3, 4]) {
    const before = g.game_coop_hash();
    assert.equal(g.game_coop_corrupt(kind), 1, `corruption ${kind} found nothing to change`);
    assert.notEqual(g.game_coop_hash(), before, `corruption ${kind} left the hash alone`);
  }
}

const report = [];
for (const file of streams) {
  const run = decode(fs.readFileSync(path.join(corpus, file)));
  const { cmd, ticks, opens } = requests(run);
  const expected = oracle(run, cmd, ticks);
  let at = performance.now();
  for (let i = 0; i < 100; i++) solo.game_coop_hash();
  const hashUs = (1000 * (performance.now() - at)) / 100;
  const forced = rollbacks(run, cmd, ticks, opens, expected);
  for (const name of Object.keys(coverage))
    coverage[name] += (name === "overflow_rollbacks" ? forced : expected).stats[name];
  const line = {
    stream: file,
    ticks,
    rollbacks: forced.stats.rollbacks,
    max_depth: forced.stats.max_depth,
    resimulated: forced.stats.resimulated,
    plain_ms: Math.round(expected.plainMs),
    solo_ms: Math.round(expected.soloMs),
    rollback_ms: Math.round(forced.ms),
    // The engine's cost a tick over the plain run's: its capture, and the hash.
    engine_us_per_tick: +((1000 * (expected.soloMs - expected.plainMs)) / ticks).toFixed(1),
    hash_us: +hashUs.toFixed(1),
    restore_us: +((1000 * forced.restoreMs) / forced.restores).toFixed(1),
    slot_kib: Math.round(forced.stats.slot_bytes / 1024),
  };
  report.push(line);
  console.log(JSON.stringify(line));
}
assert.ok(overflowSeen, "no co-op stream reaches the effect overflow");
init(plain, overflowSeen.run.config);
for (let t = 0; t < overflowSeen.ticks; t++) step(plain, overflowSeen.run.records[t]);
corruptions(plain);
coverage.menu_rollbacks = menuRestores;
for (const [name, count] of Object.entries(coverage)) assert.ok(count > 0, `no ${name} across the co-op streams`);
console.log(`Passed ${report.length} co-op streams; coverage ${JSON.stringify(coverage)}`);
