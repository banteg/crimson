// The co-op engine (host/coop.inc) headless, over every co-op stream of the
// corpus (docs/rewrite/network-coop.md, Phase A). Each stream's perk commands
// become the players' requests: the opener alternates between the players, some
// menus both open in the same tick, and some requests must drop (no perk to
// pick, or the menu already open); a stream whose player one holds Perk Expert
// or Master takes its last pick from the extra choices. Then:
// 1. the engine with both players local plays the stream as the plain run does,
//    every canonical word of every tick (but the picker, which only co-op has),
//    and gives each tick's state hash, bake digest, terrain and music digests and
//    raw state;
// 2. again, with forced rollbacks, at each window (lockstep, 1, 4, 8 and 12
//    ticks), delay and frame budget (catch-up frames that run several ticks):
//    every so often one player's record arrives up to 12 ticks late, the players
//    taking turns, the ticks before it running on a stand-in (another record, the
//    real one, or the engine's guess); the picker's choice of each perk menu comes
//    late; a tick that leaves the next one's bake queued is confirmed right after
//    it ran, and a tick after one that played music is corrected after the music
//    played; the run goes back up to 12 ticks on its own, into each open perk
//    menu, to each tick where the effect overflow's entries in use change, and
//    every so often anywhere. Each tick, once confirmed, has the hash, bake,
//    terrain and music digests and raw state of (1), and no tick ran on a record
//    not yet real further past the last confirmed one than the window allows.
// Corrupting each family of fields the hash covers changes it; every byte of the
// run's state is in the hash or in the engine's list of what is left out and why
// (game_coop_audit); the receive path tells stale records from invalid ones; and
// the corpus covers what the engine must get right: both players opening, late
// and picking, same-tick and dropped requests, a survivor's menu, the extra
// choices, rollbacks into an open menu and over freed effect overflow entries,
// held bakes with overflow decals, bakes drawn between ticks while the next
// tick's queue waits, and final bakes on ticks not drawn.
//
// With --live, a few streams play (1) and (2) inside the original booted from a
// game directory with seven in-game tunes loaded: what it draws into the terrain
// and its music after every frame are what (1) presented by the tick confirmed.
//
//   node crimson-core/checks/game_coop.mjs [--live <game directory>] [game.wasm] [corpus directory]
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { CORE, decode, field, init, INPUT_BYTES, names, record, state, step } from "./engine.mjs";
import { loadGame } from "./game_compare.mjs";
import { bootGame, sevenTunes } from "./game_host.mjs";

const args = process.argv.slice(2);
const live = args[0] === "--live" ? args.splice(0, 2)[1] : null;
const [wasm = new URL("build/game/game.wasm", CORE).pathname, corpus = new URL("build/fixtures", CORE).pathname] = args;
const streams = fs
  .readdirSync(corpus)
  .filter((f) => /^coop-.*\.rsi$/.test(f))
  .sort();
assert.ok(streams.length, "no co-op streams: run checks/matrix.mjs");

// The engine's records (host/coop.inc CoopInput): an input, then the request.
const OPEN = 8;
// Forced rollbacks: a late record every ALTER ticks, a rollback on its own every RESTORE; the lead cap.
const ALTER = 29,
  RESTORE = 97,
  LEAD = 12;
// The windows, delays and frame budgets the rollbacks run at: the cap, lockstep, M2's windows (4 and 8) with
// catch-up frames whose ticks run final behind held ones, and a window of one at a longer delay, whose catch-up
// confirms held ticks with more of the run produced past them.
const MODES = [
  { delay: 2, rmax: 12, budget: 1 },
  { delay: 2, rmax: 0, budget: 1 },
  { delay: 2, rmax: 4, budget: 2 },
  { delay: 4, rmax: 1, budget: 6 },
  { delay: 8, rmax: 8, budget: 4 },
];
// Inside the original (--live), with seven in-game tunes loaded (game_host.mjs sevenTunes): streams with an
// in-game tune, the quest's end tune and its volume, a game over's, Nukes whose blood waits for the next tick's
// bake, and overflow decals; a window of 4 whose corrections follow played music, and catch-up frames.
const LIVE_STREAMS = ["coop-quest-1.1-ranked.rsi", "coop-survival-hunt-ranked.rsi", "coop-survival-effects-ranked.rsi"];
const LIVE_MODES = [
  { delay: 2, rmax: 4, budget: 2 },
  { delay: 4, rmax: 1, budget: 6 },
];
const LIVE_COVERAGE = ["queued_commits", "unseen_bakes", "overflow_decal_holds"];
// CoopStats, in order.
const STATS = [
  "ticks",
  "resimulated",
  "rollbacks",
  "max_depth",
  "stalls",
  "guesses_one",
  "guesses_two",
  "mispredictions_one",
  "mispredictions_two",
  "picker_waits_one",
  "picker_waits_two",
  "guessed_lead",
  "opens_one",
  "opens_two",
  "double_opens",
  "dropped_opens",
  "survivor_menus",
  "extra_picks",
  "overflow_rollbacks",
  "overflow_free_rollbacks",
  "overflow_decal_holds",
  "queued_commits",
  "unseen_bakes",
  "slot_bytes",
];
const stats = (g) => {
  const words = new Int32Array(g.memory.buffer, g.game_coop_stats(), STATS.length);
  return Object.fromEntries(STATS.map((name, i) => [name, words[i]]));
};
// Counters the plain pass must reach somewhere in the corpus, and those the rollbacks must.
const PLAIN_COVERAGE = ["opens_one", "opens_two", "double_opens", "dropped_opens", "survivor_menus", "extra_picks"];
const ROLLBACK_COVERAGE = [
  "guesses_one",
  "guesses_two",
  "mispredictions_one",
  "mispredictions_two",
  "picker_waits_one",
  "picker_waits_two",
  "overflow_rollbacks",
  "overflow_free_rollbacks",
  "overflow_decal_holds",
  "queued_commits",
  "unseen_bakes",
];
const prng = (s) => () => ((s = (Math.imul(s ^ (s >>> 15), 0x2c1b3c6d) + 0x9e3779b9) | 0) >>> 0) / 2 ** 32;

const plain = loadGame(wasm),
  solo = loadGame(wasm);
solo.game_coop_states(1);
const coverage = Object.fromEntries([...PLAIN_COVERAGE, ...ROLLBACK_COVERAGE, "menu_rollbacks"].map((n) => [n, 0]));
let overflowSeen = null;

// Perk ids (src/crimson/perks/ids.py): player one's Perk Expert and Perk Master offer a sixth and seventh choice.
const PERK_EXPERT = 21,
  PERK_MASTER = 43;
const offered = (g) =>
  field(g, `players[0].perk_counts[${PERK_MASTER}]`) ? 7 : field(g, `players[0].perk_counts[${PERK_EXPERT}]`) ? 6 : 5;
const command = (r) => {
  const count = r.readUInt32LE(2 * INPUT_BYTES);
  assert.ok(count <= 1, "a co-op stream takes one command a tick");
  return count ? [r.readInt32LE(2 * INPUT_BYTES + 4), r.readInt32LE(2 * INPUT_BYTES + 8)] : [0];
};

// The plain run of the stream: which ticks it takes, where each tick's open request would be valid, the last pick
// that had extra choices to take instead, the overflow ticks (where the effect overflow's entries in use change),
// which the rollbacks return to, and the ticks that leave the next tick's bake queued (a Nuke taken after the world
// drew), after which the rollbacks confirm held ticks.
function playPlain(run) {
  init(plain, run.config);
  const valid = [],
    overflow = [],
    queued = [];
  let ticks = 0,
    extra = null,
    last = 0;
  for (const r of run.records) {
    state(plain);
    if (ticks && (field(plain, "globals.fx_queue_count") || field(plain, "globals.fx_queue_rotated")))
      queued.push(ticks - 1);
    const alive = [0, 1].some((p) => field(plain, `players[${p}].health`, true) > 0);
    valid.push(run.config.readUInt32LE(4) !== 2 && alive && field(plain, "globals.perk_pending_count") > 0);
    const [type, choice] = command(r);
    const n = offered(plain);
    if (type === 1 && n > 5 && field(plain, `globals.perk_choice_ids[${n - 1}]`) > 0 && choice !== n - 1)
      extra = { tick: ticks, choice: n - 1 };
    if (!step(plain, r)) break;
    ticks++;
    const effects = plain.game_effects_active();
    if (effects > 0 && !overflowSeen) overflowSeen = { run, ticks };
    if (effects !== last) overflow.push(ticks);
    last = effects;
  }
  return { ticks, valid, extra, overflow, queued };
}

// The players' requests for each tick, from the stream's commands and the plain run's states (a request no perk
// could answer drops), and the stream with its last extra-choice pick taken.
function requests(stream) {
  let run = stream,
    plainRun = playPlain(run);
  if (plainRun.extra) {
    const records = [...run.records];
    const r = Buffer.from(records[plainRun.extra.tick]);
    r.writeInt32LE(plainRun.extra.choice, 2 * INPUT_BYTES + 8);
    records[plainRun.extra.tick] = r;
    run = { ...run, records };
    plainRun = playPlain(run);
  }
  const { ticks, valid, overflow, queued } = plainRun;
  const cmd = run.records.map(() => [0, 0]),
    opens = [];
  let menus = 0,
    picker = -1;
  run.records.forEach((r, t) => {
    const [type, argument] = command(r);
    const menuOpen = picker >= 0;
    if (type === 2) {
      // Every third menu both players open; the rest alternate.
      picker = menus % 3 === 2 ? 0 : menus % 2;
      cmd[t][picker] = OPEN;
      if (menus % 3 === 2) cmd[t][1] = OPEN;
      menus++;
      opens.push({ tick: t, picker });
      return;
    }
    if (type === 1) cmd[t][picker] = argument + 1;
    // The partner's request while the menu is open drops, every fourth menu.
    if (menuOpen && menus % 4 === 1) cmd[t][1 - picker] = OPEN;
    else if (!menuOpen && t < ticks && !valid[t] && t % 50 === 0) cmd[t][(t / 50) % 2] = OPEN;
    picker = -1;
  });
  return { run, cmd, ticks, opens, overflow, queued };
}

const write = (g, at, r, seat, cmd) => {
  const memory = new Uint8Array(g.memory.buffer);
  memory.set(r.subarray(seat * INPUT_BYTES, (seat + 1) * INPUT_BYTES), at);
  memory[at + INPUT_BYTES] = cmd;
};
function start(g, run, cmd, { delay, rmax }) {
  init(g, run.config);
  assert.equal(g.game_coop_start(-1, delay, rmax, 1), 1);
  for (let t = 0; t < delay; t++)
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
// The canonical words' perk picker (coop_words: after rng, tick, menu_requested, perk_menu_open), which a plain
// run never names.
const PICKER = SNAPSHOT + 4;
const canonical = (g) => Buffer.from(g.memory.buffer, g.portable_output(), g.game_coop_canonical() * 4);
function sameCanonical(expected, actual, tick) {
  assert.equal(actual.length, expected.length, `tick ${tick}: canonical words`);
  const at = PICKER * 4;
  if (expected.subarray(0, at).equals(actual.subarray(0, at)) && expected.subarray(at + 4).equals(actual.subarray(at + 4)))
    return;
  for (let i = 0; i < expected.length / 4; i++)
    if (i !== PICKER && expected.readUInt32LE(i * 4) !== actual.readUInt32LE(i * 4))
      assert.fail(`tick ${tick}: ${names[i] ?? `word ${i}`} ${expected.readUInt32LE(i * 4)} != ${actual.readUInt32LE(i * 4)}`);
}
// What a tick left, from its last run, and the raw state after it.
const DIGESTS = ["hash", "bake", "terrain", "music", "state"];
const digests = (g, t) => DIGESTS.map((name) => g[`game_coop_${name}_at`](t));

// (1): the solo engine against the plain run, tick for tick; inside the original (`look`), keeping what this
// machine presented after each tick.
function oracle(g, run, cmd, ticks, look) {
  init(plain, run.config);
  start(g, run, cmd, { delay: 2, rmax: 0 });
  const expected = [],
    shown = [];
  let plainMs = 0,
    soloMs = 0;
  for (let t = 0; t < ticks; t++) {
    let at = performance.now();
    assert.equal(step(plain, run.records[t]), 1);
    plainMs += performance.now() - at;
    at = performance.now();
    produce(g, run, cmd);
    assert.equal(g.game_coop_advance(1, 0), 1, `tick ${t} did not run`);
    soloMs += performance.now() - at;
    assert.equal(g.game_coop_confirmed(), t);
    // Inside the original the run's settings and progress are what the original had (no session swaps them in),
    // so the snapshot is compared.
    if (look) sameCanonical(canonical(plain).subarray(0, SNAPSHOT * 4), canonical(g).subarray(0, SNAPSHOT * 4), t);
    else sameCanonical(canonical(plain), canonical(g), t);
    expected.push(digests(g, t));
    if (look) shown.push(look());
  }
  // The ticks whose music the engine played (the music digest moved).
  const tunes = expected.flatMap((d, t) => (t && d[3] !== expected[t - 1][3] ? [t] : []));
  // Past the stream, a neutral tick runs in both or, after the run's end, in neither.
  const neutral = record([
    [0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0],
  ]);
  if (ticks === run.records.length) {
    for (const seat of [0, 1]) write(g, g.game_coop_input_for(seat), neutral, seat, 0);
    assert.equal(g.game_coop_produce(0), ticks);
  }
  assert.equal(g.game_coop_advance(1, 0), step(plain, neutral), "the engine and the plain run part at the end");
  return { expected, shown, tunes, plainMs, soloMs, stats: stats(g) };
}

// (2): forced rollbacks, every confirmed tick against (1). Inside the original (`look`), what this machine
// presented after each frame is what (1) presented by the same tick, and only unconfirmed ticks go back.
function rollbacks(g, { run, cmd, ticks, opens, overflow, queued }, { expected, shown, tunes }, mode, look) {
  const solo = g;
  start(solo, run, cmd, mode);
  const random = prng(run.records.length + mode.delay * 31 + mode.rmax);
  const late = new Map(); // `${seat} ${tick}` -> the tick the engine reaches before that record arrives
  const picks = new Map(opens.map((o) => [o.tick + 1, o.picker]));
  const nuked = new Set(queued),
    tuned = new Set(tunes);
  let seen = -1,
    restores = 0,
    nextRestore = RESTORE,
    menu = 0,
    menuRestores = 0,
    churn = 0;
  const at = performance.now();
  const check = () => {
    const confirmed = solo.game_coop_confirmed();
    assert.ok(solo.game_coop_next() - (confirmed + 1) <= LEAD, "ran past the lead");
    for (let t = seen + 1; t <= confirmed; t++) {
      const actual = digests(solo, t);
      DIGESTS.forEach((name, i) => assert.equal(actual[i], expected[t][i], `tick ${t}: ${name}`));
    }
    seen = Math.max(seen, confirmed);
    if (look && confirmed >= 0)
      look().forEach((value, i) => assert.equal(value, shown[confirmed][i], `tick ${confirmed}: ${PRESENTED[i]} presented`));
  };
  const deliver = (key) => {
    const [seat, t] = key.split(" ").map(Number);
    write(solo, solo.game_coop_input_for(seat), run.records[t], seat, cmd[t][seat]);
    assert.equal(solo.game_coop_deliver(seat, t, 1), 1);
    late.delete(key);
  };
  const delay = (seat, t, r, request, real, due = t + 1 + Math.floor(random() * LEAD)) => {
    write(solo, solo.game_coop_input_for(seat), r, seat, request);
    assert.equal(solo.game_coop_deliver(seat, t, real), 1);
    late.set(`${seat} ${t}`, due);
  };
  // A stand-in that holds and one that does not, for player one's record.
  const stand = (t, wrong) => {
    const r = Buffer.from(run.records[t]);
    if (wrong) r.writeFloatLE(r.readFloatLE(8) + 37, 8);
    return r;
  };
  while (solo.game_coop_confirmed() < ticks - 1) {
    produce(solo, run, cmd, (t) => {
      // The picker's choice comes late: the menu waits for it.
      if (picks.has(t)) delay(picks.get(t), t, run.records[t], cmd[t][picks.get(t)], -1);
      // A tick that leaves the next one's bake queued runs held, and is confirmed right after it ran.
      if (nuked.has(t)) delay(0, t, stand(t, false), cmd[t][0], 0, t + 1);
      // A tick that plays music runs held, and is confirmed once a tick after it ran on a stand-in; that tick,
      // whose state is from before the music played, is corrected after: the music played stays.
      if (tuned.has(t)) delay(0, t, stand(t, false), cmd[t][0], 0, t + 4);
      if (tuned.has(t - 3)) delay(0, t, stand(t, true), cmd[t][0], 0, t + 6);
      if (t % ALTER) return;
      // One player's record comes late, the players taking turns: a stand-in runs in its place (elsewhere, firing
      // or not, sometimes asking for the menu), or the real one (a guess that holds), or none, and the engine guesses.
      const seat = (t / ALTER) % 2,
        kind = (t / ALTER) % 3,
        r = Buffer.from(run.records[t]);
      if (kind === 0) {
        const input = seat * INPUT_BYTES;
        r.writeFloatLE(-r.readFloatLE(input), input);
        r.writeFloatLE(r.readFloatLE(input + 8) + 37, input + 8);
        r.writeUInt32LE(r.readUInt32LE(input + 16) ^ 1, input + 16);
      }
      delay(seat, t, r, kind === 0 && t % (4 * ALTER) === 0 ? OPEN : cmd[t][seat], kind === 2 ? -1 : 0);
    });
    for (const [key, due] of late) if (solo.game_coop_next() >= due) deliver(key);
    const next = solo.game_coop_next();
    // Back to the tick after each menu opened, the menu open in the state restored; to each tick the effect
    // overflow changed at; and every so often to any.
    while (menu < opens.length && opens[menu].tick + 1 + LEAD < next) menu++;
    while (churn < overflow.length && overflow[churn] + LEAD < next) churn++;
    const opened = menu < opens.length && opens[menu].tick + 1 < next;
    const changed = !opened && churn < overflow.length && overflow[churn] < next;
    const target = opened
      ? opens[menu++].tick + 1
      : changed
        ? overflow[churn++]
        : next >= nextRestore
          ? next - 1 - Math.floor(random() * LEAD)
          : -1;
    if (target > (look ? solo.game_coop_confirmed() : -1)) {
      assert.equal(solo.game_coop_restore(target), 1);
      restores++;
      if (opened) menuRestores++;
      else if (!changed) nextRestore = next + RESTORE;
      seen = Math.min(seen, solo.game_coop_confirmed());
    }
    const confirmed = solo.game_coop_confirmed();
    solo.game_coop_advance(mode.budget, 0);
    check();
    // Held up (the window, or a perk menu waiting on its picker): the real records arrive.
    if (solo.game_coop_next() === next && solo.game_coop_confirmed() === confirmed) {
      assert.ok(late.size, `stalled at tick ${next}`);
      for (const key of [...late.keys()]) deliver(key);
    }
  }
  assert.equal(solo.game_coop_next(), ticks);
  const result = stats(solo);
  assert.ok(result.guessed_lead <= mode.rmax, `a tick ran on a guess ${result.guessed_lead} past the confirmed one`);
  return { ms: performance.now() - at, restores, menuRestores, stats: result };
}

// Each field family the hash covers changes it, two sign flips included.
function corruptions(g) {
  for (let kind = 0; kind < 8; kind++) {
    const before = g.game_coop_hash();
    assert.equal(g.game_coop_corrupt(kind), 1, `corruption ${kind} found nothing to change`);
    assert.notEqual(g.game_coop_hash(), before, `corruption ${kind} left the hash alone`);
  }
}

// Every byte of the run's state is hashed or listed as left out (host/coop.inc COOP_UNHASHED), named here by the
// executable's globals (build/game/data.cpp).
function audit(g) {
  const symbols = [
    ...fs.readFileSync(path.join(path.dirname(wasm), "data.cpp"), "latin1").matchAll(/\.set (\w+), game_image_exe\+(\d+)/g),
  ]
    .map((m) => [Number(m[2]), m[1]])
    .sort((a, b) => a[0] - b[0]);
  const named = (at) => {
    const [start, name] = symbols.findLast(([s]) => s <= at);
    return `${name}+${at - start}`;
  };
  const count = g.game_coop_audit();
  const ranges = new Uint32Array(g.memory.buffer, g.portable_output(), count * 2);
  const wrong = Array.from({ length: count }, (_, i) => `${named(ranges[2 * i])} (${ranges[2 * i + 1] - ranges[2 * i]} bytes)`);
  assert.deepEqual(wrong, [], "run state bytes neither hashed nor listed as left out, or listed but hashed");
}

// The receive path (two peers, this machine seat 0): stale and repeated records change nothing, records no peer
// sends are protocol errors.
function receive(run) {
  init(solo, run.config);
  assert.equal(solo.game_coop_start(0, 2, 8, 1), 1);
  const deliver = (seat, t, real, r = run.records[t]) => {
    write(solo, solo.game_coop_input_for(seat), r, seat, 0);
    return solo.game_coop_deliver(seat, t, real);
  };
  assert.equal(deliver(0, 2, 1), -1, "this machine's own seat");
  assert.equal(deliver(1, 2, 0), -1, "a stand-in outside solo");
  assert.equal(deliver(1, 2, 1), 1);
  assert.equal(deliver(1, 2, 1), 0, "the same record again");
  assert.equal(deliver(1, 2, 1, run.records[3]), -1, "another record for a known tick");
  const nan = Buffer.from(run.records[3]);
  nan.writeFloatLE(NaN, INPUT_BYTES);
  assert.equal(deliver(1, 3, 1, nan), -1, "an invalid record");
  assert.equal(deliver(1, 2 + 300, 1), -1, "a tick past the ring");
  write(solo, solo.game_coop_input_for(0), run.records[2], 0, 0);
  assert.equal(solo.game_coop_produce(0), 2);
  solo.game_coop_advance(3, 0);
  assert.equal(solo.game_coop_confirmed(), 2);
  assert.equal(deliver(1, 2, 1), 0, "a confirmed tick's record again");
}

// Inside the original, booted afresh from `directory` for each run (a run inside it, with no session around it,
// leaves the verifier's music track ids and its own progress in place for the next): what it draws into its
// offscreen render targets (the terrain, which bakes take) and its music (game_coop_music), after each tick or
// frame.
const PRESENTED = ["terrain", "music"];
function bootLive(directory) {
  let target = 0,
    terrain = 2166136261;
  const run = bootGame(wasm, directory, 1, {
    onHost: (name, args) => {
      if (name === "set_render_target") target = args[0];
      if (name !== "draw" || !target) return;
      const [, vertices, count] = args;
      for (const byte of new Uint8Array(run.game.memory.buffer, vertices, count * 28))
        terrain = Math.imul(terrain ^ byte, 16777619) >>> 0;
    },
  });
  // The startup sequence shares the main menu's screen id and ends after about 14 s.
  for (let frame = 0; frame < 1200; frame++) run.frame(16);
  terrain = 2166136261;
  return { game: run.game, look: () => [terrain, run.game.game_coop_music()] };
}

if (live) sevenTunes(live);
const report = [];
for (const file of live ? LIVE_STREAMS : streams) {
  const stream = requests(decode(fs.readFileSync(path.join(corpus, file))));
  const { run, cmd, ticks } = stream;
  const truth = oracle(solo, run, cmd, ticks);
  for (const name of PLAIN_COVERAGE) coverage[name] += truth.stats[name];
  if (live) {
    const at = performance.now();
    const first = bootLive(live);
    const shown = oracle(first.game, run, cmd, ticks, first.look);
    const forced = LIVE_MODES.map((mode) => {
      const original = bootLive(live);
      return rollbacks(original.game, stream, shown, mode, original.look);
    });
    for (const result of forced) for (const name of LIVE_COVERAGE) coverage[name] += result.stats[name];
    console.log(JSON.stringify({ stream: file, ticks, live_ms: Math.round(performance.now() - at) }));
    continue;
  }
  let at = performance.now();
  for (let i = 0; i < 100; i++) solo.game_coop_hash();
  const hashUs = (1000 * (performance.now() - at)) / 100;
  const forced = MODES.map((mode) => rollbacks(solo, stream, truth, mode));
  for (const result of forced) {
    for (const name of ROLLBACK_COVERAGE) coverage[name] += result.stats[name];
    coverage.menu_rollbacks += result.menuRestores;
  }
  const line = {
    stream: file,
    ticks,
    rollbacks: forced.reduce((n, f) => n + f.stats.rollbacks, 0),
    resimulated: forced.reduce((n, f) => n + f.stats.resimulated, 0),
    plain_ms: Math.round(truth.plainMs),
    solo_ms: Math.round(truth.soloMs),
    rollback_ms: forced.map((f) => Math.round(f.ms)),
    // The engine's cost a tick over the plain run's: its capture, the hash and the raw state's digest.
    engine_us_per_tick: +((1000 * (truth.soloMs - truth.plainMs)) / ticks).toFixed(1),
    hash_us: +hashUs.toFixed(1),
    slot_kib: Math.round(forced[0].stats.slot_bytes / 1024),
  };
  report.push(line);
  console.log(JSON.stringify(line));
}
if (live) {
  const shown = Object.fromEntries(LIVE_COVERAGE.map((name) => [name, coverage[name]]));
  for (const [name, count] of Object.entries(shown)) assert.ok(count > 0, `no ${name} inside the original`);
  console.log(`Passed ${LIVE_STREAMS.length} co-op streams inside the original; coverage ${JSON.stringify(shown)}`);
  process.exit(0);
}
assert.ok(overflowSeen, "no co-op stream reaches the effect overflow");
init(plain, overflowSeen.run.config);
for (let t = 0; t < overflowSeen.ticks; t++) step(plain, overflowSeen.run.records[t]);
let at = performance.now();
audit(plain);
const auditMs = Math.round(performance.now() - at);
corruptions(plain);
receive(decode(fs.readFileSync(path.join(corpus, streams[0]))));
for (const [name, count] of Object.entries(coverage)) assert.ok(count > 0, `no ${name} across the co-op streams`);
console.log(`Passed ${report.length} co-op streams; audit ${auditMs} ms; coverage ${JSON.stringify(coverage)}`);
