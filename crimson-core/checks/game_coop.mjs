// The co-op engine (host/coop.inc) headless, over every co-op stream of the
// corpus (docs/rewrite/network-coop.md, Phase A). Each stream's perk commands
// become the players' requests: the opener alternates between the players, some
// menus both open in the same tick, and some requests must drop (no perk to
// pick, or the menu already open); a stream whose player one holds Perk Expert
// or Master takes its last pick from the extra choices, one that offers Perk
// Master to Perk Expert plays again taking it, and a stream without extra
// choices asks at its last pick for one past the five offered. Then:
// 1. the engine with both players local plays the stream as the plain run does,
//    every canonical word of every tick (but the picker, which only co-op has),
//    and gives each tick's state hash, bake digest, terrain and music digests and
//    raw state (excluding consumed decal-queue bytes, whose bakes are compared);
// 2. again, with forced rollbacks, at each window (lockstep, 1, 4, 8 and 12
//    ticks; a Survival stream's 8 narrowing to 4 halfway through, as past 15
//    minutes), delay and frame budget (catch-up frames that run several ticks):
//    every so often one player's record arrives up to 12 ticks late, the players
//    taking turns, the ticks before it running on a stand-in (another record, the
//    real one, or the engine's guess); the picker's choice of each perk menu comes
//    late; a tick that leaves the next one's bake queued is confirmed right after
//    it ran, and a tick after one that played music is corrected after the music
//    played; the run goes back up to 12 ticks on its own, into each open perk
//    menu, to each tick where the effect overflow's entries in use change, and
//    every so often anywhere. Each tick, once confirmed, has the hash, bake,
//    terrain and music digests and raw state of (1), no tick ran on a record
//    not yet real further past the last confirmed one than the window allows,
//    and every frame shows the newest tick run;
// 3. between two peers, each a module playing its own seat through the wire
//    protocol (host/coop_wire.inc), over a simulated pipe with latency, jitter,
//    loss, a burst of lost packets, a stutter and different frame rates: the
//    Host starts the run, each peer produces its seat's records (opens when its
//    state allows them, its picks when it is the picker) and both play the
//    whole stream in lockstep and with a window of 8, at delays 2 and 4, and
//    with a window of 8 at delay 8. On both, each tick once confirmed has the
//    digests and raw state of (1) and the partner's hash compared; both end on
//    the same tick in the same state, neither sending more than 60 ticks
//    packets a second. Then the session's cases: pause races, leaving mid-run,
//    while paused, from an open perk menu, while a request waits and while the
//    leaver's last acknowledgements are lost (each closing promptly, for the
//    reason it left), hashes held back past the engine's ring, a rematch the
//    Host cannot start before the Guest confirmed the last run's end, through a
//    storm of the last run's packets, a hello before the partner connected, a
//    start the Guest answers too late, a partner gone silent, one whose records
//    stop coming, a peer that times out alone and connects again while its
//    partner's session went on (then reloads), a transport that closes, an
//    invalid record, an error while starting, a desync and different builds.
// Corrupting each family of fields the hash covers changes it; every byte of the
// run's state is in the hash or in the engine's list of what is left out and why
// (game_coop_audit); the receive path tells stale records from invalid ones; a
// guess drops the presses of the record it copies; and
// the corpus covers what the engine must get right: both players opening, late
// and picking, same-tick and dropped requests, a survivor's menu, a sixth and a
// seventh choice and one past those offered, rollbacks into an open menu and
// over freed effect overflow entries, held bakes with overflow decals, bakes
// drawn between ticks while the next tick's queue waits, and final bakes on
// ticks not drawn.
//
// With --live, a few streams play (1) and (2) inside the original booted from a
// copy of a game directory with seven in-game tunes loaded: every canonical word
// of every tick is the plain run's, and what it draws into the terrain and its
// music after every frame are what (1) presented by the tick confirmed.
//
//   node crimson-core/checks/game_coop.mjs [--live <game directory>] [game.wasm] [corpus directory]
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { coopStats, Link, prng } from "./coop_link.mjs";
import { CONFIG_BYTES, CORE, decode, field, init, INPUT_BYTES, names, record, state, step } from "./engine.mjs";
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
// confirms held ticks with more of the run produced past them. With `late`, a Survival run's window of 8 narrows
// halfway through it, as it does past 15 minutes (host/coop.inc COOP_LATE_MS).
const MODES = [
  { delay: 2, rmax: 12, budget: 1 },
  { delay: 2, rmax: 0, budget: 1 },
  { delay: 2, rmax: 4, budget: 2 },
  { delay: 4, rmax: 1, budget: 6 },
  { delay: 8, rmax: 8, budget: 4, late: true },
];
const SURVIVAL = 1,
  LATE_MS = 900000,
  LATE_RMAX = 4;
// Inside the original (--live), with seven in-game tunes loaded (game_host.mjs sevenTunes): streams with an
// in-game tune, the quest's end tune and its volume, a game over's, Nukes whose blood waits for the next tick's
// bake, and overflow decals; a window of 4 whose corrections follow played music, and catch-up frames.
const LIVE_STREAMS = [
  "coop-quest-1.1-ranked.rsi",
  "coop-survival-hunt-ranked.rsi",
  "coop-survival-effects-ranked.rsi",
  // Original-policy Nukes still cover committing a decal while the next tick's bake is queued.
  "coop-survival-extra-choices.rsi",
];
const LIVE_MODES = [
  { delay: 2, rmax: 4, budget: 2 },
  { delay: 4, rmax: 1, budget: 6 },
];
const LIVE_COVERAGE = ["queued_commits", "unseen_bakes", "overflow_decal_holds"];
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

const plain = loadGame(wasm),
  solo = loadGame(wasm);
solo.game_coop_states(1);
// And the picks the streams take: a sixth and a seventh choice, and one past those offered.
const PICK_COVERAGE = ["sixth_choices", "seventh_choices", "beyond_picks"];
const coverage = Object.fromEntries(
  [...PLAIN_COVERAGE, ...ROLLBACK_COVERAGE, "menu_rollbacks", ...PICK_COVERAGE].map((n) => [n, 0]),
);
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
// The stream with tick `t`'s pick taking `choice`, or with none (the menu closes).
function repick(run, t, choice) {
  const records = [...run.records];
  const r = Buffer.from(choice < 0 ? records[t].subarray(0, 2 * INPUT_BYTES + 4) : records[t]);
  if (choice < 0) r.writeUInt32LE(0, 2 * INPUT_BYTES);
  else r.writeInt32LE(choice, 2 * INPUT_BYTES + 8);
  records[t] = r;
  return { ...run, records };
}

// The plain run of the stream: which ticks it takes, where each tick's open request would be valid, its picks (how
// many choices each offered, which, and the one taken), the overflow ticks (where the effect overflow's entries in
// use change), which the rollbacks return to, and the ticks that leave the next tick's bake queued (a Nuke taken
// after the world drew), after which the rollbacks confirm held ticks.
function playPlain(run) {
  init(plain, run.config);
  const valid = [],
    picks = [],
    overflow = [],
    queued = [];
  let ticks = 0,
    last = 0;
  for (const r of run.records) {
    state(plain);
    if (ticks && (field(plain, "globals.fx_queue_count") || field(plain, "globals.fx_queue_rotated")))
      queued.push(ticks - 1);
    const alive = [0, 1].some((p) => field(plain, `players[${p}].health`, true) > 0);
    valid.push(run.config.readUInt32LE(4) !== 2 && alive && field(plain, "globals.perk_pending_count") > 0);
    const [type, choice] = command(r);
    if (type === 1) {
      const n = offered(plain);
      const ids = Array.from({ length: n }, (_, i) => field(plain, `globals.perk_choice_ids[${i}]`));
      picks.push({ tick: ticks, n, choice, ids });
    }
    if (!step(plain, r)) break;
    ticks++;
    const effects = plain.game_effects_active();
    if (effects > 0 && !overflowSeen) overflowSeen = { run, ticks };
    if (effects !== last) overflow.push(ticks);
    last = effects;
  }
  return { ticks, valid, picks, overflow, queued };
}

// The stream as recorded and, where player one holds Perk Expert and a pick before the last offers Perk Master,
// taking it there when the run still plays to its end: its later picks offer seven choices.
function variants(stream) {
  const { ticks, picks } = playPlain(stream);
  const at = picks.findIndex((p, i) => i < picks.length - 1 && p.n === 6 && p.ids.includes(PERK_MASTER));
  const runs = [{ stream }];
  if (at >= 0) {
    const master = repick(stream, picks[at].tick, picks[at].ids.indexOf(PERK_MASTER));
    if (playPlain(master).ticks === ticks) runs.push({ stream: master, name: "Perk Master" });
  }
  // A run that later earns Master takes its last extra pick from seven choices.
  // Also stop at its last six-choice menu so requests explicitly takes slot six.
  const sixth = picks.findLast((p) => p.n === 6 && p.ids[5] > 0);
  if (sixth && picks.some((p) => p.tick > sixth.tick && p.n === 7))
    runs.push({ stream: { ...stream, records: stream.records.slice(0, sixth.tick + 1) }, name: "Perk Expert sixth choice" });
  return runs;
}

// The players' requests for each tick, from the stream's commands and the plain run's states (a request no perk
// could answer drops). The last pick that has extra choices takes the last of them; in a stream without, the last
// pick asks for one past the five offered, which drops and closes the menu as no pick does, when the run still
// plays to its end.
function requests(stream) {
  let run = stream,
    plainRun = playPlain(run),
    beyond = null;
  const extra = plainRun.picks.findLast((p) => p.n > 5);
  const lastPick = plainRun.picks.at(-1);
  if (extra && extra.ids[extra.n - 1] > 0 && extra.choice !== extra.n - 1) {
    run = repick(run, extra.tick, extra.n - 1);
    plainRun = playPlain(run);
  } else if (!extra && lastPick) {
    const closed = repick(run, lastPick.tick, -1);
    const closedRun = playPlain(closed);
    if (closedRun.ticks === plainRun.ticks) [run, plainRun, beyond] = [closed, closedRun, lastPick];
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
    if (t === beyond?.tick) cmd[t][picker] = beyond.n + 1;
    // The partner's request while the menu is open drops, every fourth menu.
    if (menuOpen && menus % 4 === 1) cmd[t][1 - picker] = OPEN;
    else if (!menuOpen && t < ticks && !valid[t] && t % 50 === 0) cmd[t][(t / 50) % 2] = OPEN;
    picker = -1;
  });
  const took = extra?.ids[extra.n - 1] > 0 ? extra.n : 0;
  return { run, cmd, ticks, opens, overflow, queued, extra: took, beyond: !!beyond };
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
    sameCanonical(canonical(plain), canonical(g), t);
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
  return { expected, shown, tunes, plainMs, soloMs, stats: coopStats(g) };
}

// (2): forced rollbacks, every confirmed tick against (1). Inside the original (`look`), what this machine
// presented after each frame is what (1) presented by the same tick, and only unconfirmed ticks go back.
function rollbacks(g, { run, cmd, ticks, opens, overflow, queued }, { expected, shown, tunes }, mode, look) {
  const solo = g;
  const narrows = mode.late && run.config.readUInt32LE(4) === SURVIVAL;
  solo.game_coop_late(narrows ? Math.floor((ticks * 1000) / 60 / 2) : LATE_MS);
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
    assert.equal(solo.game_coop_drawn(), solo.game_coop_next() - 1, "the frame shows a state taken back");
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
  const result = coopStats(solo);
  assert.ok(result.guessed_lead <= mode.rmax, `a tick ran on a guess ${result.guessed_lead} past the confirmed one`);
  assert.equal(result.depths.reduce((a, b) => a + b), result.rollbacks, "rollbacks by depth");
  if (narrows) {
    assert.ok(result.late_ticks > 0, "no tick ran under the late window");
    assert.ok(result.late_lead <= LATE_RMAX, `a tick ran on a guess ${result.late_lead} past the confirmed one, late`);
  }
  return { ms: performance.now() - at, restores, menuRestores, stats: result };
}

// Each field family the hash covers changes it, two sign flips included.
function corruptions(g) {
  for (let kind = 0; kind < 11; kind++) {
    const before = g.game_coop_hash();
    assert.equal(g.game_coop_corrupt(kind), 1, `corruption ${kind} found nothing to change`);
    assert.notEqual(g.game_coop_hash(), before, `corruption ${kind} left the hash alone`);
  }
}

// Every byte of the run's state is hashed or listed as left out (host/coop.inc COOP_UNHASHED). Bytes that are not
// are named by the executable's globals (data.cpp, which the build leaves beside game.wasm), else by their offset
// into its image (a game.wasm on its own, as CI's game jobs download it).
function audit(g) {
  const count = g.game_coop_audit();
  if (!count) return;
  const ranges = Array.from(new Uint32Array(g.memory.buffer, g.portable_output(), count * 2));
  const data = path.join(path.dirname(wasm), "data.cpp");
  const symbols = fs.existsSync(data)
    ? [...fs.readFileSync(data, "latin1").matchAll(/\.set (\w+), game_image_exe\+(\d+)/g)]
        .map((m) => [Number(m[2]), m[1]])
        .sort((a, b) => a[0] - b[0])
    : [];
  const named = (at) => {
    const [start, name] = symbols.findLast(([s]) => s <= at) ?? [0, "game_image_exe"];
    return `${name}+${at - start}`;
  };
  const wrong = Array.from({ length: count }, (_, i) => `${named(ranges[2 * i])} (${ranges[2 * i + 1] - ranges[2 * i]} bytes)`);
  assert.fail(`run state bytes neither hashed nor listed as left out, or listed but hashed: ${wrong.join(", ")}`);
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

// A guess (host/coop.inc coop_record) for a record not yet arrived keeps the partner's last real one's axes, aim and
// held keys, but not its presses or its request; one that arrived out of order, past it, plays no part. The real
// record, once it comes, puts the tick right.
function prediction(run) {
  const PRESSES = 2 | 4,
    t = 10;
  init(solo, run.config);
  assert.equal(solo.game_coop_start(0, 2, 8, 1), 1);
  for (let s = 0; s < 2; s++)
    for (const seat of [0, 1]) write(solo, solo.game_coop_seed(seat, s), run.records[s], seat, 0);
  const take = (s, r = run.records[s], request = 0) => {
    write(solo, solo.game_coop_input_for(1), r, 1, request);
    assert.equal(solo.game_coop_deliver(1, s, 1), 1);
  };
  const last = Buffer.from(run.records[t - 1]);
  last.writeUInt32LE(last.readUInt32LE(INPUT_BYTES + 16) | PRESSES, INPUT_BYTES + 16);
  for (let s = 2; s < t - 1; s++) take(s);
  take(t - 1, last, OPEN);
  take(t + 1, run.records[t + 1], OPEN);
  for (let s = 2; s <= t; s++) {
    write(solo, solo.game_coop_input(), run.records[s], 0, 0);
    while (solo.game_coop_produce(0) < 0) solo.game_coop_advance(1, 0);
  }
  solo.game_coop_advance(t, 0);
  assert.equal(solo.game_coop_next(), t + 1);
  const used = () => Buffer.from(new Uint8Array(solo.memory.buffer, solo.game_coop_used(t, 1), INPUT_BYTES + 1));
  const unrequested = (r) => Buffer.concat([r.subarray(INPUT_BYTES, 2 * INPUT_BYTES), Buffer.from([0])]);
  const guess = unrequested(last);
  guess.writeUInt32LE(last.readUInt32LE(INPUT_BYTES + 16) & ~PRESSES, 16);
  assert.ok(used().equals(guess), "the guess");
  take(t);
  solo.game_coop_advance(1, 0);
  assert.ok(used().equals(unrequested(run.records[t])), "the record");
}

// (3): two peers, each a module playing its own seat, over a simulated pipe (the transport, client/web/coop.js, as
// coop_link.mjs plays it): channel 0 best effort, 40 ± 30 ms one way (reordering), 2 % loss and one burst of 12
// packets in a row; channel 1 reliable and ordered over the same latency. One peer draws at 60 Hz, the other at
// 144 Hz with a 300 ms hitch, each banking real time for its 60 ticks a second.
// game_coop_status and game_coop_request (host/coop_wire.inc).
const STATUS = {
  connected: 1,
  started: 2,
  paused: 4,
  waiting: 8,
  picker: 16,
  leaving: 32,
  ended: 64,
  desynced: 128,
  failed: 256,
  starting: 512,
  remote: 1024,
  signed: 2048,
  closed: 4096,
};
const REASON = {
  version: 1,
  badRecord: 2,
  badMessage: 3,
  stalled: 4,
  silent: 5,
  unanswered: 6,
  left: 7,
  partnerLeft: 8,
  disconnected: 9,
  partnerGone: 10,
  diverged: 11,
};
const reason = (status) => (status >>> 16) & 255;
// Why the session or its run stopped, as the game tells its player and the page's panel says (game_coop_why), or
// null.
const why = (g) => {
  const at = g.game_coop_why();
  const bytes = new Uint8Array(g.memory.buffer, at);
  return at ? Buffer.from(bytes.subarray(0, bytes.indexOf(0))).toString("latin1") : null;
};
// Session timeouts (host/coop_wire.inc), and how long a leave may take to close both peers: the run to its end,
// and the last records and hashes each way.
const PROGRESS_MS = 5000,
  LIVENESS_MS = 15000,
  START_MS = 10000,
  CLOSE_MS = 2000;
const ASK = { open: 1, pause: 2, leave: 3, nextRun: 4, start: 5 };
const TICK_MS = 1000 / 60;
// The ticks whose results the engine keeps (host/coop.inc COOP_RING), and the most by which a peer's partner may
// trail its confirmed ticks hearing their hashes over the plain pipe: a second.
const RING = 256,
  UNHEARD = 60;
// A ticks packet's hash_ack (host/coop_wire.inc), -1 none.
const hashAck = (bytes) => new DataView(bytes.buffer, bytes.byteOffset).getInt32(32, true);
// A ticks packet cut back to the records up to tick `last`, without its hashes: its head (the newest record's tick)
// at byte 20, the records' perk nibbles at 36, and the records, 20 bytes each from 40, oldest first.
function cutTo(bytes, last) {
  const view = new DataView(bytes.buffer, bytes.byteOffset), count = bytes[1], head = view.getUint32(20, true);
  const kept = Math.max(0, count - Math.max(0, head - last));
  if (kept === count) return bytes;
  const out = bytes.slice(0, 40 + 20 * kept), cut = new DataView(out.buffer);
  out[1] = kept;
  out[3] = 0;
  cut.setUint32(20, last, true);
  cut.setUint32(36, (view.getUint32(36, true) & (2 ** (4 * kept) - 1)) >>> 0, true);
  return out;
}
// How long the engine takes a partner's records to stop after its pick for its perk screen's close
// (host/coop.inc COOP_PICK_FADE_MS).
const PICK_FADE_MS = Number(/COOP_PICK_FADE_MS = (\d+)/.exec(fs.readFileSync(new URL("host/coop.inc", CORE), "utf8"))[1]);
// A ticks packet without its hashes.
const bare = (bytes) => {
  const kept = bytes.slice(0, bytes.length - 4 * bytes[3]);
  kept[3] = 0;
  return kept;
};
// The pipe's runs: lockstep and M2's window, each at two delays, and the longest delay with that window; every
// other one swaps which peer draws fast, stutters and loses the burst.
const PIPE_MODES = [
  { delay: 2, rmax: 0 },
  { delay: 2, rmax: 8 },
  { delay: 4, rmax: 0 },
  { delay: 4, rmax: 8 },
  { delay: 8, rmax: 8 },
];
const PIPE_COVERAGE = ["repairs", "mispredictions", "opens_one", "opens_two", "picker_waits_one", "picker_waits_two"];
const pipeCoverage = Object.fromEntries(PIPE_COVERAGE.map((n) => [n, 0]));
// The Host's module and the Guest's.
let host, guest;

class Pipe extends Link {
  // `stream` is what requests() gives, `truth` its oracle(); `swap` makes the Host the fast peer.
  constructor(stream, truth, mode, { swap = false, faults = true, seed = 1 } = {}) {
    super(stream.run.records.length * 7 + mode.delay * 131 + mode.rmax + seed);
    if (!host) {
      [host, guest] = [loadGame(wasm), loadGame(wasm)];
      for (const g of [host, guest]) g.game_coop_states(1);
    }
    this.mode = mode;
    const duration = stream.ticks * TICK_MS;
    this.peers = [host, guest].map((g, seat) => ({
      g,
      seat,
      frameMs: (seat === 1) !== swap ? 1000 / 144 : 1000 / 60,
      at: seat * 3,
      last: 0,
      bank: 0,
      seen: -1,
      stream: null,
      truth: null,
      run: 0,
      connectedAt: null,
      heardAt: 0, // the last arrival
      gone: false, // neither frames nor takes arrivals
      stalled: false, // frames, sends and takes arrivals, but runs no tick
    }));
    const fast = this.peers.find((p) => p.frameMs < 10);
    this.hitch = faults ? { peer: fast, from: duration * 0.6, to: duration * 0.6 + 300 } : null;
    this.burst = faults ? { from: 1 - fast.seat, at: duration / 3, left: 12 } : null;
    this.loss = faults ? 0.02 : 0;
    this.tap = null;
    this.drop = null; // (peer, channel, bytes) => true to lose what it sends
    this.alter = null; // (peer, channel, bytes) => what arrives instead
    this.hooks = {};
    this.leaver = null;
    this.stream = stream;
    this.truth = truth;
    this.upcoming = null;
    this.runs = 0;
    this.checking = true;
    this.unheard = [0, 0]; // the most each peer's confirmed ticks ran ahead of its partner's hash_ack
  }
  status(p) {
    return p.g.game_coop_status();
  }
  send(p, channel, bytes) {
    this.tap?.(p, channel, bytes);
    if (channel === 0 && this.peers.every((q) => this.status(q) & STATUS.started)) {
      const q = this.peers[1 - p.seat];
      this.unheard[q.seat] = Math.max(this.unheard[q.seat], q.g.game_coop_confirmed() - hashAck(bytes));
    }
    if (this.drop?.(p, channel, bytes)) return;
    super.send(p, channel, this.alter ? this.alter(p, channel, bytes) : bytes);
  }
  // A message arriving at `p` now.
  receive(p, channel, bytes) {
    if (p.gone) return;
    const at = p.g.game_coop_rx(bytes.length);
    new Uint8Array(p.g.memory.buffer, at, bytes.length).set(bytes);
    p.g.game_coop_receive(channel, bytes.length, this.now);
    p.heardAt = this.now;
    this.hooks.received?.(p, channel, bytes);
    this.seed(p);
  }
  connect(seats = [0, 1]) {
    for (const seat of seats) {
      const p = this.peers[seat];
      assert.equal(p.g.game_coop_connect(seat, this.now), 1);
      p.connectedAt = this.now;
    }
  }
  // The Host starts a run of `stream` once it can; each peer seeds its first ticks from the stream as it starts.
  start(stream = this.stream, truth = this.truth) {
    this.upcoming = { stream, truth, run: ++this.runs };
    const [h] = this.peers;
    this.until(() => {
      if (!(this.status(h) & STATUS.connected)) return false;
      const config = stream.run.config.subarray(0, CONFIG_BYTES);
      new Uint8Array(h.g.memory.buffer, h.g.portable_config(), CONFIG_BYTES).set(config);
      return h.g.game_coop_request(ASK.start, this.mode.delay, this.mode.rmax, 0, this.now) === 1;
    }, "the Host starts the run");
    this.stream = stream;
    this.truth = truth;
    this.seed(h);
  }
  seed(p) {
    const { delay } = this.mode;
    if (!this.upcoming || p.run === this.upcoming.run || !(this.status(p) & (STATUS.started | STATUS.starting)))
      return;
    if (p.g.game_coop_next() !== 0 || p.g.game_coop_produced() !== delay - 1) return;
    const { run, cmd } = this.upcoming.stream;
    for (let t = 0; t < delay; t++)
      for (const seat of [0, 1]) write(p.g, p.g.game_coop_seed(seat, t), run.records[t], seat, cmd[t][seat]);
    Object.assign(p, { stream: this.upcoming.stream, truth: this.upcoming.truth, run: this.upcoming.run, seen: -1 });
  }
  // This peer's records for the ticks its engine takes: an open waits until the state it is judged on is final,
  // and the picker's choice goes on the tick after its open.
  feed(p) {
    if (!p.stream) return;
    const { g, seat } = p;
    const { run, cmd } = p.stream;
    for (;;) {
      const t = g.game_coop_produced() + 1,
        status = this.status(p);
      const held = status & (STATUS.paused | STATUS.leaving);
      if (t >= run.records.length || !(status & STATUS.started) || held) return;
      const nibble = cmd[t][seat];
      if (status & STATUS.picker) assert.ok(nibble < OPEN, `tick ${t}: the picker opens the menu again`);
      else if (nibble === OPEN) {
        if (!(status & STATUS.waiting)) {
          if (g.game_coop_next() !== t || g.game_coop_confirmed() !== t - 1) return;
          g.game_coop_request(ASK.open, 0, 0, 0, this.now);
        }
      } else if (status & STATUS.waiting) return;
      else assert.equal(nibble, 0, `tick ${t}: seat ${seat} picks with no menu of its own`);
      write(g, g.game_coop_input(), run.records[t], seat, nibble);
      if (g.game_coop_produce(this.now) < 0) return;
    }
  }
  // Each tick, once confirmed, has the oracle's hash, bake, terrain and music digests and raw state.
  check(p) {
    const { g } = p;
    const confirmed = g.game_coop_confirmed();
    assert.ok(g.game_coop_next() - (confirmed + 1) <= LEAD, "ran past the lead");
    for (let t = p.seen + 1; t <= confirmed; t++) {
      const actual = digests(g, t);
      const expected = p.truth.expected[t];
      DIGESTS.forEach((name, i) => assert.equal(actual[i], expected[i], `seat ${p.seat} tick ${t}: ${name}`));
    }
    p.seen = Math.max(p.seen, confirmed);
  }
  frame(p) {
    const { g } = p;
    p.bank += Math.min(this.now - p.last, 100);
    p.last = this.now;
    this.hooks.frame?.(p);
    this.feed(p);
    const budget = p.stalled ? 0 : Math.floor(p.bank / TICK_MS),
      ran = g.game_coop_advance(budget, this.now);
    p.bank -= ran * TICK_MS;
    if (ran < budget) p.bank = Math.min(p.bank, 4 * TICK_MS);
    if (p.stream && this.checking) this.check(p);
    this.hooks.advanced?.(p);
    this.feed(p);
    const sent = (size) => new Uint8Array(g.memory.buffer, g.game_coop_tx_buffer(), size).slice();
    let size = g.game_coop_tx(0, this.now);
    if (size) this.send(p, 0, sent(size));
    while ((size = g.game_coop_tx(1, this.now))) this.send(p, 1, sent(size));
    p.at += p.frameMs;
  }
  describe() {
    return this.peers.map((q) => ({
      status: this.status(q).toString(16),
      produced: q.g.game_coop_produced(),
      remote: q.g.game_coop_remote(),
      next: q.g.game_coop_next(),
      confirmed: q.g.game_coop_confirmed(),
      checked: coopStats(q.g).checked,
    }));
  }
  // At `ms` from now, in one instant (both players pressing at once, say).
  after(ms, what, act) {
    const at = this.now + ms;
    this.until(() => this.now >= at, what);
    act();
  }
  // Until the run is over on both sides, ending it there once both produced the whole stream; then the Host leaves
  // and both close.
  finish() {
    const records = this.stream.run.records.length;
    const ended = (p) => this.status(p) & STATUS.ended;
    this.until(
      () => this.peers.every(ended) || this.peers.every((p) => p.g.game_coop_produced() === records - 1),
      "the stream played",
    );
    for (const p of this.peers) {
      const status = this.status(p);
      assert.equal(status & ~0xffff, 0, `seat ${p.seat} stopped: status ${status.toString(16)}`);
    }
    this.leave(this.peers[0]);
    this.close();
  }
  leave(p) {
    assert.equal(p.g.game_coop_request(ASK.leave, 0, 0, 0, this.now), 1);
    this.leaver = { p, at: this.now };
  }
  // Both close soon after the leave (`late` ms more), the leaver for leaving and its partner for the partner's leave.
  close(late = 0) {
    const { p, at } = this.leaver;
    const closed = () => this.peers.every((q) => !(this.status(q) & STATUS.connected));
    this.until(closed, "both close", at + late + CLOSE_MS - this.now);
    for (const q of this.peers) {
      assert.equal(reason(this.status(q)), q === p ? REASON.left : REASON.partnerLeft, `seat ${q.seat}: the reason`);
      assert.ok(this.status(q) & STATUS.closed, `seat ${q.seat}: closed`);
    }
  }
  // `p` closes `ms` after `since` (within `slack`), for `why`; its run then ends at its last confirmed tick, every
  // tick to it checked.
  dropped(p, why, since, ms, slack = p.frameMs) {
    this.until(() => !(this.status(p) & STATUS.connected), `seat ${p.seat} closes`, since + ms + 1000 - this.now);
    const late = this.now - (since + ms);
    assert.ok(late > 0 && late <= slack + 1e-6, `seat ${p.seat} closed ${Math.round(late)} ms off`);
    assert.equal(reason(this.status(p)), why, `seat ${p.seat}: the reason`);
    assert.ok(this.status(p) & STATUS.closed, `seat ${p.seat}: closed`);
    this.endsAlone(p);
  }
  endsAlone(p) {
    this.until(() => this.status(p) & STATUS.ended, `seat ${p.seat}: the run ends`, 1000);
    const status = this.status(p);
    assert.equal(status & (STATUS.desynced | STATUS.failed), 0, `seat ${p.seat}: status ${status.toString(16)}`);
    const confirmed = p.g.game_coop_confirmed();
    assert.equal(p.g.game_coop_next(), confirmed + 1, `seat ${p.seat}: the last tick`);
    assert.equal(p.seen, confirmed, `seat ${p.seat}: ticks checked`);
  }
  // Both ended on the same tick, every tick to it confirmed and checked, in the same state; `end` the last tick.
  ended(end) {
    const [a, b] = this.peers;
    const compared = () => this.peers.every((p) => coopStats(p.g).checked === end + 1);
    this.until(compared, "every tick's hash compared", 2000);
    for (const p of this.peers) {
      const status = this.status(p);
      const clean = status & STATUS.ended && !(status & (STATUS.desynced | STATUS.failed));
      assert.ok(clean, `seat ${p.seat}: status ${status.toString(16)}`);
      assert.equal(p.g.game_coop_next(), end + 1, `seat ${p.seat}: the last tick`);
      assert.equal(p.seen, end, `seat ${p.seat}: ticks checked`);
      const result = coopStats(p.g);
      const lead = result.guessed_lead;
      assert.ok(lead <= this.mode.rmax, `a tick ran on a guess ${lead} past the confirmed one`);
    }
    assert.ok(canonical(a.g).equals(canonical(b.g)), "the peers' states part at the end");
  }
  report(name, at) {
    const [a, b] = this.peers.map((p) => coopStats(p.g));
    const both = (n) => a[n] + b[n];
    const [wa, wb] = [a.wire, b.wire];
    // At most 60 ticks packets a second (one on connecting).
    for (const [p, w] of [
      [this.peers[0], wa],
      [this.peers[1], wb],
    ])
      if (p.connectedAt !== null) {
        const most = 1 + (60 * (this.now - p.connectedAt)) / 1000;
        assert.ok(w.sent <= most + 1e-6, `seat ${p.seat} sent ${w.sent} ticks packets, at most ${Math.floor(most)}`);
      }
    // Each peer guesses and mispredicts its partner's seat.
    const counts = { repairs: wa.repairs + wb.repairs, mispredictions: a.mispredictions_two + b.mispredictions_one };
    for (const name of PIPE_COVERAGE) pipeCoverage[name] += counts[name] ?? both(name);
    return {
      pipe: name,
      stream: this.stream.label,
      delay: this.mode.delay,
      rmax: this.mode.rmax,
      ticks: this.peers[0].g.game_coop_next(),
      rollbacks: [a.rollbacks, b.rollbacks],
      max_depth: Math.max(a.max_depth, b.max_depth),
      max_lead: Math.max(a.max_lead, b.max_lead),
      stalls: [a.stalls, b.stalls],
      repairs: [wa.repairs, wb.repairs],
      rtt_ms: [wa.rtt_ms, wb.rtt_ms],
      lost: [wa.lost, wb.lost],
      stale: [wa.stale, wb.stale],
      unheard: this.unheard,
      ms: Math.round(performance.now() - at),
    };
  }
}
// The whole stream between the peers.
function pipe(stream, truth, mode, swap) {
  const at = performance.now();
  const sim = new Pipe(stream, truth, mode, { swap });
  sim.connect();
  sim.start();
  sim.finish();
  sim.ended(stream.ticks - 1);
  const most = Math.max(...sim.unheard);
  assert.ok(most <= UNHEARD, `${stream.label} at ${JSON.stringify(mode)}: a hash went ${most} ticks unheard`);
  return sim.report("stream", at);
}

// The session's cases, on a stream with perk menus (`stream`) and a short one that ends by itself (`short`).
function pipeCases(stream, truth, short, shortTruth) {
  const lines = [];
  const mode = { delay: 2, rmax: 8 };
  const at = () => performance.now();
  const third = (stream.ticks * TICK_MS) / 3;
  const statusOf = (sim, p) => sim.status(p);
  const produced = (sim) => sim.peers.map((p) => p.g.game_coop_produced());
  const endTick = (sim) => sim.peers[0].g.game_coop_next() - 1;
  // Pause races: both press pause in the same instant (a tie, the Host's wins), hold it past the progress timeout,
  // then the Host resumes as the Guest presses pause again: the Host's resume wins on both.
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 2 });
    sim.connect();
    sim.start();
    sim.after(third, "the pause", () => {
      for (const p of sim.peers) assert.equal(p.g.game_coop_request(ASK.pause, 1, 0, 0, sim.now), 1);
    });
    sim.after(1000, "the pause holds", () => {});
    const held = produced(sim);
    for (const p of sim.peers) assert.ok(statusOf(sim, p) & STATUS.paused, `seat ${p.seat} paused`);
    sim.after(5500, "a long pause", () => {
      assert.deepEqual(produced(sim), held, "records produced while paused");
      assert.equal(sim.peers[0].g.game_coop_request(ASK.pause, 0, 0, 0, sim.now), 1);
      assert.equal(sim.peers[1].g.game_coop_request(ASK.pause, 1, 0, 0, sim.now), 1);
    });
    sim.after(500, "the resume", () => {});
    for (const p of sim.peers) assert.ok(!(statusOf(sim, p) & STATUS.paused), `seat ${p.seat} resumed`);
    sim.finish();
    sim.ended(stream.ticks - 1);
    lines.push(sim.report("pause race", start));
  }
  // Leaving: mid-run (the leaver running no tick for a while after, which the partner waits for to compare the last
  // ticks' hashes before it closes), while paused, from an open perk menu (its picker), and while a request waits
  // (its partner).
  const leaving = (name, seed, act, late = 0) => {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed });
    sim.connect();
    sim.start();
    const check = act(sim);
    sim.close(late);
    check?.();
    const end = endTick(sim);
    assert.ok(end < stream.ticks - 1, `${name}: the run ended where it would anyway`);
    sim.ended(end);
    lines.push(sim.report(name, start));
  };
  const STALL_MS = 1500;
  leaving(
    "leave",
    3,
    (sim) => {
      const g = sim.peers[1];
      sim.after(third, "the leave", () => {
        sim.leave(g);
        g.stalled = true;
      });
      sim.after(STALL_MS, "the leaver runs again", () => (g.stalled = false));
    },
    STALL_MS,
  );
  leaving("leave paused", 4, (sim) => {
    sim.after(third, "the pause", () => sim.peers[0].g.game_coop_request(ASK.pause, 1, 0, 0, sim.now));
    sim.after(1500, "the leave", () => sim.leave(sim.peers[0]));
  });
  const leaveOn = (flag, who) => (sim) => {
    let left = false;
    sim.hooks.advanced = (p) => {
      if (!left && sim.status(p) & flag) {
        sim.leave(who(sim, p));
        left = true;
      }
    };
    sim.until(() => left, "a perk menu");
  };
  leaving("leave picking", 5, leaveOn(STATUS.picker, (sim, p) => p));
  leaving("leave requested", 6, leaveOn(STATUS.waiting, (sim, p) => sim.peers[1 - p.seat]));
  // The Host leaves and the Guest's hashes stop for a while, so the Guest holds the Host's through the run's end
  // before the Host holds the Guest's; then the Host's ticks packets, which would acknowledge them, are lost for longer
  // than a peer used to wait before it closed: the Guest closes for the Host's leave all the same.
  const LOST_MS = 1200;
  leaving(
    "leave unacknowledged",
    17,
    (sim) => {
      const [h, g] = sim.peers;
      let left = Infinity,
        lost = 0;
      const within = (from, ms) => sim.now >= from && sim.now < from + ms;
      sim.alter = (p, channel, bytes) => (p === g && channel === 0 && within(left, STALL_MS) ? bare(bytes) : bytes);
      sim.drop = (p, channel) => p === h && channel === 0 && within(left + STALL_MS, LOST_MS) && ++lost > 0;
      sim.after(third, "the leave", () => {
        sim.leave(h);
        left = sim.now;
      });
      return () => assert.ok(lost > 0, "no acknowledgement lost");
    },
    STALL_MS,
  );
  // The Guest's ticks packets carry no hashes for longer than the engine keeps a tick's results: both peers keep
  // every hash the other lacks or has not had compared, and every tick's is compared by the end.
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 18 });
    const g = sim.peers[1];
    sim.connect();
    sim.start();
    let from = Infinity;
    sim.after(third, "the hashes held back", () => (from = sim.now));
    const held = () => sim.now >= from && sim.now < from + (RING * 3 * TICK_MS) / 2;
    sim.alter = (p, channel, bytes) => (p === g && channel === 0 && held() ? bare(bytes) : bytes);
    sim.finish();
    sim.ended(stream.ticks - 1);
    assert.ok(sim.unheard[1] > RING, `the Guest's hashes went at most ${sim.unheard[1]} ticks unheard`);
    lines.push(sim.report("hashes held back", start));
  }
  // A rematch: the short stream, paused once, plays to its end; the Host cannot start another run mid-run, nor once
  // its own run ended until the Guest confirmed the end (the Guest running no tick a while once it produced its last
  // record). The Guest asks for the same run again and the Host starts it, while every packet and message of the
  // first run arrives again at random: none counts.
  {
    const start = at(),
      sim = new Pipe(short, shortTruth, mode, { seed: 7 });
    const first = [];
    sim.tap = (p, channel, bytes) => first.push({ to: sim.peers[1 - p.seat], channel, bytes });
    sim.connect();
    sim.start();
    const [h, g] = sim.peers;
    const startHost = () => h.g.game_coop_request(ASK.start, mode.delay, mode.rmax, 0, sim.now);
    const pause = (paused) => () => assert.equal(g.g.game_coop_request(ASK.pause, paused, 0, 0, sim.now), 1);
    sim.after((short.ticks * TICK_MS) / 2, "the pause", () => {
      assert.equal(startHost(), 0, "a run started mid-run");
      pause(1)();
    });
    sim.after(300, "the resume", pause(0));
    let stalled = null,
      refused = 0;
    sim.hooks.advanced = (p) => {
      if (p === g && stalled === null && g.g.game_coop_produced() >= short.ticks - 1) {
        stalled = sim.now;
        g.stalled = true;
      }
      if (stalled !== null && sim.now >= stalled + 400) g.stalled = false;
      if (p !== h || !g.stalled || !(sim.status(h) & STATUS.ended)) return;
      assert.equal(startHost(), 0, "a run started before the Guest confirmed the last");
      refused++;
    };
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.ended), "the first run ends");
    sim.ended(short.ticks - 1);
    assert.ok(refused > 0, "the Host never asked before the Guest's end");
    sim.hooks.advanced = null;
    assert.equal(g.g.game_coop_request(ASK.nextRun, 0, 0, 0, sim.now), 1);
    sim.until(() => sim.status(h) >>> 24 === 1, "the Host hears the Guest's choice");
    sim.tap = null;
    sim.start(stream, truth);
    assert.equal(g.g.game_coop_confirmed(), short.ticks - 1, "the Guest's last run when the next started");
    sim.hooks.frame = (p) => {
      for (let i = 0; i < 2; i++) {
        const old = first[Math.floor(sim.random() * first.length)];
        if (old.to === p) sim.receive(p, old.channel, old.bytes);
      }
      const status = sim.status(p);
      assert.ok(!(status & STATUS.paused), "a pause of the first run");
      assert.equal(status >>> 24, 0, "a choice of the first run");
    };
    sim.finish();
    sim.ended(stream.ticks - 1);
    const line = sim.report("rematch", start);
    assert.ok(line.stale.every((n) => n > 0), "no stale packets");
    lines.push(line);
  }
  // The Host's hello reaches the Guest before the Guest connects: the Guest's answers it, and the run plays.
  {
    const start = at(),
      sim = new Pipe(short, shortTruth, mode, { seed: 11 });
    const g = sim.peers[1];
    sim.connect([0]);
    let early = 0;
    sim.hooks.received = (p) => (early += p === g && p.connectedAt === null);
    sim.until(() => early > 0, "the Host's hello");
    sim.hooks.received = null;
    sim.connect([1]);
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.connected), "both connect", 1000);
    sim.start();
    sim.finish();
    sim.ended(short.ticks - 1);
    lines.push(sim.report("hello first", start));
  }
  // The Guest's frames and arrivals stop for longer than the start timeout from the Host's start: the Host gives up
  // after it and tells the Guest, which stops the run it then starts; both can start the next, for no old reason.
  {
    const start = at(),
      sim = new Pipe(short, shortTruth, mode, { seed: 12 });
    const [h, g] = sim.peers;
    sim.connect();
    sim.start();
    const asked = sim.now,
      faults = sim.hitch;
    sim.hitch = { peer: g, from: asked, to: asked + START_MS + 1000 };
    sim.until(() => !(sim.status(h) & STATUS.starting), "the Host gives up", START_MS + 1000);
    const late = sim.now - asked - START_MS;
    assert.ok(late > 0 && late <= h.frameMs + 1, `the Host gave up ${Math.round(late)} ms off`);
    sim.until(() => sim.now >= asked + START_MS + 2000, "the Guest wakes");
    for (const p of sim.peers) {
      const status = sim.status(p);
      const run = status & (STATUS.started | STATUS.starting | STATUS.connected);
      assert.equal(run, STATUS.connected, `seat ${p.seat}: status ${status.toString(16)}`);
      assert.equal(reason(status), REASON.unanswered, `seat ${p.seat}: the reason`);
    }
    sim.hitch = faults;
    sim.start();
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.started), "the next run starts");
    for (const p of sim.peers) assert.equal(reason(sim.status(p)), 0, `seat ${p.seat}: the last run's reason`);
    sim.finish();
    sim.ended(short.ticks - 1);
    lines.push(sim.report("start unanswered", start));
  }
  // The Guest goes away while paused, every record delivered: the Host closes on the liveness timeout.
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 13 });
    const [h, g] = sim.peers;
    sim.connect();
    sim.start();
    sim.after(third, "the pause", () => assert.equal(h.g.game_coop_request(ASK.pause, 1, 0, 0, sim.now), 1));
    sim.after(1000, "the Guest goes", () => (g.gone = true));
    sim.until(() => !sim.flights.some((f) => f.to === h), "the Guest's last packets");
    sim.dropped(h, REASON.silent, h.heardAt, LIVENESS_MS);
    lines.push(sim.report("silent", start));
  }
  // The Guest's packets and messages stop reaching the Host mid-run while the Host's reach the Guest: the Host times
  // out alone, and its transport connects its session again at once (as the page does, client/web/coop.js). The
  // Guest's session, which went on, begins anew on the Host's hello: its run ends at its last confirmed tick, and the
  // Host's next run (the short stream) starts on both and plays out. Then the Host's page reloads, a module that
  // never played a run, and both connect again: the epochs go on from the Guest's, so the next run plays too. Each
  // page reports every session that reached its partner once (game_coop_report): the first with its ticks, the
  // Guest's too though it never closed, then nothing until the next ends.
  const reports = (p) => {
    const taken = [];
    for (let at; (at = p.g.game_coop_report()); ) taken.push(new Int32Array(p.g.memory.buffer, at, 3).slice());
    return taken.map(([rtt, why, ticks]) => ({ rtt, why, ticks }));
  };
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 19 });
    const [h, g] = sim.peers;
    sim.connect();
    // The modules' sessions of the cases before, which their pages would have taken.
    for (const p of sim.peers) reports(p);
    sim.start();
    let cut = Infinity;
    sim.after(third, "the cut", () => (cut = sim.now));
    sim.drop = (p) => p === g && sim.now >= cut;
    sim.until(() => sim.now >= cut && !sim.flights.some((f) => f.to === h), "the Guest's last packets");
    sim.dropped(h, REASON.silent, h.heardAt, LIVENESS_MS);
    const before = sim.status(g);
    assert.ok(before & STATUS.connected && before & STATUS.started, `the Guest goes on: ${before.toString(16)}`);
    cut = Infinity;
    sim.connect([0]);
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.connected), "both connect again", 1000);
    sim.until(() => sim.status(g) & STATUS.ended, "the Guest's run ends", 1000);
    const after = sim.status(g);
    assert.equal(after & (STATUS.started | STATUS.closed | STATUS.leaving), 0, `the Guest: ${after.toString(16)}`);
    assert.equal(reason(after), 0, "the Guest's reason");
    const [hostFirst, guestFirst] = sim.peers.map(reports);
    assert.equal(hostFirst.length, 1, "the Host's first session, reported");
    assert.equal(hostFirst[0].why, REASON.silent, "why the Host's first session ended");
    assert.equal(guestFirst.length, 1, "the Guest's first session, reported though it never closed");
    for (const [first] of [hostFirst, guestFirst]) assert.ok(first.ticks >= stream.ticks / 4 && first.rtt > 0, JSON.stringify(first));
    assert.deepEqual(sim.peers.map(reports), [[], []], "a session reported twice");
    const again = (what) => {
      sim.start(short, shortTruth);
      sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.started), what, START_MS);
      sim.finish();
      sim.ended(short.ticks - 1);
    };
    again("the next run starts");
    // Each side's echoes of the other's packets measured the round trip across the sessions.
    const restarted = sim.report("timeout alone", start);
    assert.ok(restarted.rtt_ms.every((ms) => ms > 0), `round trips ${restarted.rtt_ms}`);
    lines.push(restarted);
    // The second session closed as the Host left at its run's end: each page takes it once, with the run's ticks.
    const closed = sim.peers.map((p) => reports(p).map(({ why, ticks }) => [why, ticks >= short.ticks]));
    assert.deepEqual(closed, [[[REASON.left, true]], [[REASON.partnerLeft, true]]], "the second session, reported");
    // The transport drops what the old page sent (client/web/coop.js's page filter).
    sim.flights = sim.flights.filter((f) => f.to !== g);
    h.g = loadGame(wasm);
    h.g.game_coop_states(1);
    sim.connect();
    again("the run after the reload starts");
    lines.push(sim.report("reload", start));
    // The reloaded page's session closed as its run ended too.
    assert.deepEqual(sim.peers.map((p) => reports(p).length), [1, 1], "the sessions after the reload, reported");
  }
  // The Guest's ticks packets are lost for a second and its repairs never come: the Host closes on the progress
  // timeout, counted from the first packet past the gap, while the Guest's packets keep coming.
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 14 });
    const [h, g] = sim.peers;
    sim.connect();
    sim.start();
    let from = Infinity,
      past = null;
    sim.after(third, "the loss", () => (from = sim.now));
    sim.drop = (p, channel) => p === g && sim.now >= from && (channel === 1 || sim.now < from + 1000);
    sim.hooks.received = (p, channel) => {
      if (p === h && channel === 0 && past === null && sim.now >= from + 1000) past = sim.now;
    };
    sim.until(() => past !== null, "the Guest's packets again");
    // The timeout counts from the Host's last frame before that packet.
    sim.dropped(h, REASON.stalled, past - h.frameMs, PROGRESS_MS, 2 * h.frameMs);
    lines.push(sim.report("stalled", start));
  }
  // A perk menu whose picker chooses for longer than its perk screen takes to close, then picks, its records past the
  // pick withheld for a second (its ticks packets cut back to the pick, its repairs lost) while it plays on; under
  // the window and in lockstep, where the window stops a tick before the menu does. The other peer's frames that
  // wait are perk waits while the menu is open and while the picker's perk screen could still be closing
  // (PICK_FADE_MS from confirming the pick's tick), and network stalls after.
  for (const [rmax, seed] of [[8, 21], [0, 22]]) {
    const start = at(),
      sim = new Pipe(stream, truth, { delay: 2, rmax }, { seed, faults: false });
    const CHOOSING_MS = 700,
      WITHHELD_MS = 1000;
    let menu = null,
      pick = null,
      picked = null,
      last = null;
    const waits = Object.fromEntries(["choosing", "fade", "after"].map((phase) => [phase, { network: 0, perk: 0 }]));
    // The picker's choice waits CHOOSING_MS, then goes on the record after its open.
    const feed = sim.feed.bind(sim);
    sim.feed = (p) => {
      if (p !== menu?.picker || pick) return feed(p);
      if (sim.now < menu.at + CHOOSING_MS) return;
      pick = { tick: menu.open + 1, at: sim.now };
      feed(p);
    };
    const withheld = (p) => pick && p === menu.picker && sim.now < pick.at + WITHHELD_MS;
    sim.drop = (p, channel) => channel === 1 && withheld(p);
    sim.alter = (p, channel, bytes) => (channel === 0 && withheld(p) ? cutTo(bytes, pick.tick) : bytes);
    sim.hooks.advanced = (p) => {
      if (!menu && sim.status(p) & STATUS.picker)
        menu = { picker: p, other: sim.peers[1 - p.seat], open: p.g.game_coop_produced(), at: sim.now };
      if (!menu || p !== menu.other) return;
      const confirmed = p.g.game_coop_confirmed();
      if (pick && picked === null && confirmed >= pick.tick) picked = sim.now;
      const { stalled_network: network, stalled_perk: perk } = coopStats(p.g);
      const phase =
        picked !== null ? (sim.now - picked < PICK_FADE_MS ? "fade" : "after") : confirmed >= menu.open ? "choosing" : null;
      if (last && phase && !(pick && sim.now >= pick.at + WITHHELD_MS)) {
        waits[phase].network += network - last.network;
        waits[phase].perk += perk - last.perk;
      }
      last = { network, perk };
    };
    sim.connect();
    sim.start();
    sim.until(() => pick && sim.now >= pick.at + WITHHELD_MS, "the pick and the records withheld");
    assert.equal(menu.other.g.game_coop_remote(), pick.tick, "the picker's records past its pick arrived");
    const { choosing, fade, after } = waits;
    const counted = choosing.perk > 30 && choosing.network === 0 && fade.perk > 0 && fade.network === 0;
    assert.ok(counted && after.network > 0 && after.perk === 0, `window ${rmax}: waits ${JSON.stringify(waits)}`);
    sim.finish();
    sim.ended(stream.ticks - 1);
    lines.push({ ...sim.report("withheld after a pick", start), waits });
  }
  // The transport closes mid-run: the Host, told so, closes at once, its run ending at its last confirmed tick.
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 15 });
    const [h, g] = sim.peers;
    sim.connect();
    sim.start();
    sim.after(third, "the close", () => {
      g.gone = true;
      assert.equal(h.g.game_coop_disconnect(REASON.left), 0, "not a transport's reason");
      assert.equal(h.g.game_coop_disconnect(REASON.partnerGone), 1);
      assert.equal(h.g.game_coop_disconnect(REASON.disconnected), 0, "closed twice");
    });
    const status = sim.status(h);
    assert.equal(status & STATUS.connected, 0, "the Host stays connected");
    assert.equal(reason(status), REASON.partnerGone, "the reason");
    sim.endsAlone(h);
    lines.push(sim.report("disconnect", start));
  }
  // An invalid record: the receiver stops on a protocol error and tells the partner. Both tell their players the
  // same, and not what they tell of a malformed message.
  let badRecord;
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 8 });
    let last = null;
    sim.tap = (p, channel, bytes) => {
      if (p.seat === 0 && channel === 0 && bytes[1]) last = bytes;
    };
    sim.connect();
    sim.start();
    sim.after(third, "the invalid record", () => {
      const bad = Buffer.from(last);
      bad.writeFloatLE(NaN, 40);
      sim.receive(sim.peers[1], 0, bad);
    });
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.failed), "both stop");
    const [h, g] = sim.peers.map((p) => sim.status(p));
    assert.equal(g & STATUS.remote, 0, "the Guest found it");
    assert.ok(h & STATUS.remote, "the Host heard it");
    for (const s of [h, g]) assert.equal((s >>> 16) & 255, REASON.badRecord, "the error");
    badRecord = why(sim.peers[0].g);
    assert.equal(why(sim.peers[1].g), badRecord, "the error's words");
    lines.push(sim.report("invalid record", start));
  }
  // A malformed message reaches the Guest as the Host starts a run: the Host stops waiting for it.
  {
    const start = at(),
      sim = new Pipe(short, shortTruth, mode, { seed: 16 });
    sim.connect();
    sim.start();
    sim.receive(sim.peers[1], 1, Uint8Array.of(99, 0, 0, 0, 0));
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.failed), "both stop");
    const [h, g] = sim.peers.map((p) => sim.status(p));
    assert.equal(h & (STATUS.starting | STATUS.started | STATUS.remote), STATUS.remote, `the Host: ${h.toString(16)}`);
    for (const s of [h, g]) assert.equal(reason(s), REASON.badMessage, "the error");
    for (const p of sim.peers) assert.notEqual(why(p.g), badRecord, "a malformed message's words");
    lines.push({ pipe: "error starting", ms: Math.round(at() - start) });
  }
  // A desync in lockstep: one peer's state changes under it, and both stop at a tick after the change.
  {
    const start = at(),
      sim = new Pipe(stream, truth, { delay: 2, rmax: 0 }, { seed: 9 });
    sim.connect();
    sim.start();
    let changed = -1;
    sim.after(third, "the change", () => {
      changed = sim.peers[0].g.game_coop_next();
      assert.equal(sim.peers[0].g.game_coop_corrupt(1), 1);
      sim.checking = false;
    });
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.desynced), "both desync");
    for (const p of sim.peers) {
      const [tick, local, remote] = new Int32Array(p.g.memory.buffer, p.g.game_coop_desync(), 3);
      assert.ok(tick >= changed && local !== remote, `seat ${p.seat}: desync at ${tick}, changed at ${changed}`);
      // The session ended, and says why.
      const status = sim.status(p);
      const closed = status & (STATUS.connected | STATUS.closed);
      assert.equal(closed, STATUS.closed, `seat ${p.seat}: ${status.toString(16)}`);
      assert.equal(reason(status), REASON.diverged, `seat ${p.seat}: the reason`);
    }
    lines.push(sim.report("desync", start));
  }
  // Different builds: both stop at hello.
  {
    const start = at(),
      sim = new Pipe(stream, truth, mode, { seed: 10 });
    const version = new Uint8Array(guest.memory.buffer, guest.game_recorder_version(), 64);
    const saved = version.slice();
    version[0] ^= 1;
    sim.connect();
    sim.until(() => sim.peers.every((p) => sim.status(p) & STATUS.failed), "both refuse");
    version.set(saved);
    for (const p of sim.peers) assert.equal((sim.status(p) >>> 16) & 255, REASON.version, "the error");
    lines.push({ pipe: "versions", ms: Math.round(at() - start) });
  }
  return lines;
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

const liveGame = live && sevenTunes(live);
const report = [];
// The streams the session's cases play: one with perk menus, and a short one that ends by itself.
const CASES = { menus: "coop-quest-2.4-ranked.rsi", short: "coop-quest-1.1.rsi" };
const cases = {};
for (const file of live ? LIVE_STREAMS : streams) {
  const recorded = decode(fs.readFileSync(path.join(corpus, file)));
  for (const { stream: variant, name: variantName } of live ? [{ stream: recorded }] : variants(recorded)) {
    const stream = requests(variant);
    const { run, cmd, ticks } = stream;
    const label = (stream.label = variantName ? `${file} (${variantName})` : file);
    coverage.sixth_choices += stream.extra === 6;
    coverage.seventh_choices += stream.extra === 7;
    coverage.beyond_picks += stream.beyond;
    const truth = oracle(solo, run, cmd, ticks);
    for (const name of PLAIN_COVERAGE) coverage[name] += truth.stats[name];
    if (live) {
      const at = performance.now();
      const first = bootLive(liveGame);
      const shown = oracle(first.game, run, cmd, ticks, first.look);
      const forced = LIVE_MODES.map((mode) => {
        const original = bootLive(liveGame);
        return rollbacks(original.game, stream, shown, mode, original.look);
      });
      for (const result of forced) for (const name of LIVE_COVERAGE) coverage[name] += result.stats[name];
      console.log(JSON.stringify({ stream: label, ticks, live_ms: Math.round(performance.now() - at) }));
      continue;
    }
    let at = performance.now();
    for (let i = 0; i < 100; i++) solo.game_coop_hash();
    const hashUs = (1000 * (performance.now() - at)) / 100;
    const forced = MODES.map((mode) => rollbacks(solo, stream, truth, mode));
    const piped = PIPE_MODES.map((mode, i) => pipe(stream, truth, mode, i % 2 === 1));
    for (const [name, wanted] of Object.entries(CASES))
      if (file === wanted && !variantName) cases[name] = { stream, truth };
    for (const result of forced) {
      for (const name of ROLLBACK_COVERAGE) coverage[name] += result.stats[name];
      coverage.menu_rollbacks += result.menuRestores;
    }
    const line = {
      stream: label,
      ticks,
      rollbacks: forced.reduce((n, f) => n + f.stats.rollbacks, 0),
      resimulated: forced.reduce((n, f) => n + f.stats.resimulated, 0),
      plain_ms: Math.round(truth.plainMs),
      solo_ms: Math.round(truth.soloMs),
      rollback_ms: forced.map((f) => Math.round(f.ms)),
      pipe: piped.map(({ rollbacks, max_depth, max_lead, repairs, rtt_ms, lost, unheard, ms }) => ({
        rollbacks,
        max_depth,
        max_lead,
        repairs,
        rtt_ms,
        lost,
        unheard,
        ms,
      })),
      // The engine's cost a tick over the plain run's: its capture, the hash and the raw state's digest.
      engine_us_per_tick: +((1000 * (truth.soloMs - truth.plainMs)) / ticks).toFixed(1),
      hash_us: +hashUs.toFixed(1),
      slot_kib: Math.round(forced[0].stats.slot_bytes / 1024),
    };
    report.push(line);
    console.log(JSON.stringify(line));
  }
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
prediction(cases.menus.stream.run);
for (const line of pipeCases(cases.menus.stream, cases.menus.truth, cases.short.stream, cases.short.truth))
  console.log(JSON.stringify(line));
const missing = Object.entries(coverage).filter(([, count]) => count === 0).map(([name]) => name);
const missingPipe = Object.entries(pipeCoverage).filter(([, count]) => count === 0).map(([name]) => name);
assert.deepEqual(missing, [], `missing co-op coverage: ${missing.join(", ")}; ${JSON.stringify(coverage)}`);
assert.deepEqual(missingPipe, [], `missing peer coverage: ${missingPipe.join(", ")}; ${JSON.stringify(pipeCoverage)}`);
console.log(
  `Passed ${report.length} co-op streams; audit ${auditMs} ms; coverage ${JSON.stringify(coverage)}; ` +
    `between the peers ${JSON.stringify(pipeCoverage)}`,
);
