// What co-op costs late in a long two-player Survival run (docs/rewrite/network-coop.md §3.1), in game.wasm: the
// numbers the feasibility of rollback rests on. A bot plays both players (each kites away from the nearest creature,
// otherwise picks up bonuses or circles, aims at the nearest creature and fires; player one opens the perk menu
// whenever a perk is pending and takes the first choice that neither kills nor spends health), both players' health
// set far past full before every frame, more than a crowd's hits take within one, so the run reaches the late game,
// the spawn rate rising with the run's time. The run is the one a co-op session starts (host/coop_live.inc
// coop_latch, host/ranked.inc ranked_spec): two players, the ranked profile, the original's bugs fixed. The same bot
// plays:
// 1. a plain run (portable_step_many): each tick's cost from `from` to `to` minutes of the run's time; the creature
//    pool over those ticks (the share with every slot holding a creature, and the fewest creatures any held) and the
//    minute every slot first held one; at `from` minutes how many perks player one holds and how many the run has
//    available (perk_meta_table);
// 2. the run through the co-op engine (host/coop.inc) with both players local, records on time, input delay 2 and
//    window 8 (4 past 15 minutes): from `from` minutes, each tick's cost there (the step, the state's capture into
//    its slot, its hash); every 30th frame a rollback of 8 or 12 ticks (alternately), player two's record for the
//    first of them a stand-in its real one contradicts, which arrives once they ran, all on predictions with their
//    bakes held: the frame that takes them back, runs them again and the next; and the capture, the hash and a
//    restore alone (the frame after it, which runs the restored tick again with its own, is no tick's sample); the
//    ring's slot size and the memory the engine holds over the plain run's;
// 3. from `to` minutes on, `session` seconds of play at 60 Hz and again at 144 Hz with player two's records
//    arriving over a network (`profile`: one way ms ± jitter, the jitter seeded, sent as the partner's run reaches
//    the tick less the input delay), the engine predicting them: the work of each frame that ran or ran again ticks
//    (game_coop_advance), the rollbacks by depth (game_coop_telemetry), frames whose due ticks all waited, and ticks
//    run again per tick run.
// Timings are wall time (performance.now) around single calls, so in a browser they need a cross-origin isolated
// page for microsecond resolution; checks/coop_browser.mjs runs `measure` in Chrome that way. It is simulation alone:
// the module runs headless (grim_render_disabled), so a tick's world draw and the held bakes' commit into the terrain
// draw nothing, and no wire carries the records.
//
//   node crimson-core/checks/coop_cost.mjs [game.wasm] [--from 20] [--to 35] [--session 60]
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { coopStatIndex } from "./coop_link.mjs";
import { CORE, config, index, names } from "./engine.mjs";

// The run, and the snapshot fields the bot reads (word indices).
export function costSetup() {
  const read = /^(players\[[01]\]\.(health|pos_x|pos_y)|creatures\[\d+\]\.(active|health|pos_x|pos_y)|bonuses\[\d+\]\.(bonus_id|picked|time\.pos_x|time\.pos_y)|globals\.(perk_pending_count|run_elapsed_ms|perk_choice_ids\[\d\])|players\[0\]\.perk_counts\[\d+\]|perk_metadata\[\d+\]\.available)$/;
  return {
    config: [...config(1, 1, 1, { seed: 41, players: 2, preserveBugs: 0 })],
    fields: Object.fromEntries(names.filter((name) => read.test(name)).map((name) => [name, index.get(name)])),
    words: names.length,
    slotBytes: coopStatIndex("slot_bytes"),
    ran: ["ticks", "resimulated"].map(coopStatIndex),
  };
}

// Self-contained, so that a page can run it from its source.
export async function measure(bytes, { config, fields, words, slotBytes, ran, from = 20, to = 35, session = 60, profile = { ms: 60, jitter: 20 } }) {
  const module = await WebAssembly.compile(bytes);
  const TICK_MS = 1000 / 60, MINUTE = 60000, DELAY = 2, RMAX = 8, OPEN = 8, EVERY = 30;
  // Perks the bot passes over (src/crimson/perks/ids.py): Fatal Lottery, Infernal Contract, Ammunition Within,
  // Highlander and Death Clock kill or spend health outright.
  const SPARED = [15, 24, 35, 41, 47], CHOICES = 5, HEALTH = 10000;
  // The creature pool's slots: the snapshot's last creature is the entry the allocator hands out when every slot is
  // taken (creature_alloc_slot), which updates and collisions never process.
  const CREATURES = Object.keys(fields).filter((name) => /^creatures\[\d+\]\.active$/.test(name)).length - 1;
  // host/api.h PortableInput: the pad's movement and aim (matrix.mjs PAD), firing.
  const INPUT_BYTES = 20, PAD = 0x100 | (3 << 9) | 0x1000 | (4 << 13), FIRE = 1;
  // host/coop_wire.inc game_coop_telemetry: the round trip, why the session ended, then CoopSessionStats.
  const DEPTHS = 12, FRAME_BUCKETS = 6;
  // A headless host: no assets, the clock real.
  function instance() {
    let memory;
    const refuse = (scope) =>
      Object.fromEntries(
        WebAssembly.Module.imports(module)
          .filter((i) => i.module === scope)
          .map((i) => [i.name, () => { throw Error(`headless game module called ${scope} ${i.name}`); }]),
      );
    const wasi = {
      ...refuse("wasi_snapshot_preview1"),
      fd_write: (fd, iovs, count, written) => {
        const view = new DataView(memory.buffer);
        let total = 0;
        for (let k = 0; k < count; k++) total += view.getUint32(iovs + k * 8 + 4, true);
        view.setUint32(written, total, true);
        return 0;
      },
      fd_prestat_get: () => 8,
    };
    const host = { ...refuse("host"), fatal: () => { throw Error("game module: fatal"); }, time_ms: () => performance.now(), clock_ms: () => performance.now() };
    const exports = new WebAssembly.Instance(module, { wasi_snapshot_preview1: wasi, host }).exports;
    const g = Object.create(exports);
    memory = g.memory;
    g._initialize();
    new Uint8Array(memory.buffer, g.portable_config(), config.length).set(config);
    const head = new DataView(new Uint8Array(config).buffer);
    if (!g.portable_init(...[0, 4, 8, 12].map((at) => head.getUint32(at, true)))) throw Error("rejected config");
    // Where each player's health lives: the word that, written, the snapshot reads back.
    g.health = [0, 1].map((p) => {
      const name = `players[${p}].health`, words32 = new Float32Array(memory.buffer);
      const value = snapshot(g).float(name), out = g.portable_output() >> 2;
      for (let i = 0; i < words32.length; i++) {
        if (words32[i] !== value || (i >= out && i < out + words)) continue;
        words32[i] = 4321.5;
        const found = snapshot(g).float(name) === 4321.5;
        words32[i] = value;
        if (found) return i;
      }
      throw Error(`${name} not found`);
    });
    return g;
  }
  function snapshot(g) {
    if (g.portable_snapshot() !== words) throw Error("snapshot schema");
    const view = new DataView(g.memory.buffer, g.portable_output(), words * 4);
    return { float: (name) => view.getFloat32(fields[name] * 4, true), word: (name) => view.getUint32(fields[name] * 4, true) };
  }
  const heal = (g) => {
    const words32 = new Float32Array(g.memory.buffer);
    for (const i of g.health) words32[i] = HEALTH;
  };
  // Each player's input from the state the frame starts from, whether a perk is pending, and the choice to take
  // from the open menu.
  function bot(g) {
    const s = snapshot(g);
    const inputs = [0, 1].map((p) => {
      const x = s.float(`players[${p}].pos_x`), y = s.float(`players[${p}].pos_y`);
      let nearest = Infinity, target = null;
      for (let c = 0; c < CREATURES; c++) {
        if (!s.word(`creatures[${c}].active`) || s.float(`creatures[${c}].health`) <= 0) continue;
        const cx = s.float(`creatures[${c}].pos_x`), cy = s.float(`creatures[${c}].pos_y`), d = Math.hypot(cx - x, cy - y);
        if (d < nearest) [nearest, target] = [d, [cx, cy]];
      }
      let mx = -(y - 512) * (p ? -1 : 1), my = (x - 512) * (p ? -1 : 1);
      if (target && nearest < 210) [mx, my] = [x - target[0], y - target[1]];
      else
        for (let b = 0, best = 300; b < 16; b++) {
          if (!s.word(`bonuses[${b}].bonus_id`) || s.word(`bonuses[${b}].picked`)) continue;
          const bx = s.float(`bonuses[${b}].time.pos_x`), by = s.float(`bonuses[${b}].time.pos_y`), d = Math.hypot(bx - x, by - y);
          if (d < best) [best, mx, my] = [d, bx - x, by - y];
        }
      if (x < 140) mx = Math.abs(mx) + 180;
      if (x > 884) mx = -Math.abs(mx) - 180;
      if (y < 140) my = Math.abs(my) + 180;
      if (y > 884) my = -Math.abs(my) - 180;
      const n = Math.hypot(mx, my) || 1;
      const [ax, ay] = target ? [target[0] - x, target[1] - y] : [0, -60];
      return [mx / n, my / n, ax, ay, PAD | (target ? FIRE : 0)];
    });
    const offered = Array.from({ length: CHOICES }, (_, i) => s.word(`globals.perk_choice_ids[${i}]`));
    const choice = Math.max(0, offered.findIndex((id) => !SPARED.includes(id)));
    let active = 0;
    for (let c = 0; c < CREATURES; c++) active += s.word(`creatures[${c}].active`) ? 1 : 0;
    return { inputs, pending: s.word("globals.perk_pending_count") > 0, choice, ms: s.word("globals.run_elapsed_ms"), active };
  }
  const writeInput = (g, at, input) => {
    const view = new DataView(g.memory.buffer);
    input.slice(0, 4).forEach((v, i) => view.setFloat32(at + i * 4, v, true));
    view.setUint32(at + 16, input[4], true);
  };
  const summary = (samples) => {
    const sorted = Float64Array.from(samples).sort(), at = (q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
    const round = (ms) => Math.round(ms * 1000) / 1000;
    return { n: sorted.length, mean: round(sorted.reduce((a, b) => a + b, 0) / sorted.length), p50: round(at(0.5)), p99: round(at(0.99)), max: round(sorted.at(-1)) };
  };
  const late = (ms) => ms >= from * MINUTE && ms < to * MINUTE;
  // The perks the run's players hold: how often each was taken, by perk id (src/crimson/perks/ids.py).
  const held = (run) => {
    const s = snapshot(run);
    return Object.fromEntries(
      Object.keys(fields)
        .filter((name) => name.startsWith("players[0].perk_counts[") && s.word(name))
        .map((name) => [/\[(\d+)\]$/.exec(name)[1], s.word(name)]),
    );
  };
  const minutes = (ms) => Math.round((ms / MINUTE) * 10) / 10;

  // (1) The plain run.
  const plain = instance(), plainTicks = [];
  const pool = { first_full_minute: null, full_share: 0, min_active: CREATURES };
  let perksAtFrom = null;
  for (let asked = false, view = bot(plain); view.ms < to * MINUTE; ) {
    const { inputs, pending, choice } = view;
    inputs.forEach((input, p) => writeInput(plain, plain.portable_input() + p * INPUT_BYTES, input));
    // The menu opens on one tick and its first choice is taken on the next.
    const command = asked ? [1, choice] : pending ? [2, 0] : null;
    asked = !asked && pending;
    if (command) new Int32Array(plain.memory.buffer, plain.portable_commands(), 2).set(command);
    heal(plain);
    const start = performance.now();
    if (!plain.portable_step_many(command ? 1 : 0)) throw Error("the plain run stopped");
    const spent = performance.now() - start;
    view = bot(plain);
    const full = view.active === CREATURES;
    if (late(view.ms)) {
      plainTicks.push(spent);
      pool.full_share += full;
      pool.min_active = Math.min(pool.min_active, view.active);
    }
    if (full && pool.first_full_minute === null) pool.first_full_minute = minutes(view.ms);
    if (view.ms >= from * MINUTE && perksAtFrom === null) {
      const s = snapshot(plain), available = Object.keys(fields).filter((name) => name.startsWith("perk_metadata[") && s.word(name));
      perksAtFrom = { held: Object.keys(held(plain)).length, available: available.length };
    }
  }

  pool.full_share = Math.round((pool.full_share / plainTicks.length) * 1000) / 1000;

  // (2) The run through the co-op engine.
  const g = instance();
  const telemetry = () => Array.from(new Int32Array(g.memory.buffer, g.game_coop_telemetry(), 5 + DEPTHS + FRAME_BUCKETS));
  // Ticks run and run again so far.
  const worked = () => ran.reduce((n, at) => n + new Int32Array(g.memory.buffer, g.game_coop_stats(), at + 1)[at], 0);
  if (g.game_coop_start(-1, DELAY, RMAX, 1) !== 1) throw Error("co-op did not start");
  // Player one's perk request: the tick its open went on, until the pick that follows it is produced (-1 none), and
  // the tick by which the state shows the pick.
  let opened = -1, picked = -1, frame = 0, deep = 0;
  // Records for both seats up to the delay past the run, from the frame's state; with `late`, player two's
  // records stand in until their time (none: the engine guesses), each arrival delivered then.
  const arrivals = [];
  const writeRecord = (at, input, cmd) => {
    writeInput(g, at, input);
    new Uint8Array(g.memory.buffer)[at + INPUT_BYTES] = cmd;
  };
  for (let t = 0; t < DELAY; t++) for (const seat of [0, 1]) writeRecord(g.game_coop_seed(seat, t), bot(g).inputs[seat], 0);
  // A rollback under way: player two's real record for `tick`, which a stand-in took the place of, and how many
  // ticks run before it arrives. The stand-in's stick goes the other way.
  let forced = null;
  const reversed = ([mx, my, ...rest]) => [-mx, -my, ...rest];
  // The pick goes on the tick after the open, once the run has run the open and the menu shows its choices: the
  // run waits for it. No perk request starts during a rollback.
  function produce({ inputs, pending, choice }, arrive) {
    while (g.game_coop_produced() < g.game_coop_next() + DELAY) {
      const t = g.game_coop_produced() + 1;
      let cmd = 0;
      if (opened >= 0) {
        if (g.game_coop_next() <= opened) return;
        [cmd, opened, picked] = [choice + 1, -1, t + 1];
      } else if (pending && !forced && g.game_coop_next() > picked) [cmd, opened] = [OPEN, t];
      for (const seat of [0, 1]) writeRecord(g.game_coop_input_for(seat), inputs[seat], seat ? 0 : cmd);
      if (g.game_coop_produce(0) !== t) throw Error(`no record for ${t}`);
      if (forced && forced.tick < 0) {
        forced.tick = t;
        forced.input = inputs[1];
        writeRecord(g.game_coop_input_for(1), reversed(inputs[1]), 0);
        if (g.game_coop_deliver(1, t, 0) !== 1) throw Error(`player two's stand-in for ${t}`);
      }
      if (!arrive) continue;
      writeRecord(g.game_coop_input_for(1), inputs[1], 0);
      if (g.game_coop_deliver(1, t, -1) !== 1) throw Error(`player two's stand-in for ${t}`);
      arrivals.push({ t, at: arrive(t), input: inputs[1] });
    }
  }
  const time = (call) => {
    const start = performance.now();
    call();
    return performance.now() - start;
  };
  const coopTicks = [], captures = [], hashes = [], restores = [], rollbacks = { 8: [], 12: [] };
  let view = bot(g), restored = false;
  for (; view.ms < to * MINUTE; frame++) {
    const measured = late(view.ms);
    if (measured && !forced && opened < 0 && frame % EVERY === 0) forced = { tick: -1, depth: deep++ % 2 ? 12 : 8 };
    produce(view);
    heal(g);
    if (forced?.tick >= 0 && g.game_coop_next() - forced.tick === forced.depth) {
      // The real record arrives: the frame takes back the ticks run since, runs them again and the next.
      writeRecord(g.game_coop_input_for(1), forced.input, 0);
      if (g.game_coop_deliver(1, forced.tick, 1) !== 1) throw Error(`player two's record for ${forced.tick}`);
      let fresh;
      rollbacks[forced.depth].push(time(() => (fresh = g.game_coop_advance(1, 0))));
      if (fresh !== 1 || g.game_coop_confirmed() !== g.game_coop_next() - 1) throw Error("the rollback confirmed nothing");
      forced = null;
    } else {
      let fresh;
      const spent = time(() => (fresh = g.game_coop_advance(1, 0)));
      // A frame waiting for the pick runs nothing; the one after a restore runs the restored tick again first.
      if (fresh === 1 && measured && !restored) coopTicks.push(spent);
      else if (fresh !== 1 && opened < 0) throw Error("the run stopped");
    }
    restored = false;
    // Between the rollbacks: the capture, the hash and a restore one tick back, which the next frame runs again.
    if (measured && !forced && opened < 0 && frame % EVERY === EVERY / 2) {
      captures.push(time(() => g.game_coop_capture()));
      hashes.push(time(() => g.game_coop_hash()));
      restores.push(time(() => g.game_coop_restore(g.game_coop_next() - 1)));
      restored = true;
    }
    view = bot(g);
  }
  // A rollback under way as the run's time ran out takes its real record.
  if (forced?.tick >= 0) {
    writeRecord(g.game_coop_input_for(1), forced.input, 0);
    if (g.game_coop_deliver(1, forced.tick, 1) !== 1) throw Error(`player two's record for ${forced.tick}`);
  }
  forced = null;
  const slot = new Int32Array(g.memory.buffer, g.game_coop_stats(), slotBytes + 1)[slotBytes];
  const perks = { plain: held(plain), coop: held(g), at_from: perksAtFrom };

  // (3) Play over a network at 60 and 144 Hz, from `to` minutes of the run's time on.
  const sessions = {};
  for (const hz of [60, 144]) {
    const before = telemetry(), work = [], start = { next: g.game_coop_next(), confirmed: g.game_coop_confirmed(), ms: view.ms };
    let clock = 0, banked = 0, stalled = 0, frames = 0;
    // The jitter, seeded (mulberry32), so every run of the check sends alike.
    let seed = hz;
    const random = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let r = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) ^ r;
      return ((r ^ (r >>> 14)) >>> 0) / 2 ** 32;
    };
    // The partner's run reaches tick t at its time less the delay, and its record takes a one-way trip.
    const arrive = (t) => (t - start.next - DELAY) * TICK_MS + profile.ms + (2 * random() - 1) * profile.jitter;
    for (; clock < session * 1000; clock += 1000 / hz, frames++) {
      for (const arrival of arrivals.filter((a) => a.at <= clock)) {
        writeRecord(g.game_coop_input_for(1), arrival.input, 0);
        if (g.game_coop_deliver(1, arrival.t, 1) !== 1) throw Error(`player two's record for ${arrival.t}`);
        arrivals.splice(arrivals.indexOf(arrival), 1);
      }
      produce(bot(g), arrive);
      heal(g);
      banked += 1000 / hz;
      const budget = Math.floor(banked / TICK_MS), done = worked(), at = performance.now();
      const fresh = g.game_coop_advance(budget, 0);
      const spent = performance.now() - at;
      if (worked() > done) work.push(spent);
      banked -= fresh * TICK_MS;
      if (fresh < budget) {
        stalled += fresh === 0;
        banked = Math.min(banked, 4 * TICK_MS);
      }
    }
    // Every record arrives, and the run confirms what it ran (a perk menu may wait for its pick), before the
    // next session.
    for (const arrival of arrivals.splice(0)) {
      writeRecord(g.game_coop_input_for(1), arrival.input, 0);
      if (g.game_coop_deliver(1, arrival.t, 1) !== 1) throw Error(`player two's record for ${arrival.t}`);
    }
    for (let frames = 0; g.game_coop_confirmed() < g.game_coop_next() - 1; frames++) {
      if (frames > 60) throw Error("the run confirms nothing");
      produce(bot(g));
      heal(g);
      g.game_coop_advance(1, 0);
    }
    const after = telemetry(), delta = after.map((n, i) => n - before[i]);
    const [, , ticks, resimulated] = delta;
    if (ticks < 0.9 * session * 60) throw Error(`the run stopped at ${hz} Hz`);
    const buckets = [1, 2, 4, 8, 16];
    view = bot(g);
    sessions[hz] = {
      minutes: [minutes(start.ms), minutes(view.ms)],
      frames,
      worked: work.length,
      work: summary(work),
      work_buckets: [...buckets.map((ms, i) => work.filter((w) => w >= (buckets[i - 1] ?? 0) && w < ms).length), work.filter((w) => w >= 16).length],
      depths: delta.slice(5, 5 + DEPTHS),
      stalled,
      resimulated_per_tick: Math.round((resimulated / ticks) * 1000) / 1000,
      ticks,
    };
  }
  return {
    minutes: [from, to],
    pool,
    plain_tick: summary(plainTicks),
    coop_tick: summary(coopTicks),
    capture: summary(captures),
    restore: summary(restores),
    hash: summary(hashes),
    rollback_8: summary(rollbacks[8]),
    rollback_12: summary(rollbacks[12]),
    slot_bytes: slot,
    engine_bytes: g.memory.buffer.byteLength - plain.memory.buffer.byteLength,
    perks,
    profile,
    sessions,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const option = (name, fallback) => {
    const at = args.indexOf(`--${name}`);
    return at < 0 ? fallback : Number(args.splice(at, 2)[1]);
  };
  const options = { from: option("from", 20), to: option("to", 35), session: option("session", 60) };
  const [wasm = new URL("build/game/game.wasm", CORE).pathname] = args;
  console.log(JSON.stringify(await measure(fs.readFileSync(wasm), { ...costSetup(), ...options })));
}
