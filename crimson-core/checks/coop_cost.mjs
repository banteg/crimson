// What co-op costs late in a long two-player Survival run (docs/rewrite/network-coop.md §3.1), in game.wasm: the
// numbers the feasibility of rollback rests on. A bot plays both players (each kites away from the nearest creature,
// otherwise picks up bonuses or circles, aims at the nearest creature and fires; player one opens the perk menu
// whenever a perk is pending and takes the first choice that neither kills nor spends health), both players' health
// set far past full before every frame, more than a crowd's hits take within one, so the run reaches the late game:
// the creature pool fills about ten minutes in, and the spawn rate keeps rising with the run's time. The same bot
// plays:
// 1. a plain run (portable_step_many): each tick's cost from `from` to `to` minutes of the run's time;
// 2. the run through the co-op engine (host/coop.inc) with both players local, records on time, input delay 2 and
//    window 8 (4 past 15 minutes): each tick's cost there (the step, the state's capture into its slot, its hash),
//    and from `from` minutes, every 30th frame a forced rollback of 8 or 12 ticks (alternately): the restore alone
//    and the frame that runs the ticks again with the next one; the hash alone every 30th frame; the ring's slot
//    size and the memory the engine holds over the plain run's;
// 3. from `to` minutes on, `session` seconds of play at 60 Hz and again at 144 Hz with player two's records
//    arriving over a network (`profile`: one way ms ± jitter, sent as the partner's run reaches the tick less the
//    input delay), the engine predicting them: each frame's work (game_coop_advance), the rollbacks by depth
//    (game_coop_telemetry), frames whose due ticks all waited, and ticks run again per tick run.
// Timings are wall time (performance.now) around single calls, so in a browser they need a cross-origin isolated
// page for microsecond resolution; checks/coop_browser.mjs runs `measure` in Chrome that way.
//
//   node crimson-core/checks/coop_cost.mjs [game.wasm] [--from 20] [--to 35] [--session 60]
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { coopStatIndex } from "./coop_link.mjs";
import { CORE, config, index, names } from "./engine.mjs";

// The run, and the snapshot fields the bot reads (word indices).
export function costSetup() {
  const read = /^(players\[[01]\]\.(health|pos_x|pos_y)|creatures\[\d+\]\.(active|health|pos_x|pos_y)|bonuses\[\d+\]\.(bonus_id|picked|time\.pos_x|time\.pos_y)|globals\.(perk_pending_count|run_elapsed_ms|perk_choice_ids\[\d\])|players\[0\]\.perk_counts\[\d+\])$/;
  return {
    config: [...config(1, 1, 1, { seed: 41, players: 2 })],
    fields: Object.fromEntries(names.filter((name) => read.test(name)).map((name) => [name, index.get(name)])),
    words: names.length,
    slotBytes: coopStatIndex("slot_bytes"),
  };
}

// Self-contained, so that a page can run it from its source.
export async function measure(bytes, { config, fields, words, slotBytes, from = 20, to = 35, session = 60, profile = { ms: 60, jitter: 20 } }) {
  const module = await WebAssembly.compile(bytes);
  const TICK_MS = 1000 / 60, MINUTE = 60000, DELAY = 2, RMAX = 8, OPEN = 8, ROLLBACK_EVERY = 30;
  // Perks the bot passes over (src/crimson/perks/ids.py): Fatal Lottery, Infernal Contract, Ammunition Within,
  // Highlander and Death Clock kill or spend health outright.
  const SPARED = [15, 24, 35, 41, 47], CHOICES = 5, HEALTH = 10000;
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
      for (let c = 0; c < 384; c++) {
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
    return { inputs, pending: s.word("globals.perk_pending_count") > 0, choice, ms: s.word("globals.run_elapsed_ms") };
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

  // (1) The plain run.
  const plain = instance(), plainTicks = [];
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
    if (late(view.ms)) plainTicks.push(spent);
  }

  // (2) The run through the co-op engine.
  const g = instance();
  const telemetry = () => Array.from(new Int32Array(g.memory.buffer, g.game_coop_telemetry(), 5 + DEPTHS + FRAME_BUCKETS));
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
  // The pick goes on the tick after the open, once the run has run the open and the menu shows its choices: the
  // run waits for it.
  function produce({ inputs, pending, choice }, arrive) {
    while (g.game_coop_produced() < g.game_coop_next() + DELAY) {
      const t = g.game_coop_produced() + 1;
      let cmd = 0;
      if (opened >= 0) {
        if (g.game_coop_next() <= opened) return;
        [cmd, opened, picked] = [choice + 1, -1, t + 1];
      } else if (pending && g.game_coop_next() > picked) [cmd, opened] = [OPEN, t];
      for (const seat of [0, 1]) writeRecord(g.game_coop_input_for(seat), inputs[seat], seat ? 0 : cmd);
      if (g.game_coop_produce(0) !== t) throw Error(`no record for ${t}`);
      if (!arrive) continue;
      writeRecord(g.game_coop_input_for(1), inputs[1], 0);
      if (g.game_coop_deliver(1, t, -1) !== 1) throw Error(`player two's stand-in for ${t}`);
      arrivals.push({ t, at: arrive(t), input: inputs[1] });
    }
  }
  const coopTicks = [], restores = [], rollbacks = { 8: [], 12: [] }, hashes = [];
  let view = bot(g);
  for (; view.ms < to * MINUTE; frame++) {
    produce(view);
    heal(g);
    // No forced rollback while a perk request is under way.
    const due = late(view.ms) && frame % ROLLBACK_EVERY === 0 && opened < 0;
    if (due) {
      const depth = (deep++ % 2 ? 12 : 8);
      let start = performance.now();
      if (g.game_coop_restore(g.game_coop_next() - depth) !== 1) throw Error("no rollback");
      const restored = performance.now() - start;
      restores.push(restored);
      start = performance.now();
      if (g.game_coop_advance(1, 0) !== 1) throw Error("the run stopped");
      rollbacks[depth].push(restored + performance.now() - start);
      start = performance.now();
      g.game_coop_hash();
      hashes.push(performance.now() - start);
    } else {
      const start = performance.now();
      const fresh = g.game_coop_advance(1, 0);
      const spent = performance.now() - start;
      // A frame waiting for the pick runs nothing.
      if (fresh === 1 && late(view.ms)) coopTicks.push(spent);
      else if (fresh !== 1 && opened < 0) throw Error("the run stopped");
    }
    view = bot(g);
  }
  const slot = new Int32Array(g.memory.buffer, g.game_coop_stats(), slotBytes + 1)[slotBytes];
  // The perks the run's players hold: how often each was taken, by perk id (src/crimson/perks/ids.py).
  const held = (run) => {
    const s = snapshot(run);
    return Object.fromEntries(
      Object.keys(fields)
        .filter((name) => name.startsWith("players[0].perk_counts[") && s.word(name))
        .map((name) => [/\[(\d+)\]$/.exec(name)[1], s.word(name)]),
    );
  };
  const perks = { plain: held(plain), coop: held(g) };

  // (3) Play over a network at 60 and 144 Hz.
  const sessions = {};
  for (const hz of [60, 144]) {
    const before = telemetry(), work = [], start = { next: g.game_coop_next(), confirmed: g.game_coop_confirmed() };
    let clock = 0, banked = 0, stalled = 0;
    // The partner's run reaches tick t at its time less the delay, and its record takes a one-way trip.
    const arrive = (t) => (t - start.next - DELAY) * TICK_MS + profile.ms + (2 * Math.random() - 1) * profile.jitter;
    for (; clock < session * 1000; clock += 1000 / hz) {
      for (const arrival of arrivals.filter((a) => a.at <= clock)) {
        writeRecord(g.game_coop_input_for(1), arrival.input, 0);
        if (g.game_coop_deliver(1, arrival.t, 1) !== 1) throw Error(`player two's record for ${arrival.t}`);
        arrivals.splice(arrivals.indexOf(arrival), 1);
      }
      produce(bot(g), arrive);
      heal(g);
      banked += 1000 / hz;
      const budget = Math.floor(banked / TICK_MS), at = performance.now();
      const fresh = g.game_coop_advance(budget, 0);
      work.push(performance.now() - at);
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
    sessions[hz] = {
      frames: work.length,
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
    plain_tick: summary(plainTicks),
    coop_tick: summary(coopTicks),
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
