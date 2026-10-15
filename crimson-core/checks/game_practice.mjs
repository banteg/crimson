// Branch proof: an initialized core plus the recorded prefix and alternate
// inputs must agree with the game's restored anchor plus those same inputs.
// Also exercise the click latch, pause/focus, retry, original, and persistence.
// node crimson-core/checks/game_practice.mjs <game directory> [core.wasm] [game.wasm]
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { CORE, decode, field, init, loadCore, names, state, step } from "./engine.mjs";
import { PRESENTATION } from "./game_compare.mjs";
import { bootGame, INPUT } from "./game_host.mjs";
const ROOT = new URL("..", CORE).pathname;
const [directory, coreWasm = new URL("build/wasm/core.wasm", CORE).pathname, gameWasm = new URL("build/game/game.wasm", CORE).pathname] =
  process.argv.slice(2);
if (!directory) throw Error("usage: game_practice.mjs <game directory> [core.wasm] [game.wasm]");
const requests = [];
let run = bootGame(gameWasm, directory, 1, { leaderboard: true, requests });
let { game } = run;
const core = loadCore(coreWasm);
const fields = names.map((n, i) => [n, i]).filter(([n]) => !PRESENTATION.has(n) && !/^players\[\d+\]\.input\./.test(n));
function equal(a, b, label) {
  const off = fields.filter(([, i]) => a.readUInt32LE(i * 4) !== b.readUInt32LE(i * 4)).map(([n]) => n);
  assert.deepEqual(off, [], label);
}
function frame(dt = 1) {
  run.frame(dt);
  game.game_audio(735);
}
function key(code, down) {
  const input = run.input(),
    n = input.getInt32(INPUT.event_count, true);
  input.setUint8(code, down ? 128 : 0);
  input.setUint8(INPUT.events + n * 2, code);
  input.setUint8(INPUT.events + n * 2 + 1, down ? 1 : 0);
  input.setInt32(INPUT.event_count, n + 1, true);
}
function clear() {
  for (let i = 0; i < 256; ++i) run.input().setUint8(i, 0);
  for (let i = 0; i < 8; ++i) run.input().setUint8(INPUT.buttons + i, 0);
}
function files(dir = directory) {
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => {
      const f = path.join(dir, e.name);
      if (["watched", "console.log", "registry.cfg"].includes(path.relative(directory, f))) return [];
      if (e.isDirectory()) return files(f);
      return [path.relative(directory, f) + " " + crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex")];
    })
    .sort()
    .join("\n");
}
while (run.clock < 15000) frame(16);
fs.mkdirSync(path.join(directory, "watched"), { recursive: true });
const before = files(),
  requestCount = requests.length;
let anchors = 0,
  compared = 0;
for (const name of ["survival-238852.crd", "rush-kills103.crd", "quest-1.1-completed.crd"]) {
  clear();
  fs.copyFileSync(path.join(ROOT, "tests/fixtures/replays", name), path.join(directory, "watched/practice.crd"));
  Buffer.from(game.memory.buffer).write("watched/practice.crd\0", game.game_replay_path(), "latin1");
  assert.ok(game.game_replay_open());
  assert.ok(game.game_watch());
  for (let i = 0; game.game_watch_status() < 0 || !game.game_watch_ticks(); ++i) {
    assert.ok(i < 2000);
    frame(16);
  }
  const recording = Buffer.from(new Uint8Array(game.memory.buffer, game.game_replay_recording(), game.game_replay_recording_size()));
  const { config, records } = decode(recording);
  const perkAt = records.findIndex((r) => r.readUInt32LE(20) > 0 && r.readInt32LE(24) === 2);
  if (name.startsWith("survival")) assert.ok(perkAt > 0, "fixture must offer a pending perk");
  for (const target of name.startsWith("survival") ? [1, 119, 120, 121, 10800, 21000, perkAt] : [1, 119, 121, 480]) {
    clear();
    game.game_watch_stop_at(target);
    game.game_watch_seek(target);
    assert.equal(game.game_practice_take(), 0, "seeking cannot be taken over");
    frame();
    init(core, config);
    for (let t = 0; t < target; ++t) assert.ok(step(core, records[t]));
    const anchor = Buffer.from(state(core));
    equal(anchor, state(game), `${name}:${target} prefix`);
    // Enter and the bar's click take over with the button held: play starts at
    // once, but that click fires only once let go.
    const generationBeforeTake = game.game_play_run();
    const latched = target === 119 || target === 120;
    if (target === 119) {
      run.input().setUint8(INPUT.buttons, 128);
      key(0x1c, true);
      frame();
    } else if (target === 120) {
      run.input().setUint8(INPUT.buttons, 128);
      key(57, true); // play and take over in the same frame, before its ticks
      run.input().setInt32(INPUT.motion_x, game.game_motion_x(900), true);
      run.input().setInt32(INPUT.motion_y, game.game_motion_y(740), true);
      frame();
    } else assert.ok(game.game_practice_take(), `${name}:${target} takeover`);
    assert.equal(game.game_practice_state(), 1, "takeover plays at once");
    assert.equal(game.game_play_mode(), 6, "practice is live play, separately from ranked modes");
    assert.equal(game.game_play_run(), generationBeforeTake + 1, "takeover is a new attempt");
    assert.equal(game.game_practice_ticks(), 0, "takeover starts from the anchor");
    equal(anchor, state(game), "takeover frame shows the anchor");
    function alternate() {
      clear(); // the button stays down: a latch set at the start holds
      run.input().setInt32(INPUT.motion_x, game.game_motion_x(800), true);
      run.input().setInt32(INPUT.motion_y, game.game_motion_y(300), true);
      key(0xc8, true);
      run.input().setUint8(INPUT.buttons, 128);
      const sequence = [];
      for (let i = 0; game.game_practice_ticks() < 64; ++i) {
        assert.ok(i < 5000, "practice did not tick");
        const was = game.game_practice_ticks();
        frame();
        const now = game.game_practice_ticks();
        assert.ok(now - was <= 1, "test frame contains at most one tick");
        if (now === was) continue;
        const record = Buffer.alloc(24);
        Buffer.from(game.memory.buffer).copy(record, 0, game.portable_input(), game.portable_input() + 20);
        const fires = !!(record.readUInt32LE(16) & 1);
        if (now <= 8) assert.equal(fires, !latched, "a held takeover click does not fire");
        else if (now === 9) assert.ok(!fires, "a released button does not fire");
        else assert.ok(fires, "a fresh press fires");
        // Let go for the ninth tick, then press again.
        run.input().setUint8(INPUT.buttons, now === 8 ? 0 : 128);
        sequence.push(record);
        assert.ok(step(core, record));
        equal(state(core), state(game), `${name}:${target}+${now}`);
        ++compared;
      }
      return sequence;
    }
    if (target === perkAt) {
      assert.ok(field(core, "globals.perk_pending_count") > 0, "anchor has a pending perk");
      key(57, true);
      while (game.game_practice_ticks() === 0) frame();
      assert.equal(game.game_state(), 6, "perk action opens the real menu");
      const open = Buffer.alloc(32);
      Buffer.from(game.memory.buffer).copy(open, 0, game.portable_input(), game.portable_input() + 20);
      open.writeUInt32LE(1, 20);
      open.writeInt32LE(2, 24);
      assert.ok(step(core, open));
      equal(state(core), state(game), "perk opening follows the baseline");
      const opened = game.game_practice_ticks();
      clear();
      for (let i = 0; i < 80; ++i) {
        run.input().setInt32(INPUT.motion_x, game.game_motion_x(150), true);
        run.input().setInt32(INPUT.motion_y, game.game_motion_y(216), true);
        frame(16);
      }
      run.input().setUint8(INPUT.buttons, 128);
      frame(16);
      clear();
      for (let i = 0; game.game_state() !== 9; ++i) {
        assert.ok(i < 300, "perk menu never closed");
        frame(16);
      }
      assert.equal(game.game_practice_state(), 1, "perk choice returns straight to play");
      while (game.game_practice_ticks() === opened) frame(16);
      assert.equal(game.game_practice_ticks(), opened + 1);
      const pick = Buffer.alloc(32);
      Buffer.from(game.memory.buffer).copy(pick, 0, game.portable_input(), game.portable_input() + 20);
      pick.writeUInt32LE(1, 20);
      pick.writeInt32LE(1, 24);
      assert.ok(step(core, pick));
      equal(state(core), state(game), "perk choice reaches the next tick");
      clear();
      run.input().setUint8(INPUT.buttons, latched ? 128 : 0);
      game.game_practice_action(2);
      frame();
      init(core, config);
      for (let t = 0; t < target; ++t) step(core, records[t]);
    }
    const sequence = alternate(),
      future = Buffer.from(state(game));
    const pauseGeneration = game.game_play_run();
    game.game_activate(0);
    assert.equal(game.game_practice_state(), 2, "focus loss pauses");
    assert.equal(game.game_play_mode(), 0, "paused practice reports no play");
    game.game_activate(1);
    for (let i = 0; i < 8; ++i) frame();
    equal(future, state(game), "paused branch stays still");
    clear();
    key(1, true);
    frame();
    assert.equal(game.game_practice_state(), 1, "Escape resumes");
    assert.equal(game.game_play_run(), pauseGeneration, "resuming does not start another attempt");
    key(1, false);
    frame();
    key(1, true);
    frame();
    assert.equal(game.game_practice_state(), 2, "Escape pauses");
    key(1, false);
    run.input().setUint8(INPUT.buttons, latched ? 128 : 0); // the Retry click
    game.game_practice_action(2);
    frame();
    assert.equal(game.game_practice_state(), 1, "retry plays at once");
    assert.equal(game.game_play_run(), pauseGeneration + 1, "retry is another attempt");
    assert.equal(game.game_practice_ticks(), 0);
    equal(anchor, state(game), "retry restores the exact anchor");
    // Reapply the same live input and compare every new state with a fresh prefix.
    init(core, config);
    for (let t = 0; t < target; ++t) step(core, records[t]);
    const again = alternate();
    assert.deepEqual(again, sequence, "retry starts with the same inputs");
    equal(future, state(game), "retry reproduces the alternate future");
    game.game_practice_action(3);
    frame();
    assert.equal(game.game_practice_state(), 0);
    assert.equal(game.game_play_mode(), 0, "returning to the original replay stops live play");
    assert.equal(game.game_watch_tick(), target);
    equal(anchor, state(game), "original returns to the anchor");
    // Escape pauses a fresh takeover; Watch the original returns, still watching.
    clear();
    assert.ok(game.game_practice_take());
    key(1, true);
    frame();
    assert.equal(game.game_practice_state(), 2);
    key(1, false);
    game.game_practice_action(3);
    frame();
    assert.equal(game.game_watch_status(), 0);
    assert.equal(game.game_practice_state(), 0);
    clear();
    for (let i = 0; i < 8; ++i) frame();
    assert.equal(game.game_watch_tick(), target, "original returns paused");
    ++anchors;
  }
  if (!name.startsWith("rush")) {
    const endAt = name.startsWith("survival") ? 21000 : game.game_watch_ticks() - 240;
    clear();
    game.game_watch_stop_at(endAt);
    game.game_watch_seek(endAt);
    frame();
    assert.ok(game.game_practice_take(), "take over near the end");
    init(core, config);
    for (let t = 0; t < endAt; ++t) step(core, records[t]);
    clear();
    frame();
    key(0xc8, true);
    for (let i = 0; game.game_practice_state() !== 3; ++i) {
      assert.ok(i < 50000, "branch never ended");
      const was = game.game_practice_ticks();
      frame();
      const now = game.game_practice_ticks();
      if (now !== was || game.game_practice_state() === 3) {
        const record = Buffer.alloc(24);
        Buffer.from(game.memory.buffer).copy(record, 0, game.portable_input(), game.portable_input() + 20);
        assert.equal(!!step(core, record), game.game_practice_state() !== 3, "baseline ends on the same tick");
        if (now !== was) equal(state(core), state(game), "alternate ending follows the baseline");
      }
      clear();
    }
    assert.equal(field(core, "players[0].health", true) > 0, name.startsWith("quest"), "branch outcome matches death/completion");
    assert.equal(game.game_state(), 9, "practice end remains on the detached gameplay screen");
    assert.equal(game.game_replay_size(), 0, "death/completion cannot record");
    game.game_practice_action(2);
    frame();
    assert.equal(game.game_practice_state(), 1, "retry after end");
    assert.equal(game.game_practice_ticks(), 0);
    game.game_practice_action(3);
    frame();
    assert.equal(game.game_watch_tick(), endAt, "return after end");
  }
  clear();
  game.game_watch_seek(game.game_watch_ticks());
  frame();
  assert.equal(game.game_practice_take(), 0, "finished replay cannot be taken over");
  key(1, true);
  frame();
  key(1, false);
  for (let i = 0; i < 20; ++i) frame(16);
}
assert.equal(requests.length, requestCount, "practice never requests an upload");
assert.equal(game.game_replay_size(), 0, "practice never publishes a live recording");
game.game_close();
try {
  frame();
} catch (e) {
  assert.equal(e.message, "the game quit");
}
game.game_exit();
assert.equal(files(), before, "practice changed saved progress, scores, recordings or outbox");
assert.equal(/timePlayed=(\d+)/.exec(fs.readFileSync(path.join(directory, "registry.cfg"), "latin1"))?.[1], "0");
// Quitting is another exit path: test it during play and with the real perk menu open.
for (const phase of ["playing", "perk"]) {
  run = bootGame(gameWasm, directory, 1, { leaderboard: true, requests });
  game = run.game;
  while (run.clock < 15000) frame(16);
  const requested = requests.length;
  fs.copyFileSync(path.join(ROOT, "tests/fixtures/replays/survival-238852.crd"), path.join(directory, "watched/practice.crd"));
  Buffer.from(game.memory.buffer).write("watched/practice.crd\0", game.game_replay_path(), "latin1");
  assert.ok(game.game_replay_open());
  assert.ok(game.game_watch());
  for (let i = 0; !game.game_watch_ticks(); ++i) {
    assert.ok(i < 2000);
    frame(16);
  }
  const { records } = decode(
    Buffer.from(new Uint8Array(game.memory.buffer, game.game_replay_recording(), game.game_replay_recording_size())),
  );
  const target = phase === "playing" ? 119 : records.findIndex((r) => r.readUInt32LE(20) > 0 && r.readInt32LE(24) === 2);
  game.game_watch_stop_at(target);
  game.game_watch_seek(target);
  frame();
  assert.ok(game.game_practice_take());
  clear();
  frame();
  key(phase === "playing" ? 0xc8 : 57, true);
  while (!game.game_practice_ticks()) frame();
  assert.equal(game.game_state(), phase === "playing" ? 9 : 6, "quit in the intended practice screen");
  game.game_close();
  assert.throws(() => frame(), /the game quit/);
  game.game_exit();
  assert.equal(files(), before, `quit during ${phase} changed persisted state`);
  assert.equal(requests.length, requested, "quit cannot request an upload");
  assert.equal(/timePlayed=(\d+)/.exec(fs.readFileSync(path.join(directory, "registry.cfg"), "latin1"))?.[1], "0");
}
console.log(
  JSON.stringify({
    anchors,
    alternate_ticks: compared,
    retry: true,
    original: true,
    isolated: true,
  }),
);
