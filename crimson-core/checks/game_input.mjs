// Feed the recovered game short presses through its client input ABI, then
// inspect the ticks the run actually recorded. Use a fresh game directory.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { CORE, decode, field } from "./engine.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const [directory, wasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_input.mjs <fresh game directory> [game.wasm]");
bootGame(wasm, directory, 97);
const configPath = path.join(directory, "crimson.cfg");
const config = fs.readFileSync(configPath);
// Fire binding, host press code, held byte. The modern pad bindings and their
// original joystick aliases share the same physical button.
for (const [binding, code, held] of [
  [0x100, 0x100, INPUT.buttons],       // left mouse
  [0x21, 0x21, INPUT.keys + 0x21],     // F
  [0x215, 0x124, INPUT.pad_buttons + 5], // RB
  [0x217, 0x126, INPUT.pad_buttons + 7], // RT
  [0x126, 0x126, INPUT.pad_buttons + 7], // original Joys8
]) {
  config.writeInt32LE(binding, 0x1d8); // input_config[0].fire_key
  fs.writeFileSync(configPath, config);
  const run = bootGame(wasm, directory, 97), game = run.game;
  function frame(dt, x = 700, y = 384) {
    const input = run.input();
    input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(x)), true);
    input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(y)), true);
    run.frame(dt);
  }
  function click(screen, x, y) {
    for (let wait = 0, settled = 0; settled < 60; ++wait) {
      assert.ok(wait < 600, "menu did not open");
      frame(16, x, y);
      settled = game.game_state() === screen ? settled + 1 : 0;
    }
    run.input().setUint8(INPUT.buttons, 0x80);
    for (let i = 0; i < 5; ++i) frame(16, x, y);
    run.input().setUint8(INPUT.buttons, 0);
    frame(16, x, y);
  }
  while (run.clock < 15000) frame(16);
  click(0, 240, 338); // Play Game
  click(1, 232, 414); // Survival
  for (let i = 0; i < 120; ++i) frame(16);
  assert.equal(game.game_state(), 9);
  run.input().setUint8(INPUT.pad_connected, held >= INPUT.pad_buttons ? 1 : 0);
  function press() {
    run.input().setUint8(INPUT.presses + (code >> 3), 1 << (code & 7));
  }
  const records = () => decode(Buffer.from(game.memory.buffer, game.game_replay(), game.game_replay_size())).records;
  let recorded = records().length;
  function ticks(dt) {
    frame(dt);
    const all = records(), added = all.slice(recorded);
    recorded = all.length;
    return added.map((r) => r.readUInt32LE(16) & 3);
  }
  // A complete tap during a stall, even while the menu can still see its click.
  press();
  run.input().setUint8(INPUT.mouse_clicks, binding === 0x100 ? 1 : 0);
  const stalled = ticks(83);
  assert.ok(stalled.length >= 4);
  assert.deepEqual(stalled, [3, ...stalled.slice(1).fill(0)]);
  assert.ok(ticks(33).every((f) => f === 0));
  run.input().setUint8(INPUT.mouse_clicks, 0);
  game.portable_snapshot();
  assert.equal(field(game, "globals.highscore_record_shots_fired"), 1);

  // Down and up on separate fast frames before a tick. The press survives both.
  for (let i = 0; i < 60; ++i) ticks(2); // settle at the new display cadence
  for (let i = 0; !ticks(2).length; ++i) assert.ok(i < 12);
  press();
  run.input().setUint8(held, 0x80);
  assert.deepEqual(ticks(2), []);
  run.input().setUint8(held, 0);
  const released = ticks(50);
  assert.deepEqual(released, [3, ...released.slice(1).fill(0)]);

  // A press still held when sampled starts once, then stays down on later ticks.
  press();
  run.input().setUint8(held, 0x80);
  const first = ticks(60);
  assert.ok(first.length >= 3);
  assert.deepEqual(first, [...first.slice(1).fill(0), 3]);
  assert.ok(ticks(60).every((f) => f === 1));
  run.input().setUint8(held, 0);
  assert.ok(ticks(33).every((f) => f === 0));

  press();
  game.game_activate(0);
  game.game_activate(1);
  assert.ok(ticks(50).every((f) => f === 0), "a tap from before focus loss escaped");
}
console.log("game input: short taps and held fire passed");
