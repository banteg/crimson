// Sweep the mouse across 240 display frames in one second of Survival. Run the
// same inputs twice and observe what the game actually sends to the renderer.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bootGame, INPUT } from "./game_host.mjs";

const [assets, wasm = new URL("../build/game/game.wasm", import.meta.url).pathname] = process.argv.slice(2);
if (!assets) throw Error("usage: game_display_aim.mjs <game directory> [game.wasm]");

function sweep(enabled) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "crimson-display-aim-"));
  try {
    for (const name of ["crimson.paq", "sfx.paq", "music.paq"])
      fs.copyFileSync(path.join(assets, name), path.join(directory, name));
    let game, center;
    const run = bootGame(wasm, directory, 123, {
      onHost(name, args) {
        if (enabled && name === "mouse_aim" && args[2]) center = args.slice(0, 2);
        if (!enabled && name === "circle" && game) {
          // The original spread disc, at its screen-space center.
          const shape = new Float32Array(game.memory.buffer, args[0], 4);
          if (shape[2] === 0) center = [shape[0], shape[1]];
        }
      },
    });
    game = run.game;
    game.game_display_aim(enabled);
    function frame(dt, x, y, down = false) {
      const input = run.input();
      input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(x)), true);
      input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(y)), true);
      input.setUint8(INPUT.buttons, down ? 0x80 : 0);
      game.game_mouse_move(x, y);
      run.frame(dt);
    }
    function click(x, y) {
      for (let i = 0; i < 145; i++) frame(16, x, y, i >= 60 && i < 65);
    }
    while (run.clock < 15000) frame(16, 512, 384);
    click(240, 338); // Play Game
    click(232, 414); // Survival on a fresh profile
    assert.equal(game.game_state(), 9);
    const start = run.clock, before = run.calls.present, initial = center.join(","), centers = new Set();
    for (let i = 1; i <= 240; i++) {
      frame(start + Math.floor(i * 1000 / 240) - run.clock, 300 + i * 2, 410);
      centers.add(center.join(","));
    }
    centers.delete(initial); // A held first refresh can still show the pre-sweep position.
    assert.equal(run.calls.present - before, 60, "world frames");
    assert.equal(centers.size, enabled ? 240 : 60, "distinct displayed reticle positions");
    return Buffer.from(new Uint8Array(game.memory.buffer, game.game_replay(), game.game_replay_size()));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}
assert.deepEqual(sweep(false), sweep(true), "display aim changed the recording");
console.log("240 Hz mouse sweep: 60 to 240 reticle positions, 60 world frames, identical recordings");
