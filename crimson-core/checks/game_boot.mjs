// Boots the original game from a game directory (crimson.paq, sfx.paq
// and music/), headless under Node's WASI, then clicks through to a Survival
// run. No asset may fail to load, the menus' music must reach the mix, the run
// must play as a session and keep drawing, and losing the window must stop the
// run until it returns.
//
//   node crimson-core/checks/game_boot.mjs <game directory> [game.wasm]
import fs from "node:fs";
import path from "node:path";
import { CORE } from "./engine.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const [directory, wasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_boot.mjs <game directory> [game.wasm]");
const run = bootGame(wasm, directory);
const { game } = run;

// A fresh profile runs at 1024x768 without mods: on the main menu, Play Game;
// on the Play Game screen, Survival. Each click lands once its screen has
// settled; the main menu shares its screen id with the startup sequence, which
// ends after about 14 s.
const steps = [
  { screen: 0, at: [240, 338] },
  { screen: 1, at: [232, 414] },
];
const GAMEPLAY = 9;
let cursor = [512, 384],
  playing = 0,
  step = 0,
  settled = 0,
  click = 0,
  audible = 0,
  away = 0;
for (let frame = 1; frame <= 3000; frame++) {
  if (frame > 900 && step < steps.length && game.game_state() === steps[step].screen) {
    cursor = steps[step].at;
    if (++settled === 120) click = 5;
  }
  const input = run.input();
  input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(cursor[0])), true);
  input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(cursor[1])), true);
  input.setUint8(INPUT.buttons, click > 0 ? 0x80 : 0);
  if (click > 0 && --click === 0) {
    ++step;
    settled = 0;
  }
  // Ten frames away from the window: the run records no tick.
  if (frame === 2500) {
    game.game_activate(0);
    away = game.game_replay_size();
  }
  if (frame === 2510) {
    if (game.game_replay_size() !== away) throw Error("the run played on while the window was away");
    game.game_activate(1);
  }
  const draws = run.calls.draw ?? 0;
  run.frame(16);
  // A 60 Hz frame of the mix: 735 stereo frames at 44.1 kHz.
  const mix = new Int16Array(game.memory.buffer, game.game_audio(735), 735 * 2);
  if (mix.some((v) => v !== 0)) ++audible;
  if (game.game_state() === GAMEPLAY && run.calls.draw > draws) ++playing;
}
const log = fs.readFileSync(path.join(directory, "console.log"), "latin1");
const failed = log.split("\n").filter((line) => line.includes("failed"));
if (failed.length) throw Error(`assets failed to load:\n${failed.join("\n")}`);
if (playing < 600) throw Error(`the Survival run drew ${playing} frames`);
// The client plays the run as a session, which records it (host/session.inc).
if (game.game_replay_size() <= away) throw Error("the run did not play on as a session when the window returned");
// The run itself is quiet: its music starts at the first hit, and nothing fires.
if (audible < 1000) throw Error(`only ${audible} frames made sound`);
console.log(JSON.stringify({ ...run.calls, audible }));
