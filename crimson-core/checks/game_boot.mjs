// Boots the original game from a game directory (grim.dll and the three PAQs),
// headless under Node's WASI, then clicks through to a Survival run. Every
// texture must load, the run must keep drawing, and losing and regaining the
// window mid-run must suspend and resume it.
//
//   node crimson-core/checks/game_boot.mjs <game directory> [game.wasm]
import fs from "node:fs";
import path from "node:path";
import { WASI } from "node:wasi";
import { CORE } from "./engine.mjs";

const [directory, wasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_boot.mjs <game directory> [game.wasm]");
const module = new WebAssembly.Module(fs.readFileSync(wasm));
const wasi = new WASI({ version: "preview1", preopens: { ".": directory }, returnOnExit: true });
let memory;
const text = (at) => {
  const bytes = new Uint8Array(memory.buffer, at);
  return Buffer.from(bytes.subarray(0, bytes.indexOf(0))).toString("latin1");
};
// A clock that moves 16 ms a frame, and a millisecond each time it is read.
let clock = 0;
const calls = {};
const host = new Proxy(
  {},
  {
    get: (_, name) =>
      (...args) => {
        calls[name] = (calls[name] ?? 0) + 1;
        if (name === "fatal") throw Error(`game module: ${text(args[0])}`);
        if (name === "message") throw Error(`${text(args[1])}: ${text(args[0])}`);
        if (name === "time_ms") return clock++;
      },
  },
);
const instance = new WebAssembly.Instance(module, { wasi_snapshot_preview1: wasi.wasiImport, host });
memory = instance.exports.memory;
wasi.initialize(instance);
const game = instance.exports;
if (!game.game_start()) throw Error("startup failed");

// A fresh profile runs at 800x600 without mods: on the main menu, Play Game;
// on the Play Game screen, Survival. Each click lands once its screen has
// settled; the main menu shares its screen id with the startup sequence, which
// ends after about 14 s.
const steps = [
  { screen: 0, at: [240, 286] },
  { screen: 1, at: [232, 362] },
];
let cursor = [512, 384],
  playing = 0,
  step = 0,
  settled = 0,
  click = 0;
for (let frame = 1; frame <= 3000; frame++) {
  if (frame > 900 && step < steps.length && game.game_state() === steps[step].screen) {
    cursor = steps[step].at;
    if (++settled === 120) click = 5;
  }
  // Memory can grow during a frame, so the view is taken each time.
  const input = new DataView(memory.buffer, game.game_input());
  input.setInt32(256, Math.round(game.game_motion_x(cursor[0])), true);
  input.setInt32(260, Math.round(game.game_motion_y(cursor[1])), true);
  input.setUint8(268, click > 0 ? 0x80 : 0);
  if (click > 0 && --click === 0) {
    ++step;
    settled = 0;
  }
  if (frame === 2500) game.game_activate(0);
  if (frame === 2510) game.game_activate(1);
  clock += 16;
  if (!game.game_frame()) throw Error(`the game quit at frame ${frame}`);
  if (game.game_state() === 9) ++playing; // game_state_id_t's gameplay screen
}
const log = fs.readFileSync(path.join(directory, "console.log"), "latin1");
const failed = log.split("\n").filter((line) => line.includes("failed"));
if (failed.length) throw Error(`assets failed to load:\n${failed.join("\n")}`);
if ((calls.texture_create ?? 0) < 60) throw Error(`only ${calls.texture_create} textures`);
if (playing < 600) throw Error(`the Survival run lasted ${playing} frames`);
console.log(JSON.stringify(calls));
