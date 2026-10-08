// The game module as a host runs the original: from a game directory under
// Node's WASI, with presentation calls counted and dropped. The clock moves by
// each frame's time and a millisecond each time it is read, since Grim's timing
// waits for it to move.
import fs from "node:fs";
import { WASI } from "node:wasi";

// HostInput's layout (game/host_input.h).
export const INPUT = { keys: 0, motion_x: 256, motion_y: 260, buttons: 268, event_count: 276, events: 280 };

export function bootGame(wasm, directory) {
  const module = new WebAssembly.Module(fs.readFileSync(wasm));
  const wasi = new WASI({ version: "preview1", preopens: { ".": directory }, returnOnExit: true });
  const calls = {};
  let clock = 0, game;
  const text = (at) => {
    const bytes = new Uint8Array(game.memory.buffer, at);
    return Buffer.from(bytes.subarray(0, bytes.indexOf(0))).toString("latin1");
  };
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
  game = instance.exports;
  wasi.initialize(instance);
  if (!game.game_start()) throw Error("startup failed");
  return {
    game,
    calls,
    get clock() {
      return clock;
    },
    // One frame of the original after `dt` milliseconds.
    frame(dt) {
      clock += dt;
      if (!game.game_frame()) throw Error("the game quit");
    },
    // The module's DirectInput state, taken afresh: memory can grow.
    input: () => new DataView(game.memory.buffer, game.game_input()),
  };
}
