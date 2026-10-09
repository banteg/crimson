// The game module as a host runs the original: from a game directory under
// Node's WASI, with presentation calls counted and dropped. The clock moves by
// each frame's time and a millisecond each time it is read, since Grim's timing
// waits for it to move. A given seed answers the module's entropy requests, which
// seed its runs (host/session.inc).
import fs from "node:fs";
import { WASI } from "node:wasi";

// HostInput's layout (game/host_input.h).
export const INPUT = { keys: 0, motion_x: 256, motion_y: 260, buttons: 268, event_count: 276, events: 280 };

// `leaderboard` enables the leaderboard, and `requests` collects its host
// requests (HOST_LEADERBOARD_*) for the check to answer between frames.
export function bootGame(wasm, directory, seed, { leaderboard = false, requests } = {}) {
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
          if (name === "leaderboard") requests?.push(args[0]);
        },
    },
  );
  // On the import object itself: a copy would leave the WASI object unreferenced, and Node 20 collects it mid-run.
  if (seed !== undefined)
    wasi.wasiImport.random_get = (at, length) => {
      const bytes = new Uint8Array(game.memory.buffer, at, length);
      for (let i = 0; i < length; i++) bytes[i] = seed >>> (8 * (i % 4));
      return 0;
    };
  const instance = new WebAssembly.Instance(module, { wasi_snapshot_preview1: wasi.wasiImport, host });
  game = instance.exports;
  wasi.initialize(instance);
  // As the browser host does: its replays name the browser, and ranked runs go to leaderboard/outbox/.
  game.game_platform(1);
  if (leaderboard) game.game_leaderboard_enable();
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
