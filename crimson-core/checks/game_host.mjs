// The game module as a host runs the original: from a game directory under
// Node's WASI, with presentation calls counted and dropped. The clock moves by
// each frame's time and a millisecond each time it is read, since Grim's timing
// waits for it to move. A given seed answers the module's entropy requests, which
// seed its runs (host/session.inc); `clocks` sets the system clocks by that clock
// too (from 2026-01-01), which seed the original's own randomness, so a run the
// original plays comes out the same each time.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { WASI } from "node:wasi";

// HostInput's layout (game/host_input.h).
export const INPUT = {
  keys: 0,
  motion_x: 256,
  motion_y: 260,
  buttons: 268,
  event_count: 276,
  events: 280,
  pad_axes: 344,
  pad_hat: 360,
  pad_buttons: 364,
  pad_connected: 396,
};

// `leaderboard` enables the leaderboard, and `requests` collects its host
// requests (HOST_LEADERBOARD_*) for the check to answer between frames.
export function bootGame(wasm, directory, seed, { leaderboard = false, requests, onHost, clocks = false } = {}) {
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
          onHost?.(name, args);
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
  if (clocks)
    wasi.wasiImport.clock_time_get = (id, precision, at) => {
      const ms = BigInt(Math.round(clock)) + (id === 0 ? BigInt(Date.UTC(2026, 0, 1)) : 0n);
      new DataView(game.memory.buffer).setBigUint64(at, ms * 1000000n, true);
      return 0;
    };
  const instance = new WebAssembly.Instance(module, { wasi_snapshot_preview1: wasi.wasiImport, host });
  game = instance.exports;
  wasi.initialize(instance);
  // As the browser host does: its replays name the browser, and ranked runs go to leaderboard/outbox/.
  game.game_platform(1);
  if (leaderboard) game.game_leaderboard_enable(1);
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

// Seven in-game tunes for the original to load, in a copy of the game in `directory` (music\game_tunes.txt in the
// folder takes the pack's place: the release's five, the first two again), which goes when the check exits; the
// copy's path. The original's crimsonquest is then the verifier's in-game tune request (host/game.inc
// GameShellMusic).
export function sevenTunes(directory) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), "crimson-tunes-"));
  process.on("exit", () => fs.rmSync(copy, { recursive: true, force: true }));
  fs.cpSync(directory, copy, { recursive: true });
  const tunes = ["gt1_ingame", "gt2_harppen", "crimson_addon01", "crimson_addon02", "crimson_addon03"];
  fs.mkdirSync(`${copy}/music`, { recursive: true });
  const lines = [...tunes, ...tunes.slice(0, 2)].map((tune) => `snd_addGameTune ${tune}.ogg\n`);
  fs.writeFileSync(`${copy}/music/game_tunes.txt`, lines.join(""));
  return copy;
}
