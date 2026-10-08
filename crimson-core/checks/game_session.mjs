// Plays a run the way the client does: the original boots from a game
// directory (grim.dll, crimson.paq, sfx.paq and music/), its menus start a
// Survival run, and the run plays as a session (host/session.inc). A scripted
// player aims at the nearest creature and fires in bursts, opens the perk menu
// with Space and picks from it (and asks again at once), pauses with Escape and
// resumes, and taps the console key, which a run ignores, at frame times that
// run several ticks a frame or none. After every frame of play the
// verifier replays the run's own recording to the same tick and must agree on
// every snapshot field; when the run ends the verifier must end it at the same
// tick, and the replay the game saved must be the one it recorded.
//
//   node crimson-core/checks/game_session.mjs <game directory> [core.wasm] [game.wasm]
import fs from "node:fs";
import path from "node:path";
import { WASI } from "node:wasi";
import { CONFIG_BYTES, CORE, decode, field, init, loadCore, names, record, state, step } from "./engine.mjs";
import { PRESENTATION } from "./game_compare.mjs";

const [
  directory,
  coreWasm = new URL("build/wasm/core.wasm", CORE).pathname,
  gameWasm = new URL("build/game/game.wasm", CORE).pathname,
] = process.argv.slice(2);
if (!directory) throw Error("usage: game_session.mjs <game directory> [core.wasm] [game.wasm]");

const module = new WebAssembly.Module(fs.readFileSync(gameWasm));
const wasi = new WASI({ version: "preview1", preopens: { ".": directory }, returnOnExit: true });
let memory;
const text = (at) => {
  const bytes = new Uint8Array(memory.buffer, at);
  return Buffer.from(bytes.subarray(0, bytes.indexOf(0))).toString("latin1");
};
// The clock moves by each frame's time, and a millisecond each time it is read.
let clock = 0;
const host = new Proxy(
  {},
  {
    get: (_, name) =>
      (...args) => {
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

// game_state_id_t
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, PAUSE_MENU = 5, PERK_SELECTION = 6, GAMEPLAY = 9;
// DirectInput scancodes.
const [ESCAPE, W, A, S, D, CONSOLE, SPACE] = [0x01, 0x11, 0x1e, 0x1f, 0x20, 0x29, 0x39];
// Where a fresh 1024x768 profile lays out the perk menu's first choice (the
// rest follow 19 pixels apart) and the pause menu's Resume.
const PERK_CHOICE = [150, 216], RESUME = [232, 397];

// The module's DirectInput state (game/dinput.cpp), taken afresh each frame
// because memory can grow. A tapped key is held for the frame and delivered as
// a press, then released.
let held = new Set();
function frame(dt, { cursor, buttons = 0, keys = [], taps = [] }) {
  const input = new DataView(memory.buffer, game.game_input());
  const events = [...taps.map((k) => [k, 1]), ...[...held].filter((k) => !taps.includes(k)).map((k) => [k, 0])];
  for (const [key, down] of events) {
    const n = input.getInt32(276, true);
    input.setUint8(280 + n * 2, key);
    input.setUint8(281 + n * 2, down);
    input.setInt32(276, n + 1, true);
  }
  held = new Set(taps);
  for (const key of [W, A, S, D, ESCAPE, CONSOLE, SPACE]) input.setUint8(key, keys.includes(key) || held.has(key) ? 0x80 : 0);
  input.setInt32(256, Math.round(game.game_motion_x(cursor[0])), true);
  input.setInt32(260, Math.round(game.game_motion_y(cursor[1])), true);
  input.setUint8(268, buttons & 1 ? 0x80 : 0);
  clock += dt;
  if (!game.game_frame()) throw Error("the game quit");
}

// Holds the cursor on a spot until the screen settles, then clicks it. A menu
// opened while fire was held can close on its own: a button takes the release.
function click(screen, at) {
  for (let settled = 0, frames = 0; settled < 60; ++frames) {
    if (frames > 3000) throw Error(`screen ${screen} never settled`);
    frame(16, { cursor: at });
    if (settled && game.game_state() !== screen) return;
    settled = game.game_state() === screen ? settled + 1 : 0;
  }
  for (let i = 0; i < 5; ++i) frame(16, { cursor: at, buttons: 1 });
  frame(16, { cursor: at });
}

// On a fresh profile the main menu shares its screen id with the startup
// sequence, which ends after about 14 s.
while (clock < 15000) frame(16, { cursor: [512, 384] });
click(MAIN_MENU, [240, 338]);
click(PLAY_GAME_MENU, [232, 414]);

const replay = () => Buffer.from(memory.buffer, game.game_replay(), game.game_replay_size());
const core = loadCore(coreWasm);
const CREATURES = names.filter((n) => /^creatures\[\d+\]\.active$/.test(n)).length;
// The nearest live creature's screen position and the way away from it.
function target() {
  const f = (n) => field(core, n, true);
  const px = f("players[0].pos_x"), py = f("players[0].pos_y");
  let best = Infinity, aim = [512, 384], away = [0, 1];
  for (let i = 0; i < CREATURES; i++) {
    if (!field(core, `creatures[${i}].active`) || f(`creatures[${i}].health`) <= 0) continue;
    const x = f(`creatures[${i}].pos_x`), y = f(`creatures[${i}].pos_y`);
    const d = (x - px) ** 2 + (y - py) ** 2;
    if (d < best) {
      best = d;
      aim = [x + f("globals.camera_offset_x"), y + f("globals.camera_offset_y")];
      away = [px - x, py - y];
    }
  }
  return { aim, away };
}

// Frame times from 4 ms (most frames run no tick) to 50 ms (three ticks).
const times = [16, 7, 33, 16, 50, 4, 16, 12, 21];
let started = false, ticks = 0, frames = 0, idle = 0, choice = 0, pauses = 0, picked = false;
while (true) {
  const screen = game.game_state();
  if (screen === PERK_SELECTION) {
    click(PERK_SELECTION, [PERK_CHOICE[0], PERK_CHOICE[1] + 19 * (choice++ % 5)]);
    picked = true;
    continue;
  }
  if (screen === PAUSE_MENU) {
    click(PAUSE_MENU, RESUME);
    continue;
  }
  const taps = [];
  let cursor = [512, 384], keys = [];
  if (started) {
    const { aim, away } = target();
    cursor = aim;
    keys = [Math.abs(away[0]) > Math.abs(away[1]) ? (away[0] < 0 ? A : D) : away[1] < 0 ? W : S];
    // Another request right after a pick, which the pick may have used up.
    if (picked || (field(core, "globals.perk_pending_count") > 0 && frames % 30 === 0)) taps.push(SPACE);
    picked = false;
    if (frames % 997 === 500) taps.push(CONSOLE);
    if (ticks > 1200 * (pauses + 1) && pauses < 2) {
      taps.push(ESCAPE);
      ++pauses;
    }
  }
  // Fire in bursts, so presses and releases both fall between ticks.
  const buttons = Math.floor(clock / 333) % 4 === 3 ? 0 : 1;
  frame(times[frames++ % times.length], { cursor, buttons, keys, taps });

  const recorded = replay();
  if (!started) {
    if (recorded.length < CONFIG_BYTES) {
      if (frames > 600) throw Error("the Survival run did not play as a session");
      continue;
    }
    init(core, recorded.subarray(0, CONFIG_BYTES));
    started = true;
  }
  const run = decode(recorded);
  idle = run.records.length === ticks && game.game_state() === GAMEPLAY ? idle + 1 : 0;
  for (const tick of run.records.slice(ticks)) {
    if (!step(core, tick)) throw Error(`the verifier refused tick ${ticks}`);
    ++ticks;
  }
  if (![GAMEPLAY, PERK_SELECTION, PAUSE_MENU].includes(game.game_state())) break;
  if (game.game_state() !== GAMEPLAY) continue;
  const expected = state(core), actual = state(game);
  for (let i = 0; i < names.length; i++) {
    if (PRESENTATION.has(names[i])) continue;
    const a = expected.readUInt32LE(i * 4), b = actual.readUInt32LE(i * 4);
    if (a !== b) throw Error(`tick ${ticks}: ${names[i]} is ${b}, the verifier says ${a}`);
  }
  if (idle > 120) throw Error(`the run stopped ticking at tick ${ticks}`);
  if (frames > 60000) throw Error("the run never ended");
}
// The run ended where the verifier ends it: one more tick is refused.
if (step(core, record([0, 0, 0, 0, 0]))) throw Error(`the run ended at tick ${ticks}, but the verifier plays on`);
// Commands by type: 1 picks a perk, 2 opens the perk menu.
const commands = [0, 0, 0];
for (const r of decode(replay()).records)
  for (let i = 0; i < r.readUInt32LE(20); i++) ++commands[r.readInt32LE(24 + i * 8)];
if (!commands[1] || pauses < 2) throw Error(`the run picked ${commands[1]} perks and paused ${pauses} times`);
const saved = fs.readdirSync(path.join(directory, "replays")).map((f) => path.join(directory, "replays", f));
if (!saved.some((f) => fs.readFileSync(f).equals(replay()))) throw Error("the saved replay differs from the recording");
console.log(JSON.stringify({ ticks, frames, picks: commands[1], pauses }));
