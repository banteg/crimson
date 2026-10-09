// Watches replays in the game module (host/watch.inc), as a link to a run
// plays one: a replay asked for as the game boots plays once its startup is
// over, then every recorded fixture the module can play starts from the menus,
// plays a while at normal speed, holds still while paused and moves one tick
// on a step, then skips to its end, which must be the result it recorded, with
// the world where the verifier leaves it, though the host reads another replay
// meanwhile. Escape returns to the high scores. Watching writes nothing: once
// the game has quit, the save, the settings, the scores, the replays and the
// play time are as they were, with Watch pressed twice for a replay too.
//
//   node crimson-core/checks/game_watch.mjs <game directory> [core.wasm] [game.wasm]
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { CORE, decode, init, loadCore, names, state, step } from "./engine.mjs";
import { PRESENTATION } from "./game_compare.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const ROOT = new URL("..", CORE).pathname;
const [
  directory,
  coreWasm = new URL("build/wasm/core.wasm", CORE).pathname,
  gameWasm = new URL("build/game/game.wasm", CORE).pathname,
] = process.argv.slice(2);
if (!directory) throw Error("usage: game_watch.mjs <game directory> [core.wasm] [game.wasm]");

const run = bootGame(gameWasm, directory, 1);
const { game } = run;
const HIGHSCORES = 14;
// DirectInput scancodes: Escape, 1, [, ], period, Space, Page Down.
const [ESCAPE, ONE, SLOWER, FASTER, STEP, SPACE, PAGE_DOWN] = [0x01, 0x02, 0x1a, 0x1b, 0x34, 0x39, 0xd1];
// A frame after `dt` milliseconds, with keys tapped for it.
function frame(dt = 16, taps = []) {
  const input = run.input();
  for (const key of taps) {
    const n = input.getInt32(INPUT.event_count, true);
    input.setUint8(INPUT.events + n * 2, key);
    input.setUint8(INPUT.events + n * 2 + 1, 1);
    input.setInt32(INPUT.event_count, n + 1, true);
  }
  run.frame(dt);
  game.game_audio(735);
}
const memory = () => Buffer.from(game.memory.buffer);
// The fields a replay plays; between ticks the player holds their own key codes.
const compared = names.map((name, i) => [name, i]).filter(([name]) => !PRESENTATION.has(name) && !/^players\[\d+\]\.input\./.test(name));
const differences = (a, b) => compared.filter(([, i]) => a.readUInt32LE(i * 4) !== b.readUInt32LE(i * 4)).map(([name]) => name);

// Every file of the game folder by digest, but the replays this check gives it,
// the game's log, and the registry, where quitting adds the time played.
const watched = path.join(directory, "watched"), registry = path.join(directory, "registry.cfg");
const skipped = [watched, path.join(directory, "console.log"), registry];
function files(dir = directory) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(dir, entry.name);
    if (skipped.includes(file)) return [];
    if (entry.isDirectory()) return files(file);
    return [`${path.relative(directory, file)} ${crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex")}`];
  });
}

const fixtures = path.join(ROOT, "tests/fixtures/replays");
fs.mkdirSync(watched, { recursive: true });
// A link opened as the game boots: the startup sequence plays out first.
fs.copyFileSync(path.join(fixtures, "quest-1.1-completed.crd"), path.join(watched, "linked.crd"));
memory().write("watched/linked.crd\0", game.game_replay_path(), "latin1");
if (!game.game_replay_open() || !game.game_watch()) throw Error("a link at startup does not take");
for (let frames = 0; game.game_watch_status() < 0; ++frames) {
  if (frames > 2000) throw Error("a link at startup never plays");
  frame();
}
if (run.clock < 12000) throw Error("a link at startup cut the startup sequence short");
frame(16, [ESCAPE]);
for (let frames = 0; game.game_state() !== HIGHSCORES; ++frames) {
  if (frames > 600) throw Error("a linked replay does not return to the high scores");
  frame();
}
for (let i = 0; i < 60; ++i) frame();
const before = files().sort().join("\n");
const core = loadCore(coreWasm);
let played = 0;
for (const name of fs.readdirSync(fixtures).filter((f) => f.endsWith(".crd")).sort()) {
  fs.copyFileSync(path.join(fixtures, name), path.join(watched, name));
  memory().write(`watched/${name}\0`, game.game_replay_path(), "latin1");
  if (!game.game_replay_open()) continue; // one the Python port plays (game_replay_read.mjs)
  const recording = Buffer.from(memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size()));
  if (!game.game_watch() || (!played && !game.game_watch())) throw Error(`${name}: Watch does not start`);
  for (let frames = 0; game.game_watch_status() < 0; ++frames) {
    if (frames > 600) throw Error(`${name}: the replay never started`);
    frame();
  }
  // The host reads the next replay while this one plays.
  game.game_replay_open();
  for (let i = 0; i < 120; ++i) frame(i % 2 ? 33 : 16);
  frame(16, [SPACE]);
  const paused = Buffer.from(state(game));
  for (let i = 0; i < 30; ++i) frame();
  if (differences(paused, state(game)).length) throw Error(`${name}: the world moves while paused`);
  frame(16, [STEP]);
  if (!differences(paused, state(game)).length) throw Error(`${name}: a step moves nothing`);
  frame(16, [SPACE]);
  frame(16, [FASTER]);
  frame(16, [FASTER]);
  for (let i = 0; i < 30; ++i) frame();
  frame(16, [SLOWER]);
  frame(16, [ONE]);
  for (let frames = 0; game.game_watch_status() === 0; ++frames) {
    if (frames > 2000) throw Error(`${name}: the replay never ended`);
    frame(16, frames % 10 ? [] : [PAGE_DOWN]);
  }
  const status = game.game_watch_status();
  if (status !== 1) throw Error(`${name}: the replay ${status === 2 ? "played differently" : "stopped before its end"}`);
  // The verifier plays the same ticks to the same world.
  const { config, records } = decode(recording);
  init(core, config);
  for (const [i, tick] of records.entries()) if (!step(core, tick)) throw Error(`${name}: the verifier refuses tick ${i}`);
  const off = differences(state(core), state(game));
  if (off.length) throw Error(`${name}: at its end ${off.slice(0, 4).join(", ")} differ from the verifier`);
  frame(16, [ESCAPE]);
  for (let frames = 0; game.game_state() !== HIGHSCORES || game.game_watch_status() !== -1; ++frames) {
    if (frames > 600) throw Error(`${name}: Escape does not return to the high scores`);
    frame();
  }
  for (let i = 0; i < 60; ++i) frame();
  if (game.game_state() !== HIGHSCORES) throw Error(`${name}: the high scores close on their own`);
  ++played;
}
if (played < 2) throw Error(`only ${played} fixtures played`);
game.game_close();
try {
  frame();
} catch (error) {
  if (error.message !== "the game quit") throw error;
}
game.game_exit();
const after = files().sort().join("\n");
if (after !== before) throw Error(`watching changed the game folder:\n${before}\n---\n${after}`);
// A fresh profile that only watched has played for no time.
const played_ms = /timePlayed=(\d+)/.exec(fs.readFileSync(registry, "latin1"))?.[1];
if (played_ms !== "0") throw Error(`watching counted ${played_ms} ms as played`);
fs.rmSync(watched, { recursive: true });
console.log(JSON.stringify({ played }));
