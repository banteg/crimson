// Seeking a replay (host/watch.inc, host/keyframes.inc): once a fixture is
// prepared, seeks to ticks across the run, backwards and forwards in a shuffled
// order, must each land on the tick asked for with the world where the
// verifier's straight replay leaves it. It reports how long the preparing pass
// and the seeks take.
//
//   node crimson-core/checks/game_seek.mjs <game directory> [fixture.crd] [core.wasm] [game.wasm]
import fs from "node:fs";
import path from "node:path";
import { CORE, decode, init, loadCore, names, state, step } from "./engine.mjs";
import { PRESENTATION } from "./game_compare.mjs";
import { bootGame } from "./game_host.mjs";

const ROOT = new URL("..", CORE).pathname;
const [
  directory,
  fixture = path.join(ROOT, "tests/fixtures/replays/survival-238852.crd"),
  coreWasm = new URL("build/wasm/core.wasm", CORE).pathname,
  gameWasm = new URL("build/game/game.wasm", CORE).pathname,
] = process.argv.slice(2);
if (!directory) throw Error("usage: game_seek.mjs <game directory> [fixture.crd] [core.wasm] [game.wasm]");

const run = bootGame(gameWasm, directory, 1);
const { game } = run;
const frame = () => {
  run.frame(16);
  game.game_audio(735);
};
const memory = () => Buffer.from(game.memory.buffer);
const compared = names.map((name, i) => [name, i]).filter(([name]) => !PRESENTATION.has(name) && !/^players\[\d+\]\.input\./.test(name));

while (run.clock < 15000) frame();
fs.mkdirSync(path.join(directory, "watched"), { recursive: true });
fs.copyFileSync(fixture, path.join(directory, "watched/seek.crd"));
memory().write("watched/seek.crd\0", game.game_replay_path(), "latin1");
if (!game.game_replay_open() || !game.game_watch()) throw Error("the fixture does not play");
const recording = Buffer.from(memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size()));
for (let frames = 0; game.game_watch_status() < 0; ++frames) {
  if (frames > 2000) throw Error("the replay never started");
  frame();
}
let t0 = performance.now(), frames = 0;
while (!game.game_watch_ticks()) {
  frame();
  if (++frames > 20000) throw Error("the replay was never prepared");
}
const prepared = { ms: Math.round(performance.now() - t0), frames, ticks: game.game_watch_ticks() };

// The verifier's world at every target, from one straight replay.
const ticks = game.game_watch_ticks();
const targets = [1, 2, 59, 60, 61, 119, 120, 121, ticks - 1, ticks];
for (let i = 0; targets.length < 40; ++i) targets.push(1 + ((i * 7919 + 13) % ticks));
const sorted = [...new Set(targets)].sort((a, b) => a - b);
const core = loadCore(coreWasm);
const { config, records } = decode(recording);
init(core, config);
const expected = new Map();
for (let t = 0, next = 0; next < sorted.length; ) {
  if (t === sorted[next]) {
    expected.set(t, Buffer.from(state(core)));
    ++next;
    continue;
  }
  step(core, records[t++]);
}

// Shuffled, so seeks go both ways.
const order = sorted.map((t, i) => [t, (i * 2654435761) % 1000]).sort((a, b) => a[1] - b[1]).map(([t]) => t);
const times = [];
for (const target of order) {
  t0 = performance.now();
  game.game_watch_seek(target);
  frame();
  times.push(performance.now() - t0);
  if (game.game_watch_tick() !== target) throw Error(`a seek to ${target} landed on ${game.game_watch_tick()}`);
  const a = expected.get(target), b = state(game);
  const off = compared.filter(([, i]) => a.readUInt32LE(i * 4) !== b.readUInt32LE(i * 4)).map(([name]) => name);
  if (off.length) throw Error(`after a seek to ${target}, ${off.slice(0, 4).join(", ")} differ from the verifier`);
}
times.sort((a, b) => a - b);
console.log(
  JSON.stringify({
    prepared,
    seeks: order.length,
    seek_ms: { median: +times[times.length >> 1].toFixed(1), worst: +times[times.length - 1].toFixed(1) },
  }),
);
