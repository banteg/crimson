// Seeking a replay (host/watch.inc, host/keyframes.inc): once a fixture is
// prepared, seeks to ticks across the run, backwards and forwards in a shuffled
// order, must each land on the tick asked for with the world where the
// verifier's straight replay leaves it. It reports how long the preparing pass
// and the seeks take.
//
//   node crimson-core/checks/game_seek.mjs <game directory> [fixture.crd] [core.wasm] [game.wasm]
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { CORE, decode, init, loadCore, names, state, step } from "./engine.mjs";
import { loadGame, PRESENTATION } from "./game_compare.mjs";
import { bootGame } from "./game_host.mjs";

const ROOT = new URL("..", CORE).pathname;
const [
  directory,
  fixture = path.join(ROOT, "tests/fixtures/replays/survival-238852.crd"),
  coreWasm = new URL("build/wasm/core.wasm", CORE).pathname,
  gameWasm = new URL("build/game/game.wasm", CORE).pathname,
] = process.argv.slice(2);
if (!directory) throw Error("usage: game_seek.mjs <game directory> [fixture.crd] [core.wasm] [game.wasm]");

let groundId = 0, renderTarget = 0, boundTexture = 0, srcBlend = 0, dstBlend = 0;
const textures = new Map(), terrainAt = new Map();
const run = bootGame(gameWasm, directory, 1, {
  onHost(name, args) {
    if (name === "texture_create" && (args[3] & 1)) {
      groundId = args[0];
      textures.set(groundId, Buffer.alloc(32));
    } else if (name === "set_render_target") renderTarget = args[0];
    else if (name === "set_texture" && args[0] === 0) boundTexture = args[1];
    else if (name === "render_state") {
      if (args[0] === 19) srcBlend = args[1];
      else if (args[0] === 20) dstBlend = args[1];
    } else if (name === "texture_copy") textures.set(args[0], Buffer.from(textures.get(args[1]) ?? Buffer.alloc(32)));
    else if (name === "texture_release") textures.delete(args[0]);
    else if ((name === "clear" || name === "draw") && renderTarget === groundId && groundId) {
      const hash = crypto.createHash("sha256").update(textures.get(groundId));
      if (name === "clear") hash.update(Buffer.from([0, args[0] & 255, (args[0] >>> 8) & 255, (args[0] >>> 16) & 255, (args[0] >>> 24) & 255]));
      else {
        hash.update(Buffer.from([1, args[0], boundTexture, srcBlend, dstBlend]));
        hash.update(memory().subarray(args[1], args[1] + args[2] * 28));
      }
      const digest = hash.digest();
      textures.set(groundId, digest);
      if (!game.game_watch_ticks()) terrainAt.set(game.game_watch_status() < 0 ? 0 : game.game_watch_tick() + 1, digest);
    }
  },
});
const { game } = run;
const frame = () => {
  run.frame(16);
  game.game_audio(735);
};
const memory = () => Buffer.from(game.memory.buffer);
const compared = names.map((name, i) => [name, i]).filter(([name]) => !PRESENTATION.has(name));

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
const straight = loadGame(gameWasm);
const { config, records } = decode(recording);
init(core, config);
init(straight, config);
const expected = new Map();
const overflow = new Map();
for (let t = 0, next = 0; next < sorted.length; ) {
  if (t === sorted[next]) {
    expected.set(t, Buffer.from(state(core)));
    overflow.set(t, straight.game_effects_active());
    ++next;
    continue;
  }
  step(core, records[t]);
  step(straight, records[t++]);
}

const expectedTerrain = (target) => {
  for (let t = target; t >= 0; --t) if (terrainAt.has(t)) return terrainAt.get(t);
};
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
  if (game.game_effects_active() !== overflow.get(target))
    throw Error(`after a seek to ${target}, the overflow pool differs from straight playback`);
  if (!textures.get(groundId)?.equals(expectedTerrain(target)))
    throw Error(`after a seek to ${target}, the rebuilt terrain differs from straight playback`);
}
times.sort((a, b) => a - b);
console.log(
  JSON.stringify({
    prepared,
    seeks: order.length,
    seek_ms: { median: +times[times.length >> 1].toFixed(1), worst: +times[times.length - 1].toFixed(1) },
  }),
);
