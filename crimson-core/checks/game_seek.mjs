// Seeking a replay (host/watch.inc, host/keyframes.inc): once a fixture is
// prepared, seeks to ticks across the run, backwards and forwards in a shuffled
// order, must each land on the tick asked for with the world where the
// verifier's straight replay leaves it. Without a fixture given, the service's
// co-op runs (service/test/vectors.json) seek after a one-player fixture, in
// the same game. It reports how long the preparing passes and the seeks take.
//
//   node crimson-core/checks/game_seek.mjs <game directory> [fixture.crd] [core.wasm] [game.wasm] [--rtx]
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { CORE, decode, init, loadCore, names, state, step } from "./engine.mjs";
import { loadGame, PRESENTATION } from "./game_compare.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const ROOT = new URL("..", CORE).pathname;
const rtx = process.argv.includes("--rtx");
const maxShots = 8;
const [
  directory,
  fixture,
  coreWasm = new URL("build/wasm/core.wasm", CORE).pathname,
  gameWasm = new URL("build/game/game.wasm", CORE).pathname,
] = process.argv.slice(2).filter((arg) => arg !== "--rtx");
if (!directory) throw Error("usage: game_seek.mjs <game directory> [fixture.crd] [core.wasm] [game.wasm]");
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, "service/test/vectors.json"))).coop_run;
const replays = fixture
  ? { [path.basename(fixture)]: fs.readFileSync(fixture) }
  : {
      "coop-perk-timers-rules2.crd": fs.readFileSync(path.join(ROOT, "tests/fixtures/replays/coop-perk-timers-rules2.crd")),
      "quest-1.1-completed.crd": fs.readFileSync(path.join(ROOT, "tests/fixtures/replays/quest-1.1-completed.crd")),
      "survival-rules2.crd": fs.readFileSync(path.join(ROOT, "tests/fixtures/replays/survival-rules2.crd")),
      "coop-survival.crd": Buffer.from(vectors.file, "base64"),
      "coop-quest.crd": Buffer.from(vectors.quest_file, "base64"),
    };

let groundId = 0, renderTarget = 0, boundTexture = 0, srcBlend = 0, dstBlend = 0;
let peakTerrainShots = 0, terrainCopies = 0, terrainReleases = 0;
const textures = new Map(), terrainAt = new Map();
const shotTicks = new Map();
const run = bootGame(gameWasm, directory, 1, {
  rtx,
  onHost(name, args) {
    if (name === "texture_create" && (args[3] & 1)) {
      groundId = args[0];
      textures.set(groundId, Buffer.alloc(32));
    } else if (name === "set_render_target") renderTarget = args[0];
    else if (name === "set_texture" && args[0] === 0) boundTexture = args[1];
    else if (name === "render_state") {
      if (args[0] === 19) srcBlend = args[1];
      else if (args[0] === 20) dstBlend = args[1];
    } else if (name === "texture_copy") {
      textures.set(args[0], Buffer.from(textures.get(args[1]) ?? Buffer.alloc(32)));
      if (args[0] >= (1 << 30)) {
        ++terrainCopies;
        shotTicks.set(args[0], game.game_watch_tick());
        const ticks = [...shotTicks.values()].sort((a, b) => a - b);
        for (let i = 2; i < ticks.length; ++i)
          if (ticks[i] - ticks[i - 1] !== ticks[1] - ticks[0])
            throw Error("terrain snapshot compaction shifted the uniform tick spacing");
      }
      const shots = [...textures.keys()].filter((id) => id >= (1 << 30)).length;
      peakTerrainShots = Math.max(peakTerrainShots, shots);
      if (shots > maxShots) throw Error(`terrain copies exceeded the ${maxShots}-target budget`);
    } else if (name === "texture_release") {
      if (shotTicks.has(args[0])) ++terrainReleases;
      textures.delete(args[0]);
      shotTicks.delete(args[0]);
    } else if ((name === "clear" || name === "draw") && renderTarget === groundId && groundId) {
      const hash = crypto.createHash("sha256").update(textures.get(groundId));
      if (name === "clear") hash.update(Buffer.from([0, args[0] & 255, (args[0] >>> 8) & 255, (args[0] >>> 16) & 255, (args[0] >>> 24) & 255]));
      else {
        hash.update(Buffer.from([1, args[0], boundTexture, srcBlend, dstBlend]));
        hash.update(memory().subarray(args[1], args[1] + args[2] * 28));
      }
      const digest = hash.digest();
      textures.set(groundId, digest);
      // Until a replay is prepared: its start, then each tick's bakes.
      if (game.game_watch_status() < 0 || !game.game_watch_ticks())
        terrainAt.set(game.game_watch_status() < 0 ? 0 : game.game_watch_tick() + 1, digest);
    }
  },
});
const { game } = run;
game.game_render_mode(rtx ? 1 : 0);
const frame = (taps = []) => {
  const input = run.input();
  for (const key of taps) {
    const n = input.getInt32(INPUT.event_count, true);
    input.setUint8(INPUT.events + n * 2, key);
    input.setUint8(INPUT.events + n * 2 + 1, 1);
    input.setInt32(INPUT.event_count, n + 1, true);
  }
  run.frame(16);
  game.game_audio(735);
};
const ESCAPE = 0x01;
const memory = () => Buffer.from(game.memory.buffer);
const compared = names.map((name, i) => [name, i]).filter(([name]) => !PRESENTATION.has(name));

// Seeks across the replay `name` (`file`), which plays from the menus.
function seeks(name, file) {
  peakTerrainShots = terrainCopies = terrainReleases = 0;
  fs.writeFileSync(path.join(directory, "watched/seek.crd"), file);
  memory().write("watched/seek.crd\0", game.game_replay_path(), "latin1");
  if (!game.game_replay_open() || !game.game_watch()) throw Error(`${name} does not play`);
  terrainAt.clear();
  const recording = Buffer.from(memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size()));
  for (let frames = 0; game.game_watch_status() < 0; ++frames) {
    if (frames > 2000) throw Error(`${name}: the replay never started`);
    frame();
  }
  let t0 = performance.now(), frames = 0;
  const lockedMode = () => {
    if (game.game_render_mode_available()) throw Error("replay permits changing render mode");
    const calls = run.calls.render_mode;
    const choice = path.join(directory, "render_mode.txt");
    const saved = fs.existsSync(choice) ? fs.readFileSync(choice, "utf8") : null;
    for (const mode of [0, 1]) {
      game.game_render_mode(mode);
      game.game_render_choice(mode);
    }
    if (run.calls.render_mode !== calls) throw Error("replay changed the renderer");
    if ((fs.existsSync(choice) ? fs.readFileSync(choice, "utf8") : null) !== saved)
      throw Error("replay changed the saved render preference");
  };
  lockedMode();
  while (!game.game_watch_ticks()) {
    frame();
    if (++frames > 20000) throw Error(`${name}: the replay was never prepared`);
  }
  lockedMode();
  const prepared = { ms: Math.round(performance.now() - t0), frames, ticks: game.game_watch_ticks() };

  // The verifier's world at every target, from one straight replay.
  const ticks = game.game_watch_ticks();
  if (ticks >= maxShots * 1800 && (peakTerrainShots !== maxShots || !terrainReleases))
    throw Error(`${name}: the long replay did not exercise terrain-cache compaction`);
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
    if (game.game_watch_tick() !== target) throw Error(`${name}: a seek to ${target} landed on ${game.game_watch_tick()}`);
    const a = expected.get(target), b = state(game);
    const off = compared.filter(([, i]) => a.readUInt32LE(i * 4) !== b.readUInt32LE(i * 4)).map(([field]) => field);
    if (off.length) throw Error(`${name}: after a seek to ${target}, ${off.slice(0, 4).join(", ")} differ from the verifier`);
    if (game.game_effects_active() !== overflow.get(target))
      throw Error(`${name}: after a seek to ${target}, the overflow pool differs from straight playback`);
    if (!textures.get(groundId)?.equals(expectedTerrain(target)))
      throw Error(`${name}: after a seek to ${target}, the rebuilt terrain differs from straight playback`);
  }
  times.sort((a, b) => a - b);
  // Escape leaves for the scores, from which the next replay plays.
  frame([ESCAPE]);
  for (let frames = 0; game.game_watch_status() !== -1; ++frames) {
    if (frames > 600) throw Error(`${name}: Escape does not leave the replay`);
    frame();
  }
  return {
    prepared,
    terrain_shots_peak: peakTerrainShots,
    terrain_copies: terrainCopies,
    seeks: order.length,
    seek_ms: { median: +times[times.length >> 1].toFixed(1), worst: +times[times.length - 1].toFixed(1) },
  };
}

while (run.clock < 15000) frame();
fs.mkdirSync(path.join(directory, "watched"), { recursive: true });
const reports = Object.fromEntries(Object.entries(replays).map(([name, file]) => [name, seeks(name, file)]));
console.log(JSON.stringify(reports));
