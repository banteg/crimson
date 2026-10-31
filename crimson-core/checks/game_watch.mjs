// Watches replays in the game module (host/watch.inc), as a link to a run
// plays one: a replay asked for as the game boots skips the intro and plays,
// then every recorded fixture the module can play, the service's co-op runs
// (a Survival run and a custom quest's clear) and a run on the 1.9.8 rules (a
// matrix stream as the Python port records it), plays its build, starts from the menus,
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
import { CL_BUILD_1_9_8, clBuild, CORE, decode, field, init, loadCore, names, state, step } from "./engine.mjs";
import { PRESENTATION } from "./game_compare.mjs";
import { bootGame, INPUT, streamReplay } from "./game_host.mjs";

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
// A frame after `dt` milliseconds, with keys tapped for it; `mixed` is its sound.
let mixed;
function frame(dt = 16, taps = []) {
  const input = run.input();
  for (const key of taps) {
    const n = input.getInt32(INPUT.event_count, true);
    input.setUint8(INPUT.events + n * 2, key);
    input.setUint8(INPUT.events + n * 2 + 1, 1);
    input.setInt32(INPUT.event_count, n + 1, true);
  }
  run.frame(dt);
  if (game.game_play_mode() !== 0) throw Error("replay watching reported live gameplay");
  mixed = new Int16Array(game.memory.buffer, game.game_audio(735), 735 * 2);
}
const memory = () => Buffer.from(game.memory.buffer);
// The fields a replay plays.
const compared = names.map((name, i) => [name, i]).filter(([name]) => !PRESENTATION.has(name));
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
// A link opened as the game boots skips the intro and the menu. It comes in
// once the intro's tune plays, as the page's fetch does, and the preparing pass
// that follows is silent.
fs.copyFileSync(path.join(fixtures, "quest-1.1-rules2.crd"), path.join(watched, "linked.crd"));
while (run.clock < 1500) frame();
memory().write("watched/linked.crd\0", game.game_replay_path(), "latin1");
if (!game.game_replay_open() || !game.game_watch()) throw Error("a link at startup does not take");
// A link's moment lies within this recording, its stop past its start.
const linkedTicks = decode(Buffer.from(memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size()))).records.length;
for (const [tick, stop] of [[linkedTicks + 1, 0], [0, linkedTicks + 1], [-1, 0], [300, 300], [0, 1]])
  if (game.game_watch_moment(tick, stop)) throw Error(`a link took the moment ${tick}..${stop}`);
if (!game.game_watch_moment(300, 305)) throw Error("a link refused the moment 300..305");
for (let frames = 0; game.game_watch_status() < 0 || !game.game_watch_ticks(); ++frames) {
  if (frames > 2000) throw Error("a link at startup never plays");
  frame();
  if (game.game_watch_status() === 0 && !game.game_watch_ticks() && mixed.some((v) => v !== 0))
    throw Error("a link's preparing pass is not silent");
}
if (run.clock > 5000) throw Error(`a link at startup waited ${run.clock} ms for the intro`);
if (game.game_watch_tick() !== 300) throw Error(`a link's seek to 300 landed on ${game.game_watch_tick()}`);
for (let i = 0; i < 20; ++i) frame();
if (game.game_watch_tick() !== 305) throw Error(`a link's stop at 305 stopped on ${game.game_watch_tick()}`);
if (game.game_watch_moment(0, 305)) throw Error("a stop at the tick playback is on took");
// Batched captures resume without a seek, including adjacent ticks and a frame
// long enough to advance several simulation steps. Each stop must still land exactly.
for (const tick of [306, 307, 310]) {
  if (!game.game_watch_moment(0, tick)) throw Error(`resume to ${tick} was refused`);
  if (game.game_watch_tick() !== (tick === 306 ? 305 : tick === 307 ? 306 : 307))
    throw Error("arming a capture stop changed the current tick");
  for (let i = 0; i < 10; ++i) frame(50);
  if (game.game_watch_paused_tick() !== tick) throw Error(`capture stop ${tick} landed on ${game.game_watch_tick()}`);
}
frame(16, [SPACE]);
for (let i = 0; i < 5; ++i) frame();
if (game.game_watch_tick() <= 310) throw Error("resuming after a stop tick did not play on");
// A seek past a stop is done with it: scrubbing back plays through.
if (!game.game_watch_moment(0, 400)) throw Error("a stop ahead of playback was refused");
game.game_watch_seek(600);
frame();
game.game_watch_seek(390);
for (let i = 0; i < 20; ++i) frame();
if (game.game_watch_tick() <= 400) throw Error(`a stop a seek passed paused on ${game.game_watch_tick()}`);
// Playback banks the paced time live play does (host/live_pace.h, whose own
// check, game_pace.cpp, takes it through every kind of display): through a 60
// Hz display's frames, read as Grim's clock reads them, in whole milliseconds up
// to 0.9 ms after each shows, it runs one tick a frame, and through a 59 Hz
// one's, one a frame but for one frame a second that runs two.
function display(hz, frames) {
  const ran = [], start = run.clock;
  for (let k = -60; k < frames; ++k) {
    const from = game.game_watch_tick();
    frame(start + Math.floor(((k + 61) * 1000) / hz + ((k * 0.618 + 60) % 1) * 0.9) - run.clock);
    if (k >= 0) ran.push(game.game_watch_tick() - from);
  }
  return ran.join("");
}
for (const [hz, frames, expected] of [[60, 120, /^1+$/], [59, 150, /^(?!.*(0|2.{0,49}2))[12]+$/]]) {
  const ran = display(hz, frames);
  if (!expected.test(ran)) throw Error(`a ${hz} Hz display ran ${ran}`);
}
frame(16, [ESCAPE]);
for (let frames = 0; game.game_state() !== HIGHSCORES; ++frames) {
  if (frames > 600) throw Error("a linked replay does not return to the high scores");
  frame();
}
for (let i = 0; i < 60; ++i) frame();
const before = files().sort().join("\n");
const core = loadCore(coreWasm);
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, "service/test/vectors.json"))).coop_run;
const coop = { "coop-survival.crd": vectors.file, "coop-quest.crd": vectors.quest_file };
// A quest on the 1.9.8 rules, recorded from the matrix's stream.
const streams = { "rules-1.9.8.crd": "1.9.8-quest-1.5-ranked" };
const replays = fs.readdirSync(fixtures).filter((f) => f.endsWith(".crd")).sort();
let played = 0, played198 = 0;
for (const name of [...replays, ...Object.keys(coop), ...Object.keys(streams)]) {
  if (coop[name]) fs.writeFileSync(path.join(watched, name), Buffer.from(coop[name], "base64"));
  else if (streams[name]) streamReplay(streams[name], path.join(watched, name));
  else fs.copyFileSync(path.join(fixtures, name), path.join(watched, name));
  memory().write(`watched/${name}\0`, game.game_replay_path(), "latin1");
  if (!game.game_replay_open()) {
    if (coop[name] || streams[name]) throw Error(`${name} does not read`);
    continue; // one the Python port plays (game_replay_read.mjs)
  }
  const recording = Buffer.from(memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size()));
  if (!game.game_watch() || (!played && !game.game_watch())) throw Error(`${name}: Watch does not start`);
  let moment = 0;
  if (name === "coop-perk-timers-rules2.crd") {
    // Locate an actual Reflex Boost window in the generated fixture.
    const sample = decode(recording);
    init(core, sample.config);
    for (let i = 0; i < sample.records.length - 30; ++i) {
      if (!step(core, sample.records[i])) throw Error("Reflex sample ended early");
      state(core);
      if (field(core, "globals.bonus_reflex_boost_timer", true) > 1) {
        moment = i + 1;
        break;
      }
    }
    if (!moment) throw Error("Co-op timer fixture has no Reflex Boost window");
    game.game_watch_seek(moment);
    game.game_watch_stop_at(moment + 30);
  }
  for (let frames = 0; game.game_watch_status() < 0; ++frames) {
    if (frames > 600) throw Error(`${name}: the replay never started`);
    frame();
  }
  // The host reads the next replay while this one plays.
  game.game_replay_open();
  if (name === "coop-perk-timers-rules2.crd") {
    while (!game.game_watch_ticks()) frame();
    if (game.game_watch_tick() !== moment)
      throw Error(`Reflex Boost link seek landed on ${game.game_watch_tick()}`);
    for (let i = 0; i < 60; ++i) frame();
    if (game.game_watch_tick() !== moment + 30)
      throw Error(`Reflex Boost link stop landed on ${game.game_watch_tick()}`);
    frame(16, [SPACE]);
  }
  for (let i = 0; i < 120; ++i) frame(i % 2 ? 33 : 16);
  frame(16, [SPACE]);
  const paused = Buffer.from(state(game));
  const build = clBuild(recording);
  if (field(game, "globals.portable_cl_build") !== build) throw Error(`${name}: plays build ${field(game, "globals.portable_cl_build")}, not ${build}`);
  played198 += build === CL_BUILD_1_9_8;
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
if (played < 2 + Object.keys(coop).length + Object.keys(streams).length) throw Error(`only ${played} replays played`);
if (!played198) throw Error("no replay played the 1.9.8 rules");
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
console.log(JSON.stringify({ played, played_1_9_8: played198 }));
