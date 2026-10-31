// The game module reads replays for playback (host/replay.inc): every recorded
// fixture it can play, and the service's co-op runs, read as checks/replay.py
// converts them, the session's own recording layout, each command for the
// player it names; the rest say they need the Python port.
//
// Usage: node game_replay_read.mjs <game directory> [game.wasm]

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CL_BUILD_1_9_8, clBuild } from "./engine.mjs";
import { bootGame } from "./game_host.mjs";

const CORE = new URL("..", import.meta.url).pathname;
const ROOT = path.join(CORE, "..");
const [directory, gameWasm = path.join(CORE, "build/game/game.wasm")] = process.argv.slice(2);
if (!directory) throw Error("usage: game_replay_read.mjs <game directory> [game.wasm]");

const { game } = bootGame(gameWasm, directory, 1);
const memory = () => Buffer.from(game.memory.buffer);
const fixtures = path.join(ROOT, "tests/fixtures/replays");
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "replay-read-"));
fs.mkdirSync(path.join(directory, "replays"), { recursive: true });
// The service's co-op runs (service/test/vectors.json): a Survival run, and a custom quest's clear with and without
// the seats' keys.
const vectors = JSON.parse(fs.readFileSync(path.join(ROOT, "service/test/vectors.json"))).coop_run;
const coop = { "coop-survival.crd": vectors.file, "coop-quest.crd": vectors.quest_file, "coop-quest-unkeyed.crd": vectors.unkeyed_quest_file };
for (const [name, file] of Object.entries(coop)) fs.writeFileSync(path.join(scratch, name), Buffer.from(file, "base64"));
const replays = [
  ...fs.readdirSync(fixtures).filter((f) => f.endsWith(".crd")).sort().map((name) => path.join(fixtures, name)),
  ...Object.keys(coop).map((name) => path.join(scratch, name)),
];
const open = (name) => {
  memory().write(`replays/${name}\0`, game.game_replay_path(), "latin1");
  return game.game_replay_open();
};
const reason = () => memory().toString("latin1", game.game_replay_reason(), memory().indexOf(0, game.game_replay_reason()));
const pickers = () => {
  const players = [];
  for (let picker; (picker = game.game_replay_picker(players.length)) >= 0; ) players.push(picker);
  return players;
};
let read = 0;
for (const source of replays) {
  const name = path.basename(source);
  fs.copyFileSync(source, path.join(directory, "replays", name));
  const playable = open(name);
  const expected = path.join(scratch, `${name}.rsi`);
  let converted = true;
  try {
    execFileSync("uv", ["run", "--no-sync", "python", path.join(CORE, "checks/replay.py"), source, "--out", expected], { stdio: "pipe" });
  } catch {
    converted = false; // the core plays one or two players in Rush, Survival or Quests
  }
  if (!converted) {
    if (playable || reason() !== "This run needs the Python port") throw Error(`${name}: read as playable (${reason()})`);
    continue;
  }
  if (!playable) throw Error(`${name}: ${reason()}`);
  const recording = memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size());
  if (!recording.equals(fs.readFileSync(expected))) throw Error(`${name}: reads differently from checks/replay.py`);
  ++read;
}
// A fixture (or a co-op run) rewritten as `expression` (Python over its decoded `wire`) at replays/rewritten.crd.
const fixture = "rules2-survival.crd";
const rewrite = (expression, source = path.join(fixtures, fixture)) => {
  const script =
    "import sys, msgspec, zstandard; data = open(sys.argv[1], 'rb').read(); " +
    "wire = msgspec.msgpack.decode(zstandard.ZstdDecompressor().decompress(data)); " +
    "pack = lambda value: zstandard.ZstdCompressor().compress(msgspec.msgpack.encode(value)); " +
    "v34 = lambda seat_keys: pack({'format_version': 34, 'game_version': wire['game_version'], 'rules': wire['rules'], " +
    "'recorder': wire['recorder'], 'pilot': None, 'seat_keys': seat_keys, " +
    "**{key: wire[key] for key in ('run', 'result', 'ticks')}}); " +
    "v35 = lambda run: pack({**wire, 'format_version': 35, 'run': {k: v for k, v in wire['run'].items() if k != 'cl_build'} | run}); " +
    `open(sys.argv[2], 'wb').write(${expression})`;
  execFileSync("uv", ["run", "--no-sync", "python", "-c", script, source, path.join(directory, "replays", "rewritten.crd")]);
  return open("rewritten.crd");
};
// Format 34 names each seat's key, or none: either reads as the fixture does.
const fixtureRecording = path.join(scratch, "fixture.rsi");
execFileSync("uv", ["run", "--no-sync", "python", path.join(CORE, "checks/replay.py"), path.join(fixtures, fixture), "--out", fixtureRecording], { stdio: "pipe" });
// Format 35 names the run's build: 1.9.93's reads as the fixture does too.
const seated = { "no seat keys": "v34(None)", "a seat key": "v34([bytes(range(32))])", "1.9.93 rules": "v35({'cl_build': 10993})" };
for (const [name, expression] of Object.entries(seated)) {
  if (!rewrite(expression)) throw Error(`a replay with ${name} reads as unplayable`);
  const recording = memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size());
  if (!recording.equals(fs.readFileSync(fixtureRecording))) throw Error(`a replay with ${name} reads differently from its fixture`);
}
// Ranked co-op's recorded seats postdate the reload fix: an unlisted 0.18 build must still play.
for (const version of ["0.18.0", "0.18.0+build.0123456789abcdef01234567"]) {
  if (!rewrite(`pack({**wire, 'game_version': '${version}'})`, path.join(fixtures, "rules1-ranked-coop.crd")))
    throw Error(`ranked co-op build ${version}: ${reason()}`);
  const expected = path.join(scratch, "ranked-coop.rsi");
  execFileSync("uv", ["run", "--no-sync", "python", path.join(CORE, "checks/replay.py"), path.join(directory, "replays", "rewritten.crd"), "--out", expected], { stdio: "pipe" });
  const recording = memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size());
  if (recording.readUInt32LE(67 * 4) !== 0 || !recording.equals(fs.readFileSync(expected)))
    throw Error(`ranked co-op build ${version}: wrong reload profile`);
}
// The run with the perk menu opened on its second tick and a pick on its third, both for `picker`.
const commands = (picker) =>
  `[{'type': 'perk_menu_open', 'player_index': ${picker}}], [{'type': 'perk_pick', 'player_index': ${picker}, 'choice_index': 0}]`;
const picked = (picker) =>
  `pack({**wire, 'ticks': [[t[0], c] for t, c in zip(wire['ticks'], [[], ${commands(picker)}])] + wire['ticks'][3:]})`;
// Broken replays read as unreadable, and never trap the module.
const broken = {
  truncated: "data[: len(data) // 2]",
  "too many commands": "pack({**wire, 'ticks': [[wire['ticks'][0][0], [{'type': 'perk_menu_open', 'player_index': 0}] * 17]]})",
  "infinite aim": "pack({**wire, 'ticks': [[[[0.0, 0.0, 1e300, 0.0, 0]], []]]})",
  "no run": "pack({'format_version': wire['format_version'], 'rules': 1})",
  "no quest 6.1": "pack({**wire, 'run': {**wire['run'], 'game_mode_id': 3, 'quest_level': {'major': 6, 'minor': 1}}})",
  "custom quest": "pack({**wire, 'run': {**wire['run'], 'game_mode_id': 3, 'quest_level': None, 'custom_quest': {'title': 'Crosswind'}}})",
  "format 34 without seat keys": "pack({k: v for k, v in wire.items() if k != 'seat_keys'})",
  "seat keys before format 34": "pack({**wire, 'format_version': 33, 'seat_keys': None})",
  "future rules": "pack({**wire, 'rules': wire['rules'] + 1})",
  "format 35 without a build": "v35({})",
  "an unknown build": "v35({'cl_build': 10992})",
  "a build before format 35": "pack({**wire, 'format_version': 34, 'run': {**wire['run'], 'cl_build': 10993}})",
  "1.9.8 rules under rules 1": "pack({**wire, 'format_version': 35, 'rules': 1, 'run': {**wire['run'], 'cl_build': 10908}})",
  "1.9.8's build past 32 bits": "v35({'cl_build': 10908 + 2**32})",
  "1.9.8's build less 32 bits": "v35({'cl_build': 10908 - 2**32})",
  "no seat's key": "v34([])",
  "a key per two seats": "v34([bytes(32), bytes(range(32))])",
  "a short seat key": "v34([bytes(31)])",
  "a seat key as text": "v34(['k' * 32])",
  "player two's perk commands": picked(1),
  "a tick with no inputs first": "pack({**wire, 'ticks': [[[], wire['ticks'][0][1]]] + wire['ticks'][1:]})",
};
for (const [name, expression] of Object.entries(broken))
  if (rewrite(expression)) throw Error(`a replay with ${name} reads as playable`);
// A co-op run's perk commands each name their player: player two's menu and pick read as player two's.
const coopRun = path.join(scratch, "coop-survival.crd");
if (!rewrite(picked(1), coopRun) || pickers().join() !== "1,1") throw Error(`player two's perk commands read as ${pickers()}`);
// Broken co-op runs read as unreadable too; three players, which the format allows, need the Python port.
const coopBroken = {
  "a third player's perk command": picked(2),
  "a negative player index": picked(-1),
  "one player's inputs a tick": "pack({**wire, 'ticks': [[t[0][:1], t[1]] for t in wire['ticks']]})",
  "ticks with no inputs first": "pack({**wire, 'ticks': [[[], t[1]] for t in wire['ticks'][:2]] + wire['ticks'][2:]})",
  "no players": "pack({**wire, 'run': {**wire['run'], 'player_count': 0}, 'seat_keys': None})",
  "five players": "pack({**wire, 'run': {**wire['run'], 'player_count': 5}, 'seat_keys': None})",
};
for (const [name, expression] of Object.entries(coopBroken)) {
  if (rewrite(expression, coopRun)) throw Error(`a co-op run with ${name} reads as playable`);
  if (reason() !== "This version cannot read its replay") throw Error(`a co-op run with ${name}: ${reason()}`);
}
const three = "pack({**wire, 'run': {**wire['run'], 'player_count': 3}, 'seat_keys': None, 'ticks': [[t[0] + t[0][:1], t[1]] for t in wire['ticks']]})";
if (rewrite(three, coopRun) || reason() !== "This run needs the Python port") throw Error(`three players: ${reason()}`);
// A 1.9.8 run reads as checks/replay.py converts it, its build in the config.
{
  if (!rewrite("v35({'cl_build': 10908})")) throw Error(`1.9.8 rules: ${reason()}`);
  const expected = path.join(scratch, "rules-1.9.8.rsi");
  execFileSync("uv", ["run", "--no-sync", "python", path.join(CORE, "checks/replay.py"), path.join(directory, "replays", "rewritten.crd"), "--out", expected], { stdio: "pipe" });
  const recording = memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size());
  if (clBuild(recording) !== CL_BUILD_1_9_8 || !recording.equals(fs.readFileSync(expected))) throw Error("1.9.8 rules: reads differently from checks/replay.py");
}
fs.rmSync(scratch, { recursive: true });
console.log(
  JSON.stringify({ read, seated: Object.keys(seated).length, broken: Object.keys(broken).length, coop_broken: Object.keys(coopBroken).length }),
);
