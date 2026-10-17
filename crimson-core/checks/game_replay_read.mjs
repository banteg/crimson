// The game module reads replays for playback (host/replay.inc): every recorded
// fixture it can play reads as checks/replay.py converts it, the session's own
// recording layout, and the rest say they need the Python port.
//
// Usage: node game_replay_read.mjs <game directory> [game.wasm]

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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
let read = 0;
for (const name of fs.readdirSync(fixtures).filter((f) => f.endsWith(".crd")).sort()) {
  fs.copyFileSync(path.join(fixtures, name), path.join(directory, "replays", name));
  memory().write(`replays/${name}\0`, game.game_replay_path(), "latin1");
  const playable = game.game_replay_open();
  const reason = memory().toString("latin1", game.game_replay_reason(), memory().indexOf(0, game.game_replay_reason()));
  const expected = path.join(scratch, `${name}.rsi`);
  let converted = true;
  try {
    execFileSync("uv", ["run", "--no-sync", "python", path.join(CORE, "checks/replay.py"), path.join(fixtures, name), "--out", expected], { stdio: "pipe" });
  } catch {
    converted = false; // the core plays one player in Rush, Survival or Quests
  }
  if (!converted) {
    if (playable || reason !== "This run needs the Python port") throw Error(`${name}: read as playable (${reason})`);
    continue;
  }
  if (!playable) throw Error(`${name}: ${reason}`);
  const recording = memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size());
  if (!recording.equals(fs.readFileSync(expected))) throw Error(`${name}: reads differently from checks/replay.py`);
  ++read;
}
// A fixture rewritten as `expression` (Python over its decoded `wire`) at replays/rewritten.crd.
const fixture = "survival-135302.crd";
const rewrite = (expression) => {
  const script =
    "import sys, msgspec, zstandard; data = open(sys.argv[1], 'rb').read(); " +
    "wire = msgspec.msgpack.decode(zstandard.ZstdDecompressor().decompress(data)); " +
    "pack = lambda value: zstandard.ZstdCompressor().compress(msgspec.msgpack.encode(value)); " +
    "v34 = lambda seat_keys: pack({'format_version': 34, 'game_version': wire['game_version'], 'rules': 1, " +
    "'recorder': wire['recorder'], 'pilot': None, 'seat_keys': seat_keys, " +
    "**{key: wire[key] for key in ('run', 'result', 'ticks')}}); " +
    `open(sys.argv[2], 'wb').write(${expression})`;
  execFileSync("uv", ["run", "--no-sync", "python", "-c", script, path.join(fixtures, fixture), path.join(directory, "replays", "rewritten.crd")]);
  memory().write("replays/rewritten.crd\0", game.game_replay_path(), "latin1");
  return game.game_replay_open();
};
// Format 34 names each seat's key, or none: either reads as the fixture does.
const fixtureRecording = path.join(scratch, "fixture.rsi");
execFileSync("uv", ["run", "--no-sync", "python", path.join(CORE, "checks/replay.py"), path.join(fixtures, fixture), "--out", fixtureRecording], { stdio: "pipe" });
const seated = { "no seat keys": "v34(None)", "a seat key": "v34([bytes(range(32))])" };
for (const [name, expression] of Object.entries(seated)) {
  if (!rewrite(expression)) throw Error(`a replay with ${name} reads as unplayable`);
  const recording = memory().subarray(game.game_replay_recording(), game.game_replay_recording() + game.game_replay_recording_size());
  if (!recording.equals(fs.readFileSync(fixtureRecording))) throw Error(`a replay with ${name} reads differently from its fixture`);
}
// Broken replays read as unreadable, and never trap the module.
const broken = {
  truncated: "data[: len(data) // 2]",
  "too many commands": "pack({**wire, 'ticks': [[wire['ticks'][0][0], [{'type': 'perk_menu_open', 'player_index': 0}] * 17]]})",
  "infinite aim": "pack({**wire, 'ticks': [[[[0.0, 0.0, 1e300, 0.0, 0]], []]]})",
  "no run": "pack({'format_version': wire['format_version'], 'rules': 1})",
  "no quest 6.1": "pack({**wire, 'run': {**wire['run'], 'game_mode_id': 3, 'quest_level': {'major': 6, 'minor': 1}}})",
  "custom quest": "pack({**wire, 'run': {**wire['run'], 'game_mode_id': 3, 'quest_level': None, 'custom_quest': {'title': 'Crosswind'}}})",
  "format 34 without seat keys": "pack({**wire, 'format_version': 34, 'rules': 1, 'pilot': None})",
  "seat keys before format 34": "pack({**wire, 'seat_keys': None})",
  "no seat's key": "v34([])",
  "a key per two seats": "v34([bytes(32), bytes(range(32))])",
  "a short seat key": "v34([bytes(31)])",
  "a seat key as text": "v34(['k' * 32])",
};
for (const [name, expression] of Object.entries(broken))
  if (rewrite(expression)) throw Error(`a replay with ${name} reads as playable`);
fs.rmSync(scratch, { recursive: true });
console.log(JSON.stringify({ read, seated: Object.keys(seated).length, broken: Object.keys(broken).length }));
