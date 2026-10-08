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
fs.rmSync(scratch, { recursive: true });
console.log(JSON.stringify({ read }));
