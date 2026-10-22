// The leaderboard on the high score screen (host/ranked.inc) and watching its
// runs (host/watch.inc), as the browser host serves them: ticking Show internet
// scores fetches the Survival board quietly, and its runs join the table. The
// original's Survival table imports at startup (host/scores.inc) as the Python
// port imports it, without the leaderboard row an earlier build saved there. A
// pinned run's replay is
// asked for once and, written to replays/online/, plays to the result it
// recorded; a run the leaderboard no longer has gives no Watch; a failed
// download is asked for again when the row is pinned again; two runs with the
// same name and numbers keep their own ids. Update scores replaces the board's
// runs whole. Nothing online is stored: the imported row is the only score, and
// only the downloaded replay is new. Then the game starts again for two players:
// the two players' table fetches the co-op pairs' Survival board, whose runs name
// both players.
//
//   node crimson-core/checks/game_online.mjs <game directory> [game.wasm]
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CORE } from "./engine.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const ROOT = new URL("..", CORE).pathname;
const [directory, gameWasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_online.mjs <game directory> [game.wasm]");

// The original's Survival table, which the game imports as it starts.
const table = path.join(directory, "scores5/survival.hi");
fs.mkdirSync(path.dirname(table), { recursive: true });
// The local row ranks below the board's runs, so they keep the rows they are clicked on.
const originalTable = Buffer.concat([originalRow("stale", 999999, 1), originalRow("Kept \u00e9", 1, 0)]);
fs.writeFileSync(table, originalTable);

const requests = [];
let run = bootGame(gameWasm, directory, 1, { leaderboard: true, requests });
let { game } = run;
// game_state_id_t, HOST_LEADERBOARD_* (game/host_abi.h), DirectInput scancodes.
const [STATISTICS_MENU, HIGHSCORES] = [4, 14];
const [SCORES, REPLAY] = [3, 4];
const [ESCAPE, PAGE_DOWN] = [0x01, 0xd1];
// Where a fresh 1024x768 profile lays these out: the main menu's Statistics,
// its High scores, Show internet scores, the first two rows, Update scores, a
// spot clear of the panels, and the pinned card's Watch.
const STATISTICS = [200, 458], HIGH_SCORES = [275, 316], INTERNET = [682, 261];
const ROWS = [305, 321, 337, 353].map((y) => [180, y]), UPDATE = [209, 480], CLEAR = [700, 650], WATCH = [745, 421];

function frame({ cursor = CLEAR, buttons = 0, taps = [] } = {}) {
  const input = run.input();
  for (const key of taps) {
    const n = input.getInt32(INPUT.event_count, true);
    input.setUint8(INPUT.events + n * 2, key);
    input.setUint8(INPUT.events + n * 2 + 1, 1);
    input.setInt32(INPUT.event_count, n + 1, true);
  }
  input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(cursor[0])), true);
  input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(cursor[1])), true);
  input.setUint8(INPUT.buttons, buttons ? 0x80 : 0);
  run.frame(16);
  game.game_audio(735);
}
// Holds the cursor on a spot for a while, then clicks it.
function click(at, settle = 30) {
  for (let i = 0; i < settle; ++i) frame({ cursor: at });
  for (let i = 0; i < 5; ++i) frame({ cursor: at, buttons: 1 });
  frame({ cursor: at });
}
function waitFor(what, done, limit = 600) {
  for (let frames = 0; !done(); ++frames) {
    if (frames > limit) throw Error(`${what} never happened`);
    frame();
  }
}
const memory = () => Buffer.from(game.memory.buffer);
const text = (at) => memory().toString("latin1", at, memory().indexOf(0, at));

// The service's answer for the Survival board (service/src/views.ts gameScores):
// the fixture's run, and one the leaderboard drops before its replay is asked for.
const fixture = path.join(ROOT, "tests/fixtures/replays/rules2-survival.crd");
const score = (run, name, experience) => ({
  run, name, score: experience, elapsed_ms: 512000, experience, most_used_weapon_id: 1,
  shots_fired: 9000, shots_hit: 7000, kills: 1400, accepted_at: Date.now(),
});
function answerScores(scores) {
  if (requests.shift() !== SCORES) throw Error("the screen asked for no scores");
  const body = JSON.stringify({ scores });
  memory().write(body, game.game_scores_buffer(body.length), "latin1");
  game.game_scores_received(body.length);
}

// A Survival row of the original's table, as highscore_write_record writes it:
// each byte offset, the checksum over the signed bytes. `flags` 1 is a row an
// earlier build saved from the leaderboard.
function originalRow(name, experience, flags) {
  const record = Buffer.alloc(72);
  record.write(name, 0, "latin1");
  record.writeUInt32LE(512000, 0x20);
  record.writeUInt32LE(experience, 0x24);
  record[0x28] = 1;
  [record[0x40], record[0x42], record[0x43]] = [1, 1, 26];
  [record[0x44], record[0x46], record[0x47]] = [flags, 0x7c, 0xff];
  let checksum = 0;
  for (let i = 0; i < 72; ++i) checksum = (checksum + (i + 3) * ((record[i] << 24) >> 24) * 7) | 0;
  for (let i = 0; i < 72; ++i) record[i] = (record[i] + (i * 5 + 1) * i + 6) & 0xff;
  const wire = Buffer.alloc(76);
  record.copy(wire);
  wire.writeInt32LE(checksum, 72);
  return wire;
}

// On a fresh profile the main menu shares its screen id with the startup sequence.
while (run.clock < 15000) frame();
click(STATISTICS);
waitFor("the Statistics menu", () => game.game_state() === STATISTICS_MENU);
click(HIGH_SCORES);
waitFor("the high scores", () => game.game_state() === HIGHSCORES);
if (requests.length) throw Error("the screen fetched a board before Show internet scores was ticked");
click(INTERNET);
waitFor("a quiet fetch", () => requests.length);
answerScores([score("r1", "pilot", 135302), score("gone", "ghost", 1000), score("twin-a", "twin", 500), score("twin-b", "twin", 500)]);
for (let i = 0; i < 30; ++i) frame();
if (requests.length) throw Error("the screen fetched the board twice");

// The board's first run: its replay is fetched once, then it plays.
click(ROWS[0]);
for (let i = 0; i < 10; ++i) frame();
if (requests.join() !== `${REPLAY}`) throw Error(`the card asked for ${requests.join() || "nothing"}`);
requests.length = 0;
if (text(game.game_replay_download()) !== "r1") throw Error("the card asked for another run");
fs.mkdirSync(path.join(directory, "replays/online"), { recursive: true });
fs.copyFileSync(fixture, path.join(directory, "replays/online/r1.crd"));
game.game_replay_downloaded(0);
click(WATCH);
waitFor("the replay", () => game.game_watch_status() === 0);
if (text(game.game_watch_run()) !== "r1") throw Error(`watching named ${text(game.game_watch_run())}`);
for (let frames = 0; game.game_watch_status() === 0; ++frames) {
  if (frames > 2000) throw Error("the replay never ended");
  frame({ taps: frames % 10 ? [] : [PAGE_DOWN] });
}
if (game.game_watch_status() !== 1) throw Error("the board's run did not play as recorded");
frame({ taps: [ESCAPE] });
waitFor("the return to the scores", () => game.game_state() === HIGHSCORES && game.game_watch_status() === -1);
if (text(game.game_watch_run()) !== "") throw Error("game_watch_run stayed set after leaving Watch");

// A run gone from the leaderboard: no Watch.
click(ROWS[1]);
for (let i = 0; i < 10; ++i) frame();
if (requests.shift() !== REPLAY || text(game.game_replay_download()) !== "gone") throw Error("the card did not ask for the second run");
game.game_replay_downloaded(1);
click(WATCH);
for (let i = 0; i < 120; ++i) frame();
if (game.game_watch_status() !== -1) throw Error("a run gone from the leaderboard plays");
if (requests.length) throw Error("the card asked again for a run the leaderboard no longer has");

// A failed download is asked for again once the row is pinned again, and the
// twin row asks for its own run.
const download = (row) => {
  click(row);
  for (let i = 0; i < 10; ++i) frame();
  if (requests.shift() !== REPLAY || requests.length) throw Error("the card did not ask for the run once");
  return text(game.game_replay_download());
};
const twin = download(ROWS[2]);
game.game_replay_downloaded(2);
click(ROWS[2]);
if (download(ROWS[2]) !== twin) throw Error("the retry asked for another run");
game.game_replay_downloaded(2);
const other = download(ROWS[3]);
game.game_replay_downloaded(2);
if ([twin, other].sort().join() !== "twin-a,twin-b") throw Error(`the twin rows asked for ${twin} and ${other}`);

// Update scores fetches the board again and replaces its runs: the first
// run's row pins and plays without another fetch.
click(UPDATE);
waitFor("Update scores", () => requests.length);
answerScores([score("r1", "pilot", 135302)]);
for (let i = 0; i < 30; ++i) frame();
click(ROWS[0]);
click(WATCH);
waitFor("the replay again", () => game.game_watch_status() === 0);
if (requests.length) throw Error(`watching again asked for ${requests.join()}`);
frame({ taps: [ESCAPE] });
waitFor("the return to the scores", () => game.game_state() === HIGHSCORES);

// The import moved the table aside, and its local row is the one score, as the Python port reads the table.
if (fs.existsSync(table)) throw Error("the original's table was not imported");
const imported = path.join(directory, "scores5/imported/survival.hi");
if (!fs.readFileSync(imported).equals(originalTable)) throw Error("the imported table changed");
const same = "import sys; from pathlib import Path; from crimson.persistence.highscores import read_highscore_records; " +
  "from crimson.persistence.scores5 import read_original_records; " +
  "print(read_highscore_records(Path(sys.argv[1])) == read_original_records(Path(sys.argv[2])))";
if (execFileSync("uv", ["run", "--no-sync", "python", "-c", same, directory, imported], { encoding: "utf8" }).trim() !== "True")
  throw Error(`the scores are ${fs.readFileSync(path.join(directory, "scores.jsonl"), "utf8")}`);
const replays = fs.readdirSync(path.join(directory, "replays"), { recursive: true }).filter((name) => name.endsWith(".crd"));
if (replays.join() !== path.join("online", "r1.crd")) throw Error(`the replays are ${replays.join(", ")}`);

// Two players: the game closes and starts again for two players, Show internet scores ticked.
game.game_close();
try {
  run.frame(16);
  throw Error("the game did not quit");
} catch (error) {
  if (!/the game quit/.test(error.message)) throw error;
}
game.game_exit();
const change = "import sys; from pathlib import Path; from grim.config import load_crimson_cfg; " +
  "c = load_crimson_cfg(Path(sys.argv[1]) / 'crimson.cfg'); c.gameplay.player_count = 2; " +
  "c.profile.show_internet_scores = True; c.save()";
execFileSync("uv", ["run", "--no-sync", "python", "-c", change, directory]);
run = bootGame(gameWasm, directory, 1, { leaderboard: true, requests });
game = run.game;
while (run.clock < 15000) frame();
click(STATISTICS);
waitFor("the Statistics menu", () => game.game_state() === STATISTICS_MENU);
click(HIGH_SCORES);
waitFor("the two players' high scores", () => game.game_state() === HIGHSCORES && requests.length);
const asked = text(game.game_scores_request());
if (asked !== '{"board": "survival-coop", "quest": ""}') throw Error(`the two players' table asked for ${asked}`);
answerScores([score("pair", "banteg & razenpok", 90000)]);
for (let i = 0; i < 30; ++i) frame();
click(ROWS[0]);
for (let i = 0; i < 10; ++i) frame();
if (requests.shift() !== REPLAY || text(game.game_replay_download()) !== "pair") throw Error("the pair's run is not on the table");
console.log(JSON.stringify({ watched: 2 }));
