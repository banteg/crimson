// The main menu's Mods entry as the custom quest browser (host/custom_quests.inc),
// as the browser host serves it: inside another site's page, which ranks no
// runs, the entry is gone; otherwise it opens the browser, which asks for the
// newest page each time it opens, says so when the leaderboard can't be
// reached, pages with the arrow keys and sorts by Most played. Watch proof
// plays the clear that published the quest. The pad's d-pad walks the rows and
// A plays one. Play asks for the quest's table, asks again after a failed
// fetch, and starts the quest from quests/online/<id>.bin under its title and
// byline.
//
//   node crimson-core/checks/game_custom.mjs <game directory> [game.wasm]
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CORE } from "./engine.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const ROOT = new URL("..", CORE).pathname;
const [directory, gameWasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_custom.mjs <game directory> [game.wasm]");

// game_state_id_t, HOST_LEADERBOARD_* (game/leaderboard_requests.h), DirectInput scancodes.
const [MAIN_MENU, GAMEPLAY, MODS_MENU] = [0, 9, 20];
const [REPLAY, CUSTOM, QUEST] = [4, 5, 6];
const [ESCAPE, LEFT, RIGHT] = [0x01, 0xcb, 0xcd];
// The pad as the host lays it out (game/host_input.h): A by index, the d-pad's down as the hat, in hundredths of a degree.
const [PAD_SOUTH, HAT_DOWN] = [1, 18000];
// Where a fresh 1024x768 profile lays these out: the main menu's Mods, the
// browser's Most played box, its first two rows, Play and Watch proof, and a
// spot clear of the panels.
const MODS = [230, 270], POPULAR = [261, 276], ROWS = [301, 321].map((y) => [184, y]), PLAY = [726, 422];
const PROOF = [845, 422];
const CLEAR = [600, 700];

let run, game;
const requests = [];
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
function click(at, settle = 30) {
  for (let i = 0; i < settle; ++i) frame({ cursor: at });
  for (let i = 0; i < 5; ++i) frame({ cursor: at, buttons: 1 });
  frame({ cursor: at });
}
function frames(n, options) {
  for (let i = 0; i < n; ++i) frame(options);
}
function tap(key) {
  frame({ taps: [key] });
  frames(3);
}
// A pad press for a few frames, then a release.
function padTap({ press = [], hat = 0xffffffff }) {
  for (let i = 0; i < 6; ++i) {
    const input = run.input();
    input.setUint8(INPUT.pad_connected, 1);
    input.setUint32(INPUT.pad_hat, i < 3 ? hat : 0xffffffff, true);
    input.setUint8(INPUT.pad_buttons + PAD_SOUTH, i < 3 && press.includes(PAD_SOUTH) ? 0x80 : 0);
    frame();
  }
}
function waitFor(what, done, limit = 600) {
  for (let n = 0; !done(); ++n) {
    if (n > limit) throw Error(`${what} never happened`);
    frame();
  }
}
const memory = () => Buffer.from(game.memory.buffer);
const text = (at) => memory().toString("latin1", at, memory().indexOf(0, at));
function boot(leaderboard) {
  run = bootGame(gameWasm, directory, 1, { leaderboard, requests });
  game = run.game;
  // On a fresh profile the main menu shares its screen id with the startup sequence.
  while (run.clock < 15000) frame();
}

// The page the browser asks for, answered with `quests` (service/src/views.ts
// gameCustomQuests), or as a failed fetch.
function asked(body) {
  proofs();
  if (requests.shift() !== CUSTOM || requests.length) throw Error("the browser asked for no page");
  const request = text(game.game_custom_request());
  if (request !== body) throw Error(`the browser asked for ${request}`);
}
function answer(quests, more = false) {
  const body = JSON.stringify({ quests, more });
  memory().write(body, game.game_custom_buffer(body.length), "latin1");
  game.game_custom_received(body.length);
  frames(10);
}

// The quest the service test publishes and the clear that published it, its
// table and replay as the site serves them.
const published = JSON.parse(fs.readFileSync(path.join(ROOT, "service/test/vectors.json"), "utf8")).custom_quest_run;
const proof = Buffer.from(published.file, "base64");
const table = execFileSync(
  "uv",
  [
    "run", "--no-sync", "python", "-c",
    "import sys; from crimson.replay.codec import load_replay; " +
      "sys.stdout.buffer.write(load_replay(sys.stdin.buffer.read()).run.custom_quest.to_portable_bytes())",
  ],
  { input: proof, maxBuffer: 1 << 20 },
);
// The proof the detail panel shows asks for its replay, which the host fetches into replays/online/.
function proofs() {
  while (requests[0] === REPLAY) {
    requests.shift();
    const run = text(game.game_replay_download());
    if (run !== published.run_id) throw Error(`the panel asked for the replay of ${run}`);
    fs.mkdirSync(path.join(directory, "replays/online"), { recursive: true });
    fs.writeFileSync(path.join(directory, `replays/online/${run}.crd`), proof);
    game.game_replay_downloaded(0);
  }
}
const quest = (id, title) => ({
  id, title, author: "banteg", players: 2, proof: published.run_id, start_weapon_id: 3,
  no_bonuses: [3], no_perks: [9, 16], no_weapons: [2, 3], best: [{ name: "banteg", score: 41250 }],
});
const page = [quest("000000000001", "Gone"), quest("06c4073e94c5", "Quick Clear")];

// Inside another site's page there is no Mods entry: the spot it takes opens nothing.
boot("framed");
click(MODS);
frames(60);
if (game.game_state() !== MAIN_MENU || requests.length) throw Error("the Mods entry shows inside another site's page");

boot(true);
click(MODS);
waitFor("the browser", () => game.game_state() === MODS_MENU && requests.length);
asked('{"sort": "newest", "page": 0}');
game.game_custom_received(-1);
frames(10);
// Back, and in again: the browser asks afresh.
frame({ taps: [ESCAPE] });
waitFor("the main menu", () => game.game_state() === MAIN_MENU);
click(MODS);
waitFor("the browser again", () => game.game_state() === MODS_MENU && requests.length);
asked('{"sort": "newest", "page": 0}');
answer(page, true);
// The arrow keys page, as far as there are pages; Most played asks for its first.
tap(RIGHT);
asked('{"sort": "newest", "page": 1}');
answer([quest("000000000002", "Next")]);
tap(RIGHT);
if (requests.length) throw Error("the browser paged past its last page");
tap(LEFT);
asked('{"sort": "newest", "page": 0}');
answer(page, true);
click(POPULAR);
asked('{"sort": "popular", "page": 0}');
answer(page, true);

// Watch proof plays the creator's clear, and leaving it comes back to the menus.
frames(10);
proofs();
click(PROOF);
waitFor("the proof", () => game.game_watch_status() === 0);
if (text(game.game_watch_run()) !== published.run_id) throw Error(`watching named ${text(game.game_watch_run())}`);
frame({ taps: [ESCAPE] });
waitFor("the end of the proof", () => game.game_watch_status() === -1 && game.game_state() !== GAMEPLAY);
// The high scores, as after any replay, then back to the main menu.
for (let n = 0; game.game_state() !== MAIN_MENU; ++n) {
  if (n > 5) throw Error("Escape never reached the main menu");
  frame({ taps: [ESCAPE] });
  frames(60);
}
click(MODS);
waitFor("the browser once more", () => game.game_state() === MODS_MENU && requests.length);
asked('{"sort": "popular", "page": 0}');
answer(page, true);

// Play: the pad steps from Most played down the rows and A plays the second
// quest; a failed fetch is asked for again, and a quest the leaderboard no
// longer has starts nothing.
const tableAsked = () => {
  proofs();
  if (requests.shift() !== QUEST || requests.length) throw Error("Play asked for no table");
  return text(game.game_quest_download());
};
frames(60);
padTap({ hat: HAT_DOWN });
padTap({ hat: HAT_DOWN });
padTap({ press: [PAD_SOUTH] });
if (tableAsked() !== "06c4073e94c5") throw Error("the pad played another quest");
game.game_quest_downloaded(2);
frames(60);
const play = (row) => {
  click(row);
  click(PLAY);
  return tableAsked();
};
if (play(ROWS[0]) !== "000000000001") throw Error("Play asked for another quest");
game.game_quest_downloaded(1);
frames(60);
if (game.game_state() !== MODS_MENU) throw Error("a quest the leaderboard no longer has started");
if (play(ROWS[1]) !== "06c4073e94c5") throw Error("Play did not ask again after a failed fetch");
fs.mkdirSync(path.join(directory, "quests/online"), { recursive: true });
fs.writeFileSync(path.join(directory, "quests/online/06c4073e94c5.bin"), table);
game.game_quest_downloaded(0);
waitFor("the quest", () => game.game_state() === GAMEPLAY);
const named = [text(game.game_custom_quest_title()), text(game.game_custom_quest_author())];
if (named.join() !== "Quick Clear,banteg") throw Error(`the quest started as ${named.join(" by ")}`);
console.log(JSON.stringify({ played: named[0] }));
