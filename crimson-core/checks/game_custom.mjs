// The main menu's Mods entry as the custom quest browser (host/custom_quests.inc),
// as the browser host serves it: inside another site's page, which ranks no
// runs, the entry is gone; otherwise it opens the browser, which asks for the
// first page each time it opens and says so when the leaderboard can't be
// reached. The arrow keys scroll the list, which asks for the next page as it
// nears the end and stops once there is none. The pad's d-pad walks the list
// and A plays a quest. Play asks for the quest's table, asks again after a
// failed fetch, and starts the quest from quests/online/<id>.bin under its
// title and byline.
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
const [CUSTOM, QUEST] = [5, 6];
const [ESCAPE, DOWN] = [0x01, 0xd0];
// The pad as the host lays it out (game/host_input.h): A by index, the d-pad's down as the hat, in hundredths of a degree.
const [PAD_SOUTH, HAT_DOWN] = [1, 18000];
// Where a fresh 1024x768 profile lays these out: the main menu's Mods, the
// browser's first two rows and Play, and a spot clear of the panels.
const MODS = [230, 270], ROWS = [296, 316].map((y) => [150, y]), PLAY = [191, 522], CLEAR = [600, 700];

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
function frames(n) {
  for (let i = 0; i < n; ++i) frame();
}
function click(at, settle = 30) {
  for (let i = 0; i < settle; ++i) frame({ cursor: at });
  for (let i = 0; i < 5; ++i) frame({ cursor: at, buttons: 1 });
  frame({ cursor: at });
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
function open() {
  click(MODS);
  waitFor("the browser", () => game.game_state() === MODS_MENU && requests.length);
}

// The page the browser asks for, answered with `quests` (service/src/views.ts
// gameCustomQuests), or as a failed fetch.
function asked(page) {
  if (requests.shift() !== CUSTOM || requests.length) throw Error("the browser asked for no page");
  const request = text(game.game_custom_request());
  if (request !== `{"page": ${page}}`) throw Error(`the browser asked for ${request}`);
}
function answer(quests, more = false) {
  const body = JSON.stringify({ quests, more });
  memory().write(body, game.game_custom_buffer(body.length), "latin1");
  game.game_custom_received(body.length);
  frames(10);
}

// The quest the service test publishes, its table as the site serves it.
const published = JSON.parse(fs.readFileSync(path.join(ROOT, "service/test/vectors.json"), "utf8")).custom_quest_run;
const table = execFileSync(
  "uv",
  [
    "run", "--no-sync", "python", "-c",
    "import sys; from crimson.replay.codec import load_replay; " +
      "sys.stdout.buffer.write(load_replay(sys.stdin.buffer.read()).run.custom_quest.to_portable_bytes())",
  ],
  { input: Buffer.from(published.file, "base64"), maxBuffer: 1 << 20 },
);
const quest = (id, title) => ({
  id, title, author: "banteg", players: 2, start_weapon_id: 3, no_bonuses: [3], no_perks: [9, 16], no_weapons: [2, 3],
});
const page = (from, count) => Array.from({ length: count }, (_, i) => quest((from + i).toString(16).padStart(12, "0"), `Quest ${from + i}`));

// Inside another site's page there is no Mods entry: the spot it takes opens nothing.
boot("framed");
click(MODS);
frames(60);
if (game.game_state() !== MAIN_MENU || requests.length) throw Error("the Mods entry shows inside another site's page");

boot(true);
open();
asked(0);
game.game_custom_received(-1);
frames(10);
// Back, and in again: the browser asks afresh.
frame({ taps: [ESCAPE] });
waitFor("the main menu", () => game.game_state() === MAIN_MENU);
open();
asked(0);
answer(page(1, 30), true);
// Scrolling down asks for the next page as the list nears its end, and no more past the last.
for (let i = 0; i < 9 && !requests.length; ++i) tap(DOWN);
if (requests.length) throw Error("the browser asked for more long before the end");
for (let i = 0; i < 20 && !requests.length; ++i) tap(DOWN);
asked(1);
answer(page(31, 2));
for (let i = 0; i < 40; ++i) tap(DOWN);
if (requests.length) throw Error("the browser asked past its last page");

// Play: the pad steps down the list and A plays the second quest; a failed
// fetch is asked for again, and a quest the leaderboard no longer has starts
// nothing.
frame({ taps: [ESCAPE] });
waitFor("the main menu", () => game.game_state() === MAIN_MENU);
open();
asked(0);
answer([quest("000000000001", "Gone"), quest("06c4073e94c5", "Quick Clear")]);
const tableAsked = () => {
  if (requests.shift() !== QUEST || requests.length) throw Error("Play asked for no table");
  return text(game.game_quest_download());
};
frames(60);
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
