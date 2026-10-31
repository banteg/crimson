// The main menu's Mods entry as the custom quest browser (host/custom_quests.inc),
// as the browser host serves it: inside another site's page, which ranks no
// runs, the entry is gone; otherwise it opens the browser, which asks for the
// first page each time it opens and says so when the leaderboard can't be
// reached. The arrow keys scroll the list, which asks for the next page as it
// nears the end and stops once there is none. The pad's d-pad walks the list
// and A plays a quest. Play asks for the quest's table, asks again after a
// failed fetch, and starts the quest from quests/online/<id>.bin under its
// title and byline; leaving the browser meanwhile drops it.
//
// Each page names the build whose boards it counts the quests' clears on, the
// Play Game menu's 1.9.8 box's, and the browser takes an answer only for that
// build. One without a build is 1.9.93's, the only one a service from before
// builds has: the browser takes it with the box unticked and, ticked, takes
// neither it nor one naming 1.9.93, but one naming 1.9.8, whose quests play by
// 1.9.8's rules. A link to a custom quest (game_custom_quest_play) plays it by
// the rules of the build it names, as the game starts, and leaves the menus on
// 1.9.93's. Left, its run's replay holds the quest it played, written as the
// Python port writes it. Cleared, Quest Results' Play Next starts the player's
// own run on their own settings: on a menu of two players on 1.9.93, the
// original's own Survival for both on 1.9.93's rules, which no session records.
//
//   node crimson-core/checks/game_custom.mjs <game directory> [game.wasm]
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CL_BUILD_1_9_8, CL_BUILD_1_9_93, CORE, field, names, state } from "./engine.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const ROOT = new URL("..", CORE).pathname;
const [directory, gameWasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_custom.mjs <game directory> [game.wasm]");

// game_state_id_t, game_mode_id_t, HOST_LEADERBOARD_* (game/leaderboard_requests.h), DirectInput scancodes.
const [MAIN_MENU, PLAY_GAME_MENU, PAUSE_MENU, QUEST_RESULTS, GAMEPLAY, MODS_MENU] = [0, 1, 5, 8, 9, 20];
const SURVIVAL = 1;
const [CUSTOM, QUEST] = [5, 6];
const [ESCAPE, DOWN] = [0x01, 0xd0];
// The pad as the host lays it out (game/host_input.h): A by index, the d-pad's down as the hat, in hundredths of a degree.
const [PAD_SOUTH, HAT_DOWN] = [1, 18000];
// Where a fresh 1024x768 profile lays these out: the main menu's Mods, the
// browser's first two rows and Play, and a spot clear of the panels.
const MODS = [230, 270], ROWS = [296, 316].map((y) => [150, y]), PLAY = [191, 522], CLEAR = [600, 700];
// The main menu's Play Game, and its panel's 1.9.8 box, left of Ranked.
const PLAY_GAME = [240, 338], RULES_1_9_8 = [210, 489];

let run, game;
const requests = [];
// A frame: the cursor as DirectInput motion, a mouse button, `keys` held for the frame and `taps` delivered as presses.
let held = [];
function frame({ cursor = CLEAR, buttons = 0, taps = [], keys = [] } = {}) {
  const input = run.input();
  for (const key of held) input.setUint8(INPUT.keys + key, 0);
  for (const key of (held = keys)) input.setUint8(INPUT.keys + key, 0x80);
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
// The build a run plays by, of a snapshot taken once it has started.
function build() {
  frames(60);
  state(game);
  return field(game, "globals.portable_cl_build");
}
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

// The page the browser asks for, on `build`'s boards, answered with `quests` (service/src/views.ts
// gameCustomQuests) on the boards of the build the answer names (null for none), or as a failed fetch.
function asked(page, build = "1.9.93") {
  if (requests.shift() !== CUSTOM || requests.length) throw Error("the browser asked for no page");
  const request = text(game.game_custom_request());
  if (request !== `{"page": ${page}, "build": "${build}"}`) throw Error(`the browser asked for ${request}`);
}
function answer(quests, more = false, build = "1.9.93") {
  const body = JSON.stringify(build === null ? { quests, more } : { build, quests, more });
  memory().write(body, game.game_custom_buffer(body.length), "latin1");
  game.game_custom_received(body.length);
  frames(10);
}

// A replay file's quest table, as the Python port reads it. Its codec takes a replay only in the form it writes
// itself, every map's keys in its order, which the service's decoder requires too (service/src/replay.ts).
const replayRun = (replay) => {
  const out = execFileSync(
    "uv",
    [
      "run", "--no-sync", "python", "-c",
      "import sys; from crimson.replay.codec import load_replay; run = load_replay(sys.stdin.buffer.read()).run; " +
        "sys.stdout.buffer.write(int(run.cl_build).to_bytes(4, 'little') + run.custom_quest.to_portable_bytes())",
    ],
    { input: replay, maxBuffer: 1 << 20 },
  );
  return { cl_build: out.readUInt32LE(0), table: out.subarray(4) };
};
// The quest the service test publishes, its table as the site serves it.
const published = JSON.parse(fs.readFileSync(path.join(ROOT, "service/test/vectors.json"), "utf8")).custom_quest_run;
const table = replayRun(Buffer.from(published.file, "base64")).table;
const quest = (id, title, start_weapon_id = 3) => ({
  id, title, author: "banteg", players: 2, start_weapon_id, no_bonuses: [3], no_perks: [9, 16], no_weapons: [2, 3],
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
// nothing. The first starts with one of the weapons past the droppable ones.
frame({ taps: [ESCAPE] });
waitFor("the main menu", () => game.game_state() === MAIN_MENU);
open();
asked(0);
// From a service before builds, whose answer names none: 1.9.93's.
answer([quest("000000000001", "Gone", 41), quest("06c4073e94c5", "Quick Clear")], false, null);
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
// Back while the table downloads: the quest waits for another Play, which
// starts it from the table here.
fs.mkdirSync(path.join(directory, "quests/online"), { recursive: true });
fs.writeFileSync(path.join(directory, "quests/online/06c4073e94c5.bin"), table);
frame({ taps: [ESCAPE] });
game.game_quest_downloaded(0);
waitFor("the main menu", () => game.game_state() === MAIN_MENU);
frames(60);
if (game.game_state() !== MAIN_MENU) throw Error("a quest started after leaving the browser");
open();
asked(0);
answer([quest("000000000001", "Gone", 41), quest("06c4073e94c5", "Quick Clear")]);
click(ROWS[1]);
click(PLAY);
if (requests.length) throw Error("Play asked for a table it has");
waitFor("the quest", () => game.game_state() === GAMEPLAY);
const named = [text(game.game_custom_quest_title()), text(game.game_custom_quest_author())];
if (named.join() !== "Quick Clear,banteg") throw Error(`the quest started as ${named.join(" by ")}`);
if (build() !== CL_BUILD_1_9_93) throw Error("the quest Play started with the box unticked plays another build");

// The 1.9.8 box ticked: the browser asks for 1.9.8's boards, and takes neither an answer naming no build nor one naming
// 1.9.93, whose quest Play starts nothing, but one naming 1.9.8, whose quest plays by 1.9.8's rules.
boot(true);
click(PLAY_GAME);
waitFor("the Play Game menu", () => game.game_state() === PLAY_GAME_MENU);
click(RULES_1_9_8);
frame({ taps: [ESCAPE] });
waitFor("the main menu", () => game.game_state() === MAIN_MENU);
const ignored = [null, "1.9.93"];
for (const other of ignored) {
  open();
  asked(0, "1.9.8");
  answer([quest("06c4073e94c5", "Quick Clear")], false, other);
  click(ROWS[0]);
  click(PLAY);
  frames(60);
  if (game.game_state() !== MODS_MENU || requests.length) throw Error(`1.9.8's browser took an answer naming ${other}`);
  frame({ taps: [ESCAPE] });
  waitFor("the main menu", () => game.game_state() === MAIN_MENU);
}
open();
asked(0, "1.9.8");
answer([quest("06c4073e94c5", "Quick Clear")], false, "1.9.8");
click(ROWS[0]);
click(PLAY);
waitFor("1.9.8's quest", () => game.game_state() === GAMEPLAY);
if (build() !== CL_BUILD_1_9_8) throw Error("the quest Play started with the box ticked plays another build");

// A link to the quest on 1.9.8's boards, as the game starts, plays by 1.9.8's rules; leaving it, the browser asks for
// 1.9.93's boards.
run = bootGame(gameWasm, directory, 1, { leaderboard: true, requests });
game = run.game;
memory().set(table, game.portable_quest());
if (game.game_custom_quest_play(CL_BUILD_1_9_8) !== 1) throw Error("the link's quest does not start");
waitFor("the linked quest", () => game.game_state() === GAMEPLAY, 3000);
const linked = build();
if (linked !== CL_BUILD_1_9_8) throw Error(`the quest linked on 1.9.8's boards plays ${linked}`);
frame({ taps: [ESCAPE] });
waitFor("the pause menu", () => game.game_state() === PAUSE_MENU);
frames(60);
padTap({ hat: HAT_DOWN });
padTap({ press: [PAD_SOUTH] });
waitFor("the main menu", () => game.game_state() === MAIN_MENU, 3000);
// The run left saved its replay, the first numbered one in a fresh game folder, which the Python port reads back as
// the quest the link played.
const saved = replayRun(fs.readFileSync(path.join(directory, "replays/1-quest.crd")));
if (!saved.table.equals(table)) throw Error("the linked quest's replay holds another quest");
if (saved.cl_build !== CL_BUILD_1_9_8) throw Error(`the quest linked on 1.9.8's boards recorded ${saved.cl_build}`);
open();
asked(0);

// Two players on 1.9.93 in the player's own menu, and the link's quest cleared on 1.9.8's boards: Quest Results' Play
// Next starts the player's own run, the menu's Survival for both players on 1.9.93's rules, which the original sets up
// itself rather than a session of the one player the quest had. The pad the scenes above pressed gave player one its
// profile; the stock controls play the quest by the mouse.
execFileSync("uv", [
  "run", "--no-sync", "python", "-c",
  "import sys; from pathlib import Path; from grim.config import default_crimson_cfg, load_crimson_cfg; " +
    "c = load_crimson_cfg(Path(sys.argv[1]) / 'crimson.cfg'); c.gameplay.player_count = 2; " +
    "c.controls = default_crimson_cfg().controls; c.save()",
  directory,
]);
run = bootGame(gameWasm, directory, 1, { leaderboard: true, requests });
game = run.game;
memory().set(table, game.portable_quest());
if (game.game_custom_quest_play(CL_BUILD_1_9_8) !== 1) throw Error("the link's quest does not start for two players' menu");
waitFor("the linked quest", () => game.game_state() === GAMEPLAY, 3000);
// The mouse aims at the quest's one creature and fires until the quest ends.
const CREATURES = names.filter((name) => /^creatures\[\d+\]\.active$/.test(name)).length;
function aim() {
  state(game);
  const f = (name) => field(game, name, true);
  for (let i = 0; i < CREATURES; ++i)
    if (field(game, `creatures[${i}].active`) && f(`creatures[${i}].health`) > 0)
      return [f(`creatures[${i}].pos_x`) + f("globals.camera_offset_x"), f(`creatures[${i}].pos_y`) + f("globals.camera_offset_y")];
  return CLEAR;
}
for (let n = 0; game.game_state() === GAMEPLAY; ++n) {
  if (n > 3000) throw Error("the linked quest never ended");
  frame({ cursor: aim(), buttons: 1 });
}
waitFor("Quest Results", () => game.game_state() === QUEST_RESULTS);
// The final time shows, the name field below Ok takes A as Enter, and A then presses Play Next, the first button.
frames(300);
padTap({ hat: HAT_DOWN });
padTap({ press: [PAD_SOUTH] });
frames(60);
padTap({ press: [PAD_SOUTH] });
waitFor("the run Play Next starts", () => game.game_state() === GAMEPLAY);
frames(60);
// The second player's keys, the arrows, walk it down, and no session records the run.
state(game);
const [walkedFrom, recording] = [field(game, "players[1].pos_y", true), game.game_replay_size()];
for (let i = 0; i < 60; ++i) frame({ keys: [DOWN] });
frame();
state(game);
const next = {
  mode: game.game_play_mode(),
  walked: Math.round(field(game, "players[1].pos_y", true) - walkedFrom),
  build: field(game, "globals.portable_cl_build"),
  recorded: game.game_replay_size() - recording,
};
if (next.mode !== SURVIVAL) throw Error(`Play Next past the linked quest plays mode ${next.mode}`);
if (next.walked <= 0) throw Error("Play Next past the linked quest plays no second player");
if (next.build !== CL_BUILD_1_9_93) throw Error(`Play Next past the linked quest plays ${next.build}`);
if (next.recorded) throw Error(`Play Next past the linked quest plays as a session, which recorded ${next.recorded} bytes`);
console.log(JSON.stringify({ played: named[0], other_builds_ignored: ignored.length, linked, recorded: saved.cl_build, next }));
