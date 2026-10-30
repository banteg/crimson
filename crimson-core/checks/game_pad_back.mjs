// B, a pad's back button, on every screen a pad reaches from the menus
// (game/pad.cpp, changes/escape-back.patch): it presses Escape, which each
// screen takes as its way out. The d-pad and A walk to each screen, and B must
// return to the one before: from Play Game and its quest list, Options and its
// controls screen, the Statistics menu and the high scores, databases and
// credits under it, and a replay being watched. An open list takes B as
// closing it, and a rebind waiting for an axis as its cancel; the screen stays,
// and the next B leaves it. The perk screen, the pause menu and the end screens
// take B in game_session.mjs --pad.
//
//   node crimson-core/checks/game_pad_back.mjs <game directory> [game.wasm]
import fs from "node:fs";
import path from "node:path";
import { CORE } from "./engine.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const [directory, gameWasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_pad_back.mjs <game directory> [game.wasm]");
const run = bootGame(gameWasm, directory, 1, { rtx: true });
const { game } = run;
game.game_render_mode(1);

// game_state_id_t
const MAIN_MENU = 0, PLAY_GAME = 1, OPTIONS = 2, CONTROLS = 3, STATISTICS = 4, QUEST_SELECT = 11, HIGHSCORES = 14,
  WEAPON_DATABASE = 15, PERK_DATABASE = 16, CREDITS = 17;
// The pad as the host lays it out (game/host_input.h): buttons by index, the
// d-pad as the hat, in hundredths of a degree.
const [PAD_SOUTH, PAD_EAST] = [1, 2];
const [HAT_DOWN, HAT_RIGHT, HAT_LEFT] = [18000, 9000, 27000];
// A pad player's mouse rests where it covers no widget.
const PAD_CURSOR = [1000, 740];

function frame(pad = {}) {
  const input = run.input();
  input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(PAD_CURSOR[0])), true);
  input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(PAD_CURSOR[1])), true);
  const { press = [], hat = 0xffffffff } = pad;
  input.setUint8(INPUT.pad_connected, 1);
  input.setUint32(INPUT.pad_hat, hat, true);
  for (let button = 0; button < 32; ++button) input.setUint8(INPUT.pad_buttons + button, press.includes(button) ? 0x80 : 0);
  run.frame(16);
}
// Waits on a screen until it settles.
function settle(screen) {
  for (let settled = 0, frames = 0; settled < 60; ++frames) {
    if (frames > 3000) throw Error(`screen ${screen} never settled (on ${game.game_state()})`);
    frame();
    settled = game.game_state() === screen ? settled + 1 : 0;
  }
}
// A press for a few frames, then a release.
function tap(pad) {
  for (let i = 0; i < 6; ++i) frame(i < 3 ? pad : {});
}
// From a settled screen, `steps` presses of the d-pad from its first widget, then A, to `next`.
function open(screen, steps, next) {
  settle(screen);
  for (const hat of steps) tap({ hat });
  tap({ press: [PAD_SOUTH] });
  settle(next);
}
const down = (n) => Array(n).fill(HAT_DOWN);
// B on `screen` returns to `back`; with `stays`, the first B is taken on the screen and the next leaves.
function back(screen, back, stays) {
  settle(screen);
  tap({ press: [PAD_EAST] });
  if (stays) {
    for (let i = 0; i < 60; ++i) frame();
    if (game.game_state() !== screen) throw Error(`B with ${stays} left screen ${screen} for ${game.game_state()}`);
    tap({ press: [PAD_EAST] });
  }
  for (let frames = 0; game.game_state() !== back; ++frames) {
    if (frames > 600) throw Error(`B on screen ${screen} went to ${game.game_state()}, not ${back}`);
    frame();
  }
}

// On a fresh profile the main menu shares its screen id with the startup
// sequence, which ends after about 14 s.
while (run.clock < 15000) frame();
const checkMode = (available) => {
  if (!!game.game_render_mode_available() !== available) throw Error("wrong render-mode availability");
  const calls = run.calls.render_mode;
  const choice = path.join(directory, "render_mode.txt");
  const saved = fs.existsSync(choice) ? fs.readFileSync(choice, "utf8") : null;
  for (const mode of [0, 1]) {
    game.game_render_choice(mode);
    const expected = available ? (mode ? "rtx\n" : "classic\n") : saved;
    if ((fs.existsSync(choice) ? fs.readFileSync(choice, "utf8") : null) !== expected)
      throw Error("renderer choice did not preserve or save the expected preference");
  }
  if (run.calls.render_mode !== calls + (available ? 2 : 0)) throw Error("render-mode guard failed");
};
checkMode(true);
// The main menu's Play Game, Options and Statistics, top down.
open(MAIN_MENU, [], PLAY_GAME);
checkMode(false);
back(PLAY_GAME, MAIN_MENU);
// The panel starts on its player-count list, which A opens.
open(MAIN_MENU, [], PLAY_GAME);
tap({ press: [PAD_SOUTH] });
back(PLAY_GAME, MAIN_MENU, "the player-count list open");
// Quests, left of the player count and the second of the modes.
open(MAIN_MENU, [], PLAY_GAME);
open(PLAY_GAME, [HAT_LEFT, HAT_DOWN], QUEST_SELECT);
back(QUEST_SELECT, PLAY_GAME);
back(PLAY_GAME, MAIN_MENU);

open(MAIN_MENU, down(1), OPTIONS);
checkMode(true);
back(OPTIONS, MAIN_MENU);
// Controls, the last of the options' widgets.
open(MAIN_MENU, down(1), OPTIONS);
open(OPTIONS, down(5), CONTROLS);
back(CONTROLS, OPTIONS);
// The controls screen starts on its player list, which A opens.
open(OPTIONS, down(5), CONTROLS);
tap({ press: [PAD_SOUTH] });
back(CONTROLS, OPTIONS, "the player list open");
// The first rebind row, right of the lists, binds an axis.
open(OPTIONS, down(5), CONTROLS);
tap({ hat: HAT_RIGHT });
tap({ press: [PAD_SOUTH] });
back(CONTROLS, OPTIONS, "an axis rebind waiting");
back(OPTIONS, MAIN_MENU);

// High scores, the weapon and perk databases and the credits, top down.
for (const [steps, screen] of [[0, HIGHSCORES], [1, WEAPON_DATABASE], [2, PERK_DATABASE], [3, CREDITS]]) {
  open(MAIN_MENU, down(2), STATISTICS);
  open(STATISTICS, down(steps), screen);
  back(screen, STATISTICS);
  back(STATISTICS, MAIN_MENU);
}

// A replay plays from the menu, and B leaves it for the high scores.
settle(MAIN_MENU);
fs.mkdirSync(path.join(directory, "watched"), { recursive: true });
fs.copyFileSync(new URL("../tests/fixtures/replays/quest-1.1-rules2.crd", CORE), path.join(directory, "watched/linked.crd"));
Buffer.from(game.memory.buffer).write("watched/linked.crd\0", game.game_replay_path(), "latin1");
if (!game.game_replay_open() || !game.game_watch()) throw Error("the replay does not start");
for (let frames = 0; game.game_watch_status() !== 0 || game.game_watch_tick() < 120; ++frames) {
  if (frames > 2000) throw Error("the replay never plays");
  frame();
}
tap({ press: [PAD_EAST] });
for (let frames = 0; game.game_state() !== HIGHSCORES || game.game_watch_status() !== -1; ++frames) {
  if (frames > 600) throw Error("B did not leave the replay");
  frame();
}
console.log("B goes back on every screen");
