// The profile the runs the original sets up itself play (host/session.inc):
// the player's own, the current rules with the documented fixes on the Play
// Game menu's 1.9.8 box's build, whatever the game's last run or replay
// played, with what the game derives from the build once (host.cpp
// portable_profile_set).
//
// As the game starts, before any run, it knows each weapon's shot sound, which
// 1.9.8's Fire Bullets reroll reads (host.cpp weapon_shot_slots): weapons share
// one exactly where the Python port's give them one first fire sound, and no
// run changes them. The tutorial started then with the box ticked plays 1.9.8's
// perk range, the Python port's perk_id_max (src/crimson/perks/availability.py),
// under the fixes, its players' Fire Cough and Hot Tempered intervals starting
// afresh, no Shock Chain (original bug 32) and Lean Mean Exp Machine's tick at
// 0, whatever the game held before. A replay on the 1.9.8 rules that keeps
// 1.9.8's bugs plays 1.9.8's perk range and its bugs; the tutorial after it,
// with the box unticked, plays 1.9.93's under the fixes, again with no Shock
// Chain, and ticked, by the pad that reaches it under the modes, 1.9.8's, after
// a replay on 1.9.93's. While a replay plays, a score card names the rules of
// its build, not the box's, as the Python port's card does
// (src/crimson/ui/highscore_card.py). Typ-o, which the original sets up too,
// draws its names' fragments from its build's table, the Python port's
// typo_fragments (src/crimson/typo/names.py), the last "the", and its high
// score names from its build's Typ-o table, as the Python port's TypoSession
// keeps them through the same runs (src/crimson/typo/state.py): the game loads
// them at a run's first pick and keeps them while its Typ-o runs stay on that
// build, whatever other modes play between them, and a Typ-o run on another
// build than the last drops them and loads its own.
//
// Each build keeps its own high scores (host/scores.inc): a Survival run on
// each, which the player stands through until it dies, saves its name, and the
// high score screen shows each build's table with the box set to it, the run on
// that build alone: its first row's Watch plays it. The screen draws a title
// that names 1.9.8's table and keeps the original's for 1.9.93's, and a card's
// origin line the Python port's for the build.
//
//   node crimson-core/checks/game_rules.mjs <game directory> [game.wasm]
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { CL_BUILD_1_9_8, CL_BUILD_1_9_93, CORE, field, state } from "./engine.mjs";
import { bootGame, INPUT, streamReplay } from "./game_host.mjs";

const [directory, gameWasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!directory) throw Error("usage: game_rules.mjs <game directory> [game.wasm]");
const python = (code, ...args) => execFileSync("uv", ["run", "--no-sync", "python", "-c", code, ...args], { encoding: "utf8" });

// Typ-o shows on the Play Game panel with the campaign's 40 quests unlocked.
python(
  "import sys; from pathlib import Path; from crimson.persistence.save_status import GameStatusData, save_status; " +
    "save_status(Path(sys.argv[1]) / 'game.cfg', GameStatusData(quest_unlock_index=40))",
  directory,
);
const run = bootGame(gameWasm, directory, 1);
const { game } = run;
const memory = () => Buffer.from(game.memory.buffer);
const text = (at) => Buffer.from(memory().subarray(at, memory().indexOf(0, at))).toString("latin1");

// game_state_id_t
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, STATISTICS = 4, PAUSE_MENU = 5, GAME_OVER = 7, GAMEPLAY = 9, HIGHSCORES = 14,
  TYPO = 18;
const ESCAPE = 0x01;
// The pad (game/host_input.h): A, and the d-pad as the hat, in hundredths of a degree.
const PAD_SOUTH = 1, HAT_DOWN = 18000, HAT_LEFT = 27000;
// The main menu's Play Game. With 40 quests unlocked and none played the panel lays out the Tutorial, Quests, Rush,
// Survival and Typ-o 28 pixels apart, and without the leaderboard the 1.9.8 box sits where Ranked would.
const PLAY_GAME = [240, 338], TUTORIAL = [232, 312], TYPO_SHOOTER = [232, 424], BOX = [298, 489];
// Survival there, and once a Survival run has played, which moves the Tutorial below Typ-o (play_game_menu_update).
const SURVIVAL = [232, 396], SURVIVAL_PLAYED = [232, 368];
// The main menu's Statistics, its High scores, the table's first row and the pinned card's Watch.
const STATISTICS_ENTRY = [200, 458], HIGH_SCORES = [275, 316], FIRST_ROW = [180, 305], WATCH = [745, 421];
// A pad player's mouse rests where it covers no widget.
const REST = [1000, 740];

function frame({ cursor = REST, button = false, taps = [], pad = null } = {}) {
  const input = run.input();
  for (const key of taps) {
    const n = input.getInt32(INPUT.event_count, true);
    input.setUint8(INPUT.events + n * 2, key);
    input.setUint8(INPUT.events + n * 2 + 1, 1);
    input.setInt32(INPUT.event_count, n + 1, true);
  }
  input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(cursor[0])), true);
  input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(cursor[1])), true);
  input.setUint8(INPUT.buttons, button ? 0x80 : 0);
  input.setUint8(INPUT.pad_connected, pad ? 1 : 0);
  input.setUint32(INPUT.pad_hat, pad?.hat ?? 0xffffffff, true);
  for (let b = 0; b < 32; ++b) input.setUint8(INPUT.pad_buttons + b, pad?.press?.includes(b) ? 0x80 : 0);
  run.frame(16);
}
// Waits on a screen until it settles.
function settle(screen, input = {}) {
  for (let settled = 0, frames = 0; settled < 60; ++frames) {
    if (frames > 3000) throw Error(`screen ${screen} never settled (on ${game.game_state()})`);
    frame(input);
    settled = game.game_state() === screen ? settled + 1 : 0;
  }
}
// Holds the cursor on a spot of a settled screen, then clicks it.
function click(screen, at) {
  settle(screen, { cursor: at });
  for (let i = 0; i < 5; ++i) frame({ cursor: at, button: true });
  frame({ cursor: at });
}
// A pad press for a few frames, then a release.
function tap(pad) {
  for (let i = 0; i < 6; ++i) frame({ pad: i < 3 ? pad : {} });
}
// The run the original sets up as a mode's button on the Play Game panel starts it, past its fade.
function start(button, screen) {
  if (game.game_state() === MAIN_MENU) click(MAIN_MENU, PLAY_GAME);
  click(PLAY_GAME_MENU, button);
  settle(screen);
}
// The 1.9.8 box ticked or unticked by mouse from the main menu, which leaves the Play Game panel up.
function box() {
  click(MAIN_MENU, PLAY_GAME);
  click(PLAY_GAME_MENU, BOX);
}
// What the run's state plays by: its build and rules (the snapshot's), the perk range, and the bug policy.
function rules() {
  state(game);
  return {
    build: field(game, "globals.portable_cl_build"),
    perks: game.game_perk_id_max(),
    rules: field(game, "globals.portable_rules"),
    bugs: game.game_preserve_bugs(),
  };
}
// Each build's perk range, the one its perk database numbers: the Python port's perk_id_max.
const PERK_ID_MAX = `
import json
from crimson.cl_build import ClBuild
from crimson.perks.availability import perk_id_max
print(json.dumps({int(b): perk_id_max(b) for b in ClBuild}))
`;
const perkIdMax = JSON.parse(python(PERK_ID_MAX));
// The Shock Chain's projectile, of the snapshot rules() took: a fresh game's (host.cpp portable_fresh_game), with original
// bug 32 fixed none, -1, where the original starts at 0, the first projectile slot, and carries the last run's.
const chain = () => field(game, "globals.shock_chain_projectile_id") | 0;
// The player's own profile on `build`: the current rules (REPLAY_RULES), the documented fixes.
const own = (build) => ({ build, perks: perkIdMax[build], rules: 2, bugs: 0 });
function expect(what, actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected))
    throw Error(`${what}: ${JSON.stringify(actual)}, not ${JSON.stringify(expected)}`);
}
// The run plays the player's own profile on `build`; the perk range the game played it by, by build.
const perkRanges = {};
function plays(what, build) {
  const played = rules();
  expect(what, played, own(build));
  perkRanges[build] = played.perks;
}
// The run left for the main menu by its pause menu's second item.
function leave(screen) {
  settle(screen);
  frame({ taps: [ESCAPE] });
  settle(PAUSE_MENU, { pad: {} });
  tap({ hat: HAT_DOWN });
  tap({ press: [PAD_SOUTH] });
  settle(MAIN_MENU);
}
// Each build's label and what a score card's origin line says for its runs, local and from the Internet: the Python
// port's (src/crimson/cl_build.py, ui/highscore_card.py).
const CARDS = `
import json
from crimson.cl_build import ClBuild
from crimson.persistence.highscores import HighScoreRecord
from crimson.ui.highscore_card import _origin_label
print(json.dumps({int(b): [b.label, [_origin_label(HighScoreRecord(cl_build=b, received=r)) for r in (False, True)]] for b in ClBuild}))
`;
const cards = JSON.parse(python(CARDS));
// The origin lines a card would show now (host/scores.inc scores_card_origin).
const origins = () => [0, 1].map((received) => text(game.game_scores_card_origin(received)));
// A replay that started plays until it ticks, by its own profile, its card naming its build's rules; Escape leaves it
// for the high scores, and Escape twice more for the main menu.
function watching(what, profile) {
  for (let frames = 0; game.game_watch_status() !== 0 || game.game_watch_tick() < 60; ++frames) {
    if (frames > 3000) throw Error(`${what} never plays`);
    frame();
  }
  expect(`${what}'s rules`, rules(), profile);
  expect(`${what}'s card`, origins(), cards[profile.build][1]);
  frame({ taps: [ESCAPE] });
  settle(HIGHSCORES);
  frame({ taps: [ESCAPE] });
  settle(STATISTICS);
  frame({ taps: [ESCAPE] });
  settle(MAIN_MENU);
}
// A replay a link plays, from the main menu.
function watch(file, profile) {
  settle(MAIN_MENU);
  memory().write(`${file}\0`, game.game_replay_path(), "latin1");
  if (!game.game_replay_open() || !game.game_watch()) throw Error(`${file} does not start`);
  watching(file, profile);
}

// Each weapon's shot sound as the Python port's weapon table names it (its first fire sound), and whether its holder
// keeps 1.9.8 from picking Fire Bullets (src/crimson/bonuses/selection.py).
const SHOT_SOUNDS = `
import json
from crimson.bonuses.selection import _FIRE_BULLETS_REROLL_SHOT_SFX
from crimson.weapons import WEAPON_BY_ID
sounds = {int(i): w.fire_sounds[0] for i, w in WEAPON_BY_ID.items()}
print(json.dumps({i: [s.value, s in _FIRE_BULLETS_REROLL_SHOT_SFX] for i, s in sounds.items()}))
`;
const sounds = Object.entries(JSON.parse(python(SHOT_SOUNDS))).map(([id, [sound, rerolls]]) => ({
  id: +id,
  sound,
  rerolls,
}));
const slots = () => [...new Int32Array(game.memory.buffer, game.game_weapon_shot_slots(), 64)];
// The weapons the reroll reads alike are those the Python port gives one sound.
function shotSounds(what, held) {
  for (const a of sounds)
    for (const b of sounds)
      if ((held[a.id] === held[b.id]) !== (a.sound === b.sound))
        throw Error(`${what}: weapons ${a.id} and ${b.id} ${a.sound === b.sound ? "share" : "differ in"} a sound in Python`);
  return sounds.filter((w) => w.rerolls).length;
}

// On a fresh profile the main menu shares its screen id with the startup
// sequence, which ends after about 14 s.
while (run.clock < 15000) frame();
const launched = slots();
const rerolling = shotSounds("as the game starts", launched);
const watched = path.join(directory, "watched");
fs.mkdirSync(watched, { recursive: true });
streamReplay("1.9.8-quest-1.5", path.join(watched, "bugs-1.9.8.crd"));
fs.copyFileSync(new URL("../tests/fixtures/replays/quest-1.1-rules2.crd", CORE), path.join(watched, "rules-1.9.93.crd"));

// Lean Mean Exp Machine's tick, which every run's frames count down from a fresh game's 0, restarting at 0.25 below 0,
// whatever its perks. The game holds one no run's countdown reaches as it starts the tutorial.
const leanMean = () => new Float32Array(game.memory.buffer, game.game_lean_mean_timer(), 1);
leanMean()[0] = 1000;
// The tutorial with the box ticked by mouse, before any other run, plays 1.9.8's rules under the fixes; the box
// unticked again after it.
box();
start(TUTORIAL, GAMEPLAY);
plays("the tutorial ticked as the game starts", CL_BUILD_1_9_8);
// The fixes' added player state starts afresh, as it does in every run portable_init sets up.
const intervals = [0, 1].flatMap((p) =>
  ["fire_cough", "hot_tempered"].map((perk) => field(game, `player_rules[${p}].${perk}_interval`, true)),
);
expect("the tutorial's perk intervals", intervals, Array(4).fill(Math.fround(1.4)));
expect("the tutorial's Shock Chain", chain(), -1);
const tick = leanMean()[0];
if (!(tick >= 0 && tick <= 0.25)) throw Error(`the tutorial's Lean Mean Exp Machine tick: ${tick}, not one counted from 0`);
leave(GAMEPLAY);
box();
frame({ taps: [ESCAPE] });
settle(MAIN_MENU);
// The tutorial after a 1.9.8 replay that keeps 1.9.8's bugs plays 1.9.93's rules with the box unticked, under the
// fixes.
watch("watched/bugs-1.9.8.crd", { ...own(CL_BUILD_1_9_8), bugs: 1 });
start(TUTORIAL, GAMEPLAY);
plays("the tutorial after a 1.9.8 replay with its bugs", CL_BUILD_1_9_93);
expect("the Shock Chain of the tutorial after a replay with the bugs", chain(), -1);
leave(GAMEPLAY);
// And after a 1.9.93 replay, 1.9.8's with the box ticked by the pad: left to the Tutorial, down past Quests, Rush,
// Survival and Typ-o, and A.
watch("watched/rules-1.9.93.crd", own(CL_BUILD_1_9_93));
click(MAIN_MENU, PLAY_GAME);
settle(PLAY_GAME_MENU, { pad: {} });
tap({ hat: HAT_LEFT });
for (let i = 0; i < 5; ++i) tap({ hat: HAT_DOWN });
tap({ press: [PAD_SOUTH] });
settle(PLAY_GAME_MENU);
start(TUTORIAL, GAMEPLAY);
plays("the tutorial with the box ticked", CL_BUILD_1_9_8);
leave(GAMEPLAY);

// Typ-o draws a fragment from each random state, by its build's table: the module's typo_word_pick_fragment under
// the run's build, and the Python port's typo_name_part, for every draw of the first n + 1 (`extended` takes "the",
// the last fragment; without it the table ends before it).
const FRAGMENTS = `
import json, sys
from grim.rand import Crand
from crimson.cl_build import ClBuild
from crimson.typo.names import typo_fragments, typo_name_part
build, states = ClBuild(int(sys.argv[1])), json.loads(sys.argv[2])
fragments = typo_fragments(build)
print(json.dumps([len(fragments), [[typo_name_part(Crand(s), fragments=fragments, allow_the=bool(e)) for s in states] for e in (0, 1)]]))
`;
// The state whose next draw is `r` (crt_rand: state * 214013 + 2531011, the draw its bits 16 to 30).
const INVERSE = (() => {
  let x = 1n;
  for (let i = 0; i < 5; ++i) x = (x * (2n - 214013n * x)) % 2n ** 32n;
  return (x + 2n ** 32n) % 2n ** 32n;
})();
const before = (r) => Number(((((BigInt(r) << 16n) - 2531011n) % 2n ** 32n + 2n ** 32n) * INVERSE) % 2n ** 32n);
// Typ-o's high score names on a build: those the Python port's run on it picks from each random state, its
// TypoSession the last run's (`session`, empty before the first), which it keeps after the run.
const HIGHSCORE_NAMES = `
import json, sys
from pathlib import Path
import msgspec
from grim.rand import Crand
from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.persistence.highscores import ScoreTable
from crimson.typo.names import TypoHighscoreNames, load_typo_highscore_names
from crimson.typo.state import TypoSession, TypoState
directory, build, states, session = Path(sys.argv[1]), ClBuild(int(sys.argv[2])), json.loads(sys.argv[3]), sys.argv[4]
session = msgspec.json.decode(session, type=TypoSession) if session else TypoSession()
session.start(build)
loaded = session.carry.highscore_names_loaded
table = ScoreTable(GameMode.TYPO, cl_build=build)
names = session.highscore_names if loaded else tuple(load_typo_highscore_names(directory, table))
typo = TypoState(highscore_names=TypoHighscoreNames(names=names, loaded=loaded))
picks = [typo.highscore_names.pick(Crand(s)) for s in states]
session.keep(typo)
print(json.dumps([picks, msgspec.json.encode(session).decode()]))
`;
// Records on each build's Typ-o table, as [build, name, kills].
const TYPO_SCORES = `
import json, sys
from pathlib import Path
from crimson.cl_build import ClBuild
from crimson.game_modes import GameMode
from crimson.persistence.highscores import HighScoreRecord, append_highscore_records
append_highscore_records(Path(sys.argv[1]), [
    HighScoreRecord(name=name, game_mode_id=GameMode.TYPO, cl_build=ClBuild(build), score_xp=kills)
    for build, name, kills in json.loads(sys.argv[2])
])
`;
const typoScores = (...records) => python(TYPO_SCORES, directory, JSON.stringify(records));
const fragmentCounts = {};
const typoNames = [];
let typoSession = "";
function typo(build) {
  start(TYPO_SHOOTER, TYPO);
  plays("Typ-o's rules", build);
  const states = Array.from({ length: 60 }, (_, r) => before(r));
  const [count, expected] = JSON.parse(python(FRAGMENTS, `${build}`, JSON.stringify(states)));
  const drawn = [0, 1].map((extended) => states.map((s) => text(game.game_typo_fragment(s, extended))));
  expect(`Typ-o's fragments on build ${build}`, drawn, expected);
  // The extended pool's table: Python's `count` fragments, its last "the", the next draw back at the first.
  expect(`build ${build}'s last fragment`, [drawn[1][count - 1], drawn[1][count]], ["the", drawn[1][0]]);
  expect(`build ${build}'s fragments`, new Set(drawn[1].slice(0, count)).size, count);
  const names = states.map((s) => text(game.game_typo_highscore_name(s)));
  const [picks, session] = JSON.parse(
    python(HIGHSCORE_NAMES, directory, `${build}`, JSON.stringify(states), typoSession),
  );
  expect(`Typ-o's high score names on build ${build}`, names, picks);
  typoSession = session;
  leave(TYPO);
  fragmentCounts[build] = count;
  typoNames.push([build, [...new Set(names)].sort()]);
}
typoScores([CL_BUILD_1_9_93, "Alpha", 20], [CL_BUILD_1_9_93, "Beta", 10], [CL_BUILD_1_9_8, "Gamma", 20],
  [CL_BUILD_1_9_8, "Epsilon", 10]);
// Ticked, a run loads 1.9.8's names. Unticked, one loads 1.9.93's, which the next keeps after a name joins each table.
typo(CL_BUILD_1_9_8);
box();
typo(CL_BUILD_1_9_93);
typoScores([CL_BUILD_1_9_93, "Delta", 30], [CL_BUILD_1_9_8, "Zeta", 30]);
typo(CL_BUILD_1_9_93);
// Ticked, a run loads 1.9.8's afresh, with the name that joined, and the next on 1.9.8 keeps them after another joins,
// through a tutorial on 1.9.93 between them.
box();
typo(CL_BUILD_1_9_8);
typoScores([CL_BUILD_1_9_8, "Eta", 40]);
box();
start(TUTORIAL, GAMEPLAY);
plays("the tutorial between Typ-o runs on 1.9.8", CL_BUILD_1_9_93);
leave(GAMEPLAY);
box();
typo(CL_BUILD_1_9_8);
// Unticked, a run loads 1.9.93's afresh, with the name that joined.
box();
typo(CL_BUILD_1_9_93);

// A Survival run from the Play Game panel, which plays `build`'s rules, the player standing through it until it dies
// and naming it.
const scores = path.join(directory, "scores.jsonl");
const saved = () => (fs.existsSync(scores) ? fs.readFileSync(scores, "utf8").split("\n").filter(Boolean).length : 0);
function survival(build, button) {
  start(button, GAMEPLAY);
  plays(`a Survival run on build ${build}`, build);
  settle(GAME_OVER);
  const kept = saved();
  for (const char of `${"\b".repeat(32)}${cards[build][0]}\r`) {
    game.game_key_char(char.charCodeAt(0));
    frame();
  }
  for (let frames = 0; saved() === kept; ++frames) {
    if (frames > 120) throw Error(`the name on build ${build} saved no score`);
    frame();
  }
  frame({ taps: [ESCAPE] });
  settle(MAIN_MENU);
}
// The high score screen with the box on `build`: its table holds the run on it alone, its title and its card, as the
// screen draws them, name the build, and its first row's Watch plays the run. 1.9.8's title is 1.9.93's, which the
// screen drew as `original`, with the build's name after it. The lines the screen drew.
function highScores(build, original) {
  click(MAIN_MENU, STATISTICS_ENTRY);
  click(STATISTICS, HIGH_SCORES);
  settle(HIGHSCORES);
  expect(`build ${build}'s table's records`, game.game_highscore_table_count(), 1);
  const title = text(game.game_scores_title_build());
  if (build === CL_BUILD_1_9_8 ? !title.includes(cards[build][0]) : title)
    throw Error(`build ${build}'s table is titled "<mode>${title}"`);
  expect(`build ${build}'s table's card`, origins(), cards[build][1]);
  click(HIGHSCORES, FIRST_ROW);
  game.game_drawn_text();
  frame({ cursor: FIRST_ROW });
  const drawn = text(game.game_drawn_text()).split("\n").filter(Boolean);
  const titled = (line) => !original || (line.endsWith(title) && original.includes(line.slice(0, -title.length)));
  if (!drawn.some(titled) || !drawn.includes(origins()[0]))
    throw Error(`build ${build}'s high score screen draws ${JSON.stringify(drawn)}`);
  click(HIGHSCORES, WATCH);
  watching(`the first row of build ${build}'s table`, own(build));
  return drawn;
}
// Ticked, then unticked.
box();
survival(CL_BUILD_1_9_8, SURVIVAL);
box();
survival(CL_BUILD_1_9_93, SURVIVAL_PLAYED);
const original = highScores(CL_BUILD_1_9_93);
box();
frame({ taps: [ESCAPE] });
settle(MAIN_MENU);
highScores(CL_BUILD_1_9_8, original);
fs.rmSync(watched, { recursive: true });
// The runs and replays since changed none of the shot sounds.
expect("the shot sounds after the runs", slots(), launched);
console.log(
  JSON.stringify({
    perk_ranges: perkRanges,
    typo_fragments: fragmentCounts,
    typo_highscore_names: typoNames,
    fire_bullets_reroll_weapons: rerolling,
  }),
);
