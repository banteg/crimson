// Plays a run the way the client does: the original boots from a game
// directory (crimson.paq, sfx.paq and music/), its menus start a
// Survival run, and the run plays as a session (host/session.inc). A scripted
// player aims at the nearest creature and fires in bursts, opens the perk menu
// with Space and picks from it (double-clicking, and asking again at once),
// pauses with Escape and resumes, and taps the console key, which a run
// ignores, at frame times that run several ticks a frame or none. After every
// frame of play the verifier replays the run's own recording to the same tick
// and must agree on every snapshot field; when the run ends the verifier must
// end it at the same tick, and the replay the game saved must be the one it
// recorded. Each run has a fresh seed, so repeated runs explore new paths; a
// failing run names its seed, and --seed plays that run again.
//
// With --ranked the run is a ranked attempt (host/ranked.inc): the Play Game
// menu's Ranked box is ticked first, and once the game closes on its end
// screen, which queues the run under the name it offers, the run queued for the
// leaderboard must be the one the game recorded, under the ranked rules, signed
// by the player's key, with the result the verifier derives (service/src/verify.ts).
// With --quest the run is quest 1.1 instead, and must be completed.
//
//   node crimson-core/checks/game_session.mjs [--seed n] [--ranked] [--quest] <game directory> [core.wasm] [game.wasm]
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { CONFIG_BYTES, CORE, decode, field, init, loadCore, names, record, state, step } from "./engine.mjs";
import { PRESENTATION } from "./game_compare.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

let args = process.argv.slice(2);
const seedAt = args.indexOf("--seed");
const seedOverride = seedAt < 0 ? undefined : Number(args[seedAt + 1]);
if (seedAt >= 0) args = args.toSpliced(seedAt, 2);
const ranked = args.includes("--ranked"), quest = args.includes("--quest");
args = args.filter((arg) => arg !== "--ranked" && arg !== "--quest");
const [
  directory,
  coreWasm = new URL("build/wasm/core.wasm", CORE).pathname,
  gameWasm = new URL("build/game/game.wasm", CORE).pathname,
] = args;
if (!directory) throw Error("usage: game_session.mjs [--seed n] [--ranked] [--quest] <game directory> [core.wasm] [game.wasm]");

const run = bootGame(gameWasm, directory, seedOverride, { leaderboard: ranked });
const { game } = run;

// game_state_id_t
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, PAUSE_MENU = 5, PERK_SELECTION = 6, GAME_OVER = 7, QUEST_RESULTS = 8, GAMEPLAY = 9;
// DirectInput scancodes.
const [ESCAPE, W, A, S, D, CONSOLE, SPACE] = [0x01, 0x11, 0x1e, 0x1f, 0x20, 0x29, 0x39];
// Where a fresh 1024x768 profile lays out the perk menu's first choice (the
// rest follow 19 pixels apart) and the pause menu's Resume.
const PERK_CHOICE = [150, 216], RESUME = [232, 397];

// A frame of play: held keys and buttons, the cursor as DirectInput motion, and
// tapped keys held for the frame and delivered as presses, then released. The
// host pulls a 60 Hz frame of the mix after each, as the client does.
let held = new Set();
function frame(dt, { cursor, buttons = 0, keys = [], taps = [] }) {
  const input = run.input();
  const events = [...taps.map((k) => [k, 1]), ...[...held].filter((k) => !taps.includes(k)).map((k) => [k, 0])];
  for (const [key, down] of events) {
    const n = input.getInt32(INPUT.event_count, true);
    input.setUint8(INPUT.events + n * 2, key);
    input.setUint8(INPUT.events + n * 2 + 1, down);
    input.setInt32(INPUT.event_count, n + 1, true);
  }
  held = new Set(taps);
  for (const key of [W, A, S, D, ESCAPE, CONSOLE, SPACE])
    input.setUint8(INPUT.keys + key, keys.includes(key) || held.has(key) ? 0x80 : 0);
  input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(cursor[0])), true);
  input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(cursor[1])), true);
  input.setUint8(INPUT.buttons, buttons & 1 ? 0x80 : 0);
  run.frame(dt);
  game.game_audio(735);
}

// Holds the cursor on a spot until the screen settles, then clicks it. A menu
// opened while fire was held can close on its own: a button takes the release.
function click(screen, at) {
  for (let settled = 0, frames = 0; settled < 60; ++frames) {
    if (frames > 3000) throw Error(`screen ${screen} never settled`);
    frame(16, { cursor: at });
    if (settled && game.game_state() !== screen) return;
    settled = game.game_state() === screen ? settled + 1 : 0;
  }
  for (let i = 0; i < 5; ++i) frame(16, { cursor: at, buttons: 1 });
  frame(16, { cursor: at });
}

// On a fresh profile the main menu shares its screen id with the startup
// sequence, which ends after about 14 s.
while (run.clock < 15000) frame(16, { cursor: [512, 384] });
click(MAIN_MENU, [240, 338]);
const unlocksBefore = savedUnlocks();
// A fresh profile's Play Game panel lists Tutorial, Quests, Rush and Survival;
// ticking Ranked, under the player-count list, leaves Quests and Survival.
if (ranked) click(PLAY_GAME_MENU, [285, 489]);
if (quest) {
  // Quests, then 1.1 on the quest list.
  click(PLAY_GAME_MENU, [232, ranked ? 318 : 350]);
  for (let frames = 0; game.game_state() === PLAY_GAME_MENU; ++frames) {
    if (frames > 600) throw Error("the quest list never opened");
    frame(16, { cursor: [250, 296] });
  }
  click(game.game_state(), [250, 296]);
} else click(PLAY_GAME_MENU, [232, ranked ? 350 : 414]);

// Between ticks the players hold their own key codes; a tick reads the
// verifier's (host/session.inc).
const SWAPPED = /^players\[\d+\]\.input\./;
const replay = () => Buffer.from(game.memory.buffer, game.game_replay(), game.game_replay_size());
const core = loadCore(coreWasm);
const CREATURES = names.filter((n) => /^creatures\[\d+\]\.active$/.test(n)).length;
// The nearest live creature's screen position and the way away from it.
function target() {
  const f = (n) => field(core, n, true);
  const px = f("players[0].pos_x"), py = f("players[0].pos_y");
  let best = Infinity, aim = [512, 384], away = [0, 1];
  for (let i = 0; i < CREATURES; i++) {
    if (!field(core, `creatures[${i}].active`) || f(`creatures[${i}].health`) <= 0) continue;
    const x = f(`creatures[${i}].pos_x`), y = f(`creatures[${i}].pos_y`);
    const d = (x - px) ** 2 + (y - py) ** 2;
    if (d < best) {
      best = d;
      aim = [x + f("globals.camera_offset_x"), y + f("globals.camera_offset_y")];
      away = [px - x, py - y];
    }
  }
  return { aim, away };
}

// Frame times from 4 ms (most frames run no tick) to 50 ms (three ticks).
const times = [16, 7, 33, 16, 50, 4, 16, 12, 21];
let started = false, seed, ticks = 0, frames = 0, idle = 0, choice = 0, pauses = 0, picked = false;
while (true) {
  const screen = game.game_state();
  if (screen === PERK_SELECTION) {
    const at = [PERK_CHOICE[0], PERK_CHOICE[1] + 19 * (choice++ % 5)];
    click(PERK_SELECTION, at);
    // A second click as the menu closes, which picks no more than the verifier allows.
    for (let i = 0; i < 3; ++i) frame(16, { cursor: at, buttons: 1 });
    picked = true;
    continue;
  }
  if (screen === PAUSE_MENU) {
    click(PAUSE_MENU, RESUME);
    continue;
  }
  const taps = [];
  let cursor = [512, 384], keys = [];
  if (started) {
    const { aim, away } = target();
    cursor = aim;
    keys = [Math.abs(away[0]) > Math.abs(away[1]) ? (away[0] < 0 ? A : D) : away[1] < 0 ? W : S];
    // Another request right after a pick, which the pick may have used up.
    if (picked || (field(core, "globals.perk_pending_count") > 0 && frames % 30 === 0)) taps.push(SPACE);
    picked = false;
    if (frames % 997 === 500) taps.push(CONSOLE);
    if (ticks > 1200 * (pauses + 1) && pauses < 2) {
      taps.push(ESCAPE);
      ++pauses;
    }
  }
  // Fire in bursts, so presses and releases both fall between ticks.
  const buttons = Math.floor(run.clock / 333) % 4 === 3 ? 0 : 1;
  frame(times[frames++ % times.length], { cursor, buttons, keys, taps });

  const recorded = replay();
  if (!started) {
    if (recorded.length < CONFIG_BYTES) {
      if (frames > 600) throw Error("the Survival run did not play as a session");
      continue;
    }
    init(core, recorded.subarray(0, CONFIG_BYTES));
    started = true;
    seed = recorded.readUInt32LE(0);
    process.on("exit", (code) => code && console.error(`the run's seed was ${seed}: --seed ${seed} plays it again`));
  }
  const recording = decode(recorded);
  idle = recording.records.length === ticks && game.game_state() === GAMEPLAY ? idle + 1 : 0;
  for (const tick of recording.records.slice(ticks)) {
    if (!step(core, tick)) throw Error(`the verifier refused tick ${ticks}`);
    ++ticks;
  }
  if (![GAMEPLAY, PERK_SELECTION, PAUSE_MENU].includes(game.game_state())) break;
  if (game.game_state() !== GAMEPLAY) continue;
  const expected = state(core), actual = state(game);
  for (let i = 0; i < names.length; i++) {
    if (PRESENTATION.has(names[i]) || SWAPPED.test(names[i])) continue;
    const a = expected.readUInt32LE(i * 4), b = actual.readUInt32LE(i * 4);
    if (a !== b) throw Error(`tick ${ticks}: ${names[i]} is ${b}, the verifier says ${a}`);
  }
  if (idle > 120) throw Error(`the run stopped ticking at tick ${ticks}`);
  if (frames > 60000) throw Error("the run never ended");
}
// The run ended where the verifier ends it: one more tick is refused.
if (step(core, record([0, 0, 0, 0, 0]))) throw Error(`the run ended at tick ${ticks}, but the verifier plays on`);
// Commands by type: 1 picks a perk, 2 opens the perk menu.
const commands = [0, 0, 0];
for (const r of decode(replay()).records)
  for (let i = 0; i < r.readUInt32LE(20); i++) ++commands[r.readInt32LE(24 + i * 8)];
// A Survival run plays long enough to pick perks and pause twice.
if (!quest && (!commands[1] || pauses < 2)) throw Error(`the run picked ${commands[1]} perks and paused ${pauses} times`);
const saved = fs.readdirSync(path.join(directory, "replays")).map((f) => path.join(directory, "replays", f));
if (!saved.some((f) => fs.readFileSync(f).equals(replay()))) throw Error("the saved replay differs from the recording");
if (ranked) checkRanked();
console.log(JSON.stringify({ seed, ticks, frames, picks: commands[1], pauses }));

// The quests the player's save unlocks (game.cfg, src/crimson/persistence/save_status.py).
function savedUnlocks() {
  const file = path.join(directory, "game.cfg");
  if (!fs.existsSync(file)) return "none";
  const script =
    "import sys; from crimson.persistence.save_status import load_status; " +
    "s = load_status(__import__('pathlib').Path(sys.argv[1])); print(s.quest_unlock_index, s.quest_unlock_index_hardcore)";
  return execFileSync("uv", ["run", "--no-sync", "python", "-c", script, file], { encoding: "utf8" }).trim();
}

// Why a replay payload does not rank, as the service decides it (src/crimson/replay/ranked.py unranked_reasons).
function unrankedReasons(payload) {
  const script =
    "import sys; from crimson.replay.codec import decode_replay_payload; from crimson.replay.ranked import unranked_reasons; " +
    "print(' '.join(unranked_reasons(decode_replay_payload(sys.stdin.buffer.read()).run)))";
  return execFileSync("uv", ["run", "--no-sync", "python", "-c", script], { input: payload, encoding: "utf8" }).trim();
}

// Closing the game on its end screen queues the run; the queued entry is
// checked as the service checks it.
function checkRanked() {
  if (game.game_state() !== (quest ? QUEST_RESULTS : GAME_OVER)) throw Error(`the run ended on screen ${game.game_state()}`);
  game.game_close();
  try {
    frame(16, { cursor: [700, 700] });
  } catch (error) {
    if (error.message !== "the game quit") throw error;
  }
  // A ranked run plays on a detached save: completing a quest unlocks nothing.
  const unlocks = savedUnlocks();
  if (unlocks !== "none" && unlocks !== unlocksBefore && unlocksBefore !== "none")
    throw Error(`the ranked run changed the save's unlocks from ${unlocksBefore} to ${unlocks}`);
  if (unlocks !== "none" && unlocksBefore === "none" && unlocks !== "0 0")
    throw Error(`the ranked run unlocked quests in a fresh save: ${unlocks}`);
  const outbox = path.join(directory, "leaderboard/outbox");
  const queued = fs.readdirSync(outbox);
  if (queued.length !== 1) throw Error(`the outbox holds ${queued.length} runs`);
  const entry = JSON.parse(fs.readFileSync(path.join(outbox, queued[0]), "utf8"));
  const payload = zlib.zstdDecompressSync(Buffer.from(entry.replay, "base64"));
  const digest = crypto.createHash("sha256").update(payload).digest();
  if (`${digest.toString("hex")}.json` !== queued[0]) throw Error("the queued run is not named by its digest");
  // identity.py sign_run: the domain, the payload's digest and the name.
  const key = crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(entry.public_key, "hex").toString("base64url") },
    format: "jwk",
  });
  const message = Buffer.concat([Buffer.from("crimson-run-v1\n"), digest, Buffer.from(entry.name, "latin1")]);
  if (!crypto.verify(null, message, key, Buffer.from(entry.signature, "hex"))) throw Error("the signature does not verify");
  const crd = unpack(payload);
  const spec = crd.run;
  const reasons = unrankedReasons(payload);
  if (reasons) throw Error(`the queued run breaks the ranked rules: ${reasons}`);
  const recorded = decode(replay());
  if (crd.ticks.length !== recorded.records.length) throw Error("the queued run's ticks are not the recording's");
  crd.ticks.forEach(([[input], queuedCommands], i) => {
    const tick = recorded.records[i];
    const values = [tick.readFloatLE(0), tick.readFloatLE(4), tick.readFloatLE(8), tick.readFloatLE(12), tick.readUInt32LE(16)];
    if (input.some((value, j) => value !== values[j]) || queuedCommands.length !== tick.readUInt32LE(20))
      throw Error(`tick ${i} is not the recording's`);
  });
  // deriveResult (service/src/verify.ts), from the verifier at the run's last tick.
  state(core);
  const u32 = (name) => field(core, name), i32 = (name) => field(core, name) | 0, f32 = (name) => field(core, name, true);
  const elapsed = i32(spec.game_mode_id === 3 ? "globals.quest_spawn_timeline" : "globals.run_elapsed_ms");
  const fired = Math.max(0, i32("globals.highscore_record_shots_fired"));
  let best = 1;
  for (let weapon = 2; weapon < 53; weapon++)
    if (i32(`globals.weapon_usage_time[${weapon}]`) > i32(`globals.weapon_usage_time[${best}]`)) best = weapon;
  const derived = {
    outcome: { 7: "death", 12: "death", 8: "quest_completed" }[u32("globals.game_state_pending")] ?? "incomplete",
    elapsed_ms: elapsed,
    kills: u32("globals.creature_kill_count"),
    shots_fired: fired,
    shots_hit: Math.max(0, Math.min(i32("globals.highscore_record_shots_hit"), fired)),
    rng_state: u32("globals.rng"),
    pending_perks: u32("globals.perk_pending_count"),
    experience: u32("players[0].experience"),
    health: f32("players[0].health"),
    most_used_weapon_id: best,
  };
  // compute_quest_final_time for one player: a completed quest's score.
  const final = elapsed - Math.trunc(derived.health) * 50 - derived.pending_perks * 1000;
  derived.quest_final_ms = derived.outcome === "quest_completed" ? final || 1 : null;
  const claimed = { ...crd.result, ...crd.result.players[0] };
  for (const [name, value] of Object.entries(derived))
    if (claimed[name] !== value) throw Error(`result.${name} claims ${claimed[name]}, the verifier derives ${value}`);
}
// The canonical msgpack the replay is (service/src/msgpack.ts), as plain values.
function unpack(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const take = (n) => ((at += n), at - n);
  const many = (n, item) => Array.from({ length: n }, item);
  const entries = (n) => Object.fromEntries(many(n, () => [value(), value()]));
  const text = (n) => bytes.subarray(take(n), at).toString("utf8");
  function value() {
    const byte = bytes[take(1)];
    if (byte <= 0x7f) return byte;
    if (byte >= 0xe0) return byte - 0x100;
    if (byte >= 0x80 && byte <= 0x8f) return entries(byte & 15);
    if (byte >= 0x90 && byte <= 0x9f) return many(byte & 15, value);
    if (byte >= 0xa0 && byte <= 0xbf) return text(byte & 31);
    switch (byte) {
      case 0xc0: return null;
      case 0xc2: return false;
      case 0xc3: return true;
      case 0xcb: return view.getFloat64(take(8));
      case 0xcc: return bytes[take(1)];
      case 0xcd: return view.getUint16(take(2));
      case 0xce: return view.getUint32(take(4));
      case 0xd0: return view.getInt8(take(1));
      case 0xd1: return view.getInt16(take(2));
      case 0xd2: return view.getInt32(take(4));
      case 0xd9: return text(bytes[take(1)]);
      case 0xdc: return many(view.getUint16(take(2)), value);
      case 0xdd: return many(view.getUint32(take(4)), value);
      case 0xde: return entries(view.getUint16(take(2)));
    }
    throw Error(`unexpected msgpack type 0x${byte.toString(16)}`);
  }
  const result = value();
  if (at !== bytes.length) throw Error("trailing bytes after the replay");
  return result;
}
