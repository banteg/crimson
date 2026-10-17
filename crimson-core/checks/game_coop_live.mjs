// Two machines play co-op sessions inside the original (host/coop_live.inc;
// docs/rewrite/network-coop.md, Phase B): two games boot, each from its own copy
// of a game directory, and Node carries their sessions' messages between them
// over the checks' lossy network (coop_link.mjs), as the transport does
// (client/web/coop.js). The machines differ in all a player may set: the Host
// plays at 60 frames a second with sound and music on, seven in-game tunes, the
// highest detail, a mouse and keys it moved (ESDF, Q for the perk menu) and
// some progress of its own; the Guest at 144 with sound and music off, the
// lowest detail, no gore, info texts or direction arrows, a pad on the pad
// profile and a fresh save. Its frames stutter once; the Host's packets are lost
// in a burst once. Each session opens on both machines as the transport opens
// one:
//
// A run alone. The Guest's machine plays the first quest by itself, and a
// session opens two seconds in: the run plays on, on the player's own save (a
// Survival run the Host starts waits for it until the Host gives up, and its
// window's focus lost pauses it as alone), and completing it unlocks the next
// quest in the save at once. Its end screen's Play Next starts nothing, as the
// Host picks the session's runs. The Guest's game closes there, its save keeping
// the unlock, and starts again.
//
// Survival. The Host's menus start it and the Guest's screen follows into the
// run. Both players move away from the nearest creature and shoot at it, the
// Host by its keys and mouse, the Guest by its sticks and trigger. The Host's
// perk key asks for the first perk menu and it picks on its perk screen while
// the Guest's card shows the pick; then the Guest's Triangle asks for the next
// and its d-pad and A pick. The Guest pauses with Start and the Host resumes
// from the pause banner's button; the Host pauses with Escape and the Guest
// resumes with Start; the Guest's window loses the focus for a while, where it
// plays on. Then both stand still until the creatures kill them: both show the
// game over screen. The Guest's pad saves its score and clicks Play Again, which
// waits a second for the Host's name, until its Enter saves the Host's score:
// then the Host's screen follows into the next run. At its first level both
// players ask for the perk menu on the same tick, and the Host's request wins.
// The Guest pauses while the Host's perk screen shows, the Host picks there,
// and the Guest's pad steps to the pause banner's Leave and presses it at once:
// both runs end on the same tick after the pick, both machines go back to the
// main menu, and the Host learns the Guest left.
//
// A desync. A run whose state the Guest's machine changes between ticks stops
// on both at the same tick with the desync banner; the Host's Enter and the
// Guest's A press its Leave.
//
// A lost connection, the machines in each other's seats: the Guest's machine
// starts the run by its mouse. The transport closes on both sides a few
// seconds into it: each machine ends it where it confirmed it and goes to the
// menu. The Host's menus are its own again: its quest list starts none of the
// quests the session unlocked.
//
// Quests. The Host starts the first quest from its quest list, which both
// players clear; both save their names. The Guest's high scores Play a game
// starts nothing; the Host's Play Next starts the next quest, which takes the
// Guest's screen from the high scores. Both stand still until it fails; the
// Host's Play Another takes both to the quest list, and its number key starts
// the first quest again. Both stand still until it fails; the Host's keys press
// Main Menu, and the Guest's Play Again right after starts nothing: the session
// ends there.
//
// Every tick either machine confirmed has the same state hash, bake digest and
// terrain digest on both, and the engine with both seats local
// (game_coop_start's solo mode, headless) gives the same for each tick from the
// records the machines played; both machines saved the same replay byte for
// byte, which the Python port verifies as a 2-player run (each perk command its
// picker's); each mouse aim the first tick took reads through the two players'
// midpoint, in either seat; neither player's save or settings took anything
// from the sessions.
//
//   node crimson-core/checks/game_coop_live.mjs <game directory> [game.wasm]
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { Link } from "./coop_link.mjs";
import { CONFIG_BYTES, CORE, field, init, INPUT_BYTES, names, state } from "./engine.mjs";
import { loadGame } from "./game_compare.mjs";
import { bootGame, INPUT, sevenTunes } from "./game_host.mjs";

const [given, gameWasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!given) throw Error("usage: game_coop_live.mjs <game directory> [game.wasm]");

// game_state_id_t, DirectInput scancodes, and the session's (host/coop_wire.inc).
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, PERK_SELECTION = 6, GAME_OVER = 7, QUEST_RESULTS = 8, GAMEPLAY = 9;
const QUEST_SELECT = 11, QUEST_FAILED = 12, HIGHSCORES = 14;
const KEYS = [0x01, 0x02, 0x0a, 0x0f, 0x10, 0x12, 0x1c, 0x1f, 0x20, 0x21];
const [ESCAPE, ONE, NINE, TAB, Q, E, ENTER, S, D, F] = KEYS;
const STATUS = { connected: 1, started: 2, paused: 4, leaving: 32, desynced: 128, starting: 512, signed: 2048 };
// Why a session ended (CoopReason).
const UNANSWERED = 6, LEFT = 7, PARTNER_LEFT = 8, DISCONNECTED = 9, PARTNER_GONE = 10;
// The pad (game/host_input.h): A, Triangle, R2 and Start, the d-pad's up, right and down; the sticks from -1000 to
// 1000.
const PAD_SOUTH = 1, PAD_NORTH = 3, PAD_R2 = 7, PAD_START = 9, HAT_UP = 0, HAT_RIGHT = 9000, HAT_DOWN = 18000;
// Each machine's frame times; the network's seed, loss and the Host's burst; the Guest's stutter.
const FRAMES = [[16, 17, 17], [7, 7, 7, 6, 7]];
const SEED = 7, LOSS = 0.02, BURST = { at: 1200, left: 12 }, HITCH = { at: 900, ms: 300 };
// Where a 1024x768 profile lays out the perk menu's first choice (the rest 19 pixels apart); a pad player's
// mouse rests where it covers no widget.
const PERK_CHOICE = [150, 216], PAD_CURSOR = [1000, 740];
// The main menu's Play Game; the Play Game panel lays out Quests, Rush and Survival first, as the Host played
// before, 28 pixels apart with every quest unlocked (the session's) and 32 with the Host's own three; a fresh save's
// Quests; the high scores' Play a game.
const PLAY_GAME = [240, 338], SURVIVAL = [232, 372], OWN_QUESTS = [232, 322], FRESH_QUESTS = [232, 350];
const PLAY_A_GAME = [190, 500];
// A banner's `count` buttons across a 1024x768 frame (coop_banner): 145 wide and 16 apart, centred, 58 below the
// band's top; the centre of button `i`.
const banner = (count, i) => [
  Math.floor((1024 - count * 161 + 16) / 2) + i * 161 + 72,
  Math.floor((768 - 104) / 2) + 74,
];
// A tick's digests (host/coop.inc), which both machines and the solo engine must agree on; not its music's, which
// names the tracks this machine loaded.
const DIGESTS = ["hash", "bake", "terrain"];
// The record a tick ran with (host/coop.inc CoopInput): a seat's input (its aim 8 bytes in, its flag word 16, with
// the movement and aim schemes at bits 9 and 13), then its request. Each machine's schemes: the Host's static
// movement and mouse aim, the Guest's pad profile.
const RECORD_BYTES = INPUT_BYTES + 1;
const schemes = (record) => `${(record.readUInt32LE(16) >> 9) & 7}/${(record.readUInt32LE(16) >> 13) & 7}`;
// CoopStats (host/coop.inc): its double_opens, and its wire's lost ticks packets.
const DOUBLE_OPENS = 14, LOST = 28;
const stat = (peer, i) => new Int32Array(peer.g.memory.buffer, peer.g.game_coop_stats(), 32)[i];
const ASK_OPEN = 1;

const python = (code, ...args) =>
  execFileSync("uv", ["run", "--no-sync", "python", "-c", code, ...args], { encoding: "utf8" }).trim();

// Each machine's copy of the game, its first start's default configuration made the player's, and the player's
// progress. What the settings and the save hold, as Python reads them, for the end: all but the time the game ran,
// which the original counts in the menus too (play_time_get).
const SETUP = `
import sys
from pathlib import Path
from grim.config import load_crimson_cfg, apply_detail_preset
from crimson.gamepad_profile import apply_pad_profile
from crimson.persistence.save_status import GameStatusData, save_status
directory, seat = Path(sys.argv[1]), int(sys.argv[2])
config = load_crimson_cfg(directory / "crimson.cfg")
player = config.controls.players[0]
if seat == 0:
    apply_detail_preset(config, 5)
    player.move_codes = (0x12, 0x20, 0x1F, 0x21)
    config.controls.pick_perk_code = 0x10
    config.audio.sfx_volume, config.audio.music_volume = 1.0, 0.4
    status = GameStatusData(quest_unlock_index=3, quest_unlock_index_hardcore=1, mode_play_survival=4)
else:
    config.audio.sound_disabled = config.audio.music_disabled = True
    apply_detail_preset(config, 1)
    config.display.violence_disabled = 1
    config.gameplay.show_info_texts = False
    player.show_direction_arrow = False
    apply_pad_profile(config.controls, 0)
    status = GameStatusData()
config.save()
save_status(directory / "game.cfg", status)
`;
const SAVED = `
import sys, msgspec
from pathlib import Path
from grim.config import load_crimson_cfg
from crimson.persistence.save_status import load_status
directory = Path(sys.argv[1])
config = msgspec.to_builtins(load_crimson_cfg(directory / "crimson.cfg"), enc_hook=str)
del config["path"], config["wire"]
status = msgspec.to_builtins(load_status(directory / "game.cfg").as_data())
del status["play_time_ms"]
print(msgspec.json.encode({"config": config, "status": status}).decode())
`;
const saved = (peer) => JSON.parse(python(SAVED, peer.directory));
// `seat` is the machine's place on the network (coop_link.mjs), `role` its seat in the session or run it plays; `at`
// the next frame's time, `last` the last's; `ticks` the confirmed ticks (keep), `config` their run's; `first` the
// record its first run's tick 0 sampled (Machines.frame).
const peers = [0, 1].map((seat) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `crimson-coop-${seat}-`));
  process.on("exit", () => fs.rmSync(directory, { recursive: true, force: true }));
  fs.cpSync(seat === 0 ? sevenTunes(given) : given, directory, { recursive: true });
  bootGame(gameWasm, directory);
  for (const name of ["game.cfg", "registry.cfg", "console.log"])
    fs.rmSync(path.join(directory, name), { force: true });
  python(SETUP, directory, `${seat}`);
  const peer = { seat, role: seat, directory, saved: python(SAVED, directory), schemes: ["2/0", "3/4"][seat] };
  return Object.assign(peer, boot(peer, 0));
});
const [host, guest] = peers;
// A machine's game starting, its first frame at `at`.
function boot(peer, at) {
  const run = bootGame(gameWasm, peer.directory, peer.seat + 1);
  return { run, g: run.game, at: at + peer.seat * 3, last: at + peer.seat * 3 - 16, frames: 0, gone: false,
    held: new Set(), ticks: new Map(), top: -1, config: null, first: null };
}

// The records each confirmed tick ran with and its digests, while the engine's ring holds them, and the run's
// configuration as its first tick ran.
function keep(peer) {
  const { g } = peer;
  const top = g.game_coop_confirmed();
  if (top < peer.top) peer.ticks.clear();
  peer.top = top;
  if (top >= 0 && !peer.ticks.size)
    peer.config = Buffer.from(new Uint8Array(g.memory.buffer, g.portable_config(), CONFIG_BYTES));
  for (let t = Math.max(0, top - 64); t <= top; ++t) {
    if (peer.ticks.has(t) || !g.game_coop_hash_at(t)) continue;
    const used = [0, 1].map((seat) =>
      Buffer.from(new Uint8Array(g.memory.buffer, g.game_coop_used(t, seat), RECORD_BYTES)),
    );
    peer.ticks.set(t, { used, digests: DIGESTS.map((name) => g[`game_coop_${name}_at`](t)) });
  }
}

// The two machines on the network: a frame of a peer takes the input `input` gives it (held keys, tapped keys,
// the cursor as DirectInput motion, the left button, the pad), then sends what its session has to send. A frame
// that produces this machine's record while its run has yet to run tick 0 keeps where the players start and the
// cursor that record read.
class Machines extends Link {
  constructor() {
    super(SEED);
    this.peers = peers;
    this.loss = LOSS;
    this.input = () => ({});
  }
  receive(peer, channel, bytes) {
    const { g, run } = peer;
    const at = g.game_coop_rx(bytes.length);
    new Uint8Array(g.memory.buffer, at, bytes.length).set(bytes);
    g.game_coop_receive(channel, bytes.length, run.clock);
  }
  frame(peer) {
    const { run, g } = peer;
    const { cursor = PAD_CURSOR, keys = [], taps = [], button = false, pad } = this.input(peer);
    const input = run.input();
    const events = [...taps.map((k) => [k, 1]), ...[...peer.held].filter((k) => !taps.includes(k)).map((k) => [k, 0])];
    for (const [key, down] of events) {
      const n = input.getInt32(INPUT.event_count, true);
      input.setUint8(INPUT.events + n * 2, key);
      input.setUint8(INPUT.events + n * 2 + 1, down);
      input.setInt32(INPUT.event_count, n + 1, true);
    }
    peer.held = new Set(taps);
    for (const key of KEYS) input.setUint8(INPUT.keys + key, keys.includes(key) || peer.held.has(key) ? 0x80 : 0);
    input.setInt32(INPUT.motion_x, Math.round(g.game_motion_x(cursor[0])), true);
    input.setInt32(INPUT.motion_y, Math.round(g.game_motion_y(cursor[1])), true);
    input.setUint8(INPUT.buttons, button ? 0x80 : 0);
    // The Guest's pad is always there.
    input.setUint8(INPUT.pad_connected, peer === guest ? 1 : 0);
    const { left = [0, 0], right = [0, 0], press = [], hat = 0xffffffff } = pad ?? {};
    [...left, ...right].forEach((value, i) => input.setInt32(INPUT.pad_axes + 4 * i, Math.round(value), true));
    input.setUint32(INPUT.pad_hat, hat, true);
    for (let b = 0; b < 32; ++b) input.setUint8(INPUT.pad_buttons + b, press.includes(b) ? 0x80 : 0);
    const fresh = screen(peer) === GAMEPLAY && (status(peer) & STATUS.started) !== 0 && g.game_coop_next() === 0;
    const before = g.game_coop_produced(), spawn = fresh && starts(peer);
    const dt = peer.at - peer.last;
    run.frame(dt);
    if (spawn && g.game_coop_produced() > before)
      peer.first = { tick: before + 1, cursor: [g.game_cursor_x(), g.game_cursor_y()], spawn };
    g.game_audio(Math.round((dt * 44100) / 1000));
    for (const channel of [0, 1])
      for (let size; (size = g.game_coop_tx(channel, run.clock)) > 0; )
        this.send(peer, channel, new Uint8Array(g.memory.buffer, g.game_coop_tx_buffer(), size).slice());
    keep(peer);
    peer.last = peer.at;
    const pattern = FRAMES[peer.seat];
    peer.at += pattern[peer.frames++ % pattern.length];
  }
  describe() {
    return peers.map((p) => ({ screen: screen(p), status: status(p).toString(16), confirmed: confirmed(p) }));
  }
}
const machines = new Machines();
const time = () => machines.now;
// Both machines' frames and what they send each other, each frame with the input `input` gives it, until `done`.
function play(input, done, what) {
  machines.input = input;
  machines.until(done, what);
}
const idle = () => ({});
const status = (peer) => peer.g.game_coop_status();
const reason = (peer) => (status(peer) >> 16) & 255;
const confirmed = (peer) => peer.g.game_coop_confirmed();
const screen = (peer) => peer.g.game_state();
const started = () => peers.every((p) => screen(p) === GAMEPLAY && status(p) & STATUS.started);
// Plays until `peer` has shown `id` for `ms`.
function settle(peer, id, input = idle, ms = 300) {
  let since = Infinity;
  const shown = () => time() - (screen(peer) === id ? (since = Math.min(since, time())) : (since = Infinity)) >= ms;
  play(input, shown, `screen ${id}`);
}
// Plays for `ms`, every frame of it passing `check`.
function hold(ms, check, what) {
  const until = time() + ms;
  play(idle, () => (assert.ok(check(), what), time() >= until), what);
}
// Holds the cursor on a spot until the screen settles, then clicks it.
function click(peer, id, at) {
  let frames = 0;
  settle(peer, id, (p) => (p === peer ? { cursor: at } : {}));
  play((p) => (p === peer ? { cursor: at, button: frames++ < 10 } : {}), () => frames > 12, "the click");
}
// A key or pad press of one peer, then its release; `presses` of them in turn.
function tap(peer, ...presses) {
  for (const input of presses) {
    let frames = 0;
    play((p) => (p === peer ? (frames++ < 3 ? input : {}) : {}), () => frames >= 6, "a tap");
  }
}
const pad = (pad) => ({ pad });
const DOWN = pad({ hat: HAT_DOWN }), RIGHT = pad({ hat: HAT_RIGHT }), A = pad({ press: [PAD_SOUTH] });
const START = pad({ press: [PAD_START] });
const key = (k) => ({ taps: [k] });
// Both sessions open, each machine in its seat (`roles`), and both said hello.
function connect(roles = [0, 1]) {
  for (const peer of peers) {
    peer.role = roles[peer.seat];
    assert.equal(peer.g.game_coop_connect(peer.role, peer.run.clock), 1);
  }
  play(idle, () => peers.every((p) => status(p) & STATUS.connected), "the hello");
}
// The scores a machine saved, and its newest replay.
const scores = (peer) => {
  const kept = path.join(peer.directory, "scores5");
  return fs.existsSync(kept) ? fs.readdirSync(kept).length : 0;
};
const newest = (peer) => {
  const replays = path.join(peer.directory, "replays");
  const numbered = fs.readdirSync(replays).filter((name) => /^\d+-/.test(name));
  return path.join(replays, numbered.reduce((a, b) => (parseInt(b, 10) > parseInt(a, 10) ? b : a)));
};

// The nearest live creature in this machine's run: where it is on the screen, the way to it and the way away.
const CREATURES = names.filter((n) => /^creatures\[\d+\]\.active$/.test(n)).length;
function target(peer) {
  const { g } = peer;
  state(g);
  const f = (n) => field(g, n, true);
  const px = f(`players[${peer.role}].pos_x`), py = f(`players[${peer.role}].pos_y`);
  let best = Infinity, aim = [512, 300], toward = [0, -1];
  for (let i = 0; i < CREATURES; i++) {
    if (!field(g, `creatures[${i}].active`) || f(`creatures[${i}].health`) <= 0) continue;
    const x = f(`creatures[${i}].pos_x`), y = f(`creatures[${i}].pos_y`);
    const d = (x - px) ** 2 + (y - py) ** 2;
    if (d < best) {
      best = d;
      aim = [x + f("globals.camera_offset_x"), y + f("globals.camera_offset_y")];
      toward = [x - px, y - py];
    }
  }
  return { aim, toward, away: [-toward[0], -toward[1]], pending: field(g, "globals.perk_pending_count") };
}
// Where the run's two players start, before its first tick.
function starts(peer) {
  state(peer.g);
  return [0, 1].map((i) => [field(peer.g, `players[${i}].pos_x`, true), field(peer.g, `players[${i}].pos_y`, true)]);
}
// A stick pushed all the way along a direction.
const stick = ([x, y]) => (x || y ? [(x * 1000) / Math.hypot(x, y), (y * 1000) / Math.hypot(x, y)] : [0, 0]);

// Each player moves away from the nearest creature and aims at it, firing in bursts: the Host by its keys (ESDF:
// forward, back, left, right) and mouse, the Guest by its sticks and R2. On its perk screen the Host clicks a
// choice by its seat; the Guest's d-pad steps up from the choice under its resting mouse and A picks. `still`
// players stand. `script` adds taps (Escape, the Guest's Start; Q, the Guest's Triangle), or takes over the input.
const picks = [0, 0];
let still = false, script = () => ({});
function player(peer) {
  if (screen(peer) === PERK_SELECTION) {
    peer.picking ??= time();
    const ms = time() - peer.picking;
    if (ms > 1000 && !peer.picked) peer.picked = ++picks[peer.role];
    if (peer === host) return { cursor: PERK_CHOICE, button: ms > 1000 && ms < 1250 };
    const pad = ms > 600 && ms < 650 ? { hat: HAT_UP } : ms > 1000 && ms < 1050 ? { press: [PAD_SOUTH] } : {};
    return { cursor: [PERK_CHOICE[0], PERK_CHOICE[1] + 19 * 4], pad };
  }
  peer.picking = peer.picked = undefined;
  if (screen(peer) !== GAMEPLAY || still) return {};
  const { input, taps = [] } = script(peer);
  if (input) return input;
  const { aim, toward, away } = target(peer);
  const firing = Math.floor(peer.at / 400) % 3 !== 2;
  if (peer === guest) {
    // Start and Triangle alone, so the pad takes them as presses.
    const press = taps.flatMap((k) => (k === ESCAPE ? [PAD_START] : k === Q ? [PAD_NORTH] : []));
    if (press.length) return { pad: { press } };
    return { pad: { left: stick(away), right: stick(toward), press: firing ? [PAD_R2] : [] } };
  }
  const key = Math.abs(away[0]) > Math.abs(away[1]) ? (away[0] < 0 ? S : F) : away[1] < 0 ? E : D;
  return { cursor: aim, keys: [key], taps, button: firing };
}

// The solo engine, headless, which plays a run from the records the machines played.
const solo = loadGame(gameWasm);
// A run as `peer` played it to tick `last`: every tick's digests are the solo engine's from its records.
function replayed(peer, last) {
  init(solo, peer.config);
  assert.equal(solo.game_coop_start(-1, 2, 0, 1), 1);
  const write = (at, t, seat) =>
    new Uint8Array(solo.memory.buffer, at, RECORD_BYTES).set(peer.ticks.get(t).used[seat]);
  for (let t = 0; t < 2; ++t) for (const seat of [0, 1]) write(solo.game_coop_seed(seat, t), t, seat);
  for (let t = 0; t <= last; ++t) {
    if (t >= 2) {
      for (const seat of [0, 1]) write(solo.game_coop_input_for(seat), t, seat);
      assert.equal(solo.game_coop_produce(0), t);
    }
    assert.equal(solo.game_coop_advance(1, 0), 1, `tick ${t} did not run alone`);
    const { digests } = peer.ticks.get(t);
    DIGESTS.forEach((name, i) =>
      assert.equal(digests[i], solo[`game_coop_${name}_at`](t), `machine ${peer.seat} tick ${t}: ${name}`),
    );
  }
}
// A peer's newest replay, which the Python port verifies as a 2-player run of `ticks` ending in `outcome`.
function verified(peer, ticks, outcome) {
  const saved = newest(peer);
  const verify = ["run", "--no-sync", "crimson", "replay", "verify", "--format", "json", saved];
  const result = JSON.parse(execFileSync("uv", verify, { encoding: "utf8" }));
  assert.equal(result.status, "ok", JSON.stringify(result));
  assert.equal(result.ticks, ticks);
  assert.equal(result.result.outcome, outcome);
  assert.equal(result.result.players.length, 2);
  assert.deepEqual(result.mismatched_fields, []);
  return saved;
}
// The mouse aim of the first record the Host's machine sampled before its run's first tick: the cursor through
// the camera on the two players' midpoint, clamped to the arena (session.inc live_input), in either seat.
function midpointAim() {
  const { tick, cursor, spawn } = host.first;
  const record = host.ticks.get(tick).used[host.role];
  assert.equal(schemes(record), host.schemes);
  const f = Math.fround;
  const camera = (i, half, low) => {
    const [one, two] = [spawn[0][i], spawn[1][i]];
    return Math.max(Math.min(f(half - f(one - f(f(one - two) * 0.5))), -1), low);
  };
  const aim = [f(cursor[0] - camera(0, 512, 1024 - 1024)), f(cursor[1] - camera(1, 384, 768 - 1024))];
  assert.deepEqual([record.readFloatLE(8), record.readFloatLE(12)], aim, `seat ${host.role}'s first aim`);
  // The players start apart, so the midpoint is no player's place.
  assert.notDeepEqual(spawn[0], spawn[1]);
}
// Every tick both machines confirmed has the same digests on both, and each seat's record its machine's schemes
// (but the first few, the input delay's blank records); each machine's run to its last tick is the solo engine's.
function agreed() {
  const last = Math.min(...peers.map(confirmed));
  const expected = [0, 1].map((role) => peers.find((p) => p.role === role).schemes);
  for (let t = 0; t <= last; ++t) {
    const { used, digests } = host.ticks.get(t);
    DIGESTS.forEach((name, i) => assert.equal(guest.ticks.get(t).digests[i], digests[i], `tick ${t}'s ${name}`));
    if (t >= 8 || used.some((record) => record.readUInt32LE(16)))
      assert.deepEqual(used.map(schemes), expected, `tick ${t}'s schemes`);
  }
  for (const peer of peers) {
    assert.equal(status(peer) & STATUS.desynced, 0, `machine ${peer.seat} desynced`);
    replayed(peer, confirmed(peer));
  }
}
// A run both machines ended: the same last tick, the same digests for every tick and the solo engine's, the same
// replay, which the Python port verifies and ends as the run did. Its perk commands.
function ended(outcome) {
  const last = confirmed(host);
  assert.equal(confirmed(guest), last, "both runs end on the same tick");
  agreed();
  const saved = verified(host, last + 1, outcome);
  const replay = fs.readFileSync(saved);
  assert.ok(replay.equals(fs.readFileSync(newest(guest))), "the two replays differ");
  const commands = python(
    "import sys; from pathlib import Path; from crimson.replay.codec import load_replay; " +
      "r = load_replay(Path(sys.argv[1]).read_bytes()); " +
      "print(' '.join(f'{type(c).__name__}:{c.player_index}' for t in r.ticks for c in t.commands))",
    saved,
  );
  const replay_bytes = zlib.zstdDecompressSync(replay).length;
  return { ticks: last + 1, commands, replay_bytes, lost: peers.map((p) => stat(p, LOST)) };
}
// Both machines back on the main menu once a leave ended the session, each told who left.
function left(leaver) {
  play(idle, () => peers.every((p) => screen(p) === MAIN_MENU && !(status(p) & STATUS.connected)), "the leave");
  assert.deepEqual(peers.map(reason), peers.map((p) => (p === leaver ? LEFT : PARTNER_LEFT)), "who left");
}
// The original's startup: on a fresh profile the main menu shares its screen id with it, and it ends after about
// 14 s.
const startup = () => play(idle, () => peers.every((p) => p.at > p.booted + 15000), "the startup");
for (const peer of peers) peer.booted = 0;
startup();

// A run alone. The Guest's machine starts the first quest from its menus and plays it alone; two seconds in, a
// session opens. The run plays on: the Host's Survival waits for it until the Host gives up on its start, and its
// window losing the focus pauses it as alone. Completing it unlocks the next
// quest in the save at once; the Guest's pad saves its name and clicks Play Next, which starts nothing, then Main
// Menu, the fourth button. Its game closes and starts again, its save keeping the unlock.
click(guest, MAIN_MENU, PLAY_GAME);
click(guest, PLAY_GAME_MENU, FRESH_QUESTS);
settle(guest, QUEST_SELECT);
tap(guest, key(ONE));
settle(guest, GAMEPLAY);
const alone = guest.g.game_play_run();
const fight = (peer) => (peer === guest && screen(guest) === GAMEPLAY ? player(guest) : {});
guest.role = 0;
const recorded = () => guest.g.game_replay_size();
let solo_at = time();
play(fight, () => time() - solo_at > 2000, "two seconds alone");
connect();
guest.role = 0;
// The Host's menus start Survival: its run waits for the Guest's screen, which stays in its run, until the Host
// gives up on it.
const fighting = (p) => (p === host ? {} : fight(p));
click(host, MAIN_MENU, PLAY_GAME);
click(host, PLAY_GAME_MENU, SURVIVAL);
const unanswered = () => screen(host) === MAIN_MENU && reason(host) === UNANSWERED;
play(fighting, () => (assert.equal(guest.g.game_play_run(), alone, "the run alone"), unanswered()), "the cancel");
assert.equal(screen(guest), GAMEPLAY);
guest.g.game_activate(0);
const paused_at = recorded();
solo_at = time();
play(fight, () => time() - solo_at > 500, "the run in the background");
assert.equal(recorded(), paused_at, "a run alone played on in the background");
guest.g.game_activate(1);
play(fight, () => screen(guest) !== GAMEPLAY, "the run alone's end");
settle(guest, QUEST_RESULTS);
assert.equal(saved(guest).status.quest_unlock_index, 1, "the run alone's unlock");
settle(guest, QUEST_RESULTS, idle, 5000);
const named = scores(guest);
tap(guest, DOWN, A);
play(idle, () => scores(guest) > named, "the Guest's saved score");
settle(guest, QUEST_RESULTS);
tap(guest, A);
hold(1000, () => screen(guest) === QUEST_RESULTS && !(status(host) & (STATUS.starting | STATUS.started)), "Play Next");
tap(guest, DOWN, DOWN, DOWN, A);
settle(guest, MAIN_MENU);
guest.g.game_close();
assert.throws(() => guest.run.frame(16), /the game quit/);
guest.g.game_exit();
guest.saved = python(SAVED, guest.directory);
assert.equal(JSON.parse(guest.saved).status.quest_unlock_index, 1, "the unlock the game saved as it closed");
assert.equal(host.g.game_coop_disconnect(PARTNER_GONE), 1);
machines.flights = machines.flights.filter((f) => f.to !== guest);
Object.assign(guest, boot(guest, time()), { role: 1, booted: time() });
startup();

// A session, and in it a Survival run the machine in the Host's seat starts: it clicks Play Game, then Survival,
// and the other's screen follows.
function survival(roles = [0, 1]) {
  connect(roles);
  const starter = peers.find((p) => p.role === 0);
  click(starter, MAIN_MENU, PLAY_GAME);
  click(starter, PLAY_GAME_MENU, SURVIVAL);
  play(idle, started, "the run's start");
}
survival();

// The Host's perk key asks for the first perk menu every half second until its perk screen picks; then the
// Guest's Triangle for the next. The Guest pauses at tick 300 and the Host resumes a second later from the
// banner's Resume, its first button; the Host pauses at tick 700 and the Guest resumes with Start. The Guest's
// window is in the background from tick 400 to 600, where its player stands; its frames stutter at tick 900, and
// the Host loses a burst of packets at tick 1200.
const pauses = [
  { by: guest, at: 300, resumer: host, button: true },
  { by: host, at: 700, resumer: guest },
];
let pausing = 0, since = 0, clicking = 0, away = false;
script = (peer) => {
  const pause = pauses[pausing], taps = [];
  if (pause && !since && peer === pause.by && confirmed(host) >= pause.at) {
    since = peer.at;
    taps.push(ESCAPE);
  } else if (pause && since && peer === pause.resumer && status(peer) & STATUS.paused && peer.at - since > 1000) {
    if (!pause.button) taps.push(ESCAPE);
    else if (++clicking < 40) return { input: { cursor: banner(2, 0), button: clicking > 30 } };
  } else if (pause && since && !(status(host) & STATUS.paused) && !(status(guest) & STATUS.paused)) {
    if (peer.at - since > 1000) ++pausing, (since = clicking = 0);
  }
  if (!machines.hitch && confirmed(host) >= HITCH.at)
    machines.hitch = { peer: guest, from: time(), to: time() + HITCH.ms };
  if (!machines.burst && confirmed(host) >= BURST.at)
    machines.burst = { from: host.seat, at: time(), left: BURST.left };
  if (peer === guest) {
    const unfocused = confirmed(host) > 400 && confirmed(host) < 600;
    if (unfocused !== away) {
      away = unfocused;
      guest.g.game_activate(away ? 0 : 1);
    }
    if (away) return { input: {} };
  }
  const asks = picks[peer.role] === 0 && (peer === host || picks[0]) && !(status(peer) & STATUS.paused);
  if (asks && target(peer).pending > 0 && peer.frames % 30 === 0) taps.push(Q);
  return { taps };
};
// While paused, no machine runs a tick past the records it had.
let pausedAt = -1, stalled = 0, paused = 0;
const watched = (peer) => {
  if (status(host) & STATUS.paused) {
    if (pausedAt < 0) (pausedAt = confirmed(host)), ++paused;
    stalled = Math.max(stalled, confirmed(host) - pausedAt);
  } else pausedAt = -1;
  return player(peer);
};
play(
  watched,
  () => peers.every((p) => confirmed(p) >= 1500 && screen(p) === GAMEPLAY) && picks[0] && picks[1] && !pauses[pausing],
  "1500 confirmed ticks, both players' picks and both pauses",
);
assert.equal(paused, 2, "the pauses");
assert.ok(stalled <= 16, `a pause stopped the run ${stalled} ticks on`);
still = true;
play(player, () => peers.every((p) => screen(p) === GAME_OVER), "the team's death");
still = false;
const first = ended("death");
midpointAim();
// Each perk command is its picker's: the Host's menu and pick, then the Guest's. The Host's keys moved as it bound
// them (E forward, S left: neither moves by default); the Guest's machine missed packets, the burst among them,
// and the stutter came and went.
const PICKS = /^PerkMenuOpenCommand:0 PerkPickCommand:0 .*PerkMenuOpenCommand:1 PerkPickCommand:1/;
assert.match(first.commands, PICKS, first.commands);
const moves = new Set([...host.ticks.values()].map(({ used: [r] }) => `${r.readFloatLE(0)},${r.readFloatLE(4)}`));
assert.ok(moves.has("0,-1") && moves.has("-1,0"), [...moves].join(" "));
assert.ok(first.lost[1] >= BURST.left && machines.burst.left === 0 && time() > machines.hitch.to, `${first.lost}`);

// The Guest's pad steps to the name field and saves its score, then A on Play Again, the first button. The Host
// still shows its name entry: for a second neither screen leaves the end screen, and only the Host's machine has
// the Guest's word that its name is in. The Host's Enter saves its name, and both screens come to the next run.
settle(guest, GAME_OVER);
const hostScores = scores(host), guestScores = scores(guest);
tap(guest, DOWN, A);
play(idle, () => scores(guest) > guestScores, "the Guest's saved score");
settle(guest, GAME_OVER);
tap(guest, A);
const waiting = () =>
  peers.every((p) => screen(p) === GAME_OVER) && !(status(host) & STATUS.starting) && status(host) & STATUS.signed &&
  !(status(guest) & STATUS.signed) && scores(host) === hostScores;
hold(1000, waiting, "the Host's name entry");
tap(host, key(ENTER));
play(idle, started, "the next run's start");
assert.equal(scores(host), hostScores + 1, "the Host's saved score");

// Both players play to the next run's first level, where both ask for the perk menu on the same tick, each
// machine's request going on its next record as both have made as many: the Host's wins. While its perk screen
// shows, the Guest pauses with Start; the Host picks, and back in the paused run the Guest's d-pad steps to the
// banner's Leave and its A presses it: both run to the same last tick, after the pick, and go back to the main
// menu, each with its replay.
script = () => ({});
const level = (p) => screen(p) === GAMEPLAY && target(p).pending > 0;
play(player, () => peers.every(level) && host.g.game_coop_produced() === guest.g.game_coop_produced(), "a level");
for (const peer of peers) assert.equal(peer.g.game_coop_request(ASK_OPEN, 0, 0, 0, peer.run.clock), 1);
play(player, () => screen(host) === PERK_SELECTION, "the Host's perk screen");
tap(guest, START);
play(idle, () => peers.every((p) => status(p) & STATUS.paused), "the pause");
// The perk screen takes clicks once it has come in.
settle(host, PERK_SELECTION, idle, 1000);
click(host, PERK_SELECTION, PERK_CHOICE);
settle(host, GAMEPLAY, idle, 100);
tap(guest, RIGHT, A);
left(guest);
for (const peer of peers) assert.equal(stat(peer, DOUBLE_OPENS), 1, "a tie");
const second = ended("incomplete");
assert.equal(second.commands, "PerkMenuOpenCommand:0 PerkPickCommand:0");

// A desync: the Guest's player gains health between ticks, the next confirmed tick's hashes differ, and both
// machines stop there. The Host's Enter and the Guest's A press the banner's Leave, its one button.
survival();
play(player, () => peers.every((p) => confirmed(p) >= 200), "the third run's 200 ticks");
assert.equal(guest.g.game_coop_corrupt(0), 1);
play(player, () => peers.every((p) => status(p) & STATUS.desynced), "the desync");
const desync = peers.map((p) => new Int32Array(p.g.memory.buffer, p.g.game_coop_desync(), 1)[0]);
assert.equal(desync[0], desync[1], "both find the desync at the same tick");
tap(host, key(ENTER));
tap(guest, A);
play(idle, () => peers.every((p) => screen(p) === MAIN_MENU), "the menus after the desync");

// A lost connection, the machines in each other's seats: the Guest's machine starts the run by its mouse. 200
// ticks in, the Host's machine's page closes, so the Guest's machine's transport says the partner left the room and
// the Host's that it closed. Each machine ends the run where it confirmed it, saves it and goes to the menu.
survival([1, 0]);
play(player, () => peers.every((p) => confirmed(p) >= 200), "the fourth run's 200 ticks");
assert.equal(guest.g.game_coop_disconnect(PARTNER_GONE), 1);
assert.equal(host.g.game_coop_disconnect(DISCONNECTED), 1);
play(idle, () => peers.every((p) => screen(p) === MAIN_MENU), "the menus after the lost connection");
assert.deepEqual(peers.map(reason), [DISCONNECTED, PARTNER_GONE]);
agreed();
midpointAim();
for (const peer of peers) verified(peer, confirmed(peer) + 1, "incomplete");
// The Host's menus are its own again: its panel lays out its own progress, and its quest list starts no quest
// past its fourth (key 9 asks for the ninth).
click(host, MAIN_MENU, PLAY_GAME);
click(host, PLAY_GAME_MENU, OWN_QUESTS);
settle(host, QUEST_SELECT);
tap(host, key(NINE));
settle(host, QUEST_SELECT, idle, 1000);

// Quests. A session opens while the Host's quest list shows, and its number key starts the first quest; both
// players clear it. On the results (a few seconds reveal the final time first) the Guest's pad saves its name and
// the Host's Enter its own. The Guest's pad opens the high scores, the third button, whose Play a game starts
// nothing; the Host's Enter on Play Next, the first, starts the second quest, and the Guest's screen comes to it.
connect();
settle(host, QUEST_SELECT);
tap(host, key(ONE));
play(idle, started, "the first quest's start");
play(player, () => peers.every((p) => screen(p) === QUEST_RESULTS), "the first quest's end");
const quest = ended("quest_completed");
settle(guest, QUEST_RESULTS, idle, 5000);
tap(guest, DOWN, A);
tap(host, key(ENTER));
settle(guest, QUEST_RESULTS, idle, 1000);
tap(guest, DOWN, DOWN, A);
click(guest, HIGHSCORES, PLAY_A_GAME);
hold(1000, () => screen(guest) === HIGHSCORES && screen(host) === QUEST_RESULTS, "Play a game");
tap(host, key(ENTER));
play(idle, started, "the second quest's start");
// Both stand still until it fails; the Host's Tab and Enter press Play Another, the second button, and both
// screens go to the quest list, where the Host's key starts the first quest again.
still = true;
play(player, () => peers.every((p) => screen(p) === QUEST_FAILED), "the second quest's failure");
const failed = ended("death");
settle(host, QUEST_FAILED);
tap(host, key(TAB), key(ENTER));
play(idle, () => peers.every((p) => screen(p) === QUEST_SELECT), "the quest lists");
settle(host, QUEST_SELECT);
tap(host, key(ONE));
play(player, () => peers.every((p) => screen(p) === QUEST_FAILED), "the first quest's failure");
still = false;
const again = ended("death");
// The Host's Tab, Tab and Enter press Main Menu, the third button, and the Guest's A Play Again right after: the
// Host leaves at its click, which wins.
settle(host, QUEST_FAILED);
tap(host, key(TAB), key(TAB), key(ENTER));
tap(guest, A);
left(host);

// Neither save nor either player's settings took anything from the sessions: closing writes each player's own.
for (const peer of peers) {
  peer.g.game_close();
  assert.throws(() => peer.run.frame(16), /the game quit/);
  peer.g.game_exit();
  assert.deepEqual(saved(peer), JSON.parse(peer.saved), `machine ${peer.seat}'s save`);
}
console.log(JSON.stringify({ first, second, quest, failed, again, stalled, desync: desync[0] }));
