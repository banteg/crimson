// Two machines play a co-op run inside the original (host/coop_live.inc): two
// games boot, each from its own copy of a game directory, and Node carries their
// sessions' messages between them with some latency, as the transport does
// (client/web/coop.js). The Host plays at 60 frames a second, the Guest at about
// 144. Once both are connected, the Host's menus start Survival and the Guest's
// screen follows into the run. Both players move by keys and fire by mouse, the
// Host's aiming at the nearest creature; the Host asks for the first perk menu
// and picks on its perk screen, then the Guest the next; the Guest pauses the
// run and resumes it, and its window loses the focus for a while, where it plays
// on. Past 1000 ticks and both picks both players stand still until the
// creatures kill them: both show the game over screen. The Guest saves its
// score and clicks Play Again by pad, and the Host's screen follows into the
// next run; a few seconds in, the Host leaves: both runs end on the same tick and
// both machines go back to the main menu. In both runs every tick both
// confirmed has the same state hash on both, and both machines saved the same
// replay byte for byte, which the Python port verifies as a 2-player run (the
// first's picks each its picker's); neither player's save took the runs'
// progress or the session's unlocked quests.
//
//   node crimson-core/checks/game_coop_session.mjs <game directory> [game.wasm]
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { CORE, field, names, state } from "./engine.mjs";
import { bootGame, INPUT } from "./game_host.mjs";

const [given, gameWasm = new URL("build/game/game.wasm", CORE).pathname] = process.argv.slice(2);
if (!given) throw Error("usage: game_coop_session.mjs <game directory> [game.wasm]");

// game_state_id_t, DirectInput scancodes, and the session's (host/coop_wire.inc).
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, PERK_SELECTION = 6, GAME_OVER = 7, GAMEPLAY = 9;
const [ESCAPE, W, A, S, D, SPACE] = [0x01, 0x11, 0x1e, 0x1f, 0x20, 0x39];
const STATUS = { connected: 1, started: 2, paused: 4 }, ASK_LEAVE = 3, TICKS = 1000;
// One way, in milliseconds; each peer's frame times; where a fresh profile lays out the perk menu's first choice.
const LATENCY = [25, 45];
const FRAMES = [[16, 17, 17], [7, 7, 7, 6, 7]];
const PERK_CHOICE = [150, 216];
// The pad's A and the d-pad's down (game/host_input.h).
const PAD_SOUTH = 1, HAT_DOWN = 18000;

const peers = [0, 1].map((seat) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `crimson-coop-${seat}-`));
  process.on("exit", () => fs.rmSync(directory, { recursive: true, force: true }));
  fs.cpSync(given, directory, { recursive: true });
  const run = bootGame(gameWasm, directory, seat + 1);
  const { game } = run;
  return { seat, directory, run, game, at: 0, frames: 0, inbox: [], hashes: new Map(), top: -1, held: new Set() };
});
const [host, guest] = peers;
let now = 0;

// A frame of a peer: held keys, tapped keys (a press, then a release), the cursor as DirectInput motion, the left
// button and the pad's buttons and hat. What arrived by then goes in first; what the frame sends leaves after it.
function frame(peer, { cursor = [512, 384], keys = [], taps = [], button = false, pad } = {}) {
  const { run, game } = peer;
  const input = run.input();
  const events = [...taps.map((k) => [k, 1]), ...[...peer.held].filter((k) => !taps.includes(k)).map((k) => [k, 0])];
  for (const [key, down] of events) {
    const n = input.getInt32(INPUT.event_count, true);
    input.setUint8(INPUT.events + n * 2, key);
    input.setUint8(INPUT.events + n * 2 + 1, down);
    input.setInt32(INPUT.event_count, n + 1, true);
  }
  peer.held = new Set(taps);
  for (const key of [ESCAPE, W, A, S, D, SPACE])
    input.setUint8(INPUT.keys + key, keys.includes(key) || peer.held.has(key) ? 0x80 : 0);
  input.setInt32(INPUT.motion_x, Math.round(game.game_motion_x(cursor[0])), true);
  input.setInt32(INPUT.motion_y, Math.round(game.game_motion_y(cursor[1])), true);
  input.setUint8(INPUT.buttons, button ? 0x80 : 0);
  // A pad once used stays connected.
  pad ??= peer.padded && {};
  peer.padded ||= !!pad;
  input.setUint8(INPUT.pad_connected, pad ? 1 : 0);
  input.setUint32(INPUT.pad_hat, pad?.hat ?? 0xffffffff, true);
  for (let b = 0; b < 32; ++b) input.setUint8(INPUT.pad_buttons + b, pad?.press?.includes(b) ? 0x80 : 0);
  for (const message of peer.inbox.filter((m) => m.at <= now)) {
    const at = game.game_coop_rx(message.bytes.length);
    new Uint8Array(game.memory.buffer, at, message.bytes.length).set(message.bytes);
    game.game_coop_receive(message.channel, message.bytes.length, run.clock);
  }
  peer.inbox = peer.inbox.filter((m) => m.at > now);
  const pattern = FRAMES[peer.seat];
  const dt = pattern[peer.frames++ % pattern.length];
  run.frame(dt);
  game.game_audio(Math.round((dt * 44100) / 1000));
  // Channel 1 arrives in order: a message never overtakes an earlier one.
  const other = peers[1 - peer.seat];
  for (const channel of [0, 1])
    for (let size; (size = game.game_coop_tx(channel, run.clock)) > 0; ) {
      const bytes = Buffer.from(new Uint8Array(game.memory.buffer, game.game_coop_tx_buffer(), size));
      let at = now + LATENCY[other.inbox.length % 2];
      if (channel === 1) at = Math.max(at, ...other.inbox.filter((m) => m.channel === 1).map((m) => m.at));
      other.inbox.push({ at, channel, bytes });
    }
  peer.at += dt;
  // The run's confirmed ticks' hashes, while the engine's ring holds them.
  const top = game.game_coop_confirmed();
  if (top < peer.top) peer.hashes.clear();
  peer.top = top;
  for (let t = Math.max(0, top - 64); t <= top; ++t)
    if (!peer.hashes.has(t) && game.game_coop_hash_at(t)) peer.hashes.set(t, game.game_coop_hash_at(t));
}
// Both peers' frames in time order, each with the input `input` gives it, until `done`.
function play(input, done, what, limit = 300000) {
  while (!done()) {
    if (now > limit) throw Error(`${what} never happened`);
    const peer = host.at <= guest.at ? host : guest;
    now = peer.at;
    frame(peer, input(peer));
  }
}
const idle = () => ({});
const status = (peer) => peer.game.game_coop_status();
const confirmed = (peer) => peer.game.game_coop_confirmed();
const started = () => peers.every((p) => p.game.game_state() === GAMEPLAY && status(p) & STATUS.started);
// Plays until `peer` shows `screen` for a second.
function settle(peer, screen, input = idle) {
  let settled = 0;
  play(input, () => (peer.game.game_state() === screen ? ++settled : (settled = 0)) > 60, `screen ${screen}`);
}

// On a fresh profile the main menu shares its screen id with the startup sequence, which ends after about 14 s.
play(idle, () => host.at > 15000 && guest.at > 15000, "the startup");
for (const peer of peers) assert.equal(peer.game.game_coop_connect(peer.seat, peer.run.clock), 1);
play(idle, () => peers.every((p) => status(p) & STATUS.connected), "the hello");

// Holds the cursor on a spot until the screen settles, then clicks it.
function click(peer, screen, at) {
  let frames = 0;
  settle(peer, screen, (p) => (p === peer ? { cursor: at } : {}));
  play((p) => (p === peer ? { cursor: at, button: frames++ < 10 } : {}), () => frames > 12, "the click");
}
// The Host clicks Play Game, then Survival: with every quest unlocked the panel lays out Tutorial, Quests, Rush and
// Survival 28 pixels apart.
click(host, MAIN_MENU, [240, 338]);
click(host, PLAY_GAME_MENU, [232, 400]);
play(idle, started, "the run's start");

// The nearest live creature's screen position and the way away from it, in this machine's run.
const CREATURES = names.filter((n) => /^creatures\[\d+\]\.active$/.test(n)).length;
function target(peer) {
  const { game } = peer;
  state(game);
  const f = (n) => field(game, n, true);
  const px = f(`players[${peer.seat}].pos_x`), py = f(`players[${peer.seat}].pos_y`);
  let best = Infinity, aim = [512, 300], away = [0, 1];
  for (let i = 0; i < CREATURES; i++) {
    if (!field(game, `creatures[${i}].active`) || f(`creatures[${i}].health`) <= 0) continue;
    const x = f(`creatures[${i}].pos_x`), y = f(`creatures[${i}].pos_y`);
    const d = (x - px) ** 2 + (y - py) ** 2;
    if (d < best) {
      best = d;
      aim = [x + f("globals.camera_offset_x"), y + f("globals.camera_offset_y")];
      away = [px - x, py - y];
    }
  }
  return { aim, away, pending: field(game, "globals.perk_pending_count") };
}

// Each player moves away from the nearest creature, the Host aiming at it and the Guest on a circle; both fire in
// bursts. The Host opens the first perk menu and picks the first choice, the Guest the next and the second choice
// (each clicking on as its screen closes). The Guest pauses at tick 300 and resumes a second later, and its window
// is in the background from tick 400 to 600, where its player stands still.
const picks = [0, 0];
let pauseAt = null, away = false, still = false;
function player(peer) {
  const { game, seat } = peer;
  if (game.game_state() === PERK_SELECTION) {
    peer.pickFrames = (peer.pickFrames ?? 0) + 1;
    if (peer.pickFrames === 60) ++picks[seat];
    const button = peer.pickFrames > 60 && peer.pickFrames < 75;
    return { cursor: [PERK_CHOICE[0], PERK_CHOICE[1] + 19 * seat], button };
  }
  peer.pickFrames = 0;
  if (game.game_state() !== GAMEPLAY || still) return {};
  const { aim, away: from, pending } = target(peer);
  const taps = [];
  if (seat === 1) {
    if (pauseAt === null && confirmed(host) >= 300) {
      pauseAt = peer.at;
      taps.push(ESCAPE);
    } else if (pauseAt && peer.at - pauseAt > 1000 && status(peer) & STATUS.paused) {
      pauseAt = 0;
      taps.push(ESCAPE);
    }
    const unfocused = confirmed(host) > 400 && confirmed(host) < 600;
    if (unfocused !== away) {
      away = unfocused;
      game.game_activate(away ? 0 : 1);
    }
    if (away) return {};
  }
  // The perk key asks again every half second while a pick is this player's to make.
  if (pending > 0 && picks[0] + picks[1] === seat && peer.frames % 30 === 0) taps.push(SPACE);
  const angle = (peer.frames / 300) * Math.PI * 2;
  return {
    cursor: seat ? [512 + Math.cos(angle) * 200, 384 + Math.sin(angle) * 150] : aim,
    keys: [Math.abs(from[0]) > Math.abs(from[1]) ? (from[0] < 0 ? A : D) : from[1] < 0 ? W : S],
    taps,
    button: Math.floor(peer.at / 400) % 3 !== 2,
  };
}
// While paused, no machine runs a tick past the records it had.
let pausedAt = -1, stalled = 0;
play(
  (peer) => {
    if (status(host) & STATUS.paused) {
      if (pausedAt < 0) pausedAt = confirmed(host);
      stalled = Math.max(stalled, confirmed(host) - pausedAt);
    }
    return player(peer);
  },
  () => peers.every((p) => confirmed(p) >= TICKS && p.game.game_state() === GAMEPLAY) && picks[0] && picks[1],
  "1000 confirmed ticks and both players' picks",
);
assert.ok(pausedAt >= 0 && stalled <= 16, `the pause stopped the run ${stalled} ticks on`);
assert.ok(!(status(host) & STATUS.paused), "the run stayed paused");
still = true;
play(player, () => peers.every((p) => p.game.game_state() === GAME_OVER), "the team's death", 900000);
still = false;

// A run both machines ended: the same last tick, the same hash for every tick, the same replay, which the Python
// port verifies and ends as the run did. Its perk commands.
const python = (script, ...args) =>
  execFileSync("uv", ["run", "--no-sync", "python", "-c", script, ...args], { encoding: "utf8" }).trim();
function ended(number, outcome) {
  const last = confirmed(host);
  assert.equal(confirmed(guest), last, "both runs end on the same tick");
  let compared = 0;
  for (const [t, hash] of host.hashes)
    if (t <= last && guest.hashes.has(t)) {
      assert.equal(guest.hashes.get(t), hash, `tick ${t}'s state hash`);
      ++compared;
    }
  assert.equal(compared, last + 1, "every confirmed tick's hash on both");
  const [saved, theirs] = peers.map((p) => path.join(p.directory, `replays/${number}-survival.crd`));
  const replay = fs.readFileSync(saved);
  assert.ok(replay.equals(fs.readFileSync(theirs)), "the two replays differ");
  const verify = ["run", "--no-sync", "crimson", "replay", "verify", "--format", "json", saved];
  const verified = JSON.parse(execFileSync("uv", verify, { encoding: "utf8" }));
  assert.equal(verified.status, "ok", JSON.stringify(verified));
  assert.equal(verified.ticks, last + 1);
  assert.equal(verified.result.outcome, outcome);
  assert.equal(verified.result.players.length, 2);
  assert.deepEqual(verified.mismatched_fields, []);
  const commands = python(
    "import sys; from pathlib import Path; from crimson.replay.codec import load_replay; " +
      "r = load_replay(Path(sys.argv[1]).read_bytes()); " +
      "print(' '.join(f'{type(c).__name__}:{c.player_index}' for t in r.ticks for c in t.commands))",
    saved,
  );
  return { ticks: last + 1, commands, replay_bytes: zlib.zstdDecompressSync(replay).length };
}
const first = ended(1, "death");
// Each perk command is its picker's: the Host's menu and pick, then the Guest's.
const PICKS = /^PerkMenuOpenCommand:0 PerkPickCommand:0 .*PerkMenuOpenCommand:1 PerkPickCommand:1/;
assert.match(first.commands, PICKS, first.commands);

// The Guest's pad steps to the name field and saves its score, then A on Play Again, the first button: the Host
// starts the next run, and both screens come to it. Both players play its first 300 ticks.
function tap(peer, pad) {
  let frames = 0;
  play((p) => (p === peer ? { pad: frames++ < 3 ? pad : {} } : {}), () => frames >= 6, "a tap");
}
settle(guest, GAME_OVER);
const scores = path.join(guest.directory, "scores5");
for (const pad of [{ hat: HAT_DOWN }, { press: [PAD_SOUTH] }]) tap(guest, pad);
play(idle, () => fs.existsSync(scores) && fs.readdirSync(scores).length > 0, "the Guest's saved score");
settle(guest, GAME_OVER);
tap(guest, { press: [PAD_SOUTH] });
play(idle, started, "the next run's start");
play(player, () => peers.every((p) => confirmed(p) >= 300), "the next run's 300 ticks");

// The Host leaves: both run to the same last tick and go back to the main menu, each with its replay saved.
assert.equal(host.game.game_coop_request(ASK_LEAVE, 0, 0, 0, host.run.clock), 1);
const left = (p) => fs.existsSync(path.join(p.directory, "replays/2-survival.crd"));
play(idle, () => peers.every((p) => p.game.game_state() === MAIN_MENU && left(p)), "the leave");
const second = ended(2, "incomplete");

// Neither save took the run or the session's quests: closing writes each player's own status.
for (const peer of peers) {
  peer.game.game_close();
  assert.throws(() => peer.run.frame(16), /the game quit/);
  peer.game.game_exit();
}
const statuses = python(
  "import sys; from pathlib import Path; from crimson.persistence.save_status import load_status; " +
    "s = [load_status(Path(p) / 'game.cfg') for p in sys.argv[1:]]; " +
    "print(' '.join(f'{x.quest_unlock_index}/{x.quest_unlock_index_hardcore}/{x.mode_play_survival}' for x in s))",
  ...peers.map((p) => p.directory),
);
assert.equal(statuses, "0/0/0 0/0/0", "a player's save");
console.log(JSON.stringify({ first, second, stalled }));
