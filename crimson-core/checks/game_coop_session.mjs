// Two machines play co-op runs inside the original (host/coop_live.inc): two
// games boot, each from its own copy of a game directory, and Node carries their
// sessions' messages between them with some latency, as the transport does
// (client/web/coop.js). The Host plays at 60 frames a second, the Guest at about
// 144. Three sessions, each opened on both machines as the transport opens one:
//
// Survival. The Host's menus start it and the Guest's screen follows into the
// run. Both players move by keys and fire by mouse, the Host's aiming at the
// nearest creature. Both ask for the first perk menu on the same tick: the Host's
// request wins, and it picks on its perk screen while the Guest's card shows the
// pick; then the Guest asks for the next and picks. The Guest pauses and
// the Host resumes from the pause banner's button; the Host pauses and the
// Guest resumes with Escape; the Guest's window loses the focus for a while,
// where it plays on. Then both stand still until the creatures kill them: both
// show the game over screen. The Guest saves its score and clicks Play Again by
// pad, and the Host's screen follows into the next run; a few seconds in, the
// Host pauses and leaves from the banner: both runs end on the same tick, both
// machines go back to the main menu, and the Guest learns the Host left.
//
// A desync. A run whose state the Guest's machine changes between ticks stops
// on both at the same tick with the desync banner; Escape takes the Host to the
// menu, the banner's Leave the Guest.
//
// A lost connection. The transport closes on both sides a few seconds into a
// run: each machine ends it where it confirmed it and goes to the menu.
//
// Quests. The Host starts the first quest from its quest list, which both
// players clear; the Guest clicks Play Next on the results, and the Host starts
// the next quest. Both stand still until it fails, and the Host's Main Menu on
// that screen leaves the session.
//
// In every run both played to its end or a leave, every tick both confirmed has the same state hash
// on both, and both machines saved the same replay byte for byte, which the
// Python port verifies as a 2-player run (the first's perk commands each its
// picker's); neither player's save took the runs' progress or the session's
// unlocked quests.
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
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, PERK_SELECTION = 6, GAME_OVER = 7, QUEST_RESULTS = 8, GAMEPLAY = 9;
const QUEST_SELECT = 11, QUEST_FAILED = 12;
const [ESCAPE, ONE, W, A, S, D, SPACE] = [0x01, 0x02, 0x11, 0x1e, 0x1f, 0x20, 0x39];
const STATUS = { connected: 1, started: 2, paused: 4, leaving: 32, desynced: 128 };
const ASK_OPEN = 1, TICKS = 1000;
// Why a session ended (CoopReason).
const PARTNER_LEFT = 8, DISCONNECTED = 9, PARTNER_GONE = 10;
// One way, in milliseconds; each peer's frame times; where a fresh profile lays out the perk menu's first choice.
const LATENCY = [25, 45];
const FRAMES = [[16, 17, 17], [7, 7, 7, 6, 7]];
const PERK_CHOICE = [150, 216];
// The pad's A and the d-pad's down (game/host_input.h).
const PAD_SOUTH = 1, HAT_DOWN = 18000;
// CoopStats' double_opens (host/coop.inc).
const DOUBLE_OPENS = 14;
// A banner's `count` buttons across a 1024x768 frame (coop_banner): 145 wide and 16 apart, centred, 58 below the
// band's top; the centre of button `i`.
const banner = (count, i) => [
  Math.floor((1024 - count * 161 + 16) / 2) + i * 161 + 72,
  Math.floor((768 - 104) / 2) + 74,
];

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
  for (const key of [ESCAPE, ONE, W, A, S, D, SPACE])
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
function play(input, done, what, limit = now + 600000) {
  while (!done()) {
    if (now > limit) throw Error(`${what} never happened`);
    const peer = host.at <= guest.at ? host : guest;
    now = peer.at;
    frame(peer, input(peer));
  }
}
const idle = () => ({});
const status = (peer) => peer.game.game_coop_status();
const reason = (peer) => (status(peer) >> 16) & 255;
const confirmed = (peer) => peer.game.game_coop_confirmed();
const screen = (peer) => peer.game.game_state();
const started = () => peers.every((p) => screen(p) === GAMEPLAY && status(p) & STATUS.started);
// Plays until `peer` has shown `id` for `ms`.
function settle(peer, id, input = idle, ms = 300) {
  let since = Infinity;
  const shown = () => now - (screen(peer) === id ? (since = Math.min(since, now)) : (since = Infinity)) >= ms;
  play(input, shown, `screen ${id}`);
}
// Holds the cursor on a spot until the screen settles, then clicks it.
function click(peer, id, at) {
  let frames = 0;
  settle(peer, id, (p) => (p === peer ? { cursor: at } : {}));
  play((p) => (p === peer ? { cursor: at, button: frames++ < 10 } : {}), () => frames > 12, "the click");
}
// A key or pad press of one peer.
function tap(peer, input) {
  let frames = 0;
  play((p) => (p === peer ? (frames++ < 3 ? input : input.pad ? { pad: {} } : {}) : {}), () => frames >= 6, "a tap");
}
// Both sessions open, and both said hello.
function connect() {
  for (const peer of peers) assert.equal(peer.game.game_coop_connect(peer.seat, peer.run.clock), 1);
  play(idle, () => peers.every((p) => status(p) & STATUS.connected), "the hello");
}

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

// Each player moves away from the nearest creature and aims at it, firing in bursts. On its perk screen a player
// picks a choice by its seat (clicking on as the screen closes). `still` players stand. `script` adds taps, asks for
// a perk menu (`pick`), or takes over the input.
const picks = [0, 0];
let still = false, script = () => ({});
function player(peer) {
  const { seat } = peer;
  if (screen(peer) === PERK_SELECTION) {
    peer.pickFrames = (peer.pickFrames ?? 0) + 1;
    if (peer.pickFrames === 60) ++picks[seat];
    const button = peer.pickFrames > 60 && peer.pickFrames < 75;
    return { cursor: [PERK_CHOICE[0], PERK_CHOICE[1] + 19 * seat], button };
  }
  peer.pickFrames = 0;
  if (screen(peer) !== GAMEPLAY || still) return {};
  const { input, taps = [], pick } = script(peer);
  if (input) return input;
  const { aim, away: from, pending } = target(peer);
  return {
    cursor: aim,
    keys: [Math.abs(from[0]) > Math.abs(from[1]) ? (from[0] < 0 ? A : D) : from[1] < 0 ? W : S],
    taps: pending > 0 && pick ? [...taps, SPACE] : taps,
    button: Math.floor(peer.at / 400) % 3 !== 2,
  };
}

const python = (code, ...args) =>
  execFileSync("uv", ["run", "--no-sync", "python", "-c", code, ...args], { encoding: "utf8" }).trim();
// A peer's replay of its `number`th run, which the Python port verifies as a 2-player run of `ticks` ending in
// `outcome`.
function verified(peer, number, ticks, outcome) {
  const replays = path.join(peer.directory, "replays");
  const saved = path.join(replays, fs.readdirSync(replays).find((name) => name.startsWith(`${number}-`)));
  const verify = ["run", "--no-sync", "crimson", "replay", "verify", "--format", "json", saved];
  const result = JSON.parse(execFileSync("uv", verify, { encoding: "utf8" }));
  assert.equal(result.status, "ok", JSON.stringify(result));
  assert.equal(result.ticks, ticks);
  assert.equal(result.result.outcome, outcome);
  assert.equal(result.result.players.length, 2);
  assert.deepEqual(result.mismatched_fields, []);
  return saved;
}
// A run both machines ended: the same last tick, the same hash for every tick, the same replay, which the Python
// port verifies and ends as the run did. Its perk commands.
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
  const saved = verified(host, number, last + 1, outcome);
  const replay = fs.readFileSync(saved);
  assert.ok(replay.equals(fs.readFileSync(saved.replace(host.directory, guest.directory))), "the two replays differ");
  const commands = python(
    "import sys; from pathlib import Path; from crimson.replay.codec import load_replay; " +
      "r = load_replay(Path(sys.argv[1]).read_bytes()); " +
      "print(' '.join(f'{type(c).__name__}:{c.player_index}' for t in r.ticks for c in t.commands))",
    saved,
  );
  return { ticks: last + 1, commands, replay_bytes: zlib.zstdDecompressSync(replay).length };
}
// Both machines back on the main menu once a leave ended the session, the partner told who left.
function left(leaver) {
  play(idle, () => peers.every((p) => screen(p) === MAIN_MENU && !(status(p) & STATUS.connected)), "the leave");
  assert.equal(reason(peers[1 - leaver.seat]), PARTNER_LEFT, "the partner learns who left");
}

// On a fresh profile the main menu shares its screen id with the startup sequence, which ends after about 14 s.
play(idle, () => host.at > 15000 && guest.at > 15000, "the startup");

// A session, and in it the Host's Survival run: it clicks Play Game, then Survival (with every quest unlocked the
// panel lays out Tutorial, Quests, Rush and Survival 28 pixels apart), and the Guest's screen follows.
function survival() {
  connect();
  click(host, MAIN_MENU, [240, 338]);
  click(host, PLAY_GAME_MENU, [232, 400]);
  play(idle, started, "the run's start");
}
survival();

// Both players ask for the first perk menu on the same tick, each machine's request going on its next record as
// both have made as many: the Host's wins, and its perk screen picks. The Guest's perk key asks for the second every
// half second until its screen opens. The Guest pauses at tick 300 and the Host resumes a second later from the
// banner's Resume, its first button; the Host pauses at tick 700 and the Guest resumes with Escape. The Guest's
// window is in the background from tick 400 to 600, where its player stands.
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
  if (peer === guest) {
    const unfocused = confirmed(host) > 400 && confirmed(host) < 600;
    if (unfocused !== away) {
      away = unfocused;
      guest.game.game_activate(away ? 0 : 1);
    }
    if (away) return { input: {} };
  }
  return { taps, pick: peer === guest && picks[0] && !picks[1] && peer.frames % 30 === 0 };
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
const level = (p) => screen(p) === GAMEPLAY && !(status(p) & STATUS.paused) && target(p).pending > 0;
const even = () => host.game.game_coop_produced() === guest.game.game_coop_produced();
play(watched, () => peers.every(level) && even(), "a level for both to ask");
for (const peer of peers) assert.equal(peer.game.game_coop_request(ASK_OPEN, 0, 0, 0, peer.run.clock), 1);
play(
  watched,
  () => peers.every((p) => confirmed(p) >= TICKS && screen(p) === GAMEPLAY) && picks[0] && picks[1] && !pauses[pausing],
  "1000 confirmed ticks, both players' picks and both pauses",
);
assert.equal(paused, 2, "the pauses");
assert.ok(stalled <= 16, `a pause stopped the run ${stalled} ticks on`);
for (const peer of peers)
  assert.equal(new Int32Array(peer.game.memory.buffer, peer.game.game_coop_stats(), 32)[DOUBLE_OPENS], 1, "a tie");
still = true;
play(player, () => peers.every((p) => screen(p) === GAME_OVER), "the team's death");
still = false;
const first = ended(1, "death");
// Each perk command is its picker's: the Host's menu and pick from the tie, then the Guest's.
const PICKS = /^PerkMenuOpenCommand:0 PerkPickCommand:0 .*PerkMenuOpenCommand:1 PerkPickCommand:1/;
assert.match(first.commands, PICKS, first.commands);

// The Guest's pad steps to the name field and saves its score, then A on Play Again, the first button: the Host
// starts the next run, and both screens come to it. Both players play its first 300 ticks; the Host pauses and
// clicks Leave on the banner: both run to the same last tick and go back to the main menu, each with its replay.
settle(guest, GAME_OVER);
const scores = path.join(guest.directory, "scores5");
for (const pad of [{ hat: HAT_DOWN }, { press: [PAD_SOUTH] }]) tap(guest, { pad });
play(idle, () => fs.existsSync(scores) && fs.readdirSync(scores).length > 0, "the Guest's saved score");
settle(guest, GAME_OVER);
tap(guest, { pad: { press: [PAD_SOUTH] } });
play(idle, started, "the next run's start");
script = () => ({});
play(player, () => peers.every((p) => confirmed(p) >= 300), "the next run's 300 ticks");
tap(host, { taps: [ESCAPE] });
play(idle, () => peers.every((p) => status(p) & STATUS.paused), "the pause");
click(host, GAMEPLAY, banner(2, 1));
left(host);
const second = ended(2, "incomplete");

// A desync: the Guest's player gains health between ticks, the next confirmed tick's hashes differ, and both
// machines stop there. Escape and the banner's Leave go to the menu.
survival();
play(player, () => peers.every((p) => confirmed(p) >= 200), "the third run's 200 ticks");
assert.equal(guest.game.game_coop_corrupt(0), 1);
play(player, () => peers.every((p) => status(p) & STATUS.desynced), "the desync");
const desync = peers.map((p) => new Int32Array(p.game.memory.buffer, p.game.game_coop_desync(), 1)[0]);
assert.equal(desync[0], desync[1], "both find the desync at the same tick");
tap(host, { taps: [ESCAPE] });
click(guest, GAMEPLAY, banner(1, 0));
play(idle, () => peers.every((p) => screen(p) === MAIN_MENU), "the menus after the desync");

// A lost connection: 200 ticks into a run the Guest's page closes, so the Host's transport says the partner left the
// room and the Guest's that it closed. Each machine ends the run where it confirmed it, saves it and goes to the menu.
survival();
play(player, () => peers.every((p) => confirmed(p) >= 200), "the fourth run's 200 ticks");
assert.equal(host.game.game_coop_disconnect(PARTNER_GONE), 1);
assert.equal(guest.game.game_coop_disconnect(DISCONNECTED), 1);
play(idle, () => peers.every((p) => screen(p) === MAIN_MENU), "the menus after the lost connection");
assert.deepEqual(peers.map(reason), [PARTNER_GONE, DISCONNECTED]);
for (const peer of peers) verified(peer, 4, confirmed(peer) + 1, "incomplete");

// Quests. The Host clicks Play Game, then Quests, and starts the first quest with its number key; both players
// clear it. On the results the Guest's pad saves its name and clicks Play Next, the first button: the Host starts
// the second quest. Both stand still until it fails; the Host clicks Main Menu, the failed screen's third button.
connect();
click(host, MAIN_MENU, [240, 338]);
click(host, PLAY_GAME_MENU, [232, 344]);
settle(host, QUEST_SELECT);
tap(host, { taps: [ONE] });
play(idle, started, "the first quest's start");
play(player, () => peers.every((p) => screen(p) === QUEST_RESULTS), "the first quest's end");
const quest = ended(5, "quest_completed");
// The results reveal the final time first, which takes a few seconds.
settle(guest, QUEST_RESULTS, idle, 5000);
for (const pad of [{ hat: HAT_DOWN }, { press: [PAD_SOUTH] }]) tap(guest, { pad });
settle(guest, QUEST_RESULTS, idle, 1000);
tap(guest, { pad: { press: [PAD_SOUTH] } });
play(idle, started, "the second quest's start");
still = true;
play(player, () => peers.every((p) => screen(p) === QUEST_FAILED), "the second quest's failure");
still = false;
const failed = ended(6, "death");
settle(host, QUEST_FAILED);
for (const pad of [{ hat: HAT_DOWN }, { hat: HAT_DOWN }, { press: [PAD_SOUTH] }]) tap(host, { pad });
left(host);

// Neither save took the runs or the session's quests: closing writes each player's own status.
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
console.log(JSON.stringify({ first, second, quest, failed, stalled, desync: desync[0] }));
