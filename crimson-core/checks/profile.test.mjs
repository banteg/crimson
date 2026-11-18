import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const file = name => fs.readFileSync(new URL("../client/web/" + name, import.meta.url), "utf8");
const shell = file("shell.html");
const section = (start, end) => {
  const from = shell.indexOf(start), to = shell.indexOf(end, from);
  assert.ok(from >= 0 && to > from);
  return shell.slice(from, to);
};
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const codec = vm.createContext({ artHash: hash, Blob, TextEncoder, TextDecoder, Uint8Array, DataView });
vm.runInContext(file("backup.js"), codec);
const bytes = text => new TextEncoder().encode(text);
const storePath = "/game/";
function filesystem(entries) {
  const files = new Map([...entries].map(([name, data]) => [storePath + name, data]));
  const dirs = new Set();
  for (const name of files.keys()) {
    for (let p = name.lastIndexOf("/"); p > 0; p = name.lastIndexOf("/", p - 1)) dirs.add(name.slice(0, p));
  }
  const stat = path => ({ mode: files.has(path) ? 0o100644 : 0o40755, size: files.get(path)?.length });
  return {
    analyzePath: path => ({ exists: files.has(path) || dirs.has(path) }),
    isFile: mode => mode === 0o100644, lstat: stat, stat,
    readFile: path => files.get(path),
    readdir: path => [...files.keys(), ...dirs].filter(p => p.startsWith(path + "/") && !p.slice(path.length + 1).includes("/")).map(p => p.slice(path.length + 1)),
  };
}
const profile = new Map([
  ["game.cfg", bytes("progress")], ["crimson.cfg", bytes("configuration")], ["registry.cfg", bytes("registry")],
  ["render_mode.txt", bytes("classic")], ["reduce_camera_shake.txt", bytes("1")], ["scores.jsonl", bytes("scores")],
  ["replays/.last-number", bytes("16")], ["replays/16-quest.crd", bytes("recording")],
  ["leaderboard/outbox/" + "a".repeat(64) + ".json", bytes("queued")],
  ["leaderboard/rejected/" + "b".repeat(64) + ".json", bytes("rejected")],
  ["scores5/imported/quest1_3.hi.1", bytes("legacy")],
]);
const extras = [["identity.key", bytes("private")], ["sfx.paq", bytes("assets")], ["replays/online/shared.crd", bytes("download")]];
test("fresh profile backup restores every owned file, with separate identity and game assets", async () => {
  const archive = await codec.profileBackup(filesystem([...profile, ...extras]));
  const files = await codec.readProfile(archive);
  assert.deepEqual(Object.fromEntries(files), Object.fromEntries(profile));
  assert.equal(codec.profileName("identity.key"), false);
  assert.equal(codec.profileName("replays/../../identity.key"), false);
  assert.equal(codec.profileName("scores5/imported/../../identity.key"), false);
});
test("a profile root that links to private data is excluded from backup", async () => {
  const fs = filesystem([["identity.key", bytes("secret")], ["game.cfg", bytes("secret")]]);
  const lstat = fs.lstat;
  fs.lstat = path => path === "/game/game.cfg" ? { mode: 0o120777 } : lstat(path);
  const backup = await codec.profileBackup(fs);
  assert.equal((await codec.readProfile(backup)).size, 0);
});

test("damaged, duplicate, truncated and unsafe archives fail before any restore", async () => {
  const blob = await codec.profileBackup(filesystem(profile));
  const buf = new Uint8Array(await blob.arrayBuffer());
  buf[buf.length - 1] ^= 255;
  await assert.rejects(codec.readProfile(new Blob([buf])), /Damaged/);
  await assert.rejects(codec.readProfile(blob.slice(0, 12)), /size/);
  for (const names of [["game.cfg", "game.cfg"], ["../identity.key"], ["identity.key"], ["crimson.paq"]]) {
    const manifest = JSON.stringify(names.map(name => [name, 0, hash("")]));
    const length = Buffer.alloc(4);
    length.writeUInt32LE(Buffer.byteLength(manifest));
    await assert.rejects(codec.readProfile(new Blob(["Crimsonland profile backup 1\n", length, manifest])), /Invalid or duplicate/);
  }
});

// IDBFS exposes one readwrite transaction. The fake store only publishes its
// staged records after commit, so quota errors exercise the abort path too.
function idb(entries, fail = false) {
  const rows = new Map(entries);
  return { rows, DB_STORE_NAME: "FILE_DATA", getDB: (_name, success) => success(null, {
    transaction: (_store, mode) => {
      assert.equal(mode, "readwrite");
      const pending = new Map(rows);
      const tx = { objectStore: () => ({ put: (value, key) => pending.set(key, value), delete: key => pending.delete(key) }) };
      queueMicrotask(() => {
        if (fail) { tx.error = Error("quota"); return tx.onabort(); }
        rows.clear();
        for (const [key, value] of pending) rows.set(key, value);
        tx.oncomplete();
      });
      return tx;
    },
  }) };
}
test("profile restore uses one transaction, retains identity, and rolls back on quota failure", async () => {
  const initial = [["/game/identity.key", "existing key"], ["/game/replays/9-rush.crd", "existing run"]];
  const files = await codec.readProfile(await codec.profileBackup(filesystem(profile)));
  const fresh = idb(initial);
  await codec.commitProfile(fresh, files, ["replays/9-rush.crd"]);
  assert.equal(fresh.rows.get("/game/identity.key"), "existing key");
  assert.equal(fresh.rows.has("/game/replays/9-rush.crd"), false);
  for (const [name, data] of files) assert.deepEqual(fresh.rows.get(storePath + name).contents, data);
  assert.equal(fresh.rows.get("/game/leaderboard/outbox").mode, 0o40755);
  const full = idb(initial, true);
  await assert.rejects(codec.commitProfile(full, files, ["replays/9-rush.crd"]), /quota/);
  assert.deepEqual([...full.rows], initial);
});

function owner({ running, saved }) {
  const log = [];
  const ctx = vm.createContext({
    hydrate: async () => {}, ready() {}, stuck() {}, frameSource() {}, showFiles() {},
    Module: { ccall: name => log.push(name) }, persist: async () => (log.push("sync"), saved),
    location: { reload: () => log.push("reload") },
    BroadcastChannel: class { postMessage(data) { log.push(data.type); } },
  });
  vm.runInContext("let handoff = null, gameRunning = " + running + ", hydrated = true, gameReady = true, moved = false, fileBusy = false;\n"
    + section("  const LOCK =", "  // The game starts on a click") +
    '\nglobalThis.held = own(); globalThis.move = () => channel.onmessage({ data: { type: "move", request: "r" } }); globalThis.quit = async () => finishHandoff(await persist());', ctx);
  return { ctx, log };
}
test("a running owner waits for game shutdown and successful durable sync before relinquishing", async () => {
  const { ctx, log } = owner({ running: true, saved: true });
  await ctx.move();
  assert.deepEqual(log, ["saving", "client_close"]);
  await ctx.quit();
  await ctx.held;
  assert.deepEqual(log, ["saving", "client_close", "sync", "reload"]);
});
test("a failed handoff reports the save error and retains the lock", async () => {
  const { ctx, log } = owner({ running: false, saved: false });
  let released = false;
  ctx.held.then(() => { released = true; });
  await ctx.move();
  assert.deepEqual(log, ["saving", "sync", "failed"]);
  assert.equal(released, false);
});

function requester() {
  const refs = new Map(["here", "force-here", "elsewhere"].map(id => [id, {}]));
  const locks = [], grants = [], revoke = [], lost = [], timers = new Map(), sent = [];
  const channel = { postMessage: data => sent.push(data) };
  const ctx = vm.createContext({
    document: { getElementById: id => refs.get(id) }, crypto: { randomUUID: () => "id" },
    setTimeout: fn => (timers.set(1, fn), 1), clearTimeout: id => timers.delete(id),
    say() {}, channel, AbortController, LOCK: "lock", lost: error => lost.push(error), own() {},
    navigator: { locks: { request: (_name, options, take) => {
      locks.push(options);
      grants.push(take);
      return new Promise((_, reject) => revoke.push(reject));
    } } },
  });
  vm.runInContext(section("  function elsewhere()", "  /* PLAY_ANALYTICS */") + "\nelsewhere();", ctx);
  refs.get("here").onclick();
  return { refs, locks, grants, revoke, lost, channel, tick: () => {
    const due = [...timers.values()];
    timers.clear();
    for (const fn of due) fn();
  } };
}
test("an acknowledged save can take longer than the frozen-tab timeout without stealing the lock", () => {
  const { refs, locks, channel, tick } = requester();
  channel.onmessage({ data: { request: "id", type: "saving" } });
  tick();
  assert.equal(refs.get("force-here").hidden, true);
  assert.equal(locks.length, 1);
  channel.onmessage({ data: { request: "id", type: "failed" } });
  assert.equal(locks[0].signal.aborted, true);
  assert.equal(refs.get("here").hidden, false);
});
test("a silent owner keeps the lock until the player explicitly forces the takeover", () => {
  const { refs, locks, tick } = requester();
  tick();
  assert.equal(locks.length, 1);
  assert.equal(refs.get("force-here").hidden, false);
  refs.get("force-here").onclick();
  assert.equal(locks.length, 2);
  assert.equal(locks[0].signal.aborted, true);
  assert.equal(locks[1].steal, true);
});
test("the player can recover if the owner freezes after first acknowledging", () => {
  const { refs, locks, channel, tick } = requester();
  channel.onmessage({ data: { request: "id", type: "saving" } });
  tick();
  tick();
  assert.equal(refs.get("force-here").hidden, false);
  assert.equal(locks.length, 1);
});
test("the second tab stops writing if a third tab steals the lock after a graceful handoff", async () => {
  const second = requester();
  second.grants[0](); // The original tab has closed and released its lock.
  const stolen = new DOMException("The lock was stolen", "AbortError");
  second.revoke[0](stolen);
  await Promise.resolve();
  assert.deepEqual(second.lost, [stolen]);

  const pending = requester();
  pending.channel.onmessage({ data: { request: "id", type: "busy" } });
  pending.revoke[0](new DOMException("The request was canceled", "AbortError"));
  await Promise.resolve();
  assert.deepEqual(pending.lost, []);
});
test("a waiting host offers the invite initially and a fresh room after a guest departs", () => {
  const ctx = vm.createContext({
    coop: { role: "host", state: "waiting", room: "123", stats: () => ({ transport: null }) },
    coopRoom() {}, coopPanel: { classList: { add() {}, toggle() {} } }, coopEnded: null, coopMet: false,
    coopHello: false, coopNote: null, coopPinned: () => true, partner: () => 2, coopTransport: () => "",
    location: { origin: "https://example.invalid", pathname: "/play/" }, framed: false,
    coopLine: {}, coopInvite: {}, coopNew: {}, coopCopy: {}, coopClose: {},
  });
  vm.runInContext(section("  function coopShow(ms)", "  // A copy that fails") + "\ncoopShow(0);", ctx);
  assert.equal(ctx.coopNew.hidden, true);
  assert.equal(ctx.coopInvite.hidden, false);
  ctx.coopMet = true;
  ctx.coopShow(0);
  assert.match(ctx.coopLine.textContent, /original tab/);
  assert.equal(ctx.coopInvite.hidden, true);
  assert.equal(ctx.coopNew.hidden, false);
  // A reloaded host can learn about the absent seat from room status alone.
  ctx.coopMet = false;
  ctx.coop.guestReserved = true;
  ctx.coopShow(0);
  assert.equal(ctx.coopInvite.hidden, true);
  assert.equal(ctx.coopNew.hidden, false);
});
