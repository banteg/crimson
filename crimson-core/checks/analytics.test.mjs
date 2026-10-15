// Run the actual embedded browser collector against controlled clocks,
// storage, locks and network delivery. No game key or account enters it.
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../client/web/analytics.js", import.meta.url), "utf8");
const shared = JSON.parse(fs.readFileSync(new URL("../client/web/analytics.json", import.meta.url), "utf8"));
const { token: TOKEN, disabled: DISABLED } = shared;
function storage() {
  const values = new Map();
  let lock = Promise.resolve();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
    locked: (callback) => { const next = lock.then(callback); lock = next.catch(() => {}); return next; },
  };
}
function browser({ store = storage(), wall = Date.UTC(2026, 9, 15, 12), dnt, gpc, framed = false, hostname = "crimson.land", fail = () => false } = {}) {
  let clock = 0;
  const requests = [], events = new Map();
  const listener = (name, fn) => events.set(name, fn);
  const window = { addEventListener: listener };
  window.self = window;
  window.top = framed ? {} : window;
  const document = { hidden: false, hasFocus: () => true, addEventListener: listener };
  const context = vm.createContext({
    Date: class extends Date { constructor(...args) { super(...(args.length ? args : [wall])); } static now() { return wall; } },
    performance: { now: () => clock }, crypto: webcrypto, Uint8Array, AbortSignal,
    PLAY_ANALYTICS: shared, window, document, localStorage: store, location: { hostname },
    navigator: { doNotTrack: dnt, globalPrivacyControl: gpc, locks: { request: (_name, callback) => store.locked(callback) } },
    fetch: async (path, init) => {
      const value = { path, init, body: JSON.parse(init.body) };
      requests.push(value);
      if (fail(value)) throw Error("offline");
      return { ok: true };
    },
  });
  vm.runInContext(source + "\nglobalThis.collector = createPlayAnalytics();", context);
  const collector = context.collector;
  return {
    ...collector, requests, store, document,
    advance: (ms, mode = 0, run = 0) => { clock += ms; wall += ms; collector.activity(mode, run); },
    event: (name) => events.get(name)?.(),
    settle: () => new Promise((resolve) => setImmediate(resolve)),
  };
}
const unique = (b) => b.requests.filter((request) => request.path.endsWith("/unique"));
const totals = (b) => b.requests.filter((request) => request.path === "/api/analytics").map((request) => request.body);
const count = (b, name) => totals(b).reduce((sum, row) => sum + row[name], 0);
const seconds = (b) => totals(b).flatMap((row) => row.modes).reduce((sum, row) => sum + row.seconds, 0);
const runs = (b) => totals(b).flatMap((row) => row.modes).reduce((sum, row) => sum + row.runs, 0);

test("loading and replay-only pages never generate a presence token or play session", async () => {
  const b = browser();
  b.ready(); b.ready();
  for (let i = 0; i < 90; ++i) b.advance(1000);
  await b.settle();
  assert.equal(count(b, "ready"), 1);
  assert.equal(count(b, "sessions"), 0);
  assert.equal(unique(b).length, 0);
  assert.equal(b.store.values.has(TOKEN), false);
});

test("reloads and concurrent tabs reuse one random token for the day; presence and gameplay payloads stay separate", async () => {
  const store = storage(), a = browser({ store }), b = browser({ store });
  a.activity(1, 1); b.activity(2, 1);
  await Promise.all([a.settle(), b.settle()]);
  const token = unique(a)[0].body.token;
  assert.match(token, /^[0-9a-f]{32}$/);
  assert.equal(unique(b)[0].body.token, token);
  const reload = browser({ store });
  reload.activity(1, 1);
  await reload.settle();
  assert.equal(unique(reload)[0].body.token, token);
  for (const request of [...a.requests, ...b.requests, ...reload.requests]) {
    assert.equal(request.init.credentials, "omit");
    assert.equal(request.init.referrer, "");
    assert.equal(request.init.referrerPolicy, undefined, "no-referrer would send Origin: null");
    if (request.path.endsWith("/unique")) assert.deepEqual(Object.keys(request.body).sort(), ["day", "token"]);
    else assert.deepEqual(Object.keys(request.body).sort(), ["day", "engaged", "modes", "ready", "sessions"]);
  }
});

test("a continuing run rotates presence at UTC midnight without becoming another session or run", async () => {
  const b = browser({ wall: Date.UTC(2026, 9, 15, 23, 59, 59) });
  b.activity(1, 1);
  await b.settle();
  b.advance(1000, 1, 1);
  await b.settle();
  assert.deepEqual(unique(b).map((request) => request.body.day), ["2026-10-15", "2026-10-16"]);
  assert.notEqual(unique(b)[0].body.token, unique(b)[1].body.token);
  b.flush();
  assert.equal(count(b, "sessions"), 1);
  assert.equal(runs(b), 1);
});

test("a lock delayed across midnight cannot overwrite the new day's token with yesterday's", async () => {
  const store = storage();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  store.locked = async (callback) => { await gate; return callback(); };
  const b = browser({ store, wall: Date.UTC(2026, 9, 15, 23, 59, 59) });
  b.activity(1, 1);
  b.advance(1000, 1, 1);
  release();
  await b.settle();
  assert.equal(store.values.has(TOKEN), false, "the expired creation attempt wrote no token");
  b.activity(1, 1);
  await b.settle();
  assert.deepEqual(unique(b).map((request) => request.body.day), ["2026-10-16"]);
  assert.equal(JSON.parse(store.getItem(TOKEN)).day, "2026-10-16");
});

test("counts active wall time, several attempts and the five-minute milestone once per page", async () => {
  const b = browser();
  b.ready(); b.activity(1, 1);
  for (let i = 0; i < 180; ++i) b.advance(1000, 1, 1);
  b.advance(0, 0, 1); // pause
  b.advance(60000, 0, 1);
  b.advance(0, 6, 2); // practice takeover
  for (let i = 0; i < 180; ++i) b.advance(1000, 6, 2);
  b.activity(0, 2); b.flush();
  await b.settle();
  assert.equal(count(b, "sessions"), 1);
  assert.equal(count(b, "engaged"), 1);
  assert.equal(runs(b), 2);
  assert.equal(seconds(b), 360);
  assert.equal(unique(b).length, 1);
});

test("totals over the service's caps carry their excess into the next report", async () => {
  const b = browser();
  for (let run = 1; run <= shared.max_runs + 10; ++run) b.advance(0, 6, run);
  b.flush();
  b.flush();
  await b.settle();
  assert.ok(totals(b).every((row) => row.modes.every((mode) => mode.runs <= shared.max_runs)));
  assert.equal(runs(b), shared.max_runs + 10);
});

test("hidden and unfocused tabs stop time; a long stall cannot become minutes of play", () => {
  const b = browser();
  b.activity(1, 1); b.advance(1000, 1, 1);
  b.document.hidden = true; b.event("visibilitychange");
  b.advance(60000, 1, 1);
  b.document.hidden = false;
  b.document.hasFocus = () => false;
  b.advance(60000, 1, 1);
  b.document.hasFocus = () => true;
  b.activity(1, 1); b.advance(60000, 1, 1); b.activity(0, 1); b.flush();
  assert.equal(seconds(b), 3);
  assert.equal(runs(b), 1);
});

for (const [name, options] of [["DNT", { dnt: "1" }], ["GPC", { gpc: true }], ["embedding", { framed: true }], ["another host", { hostname: "other.invalid" }]]) {
  test(`${name} suppresses all gameplay reporting and token creation`, async () => {
    const b = browser(options);
    b.ready(); b.activity(1, 1); b.advance(60000, 1, 1); b.flush();
    await b.settle();
    assert.deepEqual(b.requests, []);
    assert.equal(b.store.values.has(TOKEN), false);
  });
}

test("opt-out and unavailable storage never prevent play or send gameplay reports", async () => {
  const store = storage();
  store.setItem(DISABLED, "1");
  const b = browser({ store });
  b.ready(); b.activity(1, 1); b.flush();
  store.getItem = () => { throw Error("storage refused"); };
  b.activity(1, 1); b.flush();
  await b.settle();
  assert.deepEqual(b.requests, []);
});

test("read-only storage suppresses reporting before even the game-ready request", async () => {
  const store = storage();
  store.setItem = () => { throw Error("quota or storage refused"); };
  const b = browser({ store });
  b.ready(); b.activity(1, 1); b.advance(60000, 1, 1); b.flush();
  await b.settle();
  assert.deepEqual(b.requests, []);
});

test("network failures retry unique presence with its same token, without retrying anonymous totals", async () => {
  const b = browser({ fail: () => true });
  b.ready(); b.activity(1, 1);
  await b.settle();
  const initialTotals = totals(b).length;
  for (let i = 0; i < 60; ++i) b.advance(1000, 1, 1);
  await b.settle();
  assert.equal(unique(b).length, 2);
  assert.equal(unique(b)[0].body.token, unique(b)[1].body.token);
  assert.equal(totals(b).length, initialTotals + 1);
  assert.equal(count(b, "ready"), 1);
  assert.equal(count(b, "sessions"), 1);
});
