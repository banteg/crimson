import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, webcrypto } from "node:crypto";
import { test } from "node:test";
import vm from "node:vm";

const shell = readFileSync(new URL("../client/web/shell.html", import.meta.url), "utf8");
// The shell's code from one line to another, both of which must be there.
const between = (from, to) => {
  const start = shell.indexOf(from), end = shell.indexOf(to, start);
  assert.ok(start >= 0 && end >= 0, `shell.html lost ${start < 0 ? from : to}`);
  return shell.slice(start, end);
};
const functions = between("  // Downloads, with", "  async function hydrate()");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const old = new TextEncoder().encode("old art"), current = new TextEncoder().encode("current art");

function browser(installed, downloaded = current, unavailable = false) {
  const files = new Map(installed ? [["/game/crimson.paq", installed]] : []);
  const requests = [];
  const context = vm.createContext({
    ART_VERSION: { current: digest(current), previous: [digest(old)] },
    artHash: async (bytes) => digest(bytes), crypto: webcrypto, URL, Uint8Array,
    location: { href: "https://example.invalid/play/" }, base: "game/",
    progress: { hidden: true, firstElementChild: { style: {} } }, say() {},
    console: { warn() {} }, exists: (name) => files.has("/game/" + name),
    FS: { readFile: (name) => files.get(name) },
    missing: () => files.has("/game/crimson.paq") ? [] : ["crimson.paq"],
    store: (name, bytes) => files.set("/game/" + name, bytes),
    storeMusic() { throw Error("Unexpected music migration"); },
    fetch: async (url) => {
      requests.push(String(url));
      if (unavailable) throw Error("offline");
      let read = false;
      return { ok: true, headers: new Map([["content-length", String(downloaded.length)]]),
        body: { getReader: () => ({ read: async () => {
          if (read) return { done: true };
          read = true;
          return { done: false, value: downloaded };
        } }) } };
    },
  });
  vm.runInContext(functions + "\nglobalThis.update = fetchMissing;", context);
  return { update: context.update, files, requests };
}

for (const [label, installed] of [["old", old], ["current", current], ["custom", new TextEncoder().encode("custom")], ["missing", null]]) {
  test(`browser upgrades ${label} artwork only when needed`, async () => {
    const b = browser(installed);
    await b.update();
    const upgrade = label === "old" || label === "missing";
    assert.equal(b.requests.length, upgrade ? 1 : 0);
    assert.equal(digest(b.files.get("/game/crimson.paq")), digest(upgrade ? current : installed));
    if (upgrade) assert.equal(new URL(b.requests[0]).searchParams.get("sha256"), digest(current));
    await b.update();
    assert.equal(b.requests.length, upgrade ? 1 : 0, "does not download again once current");
  });
}

for (const [label, downloaded, unavailable] of [["stale cache", old, false], ["HTML response", new TextEncoder().encode("<html>error</html>"), false], ["offline", current, true]]) {
  test(`browser keeps installed artwork on ${label}`, async () => {
    const b = browser(old, downloaded, unavailable);
    await b.update();
    assert.equal(digest(b.files.get("/game/crimson.paq")), digest(old));
  });
  test(`browser does not install missing artwork on ${label}`, async () => {
    const b = browser(null, downloaded, unavailable);
    await assert.rejects(b.update());
    assert.equal(b.files.has("/game/crimson.paq"), false);
  });
}

const watchFunctions = [
  between("  const query =", "  // Inside another page"),
  between("  let watchTicks", "  const showFullscreen"),
  between("  shareFull.onclick =", "  fullscreen.onclick ="),
  between("  const REPLAY_LIMIT =", "  var Module ="),
].join("\n");

// The game takes a moment within `ticks` past `tick` (host/watch.inc, which
// checks/game_watch.mjs holds to its bounds), or refuses it with `momentWhy`.
function watchBrowser(search, { status = 200, bytes = new Uint8Array([1, 2, 3]), watchWhy = "", momentWhy = "", runId = "run_1", tick = 240, ticks = 1000 } = {}) {
  const notices = [];
  const calls = [];
  const shareStop = { value: "", addEventListener() {} };
  const shareFull = { href: "#", hidden: true, onclick: null };
  const shareCopy = { onclick: null };
  const replaced = [];
  const copied = [];
  const context = vm.createContext({
    location: { search, href: `https://example.invalid/play/${search}` },
    URL,
    URLSearchParams,
    Uint8Array,
    Date,
    setTimeout,
    clearTimeout,
    setInterval() {},
    history: { replaceState: (_s, _t, url) => replaced.push(url) },
    navigator: { clipboard: { writeText: async (url) => copied.push(url) } },
    canvas: { focus() {} },
    document: { getElementById: (id) => (id === "share-copy" ? shareCopy : { hidden: true }) },
    say() {},
    tell: (text, href) => notices.push([text, href ?? null]),
    shareStop,
    shareFull,
    FS: { mkdirTree() {}, writeFile() {} },
    Module: {
      ccall: (name, _ret, _types, args) => {
        calls.push([name, [...args]]);
        if (name === "client_watch") return watchWhy;
        if (name === "client_watch_run") return runId;
        if (name === "client_watch_tick") return tick;
        if (name === "client_watch_moment") {
          const [start, stop] = args;
          return momentWhy || (!start && stop && (stop <= tick || stop > ticks) ? "refused" : "");
        }
        return "";
      },
    },
    fetch: async (url) => {
      if (String(url).startsWith("/api/runs/"))
        return { ok: true, json: async () => ({ name: "Runner", title: "Survival", board: "survival", score: 100, rank: 1, accepted_at: 0 }) };
      return { ok: status === 200, status, arrayBuffer: async () => bytes.buffer };
    },
  });
  vm.runInContext(watchFunctions + `\nwatchTicks = ${ticks}; globalThis.watchLink = watchLink; globalThis.linked = linked;`, context);
  return { run: () => context.watchLink(context.linked), setTick: (at) => (tick = at), shareCopy, shareStop, shareFull, notices, calls, replaced, copied };
}

test("watchLink opens a moment link, shares from current tick, and returns to full run", async () => {
  const day = new Date(0);
  const b = watchBrowser("?watch=run_1&tick=240&stop=360");
  await b.run();
  assert.deepEqual(b.notices, []);
  assert.deepEqual(b.calls, [
    ["client_watch", ["replays/online/run_1.crd", "run_1", "Runner", 1, day.getDate(), day.getMonth() + 1, day.getFullYear()]],
    ["client_watch_moment", [240, 360]],
  ]);
  assert.equal(b.shareStop.value, "360");
  assert.equal(b.shareFull.hidden, false);
  assert.equal(b.shareFull.href, "?watch=run_1");

  b.shareStop.value = "480";
  await b.shareCopy.onclick();
  assert.equal(b.copied.at(-1), "https://example.invalid/play/?watch=run_1&tick=240&stop=480");
  assert.equal(b.replaced.at(-1), "?watch=run_1&tick=240&stop=480");
  assert.deepEqual(b.notices.at(-1), ["Copied link to this moment", "https://example.invalid/play/?watch=run_1&tick=240&stop=480"]);

  b.shareStop.value = "240";
  await b.shareCopy.onclick();
  assert.deepEqual(b.notices.at(-1), ["Stop tick must be between 241 and 1000.", null]);

  // Playback reached the stop it was given: the next share drops it.
  b.shareStop.value = "480";
  b.setTick(480);
  await b.shareCopy.onclick();
  assert.equal(b.shareStop.value, "");
  assert.deepEqual(b.calls.at(-1), ["client_watch_moment", [0, 0]]);
  assert.equal(b.replaced.at(-1), "?watch=run_1&tick=480");

  b.shareFull.onclick({ preventDefault() {} });
  assert.deepEqual(b.calls.at(-1), ["client_watch_moment", [1, 0]]);
  assert.equal(b.shareStop.value, "");
  assert.equal(b.shareFull.hidden, true);
  assert.equal(b.replaced.at(-1), "?watch=run_1");
});

for (const [label, search, expected] of [
  ["malformed run id", "?watch=../bad", "This replay link is malformed."],
  ["malformed tick", "?watch=run_1&tick=abc", "This link's moment is malformed."],
  ["zero tick", "?watch=run_1&tick=0", "This link's moment is malformed."],
  ["negative stop", "?watch=run_1&stop=-5", "This link's moment is malformed."],
  ["stop at or before start", "?watch=run_1&tick=300&stop=300", "This link's moment is malformed."],
  ["stop at tick 1 without start", "?watch=run_1&stop=1", "This link's moment is malformed."],
]) {
  test(`watchLink rejects ${label}`, async () => {
    const b = watchBrowser(search);
    await b.run();
    assert.deepEqual(b.notices, [[expected, null]]);
  });
}

test("watchLink reports a moment the game refuses", async () => {
  const b = watchBrowser("?watch=run_1&tick=1001", { momentWhy: "This moment is past the end of the run." });
  await b.run();
  assert.deepEqual(b.notices, [["This moment is past the end of the run.", null]]);
});

for (const [status, expected] of [
  [404, "This run is no longer on the leaderboard."],
  [500, "Could not download this run."],
]) {
  test(`watchLink reports HTTP ${status} when run is unavailable`, async () => {
    const b = watchBrowser("?watch=run_1&tick=100", { status });
    await b.run();
    assert.deepEqual(b.notices, [[expected, null]]);
  });
}
