import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, webcrypto } from "node:crypto";
import { test } from "node:test";
import vm from "node:vm";
import { CL_BUILD_1_9_8, CL_BUILD_1_9_93, QUEST_BYTES } from "./engine.mjs";

const shell = readFileSync(new URL("../client/web/shell.html", import.meta.url), "utf8");
// The shell's code from one line to another, both of which must be there.
const between = (from, to) => {
  const start = shell.indexOf(from), end = shell.indexOf(to, start);
  assert.ok(start >= 0 && end >= 0, `shell.html lost ${start < 0 ? from : to}`);
  return shell.slice(start, end);
};
test("the outbox retries newer formats or rules and permanently refuses retired ones", () => {
  const code = between("  function readerBehind(", "  let uploading");
  const behind = vm.runInNewContext(code + "\nreaderBehind");
  assert.ok(behind(503, { code: "replay_reader_behind" }));
  for (const reason of [
    "unsupported replay format version: 35 (this build reads versions 30, 31, 34)",
    "replay was recorded under rules 3; this service verifies rules 1 and 2",
  ]) assert.ok(behind(422, { reason }));
  for (const reason of [
    "unsupported replay format version: 29 (this build reads versions 30, 31, 35)",
    "replay was recorded under rules 2; this service verifies rules 1 and 3",
    "not a ranked run",
  ]) assert.equal(behind(422, { reason }), false);
});

test("a legacy refusal keeps its signed recording offline, then retries without its old reason", async () => {
  const rejected = "/game/leaderboard/rejected";
  const filename = "a".repeat(64) + ".json", permanent = "b".repeat(64) + ".json";
  const signed = { name: "Ranger", signature: "original signature", replay: "original bytes" };
  const old = JSON.stringify({ ...signed, reason: "replay was recorded under rules 2; this service verifies rules 1" });
  const files = new Map([[`${rejected}/${filename}`, old], [`${rejected}/${permanent}`, '{"reason":"not ranked"}']]);
  const calls = [], statuses = [503, 201];
  const context = vm.createContext({
    moved: false, fileBusy: false, storagePaused: false, Module: { ccall() {} }, AbortSignal, persist() {},
    FS: {
      readdir: (dir) => [...files.keys()].filter((file) => file.startsWith(dir + "/")).map((file) => file.split("/").pop()),
      analyzePath: (file) => ({ exists: files.has(file) }), readFile: (file) => files.get(file), unlink: (file) => files.delete(file),
    },
    fetch: async (_, init) => {
      calls.push(JSON.parse(init.body));
      return Response.json({}, { status: statuses.shift() });
    },
  });
  const upload = vm.runInContext(between("  const OUTBOX =", "  // A short note over") + "\nupload", context);
  await upload();
  assert.equal(files.get(`${rejected}/${filename}`), old);
  await upload();
  await upload();
  assert.deepEqual(calls, [signed, signed]);
  assert.deepEqual([...files.keys()], [`${rejected}/${permanent}`]);
});

const functions = between("  function missing()", "  async function hydrate()");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const old = new TextEncoder().encode("old art"), current = new TextEncoder().encode("current art");

function browser(installed, downloaded = current, unavailable = false) {
  const files = new Map([["/game/music.paq", current], ["/game/sfx.paq", current]]);
  if (installed) files.set("/game/crimson.paq", installed);
  const controls = { offer: {}, retry: {}, folder: {} }, messages = [];
  const requests = [];
  const context = vm.createContext({
    ART_VERSION: { current: digest(current), previous: [digest(old)], audio: { "music.paq": digest(current), "sfx.paq": digest(current) } },
    artHash: async (bytes) => digest(bytes), crypto: webcrypto, URL, Uint8Array, TextEncoder, TextDecoder,
    location: { href: "https://example.invalid/play/" }, base: "game/",
    progress: { hidden: true, firstElementChild: { style: {} } }, say: (message) => messages.push(message),
    document: { getElementById: (id) => controls[id] },
    console: { warn() {} }, exists: (name) => files.has("/game/" + name),
    FS: {
      readFile: (name, options) => options?.encoding ? new TextDecoder().decode(files.get(name)) : files.get(name),
      rename: (from, to) => { assert.ok(files.has(from)); files.set(to, files.get(from)); files.delete(from); },
    },
    store: (name, bytes) => files.set("/game/" + name, bytes),
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
  vm.runInContext(between("  const FILES =", "  const ART_VERSION") + between("  const MUSIC =", "  const base =") +
    functions + "\nglobalThis.update = (damaged = new Map()) => fetchMissing(damaged); globalThis.offer = offer;", context);
  return { update: context.update, offer: context.offer, files, requests, controls, messages };
}

test("offline folder recovery backs up broken packs and accepts a complete loose soundtrack", async () => {
  const corrupt = Uint8Array.of(0), replacement = Uint8Array.of(112, 97, 113, 0);
  const b = browser(current, current, true);
  for (const name of ["music.paq", "sfx.paq"]) b.files.set("/game/" + name, corrupt);
  const damaged = new Map();
  await assert.rejects(b.update(damaged), /offline/);
  const offered = b.offer(damaged);
  const pick = (...entries) => b.controls.folder.onchange({ target: { files: entries.map(([name, bytes]) => ({
    webkitRelativePath: "GOG/" + name, arrayBuffer: async () => bytes.buffer,
  })) } });
  await pick(["SFX.PAQ", corrupt]);
  assert.match(b.messages.at(-1), /not a PAQ/);
  await pick(["SFX.PAQ", replacement], ["music/game_tunes.txt", new TextEncoder().encode("snd_addGameTune track.ogg")],
    ...["intro", "crimson_theme", "crimsonquest", "shortie_monk"].map(name => ["music/" + name + ".ogg", current]));
  assert.match(b.messages.at(-1), /lacks 1 music files/);
  await pick(["music/track.ogg", current]);
  assert.equal(await offered, "picked");
  for (const name of ["music.paq", "sfx.paq"]) assert.deepEqual(b.files.get("/game/" + name + ".invalid-" + digest(corrupt)), corrupt);
  assert.equal(b.files.has("/game/music.paq"), false);
  assert.deepEqual(b.files.get("/game/sfx.paq"), replacement);
  const requests = b.requests.length;
  await b.update();
  assert.equal(b.requests.length, requests);
});

for (const [label, installed] of [["old", old], ["current", current], ["custom", Uint8Array.of(112, 97, 113, 0)], ["missing", null]]) {
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

test("a damaged cached sound pack is preserved and replaced only with verified audio", async () => {
  const damaged = new TextEncoder().encode("error page");
  const failed = browser(current, damaged);
  failed.files.set("/game/sfx.paq", damaged);
  await assert.rejects(failed.update(), /unexpected hash/);
  assert.deepEqual(failed.files.get("/game/sfx.paq"), damaged);
  const repaired = browser(current);
  repaired.files.set("/game/sfx.paq", damaged);
  await repaired.update();
  assert.deepEqual(repaired.files.get("/game/sfx.paq.invalid-" + digest(damaged)), damaged);
  assert.deepEqual(repaired.files.get("/game/sfx.paq"), current);
});

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
  between("  const REPLAY_LIMIT =", "  const recovery ="),
].join("\n");

// Module.ccall's arguments as the game gets them: one the call declares a "string" as text, any other as a number.
const ccallArgs = (types, args) => Array.from(args, (arg, i) => (types[i] === "string" ? String(arg) : Number(arg)));

// The game takes a moment within `ticks` past `tick` (host/watch.inc, which
// checks/game_watch.mjs holds to its bounds), or refuses it with `momentWhy`.
function watchBrowser(search, { status = 200, bytes = new Uint8Array([1, 2, 3]), watchWhy = "", momentWhy = "", stalledSummary = false, runId = "run_1", tick = 240, ticks = 1000 } = {}) {
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
    AbortSignal: stalledSummary ? { timeout: ms => (assert.ok(ms > 0 && ms <= 2000), AbortSignal.abort()) } : AbortSignal,
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
      ccall: (name, _ret, types, args) => {
        const got = ccallArgs(types, args);
        calls.push([name, got]);
        if (name === "client_watch") return watchWhy;
        if (name === "client_watch_run") return runId;
        if (name === "client_watch_tick") return tick;
        if (name === "client_watch_moment") {
          const [start, stop] = got;
          return momentWhy || (!start && stop && (stop <= tick || stop > ticks) ? "refused" : "");
        }
        return "";
      },
    },
    fetch: async (url, options) => {
      if (String(url).startsWith("/api/runs/")) {
        if (stalledSummary && options?.signal.aborted) throw Error("summary timed out");
        return { ok: true, json: async () => ({ name: "Runner", title: "Survival", board: "survival", score: 100, rank: 1, accepted_at: 0 }) };
      }
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

test("a missing summary by its deadline leaves the downloaded replay playable", async () => {
  const b = watchBrowser("?watch=run_1", { stalledSummary: true });
  await b.run();
  assert.deepEqual(b.notices, []);
  assert.deepEqual(b.calls, [["client_watch", ["replays/online/run_1.crd", "run_1", "", 0, 0, 0, 2000]]]);
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

// A quest link (?quest=<id>, &build=1.9.8 from its page's 1.9.8 boards) plays the quest once its file is in, by its
// build's rules as the game takes them, the decomp's CL_BUILD; a build the game does not play only says so.
function questBrowser(search) {
  const notices = [], calls = [], requests = [];
  const context = vm.createContext({
    location: { search, href: `https://example.invalid/play/${search}` },
    URL,
    URLSearchParams,
    AbortSignal,
    Uint8Array,
    setTimeout,
    tell: (text) => notices.push(text),
    FS: { mkdirTree() {}, writeFile() {} },
    Module: { ccall: (name, _ret, types, args) => (calls.push([name, ...ccallArgs(types, args)]), "") },
    fetch: async (url) => {
      requests.push(String(url));
      return { ok: true, status: 200, arrayBuffer: async () => new Uint8Array(QUEST_BYTES).buffer };
    },
    questSummary: Promise.resolve({ title: "Crosswind", author: "Author" }),
  });
  const code = [between("  const query =", "  // Inside another page"), between("  async function questLink(id)", "  async function watchLink(run)")];
  vm.runInContext(code.join("\n") + "\nglobalThis.linkedQuestLink = () => questLink(linkedQuest);", context);
  return { run: () => context.linkedQuestLink(), notices, calls, requests };
}

for (const [build, clBuild] of [["", CL_BUILD_1_9_93], ["&build=1.9.93", CL_BUILD_1_9_93], ["&build=1.9.8", CL_BUILD_1_9_8]]) {
  test(`questLink plays a quest link${build ? ` with ${build}` : ""} on build ${clBuild}`, async () => {
    const b = questBrowser(`?quest=0123456789ab${build}`);
    await b.run();
    assert.deepEqual(b.notices, []);
    assert.deepEqual(b.requests, ["/custom/0123456789ab.bin"]);
    assert.deepEqual(b.calls, [["client_play_quest", "quests/online/0123456789ab.bin", "Crosswind", "Author", clBuild]]);
  });
}

test("questLink refuses a build the game does not play", async () => {
  const b = questBrowser("?quest=0123456789ab&build=2.0");
  await b.run();
  assert.deepEqual(b.notices, ["This quest link names a version the game does not play."]);
  assert.deepEqual(b.requests, []);
  assert.deepEqual(b.calls, []);
});
