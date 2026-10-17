// Two browsers play co-op through the site, end to end: the service runs
// locally (wrangler dev, its rooms and the game files from a local bucket) and
// serves the staged web client (`npm run play` in service/; README.md). Pages
// on two origins, http://localhost:<port> and http://127.0.0.1:<port>, each in
// a browser context of its own, so each keeps its own storage and its own lock
// on the game.
//
// First over WebRTC. The host's Play co-op opens a room and shows the invite
// link, whose Copy link leaves the link selected in its box when the clipboard
// refuses. The guest opens it, and both connect over a WebRTC candidate pair
// (not the room's relay). The guest reloads and joins again, then the host
// does: each time the other page's game ends its session with the page that
// went and begins one with the new page, again over WebRTC. The host's menus
// start a Survival run, which the guest's screen follows; both players move and
// fire for a few hundred ticks, while each page's session must show the run
// started, no desync or error, and its confirmed ticks advancing, and every
// confirmed tick both pages hold must have run with the same records and left
// the same state on both, each seat's records moving its player at times. The
// guest's page then sends late (coop.js's delay hook: its DataChannel sends held
// 60 ± 25 ms), so the host's game runs on predictions of player 2's records and
// rolls them back, while both keep playing and agreeing on every confirmed tick.
// The guest's tab then goes to the background for longer than the liveness timeout,
// which would end the session of a page that sent nothing there, and the run
// goes on. A desync the guest's page makes closes both sessions and stops both
// runs; both panels say why. The host leaves its stopped run first: its page
// begins a session whose hello waits, its panel saying it waits for player 2 to
// leave the stopped run, while the guest's page, its run still stopped, begins
// none. Once the guest leaves too, the session connects. A ranked run follows:
// both players stand still until both die, and each types a name at its end
// screen. Each page uploads the same signed run to the service, which takes one
// (201) and already has the other (409), and the co-op Survival board lists the
// pair under both names. The host's Enter plays again: in that run the host
// pauses and leaves from the banner: both runs end, the host's panel says it
// left and the guest's that player 1 left, neither address names the room any
// more, and once the host opens a new room, what the old session still sends
// goes nowhere.
//
// Then over the room's relay: a guest page without WebRTC joins a new room,
// both play a run through the room, and the guest's page closes, which the
// host's game hears at once. The host's game quits (Alt+Q): its panel goes with
// the room, offering no new room for a game that no longer runs. Every page
// proves its player's key to its room (a reloaded page the same key), and every
// run plays a seed its room issued to the pair. Screenshots of
// the pages (the cover, the invite, the menus connected, the runs, the
// background, the desync, the team's death, the pause, the end, the quit) go to
// the shots folder.
// Each session the host's page (on localhost, where the game reports analytics)
// played ends with its summary in the service's co-op totals (local D1, its
// migrations applied first): the WebRTC sessions as direct, with the rollbacks
// the late sends brought and the desync, and the relayed one as ws-relay.
//
// Last, the late game's costs (coop_cost.mjs) in Chrome: `measure` runs on a
// cross-origin isolated page of the service's origin, whose timer resolves
// microseconds, the page and game.wasm answered by the check itself.
//
//   CRIMSON_CHROME=<chrome> node crimson-core/checks/coop_browser.mjs <asset dir> [shots dir] [game.wasm]
//
// <asset dir> holds crimson.paq, sfx.paq and music.paq (artifacts/assets).
// CRIMSON_CHROME is a Chrome or Chromium binary with the new headless mode (not
// the headless shell, whose tabs are never hidden). The check drives it over the
// DevTools protocol itself: a driver such as Playwright keeps focus emulation on
// for its pages, which holds them visible, and the background step needs a
// real hidden tab (another tab of the guest's window brought to the front, with
// the guest's focus emulation off: requestAnimationFrame stops and timers slow
// to once a second, as for a player's background tab). It runs wrangler, which
// keeps state under the user's folder: outside a sandbox.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { costSetup, measure } from "./coop_cost.mjs";

const [given, shots = path.join(os.tmpdir(), "coop-browser-shots"), gameWasm = new URL("../build/game/game.wasm", import.meta.url).pathname] =
  process.argv.slice(2);
if (!given || !process.env.CRIMSON_CHROME) throw Error("usage: CRIMSON_CHROME=<chrome> coop_browser.mjs <asset dir> [shots dir] [game.wasm]");
const assets = path.resolve(given);
const SERVICE = new URL("../../service/", import.meta.url).pathname;
if (!fs.existsSync(path.join(SERVICE, "public/play/index.wasm"))) throw Error("stage the web client first: cd service && npm run play");
fs.mkdirSync(shots, { recursive: true });

// The game files' version in the bucket the page loads them from (service/src/index.ts GAME_VERSION).
const GAME_VERSION = /const GAME_VERSION = "([^"]+)"/.exec(fs.readFileSync(path.join(SERVICE, "src/index.ts"), "utf8"))[1];
// game_state_id_t; game_coop_status's flags and reasons (host/coop_wire.inc).
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, GAME_OVER = 7, GAMEPLAY = 9;
const STATUS = { connected: 1, started: 2, paused: 4, desynced: 128, failed: 256, signed: 0x800, closed: 0x1000, stopped: 0x2000 };
const PARTNER_GONE = 10, DIVERGED = 11;
const reasonOf = (status) => (status >> 16) & 255;
// The 1024x768 frame's Play Game on the main menu, and Survival on the Play Game panel, whose fresh profile lists
// Tutorial, Quests, Rush and Survival 28 pixels apart with every quest unlocked (as the session shows them); the
// pause banner's Leave, the second of its two buttons (host/coop_live.inc coop_banner).
const PLAY_GAME = [240, 338], SURVIVAL = [232, 396], LEAVE = [592, 406];
// A fresh profile's main menu shares its screen with the startup sequence, which ends after about 14 s.
const STARTUP_MS = 15000;
const TICKS = 300;
// Past the session's liveness timeout (host/coop_wire.inc COOP_LIVENESS_MS), which ends the session of a partner
// that sends nothing, as a hidden tab's game would without frames.
const WIRE = fs.readFileSync(new URL("../host/coop_wire.inc", import.meta.url), "utf8");
const BACKGROUND_MS = Number(/COOP_LIVENESS_MS = (\d+)/.exec(WIRE)[1]) + 2000;
// The guest's late sends (coop.js delay).
const LATE_SENDS = { ms: 60, jitter: 25 };
// client_coop_telemetry's words: the round trip, ticks run and run again, frames whose due ticks all waited, then
// rollbacks by depth and frames by the time their ticks took (host/coop.inc CoopSessionStats), as analytics.json
// buckets them.
const ANALYTICS = JSON.parse(fs.readFileSync(new URL("../client/web/analytics.json", import.meta.url), "utf8")).coop;
const DEPTHS = [4, 4 + ANALYTICS.depths], TELEMETRY_WORDS = DEPTHS[1] + ANALYTICS.frame_ms.length + 1;

const free = () =>
  new Promise((resolve) => {
    const server = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(what, test, ms = 60000) {
  for (const end = Date.now() + ms; ; await sleep(100)) {
    const value = await test();
    if (value) return value;
    if (Date.now() > end) throw Error(`timed out waiting for ${what}`);
  }
}

// The site, and the service with a bucket of its own holding the game files.
execFileSync("npx", ["vite", "build"], { cwd: SERVICE, stdio: "ignore" });
const port = await free();
const state = fs.mkdtempSync(path.join(os.tmpdir(), "coop-browser-"));
const wrangler = (...args) => ["wrangler", ...args, "--persist-to", state];
// The rooms record the seeds they issue for ranked runs (coop_runs).
execFileSync("npx", wrangler("d1", "migrations", "apply", "crimson-land", "--local"), { cwd: SERVICE, stdio: "ignore", env: { ...process.env, CI: "1" } });
// The service's co-op totals (service/migrations/0009_coop_analytics.sql) by transport and metric.
const coopTotals = () =>
  JSON.parse(
    execFileSync(
      "npx",
      wrangler("d1", "execute", "crimson-land", "--local", "--json", "--command",
        "SELECT transport, metric, SUM(count) AS count FROM coop_totals GROUP BY transport, metric"),
      { cwd: SERVICE, stdio: ["ignore", "pipe", "ignore"] },
    ),
  )[0].results.reduce((totals, { transport, metric, count }) => ({ ...totals, [`${transport} ${metric}`]: count }), {});
for (const name of ["crimson.paq", "sfx.paq", "music.paq"])
  execFileSync("npx", wrangler("r2", "object", "put", `crimson/${GAME_VERSION}/${name}`, "--local", "--file", path.join(assets, name)), {
    cwd: SERVICE,
    stdio: "ignore",
  });
const service = spawn("npx", wrangler("dev", "--port", String(port), "--show-interactive-dev-session=false"), {
  cwd: SERVICE,
  stdio: ["ignore", "pipe", "pipe"],
  detached: true,
});
let serviceLog = "";
service.stdout.on("data", (data) => (serviceLog += data));
service.stderr.on("data", (data) => (serviceLog += data));

// Chrome, its DevTools endpoint from the port file in its profile.
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "coop-chrome-"));
const chrome = spawn(
  process.env.CRIMSON_CHROME,
  [
    `--user-data-dir=${profile}`, "--headless=new", "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check",
    "--use-mock-keychain", "--password-store=basic", "--autoplay-policy=no-user-gesture-required",
    // Host candidates by address, not mDNS names, so the pages connect directly.
    "--disable-features=WebRtcHideLocalIpsWithMdns", "--use-angle=swiftshader", "--enable-unsafe-swiftshader",
    "about:blank",
  ],
  { stdio: "ignore", detached: true },
);
process.on("exit", () => {
  for (const child of [service, chrome])
    try {
      process.kill(-child.pid);
    } catch {}
  // Chrome may still be writing its profile as it goes.
  for (const folder of [state, profile]) fs.rmSync(folder, { recursive: true, force: true, maxRetries: 10 });
});
const endpoint = await until("Chrome", () => {
  try {
    const [devtoolsPort, target] = fs.readFileSync(path.join(profile, "DevToolsActivePort"), "utf8").split("\n");
    return `ws://127.0.0.1:${devtoolsPort}${target}`;
  } catch {
    return null;
  }
});
const devtools = new WebSocket(endpoint);
await new Promise((resolve, reject) => ((devtools.onopen = resolve), (devtools.onerror = reject)));
let lastId = 0;
const replies = new Map(), listeners = new Map();
devtools.onmessage = ({ data }) => {
  const message = JSON.parse(data);
  if (message.id) {
    const { resolve, reject, method } = replies.get(message.id);
    replies.delete(message.id);
    if (message.error) reject(Error(`${method}: ${message.error.message}`));
    else resolve(message.result);
  } else listeners.get(message.sessionId)?.(message.method, message.params);
};
const cdp = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = ++lastId;
    replies.set(id, { resolve, reject, method });
    devtools.send(JSON.stringify({ id, method, params, sessionId }));
  });

const logs = [], peers = [];
// The DirectInput-bound keys the check presses.
const KEYS = {
  Escape: ["Escape", 27],
  AltLeft: ["Alt", 18],
  Enter: ["Enter", 13],
  Backspace: ["Backspace", 8],
  ...Object.fromEntries([..."WASDQ"].map((ch) => [`Key${ch}`, [ch.toLowerCase(), ch.charCodeAt(0)]])),
};
// The names the players type at the end screen.
const NAMES = ["Ranger", "Scout"];
// A page of its own browser context: a window with one tab, the page focused (as Playwright emulates it) so
// every page plays with input.
async function open(name, origin, { webrtc = true } = {}) {
  const { browserContextId } = await cdp("Target.createBrowserContext");
  const { targetId } = await cdp("Target.createTarget", { url: "about:blank", browserContextId });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  const send = (method, params) => cdp(method, params, sessionId);
  // A navigation is done once its page loaded: nothing asks the page it leaves.
  let loaded = () => {};
  const navigate = (method, params) => {
    const done = new Promise((resolve) => (loaded = resolve));
    return send(method, params).then(() => done);
  };
  // The page's answers to its uploads (POST /api/runs).
  const uploads = [];
  listeners.set(sessionId, (method, params) => {
    if (method === "Page.loadEventFired") loaded();
    else if (method === "Network.responseReceived" && new URL(params.response.url).pathname === "/api/runs") uploads.push(params.response.status);
    else if (method === "Runtime.consoleAPICalled")
      logs.push(`${name}: ${params.args.map((arg) => arg.value ?? arg.description ?? "").join(" ")}`);
    else if (method === "Runtime.exceptionThrown") logs.push(`${name} error: ${params.exceptionDetails.exception?.description ?? params.exceptionDetails.text}`);
  });
  await send("Runtime.enable");
  await send("Page.enable");
  await send("Network.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: 1024, height: 768, deviceScaleFactor: 1, mobile: false });
  await send("Emulation.setFocusEmulationEnabled", { enabled: true });
  if (!webrtc) await send("Page.addScriptToEvaluateOnNewDocument", { source: "delete window.RTCPeerConnection;" });
  async function evaluate(fn, ...args) {
    const { result, exceptionDetails } = await send("Runtime.evaluate", {
      expression: `(${fn})(...${JSON.stringify(args)})`,
      awaitPromise: true,
      returnByValue: true,
    });
    if (exceptionDetails) throw Error(`${name}: ${exceptionDetails.exception?.description ?? exceptionDetails.text}`);
    return result.value;
  }
  const call = (fn, ...args) => evaluate((fn, args) => Module.ccall(fn, "number", args.map(() => "number"), args), fn, args);
  let at = [0, 0];
  const mouse = (type, extra = {}) => send("Input.dispatchMouseEvent", { type, x: at[0], y: at[1], button: "left", clickCount: 1, ...extra });
  const key = (type, code) => {
    const [text, keyCode] = KEYS[code];
    return send("Input.dispatchKeyEvent", { type, code, key: text, windowsVirtualKeyCode: keyCode, ...(type === "keyDown" && text.length === 1 && { text }) });
  };
  // A letter typed: its key down with its character, and up.
  const letter = async (ch) => {
    const code = `Key${ch.toUpperCase()}`, keyCode = ch.toUpperCase().charCodeAt(0);
    await send("Input.dispatchKeyEvent", { type: "keyDown", code, key: ch, text: ch, windowsVirtualKeyCode: keyCode });
    await sleep(50);
    await send("Input.dispatchKeyEvent", { type: "keyUp", code, key: ch, windowsVirtualKeyCode: keyCode });
    await sleep(50);
  };
  const peer = {
    name, origin, targetId, browserContextId, send, evaluate, uploads,
    goto: (url) => navigate("Page.navigate", { url }),
    reload: () => navigate("Page.reload"),
    status: async () => (await call("client_coop_status")) >>> 0,
    confirmed: () => call("client_coop_confirmed"),
    screen: () => call("client_game_state"),
    line: () => evaluate(() => document.getElementById("coop-line").textContent),
    transport: () => evaluate(() => coop?.stats().transport),
    // What confirmed tick `t` ran with for `seat` (PortableInput: move, aim, flags) and the state it left.
    record: (t, seat) =>
      evaluate((t, seat) => {
        const at = Module.ccall("client_coop_used", "number", ["number", "number"], [t, seat]);
        return at ? [...Module.HEAPU8.slice(at, at + 20)] : null;
      }, t, seat),
    hash: async (t) => (await call("client_coop_hash_at", t)) >>> 0,
    telemetry: () =>
      evaluate((words) => {
        const at = Module.ccall("client_coop_telemetry", "number", [], []);
        return [...new Int32Array(Module.HEAPU8.slice(at, at + 4 * words).buffer)];
      }, TELEMETRY_WORDS),
    async visible(selector) {
      return evaluate((selector) => {
        const element = document.querySelector(selector);
        return !!element && element.checkVisibility() && element.getBoundingClientRect().width > 0;
      }, selector);
    },
    waitFor: (selector, ms = 30000) => until(`${name}'s ${selector}`, () => peer.visible(selector), ms),
    async click(selector) {
      const [x, y] = await evaluate((selector) => {
        const box = document.querySelector(selector).getBoundingClientRect();
        return [box.x + box.width / 2, box.y + box.height / 2];
      }, selector);
      at = [x, y];
      await mouse("mouseMoved");
      await mouse("mousePressed", { buttons: 1 });
      await mouse("mouseReleased");
    },
    move: (x, y) => ((at = [x, y]), mouse("mouseMoved")),
    down: () => mouse("mousePressed", { buttons: 1 }),
    up: () => mouse("mouseReleased"),
    keyDown: (code) => key("keyDown", code),
    keyUp: (code) => key("keyUp", code),
    // The page's next animation frame, which runs a pass of the game first.
    frame: () => evaluate(() => new Promise((resolve) => requestAnimationFrame(() => resolve()))),
    async type(text) {
      for (const ch of text) await letter(ch);
    },
    outbox: () => evaluate(() => {
      try {
        return FS.readdir("/game/leaderboard/outbox").filter((name) => name.endsWith(".json")).length;
      } catch {
        return 0;
      }
    }),
    async shot(what) {
      const { data } = await send("Page.captureScreenshot", { format: "png" });
      fs.writeFileSync(path.join(shots, `${name}-${what}.png`), Buffer.from(data, "base64"));
    },
  };
  peers.push(peer);
  return peer;
}
// A click on the game's frame, once its screen shows (any, without one): held past a frame.
async function press(peer, screen, [x, y]) {
  if (screen !== null) await until(`screen ${screen}`, async () => (await peer.screen()) === screen, 30000);
  await peer.move(x, y);
  await sleep(1000);
  await peer.down();
  await sleep(120);
  await peer.up();
}
// A key tap the game sees: held through one of the page's frames. The original reads a key as it is down when a
// frame polls (its buttons' Enter too; the name entry takes Enter as a character), so a press and release within one
// slow frame (after a screenshot, on a busy machine) is none, and one held for half a second of frames repeats.
async function tap(peer, code) {
  await peer.keyDown(code);
  await peer.frame();
  await peer.keyUp(code);
}
const connected = async (peer) => (await peer.status()) & STATUS.connected;
// The panel says the session is connected once the game's is (both games said hello): over `how`.
const linked = (peer, how) =>
  until(`${peer.name}'s panel connected`, async () => {
    const line = await peer.line();
    return line.startsWith(`Co-op with player ${peer === host ? 2 : 1}`) && how.test(line);
  }, 2000);
// A WebRTC transport: its selected candidate pair's local candidate (coop.js candidateType), not the room's relay.
const webrtc = (peer) =>
  until(`${peer.name}'s WebRTC candidate pair`, async () => /^(host|srflx|prflx|relay)/.test((await peer.transport()) ?? ""), 5000);
const both = (what, test, ms) => until(what, async () => (await test(host)) && (await test(guest)), ms);
// A run on both pages.
const started = (what) => both(what, async (peer) => (await peer.status()) & STATUS.started && (await peer.screen()) === GAMEPLAY);
// The host's menus start Survival once the startup sequence is over; the guest's screen follows.
async function survival(host, guest) {
  await press(host, MAIN_MENU, PLAY_GAME);
  await press(host, PLAY_GAME_MENU, SURVIVAL);
  await started("the run on both");
}
// Both move and fire for a few hundred confirmed ticks: each by WASD and the mouse, its own way round. Every step
// both runs go on without a desync or an error and agree, and each seat's records move its player at times.
async function fight() {
  const keys = ["KeyW", "KeyD", "KeyS", "KeyA"];
  const first = await Promise.all([host, guest].map((peer) => peer.confirmed()));
  const moved = [false, false];
  for (let step = 0; (await host.confirmed()) < first[0] + TICKS || (await guest.confirmed()) < first[1] + TICKS; ++step) {
    if (step > 200) throw Error("the run stopped confirming ticks");
    for (const [i, peer] of [host, guest].entries()) {
      const key = keys[(step + 2 * i) % 4];
      await peer.keyDown(key);
      await peer.move(512 + 200 * Math.cos(step + i), 384 + 150 * Math.sin(step + i));
      await peer.down();
      setTimeout(() => peer.keyUp(key).then(() => peer.up()).catch(() => {}), 250);
    }
    await sleep(300);
    for (const peer of [host, guest]) {
      const status = await peer.status();
      assert.ok(status & STATUS.started, `${peer.name}'s run stopped: ${status.toString(16)}`);
      assert.equal(status & (STATUS.desynced | STATUS.failed), 0, `${peer.name}: ${status.toString(16)}`);
    }
    for (const [seat, moves] of (await agree(host, guest)).entries()) moved[seat] ||= moves;
  }
  assert.deepEqual(moved, [true, true], "each seat's records moved its player on both pages");
  console.log("confirmed ticks:", first, "->", await Promise.all([host, guest].map((peer) => peer.confirmed())));
}
// The confirmed ticks the two pages both still hold must have run with the same records and left the same state
// on both. Returns which seats' records moved their player.
async function agree(host, guest) {
  const moved = [false, false];
  const last = Math.min(await host.confirmed(), await guest.confirmed());
  for (let t = Math.max(0, last - 30); t <= last; ++t) {
    const hashes = [await host.hash(t), await guest.hash(t)];
    assert.ok(hashes[0], `tick ${t} held`);
    assert.equal(hashes[0], hashes[1], `tick ${t}'s state on both pages`);
    for (const seat of [0, 1]) {
      const records = [await host.record(t, seat), await guest.record(t, seat)];
      assert.deepEqual(records[0], records[1], `tick ${t}'s record for seat ${seat} on both pages`);
      const [moveX, moveY] = new Float32Array(Uint8Array.from(records[0]).buffer, 0, 2);
      moved[seat] ||= moveX !== 0 || moveY !== 0;
    }
  }
  return moved;
}

// A page of its own on `origin` whose document and game module the check serves (the DevTools protocol's Fetch
// domain answers its requests), cross-origin isolated, runs coop_cost.mjs's measure.
async function chromeCosts(origin) {
  const { browserContextId } = await cdp("Target.createBrowserContext");
  const { targetId } = await cdp("Target.createTarget", { url: "about:blank", browserContextId });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  const send = (method, params) => cdp(method, params, sessionId);
  const isolated = [
    { name: "cross-origin-opener-policy", value: "same-origin" },
    { name: "cross-origin-embedder-policy", value: "require-corp" },
  ];
  const files = {
    "/costs/": ["text/html", Buffer.from("<!doctype html><title>Co-op costs</title>")],
    "/costs/game.wasm": ["application/wasm", fs.readFileSync(gameWasm)],
  };
  let loaded;
  const load = new Promise((resolve) => (loaded = resolve));
  listeners.set(sessionId, (method, params) => {
    if (method === "Page.loadEventFired") loaded();
    if (method !== "Fetch.requestPaused") return;
    const [type, body] = files[new URL(params.request.url).pathname];
    send("Fetch.fulfillRequest", {
      requestId: params.requestId,
      responseCode: 200,
      responseHeaders: [{ name: "content-type", value: type }, ...isolated],
      body: body.toString("base64"),
    });
  });
  await send("Page.enable");
  await send("Fetch.enable", { patterns: [{ urlPattern: `${origin}/costs/*` }] });
  await send("Page.navigate", { url: `${origin}/costs/` });
  await load;
  await cdp("Target.activateTarget", { targetId });
  const { result, exceptionDetails } = await send("Runtime.evaluate", {
    expression: `(async () => {
      if (!crossOriginIsolated) throw Error("not cross-origin isolated");
      const bytes = await (await fetch("game.wasm")).arrayBuffer();
      return (${measure})(bytes, ${JSON.stringify(costSetup())});
    })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (exceptionDetails) throw Error(`costs: ${exceptionDetails.exception?.description ?? exceptionDetails.text}`);
  await cdp("Target.closeTarget", { targetId });
  return result.value;
}

let host, guest;
try {
  await until("the service", () => serviceLog.includes("Ready on"), 120000);
  host = await open("host", `http://localhost:${port}`);
  guest = await open("guest", `http://127.0.0.1:${port}`);

  // The host's cover offers Play co-op; its room's invite shows once it is open.
  await host.goto(`${host.origin}/play/`);
  await host.waitFor("#play-coop", 120000);
  await host.shot("cover");
  await host.click("#play-coop");
  await host.waitFor("#coop-invite");
  const invite = new URL(await host.evaluate(() => document.getElementById("coop-invite").value));
  const room = invite.searchParams.get("coop");
  assert.match(room, /^[0-9a-hjkmnp-tv-z]{10}$/);
  assert.match(await host.line(), /Waiting for player 2/);
  await host.shot("invite");
  // A clipboard that refuses leaves the link selected in its box, for the player's own copy.
  await host.evaluate(() => (navigator.clipboard.writeText = () => Promise.reject(Error("denied"))));
  await host.click("#coop-copy");
  await sleep(300);
  assert.deepEqual(
    await host.evaluate(() => {
      const box = document.activeElement;
      return [box.id, box.selectionStart, box.selectionEnd, box.value.length];
    }),
    ["coop-invite", 0, invite.href.length, invite.href.length],
  );

  // The guest opens the invite on its own origin.
  await guest.goto(`${guest.origin}/play/?coop=${room}`);
  await guest.waitFor("#play", 120000);
  assert.equal((await guest.evaluate(() => document.getElementById("play").textContent)).trim(), "Join");
  await guest.shot("cover");
  await guest.click("#play");
  await both("both sessions", connected);
  for (const peer of [host, guest]) await webrtc(peer);
  for (const peer of [host, guest]) await linked(peer, /, (direct|relayed)$/);
  console.log("connected:", await host.line(), "/", await guest.line());

  // The guest reloads, then the host: each page joins again from its stored seat, and the other page's session
  // with the page that went ends (its game is gone) for a new one with the new page.
  for (const [peer, other] of [[guest, host], [host, guest]]) {
    await peer.reload();
    await peer.waitFor("#play", 120000);
    await peer.click("#play");
    await both(`the session with ${peer.name}'s new page`, connected);
    assert.ok(logs.includes(`${other.name}: co-op: session ended ${PARTNER_GONE}`), `${other.name}'s session ended with the old page`);
    for (const each of [peer, other]) await webrtc(each);
  }

  await sleep(STARTUP_MS);
  await Promise.all([host.shot("lobby"), guest.shot("lobby")]);
  await survival(host, guest);

  await fight();
  await Promise.all([host.shot("run"), guest.shot("run")]);

  // The guest's page sends late: the host's game runs player 2's ticks on predictions and rolls them back, and the
  // run goes on, agreeing on both pages.
  const early = await host.telemetry();
  await guest.evaluate((delay) => (coop.delay = delay), LATE_SENDS);
  await fight();
  await guest.evaluate(() => (coop.delay = null));
  const lagged = (await host.telemetry()).map((n, i) => n - early[i]);
  const depths = lagged.slice(...DEPTHS);
  console.log("the host's rollbacks by depth with the guest's sends late:", depths, "round trip", lagged[0] + early[0], "ms");
  assert.ok(depths.some(Boolean), "the host's game rolled back");
  await host.shot("late");

  // The guest's tab goes to the background (another tab of its window in front, its focus emulation off), past the
  // liveness timeout: its page's frames come from a worker's timer, its game keeps sending and the run goes on.
  await guest.send("Emulation.setFocusEmulationEnabled", { enabled: false });
  const { targetId: front } = await cdp("Target.createTarget", { url: "about:blank", browserContextId: guest.browserContextId });
  await cdp("Target.activateTarget", { targetId: front });
  await until("the guest's hidden tab", () => guest.evaluate(() => document.visibilityState === "hidden"), 5000);
  const hidden = await Promise.all([host, guest].map((peer) => peer.confirmed()));
  await sleep(BACKGROUND_MS);
  for (const peer of [host, guest]) {
    const status = await peer.status();
    assert.equal(status & (STATUS.closed | STATUS.started), STATUS.started, `${peer.name} in the background: ${status.toString(16)}`);
  }
  const shown = await Promise.all([host, guest].map((peer) => peer.confirmed()));
  console.log("confirmed ticks in the background:", hidden, "->", shown);
  for (const i of [0, 1]) assert.ok(shown[i] - hidden[i] > BACKGROUND_MS * 0.03, "the run went on in the background");
  await cdp("Target.closeTarget", { targetId: front });
  await cdp("Target.activateTarget", { targetId: guest.targetId });
  await guest.send("Emulation.setFocusEmulationEnabled", { enabled: true });
  await until("the guest's tab", () => guest.evaluate(() => document.visibilityState === "visible"), 5000);
  await agree(host, guest);
  await guest.shot("background");

  // A desync: the guest's page changes its state between ticks until a confirmed tick's hashes differ. Both
  // sessions close for it, both runs stop and both panels say so. The host leaves its stopped run first: its page
  // begins a session, whose hello waits for the guest's, and says so; the guest's stopped run keeps its page from
  // beginning one. Once the guest leaves too, the session connects.
  await until("the desync", async () => {
    await guest.evaluate(() => Module.ccall("client_coop_corrupt", "number", ["number"], [0]));
    return (await host.status()) & STATUS.desynced && (await guest.status()) & STATUS.desynced;
  }, 10000);
  for (const peer of [host, guest]) {
    const status = await peer.status();
    assert.equal(status & (STATUS.connected | STATUS.closed), STATUS.closed, `${peer.name}'s session after the desync`);
    assert.equal(reasonOf(status), DIVERGED, `${peer.name}'s reason`);
  }
  await both("both panels on the desync", async (peer) => (await peer.line()) === "The two games ran differently", 5000);
  for (const peer of [host, guest]) assert.ok((await peer.status()) & STATUS.stopped, `${peer.name}'s stopped run`);
  await Promise.all([host.shot("desync"), guest.shot("desync")]);
  // The host's page reported the session the desync ended, with the rollbacks the late sends brought.
  const direct = await until("the host's co-op telemetry", () => {
    const totals = coopTotals();
    return totals["direct desyncs"] >= 1 && totals["direct depth"] >= depths.reduce((a, b) => a + b) && totals;
  }, 30000);
  console.log("co-op totals:", direct);
  await tap(host, "Escape");
  await until("the host's menu after the desync", async () => (await host.screen()) === MAIN_MENU, 30000);
  await until("the host's panel", async () => (await host.line()) === "Waiting for player 2 to leave the stopped run", 5000);
  await sleep(1500);
  assert.equal((await host.status()) & (STATUS.connected | STATUS.closed | STATUS.stopped), 0, "the host's session, its hello waiting");
  assert.equal((await guest.status()) & (STATUS.connected | STATUS.closed | STATUS.stopped), STATUS.closed | STATUS.stopped, "the guest's stopped run");
  assert.equal(await guest.line(), "The two games ran differently");
  await host.shot("desync-waiting");
  await tap(guest, "Escape");
  await until("the guest's menu after the desync", async () => (await guest.screen()) === MAIN_MENU, 30000);
  await both("the session after the desync", connected, 30000);
  for (const peer of [host, guest]) await linked(peer, /, (direct|relayed)$/);

  // A ranked run to the team's death: neither player moves or fires, and the creatures come. At its end screen
  // each player clears the name field, types a name and saves it with Enter; each page then holds both signatures
  // and uploads the same run, which the service takes once: one page hears 201 and the other 409, and both
  // outboxes empty. The co-op Survival board lists the pair under both names.
  await survival(host, guest);
  await both("the team's death", async (peer) => (await peer.screen()) === GAME_OVER, 300000);
  await Promise.all([host.shot("death"), guest.shot("death")]);
  await sleep(2000);
  for (const [i, peer] of [host, guest].entries()) {
    for (let n = 0; n < 32; ++n) await tap(peer, "Backspace");
    await peer.type(NAMES[i]);
    await tap(peer, "Enter");
  }
  await both("both signatures", async (peer) => (await peer.status()) & STATUS.signed, 10000);
  await both("both uploads", async (peer) => peer.uploads.length > 0 && (await peer.outbox()) === 0, 60000);
  assert.deepEqual([...host.uploads, ...guest.uploads].sort(), [201, 409], "the service takes the run once");
  const board = await (await fetch(`http://localhost:${port}/api/survival/coop`)).json();
  assert.equal(board.rows.length, 1, "the pair's run on the co-op board");
  assert.deepEqual(board.rows[0].team.map((seat) => seat.name), NAMES, "the pair's names");
  console.log("ranked co-op run:", board.rows[0].score, "points for", NAMES.join(" and "));
  await Promise.all([host.shot("ranked"), guest.shot("ranked")]);

  // The host's Enter presses Play Again (its button focused under the cursor), and both screens come to the next
  // run. The host pauses there with Escape and leaves from the banner: both runs end, both panels say why, and
  // neither address names the room any more.
  await tap(host, "Enter");
  await started("the next run on both");
  await tap(host, "Escape");
  await until("the pause", async () => (await host.status()) & STATUS.paused && (await guest.status()) & STATUS.paused);
  await host.shot("paused");
  await press(host, null, LEAVE);
  await until("both panels", async () => (await host.line()) === "You left co-op" && (await guest.line()) === "Player 1 left", 30000);
  await both("both menus", async (peer) => (await peer.screen()) === MAIN_MENU, 30000);
  for (const peer of [host, guest]) assert.equal(await peer.evaluate(() => new URL(location.href).searchParams.get("coop")), null);
  await Promise.all([host.shot("left"), guest.shot("left")]);
  // A new room: what the game still sends goes to the room its session connected over, which is closed.
  await host.click("#coop-new");
  await host.waitFor("#coop-invite");
  assert.equal(await host.evaluate(() => (Module.coopSend(1, new Uint8Array([1])), coop.stats().sent[1])), 0);

  // Over the room's relay: a guest page without WebRTC in a new room. Both play a run, then the guest's page
  // closes, and its goodbye ends the host's session at once.
  const relayRoom = new URL(await host.evaluate(() => document.getElementById("coop-invite").value)).searchParams.get("coop");
  for (const peer of [host, guest]) await cdp("Target.closeTarget", { targetId: peer.targetId });
  peers.length = 0;
  host = await open("relay-host", `http://localhost:${port}`);
  guest = await open("relay-guest", `http://127.0.0.1:${port}`, { webrtc: false });
  await host.goto(`${host.origin}/play/`);
  await host.waitFor("#play-coop", 120000);
  await host.click("#play-coop");
  await host.waitFor("#coop-invite");
  const relayInvite = new URL(await host.evaluate(() => document.getElementById("coop-invite").value));
  assert.notEqual(relayInvite.searchParams.get("coop"), relayRoom);
  await guest.goto(`${guest.origin}/play/?coop=${relayInvite.searchParams.get("coop")}`);
  await guest.waitFor("#play", 120000);
  await guest.click("#play");
  await both("both relayed sessions", connected);
  for (const peer of [host, guest]) assert.equal(await peer.transport(), "ws-relay", `${peer.name}'s transport`);
  for (const peer of [host, guest]) await linked(peer, /, through the room$/);
  await sleep(STARTUP_MS);
  await survival(host, guest);
  const relayed = await host.confirmed();
  await until("relayed ticks", async () => (await host.confirmed()) > relayed + TICKS && (await guest.confirmed()) > relayed + TICKS);
  await agree(host, guest);
  await Promise.all([host.shot("run"), guest.shot("run")]);
  await cdp("Target.closeTarget", { targetId: guest.targetId });
  peers.pop();
  await until("the host's session after the guest's page closed", async () => reasonOf(await host.status()) === PARTNER_GONE, 3000);
  assert.equal((await host.status()) & STATUS.connected, 0);
  await host.shot("partner-gone");
  // The host's game quits from its menu: the panel goes with the room, and the address names none.
  await until("the host's menu", async () => (await host.screen()) === MAIN_MENU, 30000);
  await host.keyDown("AltLeft");
  await tap(host, "KeyQ");
  await host.keyUp("AltLeft");
  await host.waitFor("#again", 30000);
  assert.deepEqual(
    await host.evaluate(() => [document.getElementById("coop").hidden, coop, new URL(location.href).searchParams.get("coop")]),
    [true, null, null],
  );
  await host.shot("quit");
  // The rooms attested each pair: both pages proved their keys, and every run played a seed its room issued to them,
  // each pair's keys its own (the relayed pages are new browsers, with keys of their own).
  const query = wrangler("d1", "execute", "crimson-land", "--local", "--json", "--command", "SELECT seat0_key, seat1_key FROM coop_runs");
  const issued = JSON.parse(execFileSync("npx", query, { cwd: SERVICE, encoding: "utf8" }))[0].results;
  assert.equal(issued.length, 4, "a seed a run");
  assert.equal(new Set(issued.map(({ seat0_key, seat1_key }) => `${seat0_key} ${seat1_key}`)).size, 2, "each pair's keys");
  // The relayed session's summary too.
  await until("the relayed session's telemetry", () => coopTotals()["ws-relay sessions"] >= 1, 30000);

  // The late game's costs in Chrome, on a cross-origin isolated page, the only one open.
  await cdp("Target.closeTarget", { targetId: host.targetId });
  peers.pop();
  const costs = await chromeCosts(`http://localhost:${port}`);
  console.log("late-game costs in Chrome:", JSON.stringify(costs));
  console.log(`co-op in the browser: ok (screenshots in ${shots})`);
} catch (error) {
  // Failed, whatever the diagnostics below do.
  process.exitCode = 1;
  console.error(error);
  console.error(logs.slice(-80).join("\n"));
  console.error(serviceLog.split("\n").slice(-30).join("\n"));
  for (const peer of peers) {
    try {
      console.error(`${peer.name}: screen ${await peer.screen()}, status ${(await peer.status()).toString(16)}, "${await peer.line()}"`);
      console.error(`${peer.name}: uploads ${JSON.stringify(peer.uploads)}, transport ${JSON.stringify(await peer.evaluate(() => coop?.stats()))}`);
      await peer.shot("failed");
    } catch (diagnostic) {
      console.error(`${peer.name}: no diagnostics (${diagnostic.message})`);
    }
  }
} finally {
  process.exit(process.exitCode ?? 0);
}
