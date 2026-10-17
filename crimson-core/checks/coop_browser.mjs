// Two browsers play co-op through the site, end to end: the service runs
// locally (wrangler dev, its rooms and the game files from a local bucket) and
// serves the staged web client (`npm run play` in service/; README.md). Two
// headless Chromium pages on two origins, http://localhost:<port> and
// http://127.0.0.1:<port>, so each keeps its own storage and its own lock on
// the game: the host's Play co-op opens a room and shows the invite link, the
// guest opens it, and both connect (WebRTC, else the room's relay). The guest
// reloads and joins again: the host's game ends its session with the page that
// went and begins one with the new page. The host's menus start a Survival run,
// which the guest's screen follows; both players move and fire for a few
// hundred ticks, while each page's session must show the run started, no
// desync or error, and its confirmed ticks advancing. Then the host pauses and
// leaves from the banner: both runs end, the host's panel says it left and the
// guest's that player 1 left. Screenshots of both pages (the cover, the invite,
// the menus connected, the run, the pause, the end) go to the shots folder.
//
//   node crimson-core/checks/coop_browser.mjs <asset dir> [shots dir]
//
// <asset dir> holds crimson.paq, sfx.paq and music.paq (artifacts/assets). It
// needs playwright-core and the Chromium build it pins, from CRIMSON_PLAYWRIGHT
// (the package's folder) or resolvable from here, and runs wrangler, which
// keeps state under the user's folder: outside a sandbox.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [given, shots = path.join(os.tmpdir(), "coop-browser-shots")] = process.argv.slice(2);
if (!given) throw Error("usage: coop_browser.mjs <asset dir> [shots dir]");
const assets = path.resolve(given);
const SERVICE = new URL("../../service/", import.meta.url).pathname;
if (!fs.existsSync(path.join(SERVICE, "public/play/index.wasm"))) throw Error("stage the web client first: cd service && npm run play");
const { chromium } = await import(
  process.env.CRIMSON_PLAYWRIGHT ? pathToFileURL(path.join(process.env.CRIMSON_PLAYWRIGHT, "index.mjs")).href : "playwright-core"
);
fs.mkdirSync(shots, { recursive: true });

// The game files' version in the bucket the page loads them from (service/src/index.ts GAME_VERSION).
const GAME_VERSION = /const GAME_VERSION = "([^"]+)"/.exec(fs.readFileSync(path.join(SERVICE, "src/index.ts"), "utf8"))[1];
// game_state_id_t; game_coop_status's flags (host/coop_wire.inc).
const MAIN_MENU = 0, PLAY_GAME_MENU = 1, GAMEPLAY = 9;
const STATUS = { connected: 1, started: 2, paused: 4, desynced: 128, failed: 256 };
const PARTNER_GONE = 10;
// The 1024x768 frame's Play Game on the main menu, and Survival on the Play Game panel, whose fresh profile lists
// Tutorial, Quests, Rush and Survival 28 pixels apart with every quest unlocked (as the session shows them); the
// pause banner's Leave, the second of its two buttons (host/coop_live.inc coop_banner).
const PLAY_GAME = [240, 338], SURVIVAL = [232, 396], LEAVE = [592, 406];
// A fresh profile's main menu shares its screen with the startup sequence, which ends after about 14 s.
const STARTUP_MS = 15000;
const TICKS = 300;

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
const browser = await chromium.launch({
  // Host candidates by address, not mDNS names, so the pages connect directly.
  args: ["--disable-features=WebRtcHideLocalIpsWithMdns", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"],
});
process.on("exit", () => {
  try {
    process.kill(-service.pid);
  } catch {}
  fs.rmSync(state, { recursive: true, force: true });
});

const logs = [], peers = [];
async function open(name, origin) {
  const context = await browser.newContext({ viewport: { width: 1024, height: 768 } });
  const page = await context.newPage();
  page.on("console", (message) => logs.push(`${name}: ${message.text()}`));
  page.on("pageerror", (error) => logs.push(`${name} error: ${error.message}`));
  const call = (fn, ...args) => page.evaluate(([fn, args]) => Module.ccall(fn, "number", args.map(() => "number"), args), [fn, args]);
  const peer = {
    name, origin, page,
    status: async () => (await call("client_coop_status")) >>> 0,
    confirmed: () => call("client_coop_confirmed"),
    screen: () => call("client_game_state"),
    line: () => page.locator("#coop-line").textContent(),
    shot: (what) => page.screenshot({ path: path.join(shots, `${name}-${what}.png`) }),
  };
  peers.push(peer);
  return peer;
}

try {
  await until("the service", () => serviceLog.includes("Ready on"), 120000);
  const host = await open("host", `http://localhost:${port}`);
  const guest = await open("guest", `http://127.0.0.1:${port}`);

  // The host's cover offers Play co-op; its room's invite shows once it is open.
  await host.page.goto(`${host.origin}/play/`);
  await host.page.locator("#play-coop").waitFor({ state: "visible", timeout: 120000 });
  await host.shot("cover");
  await host.page.click("#play-coop");
  await host.page.locator("#coop-invite").waitFor({ state: "visible", timeout: 30000 });
  const invite = new URL(await host.page.inputValue("#coop-invite"));
  const room = invite.searchParams.get("coop");
  assert.match(room, /^[0-9a-hjkmnp-tv-z]{10}$/);
  assert.match(await host.line(), /Waiting for player 2/);
  await host.shot("invite");

  // The guest opens the invite on its own origin.
  await guest.page.goto(`${guest.origin}/play/?coop=${room}`);
  const join = guest.page.locator("#play");
  await join.waitFor({ state: "visible", timeout: 120000 });
  assert.equal((await join.textContent()).trim(), "Join");
  await guest.shot("cover");
  await join.click();
  const connected = async (peer) => (await peer.status()) & STATUS.connected;
  await until("both sessions", async () => (await connected(host)) && (await connected(guest)));
  for (const peer of [host, guest]) assert.match(await peer.line(), new RegExp(`Co-op with player ${peer === host ? 2 : 1}`));
  console.log("connected:", await host.line(), "/", await guest.line());

  // The guest reloads: its page joins again from its stored seat, and the host's session with the page that went
  // ends (its game is gone) for a new one with the new page.
  await guest.page.reload();
  await join.waitFor({ state: "visible", timeout: 120000 });
  await join.click();
  await until("the session with the new page", async () => (await connected(host)) && (await connected(guest)));
  assert.ok(logs.includes(`host: co-op: session ended ${PARTNER_GONE}`), "the host's session ended with the guest's old page");

  // The host's menus start Survival once the startup sequence is over; the guest's screen follows.
  await sleep(STARTUP_MS);
  await Promise.all([host.shot("lobby"), guest.shot("lobby")]);
  async function click(peer, screen, [x, y]) {
    await until(`screen ${screen}`, async () => (await peer.screen()) === screen, 30000);
    await peer.page.mouse.move(x, y);
    await sleep(1000);
    await peer.page.mouse.down();
    await sleep(120);
    await peer.page.mouse.up();
  }
  await click(host, MAIN_MENU, PLAY_GAME);
  await click(host, PLAY_GAME_MENU, SURVIVAL);
  const started = async (peer) => (await peer.status()) & STATUS.started && (await peer.screen()) === GAMEPLAY;
  await until("the run on both", async () => (await started(host)) && (await started(guest)));

  // Both move and fire: the host by WASD and the mouse, the guest too, each its own way round.
  const keys = ["KeyW", "KeyD", "KeyS", "KeyA"];
  const first = await Promise.all([host, guest].map((peer) => peer.confirmed()));
  for (let step = 0; (await host.confirmed()) < first[0] + TICKS || (await guest.confirmed()) < first[1] + TICKS; ++step) {
    if (step > 200) throw Error("the run stopped confirming ticks");
    for (const [i, peer] of [host, guest].entries()) {
      const key = keys[(step + 2 * i) % 4];
      await peer.page.keyboard.down(key);
      await peer.page.mouse.move(512 + 200 * Math.cos(step + i), 384 + 150 * Math.sin(step + i));
      await peer.page.mouse.down();
      setTimeout(() => peer.page.keyboard.up(key).then(() => peer.page.mouse.up()).catch(() => {}), 250);
    }
    await sleep(300);
    for (const peer of [host, guest]) {
      const status = await peer.status();
      assert.ok(status & STATUS.started, `${peer.name}'s run stopped: ${status.toString(16)}`);
      assert.equal(status & (STATUS.desynced | STATUS.failed), 0, `${peer.name}: ${status.toString(16)}`);
    }
  }
  const last = await Promise.all([host, guest].map((peer) => peer.confirmed()));
  console.log("confirmed ticks:", first, "->", last);
  await Promise.all([host.shot("run"), guest.shot("run")]);

  // The host pauses with Escape and leaves from the banner: both runs end, and both panels say why.
  // A tap the game sees: held past a frame.
  await host.page.keyboard.down("Escape");
  await sleep(150);
  await host.page.keyboard.up("Escape");
  await until("the pause", async () => (await host.status()) & STATUS.paused && (await guest.status()) & STATUS.paused);
  await host.shot("paused");
  await host.page.mouse.move(...LEAVE);
  await sleep(500);
  await host.page.mouse.down();
  await sleep(120);
  await host.page.mouse.up();
  await until("both panels", async () => (await host.line()) === "You left co-op" && (await guest.line()) === "Player 1 left", 30000);
  await until("both menus", async () => (await host.screen()) === MAIN_MENU && (await guest.screen()) === MAIN_MENU, 30000);
  await Promise.all([host.shot("left"), guest.shot("left")]);
  console.log(`co-op in the browser: ok (screenshots in ${shots})`);
} catch (error) {
  console.error(logs.slice(-80).join("\n"));
  console.error(serviceLog.split("\n").slice(-30).join("\n"));
  for (const peer of peers) {
    console.error(`${peer.name}: screen ${await peer.screen()}, status ${(await peer.status()).toString(16)}, "${await peer.line()}"`);
    await peer.shot("failed");
  }
  console.error(error);
  process.exitCode = 1;
} finally {
  await browser.close();
  process.exit(process.exitCode ?? 0);
}
