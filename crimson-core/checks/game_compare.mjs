// Steps the game module and the verifier core in lockstep over the same input
// streams and compares every snapshot field, except presentation state the
// verifier never advances.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { CORE, decode, fieldRanges, firstDifference, init, loadCore, names, record, state, step } from "./engine.mjs";
import { bootGame } from "./game_host.mjs";

// Fields only presentation reads: the HUD's popup timer, which the verifier's
// stubbed HUD never counts down, and the weapons' sound ids, which only choose
// the sample sfx_play_panned plays and are the original's loaded ids in a run
// inside the original (the verifier loads no sounds).
export const PRESENTATION = new Set(
  names.filter((n) => /^globals\.player_weapon_popup_timer\[|^weapons\[\d+\]\.(shot_sfx_base_id|reload_sfx_id)$/.test(n)),
);
const COMPARED = fieldRanges((name) => !PRESENTATION.has(name));


export function loadGame(wasm) {
  const module = new WebAssembly.Module(fs.readFileSync(wasm));
  let memory;
  // Headless, the module performs no I/O; any WASI call is a defect.
  const wasi = Object.fromEntries(
    WebAssembly.Module.imports(module)
      .filter((i) => i.module === "wasi_snapshot_preview1")
      .map((i) => [
        i.name,
        (...args) => {
          if (i.name === "fd_write") {
            const [, iovs, count, written] = args;
            const view = new DataView(memory.buffer);
            let total = 0;
            for (let k = 0; k < count; k++) total += view.getUint32(iovs + k * 8 + 4, true);
            view.setUint32(written, total, true);
            return 0;
          }
          // libc probes for preopened directories at start: there are none.
          if (i.name === "fd_prestat_get") return 8;
          throw Error(`game module called WASI ${i.name}`);
        },
      ]),
  );
  const text = (address) => {
    const bytes = new Uint8Array(memory.buffer, address);
    return Buffer.from(bytes.subarray(0, bytes.indexOf(0))).toString("latin1");
  };
  // A headless host: no assets, and a clock that only moves when read.
  let clock = 0;
  const host = Object.fromEntries(
    WebAssembly.Module.imports(module)
      .filter((i) => i.module === "host")
      .map((i) => [
        i.name,
        {
          fatal: (message) => {
            throw Error(`game module: ${text(message)}`);
          },
          time_ms: () => (clock += 2),
        }[i.name] ??
          (() => {
            throw Error(`headless game module called host ${i.name}`);
          }),
      ]),
  );
  const e = new WebAssembly.Instance(module, { wasi_snapshot_preview1: wasi, host }).exports;
  memory = e.memory;
  e._initialize();
  return e;
}

// The original running from a game directory, settled on its main menu after
// loading every asset: sessions then run inside it, as the client plays them.
export function loadLiveGame(wasm, directory) {
  const run = bootGame(wasm, directory);
  // The startup sequence shares the main menu's screen id and ends after about 14 s.
  for (let frame = 0; frame < 1200; frame++) run.frame(16);
  return run.game;
}

// A tick nothing can refuse except a run that is over (host.cpp's run-down).
const NEUTRAL = record([0, 0, 0, 0, 0]);

// Whether the verifier still accepts a neutral tick after these records.
function acceptsAfter(coreWasm, run, count) {
  const core = loadCore(coreWasm);
  init(core, run.config);
  for (let tick = 0; tick < count; tick++) step(core, run.records[tick]);
  return step(core, NEUTRAL);
}

export function compareStream(input, core, game, coreWasm) {
  const run = decode(input);
  init(core, run.config);
  init(game, run.config);
  for (let tick = -1; tick < run.records.length; tick++) {
    if (tick >= 0) {
      const accepted = [step(core, run.records[tick]), step(game, run.records[tick])];
      if (accepted[0] !== accepted[1]) return { tick, field: "accepted", core: accepted[0], game: accepted[1] };
      if (!accepted[0]) {
        // A stream may run past its run; any other refusal hides the rest of it.
        if (acceptsAfter(coreWasm, run, tick)) return { tick, rejected: "valid ticks remained" };
        return { ticks: tick, end: "run over" };
      }
    }
    const expected = state(core),
      actual = state(game);
    const i = firstDifference(expected, actual, COMPARED);
    if (i >= 0) return { tick, field: names[i], core: expected.readUInt32LE(i * 4), game: actual.readUInt32LE(i * 4) };
  }
  // One neutral tick past the stream: both accept it mid-run, both refuse it after the run.
  const after = [step(core, NEUTRAL), step(game, NEUTRAL)];
  if (after[0] !== after[1]) return { tick: run.records.length, field: "accepted after the stream", core: after[0], game: after[1] };
  return { ticks: run.records.length, end: after[0] ? "stream" : "run over" };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const live = args[0] === "--live" ? args.splice(0, 2)[1] : null;
  const [coreWasm, gameWasm, ...streams] = args;
  const core = loadCore(coreWasm ?? new URL("build/wasm/core.wasm", CORE));
  const gamePath = gameWasm ?? new URL("build/game/game.wasm", CORE);
  const game = live ? loadLiveGame(gamePath, live) : loadGame(gamePath);
  const files = streams.length
    ? streams
    : fs.readdirSync(new URL("build/fixtures", CORE)).map((f) => path.join(new URL("build/fixtures", CORE).pathname, f));
  let failed = 0;
  for (const file of files) {
    const result = compareStream(fs.readFileSync(file), core, game, coreWasm ?? new URL("build/wasm/core.wasm", CORE));
    if (!result.end) failed++;
    console.log(path.basename(file), JSON.stringify(result));
  }
  process.exitCode = failed ? 1 : 0;
}
