// Fresh-process benchmark. Fail on a rejected tick or unexpected final state.
import fs from "node:fs";
import { createHash } from "node:crypto";
import { decode, init, loadCore, state, step } from "./engine.mjs";

const [wasm, replay, expected] = process.argv.slice(2);
if (!wasm || !replay || !expected)
  throw Error("Usage: benchmark_run.mjs module.wasm replay.rsi expected-sha256");
const { config, records } = decode(fs.readFileSync(replay));
const core = loadCore(wasm);
init(core, config);
for (const tick of records)
  if (!step(core, tick)) throw Error("Rejected tick");
const hash = createHash("sha256").update(state(core)).digest("hex");
if (hash !== expected) throw Error(`Terminal state differs: ${hash} != ${expected}`);
console.log(JSON.stringify({ hash, ticks: records.length, wasm_memory_bytes: core.memory.buffer.byteLength }));
