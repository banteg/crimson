import fs from "node:fs";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import {
  decode,
  init,
  loadCore,
  state,
  step,
  names,
  config,
  record,
} from "./engine.mjs";

export async function compare(input, native, wasm) {
  const e = loadCore(wasm);
  const run = decode(input);
  init(e, run.config);
  let pending = Buffer.alloc(0),
    stderr = "",
    snapshots = 0;
  const hash = crypto.createHash("sha256");
  const start = performance.now();
  const child = spawn(native, ["--reset-check"], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const completion = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => resolve(code));
  });
  child.stdin.on("error", () => {});
  child.stderr.on("data", (x) => (stderr += x));
  child.stdin.end(input);
  try {
    for await (const chunk of child.stdout) {
      pending = Buffer.concat([pending, chunk]);
      while (pending.length >= 4) {
        const bytes = pending.readUInt32LE(0) * 4;
        if (bytes !== names.length * 4)
          throw Error("Invalid native snapshot length");
        if (pending.length < bytes + 4) break;
        if (snapshots > 0 && !step(e, run.records[snapshots - 1]))
          throw Error(`WASM rejected tick ${snapshots - 1}`);
        const actual = state(e),
          expected = pending.subarray(4, bytes + 4);
        if (!expected.equals(actual)) {
          let i = 0;
          while (
            i < names.length &&
            expected.readUInt32LE(i * 4) === actual.readUInt32LE(i * 4)
          )
            i++;
          throw Error(
            `Snapshot ${snapshots}: ${names[i]} native=0x${expected.readUInt32LE(i * 4).toString(16)} wasm=0x${actual.readUInt32LE(i * 4).toString(16)}`,
          );
        }
        hash.update(actual);
        snapshots++;
        pending = pending.subarray(bytes + 4);
      }
    }
    const code = await completion;
    if (code !== 0 || pending.length)
      throw Error(`Native exit ${code}: ${stderr}`);
    if (snapshots !== run.records.length + 1)
      throw Error(`Compared ${snapshots - 1}/${run.records.length}`);
    if (!stderr.includes("native A/B/A passed"))
      throw Error("Native reset test did not run");
  } catch (error) {
    child.kill();
    await completion;
    throw error;
  }
  const last = Buffer.from(state(e));
  init(
    e,
    config(2, 1, 1, { seed: 12345, unlock: 0, unlockFull: 0, detail: 0 }),
  );
  for (let i = 0; i < 200; i++)
    if (!step(e, record([1, 0, 512, 512, 38656]))) throw Error("B reset run");
  init(e, run.config);
  for (const r of run.records)
    if (!step(e, r)) throw Error("A reset rejected input");
  if (!last.equals(state(e))) throw Error("WASM A/B/A reset differs");
  const comparisonSeconds = (performance.now() - start) / 1000;
  init(e, run.config);
  const bench = performance.now();
  for (const r of run.records)
    if (!step(e, r)) throw Error("Benchmark rejected input");
  const seconds = (performance.now() - bench) / 1000;
  if (!last.equals(state(e))) throw Error("Benchmark final state differs");
  return {
    ticks: run.records.length,
    fields_per_snapshot: names.length,
    sha256: hash.digest("hex"),
    final_sha256: crypto.createHash("sha256").update(last).digest("hex"),
    comparison_seconds: comparisonSeconds,
    wasm_sim_seconds: seconds,
    wasm_memory_mib: e.memory.buffer.byteLength / 1048576,
    reset: "native and WASM A/B/A passed",
    imports: 0,
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  if (process.argv.length !== 5)
    throw Error("Usage: node compare.mjs input.rsi native/core wasm/core.wasm");
  console.log(
    JSON.stringify(
      await compare(
        fs.readFileSync(process.argv[2]),
        process.argv[3],
        process.argv[4],
      ),
      null,
      2,
    ),
  );
}
