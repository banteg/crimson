// Manual before/after benchmark or every-tick comparison of the same replay.
// node profile_replay.mjs run.rsi before.wasm after.wasm out.json [--compare]
import fs from "node:fs";
import { createHash } from "node:crypto";
import { decode, field, init, loadCore, names, state, step } from "./engine.mjs";

const [replay, before, after, output, option] = process.argv.slice(2);
if (!output || (option && option !== "--compare"))
  throw Error("Usage: profile_replay.mjs run.rsi before.wasm after.wasm out.json [--compare]");
const { config, records } = decode(fs.readFileSync(replay));
const cores = [loadCore(before), loadCore(after)];
const sha256 = path => createHash("sha256").update(fs.readFileSync(path)).digest("hex");
const result = { replay, before, after, sha256: { replay: sha256(replay), before: sha256(before), after: sha256(after) }, ticks: records.length, fields: names.length, runs: [] };
if (option === "--compare") {
  cores.forEach(core => init(core, config));
  for (let tick = -1; tick < records.length; ++tick) {
    if (tick >= 0 && step(cores[0], records[tick]) !== step(cores[1], records[tick]))
      throw Error(`Acceptance differs at tick ${tick}`);
    const [a, b] = cores.map(state);
    if (!a.equals(b)) {
      const index = names.findIndex((_, i) => a.readUInt32LE(i * 4) !== b.readUInt32LE(i * 4));
      throw Error(`Tick ${tick}: ${names[index]} differs`);
    }
  }
  result.equal = true;
} else {
  // Reverse the order on the middle repetition to reduce systematic ordering effects.
  for (let repeat = 0; repeat < 3; ++repeat) {
    for (const which of repeat === 1 ? [1, 0] : [0, 1]) {
      const core = cores[which], blocks = [];
      init(core, config);
      for (let from = 0; from < records.length; from += 600) {
        const to = Math.min(from + 600, records.length), start = performance.now();
        for (let tick = from; tick < to; ++tick)
          if (!step(core, records[tick])) throw Error(`Rejected tick ${tick}`);
        const ms = performance.now() - start;
        state(core); // Snapshot and workload reads are outside the timed block.
        blocks.push({ from, to, ms, elapsed: field(core, "globals.run_elapsed_ms") });
      }
      const run = { repeat, which, ms: blocks.reduce((sum, b) => sum + b.ms, 0),
        hash: createHash("sha256").update(state(core)).digest("hex"), blocks };
      result.runs.push(run);
      fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
      console.log(`${which ? "after" : "before"} repeat ${repeat}: ${run.ms.toFixed(1)} ms`);
    }
  }
  if (new Set(result.runs.map(run => run.hash)).size !== 1) throw Error("Terminal snapshots differ");
  result.equal = true;
}
fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n");
console.log(option === "--compare" ? `${records.length} ticks agree` : output);
