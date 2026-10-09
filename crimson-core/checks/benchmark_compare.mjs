// Run on a complete stream; both implementations still compare all bytes and reset both engines.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { compare } from "./compare.mjs";

const [inputPath, native, wasm, baselinePath] = process.argv.slice(2);
if (!inputPath || !native || !wasm || !baselinePath)
  throw Error("Usage: node benchmark_compare.mjs input.rsi native/core wasm/core.wasm baseline.mjs");
const baseline = (await import(pathToFileURL(path.resolve(baselinePath)))).compare;
const input = fs.readFileSync(inputPath);
const samples = [];
delete process.env.CRIMSON_CORE_TRACE_INIT;
for (const variant of ["baseline", "current", "current", "baseline", "baseline", "current", "current", "baseline"]) {
  const start = performance.now();
  const result = await (variant === "baseline" ? baseline : compare)(input, native, wasm);
  const sample = { variant, seconds: (performance.now() - start) / 1000, ...result };
  samples.push(sample);
  console.log(JSON.stringify(sample));
}
if (new Set(samples.map(({ seconds, variant, ...result }) => JSON.stringify(result))).size !== 1)
  throw Error("Comparator reports differ");
