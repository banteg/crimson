import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { CORE } from "../checks/engine.mjs";

const out = path.resolve(
  process.argv[2] ?? fileURLToPath(new URL("build", CORE)),
);
const url = process.argv[3] ?? "http://127.0.0.1:8799";
const report = JSON.parse(fs.readFileSync(path.join(out, "report.json")));
for (const c of report.cases) {
  const response = await fetch(url, {
    method: "POST",
    body: fs.readFileSync(path.join(out, "fixtures", `${c.name}.rsi`)),
  });
  const actual = await response.json();
  if (
    response.status !== 200 ||
    actual.final_sha256 !== c.final_sha256 ||
    actual.ticks !== c.ticks
  ) {
    throw Error(`${c.name}: Worker mismatch ${JSON.stringify(actual)}`);
  }
  console.log(`${c.name}: local Worker matched native/WASM final state`);
}
const bad = await fetch(url, { method: "POST", body: new Uint8Array(3) });
if (bad.status !== 400) throw Error("Worker accepted truncated input");
console.log(`Passed ${report.cases.length} local Worker runs + malformed body`);
