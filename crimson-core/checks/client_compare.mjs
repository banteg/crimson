// Compare every existing snapshot word with the unchanged verifier module.
// An abort or incomplete stream is evidence of failure, never a parity pass.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { decode, init, loadCore, names, state, step } from "./engine.mjs";

const [inputFile, client, wasm, output] = process.argv.slice(2);
if (!output) throw Error("Usage: client_compare.mjs input.rsi client core.wasm report.json");
const run = decode(fs.readFileSync(inputFile));
const e = loadCore(wasm);
init(e, run.config);
fs.mkdirSync(path.dirname(output), { recursive: true });
const trace = path.resolve(output + ".jsonl");
const child = spawn(path.resolve(client), [], {
  env: { ...process.env, CRIMSON_CLIENT_TRACE: trace },
  stdio: ["pipe", "pipe", "pipe"],
});
const completion = new Promise((resolve, reject) => {
  child.on("error", reject);
  child.on("close", (code, signal) => resolve({ code, signal }));
});
const timer = setTimeout(() => child.kill(), 120000);
child.stdin.on("error", () => {});
child.stdin.end(fs.readFileSync(inputFile));
let stderr = "", pending = Buffer.alloc(0), snapshots = 0, clientFinal;
child.stderr.on("data", (chunk) => { stderr += chunk; });
const differences = new Map(), verifierHash = crypto.createHash("sha256");
let expected = state(e);
verifierHash.update(expected);
const advance = (index) => {
  if (!step(e, run.records[index])) throw Error(`Verifier rejected tick ${index}`);
  expected = state(e);
  verifierHash.update(expected);
};
try {
  for await (const chunk of child.stdout) {
    pending = Buffer.concat([pending, chunk]);
    while (pending.length >= 4) {
      const bytes = pending.readUInt32LE(0) * 4;
      if (bytes !== names.length * 4) throw Error("Invalid client snapshot length");
      if (pending.length < 4 + bytes) break;
      if (snapshots > run.records.length) throw Error("Extra client snapshot");
      if (snapshots) advance(snapshots - 1);
      const actual = pending.subarray(4, bytes + 4);
      clientFinal = Buffer.from(actual);
      for (let i = 0; i < names.length; ++i) {
        const a = actual.readUInt32LE(i * 4), b = expected.readUInt32LE(i * 4);
        if (a !== b && !differences.has(names[i])) differences.set(names[i], {
          field: names[i], first_snapshot: snapshots,
          first_tick: snapshots ? snapshots - 1 : null,
          client_bits: a, verifier_bits: b,
        });
      }
      ++snapshots;
      pending = pending.subarray(bytes + 4);
    }
  }
  const exit = await completion;
  // Even when the client aborts in initialization, finish the verifier reference.
  for (let i = Math.max(0, snapshots - 1); i < run.records.length; ++i) advance(i);
  const final = Object.fromEntries(names.map((name, i) => [name, expected.readUInt32LE(i * 4)]));
  const events = fs.existsSync(trace) ? fs.readFileSync(trace, "utf8").trim().split("\n").filter(Boolean).map(JSON.parse) : [];
  const complete = exit.code === 0 && snapshots === run.records.length + 1 && !pending.length;
  const report = {
    input: inputFile, ticks: run.records.length, fields_per_snapshot: names.length,
    client_exit: exit, client_stderr: stderr.trim(), client_snapshots: snapshots,
    compared_ticks: Math.max(0, snapshots - 1), incomplete_snapshot_bytes: pending.length,
    verifier_ticks: run.records.length, verifier_state_sha256: verifierHash.digest("hex"),
    differences: [...differences.values()], blockers: events.filter((event) => ["unsupported", "rand_outside_tick"].includes(event.event)),
    complete_stream: complete,
    full_state_agree: complete && differences.size === 0,
    run_result_comparison: complete ? "derive from final snapshots" : "blocked: no complete client run",
    verifier_final: final,
  };
  if (clientFinal) report.client_final = Object.fromEntries(names.map((name, i) => [name, clientFinal.readUInt32LE(i * 4)]));
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ ...report, verifier_final: undefined, client_final: undefined }, null, 2));
  process.exitCode = report.full_state_agree ? 0 : 1;
} finally {
  clearTimeout(timer);
  child.kill();
}
