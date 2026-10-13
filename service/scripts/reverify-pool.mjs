import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";

// Give each isolate one replay at a time, reusing its WASM instances and decoded art.
// Results retain input order; progress is reported as each replay finishes.
export async function verifyRuns(runs, { jobs, workerData, onResult = () => {}, workerURL = new URL("./reverify-worker.mjs", import.meta.url) }) {
  assert.ok(Number.isSafeInteger(jobs) && jobs > 0, "Invalid verification concurrency");
  const workers = [];
  const results = new Array(runs.length);
  let next = 0;
  try {
    await Promise.all(Array.from({ length: Math.min(jobs, runs.length) }, () => new Promise((resolve, reject) => {
      const worker = new Worker(workerURL, { workerData });
      workers.push(worker);
      let current;
      worker.on("error", reject);
      worker.on("exit", (code) => reject(new Error(`Verification worker exited unexpectedly (${code})`)));
      worker.on("message", (result) => {
        try {
          if (current !== undefined) {
            results[current] = result;
            onResult(result);
          }
          if (next === runs.length) return resolve();
          current = next++;
          worker.postMessage(runs[current]);
        } catch (error) {
          reject(error);
        }
      });
    })));
    return results;
  } finally {
    // Also stop peers on startup errors, corrupt replays, or a crashed worker.
    await Promise.allSettled(workers.map((worker) => worker.terminate()));
  }
}
