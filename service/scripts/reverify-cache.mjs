import assert from "node:assert/strict";
import { existsSync, mkdirSync, renameSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";

// Reuse complete local files. This directory must not enter fork-readable Actions caches.
export async function downloadReplays(ids, directory, download, concurrency = 4) {
  assert.ok(Number.isInteger(concurrency) && concurrency > 0, "Invalid download concurrency");
  mkdirSync(directory, { recursive: true });
  const runs = ids.map((id) => {
    assert.match(id, /^[a-f0-9]{64}$/, "Invalid production run ID");
    return { id, file: join(directory, `${id}.crd`) };
  });
  let next = 0;
  let downloaded = 0;
  const workers = Array.from({ length: Math.min(concurrency, runs.length) }, async () => {
    while (next < runs.length) {
      const { id, file } = runs[next++];
      if (existsSync(file) && statSync(file).size > 0) continue;
      const temporary = `${file}.partial`;
      try {
        await download(id, temporary);
        assert.ok(statSync(temporary).size > 0, `Empty replay download: ${id}`);
        renameSync(temporary, file);
        downloaded++;
      } finally {
        rmSync(temporary, { force: true });
      }
    }
  });
  // Finish in-flight downloads before reporting a failure; only complete files survive.
  const results = await Promise.allSettled(workers);
  const failure = results.find((result) => result.status === "rejected");
  if (failure) throw failure.reason;
  return { runs, downloaded };
}
