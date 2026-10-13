import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parentPort, workerData } from "node:worker_threads";
import { createServer } from "vite";

const { service: SERVICE, art: ART, grounds: GROUNDS } = workerData;
// The service's own modules, with the worker's wasm imports as the compiled modules it binds.
const vite = await createServer({
  configFile: false,
  root: SERVICE,
  logLevel: "error",
  server: { middlewareMode: true, hmr: false, ws: false, watch: null },
  appType: "custom",
  plugins: [
    {
      name: "wasm-modules",
      enforce: "pre",
      load: (id) =>
        id.endsWith(".wasm")
          ? `import { readFileSync } from "node:fs"; export default new WebAssembly.Module(readFileSync(${JSON.stringify(id)}));`
          : null,
    },
  ],
});
const { decodeReplay, inflateReplay } = await vite.ssrLoadModule("/src/replay.ts");
const { encodeTransport } = await vite.ssrLoadModule("/src/transport.ts");
const { verifyWithGround } = await vite.ssrLoadModule("/src/runs.ts");
// The worker's site files, as its ASSETS binding serves them.
const env = { ASSETS: { fetch: async (url) => new Response(readFileSync(join(ART, new URL(url).pathname))) } };

parentPort.on("message", async ({ id, file }) => {
  try {
    const start = performance.now();
    const replay = decodeReplay(inflateReplay(new Uint8Array(readFileSync(file))));
    const { verdict, ground } = await verifyWithGround(env, "https://crimson.land", replay, encodeTransport(replay));
    if (verdict.ok) writeFileSync(join(GROUNDS, `${id}.jpg`), ground);
    // Keep large timelines, signals, and image buffers inside the worker.
    parentPort.postMessage({ id, ok: verdict.ok, reason: verdict.ok ? null : verdict.reason,
      ticks: replay.ticks.length, seconds: (performance.now() - start) / 1000 });
  } catch (cause) {
    // Unexpected errors abort the deploy rather than being reported as retirement candidates.
    throw new Error(`Failed to reverify ${id}`, { cause });
  }
});
parentPort.postMessage({ ready: true });
