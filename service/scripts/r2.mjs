// The replay bucket's objects through Cloudflare's API, as `wrangler r2 object` reaches them, from one process: each
// wrangler call spends about 3 s starting, which made a deploy's replay downloads and ground uploads take minutes.
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const SERVICE = fileURLToPath(new URL("..", import.meta.url));
const BUCKET = "crimson-land-replays";
const execFileAsync = promisify(execFile);
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The deploy passes its token and account; locally, wrangler's own login.
async function credentials() {
  const wrangler = async (...args) => (await execFileAsync("npx", ["--no-install", "wrangler", ...args], { cwd: SERVICE })).stdout;
  const token = process.env.CLOUDFLARE_API_TOKEN ?? (await wrangler("auth", "token")).trim();
  if (process.env.CLOUDFLARE_ACCOUNT_ID) return { token, account: process.env.CLOUDFLARE_ACCOUNT_ID };
  const { accounts } = JSON.parse(await wrangler("whoami", "--json"));
  if (accounts.length !== 1) throw Error("Set CLOUDFLARE_ACCOUNT_ID to choose the replay bucket's account");
  return { token, account: accounts[0].id };
}

// Cloudflare's API answers bursts with 429 and Retry-After; those and server errors are retried, a few times.
export function r2Bucket(auth = credentials(), request = fetch, retries = 5) {
  async function call(key, init = {}) {
    const { token, account } = await auth;
    for (let attempt = 0; ; attempt++) {
      const response = await request(`https://api.cloudflare.com/client/v4/accounts/${account}/r2/buckets/${BUCKET}/objects/${key}`, {
        ...init, headers: { ...init.headers, Authorization: `Bearer ${token}` },
      });
      if (response.ok) return response;
      if ((response.status === 429 || response.status >= 500) && attempt < retries) {
        await response.body?.cancel();
        await pause(Number(response.headers.get("retry-after") ?? 2 ** attempt) * 1000);
        continue;
      }
      throw Error(`R2 ${init.method ?? "GET"} ${key}: HTTP ${response.status} ${await response.text()}`);
    }
  }
  return {
    get: async (key) => new Uint8Array(await (await call(key)).arrayBuffer()),
    put: async (key, body, type) => { await call(key, { method: "PUT", body, headers: { "Content-Type": type } }); },
    remove: async (key) => { await call(key, { method: "DELETE" }); },
  };
}
