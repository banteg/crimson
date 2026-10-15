// Anonymous daily gameplay totals. Only the unique-count route accepts a random
// daily token; the aggregate route cannot attach one to a mode or play time.
import type { Env } from "./http";
import { refuse } from "./http";
import type { PlayAnalyticsView, PlayTotals } from "./api-types";
import PLAY_ANALYTICS from "../../crimson-core/client/web/analytics.json";

const DAY = 86400000;
const PLAY_MODES = PLAY_ANALYTICS.modes.filter((mode) => mode !== null);
const date = (now: number) => new Date(now).toISOString().slice(0, 10);
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value: Record<string, unknown>, names: string[]) => Object.keys(value).every((name) => names.includes(name));
const integer = (value: unknown, max: number): value is number => Number.isInteger(value) && Number(value) >= 0 && Number(value) <= max;

// Bound the stream too: Content-Length is optional and cannot be trusted alone.
async function body(request: Request): Promise<unknown> {
  if (!request.body) return null;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 2048) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let at = 0;
    for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length; }
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

export async function postAnalytics(request: Request, env: Env, unique: boolean, now = Date.now()): Promise<Response> {
  const url = new URL(request.url);
  if (request.headers.get("origin") !== url.origin || url.search) return refuse(403, "same-origin analytics only");
  if (request.headers.get("content-type")?.split(";")[0] !== "application/json") return refuse(415, "JSON required");
  if (!(await env.PLAY_ANALYTICS_LIMITER.limit({ key: "crimson-land-gameplay" })).success)
    return new Response(null, { status: 429, headers: { "retry-after": "60", "cache-control": "no-store" } });
  const value = await body(request);
  if (!object(value) || typeof value.day !== "string" || ![date(now), date(now - DAY), date(now - 2 * DAY)].includes(value.day))
    return refuse(400, "invalid analytics period");
  if (unique) {
    if (!fields(value, ["day", "token"]) || typeof value.token !== "string" || !/^[0-9a-f]{32}$/.test(value.token))
      return refuse(400, "invalid daily token");
    await env.DB.prepare("INSERT INTO play_uniques (day, token) VALUES (?, ?) ON CONFLICT DO NOTHING").bind(value.day, value.token).run();
  } else {
    if (!fields(value, ["day", "ready", "sessions", "engaged", "modes"]) ||
        !integer(value.ready, 1) || !integer(value.sessions, 1) || !integer(value.engaged, 1) ||
        !Array.isArray(value.modes) || value.modes.length > PLAY_MODES.length)
      return refuse(400, "invalid gameplay totals");
    const modes = new Set<string>();
    for (const row of value.modes) {
      if (!object(row) || !fields(row, ["mode", "runs", "seconds"]) ||
          typeof row.mode !== "string" || !PLAY_MODES.includes(row.mode) || modes.has(row.mode) ||
          !integer(row.runs, PLAY_ANALYTICS.max_runs) || !integer(row.seconds, PLAY_ANALYTICS.max_seconds)) return refuse(400, "invalid mode totals");
      modes.add(row.mode);
    }
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO play_totals (day, mode, ready, sessions, engaged) VALUES (?, 'all', ?, ?, ?)
        ON CONFLICT (day, mode) DO UPDATE SET ready = ready + excluded.ready,
        sessions = sessions + excluded.sessions, engaged = engaged + excluded.engaged`)
        .bind(value.day, value.ready, value.sessions, value.engaged),
      ...value.modes.map((row: { mode: string; runs: number; seconds: number }) =>
        env.DB.prepare(`INSERT INTO play_totals (day, mode, runs, active_seconds) VALUES (?, ?, ?, ?)
          ON CONFLICT (day, mode) DO UPDATE SET runs = runs + excluded.runs, active_seconds = active_seconds + excluded.active_seconds`)
          .bind(value.day, row.mode, row.runs, row.seconds)),
    ]);
  }
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

export async function pruneAnalytics(env: Env, now = Date.now()): Promise<void> {
  // Current day and the two retry days remain. No incoming traffic is needed.
  await env.DB.prepare("DELETE FROM play_uniques WHERE day < ?").bind(date(now - 2 * DAY)).run();
}

export async function analyticsView(env: Env, now = Date.now()): Promise<PlayAnalyticsView> {
  const { results } = await env.DB.prepare(`SELECT day, mode, unique_browsers, ready, sessions, engaged, runs, active_seconds
    FROM play_totals WHERE day >= ? ORDER BY day DESC, mode`).bind(date(now - 29 * DAY)).all<PlayTotals>();
  return { days: results };
}
