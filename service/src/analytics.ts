// Anonymous daily gameplay totals. Only the unique-count route accepts a random
// daily token; the aggregate route cannot attach one to a mode or play time,
// nor the co-op route to a session's summary, which adds to daily totals by transport.
import type { Env } from "./http";
import { refuse } from "./http";
import type { CoopTotals, PlayAnalyticsView, PlayTotals } from "./api-types";
import PLAY_ANALYTICS from "../../crimson-core/client/web/analytics.json";

const DAY = 86400000;
const PLAY_MODES = PLAY_ANALYTICS.modes.filter((mode) => mode !== null);
const COOP = PLAY_ANALYTICS.coop;
// A summary's stalled frames: on the network and on a perk pick apart, or together as `stalled` from pages before
// the split, which keep posting while they stay open.
const COOP_FIELDS = ["day", "transport", "rtt", "seconds", "desync", "stalled_network", "stalled_perk", "stalled", "depths", "frames"];
// A histogram of `length` buckets counting at most `max` in all.
const counts = (value: unknown, length: number, max: number): value is number[] =>
  Array.isArray(value) && value.length === length && value.every((n) => integer(n, max)) && value.reduce((a, b) => a + b, 0) <= max;
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

export async function postAnalytics(request: Request, env: Env, kind: "totals" | "unique" | "coop", now = Date.now()): Promise<Response> {
  const url = new URL(request.url);
  if (request.headers.get("origin") !== url.origin || url.search) return refuse(403, "same-origin analytics only");
  if (request.headers.get("content-type")?.split(";")[0] !== "application/json") return refuse(415, "JSON required");
  if (!(await env.PLAY_ANALYTICS_LIMITER.limit({ key: "crimson-land-gameplay" })).success)
    return new Response(null, { status: 429, headers: { "retry-after": "60", "cache-control": "no-store" } });
  const value = await body(request);
  if (!object(value) || typeof value.day !== "string" || ![date(now), date(now - DAY), date(now - 2 * DAY)].includes(value.day))
    return refuse(400, "invalid analytics period");
  if (kind === "coop") {
    // As play totals are bounded by the minute a post covers, a session's summary is bounded by the seconds in runs it
    // claims: a rollback at most each tick, and frames, stalled ones together too, at most max_rate a second.
    const seconds = integer(value.seconds, COOP.max_seconds) ? value.seconds : -1, frames = seconds * COOP.max_rate;
    const combined = "stalled" in value;
    const stalled = combined ? [value.stalled] : [value.stalled_network, value.stalled_perk];
    if (!fields(value, COOP_FIELDS) || typeof value.transport !== "string" || !COOP.transports.includes(value.transport) ||
        !integer(value.rtt, COOP.rtt_ms.length) || seconds < 0 || !integer(value.desync, 1) ||
        (combined && ("stalled_network" in value || "stalled_perk" in value)) || !counts(stalled, stalled.length, frames) ||
        !counts(value.depths, COOP.depths, seconds * 60) || !counts(value.frames, COOP.frame_ms.length + 1, frames))
      return refuse(400, "invalid co-op session");
    // A summary that tells its stalls apart adds its seconds to theirs (split_seconds), so that the rates per minute
    // leave out the seconds of combined ones, which keep their old metric.
    const stalls: [string, number, number][] = combined ? [["stalled", 0, value.stalled as number]] :
      [["stalled_network", 0, value.stalled_network as number], ["stalled_perk", 0, value.stalled_perk as number], ["split_seconds", 0, seconds]];
    const rows: [string, number, number][] = [
      ["sessions", 0, 1], ["seconds", 0, seconds], ["desyncs", 0, value.desync], ...stalls,
      ["rtt", value.rtt, 1],
      ...value.depths.map((n, i): [string, number, number] => ["depth", i, n]),
      ...value.frames.map((n, i): [string, number, number] => ["frame", i, n]),
    ];
    await env.DB.batch(rows.filter(([, , n]) => n > 0).map(([metric, bucket, n]) =>
      env.DB.prepare(`INSERT INTO coop_totals (day, transport, metric, bucket, count) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (day, transport, metric, bucket) DO UPDATE SET count = count + excluded.count`)
        .bind(value.day, value.transport, metric, bucket, n)));
  } else if (kind === "unique") {
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
  const coop = await env.DB.prepare(`SELECT transport, metric, bucket, SUM(count) AS count FROM coop_totals WHERE day >= ?
    GROUP BY transport, metric, bucket ORDER BY transport, metric, bucket`).bind(date(now - 29 * DAY)).all<CoopTotals>();
  return { days: results, coop: coop.results };
}
