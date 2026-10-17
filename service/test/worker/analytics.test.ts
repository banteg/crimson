import { createScheduledController, env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../../src/index";
import { SESSION_COOKIE, tokenHash } from "../../src/auth";

const ORIGIN = "https://crimson.land";
const day = () => new Date().toISOString().slice(0, 10);
const token = "a".repeat(32);
const unique = () => ({ day: day(), token });
const totals = () => ({ day: day(), ready: 1, sessions: 1, engaged: 0, modes: [{ mode: "survival", runs: 2, seconds: 60 }] });
const depths = () => [5, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const coop = () => ({ day: day(), transport: "turn-udp", rtt: 2, seconds: 600, desync: 0, stalled: 4, depths: depths(), frames: [30000, 100, 0, 0, 0, 1] });
function post(value: unknown, path = "/api/analytics/unique", headers: Record<string, string> = {}) {
  return worker.fetch(new Request(ORIGIN + path, {
    method: "POST", headers: { origin: ORIGIN, "content-type": "application/json", ...headers }, body: JSON.stringify(value),
  }), env);
}
afterEach(() => vi.restoreAllMocks());

describe("private gameplay counts", () => {
  it("counts concurrent daily-token retries once, without creating an account or recording an activity", async () => {
    const responses = await Promise.all(Array.from({ length: 8 }, () => post(unique(), undefined, { cookie: "session=unrelated", "cf-connecting-ip": "192.0.2.1" })));
    expect(responses.map((response) => response.status)).toEqual(Array(8).fill(204));
    expect(responses.every((response) => !response.headers.has("set-cookie"))).toBe(true);
    expect(await env.DB.prepare("SELECT * FROM play_uniques").all()).toMatchObject({ results: [{ day: day(), token }] });
    expect(await env.DB.prepare("SELECT unique_browsers, ready, runs, active_seconds FROM play_totals").first())
      .toEqual({ unique_browsers: 1, ready: 0, runs: 0, active_seconds: 0 });
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM accounts").first()).toEqual({ n: 0 });
    expect((await post({ day: day(), token: "b".repeat(32) })).status).toBe(204);
    expect(await env.DB.prepare("SELECT unique_browsers FROM play_totals").first()).toEqual({ unique_browsers: 2 });
  });

  it("keeps anonymous gameplay totals separate from unique presence", async () => {
    expect((await post(totals(), "/api/analytics")).status).toBe(204);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM play_uniques").first()).toEqual({ n: 0 });
    expect(await env.DB.prepare("SELECT mode, unique_browsers, ready, sessions, runs, active_seconds FROM play_totals ORDER BY mode").all())
      .toMatchObject({ results: [
        { mode: "all", unique_browsers: 0, ready: 1, sessions: 1, runs: 0, active_seconds: 0 },
        { mode: "survival", unique_browsers: 0, ready: 0, sessions: 0, runs: 2, active_seconds: 60 },
      ] });
  });

  it("adds co-op session summaries to daily totals by transport, keeping no session of its own", async () => {
    expect((await post(coop(), "/api/analytics/coop")).status).toBe(204);
    expect((await post({ ...coop(), desync: 1, rtt: 4 }, "/api/analytics/coop")).status).toBe(204);
    const rows = await env.DB.prepare("SELECT * FROM coop_totals ORDER BY metric, bucket").all();
    const count = (metric: string, bucket = 0) => rows.results.find((row) => row.metric === metric && row.bucket === bucket)?.count;
    expect(rows.results.every((row) => row.day === day() && row.transport === "turn-udp")).toBe(true);
    expect([count("sessions"), count("seconds"), count("desyncs"), count("stalled")]).toEqual([2, 1200, 1, 8]);
    expect([count("rtt", 2), count("rtt", 4), count("depth", 0), count("depth", 11), count("frame", 5)]).toEqual([1, 1, 10, 2, 2]);
    // Buckets nothing reached take no row.
    expect(count("depth", 2)).toBeUndefined();
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM play_totals").first()).toEqual({ n: 0 });
    for (const value of [{ ...coop(), transport: "carrier-pigeon" }, { ...coop(), room: "abc" }, { ...coop(), rtt: 5 },
      { ...coop(), seconds: 43201 }, { ...coop(), desync: 2 }, { ...coop(), depths: depths().slice(1) },
      { ...coop(), frames: [1, 2, 3, 4, 5, -1] }, { ...coop(), stalled: 0.5 }])
      expect((await post(value, "/api/analytics/coop")).status).toBe(400);
    expect(await env.DB.prepare("SELECT SUM(count) AS n FROM coop_totals WHERE metric = 'sessions'").first()).toEqual({ n: 2 });
  });

  it("refuses ingestion before database writes when the shared anonymous budget is exhausted", async () => {
    const response = await worker.fetch(new Request(ORIGIN + "/api/analytics/unique", {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify(unique()),
    }), { ...env, PLAY_ANALYTICS_LIMITER: { limit: async () => ({ success: false }) } });
    expect([response.status, response.headers.get("retry-after")]).toEqual([429, "60"]);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM play_uniques").first()).toEqual({ n: 0 });
  });

  it("rejects cross-origin, malformed, oversized, identity-bearing and out-of-window reports", async () => {
    expect((await post(unique(), undefined, { origin: "https://other.invalid" })).status).toBe(403);
    expect((await post(unique(), "/api/analytics/unique?token=secret")).status).toBe(403);
    expect((await post(unique(), undefined, { "content-type": "text/plain" })).status).toBe(415);
    for (const value of [null, [], {}, { ...unique(), token: "short" }, { ...unique(), account: 1 }, { ...unique(), day: "2000-01-01" }, { ...unique(), day: "2099-01-01" }, { ...unique(), extra: "x".repeat(2048) }])
      expect((await post(value)).status).toBe(400);
    for (const value of [{ ...totals(), token }, { ...totals(), sessions: -1 }, { ...totals(), modes: [{ mode: "quest-id", runs: 1, seconds: 1 }] },
      { ...totals(), modes: [{ mode: "survival", runs: 1, seconds: 121 }] }, { ...totals(), modes: [{ mode: "survival", runs: 1, seconds: 1.5 }] },
      { ...totals(), modes: [totals().modes[0], totals().modes[0]] }])
      expect((await post(value, "/api/analytics")).status).toBe(400);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM play_totals").first()).toEqual({ n: 0 });
  });

  it("expires tokens on the scheduled job even without visits, retaining only daily totals", async () => {
    const now = Date.UTC(2026, 9, 15, 12);
    vi.spyOn(Date, "now").mockReturnValue(now);
    for (const date of ["2026-10-11", "2026-10-12", "2026-10-13", "2026-10-14", "2026-10-15"])
      await env.DB.prepare("INSERT INTO play_uniques VALUES (?, ?)").bind(date, token).run();
    await worker.scheduled(createScheduledController(), env);
    expect(await env.DB.prepare("SELECT day FROM play_uniques ORDER BY day").all()).toMatchObject({ results: [
      { day: "2026-10-13" }, { day: "2026-10-14" }, { day: "2026-10-15" },
    ] });
    expect(await env.DB.prepare("SELECT SUM(unique_browsers) AS n FROM play_totals").first()).toEqual({ n: 5 });
  });

  it("restricts reports to the admin and returns no token material", async () => {
    const get = (cookie = "") => worker.fetch(new Request(ORIGIN + "/api/analytics", { headers: { cookie } }), env);
    expect((await get()).status).toBe(403);
    const raw = "session-for-analytics", hash = await tokenHash(raw);
    await env.DB.prepare("INSERT INTO accounts (id, created_at, role) VALUES (1, 0, 'mod')").run();
    await env.DB.prepare("INSERT INTO sessions VALUES (?, 1, ?)").bind(hash, Date.now() + 60000).run();
    const cookie = `${SESSION_COOKIE}=${raw}`;
    expect((await get(cookie)).status).toBe(403);
    await env.DB.prepare("UPDATE accounts SET role = 'admin' WHERE id = 1").run();
    await post(unique());
    await post(coop(), "/api/analytics/coop");
    const response = await get(cookie);
    expect([response.status, response.headers.get("cache-control")]).toEqual([200, "no-store"]);
    const body = await response.text();
    expect(JSON.parse(body)).toMatchObject({ days: [{ day: day(), unique_browsers: 1 }] });
    expect(JSON.parse(body).coop).toContainEqual({ transport: "turn-udp", metric: "depth", bucket: 11, count: 1 });
    expect(body).not.toContain(token);
    expect(body).not.toContain("account");
  });
});
