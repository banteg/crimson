// Embedded by client/build.py. Daily tokens and anonymous totals travel in
// separate requests; neither carries a game key, account, URL or recording.
function createPlayAnalytics() {
  const TOKEN = "crimson.play-analytics", DISABLED = "crimson.play-analytics-disabled";
  const MODES = [null, "survival", "rush", "quests", "typo", "custom", "practice", "hardcore", "tutorial"];
  const date = () => new Date(Date.now()).toISOString().slice(0, 10);
  let day = date(), pending = { ready: 0, sessions: 0, engaged: 0 }, modes = new Map();
  let previous = 0, previousAt = performance.now(), lastFlush = previousAt, lastRun = 0;
  let played = false, readySent = false, engaged = false, activeMs = 0, uniqueDay = null, requesting = false;
  let attemptedDay = null, attemptedAt = -Infinity;
  let storageChecked = false;
  function enabled() {
    try {
      if (!["crimson.land", "localhost"].includes(location.hostname) || window.self !== window.top ||
          navigator.doNotTrack === "1" || navigator.globalPrivacyControl === true || localStorage.getItem(DISABLED) === "1") return false;
      if (!storageChecked) {
        localStorage.setItem("crimson.play-analytics-check", "");
        localStorage.removeItem("crimson.play-analytics-check");
        storageChecked = true;
      }
      return true;
    } catch { return false; }
  }
  const send = async (path, body) => fetch(path, {
    method: "POST", credentials: "omit", referrerPolicy: "no-referrer", mode: "same-origin", keepalive: true,
    headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000),
  });
  function clear() {
    pending = { ready: 0, sessions: 0, engaged: 0 };
    modes.clear();
    previous = 0;
  }
  function flush() {
    lastFlush = performance.now();
    if (!enabled()) { clear(); return; }
    const rows = [...modes].map(([mode, value]) => ({ mode, runs: value.runs, seconds: Math.floor(value.ms / 1000) }));
    if (!Object.values(pending).some(Boolean) && !rows.some((row) => row.runs || row.seconds)) return;
    const payload = { day, ...pending, modes: rows.filter((row) => row.runs || row.seconds) };
    pending = { ready: 0, sessions: 0, engaged: 0 };
    for (const row of rows) {
      const value = modes.get(row.mode);
      value.runs = 0;
      value.ms -= row.seconds * 1000;
    }
    // Best effort: retrying totals could count them twice. Only uniques retry.
    void send("/api/analytics", payload).catch(() => {});
  }
  async function unique() {
    if (uniqueDay === day || requesting || !enabled()) return;
    requesting = true;
    const today = day;
    attemptedDay = today;
    attemptedAt = performance.now();
    try {
      // The separate lock makes token creation atomic across pages.
      const token = await navigator.locks.request("crimson-play-analytics", () => {
        if (!enabled() || today !== date()) return null;
        let value;
        try { value = JSON.parse(localStorage.getItem(TOKEN)); } catch {}
        if (value?.day !== today || !/^[0-9a-f]{32}$/.test(value?.token ?? "")) {
          value = { day: today, token: [...crypto.getRandomValues(new Uint8Array(16))].map((n) => n.toString(16).padStart(2, "0")).join("") };
          localStorage.setItem(TOKEN, JSON.stringify(value));
        }
        return value.token;
      });
      if (token && enabled() && (await send("/api/analytics/unique", { day: today, token })).ok) uniqueDay = today;
    } catch {
      // Storage, locks and the network are optional for analytics, never play.
    } finally { requesting = false; }
  }
  function activity(mode, run) {
    const now = performance.now(), elapsed = Math.max(0, Math.min(2000, now - previousAt));
    previousAt = now;
    if (!enabled()) { clear(); return; }
    if (day !== date()) { flush(); day = date(); modes.clear(); }
    const row = (name) => {
      if (!modes.has(name)) modes.set(name, { runs: 0, ms: 0 });
      return modes.get(name);
    };
    if (previous) { row(MODES[previous]).ms += elapsed; activeMs += elapsed; }
    mode = !document.hidden && document.hasFocus() && MODES[mode] ? mode : 0;
    if (mode) {
      if (!played) { pending.sessions = 1; played = true; }
      if (run && run !== lastRun) { row(MODES[mode]).runs++; lastRun = run; }
      if (uniqueDay !== day && (attemptedDay !== day || now - attemptedAt >= 60000)) void unique();
    }
    if (!engaged && activeMs >= 300000) { pending.engaged = 1; engaged = true; }
    const stopped = previous && !mode;
    previous = mode;
    if (stopped || pending.sessions || pending.engaged || now - lastFlush >= 60000) flush();
  }
  function ready() {
    if (!enabled() || readySent) return;
    readySent = true;
    pending.ready = 1;
    flush();
  }
  document.addEventListener("visibilitychange", () => { if (document.hidden) { activity(0, 0); flush(); } });
  window.addEventListener("pagehide", () => { activity(0, 0); flush(); });
  window.addEventListener("storage", () => { if (!enabled()) clear(); });
  return { ready, activity, flush };
}
