// Embedded by client/build.py after PLAY_ANALYTICS (analytics.json), which the
// service shares. Daily tokens, anonymous totals and co-op session summaries
// travel in separate requests; none carries a game key, account, room, URL or
// recording.
// The kind of transport a co-op session ran over, from coop.js's name for it: the room's relay (ws-relay), or the
// WebRTC pair's two candidate types, "<local>/<remote>", the local one relay-<protocol> when this page's own TURN
// allocation names its protocol. Through TURN when either end is a relay: turn-udp or turn-tcp by this page's own
// relay's protocol, turn when this page cannot tell (only the partner relays, over a leg this page never sees, or
// its relay names no protocol); direct when neither is; unknown before the pair was read ("webrtc").
function coopTransport(transport) {
  if (transport === "ws-relay") return transport;
  const [local, remote] = transport?.split("/") ?? [];
  if (!remote) return "unknown";
  if (local === "relay-udp") return "turn-udp";
  if (local === "relay-tcp" || local === "relay-tls") return "turn-tcp";
  return local.startsWith("relay") || remote === "relay" ? "turn" : "direct";
}
function createPlayAnalytics() {
  // MODES is indexed by game_play_mode (host/session.inc).
  const { token: TOKEN, disabled: DISABLED, modes: MODES, max_runs: MAX_RUNS, max_seconds: MAX_SECONDS, coop: COOP } = PLAY_ANALYTICS;
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
    // An empty referrer drops the header; a no-referrer policy would also send Origin: null.
    method: "POST", credentials: "omit", referrer: "", mode: "same-origin", keepalive: true,
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
    // The service refuses a report over its caps; any excess waits for the next one.
    const rows = [...modes].map(([mode, value]) => ({
      mode, runs: Math.min(value.runs, MAX_RUNS), seconds: Math.min(Math.floor(value.ms / 1000), MAX_SECONDS),
    }));
    if (!Object.values(pending).some(Boolean) && !rows.some((row) => row.runs || row.seconds)) return;
    const payload = { day, ...pending, modes: rows.filter((row) => row.runs || row.seconds) };
    pending = { ready: 0, sessions: 0, engaged: 0 };
    for (const row of rows) {
      const value = modes.get(row.mode);
      value.runs -= row.runs;
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
  // A co-op session's summary as it ends (shell.html), best effort like the totals: the kind of transport it last
  // ran over (coopTransport), its round trip's bucket, its seconds in runs, whether it desynced, and the game's
  // counters (host/coop.inc CoopSessionStats): frames whose due ticks all waited, rollbacks by depth and frames by
  // the time their ticks took. As the service bounds a summary by the seconds it claims (at most max_seconds, a
  // rollback a tick, max_rate frames a second), counts past those bounds go down in proportion.
  function coop({ transport, rtt, ticks, desync, stalled, depths, frames }) {
    if (!enabled()) return;
    const { rtt_ms: RTT_MS, max_seconds: MAX_COOP_SECONDS, max_rate: MAX_RATE } = COOP;
    const seconds = Math.min(Math.ceil(ticks / 60), MAX_COOP_SECONDS);
    const fit = (counts, limit) => {
      const sum = counts.reduce((a, b) => a + b, 0);
      return sum <= limit ? counts : counts.map((n) => Math.floor((n * limit) / sum));
    };
    void send("/api/analytics/coop", {
      day: date(), transport: coopTransport(transport), rtt: RTT_MS.filter((ms) => rtt >= ms).length,
      seconds, desync: desync ? 1 : 0, stalled: Math.min(stalled, seconds * MAX_RATE),
      depths: fit(depths, seconds * 60), frames: fit(frames, seconds * MAX_RATE),
    }).catch(() => {});
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
  return { ready, activity, flush, coop };
}
