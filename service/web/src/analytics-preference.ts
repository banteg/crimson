// The game's collector (crimson-core/client/web/analytics.js) reads the same
// keys. This preference controls our gameplay counters, separately from
// Cloudflare Web Analytics.
import PLAY_ANALYTICS from "../../../crimson-core/client/web/analytics.json";

export function gameplayPreference(): { enabled: boolean; forced: boolean; available: boolean } {
  const privacy = navigator as typeof navigator & { doNotTrack?: string; globalPrivacyControl?: boolean };
  const forced = privacy.doNotTrack === "1" || privacy.globalPrivacyControl === true;
  try { return { enabled: !forced && localStorage.getItem(PLAY_ANALYTICS.disabled) !== "1", forced, available: true }; }
  catch { return { enabled: false, forced, available: false }; }
}

export function setGameplayPreference(enabled: boolean): boolean {
  try {
    if (enabled) localStorage.removeItem(PLAY_ANALYTICS.disabled);
    else {
      localStorage.setItem(PLAY_ANALYTICS.disabled, "1");
      // Today's token stays, so opting back in today does not count this browser again.
      let day;
      try { day = JSON.parse(localStorage.getItem(PLAY_ANALYTICS.token) ?? "null")?.day; } catch {}
      if (day !== new Date().toISOString().slice(0, 10)) localStorage.removeItem(PLAY_ANALYTICS.token);
    }
    return true;
  } catch { return false; }
}
