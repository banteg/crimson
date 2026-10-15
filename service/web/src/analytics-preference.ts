// Shared key names with crimson-core/client/web/analytics.js. This preference
// controls our gameplay counters, separately from Cloudflare Web Analytics.
const DISABLED = "crimson.play-analytics-disabled";
const TOKEN = "crimson.play-analytics";

export function gameplayPreference(): { enabled: boolean; forced: boolean; available: boolean } {
  const privacy = navigator as typeof navigator & { doNotTrack?: string; globalPrivacyControl?: boolean };
  const forced = privacy.doNotTrack === "1" || privacy.globalPrivacyControl === true;
  try { return { enabled: !forced && localStorage.getItem(DISABLED) !== "1", forced, available: true }; }
  catch { return { enabled: false, forced, available: false }; }
}

export function setGameplayPreference(enabled: boolean): boolean {
  try {
    if (enabled) localStorage.removeItem(DISABLED);
    else { localStorage.setItem(DISABLED, "1"); localStorage.removeItem(TOKEN); }
    return true;
  } catch { return false; }
}
