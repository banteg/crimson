import { afterEach, describe, expect, it, vi } from "vitest";
import { gameplayPreference, setGameplayPreference } from "../../web/src/analytics-preference";

afterEach(() => vi.unstubAllGlobals());
describe("gameplay analytics preference", () => {
  function setup(privacy: object = {}) {
    const store = new Map<string, string>();
    vi.stubGlobal("navigator", privacy);
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => store.set(key, value),
      removeItem: (key: string) => store.delete(key),
    });
    return store;
  }
  it("opt-out persists and removes the daily token without touching game saves", () => {
    const store = setup();
    store.set("crimson.play-analytics", "daily token");
    store.set("game-save", "untouched");
    expect(setGameplayPreference(false)).toBe(true);
    expect(gameplayPreference()).toEqual({ enabled: false, forced: false, available: true });
    expect(store.has("crimson.play-analytics")).toBe(false);
    expect(store.get("game-save")).toBe("untouched");
    expect(setGameplayPreference(true)).toBe(true);
    expect(gameplayPreference().enabled).toBe(true);
    expect(store.has("crimson.play-analytics-disabled")).toBe(false);
  });
  it.each([{ doNotTrack: "1" }, { globalPrivacyControl: true }])("respects browser privacy signals: %s", (privacy) => {
    setup(privacy);
    expect(gameplayPreference()).toEqual({ enabled: false, forced: true, available: true });
  });
  it("reports unavailable storage without throwing or claiming a preference was saved", () => {
    setup();
    vi.stubGlobal("localStorage", { getItem() { throw Error("refused"); }, setItem() { throw Error("refused"); } });
    expect(gameplayPreference()).toEqual({ enabled: false, forced: false, available: false });
    expect(setGameplayPreference(false)).toBe(false);
  });
});
