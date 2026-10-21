import { describe, expect, it } from "vitest";
import { lifeBonusMs, questFinalMs } from "../../src/quest-time";

describe("quest life bonus", () => {
  it.each([[100, -80], [-80, 100]])("clamps negative health in either co-op seat: %j", (...health) => {
    expect(lifeBonusMs(health)).toBe(5000);
    expect(lifeBonusMs(health, true)).toBe(1000);
    expect(questFinalMs(100000, health, 2)).toBe(93000);
    expect(questFinalMs(100000, health, 2, true)).toBe(97000);
  });
  it("retains seat-specific rounding and the zero-result sentinel", () => {
    expect(lifeBonusMs([90.9, 10.75])).toBe(5037);
    expect(questFinalMs(5037, [90.9, 10.75], 0)).toBe(1);
  });
});
