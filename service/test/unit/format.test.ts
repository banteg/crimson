import { describe, expect, it } from "vitest";
import { formatLongDuration } from "../../web/src/format";

const DAY = 86_400_000;

describe("formatLongDuration", () => {
  it.each([
    [0, "0 seconds"],
    [999, "0 seconds"],
    [61_000, "1 minute 1 second"],
    [3_659_000, "1 hour"],
    [DAY + 3_661_000, "1 day 1 hour"],
    [360 * DAY, "11 months 25 days"],
    [365 * DAY + 3_600_000, "1 year"],
    [(2 * 365 + 92) * DAY, "2 years 3 months"],
    [1001 * 365 * DAY, "1,001 years"],
  ])("formats %i ms as %s", (ms, expected) => {
    expect(formatLongDuration(ms)).toBe(expected);
  });
});
