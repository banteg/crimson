import { describe, expect, it } from "vitest";
import { formatLongDuration, formatPostDate } from "../../web/src/format";

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

describe("formatPostDate", () => {
  it.each([
    ["2026-02-01", "February 1st 2026"],
    ["2026-03-02", "March 2nd 2026"],
    ["2026-03-03", "March 3rd 2026"],
    ["2026-03-11", "March 11th 2026"],
    ["2026-03-12", "March 12th 2026"],
    ["2026-03-13", "March 13th 2026"],
    ["2026-03-21", "March 21st 2026"],
    ["2026-03-22", "March 22nd 2026"],
    ["2026-03-31", "March 31st 2026"],
  ])("%s → %s", (date, text) => expect(formatPostDate(date)).toBe(text));
});
