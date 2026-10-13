import { describe, expect, it } from "vitest";
import { formatSurvived } from "../../web/src/format";

describe("total survived", () => {
  it.each([
    [0, "0 seconds"],
    [999, "0 seconds"],
    [1000, "1 second"],
    [61000, "1 minute 1 second"],
    [90061000, "1 day 1 hour 1 minute"],
    [(365 * 2 + 30 * 3 + 4) * 86400000 + 3661000, "2 years 3 months 4 days"],
    [(365 * 86400 + 3600 + 2) * 1000, "1 year 1 hour 2 seconds"],
  ])("formats %i ms as %s", (ms, expected) => {
    expect(formatSurvived(ms)).toBe(expected);
  });
});
