import type { Board } from "../../src/api-types";

export function formatSurvived(ms: number): string {
  let seconds = Math.floor(ms / 1000);
  const units: [string, number][] = [
    ["year", 365 * 86400], ["month", 30 * 86400], ["day", 86400],
    ["hour", 3600], ["minute", 60], ["second", 1],
  ];
  const parts: string[] = [];
  for (const [unit, size] of units) {
    const value = Math.floor(seconds / size);
    seconds %= size;
    if (value) parts.push(`${value} ${unit}${value === 1 ? "" : "s"}`);
    if (parts.length === 3) break;
  }
  return parts.join(" ") || "0 seconds";
}

// A board's score: experience for Survival, the final time for quests, which bonuses can take below zero.
export function formatScore(board: Board, score: number): string {
  if (board === "survival") return `${score.toLocaleString("en-US")} xp`;
  const ms = Math.abs(score);
  const time = `${Math.floor(ms / 60000)}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, "0")}.${String(ms % 1000).padStart(3, "0")}`;
  return score < 0 ? `-${time}` : time;
}
