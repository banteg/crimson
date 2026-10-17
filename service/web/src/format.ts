import { type Board, BOARDS } from "../../src/api-types";

export const quantity = (count: number, unit: string): string => `${count.toLocaleString("en-US")} ${unit}${count === 1 ? "" : "s"}`;

// Seconds in each unit of a long duration, largest first; a month is a twelfth of a 365-day year.
const DURATION_UNITS: [string, number][] = [
  ["year", 31_536_000], ["month", 2_628_000], ["day", 86_400], ["hour", 3_600], ["minute", 60], ["second", 1],
];

// A duration in its largest unit and, when not zero, the next one down: "2 years 3 months", "5 hours".
export function formatLongDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const index = DURATION_UNITS.findIndex(([, size]) => size <= Math.max(seconds, 1));
  const [unit, size] = DURATION_UNITS[index]!;
  const next = DURATION_UNITS[index + 1];
  const rest = next ? Math.floor((seconds % size) / next[1]) : 0;
  return [quantity(Math.floor(seconds / size), unit), ...(rest ? [quantity(rest, next![0])] : [])].join(" ");
}

// A board's score: experience for Survival, the final time for quests, which bonuses can take below zero.
export function formatScore(board: Board, score: number): string {
  if (!BOARDS[board].quests) return `${score.toLocaleString("en-US")} xp`;
  const ms = Math.abs(score);
  const time = `${Math.floor(ms / 60000)}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, "0")}.${String(ms % 1000).padStart(3, "0")}`;
  return score < 0 ? `-${time}` : time;
}
