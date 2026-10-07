import type { Board } from "../../src/api-types";

// A board's score: experience for Survival, the final time for quests, which bonuses can take below zero.
export function formatScore(board: Board, score: number): string {
  if (board === "survival") return `${score.toLocaleString("en-US")} xp`;
  const ms = Math.abs(score);
  const time = `${Math.floor(ms / 60000)}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, "0")}.${String(ms % 1000).padStart(3, "0")}`;
  return score < 0 ? `-${time}` : time;
}
