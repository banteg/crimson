// The run-level ranked rules, a port of src/crimson/replay/ranked.py (docs/rewrite/ranked-rules.md). The per-tick
// controls and aim checks run with the simulation, in the verifier.

import type { Board } from "./api-types";
import { GameMode, type RunResult, type RunSpec } from "./replay";
import { rankedUnlocks } from "./unlocks";

export type { Board };

const RANKED_DETAIL_PRESET = 5;
const RANKED_MODES = new Set<number>([GameMode.SURVIVAL, GameMode.QUESTS]);
// One player, or a co-op pair on the co-op boards.
const RANKED_PLAYER_COUNTS = new Set([1, 2]);
const WEAPON_USAGE_SLOTS = 53;
const FINISHED: Record<number, string> = { [GameMode.SURVIVAL]: "death", [GameMode.QUESTS]: "quest_completed" };

// ranked.py board_for: the board a ranked run of this mode, difficulty and team goes to.
export function rankedBoard(run: RunSpec): Board | null {
  if (!RANKED_PLAYER_COUNTS.has(run.player_count)) return null;
  const board =
    run.game_mode_id === GameMode.SURVIVAL ? "survival"
    : run.game_mode_id === GameMode.QUESTS ? (run.hardcore ? "quests-hardcore" : "quests")
    : null;
  return board && run.player_count > 1 ? `${board}-coop` : board;
}

export function unrankedReasons(run: RunSpec): string[] {
  const reasons: string[] = [];
  if (!RANKED_MODES.has(run.game_mode_id)) reasons.push("mode");
  if (!RANKED_PLAYER_COUNTS.has(run.player_count)) reasons.push("players");
  // A custom quest's board, and the clear that publishes it, are one player's.
  else if (run.custom_quest !== null && run.player_count !== 1) reasons.push("custom_quest_players");
  if (run.preserve_bugs) reasons.push("original_rules");
  if (run.detail_preset !== RANKED_DETAIL_PRESET) reasons.push("detail_preset");
  if (run.violence_disabled) reasons.push("violence_disabled");
  if (run.friendly_fire) reasons.push("friendly_fire");
  if (run.hardcore && (run.game_mode_id !== GameMode.QUESTS || run.custom_quest !== null)) reasons.push("hardcore");
  if (run.quest_fail_retry_count) reasons.push("quest_retry");
  const [unlocks, unlocksHardcore] = rankedUnlocks(run.quest_level, run.hardcore);
  if (run.status.quest_unlock_index !== unlocks || run.status.quest_unlock_index_hardcore !== unlocksHardcore)
    reasons.push("unlocks");
  if (run.status.weapon_usage_counts.length !== WEAPON_USAGE_SLOTS || run.status.weapon_usage_counts.some(Boolean))
    reasons.push("weapon_usage");
  return reasons;
}

export function outcomeReasons(run: RunSpec, result: RunResult): string[] {
  return FINISHED[run.game_mode_id] === result.outcome ? [] : ["unfinished"];
}

// A board's score and its order: Survival ranks experience (a pair's is shared, on player one), higher first; quests
// rank final time, lower first.
export function rankedScore(run: RunSpec, result: RunResult): number {
  return run.game_mode_id === GameMode.QUESTS ? result.quest_final_ms! : result.players[0]!.experience;
}

export const LOWER_IS_BETTER: Record<Board, boolean> = {
  survival: false, quests: true, "quests-hardcore": true, "survival-coop": false, "quests-coop": true, "quests-hardcore-coop": true,
};
