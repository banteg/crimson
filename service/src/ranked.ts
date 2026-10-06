// The run-level ranked rules, a port of src/crimson/replay/ranked.py (docs/rewrite/ranked-rules.md). The per-tick
// controls and aim checks run with the simulation, in the verifier.

import { GameMode, type RunResult, type RunSpec } from "./replay";

const QUEST_COUNT = 50;
const RANKED_DETAIL_PRESET = 5;
const WEAPON_USAGE_SLOTS = 53;
const FINISHED: Record<number, string> = { [GameMode.SURVIVAL]: "death", [GameMode.QUESTS]: "quest_completed" };

export type Board = "survival" | "quests" | "quests-hardcore";

export function rankedBoard(run: RunSpec): Board | null {
  if (run.game_mode_id === GameMode.SURVIVAL) return "survival";
  if (run.game_mode_id === GameMode.QUESTS) return run.hardcore ? "quests-hardcore" : "quests";
  return null;
}

export function unrankedReasons(run: RunSpec): string[] {
  const reasons: string[] = [];
  if (rankedBoard(run) === null) reasons.push("mode");
  if (run.player_count !== 1) reasons.push("players");
  if (run.preserve_bugs) reasons.push("original_rules");
  if (run.detail_preset !== RANKED_DETAIL_PRESET) reasons.push("detail_preset");
  if (run.violence_disabled) reasons.push("violence_disabled");
  if (run.friendly_fire) reasons.push("friendly_fire");
  if (run.hardcore && run.game_mode_id !== GameMode.QUESTS) reasons.push("hardcore");
  if (run.quest_fail_retry_count) reasons.push("quest_retry");
  if (run.status.quest_unlock_index !== QUEST_COUNT || run.status.quest_unlock_index_hardcore !== QUEST_COUNT)
    reasons.push("unlocks");
  if (run.status.weapon_usage_counts.length !== WEAPON_USAGE_SLOTS || run.status.weapon_usage_counts.some(Boolean))
    reasons.push("weapon_usage");
  return reasons;
}

export function outcomeReasons(run: RunSpec, result: RunResult): string[] {
  return FINISHED[run.game_mode_id] === result.outcome ? [] : ["unfinished"];
}

// A board's score and its order: Survival ranks experience, higher first; quests rank final time, lower first.
export function rankedScore(run: RunSpec, result: RunResult): number {
  return run.game_mode_id === GameMode.QUESTS ? result.quest_final_ms! : result.players[0]!.experience;
}

export const LOWER_IS_BETTER: Record<Board, boolean> = { survival: false, quests: true, "quests-hardcore": true };
