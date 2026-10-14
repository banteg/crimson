// The site's board and quest pages. Each one's data is at /api plus its path: /survival, /quests/2.3 and
// /quests/hardcore/2.3, /custom and /custom/<id>. The Worker and the site both route by these.
import type { Board } from "./api-types";

export const QUEST = /^[1-5]\.(?:[1-9]|10)$/;
export const CUSTOM_QUEST_ID = /^[0-9a-f]{12}$/;

export type QuestBoard = Exclude<Board, "survival">;

// A stage's quest menu, or with a quest, its board too. /quests and /quests/hardcore open stage I.
export interface QuestPage {
  board: QuestBoard;
  stage: number;
  quest: string | null;
}

export function questPage(path: string): QuestPage | null {
  const match = /^\/quests(\/hardcore)?(?:\/([^/]+))?$/.exec(path);
  if (!match) return null;
  const board = match[1] ? "quests-hardcore" : "quests";
  const at = match[2] ?? "1";
  if (/^[1-5]$/.test(at)) return { board, stage: Number(at), quest: null };
  if (QUEST.test(at)) return { board, stage: Number(at.split(".")[0]), quest: at };
  return null;
}

// A stage's menu (a number) or a stock quest's board (a quest like "2.3").
export function questsPath(board: QuestBoard, at: number | string): string {
  return `/quests${board === "quests-hardcore" ? "/hardcore" : ""}/${at}`;
}

// A board's page; a custom quest's board is its quest's page.
export function boardPath(board: Board, quest: string): string {
  if (board === "survival") return "/survival";
  return CUSTOM_QUEST_ID.test(quest) ? `/custom/${quest}` : questsPath(board, quest);
}

