// The site's board and quest pages. Each one's data is at /api plus its path: /survival, /quests/2.3 and
// /quests/hardcore/2.3, /custom and /custom/<id>; a co-op pair's boards add /coop: /survival/coop,
// /quests/coop/2.3 and /quests/hardcore/coop/2.3. The Worker and the site both route by these. Each page shows 1.9.93's
// boards; ?build=1.9.8 shows 1.9.8's (withBuild).
import { type Board, BOARDS, type Build, BUILDS, DEFAULT_BUILD } from "./api-types";

export const QUEST = /^[1-5]\.(?:[1-9]|10)$/;
export const CUSTOM_QUEST_ID = /^[0-9a-f]{12}$/;

export type SurvivalBoard = "survival" | "survival-coop";
export type QuestBoard = Exclude<Board, SurvivalBoard>;

// A Survival board's page.
export function survivalPage(path: string): SurvivalBoard | null {
  return path === "/survival" ? "survival" : path === "/survival/coop" ? "survival-coop" : null;
}

// A stage's quest menu, or with a quest, its board too. /quests, /quests/hardcore and their /coop pages open stage I.
export interface QuestPage {
  board: QuestBoard;
  stage: number;
  quest: string | null;
}

export function questPage(path: string): QuestPage | null {
  const match = /^\/quests(\/hardcore)?(\/coop)?(?:\/([^/]+))?$/.exec(path);
  if (!match) return null;
  const board: QuestBoard = `${match[1] ? "quests-hardcore" : "quests"}${match[2] ? "-coop" : ""}`;
  const at = match[3] ?? "1";
  if (/^[1-5]$/.test(at)) return { board, stage: Number(at), quest: null };
  if (QUEST.test(at)) return { board, stage: Number(at.split(".")[0]), quest: at };
  return null;
}

// The build whose boards a page shows: 1.9.93's, or with ?build=1.9.8 1.9.8's.
export function pageBuild(url: URL): Build {
  const build = url.searchParams.get("build");
  return build !== null && Object.hasOwn(BUILDS, build) ? (build as Build) : DEFAULT_BUILD;
}

// A page as it shows `build`'s boards.
export const withBuild = (path: string, build: Build): string => (build === DEFAULT_BUILD ? path : `${path}?build=${build}`);

// A board's title with its build when that is not 1.9.93: a 1.9.8 run's card, link preview and tab name its boards.
export const buildTitle = (title: string, build: Build): string => (build === DEFAULT_BUILD ? title : `${title} · ${build}`);

// The game playing the custom quest `id` under `build`'s rules, for that build's boards.
export const questPlayPath = (id: string, build: Build): string => `/play/?quest=${id}${build === DEFAULT_BUILD ? "" : `&build=${build}`}`;

// A stage's menu (a number) or a stock quest's board (a quest like "2.3").
export function questsPath(board: QuestBoard, at: number | string, build: Build = DEFAULT_BUILD): string {
  return withBuild(`/quests${BOARDS[board].hardcore ? "/hardcore" : ""}${BOARDS[board].players > 1 ? "/coop" : ""}/${at}`, build);
}

// A board's page; a custom quest's board is its quest's page.
export function boardPath(board: Board, quest: string, build: Build = DEFAULT_BUILD): string {
  if (!BOARDS[board].quests) return withBuild(BOARDS[board].players > 1 ? "/survival/coop" : "/survival", build);
  return CUSTOM_QUEST_ID.test(quest) ? withBuild(`/custom/${quest}`, build) : questsPath(board as QuestBoard, quest, build);
}

// The board for a mode, difficulty and team, as `rankedBoard` names it.
export function boardFor(quests: boolean, hardcore: boolean, coop: boolean): Board {
  return (Object.keys(BOARDS) as Board[]).find((board) => {
    const info = BOARDS[board];
    return info.quests === quests && info.hardcore === (quests && hardcore) && info.players === (coop ? 2 : 1);
  })!;
}
