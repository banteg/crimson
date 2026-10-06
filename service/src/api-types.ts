// The JSON the Worker's read API answers with (src/views.ts builds it); the site (web/) imports these types.

export type Board = "survival" | "quests" | "quests-hardcore";
export type ProviderName = "github" | "discord" | "x";

export interface LinkView {
  provider: ProviderName;
  handle: string;
  avatar_url: string | null;
  // The linked account's own page.
  url: string;
}

// docs/rewrite/leaderboard-identity.md, "Names": the latest run's name (null when there is none or a moderator hid
// it), the key fingerprint, whether another account shows the same name, and the linked accounts.
export interface PlayerView {
  id: number;
  name: string | null;
  fingerprint: string;
  clash: boolean;
  links: LinkView[];
}

export interface BoardRow {
  rank: number;
  run: string;
  score: number;
  player: PlayerView;
}

export interface BoardView {
  board: Board;
  quest: string;
  title: string;
  rows: BoardRow[];
}

export interface QuestMenuView {
  board: "quests" | "quests-hardcore";
  stage: number;
  quests: { quest: string; title: string; players: number }[];
}

export interface RunView {
  id: string;
  board: Board;
  quest: string;
  score: number;
  game_version: string;
  accepted_at: number;
}

export interface ProfileView {
  player: PlayerView;
  names: string[];
  runs: RunView[];
  // Only for the signed-in player's own profile: the providers they can link and which are linked.
  account: { providers: { name: ProviderName; label: string; linked: boolean }[] } | null;
}

export interface JoinView {
  destination: PlayerView;
  destination_runs: number;
  moving: { keys: number; runs: number; names: number };
  provider: string;
}
