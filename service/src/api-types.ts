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

// docs/rewrite/leaderboard-identity.md, "Names": the name the account shows (a linked handle, or the latest run's
// name; null when there is none, it is the default or a moderator hid it), the key fingerprint, whether another account
// shows the same name, and the linked accounts.
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
  elapsed_ms: number;
  most_used_weapon_id: number;
  player: PlayerView;
}

export interface BoardView {
  board: Board;
  quest: string;
  title: string;
  rows: BoardRow[];
}

// A board row as the game's high score screen shows it: the run's id (its replay is /runs/<run>.crd), its own name
// and the fields of a high score record.
export interface GameScore {
  run: string;
  name: string;
  score: number;
  elapsed_ms: number;
  experience: number;
  most_used_weapon_id: number;
  shots_fired: number;
  shots_hit: number;
  kills: number;
  accepted_at: number;
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

// A run's timeline (src/timeline.ts): one sample a second, [t, experience, level, health, kills, damage dealt], the
// position ten times a second, and when weapons, levels, perks, nukes and timed bonuses changed. Times are seconds of
// run time; perk and weapon ids are the game's. The seed rebuilds the run's terrain.
export interface Timeline {
  seed: number;
  duration_s: number;
  samples: [t: number, xp: number, level: number, health: number, kills: number, damage: number][];
  path: [t: number, x: number, y: number][];
  weapons: { t: number; id: number }[];
  perks: { t: number; id: number }[];
  levels: { t: number; level: number }[];
  nukes: number[];
  effects: Record<string, [start: number, end: number][]>;
}

// A run's page: the run, its rank when it is its player's best on the board, the board's top run and the player's
// best when they are other runs, for comparison.
export interface RunDetailView {
  id: string;
  board: Board;
  quest: string;
  title: string;
  name: string;
  player: PlayerView;
  score: number;
  rank: number | null;
  accepted_at: number;
  game_version: string;
  recorder: { client: string; version: string; platform: string };
  result: {
    outcome: string;
    elapsed_ms: number;
    kills: number;
    shots_fired: number;
    shots_hit: number;
    experience: number;
    health: number;
    pending_perks: number;
    most_used_weapon_id: number;
  };
  timeline: Timeline | null;
  top: { id: string; name: string; score: number } | null;
  best: { id: string; score: number } | null;
}
