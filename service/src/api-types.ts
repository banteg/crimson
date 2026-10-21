// The JSON the Worker's read API answers with (src/views.ts builds it); the site (web/) imports these types.

import type { SignalName, Signals } from "./signals";
export type { SignalName, Signals };

export type Board = "survival" | "quests" | "quests-hardcore" | "survival-coop" | "quests-coop" | "quests-hardcore-coop";
// What each board ranks (docs/rewrite/ranked-rules.md): its mode, difficulty and team. A co-op pair ranks on boards
// of its own.
export const BOARDS: Record<Board, { quests: boolean; hardcore: boolean; players: 1 | 2 }> = {
  survival: { quests: false, hardcore: false, players: 1 },
  quests: { quests: true, hardcore: false, players: 1 },
  "quests-hardcore": { quests: true, hardcore: true, players: 1 },
  "survival-coop": { quests: false, hardcore: false, players: 2 },
  "quests-coop": { quests: true, hardcore: false, players: 2 },
  "quests-hardcore-coop": { quests: true, hardcore: true, players: 2 },
};
export type ProviderName = "github" | "discord" | "x";
// docs/rewrite/bots.md: every board ranks human runs and bot runs apart.
export type Category = "human" | "bot";
export const CATEGORIES: readonly Category[] = ["human", "bot"];
export type Role = "" | "mod" | "admin";

// The program that played a run, as its replay declares it: the operator's claim.
export type { CustomQuest, Pilot, SpawnEntry } from "./replay";
import type { CustomQuest, Pilot } from "./replay";
// What a custom quest's `fixed_weapon true` adds to its lists besides every weapon drop: the Weapon bonus, and the
// Alternate Weapon and Random Weapon perks.
export const FIXED_WEAPON_BONUSES = [3];
export const FIXED_WEAPON_PERKS = [9, 16];

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
  // A moderator marked the account as a bot.
  bot: boolean;
}

// A co-op run's player in one seat: their account, and the name the run carries for them (their key's fingerprint
// once a moderator hid the account's name). Both are null once the player deleted their account; the run stays their
// partner's (docs/rewrite/leaderboard-identity.md, "Co-op runs").
export interface SeatView {
  player: PlayerView | null;
  name: string | null;
}

export interface BoardRow {
  rank: number;
  run: string;
  score: number;
  elapsed_ms: number;
  most_used_weapon_id: number;
  // The account the run lists under: player one's, or their partner's once player one deleted their account.
  player: PlayerView;
  // A co-op run's players by seat, player one first; null for a one-player run.
  team: SeatView[] | null;
  pilot: Pilot | null;
}

export interface BoardView {
  board: Board;
  quest: string;
  category: Category;
  title: string;
  rows: BoardRow[];
  totals: BoardTotals;
}

// Every ranked run on a board, not only the best of each account its rows show: how many, and their kills and time.
export interface BoardTotals {
  runs: number;
  kills: number;
  elapsed_ms: number;
}

// A board row as the game's high score screen shows it: the run's id (its replay is /runs/<run>.crd), its own name
// and the fields of a high score record. A co-op run's name is its players' joined, "A & B", from `names`, by seat;
// a deleted player's is "?".
export interface GameScore {
  run: string;
  name: string;
  names: string[];
  score: number;
  elapsed_ms: number;
  experience: number;
  most_used_weapon_id: number;
  shots_fired: number;
  shots_hit: number;
  kills: number;
  accepted_at: number;
}

// `players` counts the accounts with a run on each quest's board, or the pairs on a co-op one.
export interface QuestMenuView {
  board: Exclude<Board, "survival" | "survival-coop">;
  category: Category;
  stage: number;
  quests: { quest: string; title: string; players: number }[];
}

export interface CustomQuestSummary {
  id: string;
  title: string;
  author: string | null;
  creator: PlayerView | null;
  start_weapon_id: number;
  entry_count: number;
  total_copies: number;
  no_bonuses: number[];
  no_perks: number[];
  no_weapons: number[];
  has_source: boolean;
  players: number;
  top_score: number | null;
  created_at: number;
}

export interface CustomQuestsListView {
  category: Category;
  quests: CustomQuestSummary[];
}

export interface CustomQuestDetailView {
  id: string;
  digest: string;
  title: string;
  author: string | null;
  source: string | null;
  seed: number;
  created_at: number;
  creator: PlayerView | null;
  first_run_id: string;
  definition: CustomQuest;
  board: BoardView;
}

export interface RunView {
  id: string;
  board: Board;
  quest: string;
  category: Category;
  score: number;
  // A co-op run's players.
  team: SeatView[] | null;
  game_version: string;
  accepted_at: number;
  // Why the verifier no longer accepts the run, which has left the boards; null for a ranked run.
  retired: string | null;
}

export interface ProfileView {
  player: PlayerView;
  names: string[];
  runs: RunView[];
  // Only for the signed-in player's own profile: the providers they can link and which are linked.
  account: { providers: { name: ProviderName; label: string; linked: boolean }[] } | null;
  // Only for moderators.
  moderation: AccountModeration | null;
}

export interface AccountModeration {
  role: Role;
  // Runs accepted sooner after the account's previous run than their own game time.
  overlapping_runs: number;
}

export interface JoinView {
  destination: PlayerView;
  destination_runs: number;
  // The signed-in account, which joining moves into the destination and removes.
  source: PlayerView;
  moving: { keys: number; runs: number; names: number };
  provider: string;
}

// A login link's confirmation page: who it signs in as, and who the browser is signed in as now, if someone else.
export interface LoginView {
  account: PlayerView;
  runs: number;
  current: PlayerView | null;
}

// A run's timeline (src/timeline.ts): one sample a second, [t, experience, level, health, kills, damage dealt], the
// position ten times a second, and when weapons, levels, perks, nukes and timed bonuses changed. Times are seconds of
// run time; perk and weapon ids are the game's. The seed rebuilds the run's terrain. Health, position, weapons and the
// Fire Bullets, Shield and Speed timers (PLAYER_EFFECTS) are player one's; experience, levels, perks, kills, damage,
// nukes and the other timers are the whole run's. A co-op run's timeline also has `players`, each player's own.
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
  players?: PlayerTimeline[];
}

// The timed bonuses each player has their own of; the others are the whole run's.
export const PLAYER_EFFECTS = ["Fire Bullets", "Shield", "Speed"];

// One player of a co-op run, player one first: their health at each sample's time, and their path, weapons and own
// timed bonuses up to their death, if they died (`death_s`), where the path ends.
export interface PlayerTimeline {
  health: number[];
  path: [t: number, x: number, y: number][];
  weapons: { t: number; id: number }[];
  effects: Record<string, [start: number, end: number][]>;
  death_s: number | null;
}

// Every run the boards rank, for CI to replay through a changed verifier before it ships (scripts/reverify.mjs).
export interface ReplaysView {
  runs: string[];
}

// A run's page: the run, its rank when it is its player's best on the board, the board's top run and the player's
// best when they are other runs, for comparison.
export interface RunDetailView {
  id: string;
  board: Board;
  quest: string;
  custom_slots?: [number, number, number] | null;
  category: Category;
  pilot: Pilot | null;
  title: string;
  // The name the run carries for player one, and their account (see BoardRow); a co-op run has both players in `team`.
  name: string;
  player: PlayerView;
  team: SeatView[] | null;
  score: number;
  rank: number | null;
  accepted_at: number;
  game_version: string;
  // Why the verifier no longer accepts the run, which has left the boards; null for a ranked run.
  retired: string | null;
  recorder: { client: string; version: string; platform: string };
  result: {
    outcome: string;
    elapsed_ms: number;
    kills: number;
    shots_fired: number;
    shots_hit: number;
    experience: number;
    // Player one's health, and every player's, player one first.
    health: number;
    healths: number[];
    pending_perks: number;
    most_used_weapon_id: number;
  };
  timeline: Timeline | null;
  // The top run's name is its players' joined in co-op.
  top: { id: string; name: string; score: number } | null;
  best: { id: string; score: number } | null;
  // Only for moderators.
  moderation: RunModeration | null;
}

// Why a run is in its category, and its input signals (src/signals.ts).
export interface RunModeration {
  // A moderator's choice for this run, else the pilot, the account's mark or neither.
  source: "moderator" | "pilot" | "account" | "default";
  // The moderator's choice, null when the run follows its pilot and account.
  override: Category | null;
  signals: Signals | null;
  flagged: SignalName[];
}

export interface FlaggedRun {
  id: string;
  board: Board;
  quest: string;
  score: number;
  accepted_at: number;
  player: PlayerView;
  team: SeatView[] | null;
  signals: Signals;
  flagged: SignalName[];
}

export interface ModerationAction {
  at: number;
  actor: string;
  action: string;
  target: string;
  note: string;
}

export interface FlagsView {
  runs: FlaggedRun[];
  // Runs whose signals are not measured yet.
  unmeasured: number;
}

// Aggregate gameplay statistics. Browser/day tokens never leave the ingestion table.
export interface PlayTotals {
  day: string;
  mode: string;
  unique_browsers: number;
  ready: number;
  sessions: number;
  engaged: number;
  runs: number;
  active_seconds: number;
}
// Co-op sessions' totals over the last 30 days by transport (migrations/0009_coop_analytics.sql).
export interface CoopTotals {
  transport: string;
  metric: string;
  bucket: number;
  count: number;
}
export interface PlayAnalyticsView {
  days: PlayTotals[];
  coop: CoopTotals[];
}
