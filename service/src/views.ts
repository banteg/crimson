// The read API's JSON (src/api-types.ts): the boards, the quest menu, profiles and the join confirmation.

import type { Board, BoardView, GameScore, JoinView, PlayerView, ProfileView, ProviderName, QuestMenuView, RunDetailView, RunView } from "./api-types";
import type { Env } from "./http";
import { configuredProviders } from "./oauth";
import { LOWER_IS_BETTER } from "./ranked";
import type { RunResult } from "./replay";
import { timelineFor } from "./runs";
import questTitles from "./quests.json";
import { formatScore } from "../web/src/format";
import weaponData from "../web/src/weapons.json";

export const QUEST_TITLES: Record<string, string> = questTitles;
const WEAPONS: Record<string, { name: string }> = weaponData;

// SQL over accounts `a` and runs `r`: the account's key fingerprint, and the name a run shows, which is the
// fingerprint once a moderator hid the account's name.
const FINGERPRINT = "(SELECT fingerprint FROM keys WHERE account_id = a.id ORDER BY added_at LIMIT 1)";
export const SHOWN_NAME = `CASE WHEN a.name_hidden THEN ${FINGERPRINT} ELSE r.name END`;

function linkUrl(provider: ProviderName, handle: string, subject: string): string {
  switch (provider) {
    case "github":
      return `https://github.com/${encodeURIComponent(handle)}`;
    case "x":
      return `https://x.com/${encodeURIComponent(handle)}`;
    case "discord":
      return `https://discord.com/users/${encodeURIComponent(subject)}`;
  }
}

export async function players(env: Env, ids: number[]): Promise<Map<number, PlayerView>> {
  const found = new Map<number, PlayerView>();
  if (!ids.length) return found;
  const marks = ids.map(() => "?").join(",");
  const { results: accounts } = await env.DB.prepare(
    `SELECT a.id, a.name, a.name_hidden,
       ${FINGERPRINT} AS fingerprint,
       (SELECT count(*) FROM accounts b WHERE lower(b.name) = lower(a.name) AND b.id != a.id AND b.name != '') AS clashes
     FROM accounts a WHERE a.id IN (${marks})`,
  )
    .bind(...ids)
    .all<{ id: number; name: string; name_hidden: number; fingerprint: string; clashes: number }>();
  const { results: links } = await env.DB.prepare(
    `SELECT account_id, provider, subject, handle, avatar_url FROM links WHERE account_id IN (${marks})`,
  )
    .bind(...ids)
    .all<{ account_id: number; provider: ProviderName; subject: string; handle: string; avatar_url: string | null }>();
  for (const account of accounts)
    found.set(account.id, {
      id: account.id,
      name: account.name && !account.name_hidden ? account.name : null,
      fingerprint: account.fingerprint,
      clash: account.clashes > 0,
      links: links
        .filter((link) => link.account_id === account.id)
        .map((link) => ({
          provider: link.provider,
          handle: link.handle,
          avatar_url: link.avatar_url,
          url: linkUrl(link.provider, link.handle, link.subject),
        })),
    });
  return found;
}

export function boardTitle(board: Board, quest: string): string {
  return board === "survival" ? "Survival" : `${quest} ${QUEST_TITLES[quest]}${board === "quests-hardcore" ? " · hardcore" : ""}`;
}

interface BestRun {
  id: string;
  account_id: number;
  name: string;
  score: number;
  result: string;
  accepted_at: number;
}

// Each account's best run on a board; equal scores keep the earlier accepted run ahead.
async function bestRuns(env: Env, board: Board, quest: string, limit: number): Promise<BestRun[]> {
  const order = LOWER_IS_BETTER[board] ? "ASC" : "DESC";
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.account_id, ${SHOWN_NAME} AS name, r.score, r.result, r.accepted_at FROM runs r JOIN accounts a ON a.id = r.account_id
     WHERE r.board = ? AND r.quest = ? AND r.hidden = 0 AND a.banned = 0
       AND r.id = (SELECT id FROM runs b WHERE b.account_id = r.account_id AND b.board = r.board AND b.quest = r.quest AND b.hidden = 0
                   ORDER BY b.score ${order}, b.accepted_at LIMIT 1)
     ORDER BY r.score ${order}, r.accepted_at LIMIT ?`,
  )
    .bind(board, quest, limit)
    .all<BestRun>();
  return results;
}

export async function boardView(env: Env, board: Board, quest: string, limit: number): Promise<BoardView> {
  const results = await bestRuns(env, board, quest, limit);
  const who = await players(env, results.map((row) => row.account_id));
  return {
    board,
    quest,
    title: boardTitle(board, quest),
    rows: results.map((row, i) => {
      const result = JSON.parse(row.result) as RunResult;
      return {
        rank: i + 1,
        run: row.id,
        score: row.score,
        elapsed_ms: result.elapsed_ms,
        most_used_weapon_id: result.players[0]!.most_used_weapon_id,
        player: who.get(row.account_id)!,
      };
    }),
  };
}

// The board holds each account's best run; a run that is not its player's best has no rank.
const BOARD_SCAN = 1000;

// A run's page without its timeline, which the page's preview tags and card can go without or fetch themselves.
export type RunSummary = Omit<RunDetailView, "timeline">;

export async function runDetailView(env: Env, id: string): Promise<RunDetailView | null> {
  const run = await runSummary(env, id);
  return run && { ...run, timeline: await timelineFor(env, id) };
}

export async function runSummary(env: Env, id: string): Promise<RunSummary | null> {
  const run = await env.DB.prepare(
    `SELECT r.id, r.account_id, ${SHOWN_NAME} AS name, r.board, r.quest, r.score, r.accepted_at, r.game_version, r.client,
       r.client_version, r.platform, r.result FROM runs r JOIN accounts a ON a.id = r.account_id WHERE r.id = ? AND r.hidden = 0`,
  )
    .bind(id)
    .first<{
      id: string; account_id: number; name: string; board: Board; quest: string; score: number; accepted_at: number; game_version: string;
      client: string; client_version: string; platform: string; result: string;
    }>();
  if (!run) return null;
  const board = await bestRuns(env, run.board, run.quest, BOARD_SCAN);
  const rank = board.findIndex((row) => row.id === id);
  const top = board[0] && board[0].id !== id ? board[0] : null;
  const best = board.find((row) => row.account_id === run.account_id);
  const result = JSON.parse(run.result) as RunResult;
  return {
    id,
    board: run.board,
    quest: run.quest,
    title: boardTitle(run.board, run.quest),
    name: run.name,
    player: (await players(env, [run.account_id])).get(run.account_id)!,
    score: run.score,
    rank: rank === -1 ? null : rank + 1,
    accepted_at: run.accepted_at,
    game_version: run.game_version,
    recorder: { client: run.client, version: run.client_version, platform: run.platform },
    result: {
      outcome: result.outcome,
      health: result.players[0]!.health,
      pending_perks: result.pending_perks,
      elapsed_ms: result.elapsed_ms,
      kills: result.kills,
      shots_fired: result.shots_fired,
      shots_hit: result.shots_hit,
      experience: result.players[0]!.experience,
      most_used_weapon_id: result.players[0]!.most_used_weapon_id,
    },
    top: top && { id: top.id, name: top.name, score: top.score },
    best: best && best.id !== id ? { id: best.id, score: best.score } : null,
  };
}

// What a shared run's link says under its title.
export function runDescription(run: RunSummary): string {
  const result = run.result;
  const seconds = Math.floor(result.elapsed_ms / 1000);
  const what =
    run.board === "survival"
      ? `survived ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")} for ${formatScore(run.board, run.score)}`
      : `finished ${run.quest} ${QUEST_TITLES[run.quest]}${run.board === "quests-hardcore" ? " on hardcore" : ""} in ${formatScore(run.board, run.score)}`;
  const weapon = WEAPONS[result.most_used_weapon_id];
  const numbers = [
    `${result.kills.toLocaleString("en-US")} kills`,
    ...(result.shots_fired ? [`${Math.round((result.shots_hit / result.shots_fired) * 100)}% accuracy`] : []),
    ...(weapon ? [`mostly the ${weapon.name}`] : []),
  ];
  return `${run.name} ${what}${run.rank ? `, #${run.rank} on the board` : ""}. ${numbers.join(", ")}. Verified by replay.`;
}

export async function gameScores(env: Env, board: Board, quest: string, limit: number): Promise<GameScore[]> {
  return (await bestRuns(env, board, quest, limit)).map((run) => {
    const result = JSON.parse(run.result) as RunResult;
    const player = result.players[0]!;
    return {
      name: run.name,
      score: run.score,
      elapsed_ms: result.elapsed_ms,
      experience: player.experience,
      most_used_weapon_id: player.most_used_weapon_id,
      shots_fired: result.shots_fired,
      shots_hit: result.shots_hit,
      kills: result.kills,
      accepted_at: run.accepted_at,
    };
  });
}

export async function questMenuView(env: Env, board: "quests" | "quests-hardcore", stage: number): Promise<QuestMenuView> {
  const { results } = await env.DB.prepare(
    "SELECT quest, count(DISTINCT account_id) AS players FROM runs WHERE board = ? AND quest LIKE ? AND hidden = 0 GROUP BY quest",
  )
    .bind(board, `${stage}.%`)
    .all<{ quest: string; players: number }>();
  const counts = new Map(results.map((row) => [row.quest, row.players]));
  return {
    board,
    stage,
    quests: Array.from({ length: 10 }, (_, i) => {
      const quest = `${stage}.${i + 1}`;
      return { quest, title: QUEST_TITLES[quest]!, players: counts.get(quest) ?? 0 };
    }),
  };
}

export async function profileView(env: Env, accountId: number, viewer: number | null): Promise<ProfileView | null> {
  const player = (await players(env, [accountId])).get(accountId);
  if (!player) return null;
  // A hidden name hides the account's earlier names too.
  const { results: names } = await env.DB.prepare(
    "SELECT name FROM names WHERE account_id = ? AND NOT (SELECT name_hidden FROM accounts WHERE id = ?) ORDER BY last_at DESC",
  )
    .bind(accountId, accountId)
    .all<{ name: string }>();
  const { results: runs } = await env.DB.prepare(
    "SELECT id, board, quest, score, game_version, accepted_at FROM runs WHERE account_id = ? AND hidden = 0 ORDER BY accepted_at DESC LIMIT 100",
  )
    .bind(accountId)
    .all<RunView>();
  const linked = new Set(player.links.map((link) => link.provider));
  return {
    player,
    names: names.map((row) => row.name),
    runs,
    account:
      viewer === accountId
        ? { providers: configuredProviders(env).map((p) => ({ name: p.name, label: p.label, linked: linked.has(p.name) })) }
        : null,
  };
}

export async function joinView(env: Env, from: number, into: number, provider: string): Promise<JoinView> {
  const count = async (sql: string, id: number) => (await env.DB.prepare(sql).bind(id).first<{ n: number }>())!.n;
  const [keys, runs, names, destinationRuns] = await Promise.all([
    count("SELECT count(*) AS n FROM keys WHERE account_id = ?", from),
    count("SELECT count(*) AS n FROM runs WHERE account_id = ?", from),
    count("SELECT count(*) AS n FROM names WHERE account_id = ?", from),
    count("SELECT count(*) AS n FROM runs WHERE account_id = ?", into),
  ]);
  return {
    destination: (await players(env, [into])).get(into)!,
    destination_runs: destinationRuns,
    moving: { keys, runs, names },
    provider,
  };
}
