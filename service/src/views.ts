// The read API's JSON (src/api-types.ts): the boards, the quest menu, profiles and the join confirmation.

import type { Board, BoardView, GameScore, JoinView, PlayerView, ProfileView, ProviderName, QuestMenuView, RunView } from "./api-types";
import type { Env } from "./http";
import { configuredProviders } from "./oauth";
import { LOWER_IS_BETTER } from "./ranked";
import type { RunResult } from "./replay";
import questTitles from "./quests.json";

export const QUEST_TITLES: Record<string, string> = questTitles;

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
       (SELECT fingerprint FROM keys WHERE account_id = a.id ORDER BY added_at LIMIT 1) AS fingerprint,
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
    `SELECT r.id, r.account_id, r.name, r.score, r.result, r.accepted_at FROM runs r JOIN accounts a ON a.id = r.account_id
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
  const { results: names } = await env.DB.prepare("SELECT name FROM names WHERE account_id = ? ORDER BY last_at DESC")
    .bind(accountId)
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
