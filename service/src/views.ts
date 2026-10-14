// The read API's JSON (src/api-types.ts): the boards, the quest menu, profiles and the join confirmation.

import type {
  Board,
  BoardTotals,
  BoardView,
  Category,
  CustomQuest,
  CustomQuestDetailView,
  CustomQuestsListView,
  GameScore,
  JoinView,
  LoginView,
  Pilot,
  PlayerView,
  ProfileView,
  ProviderName,
  QuestMenuView,
  RunDetailView,
  RunView,
} from "./api-types";
import type { Env } from "./http";
import { configuredProviders } from "./oauth";
import { LOWER_IS_BETTER } from "./ranked";
import type { RunResult } from "./replay";
import { accountModeration, runModeration } from "./moderation";
import { timelineFor } from "./runs";
import { encodePortableQuest } from "./transport";
import questTitles from "./quests.json";
import { formatScore } from "../web/src/format";
import { playerLabel, shownName } from "../web/src/names";
import weaponData from "../web/src/weapons.json";

export const QUEST_TITLES: Record<string, string> = questTitles;
export const CUSTOM_QUEST_ID = /^[0-9a-f]{12}$/;
const WEAPONS: Record<string, { name: string }> = weaponData;

// SQL over accounts `a` and runs `r`: the account's key fingerprint, and the name a run shows, which is the
// fingerprint once a moderator hid the account's name.
const FINGERPRINT = "(SELECT fingerprint FROM keys WHERE account_id = a.id ORDER BY added_at LIMIT 1)";
export const SHOWN_NAME = `CASE WHEN a.name_hidden THEN ${FINGERPRINT} ELSE r.name END`;
// SQL over accounts `a` and the runs `run` of that account: the run's category (docs/rewrite/bots.md). A moderator's
// choice for the run wins, else a declared pilot or the account's bot mark make it a bot run.
export const runCategory = (run: string) => `coalesce(${run}.category, CASE WHEN ${run}.pilot != '' OR a.bot THEN 'bot' ELSE 'human' END)`;

export const parsePilot = (pilot: string): Pilot | null => (pilot ? (JSON.parse(pilot) as Pilot) : null);

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
    `SELECT a.id, a.name, a.name_hidden, a.bot,
       ${FINGERPRINT} AS fingerprint,
       (SELECT count(*) FROM accounts b WHERE b.id != a.id AND (lower(b.name) = lower(a.name) AND b.name != ''
          OR EXISTS (SELECT 1 FROM links l WHERE l.account_id = b.id AND lower(l.handle) = lower(a.name)))) AS clashes
     FROM accounts a WHERE a.id IN (${marks})`,
  )
    .bind(...ids)
    .all<{ id: number; name: string; name_hidden: number; bot: number; fingerprint: string; clashes: number }>();
  const { results: links } = await env.DB.prepare(
    `SELECT account_id, provider, subject, handle, avatar_url FROM links WHERE account_id IN (${marks})`,
  )
    .bind(...ids)
    .all<{ account_id: number; provider: ProviderName; subject: string; handle: string; avatar_url: string | null }>();
  for (const account of accounts) {
    const own = links.filter((link) => link.account_id === account.id);
    found.set(account.id, {
      id: account.id,
      name: account.name_hidden ? null : shownName(account.name, own),
      fingerprint: account.fingerprint,
      clash: account.clashes > 0,
      links: own.map((link) => ({
        provider: link.provider,
        handle: link.handle,
        avatar_url: link.avatar_url,
        url: linkUrl(link.provider, link.handle, link.subject),
      })),
      bot: account.bot !== 0,
    });
  }
  return found;
}

export function boardTitle(board: Board, quest: string, customTitle?: string): string {
  if (board === "survival") return "Survival";
  if (customTitle) return customTitle;
  const stock = QUEST_TITLES[quest];
  return stock ? `${quest} ${stock}${board === "quests-hardcore" ? " · hardcore" : ""}` : `Quest ${quest}`;
}

interface BestRun {
  id: string;
  account_id: number;
  name: string;
  score: number;
  result: string;
  pilot: string;
  accepted_at: number;
}

// A run the boards rank: shown, a verified one (not retired: migrations/0005_retired.sql) and not a banned account's.
const RANKED_RUN = "r.hidden = 0 AND r.retired IS NULL AND a.banned = 0";
// The ranked runs `r` of a board in a category, with their accounts `a`; binds the board, quest and category.
const BOARD_RUNS = `FROM runs r JOIN accounts a ON a.id = r.account_id
  WHERE r.board = ? AND r.quest = ? AND ${RANKED_RUN} AND ${runCategory("r")} = ?`;

// Each account's best run on a board in a category; equal scores keep the earlier accepted run ahead.
async function bestRuns(env: Env, board: Board, quest: string, category: Category, limit: number): Promise<BestRun[]> {
  const order = LOWER_IS_BETTER[board] ? "ASC" : "DESC";
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.account_id, ${SHOWN_NAME} AS name, r.score, r.result, r.pilot, r.accepted_at ${BOARD_RUNS}
       AND r.id =(SELECT id FROM runs b WHERE b.account_id = r.account_id AND b.board = r.board AND b.quest = r.quest AND b.hidden = 0
                     AND b.retired IS NULL AND ${runCategory("b")} = ?
                   ORDER BY b.score ${order}, b.accepted_at LIMIT 1)
     ORDER BY r.score ${order}, r.accepted_at LIMIT ?`,
  )
    .bind(board, quest, category, category, limit)
    .all<BestRun>();
  return results;
}

async function boardTotals(env: Env, board: Board, quest: string, category: Category): Promise<BoardTotals> {
  const totals = await env.DB.prepare(
    `SELECT count(*) AS runs, total(json_extract(r.result, '$.kills')) AS kills, total(json_extract(r.result, '$.elapsed_ms')) AS elapsed_ms
     ${BOARD_RUNS}`,
  )
    .bind(board, quest, category)
    .first<BoardTotals>();
  return totals!;
}

export async function boardView(env: Env, board: Board, quest: string, category: Category, limit: number, customTitle?: string): Promise<BoardView> {
  const [results, totals] = await Promise.all([bestRuns(env, board, quest, category, limit), boardTotals(env, board, quest, category)]);
  const who = await players(env, results.map((row) => row.account_id));
  return {
    board,
    quest,
    category,
    title: boardTitle(board, quest, customTitle),
    totals,
    rows: results.map((row, i) => {
      const result = JSON.parse(row.result) as RunResult;
      return {
        rank: i + 1,
        run: row.id,
        score: row.score,
        elapsed_ms: result.elapsed_ms,
        most_used_weapon_id: result.players[0]!.most_used_weapon_id,
        player: who.get(row.account_id)!,
        pilot: parsePilot(row.pilot),
      };
    }),
  };
}

// The board holds each account's best run; a run that is not its player's best has no rank.
const BOARD_SCAN = 1000;

// A run's page without its timeline and moderation, which the page's preview tags and card can go without or fetch
// themselves.
export type RunSummary = Omit<RunDetailView, "timeline" | "moderation">;

export async function runDetailView(env: Env, id: string, moderator: boolean): Promise<RunDetailView | null> {
  const run = await runSummary(env, id);
  return run && { ...run, timeline: await timelineFor(env, id), moderation: moderator ? await runModeration(env, id) : null };
}

// A run anyone may see by its id: not hidden, and not a banned account's, as the boards filter; a retired run keeps
// its page and replay.
const VISIBLE_RUN = "r.hidden = 0 AND a.banned = 0";

export async function visibleRun(env: Env, id: string): Promise<boolean> {
  return !!(await env.DB.prepare(`SELECT 1 FROM runs r JOIN accounts a ON a.id = r.account_id WHERE r.id = ? AND ${VISIBLE_RUN}`).bind(id).first());
}

export async function runSummary(env: Env, id: string): Promise<RunSummary | null> {
  const run = await env.DB.prepare(
    `SELECT r.id, r.account_id, ${SHOWN_NAME} AS name, r.board, r.quest, ${runCategory("r")} AS category, r.pilot, r.score, r.accepted_at,
       r.game_version, r.retired, r.client, r.client_version, r.platform, r.result FROM runs r JOIN accounts a ON a.id = r.account_id
     WHERE r.id = ? AND ${VISIBLE_RUN}`,
  )
    .bind(id)
    .first<{
      id: string; account_id: number; name: string; board: Board; quest: string; category: Category; pilot: string; score: number;
      accepted_at: number; game_version: string; retired: string | null; client: string; client_version: string; platform: string;
      result: string;
    }>();
  if (!run) return null;
  const [board, customRow] = await Promise.all([
    bestRuns(env, run.board, run.quest, run.category, BOARD_SCAN),
    CUSTOM_QUEST_ID.test(run.quest)
      ? env.DB.prepare("SELECT title, definition FROM custom_quests WHERE id = ?").bind(run.quest).first<{ title: string; definition: string }>()
      : Promise.resolve(null),
  ]);
  const customDef = customRow ? (JSON.parse(customRow.definition) as CustomQuest) : null;
  const rank = board.findIndex((row) => row.id === id);
  const top = board[0] && board[0].id !== id ? board[0] : null;
  const best = board.find((row) => row.account_id === run.account_id);
  const result = JSON.parse(run.result) as RunResult;
  const who = await players(env, top ? [run.account_id, top.account_id] : [run.account_id]);
  return {
    id,
    board: run.board,
    quest: run.quest,
    custom_slots: customDef?.terrain_slots ?? null,
    category: run.category,
    pilot: parsePilot(run.pilot),
    title: boardTitle(run.board, run.quest, customRow?.title),
    name: run.name,
    player: who.get(run.account_id)!,
    score: run.score,
    rank: rank === -1 ? null : rank + 1,
    accepted_at: run.accepted_at,
    game_version: run.game_version,
    retired: run.retired,
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
    top: top && { id: top.id, name: playerLabel(who.get(top.account_id)!), score: top.score },
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
      : `finished ${run.title}${run.board === "quests-hardcore" ? " on hardcore" : ""} in ${formatScore(run.board, run.score)}`;
  const weapon = WEAPONS[result.most_used_weapon_id];
  const numbers = [
    `${result.kills.toLocaleString("en-US")} kills`,
    ...(result.shots_fired ? [`${Math.round((result.shots_hit / result.shots_fired) * 100)}% accuracy`] : []),
    ...(weapon ? [`mostly the ${weapon.name}`] : []),
  ];
  return `${playerLabel(run.player)} ${what}${run.rank ? `, #${run.rank} on the board` : ""}. ${numbers.join(", ")}. Verified by replay.`;
}

export async function gameScores(env: Env, board: Board, quest: string, category: Category, limit: number): Promise<GameScore[]> {
  return (await bestRuns(env, board, quest, category, limit)).map((run) => {
    const result = JSON.parse(run.result) as RunResult;
    const player = result.players[0]!;
    return {
      run: run.id,
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

export async function questMenuView(env: Env, board: "quests" | "quests-hardcore", stage: number, category: Category): Promise<QuestMenuView> {
  const { results } = await env.DB.prepare(
    `SELECT r.quest, count(DISTINCT r.account_id) AS players FROM runs r JOIN accounts a ON a.id = r.account_id
     WHERE r.board = ? AND r.quest LIKE ? AND ${RANKED_RUN} AND ${runCategory("r")} = ? GROUP BY r.quest`,
  )
    .bind(board, `${stage}.%`, category)
    .all<{ quest: string; players: number }>();
  const counts = new Map(results.map((row) => [row.quest, row.players]));
  return {
    board,
    category,
    stage,
    quests: Array.from({ length: 10 }, (_, i) => {
      const quest = `${stage}.${i + 1}`;
      return { quest, title: QUEST_TITLES[quest]!, players: counts.get(quest) ?? 0 };
    }),
  };
}

export async function customQuestDetailView(env: Env, id: string, category: Category): Promise<CustomQuestDetailView | null> {
  const row = await env.DB.prepare(
    "SELECT id, digest, account_id, first_run_id, title, author, source, seed, definition, created_at FROM custom_quests WHERE id = ?",
  )
    .bind(id)
    .first<{
      id: string;
      digest: string;
      account_id: number | null;
      first_run_id: string;
      title: string;
      author: string | null;
      source: string | null;
      seed: number;
      definition: string;
      created_at: number;
    }>();
  if (!row) return null;
  const definition = JSON.parse(row.definition) as CustomQuest;
  const [who, board] = await Promise.all([
    row.account_id !== null ? players(env, [row.account_id]) : Promise.resolve(new Map()),
    boardView(env, "quests", id, category, 100, row.title),
  ]);
  return {
    id: row.id,
    digest: row.digest,
    title: row.title,
    author: row.author,
    source: row.source,
    seed: row.seed,
    created_at: row.created_at,
    creator: row.account_id !== null ? (who.get(row.account_id) ?? null) : null,
    first_run_id: row.first_run_id,
    definition,
    board,
  };
}

export async function customQuestPortableBytes(env: Env, id: string): Promise<Uint8Array | null> {
  const row = await env.DB.prepare("SELECT definition FROM custom_quests WHERE id = ?")
    .bind(id)
    .first<{ definition: string }>();
  if (!row) return null;
  return encodePortableQuest(JSON.parse(row.definition) as CustomQuest);
}

export async function customQuestsListView(env: Env, category: Category, limit = 100): Promise<CustomQuestsListView> {
  const { results } = await env.DB.prepare(
    `SELECT q.id, q.account_id, q.title, q.author, q.source IS NOT NULL AS has_source, q.definition, q.created_at,
       (SELECT count(DISTINCT r.account_id) FROM runs r JOIN accounts a ON a.id = r.account_id
        WHERE r.board = 'quests' AND r.quest = q.id AND ${RANKED_RUN} AND ${runCategory("r")} = ?) AS players,
       (SELECT min(r.score) FROM runs r JOIN accounts a ON a.id = r.account_id
        WHERE r.board = 'quests' AND r.quest = q.id AND ${RANKED_RUN} AND ${runCategory("r")} = ?) AS top_score
     FROM custom_quests q LEFT JOIN accounts ca ON ca.id = q.account_id
     WHERE ca.banned IS NULL OR ca.banned = 0 ORDER BY q.created_at DESC LIMIT ?`,
  )
    .bind(category, category, limit)
    .all<{
      id: string;
      account_id: number | null;
      title: string;
      author: string | null;
      has_source: number;
      definition: string;
      created_at: number;
      players: number;
      top_score: number | null;
    }>();
  const who = await players(env, [...new Set(results.map((r) => r.account_id).filter((id): id is number => id !== null))]);
  return {
    category,
    quests: results.map((row) => {
      const def = JSON.parse(row.definition) as CustomQuest;
      return {
        id: row.id,
        title: row.title,
        author: row.author,
        creator: row.account_id !== null ? (who.get(row.account_id) ?? null) : null,
        start_weapon_id: def.start_weapon_id,
        entry_count: def.entries.length,
        total_copies: def.entries.reduce((sum, e) => sum + e.count, 0),
        no_bonuses: def.no_bonuses,
        no_perks: def.no_perks,
        no_weapons: def.no_weapons,
        has_source: Boolean(row.has_source),
        players: row.players,
        top_score: row.top_score,
        created_at: row.created_at,
      };
    }),
  };
}

export async function profileView(env: Env, accountId: number, viewer: number | null, moderator: boolean): Promise<ProfileView | null> {
  const player = (await players(env, [accountId])).get(accountId);
  if (!player) return null;
  // A hidden name hides the account's earlier names too.
  const { results: names } = await env.DB.prepare(
    "SELECT name FROM names WHERE account_id = ? AND NOT (SELECT name_hidden FROM accounts WHERE id = ?) ORDER BY last_at DESC",
  )
    .bind(accountId, accountId)
    .all<{ name: string }>();
  const { results: runs } = await env.DB.prepare(
    `SELECT r.id, r.board, r.quest, ${runCategory("r")} AS category, r.score, r.game_version, r.accepted_at, r.retired FROM runs r
     JOIN accounts a ON a.id = r.account_id WHERE r.account_id = ? AND r.hidden = 0 ORDER BY r.accepted_at DESC LIMIT 100`,
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
    moderation: moderator ? await accountModeration(env, accountId) : null,
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
  const found = await players(env, [from, into]);
  return {
    destination: found.get(into)!,
    destination_runs: destinationRuns,
    source: found.get(from)!,
    moving: { keys, runs, names },
    provider,
  };
}

export async function loginView(env: Env, account: number, current: number | null): Promise<LoginView> {
  const other = current !== null && current !== account ? current : null;
  const [found, runs] = await Promise.all([
    players(env, other === null ? [account] : [account, other]),
    env.DB.prepare("SELECT count(*) AS n FROM runs WHERE account_id = ?").bind(account).first<{ n: number }>(),
  ]);
  return { account: found.get(account)!, runs: runs!.n, current: other === null ? null : found.get(other)! };
}
