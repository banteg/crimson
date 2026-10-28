// The read API's JSON (src/api-types.ts): the boards, the quest menu, profiles and the join confirmation.

import {
  type Board,
  BOARDS,
  type BoardTotals,
  type BoardView,
  type Category,
  type CustomQuest,
  type CustomQuestDetailView,
  type CustomQuestsListView,
  type GameCustomQuests,
  type GameScore,
  type JoinView,
  type LoginView,
  type Pilot,
  type PlayerView,
  type ProfileView,
  type ProviderName,
  type QuestMenuView,
  type ReplaysView,
  type RunDetailView,
  type RunView,
  type SeatView,
} from "./api-types";
import type { Env } from "./http";
import { configuredProviders } from "./oauth";
import { LOWER_IS_BETTER } from "./ranked";
import type { RunResult } from "./replay";
import { accountModeration, runModeration } from "./moderation";
import { CUSTOM_QUEST_ID } from "./paths";
import { timelineFor } from "./runs";
import { encodePortableQuest } from "./transport";
import questTitles from "./quests.json";
import { formatScore } from "../web/src/format";
import { runLabel, shownName } from "../web/src/names";
import weaponData from "../web/src/weapons.json";

export const QUEST_TITLES: Record<string, string> = questTitles;
const WEAPONS: Record<string, { name: string }> = weaponData;

// SQL over accounts `account`: the account's key fingerprint.
const fingerprint = (account: string) => `(SELECT fingerprint FROM keys WHERE account_id = ${account}.id ORDER BY added_at LIMIT 1)`;
const FINGERPRINT = fingerprint("a");
// SQL over accounts `a` and runs `r`: the name a run shows, which is the fingerprint once a moderator hid the
// account's name.
export const SHOWN_NAME = `CASE WHEN a.name_hidden THEN ${FINGERPRINT} ELSE r.name END`;
// SQL over runs `run`: whether one of a co-op run's seated accounts `pa` meets `condition` (migrations/0008_coop.sql).
const anySeat = (run: string, condition: string) =>
  `EXISTS (SELECT 1 FROM run_players p JOIN accounts pa ON pa.id = p.account_id WHERE p.run_id = ${run}.id AND ${condition})`;
// SQL over accounts `a` and the runs `run` listed under that account: the run's category (docs/rewrite/bots.md). A
// moderator's choice for the run wins, else a declared pilot or a bot mark on its account, or on either co-op
// player's, make it a bot run.
export const runCategory = (run: string) =>
  `coalesce(${run}.category, CASE WHEN ${run}.pilot != '' OR a.bot OR ${anySeat(run, "pa.bot")} THEN 'bot' ELSE 'human' END)`;
// SQL over runs `run`: whether the account bound as ?1 played it, alone or in either co-op seat.
export const accountRun = (run: string) => `(${run}.account_id = ?1 OR ${run}.id IN (SELECT run_id FROM run_players WHERE account_id = ?1))`;
// SQL over runs `run`: who a board keeps one best run for, the account for one player and for a co-op pair the
// unordered pair of accounts. A player who deleted their account keeps it as a bare row in their seat
// (migrations/0008_coop.sql), so their partner's runs with them and with someone else stay apart.
const team = (run: string) =>
  `(SELECT CASE WHEN count(*) THEN min(p.account_id) || ',' || max(p.account_id) ELSE ${run}.account_id END
     FROM run_players p WHERE p.run_id = ${run}.id)`;

export const parsePilot = (pilot: string): Pilot | null => (pilot ? (JSON.parse(pilot) as Pilot) : null);

function linkUrl(provider: ProviderName, handle: string, subject: string): string {
  switch (provider) {
    case "github":
      return `https://github.com/${encodeURIComponent(handle)}`;
    case "x":
      return `https://x.com/${encodeURIComponent(handle)}`;
    case "discord":
      return `https://discord.com/users/${encodeURIComponent(subject)}`;
    case "twitch":
      return `https://www.twitch.tv/${encodeURIComponent(handle)}`;
  }
}

// The accounts' public views; a deleted account has none. The ids go in as one JSON array, since a co-op board's
// players outnumber the parameters D1 binds to a statement.
export async function players(env: Env, ids: number[]): Promise<Map<number, PlayerView>> {
  const found = new Map<number, PlayerView>();
  if (!ids.length) return found;
  const list = JSON.stringify([...new Set(ids)]);
  const { results: accounts } = await env.DB.prepare(
    `SELECT a.id, a.name, a.name_hidden, a.bot,
       ${FINGERPRINT} AS fingerprint,
       (SELECT count(*) FROM accounts b WHERE b.id != a.id AND (lower(b.name) = lower(a.name) AND b.name != ''
          OR EXISTS (SELECT 1 FROM links l WHERE l.account_id = b.id AND lower(l.handle) = lower(a.name)))) AS clashes
     FROM accounts a WHERE a.id IN (SELECT value FROM json_each(?)) AND a.deleted_at IS NULL`,
  )
    .bind(list)
    .all<{ id: number; name: string; name_hidden: number; bot: number; fingerprint: string; clashes: number }>();
  const { results: links } = await env.DB.prepare(
    `SELECT account_id, provider, subject, handle, avatar_url FROM links WHERE account_id IN (SELECT value FROM json_each(?))`,
  )
    .bind(list)
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
  const { quests, hardcore, players } = BOARDS[board];
  const coop = players > 1 ? " · co-op" : "";
  if (!quests) return `Survival${coop}`;
  if (customTitle) return customTitle;
  const stock = QUEST_TITLES[quest];
  return stock ? `${quest}: ${stock}${hardcore ? " · hardcore" : ""}${coop}` : `Quest ${quest}`;
}

// Each co-op run's seats, player one first; one-player runs have none. A deleted player's seat shows nobody.
export async function seats(env: Env, runIds: string[]): Promise<Map<string, SeatView[]>> {
  const found = new Map<string, SeatView[]>();
  if (!runIds.length) return found;
  const { results } = await env.DB.prepare(
    `SELECT p.run_id, p.account_id, CASE WHEN pa.name_hidden THEN ${fingerprint("pa")} ELSE p.name END AS name
     FROM run_players p JOIN accounts pa ON pa.id = p.account_id
     WHERE p.run_id IN (SELECT value FROM json_each(?)) ORDER BY p.run_id, p.seat`,
  )
    .bind(JSON.stringify(runIds))
    .all<{ run_id: string; account_id: number; name: string }>();
  const who = await players(env, results.map((row) => row.account_id));
  for (const row of results) {
    const player = who.get(row.account_id);
    const seat = player ? { player, name: row.name } : { player: null, name: null };
    found.set(row.run_id, [...(found.get(row.run_id) ?? []), seat]);
  }
  return found;
}

interface BestRun {
  rules: number;
  id: string;
  account_id: number;
  // Whom the board keeps this best run for (`team`).
  team: number | string;
  name: string;
  score: number;
  result: string;
  pilot: string;
  accepted_at: number;
}

// SQL over runs `r` and their accounts `a`: not a banned account's run, nor one a banned co-op player (a deleted one
// too) played. The boards, run pages and moderators' flags all keep to it.
export const NOT_BANNED = `a.banned = 0 AND NOT ${anySeat("r", "pa.banned")}`;
// A run the boards rank: shown, a verified one (not retired: migrations/0005_retired.sql) and not banned.
const RANKED_RUN = `r.hidden = 0 AND r.retired IS NULL AND ${NOT_BANNED}`;
// Every ranked run's id; each one's replay downloads from /runs/<id>.crd.
export async function replaysView(env: Env): Promise<ReplaysView> {
  const { results } = await env.DB.prepare(`SELECT r.id FROM runs r JOIN accounts a ON a.id = r.account_id WHERE ${RANKED_RUN} ORDER BY r.id`).all<{ id: string }>();
  return { runs: results.map(({ id }) => id) };
}

// The ranked runs `r` of a board in a category, with their accounts `a`; binds the board, quest and category.
const BOARD_RUNS = `FROM runs r JOIN accounts a ON a.id = r.account_id
  WHERE r.board = ? AND r.quest = ? AND ${RANKED_RUN} AND ${runCategory("r")} = ?`;

// Each account's best run on a board in a category, or each pair's on a co-op board; equal scores keep the earlier
// accepted run ahead.
async function bestRuns(env: Env, board: Board, quest: string, category: Category, limit: number, rules: number | null = null): Promise<BestRun[]> {
  const order = LOWER_IS_BETTER[board] ? "ASC" : "DESC";
  const coop = BOARDS[board].players > 1;
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.account_id, ${coop ? team("r") : "r.account_id"} AS team, ${SHOWN_NAME} AS name, r.score, r.result, r.pilot, r.accepted_at, r.rules
     ${BOARD_RUNS} AND (? IS NULL OR r.rules = ?)
       AND r.id =(SELECT id FROM runs b WHERE ${coop ? `${team("b")} = ${team("r")}` : "b.account_id = r.account_id"}
                     AND b.board = r.board AND b.quest = r.quest AND b.hidden = 0
                     AND b.retired IS NULL AND ${runCategory("b")} = ? AND (? IS NULL OR b.rules = ?)
                   ORDER BY b.score ${order}, b.accepted_at LIMIT 1)
     ORDER BY r.score ${order}, r.accepted_at LIMIT ?`,
  )
    .bind(board, quest, category, rules, rules, category, rules, rules, limit)
    .all<BestRun>();
  return results;
}

async function boardTotals(env: Env, board: Board, quest: string, category: Category, rules: number | null = null): Promise<BoardTotals> {
  const totals = await env.DB.prepare(
    `SELECT count(*) AS runs, total(json_extract(r.result, '$.kills')) AS kills, total(json_extract(r.result, '$.elapsed_ms')) AS elapsed_ms
     ${BOARD_RUNS} AND (? IS NULL OR r.rules = ?)`,
  )
    .bind(board, quest, category, rules, rules)
    .first<BoardTotals>();
  return totals!;
}

export async function boardView(env: Env, board: Board, quest: string, category: Category, limit: number, customTitle?: string, rules: number | null = null): Promise<BoardView> {
  const [results, totals] = await Promise.all([bestRuns(env, board, quest, category, limit, rules), boardTotals(env, board, quest, category, rules)]);
  const [who, teams] = await Promise.all([players(env, results.map((row) => row.account_id)), seats(env, results.map((row) => row.id))]);
  return {
    board,
    quest,
    category,
    title: boardTitle(board, quest, customTitle),
    totals,
    rows: results.map((row, i) => {
      const result = JSON.parse(row.result) as RunResult;
      return {
        rules: row.rules,
        rank: i + 1,
        run: row.id,
        score: row.score,
        elapsed_ms: result.elapsed_ms,
        most_used_weapon_id: result.players[0]!.most_used_weapon_id,
        player: who.get(row.account_id)!,
        team: teams.get(row.id) ?? null,
        pilot: parsePilot(row.pilot),
      };
    }),
  };
}

// The board holds each account's (or pair's) best run; a run that is not its player's best has no rank.
const BOARD_SCAN = 1000;

// A run's page without its timeline and moderation, which the page's preview tags and card can go without or fetch
// themselves.
export type RunSummary = Omit<RunDetailView, "timeline" | "moderation">;

export async function runDetailView(env: Env, id: string, moderator: boolean): Promise<RunDetailView | null> {
  const run = await runSummary(env, id);
  return run && { ...run, timeline: await timelineFor(env, id, BOARDS[run.board].players), moderation: moderator ? await runModeration(env, id) : null };
}

// A run anyone may see by its id: not hidden, and not a banned account's, as the boards filter; a retired run keeps
// its page and replay.
const VISIBLE_RUN = `r.hidden = 0 AND ${NOT_BANNED}`;

// The board of a run anyone may see, null for none.
export async function visibleRun(env: Env, id: string): Promise<Board | null> {
  const run = await env.DB.prepare(`SELECT r.board FROM runs r JOIN accounts a ON a.id = r.account_id WHERE r.id = ? AND ${VISIBLE_RUN}`).bind(id).first<{ board: Board }>();
  return run?.board ?? null;
}

export async function runSummary(env: Env, id: string): Promise<RunSummary | null> {
  const run = await env.DB.prepare(
    `SELECT r.id, r.account_id, ${team("r")} AS team, ${SHOWN_NAME} AS name, r.board, r.quest, ${runCategory("r")} AS category, r.pilot,
       r.score, r.accepted_at, r.game_version, r.rules, r.retired, r.client, r.client_version, r.platform, r.result
     FROM runs r JOIN accounts a ON a.id = r.account_id WHERE r.id = ? AND ${VISIBLE_RUN}`,
  )
    .bind(id)
    .first<{
      id: string; account_id: number; team: number | string; name: string; board: Board; quest: string; category: Category; pilot: string; score: number;
      accepted_at: number; game_version: string; rules: number; retired: string | null; client: string; client_version: string; platform: string;
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
  const best = board.find((row) => row.team === run.team);
  const result = JSON.parse(run.result) as RunResult;
  const [who, teams] = await Promise.all([
    players(env, top ? [run.account_id, top.account_id] : [run.account_id]),
    seats(env, top ? [id, top.id] : [id]),
  ]);
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
    team: teams.get(id) ?? null,
    score: run.score,
    rank: rank === -1 ? null : rank + 1,
    accepted_at: run.accepted_at,
    game_version: run.game_version,
    rules: run.rules,
    retired: run.retired,
    recorder: { client: run.client, version: run.client_version, platform: run.platform },
    result: {
      outcome: result.outcome,
      health: result.players[0]!.health,
      healths: result.players.map((player) => player.health),
      pending_perks: result.pending_perks,
      elapsed_ms: result.elapsed_ms,
      kills: result.kills,
      shots_fired: result.shots_fired,
      shots_hit: result.shots_hit,
      experience: result.players[0]!.experience,
      most_used_weapon_id: result.players[0]!.most_used_weapon_id,
    },
    top: top && { id: top.id, name: runLabel({ player: who.get(top.account_id)!, team: teams.get(top.id) ?? null }), score: top.score },
    best: best && best.id !== id ? { id: best.id, score: best.score } : null,
  };
}

// What a shared run's link says under its title.
export function runDescription(run: RunSummary): string {
  const result = run.result;
  const seconds = Math.floor(result.elapsed_ms / 1000);
  const { quests, hardcore } = BOARDS[run.board];
  const what = !quests
    ? `survived ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")} for ${formatScore(run.board, run.score)}`
    : `finished ${run.title}${hardcore ? " on hardcore" : ""} in ${formatScore(run.board, run.score)}`;
  const weapon = WEAPONS[result.most_used_weapon_id];
  const numbers = [
    `${result.kills.toLocaleString("en-US")} kills`,
    ...(result.shots_fired ? [`${Math.round((result.shots_hit / result.shots_fired) * 100)}% accuracy`] : []),
    ...(weapon ? [`mostly the ${weapon.name}`] : []),
  ];
  return `${runLabel(run)} ${what}${run.rank ? `, #${run.rank} on the board` : ""}. ${numbers.join(", ")}. Verified by replay.`;
}

export async function gameScores(env: Env, board: Board, quest: string, category: Category, limit: number): Promise<GameScore[]> {
  const runs = await bestRuns(env, board, quest, category, limit);
  const teams = await seats(env, runs.map((run) => run.id));
  return runs.map((run) => {
    const result = JSON.parse(run.result) as RunResult;
    const player = result.players[0]!;
    const names = teams.get(run.id)?.map((seat) => seat.name ?? "?") ?? [run.name];
    return {
      run: run.id,
      name: names.join(" & "),
      names,
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

export async function questMenuView(env: Env, board: QuestMenuView["board"], stage: number, category: Category): Promise<QuestMenuView> {
  const { results } = await env.DB.prepare(
    `SELECT r.quest, count(DISTINCT ${team("r")}) AS players FROM runs r JOIN accounts a ON a.id = r.account_id
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

export async function customQuestDetailView(env: Env, id: string, category: Category, rules: number | null = null): Promise<CustomQuestDetailView | null> {
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
    boardView(env, "quests", id, category, 100, row.title, rules),
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

// Published quests whose creator is not banned, newest first, with how many players their boards have.
async function customQuestRows(env: Env, category: Category, limit: number, offset = 0) {
  const { results } = await env.DB.prepare(
    `SELECT q.id, q.account_id, q.title, q.author, q.source IS NOT NULL AS has_source, q.definition, q.created_at,
       (SELECT count(DISTINCT r.account_id) FROM runs r JOIN accounts a ON a.id = r.account_id
        WHERE r.board = 'quests' AND r.quest = q.id AND ${RANKED_RUN} AND ${runCategory("r")} = ?) AS players,
       (SELECT min(r.score) FROM runs r JOIN accounts a ON a.id = r.account_id
        WHERE r.board = 'quests' AND r.quest = q.id AND ${RANKED_RUN} AND ${runCategory("r")} = ?) AS top_score
     FROM custom_quests q LEFT JOIN accounts ca ON ca.id = q.account_id
     WHERE ca.banned IS NULL OR ca.banned = 0 ORDER BY q.created_at DESC LIMIT ? OFFSET ?`,
  )
    .bind(category, category, limit, offset)
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
  return { results, who };
}

// A page of the game's custom quest browser. The author is the recipe's own, which the game records into the runs
// it plays, so no creator's name stands in for it.
export async function gameCustomQuests(env: Env, page: number, size: number): Promise<GameCustomQuests> {
  const { results } = await customQuestRows(env, "human", size + 1, page * size);
  return {
    quests: results.slice(0, size).map((row) => {
      const def = JSON.parse(row.definition) as CustomQuest;
      return {
        id: row.id,
        title: row.title,
        author: row.author ?? "",
        players: row.players,
        start_weapon_id: def.start_weapon_id,
        no_bonuses: def.no_bonuses,
        no_perks: def.no_perks,
        no_weapons: def.no_weapons,
      };
    }),
    more: results.length > size,
  };
}

export async function customQuestsListView(env: Env, category: Category, limit = 100): Promise<CustomQuestsListView> {
  const { results, who } = await customQuestRows(env, category, limit);
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
    `SELECT r.id, r.board, r.quest, ${runCategory("r")} AS category, r.score, r.game_version, r.rules, r.accepted_at, r.retired FROM runs r
     JOIN accounts a ON a.id = r.account_id WHERE ${accountRun("r")} AND r.hidden = 0
     ORDER BY r.accepted_at DESC LIMIT 100`,
  )
    .bind(accountId)
    .all<Omit<RunView, "team">>();
  const teams = await seats(env, runs.map((run) => run.id));
  const linked = new Set(player.links.map((link) => link.provider));
  return {
    player,
    names: names.map((row) => row.name),
    runs: runs.map((run) => ({ ...run, team: teams.get(run.id) ?? null })),
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
    count(`SELECT count(*) AS n FROM runs WHERE ${accountRun("runs")}`, from),
    count("SELECT count(*) AS n FROM names WHERE account_id = ?", from),
    count(`SELECT count(*) AS n FROM runs WHERE ${accountRun("runs")}`, into),
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
    env.DB.prepare(`SELECT count(*) AS n FROM runs WHERE ${accountRun("runs")}`).bind(account).first<{ n: number }>(),
  ]);
  return { account: found.get(account)!, runs: runs!.n, current: other === null ? null : found.get(other)! };
}
