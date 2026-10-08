// Moderation (docs/rewrite/bots.md): roles, bot marks, run categories, the flagged runs and the log.

import type { AccountModeration, Category, FlaggedRun, FlagsView, ModerationAction, Role, RunModeration } from "./api-types";
import type { Env } from "./http";
import { signalsFor } from "./runs";
import { flagged, type Signals } from "./signals";
import { players, runCategory } from "./views";

const FLAGS_LIMIT = 100;
const LOG_LIMIT = 100;
// Runs a moderator's Measure replays at once: each is a full verification.
export const MEASURE_BATCH = 5;

export async function roleOf(env: Env, accountId: number | null): Promise<Role> {
  if (accountId === null) return "";
  const account = await env.DB.prepare("SELECT role FROM accounts WHERE id = ?").bind(accountId).first<{ role: Role }>();
  return account?.role ?? "";
}

export const isModerator = (role: Role) => role === "mod" || role === "admin";

export async function runModeration(env: Env, runId: string): Promise<RunModeration | null> {
  const run = await env.DB.prepare("SELECT r.category, r.pilot, a.bot FROM runs r JOIN accounts a ON a.id = r.account_id WHERE r.id = ?")
    .bind(runId)
    .first<{ category: Category | null; pilot: string; bot: number }>();
  if (!run) return null;
  const signals = await signalsFor(env, runId);
  return {
    source: run.category ? "moderator" : run.pilot ? "pilot" : run.bot ? "account" : "default",
    override: run.category,
    signals,
    flagged: signals ? flagged(signals) : [],
  };
}

export async function accountModeration(env: Env, accountId: number): Promise<AccountModeration> {
  const { results } = await env.DB.prepare("SELECT accepted_at, result FROM runs WHERE account_id = ? ORDER BY accepted_at")
    .bind(accountId)
    .all<{ accepted_at: number; result: string }>();
  // A run takes at least its game time to play, so one accepted sooner after the previous one overlapped it.
  const overlapping = results.filter(
    (run, i) => i > 0 && run.accepted_at - (JSON.parse(run.result) as { elapsed_ms: number }).elapsed_ms < results[i - 1]!.accepted_at,
  ).length;
  return { role: await roleOf(env, accountId), overlapping_runs: overlapping };
}

// The human-category runs with a flagged signal, newest first.
export async function flagsView(env: Env): Promise<FlagsView> {
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.account_id, r.board, r.quest, r.score, r.accepted_at, r.signals FROM runs r JOIN accounts a ON a.id = r.account_id
     WHERE r.hidden = 0 AND a.banned = 0 AND r.signals IS NOT NULL AND ${runCategory("r")} = 'human' ORDER BY r.accepted_at DESC`,
  ).all<Omit<FlaggedRun, "player" | "signals" | "flagged"> & { account_id: number; signals: string }>();
  const runs = results
    .map((run) => ({ run, signals: JSON.parse(run.signals) as Signals }))
    .map(({ run, signals }) => ({ run, signals, flagged: flagged(signals) }))
    .filter((entry) => entry.flagged.length)
    .slice(0, FLAGS_LIMIT);
  const who = await players(env, runs.map(({ run }) => run.account_id));
  const unmeasured = await env.DB.prepare("SELECT count(*) AS n FROM runs WHERE signals IS NULL").first<{ n: number }>();
  return {
    runs: runs.map(({ run: { account_id, signals: _, ...run }, signals, flagged }) => ({ ...run, player: who.get(account_id)!, signals, flagged })),
    unmeasured: unmeasured!.n,
  };
}

// Measures the oldest runs without signals; the number left.
export async function measureRuns(env: Env): Promise<number> {
  const { results } = await env.DB.prepare("SELECT id FROM runs WHERE signals IS NULL ORDER BY accepted_at LIMIT ?")
    .bind(MEASURE_BATCH)
    .all<{ id: string }>();
  for (const run of results) await signalsFor(env, run.id);
  return (await env.DB.prepare("SELECT count(*) AS n FROM runs WHERE signals IS NULL").first<{ n: number }>())!.n;
}

export async function moderationLog(env: Env): Promise<ModerationAction[]> {
  const { results } = await env.DB.prepare("SELECT at, actor, action, target, note FROM moderation_log ORDER BY id DESC LIMIT ?")
    .bind(LOG_LIMIT)
    .all<ModerationAction>();
  return results;
}

const logged = (env: Env, actor: number, action: string, target: string, note: string) =>
  env.DB.prepare("INSERT INTO moderation_log (at, actor, action, target, note) VALUES (?, ?, ?, ?, ?)").bind(
    Date.now(),
    `account ${actor}`,
    action,
    target,
    note,
  );

// Each change and its log entry land together; false when there is no such account or run.
export async function markAccount(env: Env, actor: number, accountId: number, bot: boolean, note: string): Promise<boolean> {
  const [changed] = await env.DB.batch([
    env.DB.prepare("UPDATE accounts SET bot = ? WHERE id = ?").bind(Number(bot), accountId),
    logged(env, actor, bot ? "mark bot" : "unmark bot", `account ${accountId}`, note),
  ]);
  return changed!.meta.changes > 0;
}

export async function setRunCategory(env: Env, actor: number, runId: string, category: Category | null, note: string): Promise<boolean> {
  const [changed] = await env.DB.batch([
    env.DB.prepare("UPDATE runs SET category = ? WHERE id = ?").bind(category, runId),
    logged(env, actor, category ? `category ${category}` : "category follows account", `run ${runId}`, note),
  ]);
  return changed!.meta.changes > 0;
}

// The admin's own role stays: it is how moderators are made.
export async function setRole(env: Env, actor: number, accountId: number, role: "" | "mod", note: string): Promise<boolean> {
  const [changed] = await env.DB.batch([
    env.DB.prepare("UPDATE accounts SET role = ? WHERE id = ? AND role != 'admin'").bind(role, accountId),
    logged(env, actor, role ? "grant mod" : "revoke mod", `account ${accountId}`, note),
  ]);
  return changed!.meta.changes > 0;
}
