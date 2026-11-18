// Only the trusted offline compiler can write to this private R2 prefix. Each candidate has
// a fresh database-generated revision, including when only its construction seed changes.
import type { Env } from "./http";

export type RecipeState = "pending" | "verified" | "rejected";

export async function recipeState(env: Env, id: string, revision: string, state: RecipeState): Promise<RecipeState> {
  if (state !== "pending") return state;
  const key = `recipe-checks/${revision}`;
  const receipt = await env.REPLAYS.get(key);
  if (!receipt) return "pending";
  const { state: decision, compiler } = await receipt.json<{ state?: unknown; compiler?: unknown }>();
  if ((decision !== "verified" && decision !== "rejected") || typeof compiler !== "string" || !/^[a-f0-9]{40}$/.test(compiler))
    throw Error("Invalid recipe check receipt");
  // A request for yesterday's candidate must never release a replacement's source.
  const result = await env.DB.prepare(
    "UPDATE custom_quests SET source_state = ?, source_compiler = ? WHERE id = ? AND source_revision = ? AND source_state = 'pending'",
  ).bind(decision, compiler, id, revision).run();
  await env.REPLAYS.delete(key);
  if (result.meta.changes) return decision;
  return await env.DB.prepare("SELECT source_state FROM custom_quests WHERE id = ? AND source_revision = ?")
    .bind(id, revision).first<RecipeState>("source_state") ?? "pending";
}
