import { applyD1Migrations, env } from "cloudflare:test";
import { beforeEach } from "vitest";

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS);

// Storage persists between tests, so each starts from an empty database and bucket.
const TABLES = ["runs", "names", "links", "keys", "sessions", "login_links", "challenges", "oauth_states", "merge_requests", "moderation_log", "accounts"];
beforeEach(async () => {
  await env.DB.batch(TABLES.map((table) => env.DB.prepare(`DELETE FROM ${table}`)));
  const { objects } = await env.REPLAYS.list();
  if (objects.length) await env.REPLAYS.delete(objects.map((object) => object.key));
});
