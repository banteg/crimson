import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { URL } from "node:url";

const { custom_quest_run: fixture } = JSON.parse(readFileSync(new URL("./test/vectors.json", import.meta.url), "utf8")) as {
  custom_quest_run: { digest: string; source: string };
};

// Feed real compiler receipts through the Worker, including a valid recipe for a different
// spawn time. The production runner uses the same locked Python compiler and stdin contract.
function recipeVerdict(source: string): string {
  const candidate = { source, seed: 0, title: "Quick Clear", author: "banteg", digest: fixture.digest };
  return execFileSync("uv", ["run", "--frozen", "--extra", "quests", "python", "scripts/check_recipe.py"], {
    input: JSON.stringify(candidate), encoding: "utf8",
  }).trim();
}

export default defineConfig({
  test: {
    projects: [
      // The replay codec and rules are plain TypeScript; Node reads the repository's fixtures directly.
      { test: { name: "unit", include: ["test/unit/**/*.test.ts"], environment: "node" } },
      {
        plugins: [
          cloudflareTest(async () => ({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: { bindings: {
              TEST_MIGRATIONS: await readD1Migrations("./migrations"),
              TEST_RECIPE_MATCH: recipeVerdict(fixture.source),
              TEST_RECIPE_MISMATCH: recipeVerdict(fixture.source.replace("500ms", "9000ms")),
            } },
          })),
        ],
        test: { name: "worker", include: ["test/worker/**/*.test.ts"], setupFiles: ["test/worker/setup.ts"] },
      },
    ],
  },
});
