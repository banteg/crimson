import type { D1Migration } from "cloudflare:test";
import type { Env as ServiceEnv } from "../../src/http";

declare global {
  namespace Cloudflare {
    interface Env extends ServiceEnv {
      TEST_MIGRATIONS: D1Migration[];
      TEST_RECIPE_MATCH: string;
      TEST_RECIPE_MISMATCH: string;
    }
  }
}
