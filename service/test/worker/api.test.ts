import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { concat, hex, LOGIN_DOMAIN, RUN_DOMAIN, sha256 } from "../../src/crypto";
import { inflateReplay } from "../../src/replay";
import vectors from "../vectors.json";

const ORIGIN = "https://crimson.land";
const decode64 = (text: string) => Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));

class Player {
  private constructor(private readonly key: CryptoKeyPair, readonly publicKey: string) {}

  static async create(): Promise<Player> {
    const key = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    return new Player(key, hex(new Uint8Array((await crypto.subtle.exportKey("raw", key.publicKey)) as ArrayBuffer)));
  }

  async sign(message: Uint8Array): Promise<string> {
    return hex(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, this.key.privateKey, message)));
  }

  // The game's upload envelope (src/crimson/leaderboard/client.py).
  async upload(file: string, name: string, signed = name): Promise<Response> {
    const payloadSha = await sha256(inflateReplay(decode64(file)));
    const signature = await this.sign(concat(RUN_DOMAIN, payloadSha, new TextEncoder().encode(signed)));
    return post("/api/runs", { replay: file, name, public_key: this.publicKey, signature });
  }
}

function post(path: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${ORIGIN}${path}`, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
}

async function reason(response: Response): Promise<string> {
  return ((await response.json()) as { reason: string }).reason;
}

describe("runs", () => {
  it("a verified ranked run joins its board under its name", async () => {
    const player = await Player.create();
    const response = await player.upload(vectors.ranked_run, "banteg");

    expect(response.status).toBe(201);
    const run = (await response.json()) as { id: string; board: string; score: number };
    expect(run).toMatchObject({ board: "survival", score: 749 });
    const account = await env.DB.prepare("SELECT accounts.name, keys.fingerprint FROM accounts JOIN keys ON keys.account_id = accounts.id").first();
    expect(account).toMatchObject({ name: "banteg" });
    expect(await env.REPLAYS.head(`runs/${run.id}.crd`)).not.toBeNull();
  });

  it("a run is accepted once, whoever sends it again", async () => {
    const [owner, copier] = [await Player.create(), await Player.create()];
    expect((await owner.upload(vectors.ranked_run, "owner")).status).toBe(201);

    expect((await owner.upload(vectors.ranked_run, "owner")).status).toBe(409);
    expect((await copier.upload(vectors.ranked_run, "copier")).status).toBe(409);
  });

  it("a claimed result the simulation does not reach is refused", async () => {
    const response = await (await Player.create()).upload(vectors.ranked_run_inflated, "banteg");

    expect(response.status).toBe(422);
    expect(await reason(response)).toContain("players[0].experience");
  });

  it("a signature over another name is refused", async () => {
    const response = await (await Player.create()).upload(vectors.ranked_run, "banteg", "someone");

    expect(response.status).toBe(401);
  });

  it("runs outside the ranked profile are refused with their reasons", async () => {
    const response = await (await Player.create()).upload(vectors.unranked_run, "banteg");

    expect(response.status).toBe(422);
    expect(await reason(response)).toBe("not a ranked run: mode, weapon_usage, unfinished");
  });
});

describe("site login", () => {
  async function login(player: Player): Promise<string> {
    const { challenge } = (await (await post("/api/auth/challenge", { public_key: player.publicKey })).json()) as { challenge: string };
    const signature = await player.sign(concat(LOGIN_DOMAIN, new TextEncoder().encode(challenge)));
    const response = await post("/api/auth/login", { public_key: player.publicKey, challenge, signature });
    expect(response.status).toBe(200);
    return ((await response.json()) as { url: string }).url;
  }

  it("a signed challenge buys a one-time link that sets a session", async () => {
    const url = await login(await Player.create());
    expect(url.startsWith(`${ORIGIN}/login/`)).toBe(true);

    const first = await SELF.fetch(url, { redirect: "manual" });
    expect(first.status).toBe(303);
    expect(first.headers.get("set-cookie")).toMatch(/^session=[0-9a-f]{64}; .*HttpOnly; Secure/);
    expect((await SELF.fetch(url, { redirect: "manual" })).status).toBe(410);
  });

  it("a challenge works once and only for its key", async () => {
    const [player, other] = [await Player.create(), await Player.create()];
    const { challenge } = (await (await post("/api/auth/challenge", { public_key: player.publicKey })).json()) as { challenge: string };
    const message = concat(LOGIN_DOMAIN, new TextEncoder().encode(challenge));

    const stolen = await post("/api/auth/login", { public_key: other.publicKey, challenge, signature: await other.sign(message) });
    expect(stolen.status).toBe(401);
    const signature = await player.sign(message);
    expect((await post("/api/auth/login", { public_key: player.publicKey, challenge, signature })).status).toBe(200);
    expect((await post("/api/auth/login", { public_key: player.publicKey, challenge, signature })).status).toBe(401);
  });
});

