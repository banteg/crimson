// POST /api/runs: a signed ranked run (docs/rewrite/leaderboard-identity.md, "Protocol").

import { concat, fromHex, hex, latin1, RUN_DOMAIN, sha256, verifyEd25519 } from "./crypto";
import { accountForKey, type Env, json, refuse } from "./http";
import { outcomeReasons, rankedBoard, rankedScore, unrankedReasons } from "./ranked";
import { decodeReplay, inflateReplay, type Replay, ReplayError } from "./replay";
import { encodeTransport } from "./transport";
import { verifyRun } from "./verify";

const MAX_BODY_BYTES = 16 * 1024 * 1024;
const NAME_MAX_CHARS = 31;

interface Upload {
  replay: string;
  name: string;
  public_key: string;
  signature: string;
}

function parseUpload(body: unknown): Upload | null {
  if (typeof body !== "object" || body === null) return null;
  const { replay, name, public_key, signature } = body as Record<string, unknown>;
  if ([replay, name, public_key, signature].some((field) => typeof field !== "string")) return null;
  return { replay, name, public_key, signature } as Upload;
}

function base64(text: string): Uint8Array | null {
  try {
    return Uint8Array.from(atob(text), (ch) => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

export async function postRun(request: Request, env: Env): Promise<Response> {
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY_BYTES) return refuse(413, "upload too large");
  const upload = parseUpload(await request.json().catch(() => null));
  if (upload === null) return refuse(400, "expected replay, name, public_key and signature");
  const publicKey = fromHex(upload.public_key, 32);
  const signature = fromHex(upload.signature, 64);
  const file = base64(upload.replay);
  const name = latin1(upload.name);
  if (!publicKey || !signature || !file) return refuse(400, "malformed key, signature or replay");
  if (name === null || upload.name.length > NAME_MAX_CHARS || [...name].some((code) => code < 0x20))
    return refuse(422, `name must be at most ${NAME_MAX_CHARS} characters in 0x20..0xFF`);

  let payload: Uint8Array;
  let replay: Replay;
  try {
    payload = inflateReplay(file);
    replay = decodeReplay(payload);
  } catch (error) {
    if (error instanceof ReplayError) return refuse(422, error.message);
    throw error;
  }
  const payloadSha = await sha256(payload);
  if (!(await verifyEd25519(publicKey, signature, concat(RUN_DOMAIN, payloadSha, name))))
    return refuse(401, "signature does not match");

  const key = await env.DB.prepare("SELECT banned FROM keys WHERE public_key = ?").bind(upload.public_key).first<{ banned: number }>();
  if (key?.banned) return refuse(403, "this key is banned");
  const reasons = [...unrankedReasons(replay.run), ...outcomeReasons(replay.run, replay.result)];
  if (reasons.length) return refuse(422, `not a ranked run: ${reasons.join(", ")}`);

  const transport = encodeTransport(replay);
  const runId = hex(await sha256(transport));
  if (await env.DB.prepare("SELECT 1 FROM runs WHERE id = ?").bind(runId).first()) return refuse(409, "this run was already accepted");

  const verdict = await verifyRun(env, replay, transport);
  if (!verdict.ok) return refuse(422, verdict.reason);

  const board = rankedBoard(replay.run)!;
  const quest = replay.run.quest_level ? `${replay.run.quest_level.major}.${replay.run.quest_level.minor}` : "";
  const score = rankedScore(replay.run, replay.result);
  const now = Date.now();
  const accountId = await accountForKey(env, upload.public_key, publicKey, now);
  await env.REPLAYS.put(`runs/${runId}.crd`, file, { httpMetadata: { contentType: "application/octet-stream" } });
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO runs (id, payload_sha256, account_id, public_key, name, board, quest, score, game_version, ticks, result, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      runId, hex(payloadSha), accountId, upload.public_key, upload.name, board, quest, score, replay.game_version,
      replay.ticks.length, JSON.stringify(replay.result), now,
    ),
    env.DB.prepare("UPDATE accounts SET name = ? WHERE id = ?").bind(upload.name, accountId),
    env.DB.prepare(
      `INSERT INTO names (account_id, name, first_at, last_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (account_id, name) DO UPDATE SET last_at = excluded.last_at`,
    ).bind(accountId, upload.name, now, now),
  ]);
  return json({ id: runId, board, quest, score }, 201);
}
