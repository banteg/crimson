// POST /api/runs: a signed ranked run (docs/rewrite/leaderboard-identity.md, "Protocol").

import { concat, fromHex, hex, latin1, RUN_DOMAIN, sha256, verifyEd25519 } from "./crypto";
import { accountForKey, type Env, json, refuse } from "./http";
import { outcomeReasons, rankedBoard, rankedScore, unrankedReasons } from "./ranked";
import type { Signals, Timeline } from "./api-types";
import { decodeReplay, inflateReplay, type Replay, REPLAY_RULES, ReplayError } from "./replay";
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

// A replay file's run and its payload's digest. The payload, many times the file's size, goes with this call rather
// than staying through verification.
async function readReplay(file: Uint8Array): Promise<{ replay: Replay; payloadSha: Uint8Array }> {
  const payload = inflateReplay(file);
  return { replay: decodeReplay(payload), payloadSha: await sha256(payload) };
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

  let replay: Replay;
  let payloadSha: Uint8Array;
  try {
    ({ replay, payloadSha } = await readReplay(file));
  } catch (error) {
    if (error instanceof ReplayError) return refuse(422, error.message);
    throw error;
  }
  if (replay.rules !== REPLAY_RULES)
    return refuse(422, `replay was recorded under rules ${replay.rules}; this service verifies rules ${REPLAY_RULES}`);
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
  await putTimeline(env, runId, verdict.timeline);
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO runs (id, payload_sha256, account_id, public_key, name, board, quest, score, game_version, client,
         client_version, platform, pilot, ticks, result, signals, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      runId, hex(payloadSha), accountId, upload.public_key, upload.name, board, quest, score, replay.game_version,
      replay.recorder.client, replay.recorder.version, replay.recorder.platform, replay.pilot ? JSON.stringify(replay.pilot) : "",
      replay.ticks.length, JSON.stringify(replay.result), JSON.stringify(verdict.signals), now,
    ),
    env.DB.prepare("UPDATE accounts SET name = ? WHERE id = ?").bind(upload.name, accountId),
    env.DB.prepare(
      `INSERT INTO names (account_id, name, first_at, last_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (account_id, name) DO UPDATE SET last_at = excluded.last_at`,
    ).bind(accountId, upload.name, now, now),
  ]);
  return json({ id: runId, board, quest, score }, 201);
}

export const timelineKey = (runId: string) => `runs/${runId}.timeline.json`;

function putTimeline(env: Env, runId: string, timeline: Timeline): Promise<R2Object> {
  return env.REPLAYS.put(timelineKey(runId), JSON.stringify(timeline), { httpMetadata: { contentType: "application/json" } });
}

// A run's input signals (src/signals.ts). Runs accepted before signals were measured get theirs the first time a
// moderator asks, by replaying their stored file; a run the verifier now refuses has those of the ticks before.
export async function signalsFor(env: Env, runId: string): Promise<Signals | null> {
  const run = await env.DB.prepare("SELECT signals FROM runs WHERE id = ?").bind(runId).first<{ signals: string | null }>();
  if (!run) return null;
  if (run.signals) return JSON.parse(run.signals) as Signals;
  const file = await env.REPLAYS.get(`runs/${runId}.crd`);
  if (!file) return null;
  const replay = decodeReplay(inflateReplay(new Uint8Array(await file.arrayBuffer())));
  const { signals } = await verifyRun(env, replay, encodeTransport(replay));
  await env.DB.prepare("UPDATE runs SET signals = ? WHERE id = ?").bind(JSON.stringify(signals), runId).run();
  return signals;
}

// A run's timeline. Runs accepted before timelines were recorded get theirs the first time it is asked for, by
// replaying their stored file again; null when there is no such replay.
export async function timelineFor(env: Env, runId: string): Promise<Timeline | null> {
  const stored = await env.REPLAYS.get(timelineKey(runId));
  if (stored) return stored.json<Timeline>();
  const file = await env.REPLAYS.get(`runs/${runId}.crd`);
  if (!file) return null;
  const replay = decodeReplay(inflateReplay(new Uint8Array(await file.arrayBuffer())));
  const verdict = await verifyRun(env, replay, encodeTransport(replay));
  if (!verdict.ok) throw new Error(`run ${runId} no longer verifies: ${verdict.reason}`);
  await putTimeline(env, runId, verdict.timeline);
  return verdict.timeline;
}
