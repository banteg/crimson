// Co-op rooms: the signalling two browsers meet through before their peer connection opens, and the relay they fall
// back to (docs/rewrite/network-coop.md §6.1). A room is a Durable Object with a host seat and a guest seat; it relays
// each seat's messages to the other verbatim and knows nothing of the game, but for the seats' keys and the seeds it
// issues to them, which rank the pair's runs (§5.3).

import { DurableObject } from "cloudflare:workers";
import { tokenHash } from "./auth";
import { concat, COOP_SEAT_DOMAIN, fromHex, randomToken, verifyEd25519 } from "./crypto";
import { type Env, json, refuse } from "./http";
import { SEED_BITS } from "./replay";
import { iceServers, type IceServer } from "./turn";

type Role = "host" | "guest";

// The room goes a minute after its last socket closes, and in any case half a day after it was made.
const IDLE_MS = 60 * 1000;
const LIFETIME_MS = 12 * 60 * 60 * 1000;
const MAX_MESSAGE_BYTES = 16 * 1024;
// Each seat's message budget: a second's worth refills every second. A frame-paced tick stream at 144 Hz plus
// control fits; a flood does not.
const MESSAGES_PER_SECOND = 200;
// Each seat's sockets: a reload or a network change reconnects, a loop does not.
const CONNECTS_PER_MINUTE = 10;
// The host's seeds, each a row in D1: one a run, and runs take longer than this.
const SEEDS_PER_MINUTE = 10;
// ICE requests within this long of the room's last TURN mint get the servers it gave, sparing the TURN service.
const ICE_REFRESH_MS = 10 * 1000;
// Close codes for the server's own reasons; 1008 and 1009 are the standard ones for floods and oversized messages.
const CLOSE_ROOM_GONE = 4000;
const CLOSE_REPLACED = 4001;

// Room ids are short enough to read out: Crockford's base32 alphabet, 50 random bits.
const ROOM_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
export const ROOM_ID = /^[0-9a-hjkmnp-tv-z]{10}$/;
const roomId = () => Array.from(crypto.getRandomValues(new Uint8Array(10)), (byte) => ROOM_ALPHABET[byte & 31]).join("");

const otherRole = (role: Role): Role => (role === "host" ? "guest" : "host");
const utf8Length = (text: string) => new TextEncoder().encode(text).length;
const ascii = (text: string) => new TextEncoder().encode(text);

interface Room {
  id: string;
  host: string; // the host token's hash
  created: number;
  guest?: string; // the guest token's hash, once a guest has taken the seat
}

// Each seat's public key, in hex, once it has proven it: kept apart from the room, whose writes it would race.
const seatKey = (role: Role) => `key:${role}`;
// The last seed the room issued, which each new socket hears.
const LATEST_SEED = "seed";

// What the room keeps on each socket: the challenge its seat signs, the key it proved and whether it has left.
interface Attachment {
  challenge: string;
  key?: string;
  left?: true;
}

export interface RoomStatus {
  exists: boolean;
  host: boolean; // the host is connected
  guest: boolean; // the guest seat is taken: another guest is refused
}

// A token bucket: `burst` at most, refilled at `rate` a second.
class Budget {
  private tokens: number;
  private at = Date.now();

  constructor(
    private readonly rate: number,
    private readonly burst: number,
  ) {
    this.tokens = burst;
  }

  take(): boolean {
    const now = Date.now();
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.at) * this.rate) / 1000);
    this.at = now;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

const seatBudgets = (rate: number, burst: number): Record<Role, Budget> => ({ host: new Budget(rate, burst), guest: new Budget(rate, burst) });

export class CoopRoom extends DurableObject<Env> {
  // Kept per seat, so a reconnect inherits what the socket it replaces had spent. In memory only: the room
  // hibernates only after seconds of silence, which refills the message budget anyway; a wake also refills the
  // connection budget early, which only lets a seat quiet for that long reconnect a little sooner.
  private messages = seatBudgets(MESSAGES_PER_SECOND, MESSAGES_PER_SECOND);
  private connects = seatBudgets(CONNECTS_PER_MINUTE / 60, CONNECTS_PER_MINUTE);
  private seeds = new Budget(SEEDS_PER_MINUTE / 60, SEEDS_PER_MINUTE);
  // The room's last TURN mint, from when it was asked for: requests while it is under way share it, and
  // reconnects cannot reset it.
  private ice?: { servers: Promise<IceServer[]>; at: number };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Keepalives for idle sockets: the runtime answers them without waking the room or spending the seat's budget.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  private async room(): Promise<Room | null> {
    const room = await this.ctx.storage.get<Room>("room");
    return room && Date.now() < room.created + LIFETIME_MS ? room : null;
  }

  private open(role?: Role): WebSocket[] {
    return this.ctx.getWebSockets(role).filter((ws) => ws.readyState === WebSocket.OPEN);
  }

  private socket(role: Role, except?: WebSocket): WebSocket | undefined {
    return this.open(role).find((ws) => ws !== except);
  }

  async init(id: string, hostHash: string): Promise<void> {
    const now = Date.now();
    await this.ctx.storage.put("room", { id, host: hostHash, created: now } satisfies Room);
    await this.ctx.storage.setAlarm(now + IDLE_MS);
  }

  async status(): Promise<RoomStatus> {
    const room = await this.room();
    return { exists: room !== null, host: room !== null && this.socket("host") !== undefined, guest: room?.guest !== undefined };
  }

  // The WebSocket handshake, forwarded by the Worker: ?role=host&token=<host_token> or ?role=guest[&token=<guest_token>].
  async fetch(request: Request): Promise<Response> {
    const params = new URL(request.url).searchParams;
    const role = params.get("role");
    const token = params.get("token");
    const room = await this.room();
    if (!room) return refuse(404, "no such room");
    if (role !== "host" && role !== "guest") return refuse(400, "role must be host or guest");
    const hash = token === null ? null : await tokenHash(token);
    if (role === "host" && hash !== room.host) return refuse(403, "wrong host token");
    if (role === "guest" && room.guest !== undefined && hash !== room.guest) return refuse(409, "room full");
    if (!this.connects[role].take()) return refuse(429, "too many connections");

    // The first guest takes the seat and gets the token that takes it back after a reload.
    let guestToken: string | undefined;
    if (role === "guest" && room.guest === undefined) {
      guestToken = randomToken();
      await this.ctx.storage.put("room", { ...room, guest: await tokenHash(guestToken) } satisfies Room);
    }
    // A reconnect with the seat's token replaces the socket it left behind.
    for (const old of this.open(role)) old.close(CLOSE_REPLACED, "replaced by a new connection");

    const [client, server] = Object.values(new WebSocketPair()) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [role]);
    const challenge = randomToken();
    server.serializeAttachment({ challenge } satisfies Attachment);
    server.send(JSON.stringify({ type: "seat", role, challenge, ...(guestToken && { guest_token: guestToken }) }));
    const peer = this.socket(otherRole(role));
    server.send(JSON.stringify({ type: "peer", present: peer !== undefined }));
    peer?.send(JSON.stringify({ type: "peer", present: true }));
    // The keys the seats proved before this socket came (its page reloaded, or took its seat after the other's
    // proof), which the room issues seeds to, and the last seed it issued, which a socket away at the time missed.
    const stored = await this.ctx.storage.get<string | number>([seatKey("host"), seatKey("guest"), LATEST_SEED]);
    for (const seat of ["host", "guest"] as const) {
      const key = stored.get(seatKey(seat));
      if (key !== undefined) server.send(JSON.stringify({ type: "key", role: seat, public_key: key }));
    }
    const seed = stored.get(LATEST_SEED);
    if (seed !== undefined) server.send(JSON.stringify({ type: "seed", seed }));
    await this.ctx.storage.setAlarm(room.created + LIFETIME_MS);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    // A socket the room closed (oversized, flooding or replaced) is no longer heard.
    if (ws.readyState !== WebSocket.OPEN) return;
    if ((typeof message === "string" ? utf8Length(message) : message.byteLength) > MAX_MESSAGE_BYTES)
      return ws.close(1009, "message over 16 KiB");
    const role = this.ctx.getTags(ws)[0] as Role;
    if (!this.messages[role].take()) return ws.close(1008, "too many messages");
    const type = typeof message === "string" ? messageType(message) : undefined;
    if (type === "ice") {
      const servers = await this.roomIceServers();
      // The socket may have gone while the TURN service answered.
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "ice", ice_servers: servers }));
      return;
    }
    // Requests the room answers itself, to both seats.
    if (type === "key") return this.proveKey(ws, role, message as string);
    if (type === "seed") return this.issueSeed(ws, role);
    // Only the room says who sits where: relayed, these would pass for its own.
    if (type === "seat" || type === "peer") return ws.close(1008, `${type} messages are the room's`);
    // Relayed as sent; a message for a seat nobody holds is dropped.
    this.socket(otherRole(role), ws)?.send(message);
  }

  // A seat's key, proven by signing its socket's challenge with it. The first proof records the seat's key; a reconnect
  // proves again, and only that same key proves it: another leaves the socket unproven and the seat's key as it was,
  // so the pair's runs play unranked.
  private async proveKey(ws: WebSocket, role: Role, message: string): Promise<void> {
    const attachment = ws.deserializeAttachment() as Attachment;
    if (attachment.key) return ws.close(1008, "a socket proves its key once");
    const { public_key, signature } = JSON.parse(message) as Record<string, unknown>;
    const publicKey = typeof public_key === "string" ? fromHex(public_key, 32) : null;
    const signed = typeof signature === "string" ? fromHex(signature, 64) : null;
    const room = await this.room();
    if (!room) return ws.close(CLOSE_ROOM_GONE, "room closed");
    const proven =
      publicKey && signed && (await verifyEd25519(publicKey, signed, concat(COOP_SEAT_DOMAIN, ascii(room.id), ascii(attachment.challenge))).catch(() => false));
    if (!proven) return ws.close(1008, "key proof does not verify");
    const key = public_key as string;
    const recorded = await this.ctx.storage.get<string>(seatKey(role));
    if (recorded !== undefined && recorded !== key) return;
    if (recorded === undefined) await this.ctx.storage.put(seatKey(role), key);
    ws.serializeAttachment({ ...attachment, key } satisfies Attachment);
    for (const seat of this.open()) seat.send(JSON.stringify({ type: "key", role, public_key: key }));
  }

  // A run's seed for the pair whose keys the seats proved, recorded with those keys for the run's upload, in the bits
  // rand reads, so no two seeds the room issues play one run. A request past the budget or before both seats' keys
  // gets none, and the host's run plays its own seed, unranked.
  private async issueSeed(ws: WebSocket, role: Role): Promise<void> {
    if (role !== "host") return ws.close(1008, "only the host asks for a seed");
    if (!this.seeds.take()) return;
    const room = await this.room();
    if (!room) return ws.close(CLOSE_ROOM_GONE, "room closed");
    const keys = await this.ctx.storage.get<string>([seatKey("host"), seatKey("guest")]);
    const [host, guest] = [keys.get(seatKey("host")), keys.get(seatKey("guest"))];
    if (host === undefined || guest === undefined) return;
    const insert = this.env.DB.prepare(
      "INSERT INTO coop_runs (seed, room_id, seat0_key, seat1_key, issued_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (seed) DO NOTHING",
    );
    let seed: number;
    do seed = crypto.getRandomValues(new Uint32Array(1))[0]! & SEED_BITS;
    while (!(await insert.bind(seed, room.id, host, guest, Date.now()).run()).meta.changes);
    await this.ctx.storage.put(LATEST_SEED, seed);
    for (const seat of this.open()) seat.send(JSON.stringify({ type: "seed", seed }));
  }

  private roomIceServers(): Promise<IceServer[]> {
    const now = Date.now();
    if (!this.ice || now - this.ice.at >= ICE_REFRESH_MS) this.ice = { servers: iceServers(this.env), at: now };
    return this.ice.servers;
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    await this.left(ws);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.left(ws);
  }

  private async left(ws: WebSocket): Promise<void> {
    // webSocketError and webSocketClose can both report a socket; it leaves once.
    const attachment = ws.deserializeAttachment() as Attachment;
    if (attachment.left) return;
    ws.serializeAttachment({ ...attachment, left: true } satisfies Attachment);
    const role = this.ctx.getTags(ws)[0] as Role;
    // A socket replaced by its seat's reconnect leaves nobody missing.
    if (!this.socket(role, ws)) this.socket(otherRole(role))?.send(JSON.stringify({ type: "peer", present: false }));
    const room = await this.ctx.storage.get<Room>("room");
    if (room && !this.open().some((other) => other !== ws))
      await this.ctx.storage.setAlarm(Math.min(Date.now() + IDLE_MS, room.created + LIFETIME_MS));
  }

  // Due a minute after the room emptied, or at its end of life; while sockets remain, it waits for the end of life.
  async alarm(): Promise<void> {
    const room = await this.room();
    const open = this.open();
    if (room && open.length) return this.ctx.storage.setAlarm(room.created + LIFETIME_MS);
    for (const ws of open) ws.close(CLOSE_ROOM_GONE, "room closed");
    await this.ctx.storage.deleteAll();
  }
}

// The type of a JSON text message: "ice", "key" and "seed" are requests the room answers itself, and "seat" and "peer"
// are the room's own.
function messageType(message: string): unknown {
  try {
    return (JSON.parse(message) as { type?: unknown } | null)?.type;
  } catch {
    return undefined;
  }
}

const roomStub = (env: Env, id: string) => env.COOP_ROOMS.get(env.COOP_ROOMS.idFromName(id));

// /api/coop/*: rooms, their status and their sockets. No cookie or account is read: anyone with the invite plays.
export async function coopRoute(request: Request, env: Env, url: URL): Promise<Response> {
  const route = `${request.method} ${url.pathname}`;
  let match: RegExpExecArray | null;
  if (route === "POST /api/coop/rooms") {
    if (request.headers.get("origin") !== url.origin) return refuse(403, "cross-site request refused");
    if (!(await env.COOP_ROOM_LIMITER.limit({ key: request.headers.get("cf-connecting-ip") ?? "" })).success)
      return new Response(null, { status: 429, headers: { "retry-after": "60", "cache-control": "no-store" } });
    const id = roomId();
    const hostToken = randomToken();
    await roomStub(env, id).init(id, await tokenHash(hostToken));
    return json(
      { room_id: id, host_token: hostToken, invite_url: `${url.origin}/play/?coop=${id}`, ice_servers: await iceServers(env) },
      201,
      { "cache-control": "no-store" },
    );
  }
  // Browsers cannot read why a WebSocket failed, so the invited page asks first. A same-origin GET carries no Origin.
  if ((match = /^GET \/api\/coop\/rooms\/([^/]+)$/.exec(route)) && ROOM_ID.test(match[1]!))
    return json(await roomStub(env, match[1]!).status(), 200, { "cache-control": "no-store" });
  if ((match = /^GET \/api\/coop\/rooms\/([^/]+)\/ws$/.exec(route)) && ROOM_ID.test(match[1]!)) {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return refuse(426, "expected a WebSocket upgrade");
    if (request.headers.get("origin") !== url.origin) return refuse(403, "cross-site request refused");
    return roomStub(env, match[1]!).fetch(request);
  }
  return refuse(404, "no such endpoint");
}
