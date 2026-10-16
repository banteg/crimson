// Co-op rooms: the signalling two browsers meet through before their peer connection opens, and the relay they fall
// back to (docs/rewrite/network-coop.md §6.1). A room is a Durable Object with a host seat and a guest seat; it relays
// each seat's messages to the other verbatim and knows nothing of the game.

import { DurableObject } from "cloudflare:workers";
import { tokenHash } from "./auth";
import { randomToken } from "./crypto";
import { type Env, json, refuse } from "./http";
import { iceServers, type IceServer } from "./turn";

type Role = "host" | "guest";

// The room goes a minute after its last socket closes, and in any case half a day after it was made.
const IDLE_MS = 60 * 1000;
const LIFETIME_MS = 12 * 60 * 60 * 1000;
const MAX_MESSAGE_BYTES = 16 * 1024;
// Each socket's message budget: a second's worth refills every second. A frame-paced tick stream at 144 Hz plus
// control fits; a flood does not.
const MESSAGES_PER_SECOND = 200;
// A client asking for ICE servers more often than this gets the ones it was last given, sparing the TURN service.
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

interface Room {
  host: string; // the host token's hash
  created: number;
  guest?: string; // the guest token's hash, once a guest has taken the seat
}

export interface RoomStatus {
  exists: boolean;
  host: boolean; // the host is connected
  guest: boolean; // the guest seat is taken: another guest is refused
}

interface Budget {
  tokens: number;
  at: number;
  ice?: { servers: IceServer[]; at: number };
}

export class CoopRoom extends DurableObject<Env> {
  // In memory only: hibernation resets a socket's budget, which only ever lets an idle socket through.
  private budgets = new Map<WebSocket, Budget>();

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

  async init(hostHash: string): Promise<void> {
    const now = Date.now();
    await this.ctx.storage.put("room", { host: hostHash, created: now } satisfies Room);
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
    server.send(JSON.stringify({ type: "seat", role, ...(guestToken && { guest_token: guestToken }) }));
    const peer = this.socket(otherRole(role));
    server.send(JSON.stringify({ type: "peer", present: peer !== undefined }));
    peer?.send(JSON.stringify({ type: "peer", present: true }));
    await this.ctx.storage.setAlarm(room.created + LIFETIME_MS);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if ((typeof message === "string" ? utf8Length(message) : message.byteLength) > MAX_MESSAGE_BYTES)
      return ws.close(1009, "message over 16 KiB");
    const now = Date.now();
    const budget = this.budgets.get(ws) ?? { tokens: MESSAGES_PER_SECOND, at: now };
    budget.tokens = Math.min(MESSAGES_PER_SECOND, budget.tokens + ((now - budget.at) * MESSAGES_PER_SECOND) / 1000) - 1;
    budget.at = now;
    this.budgets.set(ws, budget);
    if (budget.tokens < 0) return ws.close(1008, "too many messages");
    if (typeof message === "string" && iceRequest(message)) {
      if (!budget.ice || now - budget.ice.at >= ICE_REFRESH_MS) budget.ice = { servers: await iceServers(this.env), at: now };
      return ws.send(JSON.stringify({ type: "ice", ice_servers: budget.ice.servers }));
    }
    // Relayed as sent; a message for a seat nobody holds is dropped.
    this.socket(otherRole(this.ctx.getTags(ws)[0] as Role), ws)?.send(message);
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    await this.left(ws);
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    await this.left(ws);
  }

  private async left(ws: WebSocket): Promise<void> {
    this.budgets.delete(ws);
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

// {type: "ice"} is the one client message the room answers itself; every other one is for the peer.
function iceRequest(message: string): boolean {
  try {
    return (JSON.parse(message) as { type?: unknown } | null)?.type === "ice";
  } catch {
    return false;
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
    await roomStub(env, id).init(await tokenHash(hostToken));
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
