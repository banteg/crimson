import { env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../../src/index";
import { tokenHash } from "../../src/auth";
import { ROOM_ID, type RoomStatus } from "../../src/coop";

const ORIGIN = "https://crimson.land";
const STUN_ONLY = [{ urls: ["stun:stun.cloudflare.com:3478"] }];
// The real limiter keys on the visitor's address, which every test shares.
const allow = { ...env, COOP_ROOM_LIMITER: { limit: async () => ({ success: true }) } };
const call = (path: string, init: RequestInit = {}, bindings: Cloudflare.Env = allow) => worker.fetch(new Request(ORIGIN + path, init), bindings);
const stub = (id: string) => env.COOP_ROOMS.get(env.COOP_ROOMS.idFromName(id));
afterEach(() => vi.restoreAllMocks());

interface Created {
  room_id: string;
  host_token: string;
  invite_url: string;
  ice_servers: unknown;
}

async function create(bindings: Cloudflare.Env = allow): Promise<Created> {
  const response = await call("/api/coop/rooms", { method: "POST", headers: { origin: ORIGIN } }, bindings);
  expect(response.status).toBe(201);
  return response.json();
}

const status = async (id: string) => (await call(`/api/coop/rooms/${id}`)).json<RoomStatus>();
const handshake = (id: string, query: string, headers: Record<string, string> = { origin: ORIGIN, upgrade: "websocket" }) =>
  call(`/api/coop/rooms/${id}/ws?${query}`, { headers });

// One side of a room socket: what it received, in order, and how it closed.
class Peer {
  private queue: (string | ArrayBuffer)[] = [];
  private waiting: ((message: string | ArrayBuffer) => void)[] = [];
  readonly closed: Promise<{ code: number; reason: string }>;

  constructor(readonly ws: WebSocket) {
    ws.binaryType = "arraybuffer";
    ws.accept();
    ws.addEventListener("message", (event) => {
      const wake = this.waiting.shift();
      if (wake) wake(event.data);
      else this.queue.push(event.data);
    });
    this.closed = new Promise((resolve) => ws.addEventListener("close", (event) => resolve({ code: event.code, reason: event.reason })));
  }

  next(): Promise<string | ArrayBuffer> {
    const queued = this.queue.shift();
    return queued !== undefined ? Promise.resolve(queued) : new Promise((resolve) => this.waiting.push(resolve));
  }

  async json(): Promise<unknown> {
    return JSON.parse((await this.next()) as string);
  }

  pending(): number {
    return this.queue.length;
  }
}

async function join(id: string, query: string): Promise<Peer> {
  const response = await handshake(id, query);
  expect(response.status).toBe(101);
  return new Peer(response.webSocket!);
}

// The host and a guest in a fresh room, past their join messages.
async function pair() {
  const room = await create();
  const host = await join(room.room_id, `role=host&token=${room.host_token}`);
  expect(await host.json()).toEqual({ type: "seat", role: "host" });
  expect(await host.json()).toEqual({ type: "peer", present: false });
  const guest = await join(room.room_id, "role=guest");
  const seat = (await guest.json()) as { guest_token: string };
  expect(await guest.json()).toEqual({ type: "peer", present: true });
  expect(await host.json()).toEqual({ type: "peer", present: true });
  return { room, host, guest, guestToken: seat.guest_token };
}

describe("co-op rooms", () => {
  it("makes rooms for same-origin requests within the visitor's budget, keeping only the host token's hash", async () => {
    expect((await call("/api/coop/rooms", { method: "POST" })).status).toBe(403);
    expect((await call("/api/coop/rooms", { method: "POST", headers: { origin: "https://other.invalid" } })).status).toBe(403);
    let key: string | undefined;
    const exhausted = { ...env, COOP_ROOM_LIMITER: { limit: async (options: { key: string }) => ((key = options.key), { success: false }) } };
    const refused = await call("/api/coop/rooms", { method: "POST", headers: { origin: ORIGIN, "cf-connecting-ip": "192.0.2.7" } }, exhausted);
    expect([refused.status, refused.headers.get("retry-after"), key]).toEqual([429, "60", "192.0.2.7"]);

    const room = await create();
    expect(room.room_id).toMatch(ROOM_ID);
    expect(room.host_token).toMatch(/^[0-9a-f]{64}$/);
    expect(room.invite_url).toBe(`${ORIGIN}/play/?coop=${room.room_id}`);
    expect(room.ice_servers).toEqual(STUN_ONLY);
    const stored = await runInDurableObject(stub(room.room_id), (_, state) => state.storage.list());
    expect(Object.fromEntries(stored)).toEqual({ room: { host: await tokenHash(room.host_token), created: expect.any(Number) } });
  });

  it("tells the invited page whether the room exists and whether its guest seat is taken", async () => {
    expect(await status("0000000000")).toEqual({ exists: false, host: false, guest: false });
    expect((await call("/api/coop/rooms/not-a-room")).status).toBe(404);
    const room = await create();
    expect(await status(room.room_id)).toEqual({ exists: true, host: false, guest: false });
    await join(room.room_id, `role=host&token=${room.host_token}`);
    expect(await status(room.room_id)).toEqual({ exists: true, host: true, guest: false });
    await join(room.room_id, "role=guest");
    expect(await status(room.room_id)).toEqual({ exists: true, host: true, guest: true });
  });

  it("opens the host's socket only with its token, over a same-origin WebSocket handshake", async () => {
    const room = await create();
    expect((await handshake("0000000000", `role=host&token=${room.host_token}`)).status).toBe(404);
    expect((await handshake(room.room_id, "role=host")).status).toBe(403);
    expect((await handshake(room.room_id, `role=host&token=${"0".repeat(64)}`)).status).toBe(403);
    expect((await handshake(room.room_id, "role=viewer")).status).toBe(400);
    expect((await handshake(room.room_id, `role=host&token=${room.host_token}`, { origin: ORIGIN })).status).toBe(426);
    expect((await handshake(room.room_id, `role=host&token=${room.host_token}`, { upgrade: "websocket" })).status).toBe(403);
    const response = await handshake(room.room_id, `role=host&token=${room.host_token}`);
    expect([response.status, response.headers.has("strict-transport-security")]).toEqual([101, false]);
  });

  it("gives the guest seat to the first guest, refuses anyone else and lets the guest take it back", async () => {
    const { room, host, guest, guestToken } = await pair();
    expect(guestToken).toMatch(/^[0-9a-f]{64}$/);
    expect((await handshake(room.room_id, "role=guest")).status).toBe(409);
    expect((await handshake(room.room_id, `role=guest&token=${room.host_token}`)).status).toBe(409);

    // A reload: the old socket closes, the partner sees the guest leave and come back.
    guest.ws.close(1000);
    expect(await host.json()).toEqual({ type: "peer", present: false });
    const back = await join(room.room_id, `role=guest&token=${guestToken}`);
    expect(await back.json()).toEqual({ type: "seat", role: "guest" });
    expect(await back.json()).toEqual({ type: "peer", present: true });
    expect(await host.json()).toEqual({ type: "peer", present: true });

    // A reconnect while the old socket still looks open replaces it without the partner seeing anyone leave.
    const again = await join(room.room_id, `role=guest&token=${guestToken}`);
    expect(await back.closed).toEqual({ code: 4001, reason: "replaced by a new connection" });
    expect(await again.json()).toEqual({ type: "seat", role: "guest" });
    expect(await host.json()).toEqual({ type: "peer", present: true });
    again.ws.send("still here");
    expect(await host.next()).toBe("still here");
  });

  it("replaces the host's socket when the host reconnects with its token", async () => {
    const { room, host, guest } = await pair();
    const again = await join(room.room_id, `role=host&token=${room.host_token}`);
    expect(await host.closed).toEqual({ code: 4001, reason: "replaced by a new connection" });
    expect(await again.json()).toEqual({ type: "seat", role: "host" });
    expect(await again.json()).toEqual({ type: "peer", present: true });
    expect(await guest.json()).toEqual({ type: "peer", present: true });
    guest.ws.send("to the new host");
    expect(await again.next()).toBe("to the new host");
  });

  it("relays text and binary messages verbatim in both directions", async () => {
    const { host, guest } = await pair();
    const offer = JSON.stringify({ type: "offer", sdp: "v=0\r\n" });
    host.ws.send(offer);
    expect(await guest.next()).toBe(offer);
    guest.ws.send(new Uint8Array([0xc3, 1, 0, 0, 255]));
    expect(new Uint8Array((await host.next()) as ArrayBuffer)).toEqual(new Uint8Array([0xc3, 1, 0, 0, 255]));
    const largest = "é".repeat(8 * 1024);
    host.ws.send(largest);
    expect(await guest.next()).toBe(largest);
    expect(host.pending()).toBe(0);
  });

  it("closes a socket that sends more than 16 KiB at once or floods, without relaying it", async () => {
    const { host, guest } = await pair();
    host.ws.send(new Uint8Array(16 * 1024 + 1));
    expect((await host.closed).code).toBe(1009);
    expect(await guest.json()).toEqual({ type: "peer", present: false });

    const flood = await pair();
    for (let i = 0; i < 400; i++) flood.guest.ws.send(String(i));
    expect((await flood.guest.closed).code).toBe(1008);
  });

  it("answers an ICE request itself and keeps it from the partner", async () => {
    const { host, guest } = await pair();
    guest.ws.send(JSON.stringify({ type: "ice" }));
    expect(await guest.json()).toEqual({ type: "ice", ice_servers: STUN_ONLY });
    host.ws.send("after");
    expect(await guest.next()).toBe("after");
    expect(host.pending()).toBe(0);
  });

  it("mints TURN credentials with UDP relays first and without port 53, and falls back to STUN", async () => {
    const turn = {
      urls: [
        "turn:turn.cloudflare.com:3478?transport=udp",
        "turns:turn.cloudflare.com:443?transport=tcp",
        "turn:turn.cloudflare.com:53?transport=udp",
        "turn:turn.cloudflare.com:80?transport=tcp",
        "turn:turn.cloudflare.com:443?transport=udp",
      ],
      username: "user",
      credential: "secret",
    };
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(Response.json({ iceServers: [STUN_ONLY[0], turn] }, { status: 201 }));
    const configured = { ...allow, TURN_KEY_ID: "key-id", TURN_KEY_API_TOKEN: "api-token" };
    expect((await create(configured)).ice_servers).toEqual([
      STUN_ONLY[0],
      {
        urls: [
          "turn:turn.cloudflare.com:3478?transport=udp",
          "turn:turn.cloudflare.com:443?transport=udp",
          "turn:turn.cloudflare.com:80?transport=tcp",
          "turns:turn.cloudflare.com:443?transport=tcp",
        ],
        username: "user",
        credential: "secret",
      },
    ]);
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe("https://rtc.live.cloudflare.com/v1/turn/keys/key-id/credentials/generate-ice-servers");
    expect(init).toMatchObject({ method: "POST", headers: { authorization: "Bearer api-token" }, body: JSON.stringify({ ttl: 86400 }) });

    vi.spyOn(console, "error").mockImplementation(() => {});
    fetch.mockResolvedValue(new Response("unavailable", { status: 503 }));
    expect((await create(configured)).ice_servers).toEqual(STUN_ONLY);
  });

  it("deletes a room a minute after its last socket leaves, and any room after half a day", async () => {
    const unused = await create();
    expect(await runDurableObjectAlarm(stub(unused.room_id))).toBe(true);
    expect(await status(unused.room_id)).toEqual({ exists: false, host: false, guest: false });

    const { room, host, guest } = await pair();
    // While players are connected, the alarm only waits for the end of life.
    expect(await runDurableObjectAlarm(stub(room.room_id))).toBe(true);
    expect((await status(room.room_id)).exists).toBe(true);
    guest.ws.close(1000);
    expect(await host.json()).toEqual({ type: "peer", present: false });
    host.ws.close(1000);
    await vi.waitFor(async () => {
      const alarm = await runInDurableObject(stub(room.room_id), (_, state) => state.storage.getAlarm());
      expect(alarm! - Date.now()).toBeLessThanOrEqual(60 * 1000);
    });
    expect(await runDurableObjectAlarm(stub(room.room_id))).toBe(true);
    expect(await status(room.room_id)).toEqual({ exists: false, host: false, guest: false });

    const old = await pair();
    await runInDurableObject(stub(old.room.room_id), async (_, state) => {
      const stored = (await state.storage.get<{ created: number }>("room"))!;
      await state.storage.put("room", { ...stored, created: stored.created - 12 * 60 * 60 * 1000 });
    });
    expect((await status(old.room.room_id)).exists).toBe(false);
    expect((await handshake(old.room.room_id, `role=host&token=${old.room.host_token}`)).status).toBe(404);
    expect(await runDurableObjectAlarm(stub(old.room.room_id))).toBe(true);
    expect(await old.host.closed).toEqual({ code: 4000, reason: "room closed" });
    expect(await runInDurableObject(stub(old.room.room_id), (_, state) => state.storage.list())).toEqual(new Map());
  });
});
