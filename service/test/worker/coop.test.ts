import { env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../../src/index";
import { tokenHash } from "../../src/auth";
import { ROOM_ID, type RoomStatus } from "../../src/coop";
import { concat, COOP_SEAT_DOMAIN, hex } from "../../src/crypto";

const ORIGIN = "https://crimson.land";
const STUN_ONLY = [{ urls: ["stun:stun.cloudflare.com:3478"] }];
// The real limiter keys on the visitor's address, which every test shares.
const allow = { ...env, COOP_ROOM_LIMITER: { limit: async () => ({ success: true }) } };
const call = (path: string, init: RequestInit = {}, bindings: Cloudflare.Env = allow) => worker.fetch(new Request(ORIGIN + path, init), bindings);
const stub = (id: string) => env.COOP_ROOMS.get(env.COOP_ROOMS.idFromName(id));
const ICE = JSON.stringify({ type: "ice" });
const PEER_LEFT = JSON.stringify({ type: "peer", present: false });
const SEED = JSON.stringify({ type: "seed" });
// A socket's first message: its seat, and the challenge it signs to prove its key.
const seat = (role: string) => ({ type: "seat", role, challenge: expect.stringMatching(/^[0-9a-f]{64}$/) });
const TURN = { urls: ["turn:turn.cloudflare.com:3478?transport=udp"], username: "user", credential: "secret" };
// Rooms read their TURN key from the test's own bindings; the Worker routes here get theirs per call.
const configureTurn = () => Object.assign(env, { TURN_KEY_ID: "key-id", TURN_KEY_API_TOKEN: "api-token" });
afterEach(() => {
  vi.restoreAllMocks();
  delete env.TURN_KEY_ID;
  delete env.TURN_KEY_API_TOKEN;
});

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

// Everything a socket receives before `last`.
async function until(peer: Peer, last: string): Promise<(string | ArrayBuffer)[]> {
  const received: (string | ArrayBuffer)[] = [];
  for (let message; (message = await peer.next()) !== last; ) received.push(message);
  return received;
}

async function join(id: string, query: string): Promise<Peer> {
  const response = await handshake(id, query);
  expect(response.status).toBe(101);
  return new Peer(response.webSocket!);
}

interface Seat {
  challenge: string;
  guest_token?: string;
}

// The host and a guest in a fresh room, past their join messages, with the challenges their seats sign.
async function pair() {
  const room = await create();
  const host = await join(room.room_id, `role=host&token=${room.host_token}`);
  const hostSeat = (await host.json()) as Seat;
  expect(hostSeat).toEqual(seat("host"));
  expect(await host.json()).toEqual({ type: "peer", present: false });
  const guest = await join(room.room_id, "role=guest");
  const guestSeat = (await guest.json()) as Seat;
  expect(await guest.json()).toEqual({ type: "peer", present: true });
  expect(await host.json()).toEqual({ type: "peer", present: true });
  return { room, host, guest, guestToken: guestSeat.guest_token!, challenges: { host: hostSeat.challenge, guest: guestSeat.challenge } };
}

// A player's identity key, as the game keeps it.
async function identity() {
  const key = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const publicKey = hex(new Uint8Array((await crypto.subtle.exportKey("raw", key.publicKey)) as ArrayBuffer));
  // The seat's key proof: the key signs the room's id and the socket's challenge.
  const proof = async (roomId: string, challenge: string) => {
    const message = concat(COOP_SEAT_DOMAIN, new TextEncoder().encode(roomId + challenge));
    const signature = hex(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.privateKey, message)));
    return JSON.stringify({ type: "key", public_key: publicKey, signature });
  };
  return { publicKey, proof };
}

// A room whose seats have both proven their keys, past the room's answers.
async function provenPair() {
  const paired = await pair();
  const [hostKey, guestKey] = [await identity(), await identity()];
  paired.host.ws.send(await hostKey.proof(paired.room.room_id, paired.challenges.host));
  const hostProven = { type: "key", role: "host", public_key: hostKey.publicKey };
  expect([await paired.host.json(), await paired.guest.json()]).toEqual([hostProven, hostProven]);
  paired.guest.ws.send(await guestKey.proof(paired.room.room_id, paired.challenges.guest));
  const guestProven = { type: "key", role: "guest", public_key: guestKey.publicKey };
  expect([await paired.host.json(), await paired.guest.json()]).toEqual([guestProven, guestProven]);
  return { ...paired, hostKey, guestKey };
}

const issued = () => env.DB.prepare("SELECT seed, room_id, seat0_key, seat1_key FROM coop_runs ORDER BY issued_at").all().then((result) => result.results);

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
    expect(Object.fromEntries(stored)).toEqual({ room: { id: room.room_id, host: await tokenHash(room.host_token), created: expect.any(Number) } });
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
    expect(await back.json()).toEqual(seat("guest"));
    expect(await back.json()).toEqual({ type: "peer", present: true });
    expect(await host.json()).toEqual({ type: "peer", present: true });

    // A reconnect while the old socket still looks open replaces it without the partner seeing anyone leave.
    const again = await join(room.room_id, `role=guest&token=${guestToken}`);
    expect(await back.closed).toEqual({ code: 4001, reason: "replaced by a new connection" });
    expect(await again.json()).toEqual(seat("guest"));
    expect(await host.json()).toEqual({ type: "peer", present: true });
    again.ws.send("still here");
    expect(await host.next()).toBe("still here");
  });

  it("replaces the host's socket when the host reconnects with its token", async () => {
    const { room, host, guest } = await pair();
    const again = await join(room.room_id, `role=host&token=${room.host_token}`);
    expect(await host.closed).toEqual({ code: 4001, reason: "replaced by a new connection" });
    expect(await again.json()).toEqual(seat("host"));
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

  it("closes a socket that sends more than 16 KiB at once, and relays nothing it sends after", async () => {
    const { host, guest } = await pair();
    host.ws.send(new Uint8Array(16 * 1024 + 1));
    host.ws.send("after the binary");
    expect((await host.closed).code).toBe(1009);
    expect(await guest.next()).toBe(PEER_LEFT);

    // The limit counts UTF-8 bytes: 8193 characters of two bytes each.
    const text = await pair();
    text.host.ws.send("é".repeat(8 * 1024 + 1));
    text.host.ws.send("after the text");
    expect((await text.host.closed).code).toBe(1009);
    expect(await text.guest.next()).toBe(PEER_LEFT);
  });

  it("closes a flooding socket after relaying only its budget", async () => {
    const { host, guest } = await pair();
    const start = Date.now();
    for (let i = 0; i < 400; i++) guest.ws.send(String(i));
    expect((await guest.closed).code).toBe(1008);
    const relayed = await until(host, PEER_LEFT);
    expect(relayed).toEqual(relayed.map((_, i) => String(i)));
    expect(relayed.length).toBeGreaterThanOrEqual(200);
    expect(relayed.length).toBeLessThanOrEqual(200 + ((Date.now() - start) * 200) / 1000);
  }, 30_000);

  it("keeps a seat's message budget across its reconnects, and limits those", async () => {
    const { room, host, guest, guestToken } = await pair();
    const start = Date.now();
    for (let i = 0; i < 190; i++) guest.ws.send(String(i));
    for (let i = 0; i < 190; i++) expect(await host.next()).toBe(String(i));
    const again = await join(room.room_id, `role=guest&token=${guestToken}`);
    expect(await host.json()).toEqual({ type: "peer", present: true });
    for (let i = 190; i < 590; i++) again.ws.send(String(i));
    expect((await again.closed).code).toBe(1008);
    const relayed = await until(host, PEER_LEFT);
    expect(relayed).toEqual(relayed.map((_, i) => String(190 + i)));
    expect(190 + relayed.length).toBeLessThanOrEqual(200 + ((Date.now() - start) * 200) / 1000);

    // The guest has used 2 of its 10 sockets a minute; the host's are its own.
    for (let i = 0; i < 8; i++) await join(room.room_id, `role=guest&token=${guestToken}`);
    expect((await handshake(room.room_id, `role=guest&token=${guestToken}`)).status).toBe(429);
    await join(room.room_id, `role=host&token=${room.host_token}`);
  }, 30_000);

  it("closes a socket that sends a message passing for the room's own", async () => {
    for (const forged of [{ type: "peer", present: true }, { type: "seat", role: "host" }]) {
      const { host, guest } = await pair();
      guest.ws.send(JSON.stringify(forged));
      expect(await guest.closed).toEqual({ code: 1008, reason: `${forged.type} messages are the room's` });
      expect(await host.next()).toBe(PEER_LEFT);
    }
  });

  it("records each seat's key once it signs its socket's challenge with it, and tells both seats", async () => {
    const { room, host, guest, guestToken, challenges } = await provenPair();
    expect(host.pending() + guest.pending()).toBe(0);
    // Proofs are the room's to answer: the partner never sees the request itself.
    host.ws.send("after");
    expect(await guest.next()).toBe("after");

    // A reconnect proves its seat's key again on its own challenge, and keeps the seat only with the same key.
    const stored = await runInDurableObject(stub(room.room_id), (_, state) => state.storage.get(["key:host", "key:guest"]));
    const back = await join(room.room_id, `role=guest&token=${guestToken}`);
    const { challenge } = (await back.json()) as Seat;
    expect(challenge).not.toBe(challenges.guest);
    expect(await back.json()).toEqual({ type: "peer", present: true });
    expect(await host.json()).toEqual({ type: "peer", present: true });
    back.ws.send(await (await identity()).proof(room.room_id, challenge));
    expect(await back.closed).toEqual({ code: 1008, reason: "this seat proved another key" });
    expect(await host.next()).toBe(PEER_LEFT);
    expect(await runInDurableObject(stub(room.room_id), (_, state) => state.storage.get(["key:host", "key:guest"]))).toEqual(stored);
  });

  it("refuses a key proof that does not verify, signs another room or repeats on its socket", async () => {
    const key = await identity();
    const other = await create();
    const refusals: [string, (room: string, challenges: Record<string, string>) => Promise<string>, string][] = [
      ["bad signature", async (room, challenges) => key.proof(room, challenges.guest!.replace(/^./, (ch) => (ch === "0" ? "1" : "0"))), "key proof does not verify"],
      ["wrong room id", async (_, challenges) => key.proof(other.room_id, challenges.guest!), "key proof does not verify"],
      ["host's challenge", async (room, challenges) => key.proof(room, challenges.host!), "key proof does not verify"],
      ["malformed key", async () => JSON.stringify({ type: "key", public_key: "ab", signature: "00".repeat(64) }), "key proof does not verify"],
    ];
    for (const [, proof, reason] of refusals) {
      const { room, host, guest, challenges } = await pair();
      guest.ws.send(await proof(room.room_id, challenges));
      expect(await guest.closed).toEqual({ code: 1008, reason });
      expect(await host.next()).toBe(PEER_LEFT);
      expect(await runInDurableObject(stub(room.room_id), (_, state) => state.storage.get("key:guest"))).toBeUndefined();
    }

    const { room, host, guest, challenges } = await pair();
    guest.ws.send(await key.proof(room.room_id, challenges.guest));
    await guest.json();
    await host.json();
    guest.ws.send(await key.proof(room.room_id, challenges.guest));
    expect(await guest.closed).toEqual({ code: 1008, reason: "a socket proves its key once" });
  });

  it("issues the host a seed only once both seats proved keys, to both seats, recorded with their keys", async () => {
    // Before both seats proved keys, and from the guest, a seed request closes the socket.
    const early = await pair();
    early.host.ws.send(await (await identity()).proof(early.room.room_id, early.challenges.host));
    await early.host.json();
    await early.guest.json();
    early.host.ws.send(SEED);
    expect(await early.host.closed).toEqual({ code: 1008, reason: "both seats prove their keys before a seed" });
    const { room, host, guest, guestToken, hostKey, guestKey } = await provenPair();
    guest.ws.send(SEED);
    expect(await guest.closed).toEqual({ code: 1008, reason: "only the host asks for a seed" });
    expect(await host.next()).toBe(PEER_LEFT);
    expect(await issued()).toEqual([]);

    // The guest's seat keeps its key across the reconnect, and both seats hear the seed.
    const again = await join(room.room_id, `role=guest&token=${guestToken}`);
    expect(await again.json()).toEqual(seat("guest"));
    expect(await again.json()).toEqual({ type: "peer", present: true });
    expect(await host.json()).toEqual({ type: "peer", present: true });
    host.ws.send(SEED);
    const { seed } = (await host.json()) as { seed: number };
    expect(await again.json()).toEqual({ type: "seed", seed });
    expect(seed >>> 0).toBe(seed);
    expect(await issued()).toEqual([{ seed, room_id: room.room_id, seat0_key: hostKey.publicKey, seat1_key: guestKey.publicKey }]);

    // A seed already issued is drawn again.
    const draw = vi.spyOn(crypto, "getRandomValues").mockImplementationOnce((array) => (new Uint32Array(array.buffer).set([seed]), array));
    host.ws.send(SEED);
    const next = ((await host.json()) as { seed: number }).seed;
    expect(await again.json()).toEqual({ type: "seed", seed: next });
    expect([next === seed, draw.mock.calls.length]).toEqual([false, 2]);
    expect((await issued()).map((row) => row.seed)).toEqual([seed, next]);
    expect(host.pending() + again.pending()).toBe(0);
  });

  it("issues seeds with bit 31 clear, which rand never reads", async () => {
    const { host, guest } = await provenPair();
    vi.spyOn(crypto, "getRandomValues").mockImplementationOnce((array) => (new Uint32Array(array.buffer).set([0xffffffff]), array));
    host.ws.send(SEED);
    const issuedSeed = { type: "seed", seed: 0x7fffffff };
    expect([await host.json(), await guest.json()]).toEqual([issuedSeed, issuedSeed]);
    expect((await issued()).map((row) => row.seed)).toEqual([0x7fffffff]);
  });

  it("limits the host to ten seeds a minute", async () => {
    const { host } = await provenPair();
    for (let i = 0; i < 10; i++) {
      host.ws.send(SEED);
      expect(await host.json()).toMatchObject({ type: "seed" });
    }
    host.ws.send(SEED);
    expect(await host.closed).toEqual({ code: 1008, reason: "too many seeds" });
    expect(await issued()).toHaveLength(10);
  });

  it("tells the partner once when a socket both fails and closes", async () => {
    const { room, host } = await pair();
    await runInDurableObject(stub(room.room_id), async (instance, state) => {
      const [ws] = state.getWebSockets("guest");
      await instance.webSocketError(ws!);
      await instance.webSocketClose(ws!);
    });
    expect(await host.next()).toBe(PEER_LEFT);
    host.ws.send(ICE);
    expect(await host.json()).toEqual({ type: "ice", ice_servers: STUN_ONLY });
  });

  it("answers an ICE request itself and keeps it from the partner", async () => {
    const { host, guest } = await pair();
    guest.ws.send(ICE);
    expect(await guest.json()).toEqual({ type: "ice", ice_servers: STUN_ONLY });
    host.ws.send("after");
    expect(await guest.next()).toBe("after");
    expect(host.pending()).toBe(0);
  });

  it("mints TURN credentials for a room at most every ten seconds, however its seats ask", async () => {
    configureTurn();
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => Response.json({ iceServers: [TURN] }));
    const { room, host, guest, guestToken } = await pair();
    const answer = { type: "ice", ice_servers: [TURN] };
    // Requests while the first mint is under way share it.
    for (let i = 0; i < 20; i++) guest.ws.send(ICE);
    host.ws.send(ICE);
    for (let i = 0; i < 20; i++) expect(await guest.json()).toEqual(answer);
    expect(await host.json()).toEqual(answer);
    // A reconnect does not start the wait over.
    const again = await join(room.room_id, `role=guest&token=${guestToken}`);
    expect(await again.json()).toEqual(seat("guest"));
    expect(await again.json()).toEqual({ type: "peer", present: true });
    again.ws.send(ICE);
    expect(await again.json()).toEqual(answer);
    expect(fetch).toHaveBeenCalledTimes(1);

    const later = Date.now() + 10 * 1000;
    vi.spyOn(Date, "now").mockReturnValue(later);
    again.ws.send(ICE);
    expect(await again.json()).toEqual(answer);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("answers an ICE request with STUN when the TURN service cannot be reached", async () => {
    configureTurn();
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("network connection lost"));
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const { guest } = await pair();
    guest.ws.send(ICE);
    expect(await guest.json()).toEqual({ type: "ice", ice_servers: STUN_ONLY });
    expect(error).toHaveBeenCalledWith("TURN credentials: TypeError: network connection lost");
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
    // A server left with only port 53 is dropped whole.
    const blocked = { urls: ["turn:turn.cloudflare.com:53?transport=udp"], username: "user", credential: "secret" };
    const fetch = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(Response.json({ iceServers: [STUN_ONLY[0], turn, blocked] }, { status: 201 }));
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

    // Every failure still makes the room, with STUN only.
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    fetch.mockResolvedValue(new Response("unavailable", { status: 503 }));
    expect((await create(configured)).ice_servers).toEqual(STUN_ONLY);
    fetch.mockRejectedValue(new TypeError("network connection lost"));
    expect((await create(configured)).ice_servers).toEqual(STUN_ONLY);
    fetch.mockResolvedValue(new Response("<html>", { status: 200 }));
    expect((await create(configured)).ice_servers).toEqual(STUN_ONLY);
    fetch.mockResolvedValue(Response.json({ iceServers: { urls: [] } }));
    expect((await create(configured)).ice_servers).toEqual(STUN_ONLY);
    expect(error).toHaveBeenCalledTimes(4);
    // A single URL string is a valid entry; entries without usable URLs are dropped.
    fetch.mockResolvedValue(Response.json({ iceServers: [null, {}, { urls: "stun:stun.cloudflare.com:3478" }, { urls: [7] }] }));
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
