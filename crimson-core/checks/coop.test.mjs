// Run the embedded co-op transport between two pages: a fake room service with the
// real one's routes, seats and messages (service/src/coop.ts), and fake peer
// connections that link each other through what the pages signal.
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../client/web/coop.js", import.meta.url), "utf8");
const ORIGIN = "https://crimson.land";
const HOST_ICE = [{ urls: ["stun:stun.example:3478"] }];
const GUEST_ICE = [{ urls: ["turn:turn.example:3478?transport=udp"], username: "u", credential: "c" }];

const tick = () => new Promise((resolve) => setImmediate(resolve));
async function settle() {
  for (let i = 0; i < 60; ++i) await tick();
}
const other = (role) => (role === "host" ? "guest" : "host");

// Timers run only when a test advances the clock; sockets and peer connections deliver on the event loop.
function clock() {
  let time = 0, nextId = 1;
  const timers = new Map();
  return {
    now: () => time,
    setTimeout: (fn, ms) => { timers.set(nextId, { at: time + ms, fn }); return nextId++; },
    clearTimeout: (id) => timers.delete(id),
    pending: () => timers.size,
    async advance(ms) {
      const end = time + ms;
      for (;;) {
        const [id, due] = [...timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0] ?? [];
        if (!due) break;
        timers.delete(id);
        time = due.at;
        due.fn();
        await settle();
      }
      time = end;
      await settle();
    },
  };
}

// The room service: POST and GET room routes, seat sockets, relay, peer and ice messages.
function service() {
  const rooms = new Map();
  const world = { rooms, fetches: [], sockets: [], texts: [], frames: [], down: false, observe: () => {} };
  let count = 0;
  const reply = (status, body) => ({ ok: status < 300, status, json: async () => structuredClone(body) });
  world.fetch = async (path, init = {}) => {
    world.fetches.push({ path, init });
    if (path === "/api/coop/rooms" && init.method === "POST") {
      const id = `room${String(++count).padStart(6, "0")}`;
      rooms.set(id, { id, hostToken: `host-token-${id}`, guestToken: null, seats: { host: null, guest: null } });
      return reply(201, { room_id: id, host_token: `host-token-${id}`, invite_url: `${ORIGIN}/play/?coop=${id}`, ice_servers: HOST_ICE });
    }
    const match = /^\/api\/coop\/rooms\/([^/]+)$/.exec(path);
    if (match && !init.method) {
      const room = rooms.get(decodeURIComponent(match[1]));
      return reply(200, { exists: !!room, host: !!room?.seats.host, guest: !!room?.guestToken });
    }
    return reply(404, { error: "no such endpoint" });
  };
  const push = (ws, data) => setImmediate(() => {
    if (ws.readyState !== 1) return;
    if (typeof data === "string") world.observe(ws.role, JSON.parse(data));
    ws.onmessage?.({ data });
  });
  function serverClose(ws, code, reason = "") {
    if (ws.readyState === 3) return;
    ws.readyState = 3;
    setImmediate(() => { left(ws); ws.onclose?.({ code, reason }); });
  }
  function left(ws) {
    const room = ws.room;
    if (!room || room.seats[ws.role] !== ws) return;
    room.seats[ws.role] = null;
    const partner = room.seats[other(ws.role)];
    if (partner) push(partner, JSON.stringify({ type: "peer", present: false }));
  }
  function accept(ws) {
    const url = new URL(ws.url);
    const [, , , , id] = url.pathname.split("/");
    const role = url.searchParams.get("role"), token = url.searchParams.get("token");
    const room = rooms.get(id);
    // A refused handshake reads as an abnormal close in the browser.
    if (world.down || !room || (role === "host" && token !== room.hostToken) || (role === "guest" && room.guestToken && token !== room.guestToken)) {
      ws.readyState = 3;
      return ws.onclose?.({ code: 1006, reason: "" });
    }
    let guestToken;
    if (role === "guest" && !room.guestToken) guestToken = room.guestToken = `guest-token-${id}-${++count}`;
    const old = room.seats[role];
    Object.assign(ws, { readyState: 1, role, room });
    room.seats[role] = ws;
    if (old) serverClose(old, 4001, "replaced by a new connection");
    push(ws, JSON.stringify({ type: "seat", role, ...(guestToken && { guest_token: guestToken }) }));
    const partner = room.seats[other(role)];
    push(ws, JSON.stringify({ type: "peer", present: !!partner }));
    if (partner) push(partner, JSON.stringify({ type: "peer", present: true }));
  }
  function serverReceive(ws, data) {
    if (ws.readyState !== 1) return;
    const partner = ws.room.seats[other(ws.role)];
    if (typeof data === "string") {
      const message = JSON.parse(data);
      world.texts.push({ from: ws.role, ...message });
      if (message.type === "ice") return push(ws, JSON.stringify({ type: "ice", ice_servers: GUEST_ICE }));
      if (message.type === "seat" || message.type === "peer") return serverClose(ws, 1008);
      if (partner) push(partner, data);
    } else {
      const bytes = new Uint8Array(data).slice();
      world.frames.push({ from: ws.role, bytes: [...bytes] });
      if (partner) push(partner, bytes.buffer);
    }
  }
  world.WebSocket = class FakeWebSocket {
    constructor(url) {
      Object.assign(this, { url, readyState: 0, bufferedAmount: 0, binaryType: "blob" });
      world.sockets.push(this);
      setImmediate(() => accept(this));
    }
    send(data) {
      assert.equal(this.readyState, 1, "sent on an open socket");
      setImmediate(() => serverReceive(this, typeof data === "string" ? data : new Uint8Array(data).slice()));
    }
    close(code, reason) {
      this.closedWith = code;
      serverClose(this, code, reason);
    }
  };
  world.seat = (id, role) => rooms.get(id).seats[role];
  // A message from the partner's seat, as the room relays it.
  world.inject = (id, role, message) => push(world.seat(id, role), JSON.stringify(message));
  // The connection drops under a page (its network, or the room's end).
  world.drop = (id, role, code = 1006) => serverClose(world.seat(id, role), code);
  return world;
}

// Peer connections that link the two pages through the descriptions they exchange. outcome: "connect",
// "fail" (both fail), "fail-host" (only the host's fails), or "hang" (never connects).
function network({ outcome = "connect", remoteDelay = 0, candidateType = "srflx", relayProtocol } = {}) {
  const net = { pcs: [], early: 0, added: 0, outcome };
  class FakeChannel {
    constructor(pc, label, options) {
      Object.assign(this, { pc, label, options, readyState: "connecting", bufferedAmount: 0, binaryType: "blob" });
    }
    send(data) {
      if (this.readyState !== "open") throw Error("InvalidStateError: channel not open");
      const target = this.pc.peer?.channels[this.options.id];
      const buffer = new Uint8Array(data).slice().buffer;
      setImmediate(() => { if (target?.readyState === "open") target.onmessage?.({ data: buffer }); });
    }
    close() { this.readyState = "closed"; }
  }
  const forOwner = (owner) => class FakePeerConnection {
    constructor(config) {
      Object.assign(this, { owner, config, channels: [], localDescription: null, remoteDescription: null, connectionState: "new", candidates: 0, peer: null, closed: false });
      this.id = net.pcs.push(this);
    }
    createDataChannel(label, options) {
      const channel = new FakeChannel(this, label, options);
      this.channels[options.id] = channel;
      return channel;
    }
    async createOffer() { return { type: "offer", sdp: `fake ${this.id}` }; }
    async createAnswer() { return { type: "answer", sdp: `fake ${this.id}` }; }
    async setLocalDescription(description) {
      if (this.closed) throw Error("closed");
      this.localDescription = description;
      setImmediate(() => {
        if (this.closed) return;
        this.onicecandidate?.({ candidate: { toJSON: () => ({ candidate: `candidate ${this.id}`, sdpMid: "0" }) } });
        this.onicecandidate?.({ candidate: null });
      });
      this.ready();
    }
    async setRemoteDescription(description) {
      if (this.closed) throw Error("closed");
      this.pendingRemote = true;
      for (let i = 0; i < remoteDelay; ++i) await tick();
      this.pendingRemote = false;
      this.remoteDescription = description;
      this.peer = net.pcs[Number(description.sdp.split(" ")[1]) - 1];
      this.ready();
    }
    async addIceCandidate() {
      if (this.closed) throw Error("closed");
      if (!this.remoteDescription) {
        ++net.early;
        throw Error("InvalidStateError: no remote description");
      }
      ++net.added;
      ++this.candidates;
      this.ready();
    }
    // ICE completes once both sides hold both descriptions and a candidate of the other's.
    ready() {
      const both = [this, this.peer];
      if (!both.every((pc) => pc && pc.localDescription && pc.remoteDescription && pc.candidates && pc.connectionState === "new")) return;
      for (const pc of both) pc.connectionState = "connecting";
      setImmediate(() => {
        for (const pc of both) {
          if (pc.closed) continue;
          const fails = net.outcome === "fail" || (net.outcome === "fail-host" && pc.owner === "host");
          if (net.outcome === "hang" || (net.outcome === "fail-host" && !fails)) continue;
          pc.connectionState = fails ? "failed" : "connected";
          pc.onconnectionstatechange?.();
          if (fails) continue;
          for (const channel of pc.channels) {
            channel.readyState = "open";
            channel.onopen?.();
          }
        }
      });
    }
    async getStats() {
      return new Map([
        ["T", { type: "transport", selectedCandidatePairId: "P" }],
        ["P", { type: "candidate-pair", localCandidateId: "L" }],
        ["L", { type: "local-candidate", candidateType, relayProtocol }],
      ]);
    }
    close() {
      this.closed = true;
      this.connectionState = "closed";
      for (const channel of this.channels) channel.close();
      // The partner's channels close with the connection.
      for (const channel of this.peer?.channels ?? []) {
        if (channel.readyState !== "open") continue;
        channel.readyState = "closed";
        setImmediate(() => channel.onclose?.());
      }
    }
  };
  net.RTC = forOwner;
  return net;
}

function sessionStore() {
  const values = new Map();
  return { values, getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, String(value)) };
}

function setup(options = {}) {
  const world = service(), net = network(options), time = clock();
  function page(owner, { store = sessionStore(), RTCPeerConnection = net.RTC(owner), listen = true } = {}) {
    const events = { states: [], peers: [], messages: [], logs: [] };
    const context = vm.createContext({});
    vm.runInContext(source, context);
    // The page's sockets carry its events, so a test can find and drop them.
    const WebSocket = class extends world.WebSocket {
      constructor(url) {
        super(url);
        this.owner = events;
      }
    };
    const coop = context.createCoop({
      fetch: world.fetch, WebSocket, RTCPeerConnection, sessionStorage: store,
      location: { protocol: "https:", host: "crimson.land" },
      setTimeout: time.setTimeout, clearTimeout: time.clearTimeout, now: time.now,
      log: (...args) => events.logs.push(args.join(" ")),
    });
    coop.onstate = (state, reason) => events.states.push(reason ? `${state}: ${reason}` : state);
    coop.onpeer = (present) => events.peers.push(present);
    const listener = (channel, bytes) => events.messages.push([channel, [...bytes]]);
    if (listen) coop.onmessage = listener;
    // A reload or a closed tab: the page vanishes without a word, its sockets and connections with it.
    const vanish = () => {
      for (const ws of world.sockets.filter((ws) => ws.owner === events)) {
        ws.onclose = ws.onmessage = null;
        if (ws.readyState === 1) world.drop(ws.room.id, ws.role);
      }
      for (const pc of net.pcs.filter((pc) => pc.owner === owner && !pc.closed)) pc.close();
    };
    return { coop, store, events, listener, vanish };
  }
  return { world, net, time, page };
}

async function meet(env, { hostPage = env.page("host"), guestPage = env.page("guest") } = {}) {
  await hostPage.coop.host();
  await settle();
  await guestPage.coop.join(hostPage.coop.room);
  await settle();
  return { host: hostPage, guest: guestPage };
}
const bytes = (...values) => new Uint8Array(values);
// Values made inside the page's realm, compared as plain data.
const plain = (value) => JSON.parse(JSON.stringify(value));
async function exchange(host, guest) {
  host.events.messages.length = guest.events.messages.length = 0;
  assert.ok(host.coop.send(0, bytes(1, 2, 3)));
  assert.ok(host.coop.send(1, bytes(4)));
  assert.ok(guest.coop.send(1, bytes(5, 6)));
  assert.ok(guest.coop.send(0, bytes(7)));
  await settle();
  assert.deepEqual(guest.events.messages, [[0, [1, 2, 3]], [1, [4]]]);
  assert.deepEqual(host.events.messages, [[1, [5, 6]], [0, [7]]]);
}

test("host and guest meet in a room, connect over WebRTC and exchange bytes on both channels", async () => {
  const env = setup();
  const host = env.page("host");
  const invite = await host.coop.host();
  await settle();
  assert.equal(host.coop.state, "waiting");
  assert.equal(invite, `${ORIGIN}/play/?coop=${host.coop.room}`);
  assert.equal(host.coop.inviteUrl, invite);
  const guest = env.page("guest");
  await guest.coop.join(host.coop.room);
  await settle();
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.deepEqual(host.events.states, ["opening", "waiting", "connecting", "connected"]);
  assert.deepEqual(guest.events.states, ["opening", "connecting", "connected"]);
  assert.deepEqual(host.events.peers, [true]);
  assert.deepEqual(guest.events.peers, [true]);
  await exchange(host, guest);
  assert.deepEqual(env.world.frames, [], "nothing went through the relay");
  assert.equal(host.coop.stats().transport, "srflx");
  assert.deepEqual(plain(host.coop.stats().sent), [1, 1]);
  assert.deepEqual(plain(guest.coop.stats().received), [1, 1]);

  // Requests omit credentials; the host token stays out of the invite and in this tab's storage; the guest
  // stores the token the room gave it.
  assert.ok(env.world.fetches.every(({ init }) => init.credentials === "omit"));
  const [hostSocket, guestSocket] = env.world.sockets;
  assert.equal(hostSocket.url, `wss://crimson.land/api/coop/rooms/${host.coop.room}/ws?role=host&token=host-token-${host.coop.room}`);
  assert.equal(guestSocket.url, `wss://crimson.land/api/coop/rooms/${host.coop.room}/ws?role=guest`);
  assert.ok(env.world.sockets.every((ws) => ws.binaryType === "arraybuffer"));
  assert.ok(!invite.includes("token"));
  assert.deepEqual(JSON.parse(host.store.getItem(`crimson.coop.${host.coop.room}`)), { role: "host", token: `host-token-${host.coop.room}` });
  assert.equal(JSON.parse(guest.store.getItem(`crimson.coop.${host.coop.room}`)).token, env.world.rooms.get(host.coop.room).guestToken);

  // The guest asked for its own ICE servers once; the host used the room's answer to POST.
  assert.deepEqual(env.world.texts.filter((text) => text.type === "ice").map((text) => text.from), ["guest"]);
  const [hostPc, guestPc] = env.net.pcs;
  assert.deepEqual(plain(hostPc.config), { iceServers: HOST_ICE });
  assert.deepEqual(plain(guestPc.config), { iceServers: GUEST_ICE });
  for (const pc of [hostPc, guestPc]) {
    assert.deepEqual(pc.channels.map((channel) => [channel.label, plain(channel.options)]), [
      ["coop-ticks", { ordered: false, maxRetransmits: 0, negotiated: true, id: 0 }],
      ["coop-control", { ordered: true, negotiated: true, id: 1 }],
    ]);
  }
  // Signalling avoids the room's reserved types, and every message names the host's link.
  const signals = env.world.texts.filter((text) => text.type !== "ice");
  assert.deepEqual([...new Set(signals.map((text) => `${text.from} ${text.type}`))].sort(), ["guest answer", "guest candidate", "host candidate", "host offer"]);
  assert.equal(new Set(signals.map((text) => text.link)).size, 1);
});

test("candidates that arrive before the remote description wait for it", async () => {
  const env = setup({ remoteDelay: 8 });
  let early = 0;
  env.world.observe = (role, message) => {
    if (message.type === "candidate" && env.net.pcs.some((pc) => pc.owner === role && pc.pendingRemote)) ++early;
  };
  const { host, guest } = await meet(env);
  assert.ok(early > 0, "a candidate arrived while its page was still setting the remote description");
  assert.equal(env.net.early, 0, "no candidate was added before the remote description");
  assert.ok(env.net.added >= 2);
  assert.equal(host.coop.state, "connected");
  await exchange(host, guest);
});

test("an unknown room and a taken guest seat are refused before any socket opens", async () => {
  const env = setup();
  const lost = env.page("guest");
  await lost.coop.join("nosuchroom");
  assert.equal(lost.coop.state, "error");
  assert.equal(lost.coop.reason, "no such room");
  assert.equal(env.world.sockets.length, 0);

  const { host } = await meet(env);
  const third = env.page("third");
  const sockets = env.world.sockets.length;
  await third.coop.join(host.coop.room);
  assert.deepEqual(third.events.states, ["opening", "error: room full"]);
  assert.equal(env.world.sockets.length, sockets);
  await assert.rejects(third.coop.join(host.coop.room), /already started/);
});

test("a reloaded guest takes its seat back with the stored token and both pages renegotiate", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  guest.vanish();
  await settle();
  assert.equal(host.coop.state, "waiting");
  assert.deepEqual(host.events.peers, [true, false]);

  const reloaded = env.page("guest", { store: guest.store });
  await reloaded.coop.join(host.coop.room);
  await settle();
  assert.match(env.world.sockets.at(-1).url, /role=guest&token=guest-token-/);
  assert.equal(reloaded.coop.state, "connected");
  assert.equal(host.coop.state, "connected");
  assert.deepEqual(host.events.peers, [true, false, true]);
  assert.equal(host.coop.stats().links, 2);
  await exchange(host, reloaded);
});

test("a reloaded host takes its seat back from the same tab's storage", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  host.vanish();
  await settle();
  assert.equal(guest.coop.state, "waiting");

  const reloaded = env.page("host", { store: host.store });
  await reloaded.coop.join(host.coop.room);
  await settle();
  assert.equal(reloaded.coop.role, "host");
  assert.match(env.world.sockets.at(-1).url, /role=host&token=host-token-/);
  // It asks the room for ICE servers, having lost the ones its POST returned.
  assert.deepEqual(env.world.texts.filter((text) => text.type === "ice").map((text) => text.from), ["guest", "host"]);
  assert.equal(reloaded.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.deepEqual(guest.events.peers, [true, false, true]);
  await exchange(reloaded, guest);
});

test("a repeated present partner renegotiates; the replaced page stops", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  // A duplicated tab copies session storage and takes the seat over.
  const duplicate = env.page("guest", { store: guest.store });
  await duplicate.coop.join(host.coop.room);
  await settle();
  assert.deepEqual(host.events.peers, [true, true]);
  assert.equal(guest.coop.state, "error");
  assert.equal(guest.coop.reason, "the room was opened in another tab");
  assert.equal(duplicate.coop.state, "connected");
  assert.equal(host.coop.state, "connected");
  await exchange(host, duplicate);
  assert.equal(env.time.pending(), 0, "the replaced page does not try to reconnect");
});

test("signalling for another link is stale and ignored", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  const added = env.net.added;
  env.world.inject(host.coop.room, "host", { type: "candidate", link: "old", candidate: { candidate: "candidate 9", sdpMid: "0" } });
  env.world.inject(host.coop.room, "host", { type: "switch", link: "old", transport_epoch: 5 });
  await settle();
  assert.equal(env.net.added, added);
  assert.equal(host.coop.stats().transport, "srflx");
  await exchange(host, guest);
});

test("a failed peer connection moves both pages to the room relay, the other page answering", async () => {
  const env = setup({ outcome: "fail-host" });
  const { host, guest } = await meet(env);
  const switches = env.world.texts.filter((text) => text.type === "switch");
  assert.deepEqual(switches.map(({ from, transport_epoch }) => [from, transport_epoch]), [["host", 1], ["guest", 1]]);
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.equal(guest.coop.stats().transport, "ws-relay");
  assert.ok(env.net.pcs.every((pc) => pc.closed));
  await exchange(host, guest);
  // Relayed frames are [u8 channel][payload].
  assert.deepEqual(env.world.frames, [
    { from: "host", bytes: [0, 1, 2, 3] },
    { from: "host", bytes: [1, 4] },
    { from: "guest", bytes: [1, 5, 6] },
    { from: "guest", bytes: [0, 7] },
  ]);
});

test("a connection that never completes falls back after the timeout; simultaneous decisions agree", async () => {
  const env = setup({ outcome: "hang" });
  const { host, guest } = await meet(env);
  assert.equal(host.coop.state, "connecting");
  await env.time.advance(9999);
  assert.equal(host.coop.state, "connecting");
  await env.time.advance(1);
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.deepEqual(env.world.texts.filter((text) => text.type === "switch").map((text) => text.from), ["host", "guest"]);
  await exchange(host, guest);

  // Both pages give up at once: each sends the same epoch and neither needs an answer.
  const both = setup({ outcome: "fail" });
  const pair = await meet(both);
  assert.deepEqual(both.world.texts.filter((text) => text.type === "switch").map((text) => text.transport_epoch), [1, 1]);
  assert.equal(pair.host.coop.stats().transport, "ws-relay");
  assert.equal(pair.guest.coop.stats().transport, "ws-relay");
  await exchange(pair.host, pair.guest);
});

test("a page without WebRTC plays over the relay", async () => {
  const env = setup();
  const { host, guest } = await meet(env, { guestPage: env.page("guest", { RTCPeerConnection: null }) });
  assert.deepEqual(env.world.texts.filter((text) => text.type === "switch").map(({ from, transport_epoch }) => [from, transport_epoch]), [["guest", 1], ["host", 1]]);
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.equal(guest.coop.stats().transport, "ws-relay");
  await exchange(host, guest);
});

test("relayed ticks are paced and size-capped; control messages always go", async () => {
  const env = setup({ outcome: "fail" });
  const { host, guest } = await meet(env);
  assert.ok(host.coop.send(0, bytes(1)));
  assert.equal(host.coop.send(0, bytes(2)), false, "a second tick packet within the relay's pace drops");
  assert.ok(host.coop.send(1, bytes(3)));
  assert.ok(host.coop.send(1, bytes(4)));
  await env.time.advance(10);
  assert.ok(host.coop.send(0, bytes(5)));
  env.world.seat(host.coop.room, "host").bufferedAmount = 1 << 20;
  await env.time.advance(10);
  assert.equal(host.coop.send(0, bytes(6)), false, "a backed-up socket drops ticks");
  assert.ok(host.coop.send(1, bytes(7)));
  assert.equal(host.coop.send(1, new Uint8Array(16 * 1024)), false, "the room would close the socket for this");
  await settle();
  assert.deepEqual(guest.events.messages, [[0, [1]], [1, [3]], [1, [4]], [0, [5]], [1, [7]]]);
  assert.equal(host.coop.stats().dropped, 2);
});

test("a backed-up ticks channel drops ticks, never control messages", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  const hostPc = env.net.pcs.find((pc) => pc.owner === "host");
  hostPc.channels[0].bufferedAmount = hostPc.channels[1].bufferedAmount = 1 << 20;
  assert.equal(host.coop.send(0, bytes(1)), false);
  assert.ok(host.coop.send(1, bytes(2)));
  await settle();
  assert.deepEqual(guest.events.messages, [[1, [2]]]);
  assert.equal(host.coop.stats().dropped, 1);
});

test("messages before the game listens wait in order for its handler", async () => {
  const env = setup();
  const { host, guest } = await meet(env, { guestPage: env.page("guest", { listen: false }) });
  host.coop.send(1, bytes(1));
  host.coop.send(0, bytes(2));
  host.coop.send(1, bytes(3));
  await settle();
  assert.equal(guest.coop.stats().inbox, 3);
  guest.coop.onmessage = guest.listener;
  assert.deepEqual(guest.events.messages, [[1, [1]], [0, [2]], [1, [3]]]);
  assert.equal(guest.coop.stats().inbox, 0);
});

test("a lost room socket reconnects with backoff and its stored token, then renegotiates", async () => {
  const env = setup({ outcome: "fail" });
  const { host, guest } = await meet(env);
  assert.equal(host.coop.stats().transport, "ws-relay");
  env.world.down = true;
  env.world.drop(host.coop.room, "host");
  await settle();
  assert.equal(host.coop.state, "reconnecting");
  assert.equal(host.coop.send(1, bytes(1)), false, "the relay is down with its socket");
  assert.equal(guest.coop.state, "waiting");
  const sockets = env.world.sockets.length;
  await env.time.advance(1000);
  await env.time.advance(2000);
  assert.equal(env.world.sockets.length, sockets + 2, "refused attempts back off");
  assert.equal(host.coop.state, "reconnecting");
  env.world.down = false;
  env.net.outcome = "connect";
  await env.time.advance(3999);
  assert.equal(env.world.sockets.length, sockets + 2);
  await env.time.advance(1);
  assert.equal(env.world.sockets.length, sockets + 3);
  assert.match(env.world.sockets.at(-1).url, /role=host&token=host-token-/);
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.equal(host.coop.stats().transport, "srflx");
  assert.equal(host.coop.stats().reconnects, 3);
  assert.deepEqual(host.events.states.slice(-3), ["reconnecting", "connecting", "connected"]);
  // The partner was there before and after: no news for the game.
  assert.deepEqual(host.events.peers, [true]);
  assert.deepEqual(guest.events.peers, [true, false, true]);
  await exchange(host, guest);
});

test("a closed room ends the session without reconnecting", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  env.world.drop(host.coop.room, "host", 4000);
  env.world.drop(host.coop.room, "guest", 4000);
  await settle();
  assert.equal(host.coop.reason, "the room closed");
  assert.equal(guest.coop.reason, "the room closed");
  assert.equal(env.time.pending(), 0);
});

test("close() ends everything, tells the partner and keeps the seat token", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  const room = host.coop.room;
  guest.coop.close();
  await settle();
  assert.equal(guest.coop.state, "closed");
  assert.equal(env.world.seat(room, "guest"), null);
  assert.equal(env.world.sockets.find((ws) => ws.owner === guest.events).closedWith, 1000);
  assert.ok(env.net.pcs.every((pc) => pc.closed));
  assert.equal(guest.coop.send(1, bytes(1)), false);
  assert.equal(host.coop.state, "waiting");
  assert.deepEqual(host.events.peers, [true, false]);
  assert.equal(env.time.pending(), 0);
  assert.ok(JSON.parse(guest.store.getItem(`crimson.coop.${room}`)).token, "the seat stays this tab's to take back");
  await env.time.advance(60000);
  assert.equal(guest.coop.state, "closed");
});
