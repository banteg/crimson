// Run the embedded co-op transport between two pages: a fake room service with the
// real one's routes, room ids, seats, messages and limits (service/src/coop.ts), and
// fake peer connections that link each other through what the pages signal.
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../client/web/coop.js", import.meta.url), "utf8");
const room = fs.readFileSync(new URL("../../service/src/coop.ts", import.meta.url), "utf8");
const constant = (name) => new RegExp(`const ${name} = (.+);`).exec(room)[1];
const product = (expression) => expression.split("*").reduce((value, factor) => value * Number(factor), 1);
const ROOM_ID = new RegExp(/^\/(.+)\/$/.exec(constant("ROOM_ID"))[1]);
const ROOM_ALPHABET = JSON.parse(constant("ROOM_ALPHABET"));
const MAX_MESSAGE_BYTES = product(constant("MAX_MESSAGE_BYTES"));
const MESSAGES_PER_SECOND = product(constant("MESSAGES_PER_SECOND"));
const ORIGIN = "https://crimson.land";
const HOST_ICE = [{ urls: ["stun:stun.example:3478"] }];
const GUEST_ICE = [{ urls: ["turn:turn.example:3478?transport=udp"], username: "u", credential: "c" }];
const CONTROL_HEADER = 16;

const it = (name, fn) => test(name, { timeout: 20000 }, fn);
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function settle() {
  for (let i = 0; i < 150; ++i) await tick();
}
const other = (role) => (role === "host" ? "guest" : "host");

// Timers run only when a test advances the clock; sockets and peer connections deliver on the event loop. Each
// timer belongs to the page that set it.
function clock() {
  let time = 0, nextId = 1;
  const timers = new Map();
  return {
    now: () => time,
    setTimeout: (fn, ms, owner) => { timers.set(nextId, { at: time + ms, fn, owner }); return nextId++; },
    clearTimeout: (id) => timers.delete(id),
    pending: (owner) => [...timers.values()].filter((timer) => !owner || timer.owner === owner).length,
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

// The room service: POST and GET room routes, seat sockets, relay, peer, ice and ping messages, and the room's
// message budget and size limit.
function service(time) {
  const rooms = new Map();
  const world = { rooms, fetches: [], sockets: [], texts: [], frames: [], log: [], pings: [], closes: [], down: false, observe: () => {}, intercept: () => true };
  let count = 0;
  // Real-alphabet ids that differ from room to room.
  const nextId = () => (++count, Array.from({ length: 10 }, (_, i) => ROOM_ALPHABET[(count * 7 + i * 13) % 32]).join(""));
  const reply = (status, body) => ({ ok: status < 300, status, json: async () => structuredClone(body) });
  world.fetch = async (path, init = {}) => {
    world.fetches.push({ path, init });
    if (path === "/api/coop/rooms" && init.method === "POST") {
      const id = nextId();
      const budget = () => ({ tokens: MESSAGES_PER_SECOND, at: time.now() });
      rooms.set(id, { id, hostToken: `host-token-${id}`, guestToken: null, seats: { host: null, guest: null }, budgets: { host: budget(), guest: budget() } });
      return reply(201, { room_id: id, host_token: `host-token-${id}`, invite_url: `${ORIGIN}/play/?coop=${id}`, ice_servers: HOST_ICE });
    }
    const match = /^\/api\/coop\/rooms\/([^/]+)$/.exec(path);
    if (match && !init.method && ROOM_ID.test(decodeURIComponent(match[1]))) {
      const room = rooms.get(decodeURIComponent(match[1]));
      return reply(200, { exists: !!room, host: !!room?.seats.host, guest: !!room?.guestToken });
    }
    return reply(404, { error: "no such endpoint" });
  };
  const push = (ws, data) => setImmediate(() => {
    if (ws.readyState !== 1) return;
    if (typeof data === "string" && data !== "pong") {
      const message = JSON.parse(data);
      if (!world.intercept(ws.role, message)) return;
      world.observe(ws.role, message);
    }
    ws.onmessage?.({ data });
  });
  function serverClose(ws, code, reason = "") {
    if (ws.readyState === 3) return;
    ws.readyState = 3;
    world.closes.push({ role: ws.role, code, reason });
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
    const room = ROOM_ID.test(id) && rooms.get(id);
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
  // The seat's budget: a second's worth, refilled every second, kept across its sockets.
  function take(ws) {
    const budget = ws.room.budgets[ws.role];
    budget.tokens = Math.min(MESSAGES_PER_SECOND, budget.tokens + ((time.now() - budget.at) * MESSAGES_PER_SECOND) / 1000);
    budget.at = time.now();
    if (budget.tokens < 1) return false;
    budget.tokens -= 1;
    return true;
  }
  function serverReceive(ws, data) {
    if (ws.readyState !== 1) return;
    // The room's auto-response: no wake, no budget.
    if (data === "ping") return world.pings.push(ws.role), push(ws, "pong");
    const size = typeof data === "string" ? new TextEncoder().encode(data).length : data.length;
    if (size > MAX_MESSAGE_BYTES) return serverClose(ws, 1009, "message over 16 KiB");
    if (!take(ws)) return serverClose(ws, 1008, "too many messages");
    const partner = ws.room.seats[other(ws.role)];
    if (typeof data === "string") {
      const message = JSON.parse(data);
      world.texts.push({ from: ws.role, ...message });
      world.log.push({ from: ws.role, type: message.type });
      if (message.type === "ice") return push(ws, JSON.stringify({ type: "ice", ice_servers: GUEST_ICE }));
      if (message.type === "seat" || message.type === "peer") return serverClose(ws, 1008, `${message.type} messages are the room's`);
      if (partner) push(partner, data);
    } else {
      world.frames.push({ from: ws.role, bytes: [...data] });
      world.log.push({ from: ws.role, type: "frame" });
      if (partner) push(partner, data.slice().buffer);
    }
  }
  world.WebSocket = class FakeWebSocket {
    constructor(url) {
      Object.assign(this, { url, readyState: 0, bufferedAmount: 0, binaryType: "blob" });
      world.sockets.push(this);
      setImmediate(() => accept(this));
    }
    // A closed socket discards what it is given, as browsers do.
    send(data) {
      assert.notEqual(this.readyState, 0, "sent on a connecting socket");
      if (this.readyState !== 1) return;
      const copy = typeof data === "string" ? data : new Uint8Array(data).slice();
      setImmediate(() => serverReceive(this, copy));
    }
    close(code, reason) {
      this.closedWith = code;
      serverClose(this, code, reason);
    }
  };
  world.seat = (id, role) => rooms.get(id).seats[role];
  // A message from the partner's seat, as the room relays it.
  world.inject = (id, role, message) => push(world.seat(id, role), JSON.stringify(message));
  // The connection drops under a page (its network, or the room's end or refusal).
  world.drop = (id, role, code = 1006, reason = "") => serverClose(world.seat(id, role), code, reason);
  return world;
}

// Peer connections that link the two pages through the descriptions they exchange. outcome: "connect",
// "fail" (both fail), "fail-host" (only the host's fails), or "hang" (never connects). A test can move live
// connections to another state (set), stop their data (kill) or abort their channels (abort); an ICE restart
// reconnects while net.recovers.
function network({ outcome = "connect", remoteDelay = 0, candidateType = "srflx", relayProtocol, stats = "chrome", earlyCandidates = false, legacy = false } = {}) {
  const net = { pcs: [], early: 0, added: 0, restarts: 0, outcome, recovers: true };
  class FakeChannel {
    constructor(pc, label, options) {
      Object.assign(this, { pc, label, options, readyState: "connecting", bufferedAmount: 0, binaryType: "blob" });
    }
    send(data) {
      if (this.readyState !== "open") throw Error("InvalidStateError: channel not open");
      const target = this.pc.peer?.channels[this.options.id];
      const buffer = new Uint8Array(data).slice().buffer;
      // What is in flight when the path dies is lost.
      setImmediate(() => { if (!this.pc.dead && !target?.pc.dead && target?.readyState === "open") target.onmessage?.({ data: buffer }); });
    }
    close() { this.readyState = "closed"; }
  }
  // Older Firefox has no connectionState and fires only the ICE event.
  function transition(pc, phase) {
    if (pc.closed) return;
    pc.phase = phase;
    pc.iceConnectionState = phase === "connecting" ? "checking" : phase;
    if (!legacy) {
      pc.connectionState = phase;
      pc.onconnectionstatechange?.();
    }
    pc.oniceconnectionstatechange?.();
  }
  const forOwner = (owner) => class FakePeerConnection {
    constructor(config) {
      Object.assign(this, { owner, config, channels: [], localDescription: null, remoteDescription: null, phase: "new", iceConnectionState: "new", candidates: 0, peer: null, closed: false, dead: false, restarting: false, silent: false });
      if (!legacy) this.connectionState = "new";
      this.id = net.pcs.push(this);
    }
    createDataChannel(label, options) {
      const channel = new FakeChannel(this, label, options);
      this.channels[options.id] = channel;
      return channel;
    }
    restartIce() {
      this.restarting = true;
      ++net.restarts;
    }
    async createOffer() { return { type: "offer", sdp: `fake ${this.id}` }; }
    async createAnswer() { return { type: "answer", sdp: `fake ${this.id}` }; }
    async setLocalDescription(description) {
      if (this.closed) throw Error("closed");
      this.localDescription = description;
      const gather = () => {
        if (this.closed) return;
        this.onicecandidate?.({ candidate: { toJSON: () => ({ candidate: `candidate ${this.id}`, sdpMid: "0" }) } });
        this.onicecandidate?.({ candidate: null });
      };
      // Gathering can start before the description's promise settles.
      if (earlyCandidates) gather();
      else setImmediate(gather);
      this.ready();
    }
    async setRemoteDescription(description) {
      if (this.closed) throw Error("closed");
      this.pendingRemote = true;
      for (let i = 0; i < remoteDelay; ++i) await tick();
      this.pendingRemote = false;
      this.remoteDescription = description;
      this.peer = net.pcs[Number(description.sdp.split(" ")[1]) - 1];
      // The answer to an ICE restart brings the pair back while the network allows it.
      if (this.restarting && description.type === "answer") {
        this.restarting = false;
        if (net.recovers) setImmediate(() => { for (const pc of [this, this.peer]) transition(pc, "connected"); });
      }
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
      if (!both.every((pc) => pc && pc.localDescription && pc.remoteDescription && pc.candidates && pc.phase === "new")) return;
      for (const pc of both) pc.phase = "connecting";
      setImmediate(() => {
        for (const pc of both) {
          if (pc.closed) continue;
          const fails = net.outcome === "fail" || (net.outcome === "fail-host" && pc.owner === "host");
          if (net.outcome === "hang" || (net.outcome === "fail-host" && !fails)) continue;
          transition(pc, fails ? "failed" : "connected");
          if (fails) continue;
          for (const channel of pc.channels) {
            channel.readyState = "open";
            channel.onopen?.();
          }
        }
      });
    }
    // Chrome names the selected pair on its transport; Firefox only nominates it, next to pairs that also succeeded.
    async getStats() {
      if (stats === "firefox") {
        return new Map([
          ["T", { type: "transport" }],
          ["A", { type: "candidate-pair", localCandidateId: "LA", nominated: false, state: "succeeded" }],
          ["B", { type: "candidate-pair", localCandidateId: "LB", nominated: true, state: "succeeded" }],
          ["LA", { type: "local-candidate", candidateType: "host" }],
          ["LB", { type: "local-candidate", candidateType, relayProtocol }],
        ]);
      }
      return new Map([
        ["T", { type: "transport", selectedCandidatePairId: "P" }],
        ["P", { type: "candidate-pair", localCandidateId: "L" }],
        ["L", { type: "local-candidate", candidateType, relayProtocol }],
      ]);
    }
    close() {
      if (this.closed) return;
      this.closed = true;
      this.phase = this.iceConnectionState = "closed";
      if (!legacy) this.connectionState = "closed";
      for (const channel of this.channels) channel.close();
      // A page that vanishes may never tell its partner.
      if (this.silent) return;
      // The partner's channels close with the connection.
      for (const channel of this.peer?.channels ?? []) {
        if (channel.readyState !== "open") continue;
        channel.readyState = "closed";
        setImmediate(() => channel.onclose?.());
      }
    }
  };
  const live = (owners) => net.pcs.filter((pc) => !pc.closed && owners.includes(pc.owner));
  net.set = (phase, owners = ["host", "guest"]) => { for (const pc of live(owners)) transition(pc, phase); };
  net.kill = (owners = ["host", "guest"]) => { for (const pc of live(owners)) pc.dead = true; };
  // The association aborts: data stops and every open channel closes on both sides.
  net.abort = () => {
    for (const pc of live(["host", "guest"])) {
      pc.dead = true;
      for (const channel of pc.channels.filter((each) => each.readyState === "open")) {
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
  const time = clock(), world = service(time), net = network(options);
  function page(owner, { store = sessionStore(), blockedStorage = false, RTCPeerConnection = net.RTC(owner), listen = true, fetch = world.fetch } = {}) {
    const events = { states: [], peers: [], messages: [], logs: [] };
    // The page's realm, its globals seen through `globalThis`. A sandboxed frame or blocked site data: touching
    // storage throws.
    const realm = vm.createContext({});
    const globals = blockedStorage ? Object.defineProperty({}, "sessionStorage", { get() { throw Error("SecurityError: storage is blocked"); } }) : vm.runInContext("globalThis", realm);
    const createCoop = vm.runInContext(`(function (globalThis) {\n${source}\nreturn createCoop;\n})`, realm)(globals);
    // The page's sockets carry its events, so a test can find and drop them.
    const WebSocket = class extends world.WebSocket {
      constructor(url) {
        super(url);
        this.owner = events;
      }
    };
    const coop = createCoop({
      fetch, WebSocket, RTCPeerConnection, ...(!blockedStorage && { sessionStorage: store }),
      location: { protocol: "https:", host: "crimson.land" },
      setTimeout: (fn, ms) => time.setTimeout(fn, ms, events), clearTimeout: time.clearTimeout, now: time.now,
      log: (...args) => events.logs.push(args.join(" ")),
    });
    coop.onstate = (state, reason) => events.states.push(reason ? `${state}: ${reason}` : state);
    coop.onpeer = (present) => events.peers.push(present);
    const listener = (channel, bytes) => events.messages.push([channel, [...bytes]]);
    if (listen) coop.onmessage = listener;
    // A reload or a closed tab: the page vanishes without a word, its sockets and connections with it. A silent
    // one's peer connection never tells the partner.
    const vanish = ({ silent = false } = {}) => {
      for (const ws of world.sockets.filter((ws) => ws.owner === events)) {
        ws.onclose = ws.onmessage = null;
        if (ws.readyState === 1) world.drop(ws.room.id, ws.role);
      }
      for (const pc of net.pcs.filter((pc) => pc.owner === owner && !pc.closed)) {
        pc.silent = silent;
        pc.close();
      }
    };
    const sockets = () => world.sockets.filter((ws) => ws.owner === events);
    return { coop, store, events, listener, vanish, sockets };
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
// A relayed frame: [u8 channel][payload], control payloads behind their [from][to][seq][ack] header.
function relayed({ from, bytes: [channel, ...rest] }) {
  if (channel === 0) return { from, channel, payload: rest };
  const view = new DataView(Uint8Array.from(rest).buffer);
  return { from, channel, seq: view.getUint32(8), ack: view.getUint32(12), payload: rest.slice(CONTROL_HEADER) };
}
const pcOf = (env, owner) => env.net.pcs.findLast((pc) => pc.owner === owner);
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

it("host and guest meet in a room, connect over WebRTC and exchange bytes on both channels", async () => {
  const env = setup();
  const host = env.page("host");
  const invite = await host.coop.host();
  await settle();
  assert.equal(host.coop.state, "waiting");
  assert.match(host.coop.room, ROOM_ID);
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
  // Signalling avoids the room's reserved types, each page says hello once, and every link message names the
  // host's link.
  const signals = env.world.texts.filter((text) => text.type !== "ice");
  assert.deepEqual([...new Set(signals.map((text) => `${text.from} ${text.type}`))].sort(), ["guest answer", "guest candidate", "guest hello", "host candidate", "host hello", "host offer"]);
  assert.equal(signals.filter((text) => text.type === "hello").length, 2);
  assert.equal(new Set(signals.filter((text) => text.link).map((text) => text.link)).size, 1);
});

it("candidates that arrive before the remote description wait for it", async () => {
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

it("candidates gathered before their description was sent follow it", async () => {
  const env = setup({ earlyCandidates: true });
  const order = [];
  env.world.observe = (role, message) => { if (message.link) order.push(`${other(role)} ${message.type}`); };
  const { host, guest } = await meet(env);
  assert.equal(host.coop.state, "connected");
  assert.equal(host.coop.stats().transport, "srflx");
  assert.ok(order.indexOf("host offer") < order.indexOf("host candidate"));
  assert.ok(order.indexOf("guest answer") < order.indexOf("guest candidate"));
  await exchange(host, guest);
});

it("an unknown room and a taken guest seat are refused before any socket opens", async () => {
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

it("a room id typed by hand finds its room: any case, spaces and hyphens, I and L for 1, O for 0", async () => {
  const env = setup();
  const host = env.page("host");
  await host.coop.host();
  await settle();
  const id = host.coop.room;
  const typed = ` ${id.slice(0, 5)}-${id.slice(5)} `.toUpperCase().replace("1", "I").replaceAll("1", "l").replaceAll("0", "O");
  assert.notEqual(typed.trim(), id);
  const guest = env.page("guest");
  await guest.coop.join(typed);
  await settle();
  assert.equal(guest.coop.room, id);
  assert.equal(guest.coop.state, "connected");
  assert.ok(guest.store.getItem(`crimson.coop.${id}`), "the seat is stored under the room's own id");
});

it("a page whose storage is blocked still plays, without a seat to take back", async () => {
  const env = setup();
  const { host, guest } = await meet(env, { hostPage: env.page("host", { blockedStorage: true }), guestPage: env.page("guest", { blockedStorage: true }) });
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  await exchange(host, guest);
});

it("a page that never got its seat stops after a few refused handshakes", async () => {
  const env = setup();
  const host = env.page("host");
  await host.coop.host();
  await settle();
  env.world.down = true;
  const guest = env.page("guest");
  await guest.coop.join(host.coop.room);
  await env.time.advance(120000);
  assert.equal(guest.coop.state, "error");
  assert.equal(guest.coop.reason, "could not reach the room");
  assert.equal(guest.sockets().length, 5);
  assert.equal(env.time.pending(guest.events), 0);
});

it("a page closed while it waits for the room's status schedules nothing more", async () => {
  const env = setup();
  let reject;
  const guest = env.page("guest", { fetch: () => new Promise((_, no) => { reject = no; }) });
  const joining = guest.coop.join("0000000000");
  guest.coop.close();
  reject(new TypeError("network connection lost"));
  await joining;
  await settle();
  assert.equal(guest.coop.state, "closed");
  assert.equal(env.time.pending(guest.events), 0);
  assert.equal(env.world.sockets.length, 0);
});

it("a reloaded guest takes its seat back with the stored token and both pages renegotiate", async () => {
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

it("a reloaded host takes its seat back from the same tab's storage", async () => {
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

it("a duplicated tab replaces the page in its seat: the host renegotiates with it and the old page stops", async () => {
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
  assert.equal(env.time.pending(guest.events), 0, "the replaced page does not try to reconnect");
});

it("a room socket blip keeps a working WebRTC link: no renegotiation, no switch", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  env.world.down = true;
  env.world.drop(host.coop.room, "guest");
  await settle();
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.deepEqual(host.events.peers, [true, false]);
  // Play goes on while the room is away.
  await exchange(host, guest);
  env.world.down = false;
  await env.time.advance(1000);
  assert.equal(guest.sockets().length, 2);
  assert.deepEqual(host.events.peers, [true, false, true]);
  assert.equal(host.coop.stats().links, 1);
  assert.equal(guest.coop.stats().links, 1);
  assert.equal(host.coop.stats().switches + guest.coop.stats().switches, 0);
  assert.equal(env.net.pcs.length, 2);
  assert.ok(env.net.pcs.every((pc) => !pc.closed));
  assert.equal(host.coop.stats().transport, "srflx");
  await exchange(host, guest);
});

it("an idle room socket pings every half minute and ignores the pong", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  await env.time.advance(30000);
  assert.deepEqual(env.world.pings.sort(), ["guest", "host"]);
  await env.time.advance(30000);
  assert.equal(env.world.pings.length, 4);
  assert.ok(![...host.events.logs, ...guest.events.logs].some((line) => line.includes("unreadable")));
  assert.equal(host.coop.state, "connected");
  await exchange(host, guest);
});

it("signalling for another link is stale and ignored", async () => {
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

it("a failed peer connection moves both pages to the room relay, the other page replying", async () => {
  const env = setup({ outcome: "fail-host" });
  const { host, guest } = await meet(env);
  const switches = env.world.texts.filter((text) => text.type === "switch");
  assert.deepEqual(switches.map(({ from, transport_epoch, reply }) => [from, transport_epoch, !!reply]), [["host", 1, false], ["guest", 1, true]]);
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.equal(guest.coop.stats().transport, "ws-relay");
  assert.ok(env.net.pcs.every((pc) => pc.closed), "the reply lets both pages close their peer connections");
  await exchange(host, guest);
  // Relayed frames are [u8 channel][payload]; control payloads carry their sequence numbers.
  assert.deepEqual(env.world.frames.map(relayed).filter((frame) => frame.seq !== 0).map(({ from, channel, seq, payload }) => [from, channel, seq, payload]), [
    ["host", 0, undefined, [1, 2, 3]],
    ["host", 1, 1, [4]],
    ["guest", 1, 1, [5, 6]],
    ["guest", 0, undefined, [7]],
  ]);
});

it("a connection that never completes falls back after the timeout; simultaneous decisions agree", async () => {
  const env = setup({ outcome: "hang" });
  const { host, guest } = await meet(env);
  assert.equal(host.coop.state, "connecting");
  await env.time.advance(9999);
  assert.equal(host.coop.state, "connecting");
  await env.time.advance(1);
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.deepEqual(env.world.texts.filter((text) => text.type === "switch").map(({ from, reply }) => [from, !!reply]), [["host", false], ["guest", true]]);
  await exchange(host, guest);

  // Both pages give up at once: each sends the same epoch and each takes the other's as its reply.
  const both = setup({ outcome: "fail" });
  const pair = await meet(both);
  assert.deepEqual(both.world.texts.filter((text) => text.type === "switch").map((text) => text.transport_epoch), [1, 1, 1, 1]);
  assert.equal(pair.host.coop.stats().transport, "ws-relay");
  assert.equal(pair.guest.coop.stats().transport, "ws-relay");
  await exchange(pair.host, pair.guest);
});

it("a disconnected peer connection restarts ICE on the same link and recovers without a switch", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  env.net.set("disconnected");
  await settle();
  assert.equal(host.coop.state, "connected");
  await env.time.advance(1000);
  assert.equal(env.net.restarts, 1, "the host restarted ICE");
  const offers = env.world.texts.filter((text) => text.type === "offer");
  assert.equal(offers.length, 2);
  assert.equal(offers[1].link, offers[0].link, "the restart reuses its link");
  assert.equal(env.world.texts.filter((text) => text.type === "answer").length, 2);
  await env.time.advance(30000);
  assert.equal(env.world.texts.filter((text) => text.type === "switch").length, 0);
  assert.equal(host.coop.stats().transport, "srflx");
  assert.equal(guest.coop.stats().links, 1);
  await exchange(host, guest);
});

it("a peer connection that stays disconnected falls back within seconds, not when it reports failed", async () => {
  for (const legacy of [false, true]) {
    const env = setup({ legacy });
    const { host, guest } = await meet(env);
    env.net.recovers = false;
    env.net.set("disconnected");
    await env.time.advance(4999);
    assert.equal(host.coop.stats().transport, "srflx", legacy ? "older Firefox" : "current browsers");
    await env.time.advance(1);
    assert.equal(host.coop.stats().transport, "ws-relay");
    assert.equal(guest.coop.stats().transport, "ws-relay");
    await exchange(host, guest);
  }
  // A connection that goes on to fail falls back then and there.
  const env = setup();
  const { host, guest } = await meet(env);
  env.net.recovers = false;
  env.net.set("disconnected");
  await env.time.advance(500);
  env.net.set("failed");
  await settle();
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.equal(guest.coop.stats().transport, "ws-relay");
});

it("a page without WebRTC plays over the relay", async () => {
  const env = setup();
  const { host, guest } = await meet(env, { guestPage: env.page("guest", { RTCPeerConnection: null }) });
  assert.deepEqual(env.world.texts.filter((text) => text.type === "switch").map(({ from, transport_epoch, reply }) => [from, transport_epoch, !!reply]), [["guest", 1, false], ["host", 1, true]]);
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.equal(guest.coop.stats().transport, "ws-relay");
  await exchange(host, guest);
});

it("a control message accepted right before WebRTC fails arrives once and in order after the switch", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  assert.ok(host.coop.send(1, bytes(1)));
  assert.ok(host.coop.send(1, bytes(2)));
  // The path dies with both in flight, then the connection says so.
  env.net.kill();
  env.net.set("failed");
  assert.ok(host.coop.send(1, bytes(3)));
  await settle();
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.deepEqual(guest.events.messages, [[1, [1]], [1, [2]], [1, [3]]]);
  await env.time.advance(100);
  assert.equal(host.coop.stats().unacked, 0, "the partner acknowledged them");
  await exchange(host, guest);
});

it("replayed control messages the partner already has are dropped", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  assert.ok(host.coop.send(1, bytes(4)));
  await settle();
  assert.deepEqual(guest.events.messages, [[1, [4]]]);
  // It fails before the acknowledgement leaves: the relay gets the message again.
  env.net.set("failed");
  await settle();
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.ok(env.world.frames.map(relayed).some((frame) => frame.from === "host" && frame.seq === 1));
  assert.deepEqual(guest.events.messages, [[1, [4]]]);
  assert.equal(guest.coop.stats().duplicates, 1);
  await env.time.advance(100);
  assert.equal(host.coop.stats().unacked, 0);
});

it("control messages wait for a transport and go once the partner is there", async () => {
  const env = setup();
  const host = env.page("host");
  await host.coop.host();
  await settle();
  assert.ok(host.coop.send(1, bytes(1)), "nobody to send it to yet");
  assert.equal(host.coop.send(0, bytes(2)), false, "ticks have nowhere to go");
  const guest = env.page("guest");
  await guest.coop.join(host.coop.room);
  await settle();
  assert.deepEqual(guest.events.messages, [[1, [1]]]);
});

it("control frames lost with a relay socket go again once it reconnects", async () => {
  const env = setup({ outcome: "fail" });
  const { host, guest } = await meet(env);
  guest.events.messages.length = 0;
  env.world.down = true;
  assert.ok(host.coop.send(1, bytes(9)));
  env.world.drop(host.coop.room, "host");
  await settle();
  assert.equal(host.coop.state, "reconnecting");
  assert.ok(host.coop.send(1, bytes(10)), "control messages wait while the relay is down");
  assert.equal(host.coop.send(0, bytes(11)), false, "ticks do not");
  assert.deepEqual(guest.events.messages, []);
  env.world.down = false;
  await env.time.advance(1000);
  assert.equal(host.coop.state, "connected");
  assert.equal(host.coop.stats().transport, "ws-relay", "the relay carries on without renegotiating");
  assert.deepEqual(guest.events.messages, [[1, [9]], [1, [10]]]);
});

it("a page announces its switch before it relays anything", async () => {
  const env = setup();
  const { host } = await meet(env);
  env.net.kill();
  assert.ok(host.coop.send(1, bytes(5)));
  env.net.set("failed", ["host"]);
  await settle();
  const sent = env.world.log.filter((entry) => entry.from === "host").map((entry) => entry.type);
  assert.ok(sent.includes("frame"), "the lost message went again over the relay");
  assert.ok(sent.indexOf("switch") < sent.indexOf("frame"));
});

it("after a switch the old connection delivers what was in flight until the partner switches too", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  const guestPc = pcOf(env, "guest");
  env.net.set("failed", ["guest"]);
  // The host has not heard yet and sends over WebRTC.
  assert.ok(host.coop.send(1, bytes(7)));
  assert.equal(guestPc.closed, false);
  await settle();
  assert.deepEqual(guest.events.messages, [[1, [7]]]);
  assert.equal(guest.coop.stats().duplicates, 1, "the relayed copy came second");
  assert.ok(guestPc.closed, "the host's reply ended the old connection");

  // Without a reply, the old connection goes after a moment.
  const quiet = setup();
  await meet(quiet);
  const pc = pcOf(quiet, "guest");
  quiet.world.intercept = (to, message) => !(to === "host" && message.type === "switch");
  quiet.net.set("failed", ["guest"]);
  await quiet.time.advance(1999);
  assert.equal(pc.closed, false);
  await quiet.time.advance(1);
  assert.ok(pc.closed);
});

it("a switch nobody replied to goes again when the partner retakes its seat", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  // The switch never reaches the host, and the guest's old connection never tells it either.
  env.world.intercept = (to, message) => !(to === "host" && message.type === "switch");
  pcOf(env, "guest").silent = true;
  env.net.kill();
  env.net.set("failed", ["guest"]);
  await env.time.advance(3000);
  assert.equal(guest.coop.stats().transport, "ws-relay");
  assert.equal(host.coop.stats().transport, "srflx");
  assert.ok(host.coop.send(1, bytes(8)), "lost on the host's dead connection");
  env.world.intercept = () => true;
  env.world.drop(host.coop.room, "host");
  await settle();
  await env.time.advance(1000);
  assert.equal(host.coop.stats().transport, "ws-relay");
  assert.deepEqual(guest.events.messages, [[1, [8]]]);
  await exchange(host, guest);
});

it("a link that closes while the partner is away waits for it instead of switching", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  env.world.down = true;
  env.world.drop(host.coop.room, "guest");
  await settle();
  env.net.abort();
  await settle();
  assert.equal(host.coop.state, "waiting");
  assert.equal(guest.coop.state, "reconnecting");
  assert.equal(env.world.texts.filter((text) => text.type === "switch").length, 0);
  assert.equal(host.coop.stats().switches + guest.coop.stats().switches, 0);
  env.world.down = false;
  await env.time.advance(1000);
  assert.equal(host.coop.state, "connected");
  assert.equal(host.coop.stats().transport, "srflx", "a new link over WebRTC");
  await exchange(host, guest);
});

it("a partner page that vanishes without a word is waited for, then replaced", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  guest.vanish({ silent: true });
  await settle();
  assert.equal(host.coop.state, "connected", "the host cannot tell yet");
  assert.ok(host.coop.send(1, bytes(1)));
  env.net.recovers = false;
  env.net.set("disconnected", ["host"]);
  await env.time.advance(5000);
  assert.equal(host.coop.state, "waiting");
  assert.equal(host.coop.stats().switches, 0);
  const reloaded = env.page("guest", { store: guest.store });
  await reloaded.coop.join(host.coop.room);
  await settle();
  assert.equal(host.coop.state, "connected");
  assert.equal(host.coop.stats().links, 2);
  assert.ok(host.events.logs.some((line) => line.startsWith("control messages for the replaced page dropped")));
  await exchange(host, reloaded);
  assert.deepEqual(reloaded.events.messages, [[0, [1, 2, 3]], [1, [4]]], "the old page's message is not the new page's");
});

it("room sends share one budget under the room's: ticks keep a reserve, control waits its turn", async () => {
  const env = setup({ outcome: "fail" });
  const { host, guest } = await meet(env);
  let ticks = 0;
  for (let i = 0; i < 300; i++) ticks += host.coop.send(0, bytes(i & 255));
  for (let i = 0; i < 300; i++) assert.ok(host.coop.send(1, bytes(i & 255, i >> 8)));
  assert.ok(ticks > 0 && ticks < MESSAGES_PER_SECOND, `${ticks} ticks went`);
  assert.equal(host.coop.stats().dropped, 300 - ticks);
  await env.time.advance(3000);
  assert.deepEqual(env.world.closes, [], "the room closed no socket");
  const control = guest.events.messages.filter(([channel]) => channel === 1).map(([, [low, high]]) => low + (high << 8));
  assert.deepEqual(control, Array.from({ length: 300 }, (_, i) => i));
  await exchange(host, guest);
});

it("a message the relay cannot carry is refused before the room sees it", async () => {
  const env = setup({ outcome: "fail" });
  const { host, guest } = await meet(env);
  const largest = 16 * 1024 - 1 - CONTROL_HEADER;
  assert.ok(host.coop.send(1, new Uint8Array(largest)));
  assert.throws(() => host.coop.send(1, new Uint8Array(largest + 1)), /at most/);
  assert.equal(host.coop.send(0, new Uint8Array(16 * 1024)), false);
  await settle();
  assert.equal(guest.events.messages.at(-1)[1].length, largest);
  assert.deepEqual(env.world.closes, []);
});

it("a flood close reconnects; the room's other refusals end the session", async () => {
  const env = setup({ outcome: "fail" });
  const { host, guest } = await meet(env);
  env.world.drop(host.coop.room, "host", 1008, "too many messages");
  await settle();
  assert.equal(host.coop.state, "reconnecting");
  await env.time.advance(1000);
  assert.equal(host.coop.state, "connected");
  await exchange(host, guest);

  env.world.drop(host.coop.room, "guest", 1008, "seat messages are the room's");
  env.world.drop(host.coop.room, "host", 1009, "message over 16 KiB");
  await settle();
  assert.equal(guest.coop.reason, "the room refused this page: seat messages are the room's");
  assert.equal(host.coop.reason, "the room refused this page: message over 16 KiB");
});

it("a backed-up ticks channel drops ticks, never control messages", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  const hostPc = pcOf(env, "host");
  hostPc.channels[0].bufferedAmount = hostPc.channels[1].bufferedAmount = 1 << 20;
  assert.equal(host.coop.send(0, bytes(1)), false);
  assert.ok(host.coop.send(1, bytes(2)));
  await settle();
  assert.deepEqual(guest.events.messages, [[1, [2]]]);
  assert.equal(host.coop.stats().dropped, 1);
});

it("the selected candidate pair names the transport, in Chrome and Firefox", async () => {
  const chrome = setup({ candidateType: "relay", relayProtocol: "tcp" });
  assert.equal((await meet(chrome)).host.coop.stats().transport, "relay-tcp");
  const firefox = setup({ stats: "firefox", candidateType: "relay", relayProtocol: "udp" });
  assert.equal((await meet(firefox)).host.coop.stats().transport, "relay-udp");
});

it("messages before the game listens wait in order for its handler", async () => {
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

it("a full inbox drops its oldest ticks first and never a control message", async () => {
  const env = setup();
  const { host, guest } = await meet(env, { guestPage: env.page("guest", { listen: false }) });
  host.coop.send(1, bytes(1));
  for (let i = 0; i < 1023; i++) host.coop.send(0, bytes(i & 255));
  host.coop.send(1, bytes(2));
  await settle();
  assert.equal(guest.coop.stats().inboxDropped, 1);
  guest.coop.onmessage = guest.listener;
  assert.deepEqual(guest.events.messages[0], [1, [1]]);
  assert.deepEqual(guest.events.messages[1], [0, [1]], "the oldest tick made room");
  assert.deepEqual(guest.events.messages.at(-1), [1, [2]]);

  // An inbox of control messages alone ends the session rather than lose one.
  const full = setup();
  const pair = await meet(full, { guestPage: full.page("guest", { listen: false }) });
  for (let i = 0; i < 1000; i++) pair.host.coop.send(1, bytes(1));
  await settle();
  await full.time.advance(100);
  assert.equal(pair.host.coop.stats().unacked, 0, "acknowledged into the inbox");
  for (let i = 0; i < 25; i++) pair.host.coop.send(1, bytes(2));
  await settle();
  assert.equal(pair.guest.coop.state, "error");
  assert.equal(pair.guest.coop.reason, "the game did not read its control messages");
});

it("a lost room socket reconnects with backoff and its stored token", async () => {
  const env = setup({ outcome: "fail" });
  const { host, guest } = await meet(env);
  assert.equal(host.coop.stats().transport, "ws-relay");
  env.world.down = true;
  env.world.drop(host.coop.room, "host");
  await settle();
  assert.equal(host.coop.state, "reconnecting");
  assert.equal(guest.coop.state, "waiting");
  const sockets = env.world.sockets.length;
  await env.time.advance(1000);
  await env.time.advance(2000);
  assert.equal(env.world.sockets.length, sockets + 2, "refused attempts back off");
  assert.equal(host.coop.state, "reconnecting");
  env.world.down = false;
  await env.time.advance(3999);
  assert.equal(env.world.sockets.length, sockets + 2);
  await env.time.advance(1);
  assert.equal(env.world.sockets.length, sockets + 3);
  assert.match(env.world.sockets.at(-1).url, /role=host&token=host-token-/);
  assert.equal(host.coop.state, "connected");
  assert.equal(guest.coop.state, "connected");
  assert.equal(host.coop.stats().reconnects, 3);
  assert.deepEqual(host.events.states.slice(-2), ["reconnecting", "connected"]);
  // The partner was there before and after: no news for the game.
  assert.deepEqual(host.events.peers, [true]);
  assert.deepEqual(guest.events.peers, [true, false, true]);
  await exchange(host, guest);
});

it("a closed room ends the session without reconnecting", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  env.world.drop(host.coop.room, "host", 4000);
  env.world.drop(host.coop.room, "guest", 4000);
  await settle();
  assert.equal(host.coop.reason, "the room closed");
  assert.equal(guest.coop.reason, "the room closed");
  assert.equal(env.time.pending(), 0);
});

it("close() ends everything, tells the partner and keeps the seat token", async () => {
  const env = setup();
  const { host, guest } = await meet(env);
  const room = host.coop.room;
  guest.coop.close();
  await settle();
  assert.equal(guest.coop.state, "closed");
  assert.equal(env.world.seat(room, "guest"), null);
  assert.equal(guest.sockets()[0].closedWith, 1000);
  assert.ok(env.net.pcs.filter((pc) => pc.owner === "guest").every((pc) => pc.closed));
  assert.equal(guest.coop.send(1, bytes(1)), false);
  assert.equal(host.coop.state, "waiting");
  assert.deepEqual(host.events.peers, [true, false]);
  assert.equal(env.time.pending(guest.events), 0);
  assert.ok(JSON.parse(guest.store.getItem(`crimson.coop.${room}`)).token, "the seat stays this tab's to take back");
  await env.time.advance(60000);
  assert.equal(guest.coop.state, "closed");
  assert.equal(guest.sockets().length, 1);
});
