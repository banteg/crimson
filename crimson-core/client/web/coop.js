// The co-op transport (docs/rewrite/network-coop.md §6), to be embedded by
// client/build.py like analytics.js. Two pages meet in a room (service/src/coop.ts),
// signal a WebRTC connection with two DataChannels through it, and relay over the
// room's socket when WebRTC cannot connect. It moves opaque bytes on channel 0
// (ticks, unreliable) and channel 1 (control, reliable); the game owns the protocol.
function createCoop({
  fetch = globalThis.fetch, WebSocket = globalThis.WebSocket, RTCPeerConnection = globalThis.RTCPeerConnection,
  location = globalThis.location, sessionStorage = globalThis.sessionStorage,
  setTimeout = globalThis.setTimeout, clearTimeout = globalThis.clearTimeout,
  now = () => performance.now(), log = () => {},
} = {}) {
  const CONNECT_TIMEOUT_MS = 10000;
  const BACKOFF_MS = [1000, 2000, 4000, 8000];
  // Ticks queued past this many bytes are stale before they leave; the next packet repeats their window.
  const TICKS_BUFFERED_LIMIT = 16 * 1024;
  // The room closes a seat's socket past 200 messages a second or a message over 16 KiB. Relayed ticks stay
  // under 120 a second, leaving the rest for control and signalling.
  const RELAY_TICK_INTERVAL_MS = 1000 / 120;
  const RELAY_MAX_BYTES = 16 * 1024;
  const INBOX_LIMIT = 1024;
  // Negotiated with fixed ids, so both pages create them and neither waits for the other's.
  const CHANNELS = [["coop-ticks", { ordered: false, maxRetransmits: 0 }], ["coop-control", { ordered: true }]];

  let state = "idle", reason = null, role = null, roomId = null, inviteUrl = null, token = null;
  let socket = null, seated = false, wasSeated = false, statusNext = false, attempts = 0, retry = null;
  let partner = false, iceServers = null, lastRelayTick = -Infinity;
  const iceWaiting = [];
  // The current connection attempt with the partner. The host names each one; messages of another are stale.
  let link = null;
  let handler = null;
  const inbox = [];
  const stats = { transport: null, links: 0, switches: 0, reconnects: 0, sent: [0, 0], received: [0, 0], dropped: 0, inboxDropped: 0 };

  const ended = () => state === "closed" || state === "error";
  function setState(next, why = null) {
    if (next === state && why === reason) return;
    state = next;
    reason = why;
    log("state", why ? `${next}: ${why}` : next);
    api.onstate?.(next, why);
  }
  function refresh() {
    if (ended()) return;
    if (link?.connected && (seated || !link.relay)) setState("connected");
    else if (!seated) setState(wasSeated ? "reconnecting" : "opening");
    else setState(partner ? "connecting" : "waiting");
  }
  function fail(why) {
    if (ended()) return;
    shutdown();
    setState("error", why);
  }
  function shutdown() {
    clearTimeout(retry);
    teardown();
    if (socket) socket.close(1000, "left");
    socket = null;
    seated = false;
  }

  // Seat tokens live in this tab's session storage, keyed by room, never in the page's URL: a reload takes
  // the seat back.
  const storageKey = (id) => `crimson.coop.${id}`;
  function storedSeat(id) {
    try { return JSON.parse(sessionStorage.getItem(storageKey(id))); } catch { return null; }
  }
  function storeSeat() {
    try { sessionStorage.setItem(storageKey(roomId), JSON.stringify({ role, token })); } catch {}
  }

  function begin(seat) {
    if (state !== "idle") throw Error("co-op already started");
    role = seat;
    setState("opening");
  }
  async function host() {
    begin("host");
    let room;
    try {
      const response = await fetch("/api/coop/rooms", { method: "POST", credentials: "omit" });
      if (!response.ok) return fail(response.status === 429 ? "too many rooms, try again in a minute" : `the room service answered ${response.status}`);
      room = await response.json();
    } catch { return fail("the room service is unreachable"); }
    if (ended()) return;
    ({ room_id: roomId, host_token: token, invite_url: inviteUrl, ice_servers: iceServers } = room);
    storeSeat();
    open();
    return inviteUrl;
  }
  // Joins as the guest, or takes back the seat this tab holds in the room (a reload of either player).
  async function join(id) {
    begin("guest");
    roomId = id;
    const seat = storedSeat(id);
    if (seat) ({ role, token } = seat);
    await connect();
  }

  // Browsers hide why a WebSocket handshake failed, so the room's status comes first: true to open the socket,
  // false when it never will, null to try again later.
  async function check() {
    let response, status;
    try {
      response = await fetch(`/api/coop/rooms/${encodeURIComponent(roomId)}`, { credentials: "omit", cache: "no-store" });
      status = response.ok ? await response.json() : null;
    } catch { return null; }
    if (ended()) return false;
    if (response.status === 404 || status?.exists === false) return fail("no such room"), false;
    if (!status) return null;
    if (role === "guest" && !token && status.guest) return fail("room full"), false;
    return true;
  }
  async function connect() {
    const ready = await check();
    if (ready) open();
    else if (ready === null) backoff();
  }
  function backoff() {
    const delay = BACKOFF_MS[Math.min(attempts++, BACKOFF_MS.length - 1)];
    refresh();
    retry = setTimeout(() => {
      stats.reconnects++;
      connect();
    }, delay);
  }
  function open() {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const query = `role=${role}${token ? `&token=${encodeURIComponent(token)}` : ""}`;
    const ws = new WebSocket(`${scheme}//${location.host}/api/coop/rooms/${encodeURIComponent(roomId)}/ws?${query}`);
    ws.binaryType = "arraybuffer";
    ws.onmessage = (event) => { if (ws === socket) receive(event.data); };
    ws.onclose = (event) => { if (ws === socket) lost(event.code, event.reason); };
    socket = ws;
  }
  function lost(code, why) {
    socket = null;
    seated = false;
    if (code === 4000) return fail("the room closed");
    if (code === 4001) return fail("the room was opened in another tab");
    if (code === 1008 || code === 1009) return fail(`the room refused this page: ${why}`);
    log("room socket lost", code);
    backoff();
  }
  const signal = (message) => { if (seated) socket.send(JSON.stringify(message)); };

  // Text frames are JSON: the room's own seat, peer and ice messages, or the partner's signalling. Binary frames
  // are always the partner's relayed bytes.
  function receive(data) {
    if (typeof data !== "string") {
      const bytes = new Uint8Array(data);
      if (bytes.length && bytes[0] < CHANNELS.length) deliver(bytes[0], bytes.subarray(1));
      return;
    }
    let message;
    try { message = JSON.parse(data); } catch { return log("unreadable room message"); }
    switch (message?.type) {
      case "seat": return seat(message);
      case "peer": return peer(message.present);
      case "ice": return ice(message.ice_servers);
      case "offer": return offer(message);
      case "answer": return answer(message);
      case "candidate": return candidate(message);
      case "switch": return switched(message);
    }
  }
  function seat(message) {
    seated = wasSeated = true;
    statusNext = true;
    attempts = 0;
    if (message.guest_token) {
      token = message.guest_token;
      storeSeat();
    }
    if (!iceServers) signal({ type: "ice" });
  }
  // Any present partner gets a fresh connection: a repeated `present: true` means the partner's page (or ours)
  // reconnected, and its old peer connection is gone or about to be.
  function peer(present) {
    // The status a new socket starts with is news only when it differs from what we knew.
    const news = !statusNext || present !== partner;
    statusNext = false;
    partner = present;
    teardown();
    if (present && role === "host") offerLink();
    refresh();
    if (news) api.onpeer?.(present);
  }
  function ice(servers) {
    iceServers = servers;
    for (const resolve of iceWaiting.splice(0)) resolve(servers);
  }
  const iceReady = () => (iceServers ? Promise.resolve(iceServers) : new Promise((resolve) => iceWaiting.push(resolve)));

  function newLink(id) {
    teardown();
    const current = link = { id, pc: null, channels: [], pending: [], described: false, connected: false, relay: false, epoch: 0 };
    stats.links++;
    current.timer = setTimeout(() => { if (link === current && !current.connected) fallback(current, "not connected in time"); }, CONNECT_TIMEOUT_MS);
    return current;
  }
  function teardown() {
    if (!link) return;
    clearTimeout(link.timer);
    link.pc?.close();
    link = null;
    stats.transport = null;
  }
  // The host offers; the guest answers. A page without WebRTC fails here and falls back to the relay.
  async function connectPeer(current, offerSdp) {
    try {
      const servers = await iceReady();
      if (link !== current) return;
      const pc = current.pc = new RTCPeerConnection({ iceServers: servers });
      current.channels = CHANNELS.map(([label, options], id) => watch(current, id, pc.createDataChannel(label, { ...options, negotiated: true, id })));
      pc.onicecandidate = (event) => {
        if (event.candidate && link === current) signal({ type: "candidate", link: current.id, candidate: event.candidate.toJSON() });
      };
      pc.onconnectionstatechange = () => { if (pc.connectionState === "failed") failed(current, "peer connection failed"); };
      if (offerSdp) await describe(current, { type: "offer", sdp: offerSdp });
      await pc.setLocalDescription(offerSdp ? await pc.createAnswer() : await pc.createOffer());
      if (link === current) signal({ type: offerSdp ? "answer" : "offer", link: current.id, sdp: pc.localDescription.sdp });
    } catch (error) { failed(current, error); }
  }
  function watch(current, id, channel) {
    channel.binaryType = "arraybuffer";
    channel.onopen = () => { if (link === current && current.channels.every((each) => each.readyState === "open")) connected(current); };
    channel.onclose = () => failed(current, `${channel.label} closed`);
    channel.onmessage = (event) => { if (link === current) deliver(id, new Uint8Array(event.data)); };
    return channel;
  }
  // Candidates that arrive before the remote description wait for it.
  async function describe(current, description) {
    await current.pc.setRemoteDescription(description);
    current.described = true;
    for (const each of current.pending.splice(0)) addCandidate(current, each);
  }
  const addCandidate = (current, each) => current.pc.addIceCandidate(each).catch((error) => log("candidate refused", String(error)));
  const offerLink = () => connectPeer(newLink(Math.random().toString(36).slice(2, 10)));
  function offer(message) {
    if (role !== "guest" || link?.id === message.link) return;
    connectPeer(newLink(message.link), message.sdp);
  }
  function answer(message) {
    if (role !== "host" || link?.id !== message.link) return;
    const current = link;
    describe(current, { type: "answer", sdp: message.sdp }).catch((error) => failed(current, error));
  }
  function candidate(message) {
    if (link?.id !== message.link) return;
    if (link.described) addCandidate(link, message.candidate);
    else link.pending.push(message.candidate);
  }

  function connected(current) {
    current.connected = true;
    clearTimeout(current.timer);
    stats.transport = current.relay ? "ws-relay" : "webrtc";
    refresh();
    if (current.relay) return log("transport", stats.transport);
    // Telemetry: which candidate pair carries the session.
    current.pc.getStats().then((report) => {
      if (link !== current || current.relay) return;
      stats.transport = candidateType(report);
      log("transport", stats.transport);
    }, () => {});
  }
  function candidateType(report) {
    const all = [...report.values()];
    const pairId = all.find((each) => each.type === "transport" && each.selectedCandidatePairId)?.selectedCandidatePairId;
    // Firefox has no selected pair on its transport stats; it marks the pair instead.
    const pair = pairId ? report.get(pairId) : all.find((each) => each.type === "candidate-pair" && each.selected);
    const local = pair && report.get(pair.localCandidateId);
    if (!local) return "webrtc";
    return local.candidateType !== "relay" ? local.candidateType : local.relayProtocol ? `relay-${local.relayProtocol}` : "relay";
  }
  function failed(current, why) {
    if (link !== current || current.relay) return;
    fallback(current, String(why));
  }
  // The relay fallback (the spec's MSG_SWITCH_TRANSPORT): whoever gives up on WebRTC first moves both pages to
  // the room socket. Each decision raises the link's transport epoch; the later one wins and the other page
  // answers it, so both send on the same transport.
  function fallback(current, why) {
    log("webrtc gave up", why);
    relay(current, current.epoch + 1);
    signal({ type: "switch", link: current.id, transport_epoch: current.epoch });
  }
  function relay(current, epoch) {
    current.epoch = epoch;
    if (current.relay) return;
    current.relay = true;
    current.pc?.close();
    stats.switches++;
    connected(current);
  }
  function switched(message) {
    if (link?.id !== message.link) {
      // The host names links: a guest follows the host's newest, even when it skips WebRTC altogether.
      if (role !== "guest") return;
      newLink(message.link);
    }
    if (!(message.transport_epoch > link.epoch)) return;
    relay(link, message.transport_epoch);
    signal({ type: "switch", link: link.id, transport_epoch: link.epoch });
  }

  function deliver(channel, bytes) {
    stats.received[channel]++;
    if (handler) return handler(channel, bytes);
    if (inbox.length === INBOX_LIMIT) {
      inbox.shift();
      stats.inboxDropped++;
    }
    inbox.push([channel, bytes]);
  }
  // Hands bytes to the partner's transport: true when sent. Ticks drop when their transport is backed up (or,
  // relayed, too frequent); control messages never drop, but nothing sends without a connection.
  function send(channel, bytes) {
    if (!link?.connected) return false;
    if (link.relay) {
      if (!seated) return false;
      if (channel === 0 && (socket.bufferedAmount > TICKS_BUFFERED_LIMIT || now() - lastRelayTick < RELAY_TICK_INTERVAL_MS)) {
        stats.dropped++;
        return false;
      }
      if (bytes.length + 1 > RELAY_MAX_BYTES) {
        log("message too large for the relay", bytes.length);
        return false;
      }
      const frame = new Uint8Array(bytes.length + 1);
      frame[0] = channel;
      frame.set(bytes, 1);
      if (channel === 0) lastRelayTick = now();
      socket.send(frame);
    } else {
      const channelOut = link.channels[channel];
      if (channel === 0 && channelOut.bufferedAmount > TICKS_BUFFERED_LIMIT) {
        stats.dropped++;
        return false;
      }
      // A channel closing under us is a failing connection, not the game's error.
      try { channelOut.send(bytes); } catch (error) {
        failed(link, error);
        return false;
      }
    }
    stats.sent[channel]++;
    return true;
  }
  function close() {
    if (state === "closed") return;
    shutdown();
    setState("closed");
  }

  const api = {
    host, join, send, close,
    stats: () => ({ ...stats, sent: [...stats.sent], received: [...stats.received], state, inbox: inbox.length }),
    get state() { return state; },
    get reason() { return reason; },
    get role() { return role; },
    get room() { return roomId; },
    get inviteUrl() { return inviteUrl; },
    onstate: null,
    onpeer: null,
    // Messages that arrive before the game listens wait for it.
    get onmessage() { return handler; },
    set onmessage(next) {
      handler = next;
      while (handler && inbox.length) handler(...inbox.shift());
    },
  };
  return api;
}
