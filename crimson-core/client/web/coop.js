// The co-op transport (docs/rewrite/network-coop.md §6), embedded in the page by
// client/build.py (shell.html's PLAY_COOP). Two pages meet in a room
// (service/src/coop.ts), signal a WebRTC connection with two DataChannels through
// it, and relay over the room's socket when WebRTC cannot connect. It moves opaque bytes on channel 0
// (ticks, best effort) and channel 1 (control: delivered once and in order whatever
// the transport does); the game owns the protocol.
function createCoop({
  fetch = globalThis.fetch, WebSocket = globalThis.WebSocket, RTCPeerConnection = globalThis.RTCPeerConnection,
  location = globalThis.location, sessionStorage,
  setTimeout = globalThis.setTimeout, clearTimeout = globalThis.clearTimeout,
  now = () => performance.now(), log = () => {},
} = {}) {
  const CONNECT_TIMEOUT_MS = 10000;
  // A disconnected peer connection often comes back by itself; if not, the host restarts ICE, and if that does not
  // bring it back either, the pages move to the relay.
  const ICE_RESTART_MS = 1000;
  const DISCONNECTED_MS = 5000;
  // After a switch, the old peer connection still delivers what was in flight until the partner switches too.
  const DRAIN_MS = 2000;
  const BACKOFF_MS = [1000, 2000, 4000, 8000];
  // A page that never took its seat gives up after this many tries; a seated page retries for as long as it lives.
  const JOIN_ATTEMPTS = 5;
  // Idle proxies close quiet sockets; the room answers this itself, without waking or spending the seat's budget.
  const PING_MS = 30000;
  // Ticks queued past this many bytes are stale before they leave; the next packet repeats their window.
  const TICKS_BUFFERED_LIMIT = 16 * 1024;
  // The room closes a seat's socket past 200 messages a second (a second's burst) or a message over 16 KiB. Every
  // send on the socket takes from a smaller budget of the same shape; ticks only while a reserve is left over. The
  // game paces its ticks packets (host/coop_wire.inc) well under that, so in play the ticks never reach the reserve.
  const ROOM_RATE = 160;
  const ROOM_RESERVE = 40;
  const ROOM_MAX_BYTES = 16 * 1024;
  const SIGNAL_LIMIT = 256;
  // Control frames are [u32 from page][u32 to page][u32 seq][u32 ack][payload]; seq 0 only acknowledges.
  const CONTROL_HEADER = 16;
  const CONTROL_MAX_BYTES = ROOM_MAX_BYTES - 1 - CONTROL_HEADER;
  const CONTROL_LIMIT = 1024;
  const ACK_DELAY_MS = 50;
  const INBOX_LIMIT = 1024;
  // Negotiated with fixed ids, so both pages create them and neither waits for the other's.
  const CHANNELS = [["coop-ticks", { ordered: false, maxRetransmits: 0 }], ["coop-control", { ordered: true }]];
  const EMPTY = new Uint8Array(0);

  let state = "idle", reason = null, role = null, roomId = null, inviteUrl = null, token = null;
  let socket = null, seated = false, wasSeated = false, attempts = 0, retry = null, pinger = null;
  let partner = false, reported = false, iceServers = null;
  const iceWaiting = [];
  // This page's nonce, and the partner page's from its hello: a new one is a reloaded or replaced page.
  const page = (Math.random() * 2 ** 32) >>> 0;
  let partnerPage = null;
  // The current connection attempt with the partner page. The host names each one; messages of another are stale.
  let link = null;
  // The room socket's budget, and the signalling that waits for it.
  let budget = ROOM_RATE, budgetAt = now(), drainTimer = null;
  const waiting = [];
  // Channel 1: messages the partner has not acknowledged, how many of them the current transport has, and how far
  // the partner's stream has been delivered here.
  const unacked = [];
  let handed = 0, nextSeq = 1, delivered = 0, ackDue = false, ackTimer = null;
  let handler = null;
  const inbox = [];
  const stats = { transport: null, links: 0, switches: 0, reconnects: 0, sent: [0, 0], received: [0, 0], dropped: 0, inboxDropped: 0, duplicates: 0 };

  const ended = () => state === "closed" || state === "error";
  function setState(next, why = null) {
    if (next === state && why === reason) return;
    state = next;
    reason = why;
    log("state", why ? `${next}: ${why}` : next);
    api.onstate?.(next, why);
  }
  // A WebRTC link carries on without the room; the relay needs both seats.
  function refresh() {
    if (ended()) return;
    if (link?.connected && (!link.relay || (seated && partner))) setState("connected");
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
    clearTimeout(ackTimer);
    teardown();
    socket?.close(1000, "left");
    unseat();
  }
  function unseat() {
    socket = null;
    seated = false;
    clearTimeout(pinger);
    clearTimeout(drainTimer);
    drainTimer = null;
    waiting.length = 0;
  }

  // Seat tokens live in this tab's session storage, keyed by room, never in the page's URL: a reload takes
  // the seat back. Storage is looked up when used: a page where it is blocked throws on touching it, and plays without.
  const storageKey = (id) => `crimson.coop.${id}`;
  const storage = () => (sessionStorage === undefined ? globalThis.sessionStorage : sessionStorage);
  function storedSeat(id) {
    try { return JSON.parse(storage().getItem(storageKey(id))); } catch { return null; }
  }
  function storeSeat() {
    try { storage().setItem(storageKey(roomId), JSON.stringify({ role, token })); } catch {}
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
  // Room ids are Crockford base32 and get read out: any case, spaces and hyphens, I or L for 1, O for 0.
  const normalize = (id) => String(id).toLowerCase().replace(/[\s-]/g, "").replace(/[il]/g, "1").replace(/o/g, "0");
  // Joins as the guest, or takes back the seat this tab holds in the room (a reload of either player).
  async function join(id) {
    begin("guest");
    roomId = normalize(id);
    const seat = storedSeat(roomId);
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
    if (ended()) return;
    if (ready) open();
    else if (ready === null) backoff();
  }
  function backoff() {
    attempts++;
    // Refused handshakes look like network errors; a page that never got in stops asking.
    if (!wasSeated && attempts >= JOIN_ATTEMPTS) return fail("could not reach the room");
    refresh();
    retry = setTimeout(() => {
      stats.reconnects++;
      connect();
    }, BACKOFF_MS[Math.min(attempts, BACKOFF_MS.length) - 1]);
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
    unseat();
    if (code === 4000) return fail("the room closed");
    if (code === 4001) return fail("the room was opened in another tab");
    // A flood's budget refills within a second; the room's other refusals would repeat.
    if (code === 1009 || (code === 1008 && why !== "too many messages")) return fail(`the room refused this page: ${why}`);
    log("room socket lost", code, why);
    backoff();
  }

  // The room socket's budget, refilled continuously like the room's own.
  function take(reserve = 0) {
    const time = now();
    budget = Math.min(ROOM_RATE, budget + ((time - budgetAt) * ROOM_RATE) / 1000);
    budgetAt = time;
    if (budget < reserve + 1) return false;
    budget -= 1;
    return true;
  }
  // Signalling and keepalives wait in order for the budget. They belong to this socket and go with it.
  function signal(message) {
    if (!seated) return;
    if (waiting.length === SIGNAL_LIMIT) return fail("signalling backed up on the room socket");
    waiting.push(typeof message === "string" ? message : JSON.stringify(message));
    drain();
  }
  // Sends what waits for the room socket while the budget lasts, signalling first, then relayed control frames.
  function drain() {
    clearTimeout(drainTimer);
    drainTimer = null;
    while (seated) {
      const text = waiting[0];
      const frame = text === undefined && relaying() ? controlFrame() : null;
      if (text === undefined && !frame) return;
      if (!take()) {
        drainTimer = setTimeout(drain, Math.ceil(((1 - budget) * 1000) / ROOM_RATE));
        return;
      }
      if (text !== undefined) socket.send(waiting.shift());
      else {
        controlSent();
        socket.send(framed(1, frame));
      }
    }
  }
  const relaying = () => link?.connected && link.relay && seated && partner && partnerPage !== null;
  function framed(channel, bytes) {
    const frame = new Uint8Array(bytes.length + 1);
    frame[0] = channel;
    frame.set(bytes, 1);
    return frame;
  }

  // Text frames are JSON: the room's own seat, peer and ice messages, or the partner's signalling. Binary frames
  // are always the partner's relayed bytes.
  function receive(data) {
    if (typeof data !== "string") {
      const bytes = new Uint8Array(data);
      if (bytes.length && bytes[0] < CHANNELS.length) arrive(bytes[0], bytes.subarray(1));
      return;
    }
    if (data === "pong") return;
    let message;
    try { message = JSON.parse(data); } catch { return log("unreadable room message"); }
    switch (message?.type) {
      case "seat": return seat(message);
      case "peer": return peer(message.present);
      case "ice": return ice(message.ice_servers);
      case "hello": return hello(message.page);
      case "bye": return bye(message.page);
      case "offer": return offer(message);
      case "answer": return answer(message);
      case "candidate": return candidate(message);
      case "switch": return switched(message);
    }
  }
  function seat(message) {
    seated = wasSeated = true;
    attempts = 0;
    if (message.guest_token) {
      token = message.guest_token;
      storeSeat();
    }
    if (!iceServers) signal({ type: "ice" });
    keepalive();
  }
  function keepalive() {
    pinger = setTimeout(() => {
      signal("ping");
      keepalive();
    }, PING_MS);
  }
  // Room presence is only signalling: a partner whose socket blips keeps its link. Every present partner hears
  // this page's hello, which says whether the page behind the seat is still the same; a page that closes says
  // goodbye. onpeer's second argument says the partner's page, and its game, is gone.
  function peer(present) {
    partner = present;
    if (present) signal({ type: "hello", page });
    else if (reported) {
      reported = false;
      api.onpeer?.(false);
    }
    refresh();
  }
  // The streams and the link with a page that went end with it.
  function forget() {
    if (unacked.length) log("control messages for the partner's old page dropped", unacked.length);
    unacked.length = handed = delivered = 0;
    nextSeq = 1;
    ackDue = false;
    teardown();
  }
  function hello(next) {
    const replaced = partnerPage !== null && next !== partnerPage;
    if (replaced) forget();
    partnerPage = next;
    // A replaced page lost its game: the session with it cannot go on (the shell ends it).
    if (replaced || !reported) {
      reported = true;
      api.onpeer?.(true, replaced);
    }
    if (role === "host" && !link?.connected) offerLink();
    else if (link?.relay) {
      // The partner (re)took its seat: anything relayed while it was away is sent again.
      if (!link.answered) signal({ type: "switch", link: link.id, transport_epoch: link.epoch });
      replay();
    } else pump();
    refresh();
  }
  function bye(from) {
    if (from !== partnerPage) return;
    forget();
    partnerPage = null;
    reported = false;
    api.onpeer?.(false, true);
    refresh();
  }
  function ice(servers) {
    iceServers = servers;
    for (const resolve of iceWaiting.splice(0)) resolve(servers);
  }
  const iceReady = () => (iceServers ? Promise.resolve(iceServers) : new Promise((resolve) => iceWaiting.push(resolve)));

  function newLink(id) {
    teardown();
    const current = link = {
      id, pc: null, channels: [], remote: [], local: [], described: false, signalled: false,
      connected: false, relay: false, answered: false, epoch: 0, timer: null, stall: null, drain: null,
    };
    stats.links++;
    current.timer = setTimeout(() => { if (link === current && !current.connected) fallback(current, "not connected in time"); }, CONNECT_TIMEOUT_MS);
    return current;
  }
  function teardown() {
    if (!link) return;
    for (const timer of [link.timer, link.stall, link.drain]) clearTimeout(timer);
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
        if (!event.candidate || link !== current) return;
        const message = { type: "candidate", link: current.id, candidate: event.candidate.toJSON() };
        // A candidate can come before its description has gone; the partner needs that first.
        if (current.signalled) signal(message);
        else current.local.push(message);
      };
      // Older Firefox has no connectionState; its iceConnectionState says the same.
      pc.onconnectionstatechange = pc.oniceconnectionstatechange = () => health(current);
      if (offerSdp) await describe(current, { type: "offer", sdp: offerSdp });
      await pc.setLocalDescription(offerSdp ? await pc.createAnswer() : await pc.createOffer());
      if (link === current) described(current, offerSdp ? "answer" : "offer");
    } catch (error) { failed(current, error); }
  }
  function described(current, type) {
    signal({ type, link: current.id, sdp: current.pc.localDescription.sdp });
    current.signalled = true;
    for (const message of current.local.splice(0)) signal(message);
  }
  function watch(current, id, channel) {
    channel.binaryType = "arraybuffer";
    channel.onopen = () => { if (link === current && current.channels.every((each) => each.readyState === "open")) connected(current); };
    channel.onclose = () => failed(current, `${channel.label} closed`);
    channel.onmessage = (event) => { if (link === current) arrive(id, new Uint8Array(event.data)); };
    return channel;
  }
  // Disconnected may pass by itself. Past a moment the host restarts ICE on the same link; past a few seconds
  // the pages give up on it, well before the connection would report failed.
  function health(current) {
    const pc = current.pc, states = [pc.connectionState, pc.iceConnectionState];
    if (link !== current || current.relay) return;
    if (states.includes("failed")) return failed(current, "peer connection failed");
    if (states.includes("disconnected")) {
      if (current.stall) return;
      log("peer connection disconnected");
      current.stall = setTimeout(() => {
        if (role === "host") restart(current);
        current.stall = setTimeout(() => failed(current, "peer connection stayed disconnected"), DISCONNECTED_MS - ICE_RESTART_MS);
      }, ICE_RESTART_MS);
    } else if (states.includes("connected") || states.includes("completed")) {
      clearTimeout(current.stall);
      current.stall = null;
    }
  }
  async function restart(current) {
    try {
      const pc = current.pc;
      pc.restartIce?.();
      current.signalled = false;
      await pc.setLocalDescription(await pc.createOffer({ iceRestart: true }));
      if (link === current) described(current, "offer");
    } catch (error) { failed(current, error); }
  }
  // Candidates that arrive before the remote description wait for it.
  async function describe(current, description) {
    await current.pc.setRemoteDescription(description);
    current.described = true;
    for (const each of current.remote.splice(0)) addCandidate(current, each);
  }
  const addCandidate = (current, each) => current.pc.addIceCandidate(each).catch((error) => log("candidate refused", String(error)));
  const offerLink = () => connectPeer(newLink(Math.random().toString(36).slice(2, 10)));
  function offer(message) {
    if (role !== "guest") return;
    if (link?.id !== message.link) return connectPeer(newLink(message.link), message.sdp);
    // The same link offered again is the host's ICE restart.
    if (link.pc && !link.relay) reanswer(link, message.sdp);
  }
  async function reanswer(current, sdp) {
    try {
      current.signalled = false;
      await current.pc.setRemoteDescription({ type: "offer", sdp });
      await current.pc.setLocalDescription(await current.pc.createAnswer());
      if (link === current) described(current, "answer");
    } catch (error) { failed(current, error); }
  }
  function answer(message) {
    if (role !== "host" || link?.id !== message.link) return;
    const current = link;
    describe(current, { type: "answer", sdp: message.sdp }).catch((error) => failed(current, error));
  }
  function candidate(message) {
    if (link?.id !== message.link) return;
    if (link.described) addCandidate(link, message.candidate);
    else link.remote.push(message.candidate);
  }

  function connected(current) {
    current.connected = true;
    clearTimeout(current.timer);
    stats.transport = current.relay ? "ws-relay" : "webrtc";
    refresh();
    replay();
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
    // Firefox has no selected pair on its transport stats; it marks the pair instead, or only nominates it.
    const pair = pairId ? report.get(pairId) : all.find((each) => each.type === "candidate-pair" && (each.selected || (each.nominated && each.state === "succeeded")));
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
  // replies to it, so both send on the same transport. A partner that cannot hear the switch cannot follow it:
  // then the link ends, and the next hello starts another.
  function fallback(current, why) {
    log("webrtc gave up", why);
    if (!seated || !partner) {
      teardown();
      return refresh();
    }
    const epoch = current.epoch + 1;
    signal({ type: "switch", link: current.id, transport_epoch: epoch });
    relay(current, epoch);
  }
  function relay(current, epoch) {
    current.epoch = epoch;
    if (current.relay) return;
    current.relay = true;
    clearTimeout(current.stall);
    current.drain = setTimeout(() => release(current), DRAIN_MS);
    stats.switches++;
    connected(current);
  }
  const release = (current) => {
    clearTimeout(current.drain);
    current.pc?.close();
  };
  function switched(message) {
    if (link?.id !== message.link) {
      // The host names links: a guest follows the host's newest, even when it skips WebRTC altogether.
      if (role !== "guest" || message.reply) return;
      newLink(message.link);
    }
    const current = link, epoch = message.transport_epoch;
    if (epoch > current.epoch) relay(current, epoch);
    // The partner is on the relay at this epoch: the old connection has nothing more to deliver.
    if (epoch === current.epoch && current.relay) {
      current.answered = true;
      release(current);
    }
    if (!message.reply) signal({ type: "switch", link: current.id, transport_epoch: current.epoch, reply: true });
  }

  // Channel 1 runs end to end over whichever transport is current: numbered messages, acknowledged cumulatively,
  // kept until acknowledged and handed again to every new transport; the receiver drops what it already has.
  function controlFrame() {
    const entry = unacked[handed];
    if (entry) return controlBytes(entry.seq, entry.bytes);
    return ackDue ? controlBytes(0, EMPTY) : null;
  }
  function controlBytes(seq, bytes) {
    const frame = new Uint8Array(CONTROL_HEADER + bytes.length);
    const view = new DataView(frame.buffer);
    view.setUint32(0, page);
    view.setUint32(4, partnerPage);
    view.setUint32(8, seq);
    view.setUint32(12, delivered);
    frame.set(bytes, CONTROL_HEADER);
    return frame;
  }
  // Every frame carries the ack, so one waiting goes with it.
  function controlSent() {
    if (handed < unacked.length) handed++;
    ackDue = false;
    clearTimeout(ackTimer);
    ackTimer = null;
  }
  function pump() {
    if (ended() || partnerPage === null || !link?.connected) return;
    if (link.relay) return drain();
    for (let frame; link && !link.relay && (frame = controlFrame()); ) {
      try { link.channels[1].send(frame); } catch (error) { return failed(link, error); }
      controlSent();
    }
  }
  function replay() {
    handed = 0;
    pump();
  }
  // Both transports carry at most what the room relays: a page that sends more over WebRTC is not a game's.
  function arrive(channel, bytes) {
    if (bytes.length > ROOM_MAX_BYTES - 1) return log("oversized message dropped", channel, bytes.length);
    if (channel === 0) return deliver(0, bytes);
    if (bytes.length < CONTROL_HEADER) return log("short control frame");
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // A frame between other pages is a replaced page's, still in flight.
    if (view.getUint32(0) !== partnerPage || view.getUint32(4) !== page) return;
    const ack = view.getUint32(12);
    let count = 0;
    while (count < unacked.length && unacked[count].seq <= ack) count++;
    unacked.splice(0, count);
    handed = Math.max(0, handed - count);
    const seq = view.getUint32(8);
    if (!seq) return;
    ackDue = true;
    if (seq === delivered + 1) {
      delivered = seq;
      deliver(1, bytes.subarray(CONTROL_HEADER));
    } else if (seq <= delivered) stats.duplicates++;
    // A frame past a gap cannot come on an ordered transport; its replay will.
    if (ackDue && !ended() && !ackTimer) {
      ackTimer = setTimeout(() => {
        ackTimer = null;
        pump();
      }, ACK_DELAY_MS);
    }
  }

  function deliver(channel, bytes) {
    stats.received[channel]++;
    if (handler) return handler(channel, bytes);
    if (inbox.length === INBOX_LIMIT) {
      // Old ticks make room first; a control message is never dropped.
      const tick = inbox.findIndex(([each]) => each === 0);
      if (tick < 0 && channel === 1) {
        log("inbox full of control messages", inbox.length);
        return fail("the game did not read its control messages");
      }
      stats.inboxDropped++;
      if (tick < 0) return;
      inbox.splice(tick, 1);
    }
    inbox.push([channel, bytes]);
  }
  // Ticks (channel 0) go now or never: false when they drop, because their transport is backed up, short of its
  // budget or missing. Control messages (channel 1) always go, waiting for a transport if they must: false only once
  // the session has ended.
  function send(channel, bytes) {
    if (ended()) return false;
    if (channel === 1) {
      if (bytes.length > CONTROL_MAX_BYTES) throw RangeError(`a control message carries at most ${CONTROL_MAX_BYTES} bytes`);
      if (unacked.length === CONTROL_LIMIT) return fail(`${CONTROL_LIMIT} control messages wait for the partner`), false;
      unacked.push({ seq: nextSeq++, bytes: bytes.slice() });
      stats.sent[1]++;
      pump();
      return true;
    }
    if (!link?.connected) return false;
    if (link.relay) {
      if (!seated || !partner) return false;
      if (bytes.length + 1 > ROOM_MAX_BYTES) {
        log("tick packet too large for the relay", bytes.length);
        return false;
      }
      if (socket.bufferedAmount > TICKS_BUFFERED_LIMIT || !take(ROOM_RESERVE)) {
        stats.dropped++;
        return false;
      }
      socket.send(framed(0, bytes));
    } else {
      const channelOut = link.channels[0];
      if (channelOut.bufferedAmount > TICKS_BUFFERED_LIMIT) {
        stats.dropped++;
        return false;
      }
      // A channel closing under us is a failing connection, not the game's error.
      try { channelOut.send(bytes); } catch (error) {
        failed(link, error);
        return false;
      }
    }
    stats.sent[0]++;
    return true;
  }
  // The partner hears this page go, if the room can carry its goodbye.
  function close() {
    if (state === "closed") return;
    if (partner && partnerPage !== null) signal({ type: "bye", page });
    shutdown();
    setState("closed");
  }

  const api = {
    host, join, send, close,
    stats: () => ({ ...stats, sent: [...stats.sent], received: [...stats.received], state, inbox: inbox.length, unacked: unacked.length }),
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
