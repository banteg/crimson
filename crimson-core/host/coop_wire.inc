// The co-op session's wire protocol (docs/rewrite/network-coop.md §6.2) over the
// engine (host/coop.inc): each peer runs the engine for its own seat and the
// two exchange their records and the run's control over the two channels the
// transport keeps (client/web/coop.js). Channel 0 is best effort: a ticks
// packet a frame carries this machine's newest unacknowledged records, its
// acknowledgement of the partner's, a ping, and confirmed ticks' hashes the
// partner has not acknowledged and its acknowledgement of this machine's.
// Channel 1 arrives once and in order: the session's messages, and repairs for
// records that fell out of the ticks packets' window. Each run is an epoch, and
// what belongs to another run is ignored. Headless for now: checks/game_coop.mjs
// pipes two modules together through these exports.
#include <deque>

enum CoopChannel { COOP_TICKS, COOP_CONTROL };
// Channel 1's messages: u8 type, u32 epoch, then the type's fields.
enum CoopType : uint8_t {
  COOP_HELLO = 1,
  COOP_START_RUN,
  COOP_START_ACK,
  COOP_START_CANCEL,
  COOP_INPUT_REPAIR,
  COOP_PAUSE,
  COOP_LEAVE,
  COOP_NEXT_RUN,
  COOP_RUN_SIGNED,
  COOP_DESYNC,
  COOP_ERROR,
};
// What game_coop_request asks for.
enum CoopAsk { COOP_ASK_OPEN = 1, COOP_ASK_PAUSE, COOP_ASK_LEAVE, COOP_ASK_NEXT_RUN, COOP_ASK_START };
// game_coop_status: these flags, then why the session or its run stopped
// (CoopReason, bits 16-23), then the Guest's choice for the next run the Host
// holds (plus one, bits 24-27).
enum : uint32_t {
  COOP_CONNECTED = 1, // both sides said hello with the same build, and the session goes on
  COOP_STARTED = 2,   // the epoch's run started on both sides
  COOP_PAUSED = 4,
  COOP_WAITING = 8, // this machine's perk request waits for its tick's confirmation
  COOP_PICKER = 16, // this machine picks the open menu's perk on its next tick
  COOP_LEAVING = 32,
  COOP_ENDED = 64, // the run reached its last tick, confirmed
  COOP_DESYNCED = 128,
  COOP_FAILED = 256,   // a protocol error
  COOP_STARTING = 512, // the Host waits for the Guest to start the run
  COOP_REMOTE = 1024,  // the partner found the desync or the error
};
// Also the codes ERROR sends.
enum CoopReason : uint8_t {
  COOP_FINE,
  COOP_VERSION,     // the builds differ
  COOP_BAD_RECORD,  // a record no input could make
  COOP_BAD_MESSAGE, // a message no peer sends
  COOP_STALLED,     // the partner's records stopped arriving (progress timeout)
  COOP_SILENT,      // the partner stopped sending (liveness timeout)
  COOP_UNANSWERED,  // the Guest never acknowledged the run's start
  COOP_LEFT,
  COOP_PARTNER_LEFT,
  // game_coop_disconnect's: the transport closed, or the partner left the room
  // (its page closed or reloaded).
  COOP_DISCONNECTED,
  COOP_PARTNER_GONE,
};
static constexpr uint8_t COOP_MAGIC = 0xC3;
static constexpr uint16_t COOP_PROTOCOL = 1;
static constexpr uint32_t COOP_NONE = 0xFFFFFFFF;
static constexpr int COOP_WINDOW = 8, COOP_HASHES = 4;
static constexpr double COOP_TICK_MS = 1000.0 / 60, COOP_PROGRESS_MS = 5000, COOP_LIVENESS_MS = 15000,
                        COOP_START_MS = 10000, COOP_RTT_GUESS_MS = 100;

static struct CoopWire {
  bool session; // game_coop_connect began one
  bool hello;   // the partner's HELLO named this build
  bool closed;  // over: no more ticks packets, and what arrives is ignored; channel 1 still drains
  int seat;     // 0 the Host, 1 the Guest
  CoopReason reason;
  bool failed, remote;
  // The current run: its epoch (0 before the first), started on both sides
  // (START_RUN, START_ACK), and the Host waiting for START_ACK since start_at.
  uint32_t epoch;
  bool started, starting;
  double start_at;
  // The pause with the highest sequence (the Host's on a tie), and whose.
  uint32_t pause_seq;
  int pause_by;
  bool paused;
  // LEAVE as each side sent it: its last tick produced, COOP_NONE without a run.
  // Once both left and the run is over, the session closes at close_at.
  bool left, partner_left;
  uint32_t left_tick, partner_tick;
  double close_at;
  int next_run; // the Guest's choice for the run after this one (the Host's), -1 none
  bool desync_sent;
  // Ticks packets: this side's sequence and when each left; the partner's
  // highest and when it came; the highest of this side's an echo measured; the
  // round trip (-1 unknown) and the partner's packet interval (ms).
  uint32_t ping, peer_ping, echoed;
  double ping_at[COOP_RING], peer_ping_at, rtt, interval;
  double heard_at; // the last packet or message
  // Pacing: the last packet's time, and credit for 60 a second.
  double sent_at, credit, credit_at;
  int head_sent;               // the newest record a packet carried
  double record_at[COOP_RING]; // when each record last left
  int peer_head;               // the newest record the partner said it produced
  int remote_seen;             // the remote frontier, last time it moved
  double progress_at;
  // Hashes: the next tick a packet reports; the newest tick up to which the
  // partner holds every one of this machine's, and this machine the partner's.
  int hash_next, hash_ack, hash_heard;
  std::deque<std::vector<uint8_t>> outbox;
  std::vector<uint8_t> rx, tx;
} wire;

struct CoopWriter {
  std::vector<uint8_t> out;
  CoopWriter &bytes(const void *data, size_t size) {
    out.insert(out.end(), (const uint8_t *)data, (const uint8_t *)data + size);
    return *this;
  }
  template <class T> CoopWriter &put(T value) { return bytes(&value, sizeof value); }
};
struct CoopReader {
  const uint8_t *at, *end;
  bool bad = false;
  const uint8_t *take(size_t size) {
    if ((size_t)(end - at) < size) {
      bad = true;
      return nullptr;
    }
    at += size;
    return at - size;
  }
  template <class T> T get() {
    T value{};
    if (const uint8_t *p = take(sizeof value))
      memcpy(&value, p, sizeof value);
    return value;
  }
  bool done() const { return !bad && at == end; }
};
static CoopWriter coop_message(CoopType type, uint32_t epoch) { return std::move(CoopWriter().put(type).put(epoch)); }
static void coop_send(CoopWriter &message) { wire.outbox.push_back(std::move(message.out)); }
// HELLO, naming this build (replay_client_version): `answer` 1 when it answers the partner's.
static void coop_hello(uint8_t answer) {
  uint8_t size = (uint8_t)strlen(replay_client_version);
  CoopWriter hello = coop_message(COOP_HELLO, 0).put(COOP_PROTOCOL).put(size).bytes(replay_client_version, size);
  hello.put(answer);
  coop_send(hello);
}

static bool coop_running() { return wire.started && coop.active; }
static void coop_cancel_request() {
  coop.asked = coop.picking = false;
  coop.request = -1;
}
// The Host's run waiting for START_ACK goes.
static void coop_unstart() {
  if (!wire.starting)
    return;
  wire.starting = false;
  coop_stop();
}
// Both peers hold each other's hashes up to the run's last tick.
static bool coop_compared() { return wire.hash_heard >= coop.next - 1 && wire.hash_ack >= coop.next - 1; }

// A protocol error here: the partner is told, and everything stops.
static void coop_fail(CoopReason reason) {
  if (wire.failed)
    return;
  wire.failed = true;
  wire.reason = reason;
  coop_unstart();
  CoopWriter message = coop_message(COOP_ERROR, wire.epoch).put(reason);
  coop_send(message);
  coop.hold |= COOP_HOLD_STOP;
  wire.closed = true;
}
// The partner is gone (a timeout, or the transport said so): the run ends at
// its last confirmed tick.
static void coop_drop(CoopReason reason) {
  wire.reason = reason;
  wire.closed = true;
  coop_unstart();
  coop.hold |= COOP_HOLD_LEAVE;
  coop_cancel_request();
  if (coop.active)
    coop.end = std::min(coop.end, coop.confirmed);
}

// A run from the config at portable_config, this machine playing its seat:
// the Host's when it starts one, the Guest's on START_RUN.
static bool coop_begin(int delay, int rmax, uint32_t epoch, double now) {
  bool custom = cfg.mode == GAME_MODE_QUEST && cfg.major == 0 && cfg.minor == 0;
  if (custom || cfg.players != 2 || !portable_init(cfg.seed, cfg.mode, cfg.major, cfg.minor) ||
      !game_coop_start(wire.seat, delay, rmax, epoch))
    return false;
  wire.epoch = epoch;
  wire.reason = COOP_FINE;
  wire.started = wire.starting = wire.paused = false;
  wire.pause_seq = 0;
  wire.pause_by = -1;
  wire.next_run = wire.head_sent = wire.peer_head = wire.remote_seen = wire.hash_ack = wire.hash_heard = -1;
  wire.hash_next = 0;
  wire.progress_at = now;
  return true;
}

// Highest sequence wins, the Host's on a tie; while paused neither side produces.
static void coop_pause(uint32_t seq, int by, bool paused) {
  if (seq < wire.pause_seq || (seq == wire.pause_seq && !(by == 0 && wire.pause_by != 0)))
    return;
  wire.pause_seq = seq;
  wire.pause_by = by;
  wire.paused = paused;
  coop.hold = paused ? coop.hold | COOP_HOLD_PAUSE : coop.hold & ~COOP_HOLD_PAUSE;
}

// Leaving (§4 Leave): each side stops producing and tells the other, once, how
// far it produced; a request of its own or an open perk screen closes as a
// cancel. Both run to the lower of the two ticks, going back to the state after
// it if predictions ran past, and the run ends there.
static void coop_leave() {
  wire.left = true;
  wire.left_tick = coop_running() ? (uint32_t)coop.produced : COOP_NONE;
  coop.hold |= COOP_HOLD_LEAVE;
  coop_cancel_request();
  coop_unstart();
  CoopWriter message = coop_message(COOP_LEAVE, wire.epoch).put(wire.left_tick);
  coop_send(message);
}
static void coop_agree() {
  if (!wire.left || !wire.partner_left || !coop.active)
    return;
  coop.end = wire.left_tick != COOP_NONE && wire.partner_tick != COOP_NONE
                 ? (int)std::min(wire.left_tick, wire.partner_tick)
                 : coop.confirmed;
}

// What the passing time does: the timeouts, a desync found, and the close
// after a leave once the partner holds every record the run used.
static void coop_update(double now) {
  if (wire.closed)
    return;
  if (now - wire.heard_at > COOP_LIVENESS_MS)
    return coop_drop(COOP_SILENT);
  // The progress timeout runs only while the partner says it produced records
  // this machine lacks: a pause or a perk menu holds no record back.
  if (coop_running()) {
    if (coop.remote != wire.remote_seen || wire.peer_head <= coop.remote) {
      wire.remote_seen = coop.remote;
      wire.progress_at = now;
    } else if (now - wire.progress_at > COOP_PROGRESS_MS) {
      return coop_drop(COOP_STALLED);
    }
  }
  // The Host gives up on START_ACK and tells the Guest: should START_RUN
  // still reach it, this follows on channel 1 and stops the run there too.
  if (wire.starting && now - wire.start_at > COOP_START_MS) {
    coop_unstart();
    wire.reason = COOP_UNANSWERED;
    CoopWriter message = coop_message(COOP_START_CANCEL, wire.epoch);
    coop_send(message);
  }
  if (coop.active && coop.desync.tick >= 0 && !wire.desync_sent) {
    wire.desync_sent = wire.closed = true;
    CoopWriter message =
        coop_message(COOP_DESYNC, wire.epoch).put(coop.desync.tick).put(coop.desync.local).put(coop.desync.remote);
    return coop_send(message);
  }
  // The partner learns this side holds its records and hashes from this side's
  // packets: they go on a while after (a second, or four round trips).
  if (wire.left && wire.partner_left && wire.close_at < 0 &&
      (!coop_running() || (coop_over() && coop.peer_ack >= coop.next - 1 && coop_compared())))
    wire.close_at = now + std::max(1000.0, 4 * wire.rtt);
  if (wire.close_at >= 0 && now >= wire.close_at)
    wire.closed = true;
}

// The hashes a packet reports, from `first`: of the confirmed ticks the partner
// can confirm too (it holds this machine's records), those it has not
// acknowledged, COOP_HASHES a packet in turn from the oldest, so each comes
// round again until it is acknowledged.
static int coop_hashes(int &first) {
  int top = std::min(coop.confirmed, coop.peer_ack);
  if (top <= wire.hash_ack)
    return 0;
  if (wire.hash_next <= wire.hash_ack || wire.hash_next > top)
    wire.hash_next = wire.hash_ack + 1;
  first = wire.hash_next;
  int count = std::min(COOP_HASHES, top - first + 1);
  wire.hash_next += count;
  return count;
}

// The frame's ticks packet (§3.7): at most one a frame and 60 a second. One
// carrying a new record goes as soon as there is credit for it; a keepalive
// leaves a packet's credit to spare. Before the first run a keepalive carries
// only pings; once a run is over its records and hashes keep going.
static int coop_ticks_out(double now) {
  wire.credit = std::min(2.0, wire.credit + (now - wire.credit_at) * 60 / 1000);
  wire.credit_at = now;
  bool run = coop_running();
  if (now <= wire.sent_at || wire.credit < (run && coop.produced > wire.head_sent ? 1 : 2))
    return 0;
  wire.credit -= 1;
  wire.sent_at = now;
  int count = run ? std::clamp(coop.produced - coop.peer_ack, 0, COOP_WINDOW) : 0;
  int first = 0, hashes = run ? coop_hashes(first) : 0;
  wire.ping_at[++wire.ping & (COOP_RING - 1)] = now;
  uint16_t hold = wire.peer_ping ? (uint16_t)std::min(65535.0, now - wire.peer_ping_at) : 0;
  uint32_t packed = 0;
  CoopWriter packet;
  // Flags: focus (the live session's to clear).
  packet.put(COOP_MAGIC).put((uint8_t)count).put((uint8_t)2).put((uint8_t)hashes);
  packet.put(wire.epoch).put(wire.ping).put(wire.peer_ping).put(hold).put((uint16_t)0);
  packet.put(run ? (uint32_t)coop.produced : COOP_NONE).put(run ? (uint32_t)coop.remote : COOP_NONE);
  packet.put((uint32_t)first).put(run && wire.hash_heard >= 0 ? (uint32_t)wire.hash_heard : COOP_NONE);
  size_t at = packet.out.size();
  packet.put(packed);
  for (int i = 0; i < count; ++i) {
    int t = coop.produced - count + 1 + i;
    const CoopInput &record = coop.records[coop.local][t & (COOP_RING - 1)].record;
    packet.put(record.input);
    packed |= (uint32_t)record.cmd << 4 * i;
    wire.record_at[t & (COOP_RING - 1)] = now;
  }
  memcpy(packet.out.data() + at, &packed, 4);
  for (int t = first; t < first + hashes; ++t)
    packet.put(coop.ticks[t & (COOP_RING - 1)].hash);
  if (run)
    wire.head_sent = coop.produced;
  wire.tx = std::move(packet.out);
  ++coop.stats.wire.sent;
  return (int)wire.tx.size();
}

// Records out of the ticks packets' window (older than its newest
// COOP_WINDOW) that stay unacknowledged a round trip and two of the partner's
// packet intervals after they last left go again on channel 1, from the oldest
// the partner lacks: each at most once a round trip.
static void coop_repair(double now) {
  if (!coop_running())
    return;
  double wait = (wire.rtt >= 0 ? wire.rtt : COOP_RTT_GUESS_MS) + 2 * wire.interval;
  int first = coop.peer_ack + 1, last = first;
  while (last <= coop.produced - COOP_WINDOW && now - wire.record_at[last & (COOP_RING - 1)] >= wait)
    ++last;
  if (last == first)
    return;
  CoopWriter message = coop_message(COOP_INPUT_REPAIR, wire.epoch).put((uint32_t)first).put((uint16_t)(last - first));
  for (int t = first; t < last; ++t) {
    const CoopInput &record = coop.records[coop.local][t & (COOP_RING - 1)].record;
    message.put(record.input).put(record.cmd);
    wire.record_at[t & (COOP_RING - 1)] = now;
  }
  coop_send(message);
  ++coop.stats.wire.repairs;
  coop.stats.wire.repaired += last - first;
}

// The partner's record for tick `t`: an invalid one, or one no peer sends, is a
// protocol error.
static bool coop_record_in(int t, const CoopInput &record) {
  if (!coop_valid(record) || coop_take(1 - wire.seat, t, record, 1) < 0) {
    coop_fail(COOP_BAD_RECORD);
    return false;
  }
  return true;
}

static void coop_ticks_in(CoopReader &in, double now) {
  uint8_t magic = in.get<uint8_t>(), count = in.get<uint8_t>();
  in.get<uint8_t>();
  uint8_t hashes = in.get<uint8_t>();
  uint32_t epoch = in.get<uint32_t>(), ping = in.get<uint32_t>(), echo = in.get<uint32_t>();
  uint16_t hold = in.get<uint16_t>();
  in.get<uint16_t>();
  uint32_t head = in.get<uint32_t>(), ack = in.get<uint32_t>(), hash_first = in.get<uint32_t>(),
           hash_ack = in.get<uint32_t>(), packed = in.get<uint32_t>();
  const uint8_t *inputs = in.take(count * sizeof(PortableInput));
  const uint8_t *reports = in.take(hashes * sizeof(uint32_t));
  if (!in.done() || magic != COOP_MAGIC || count > COOP_WINDOW || hashes > COOP_HASHES)
    return coop_fail(COOP_BAD_MESSAGE);
  ++coop.stats.wire.received;
  // The partner's pace and losses, and the round trip, from any epoch.
  if (ping > wire.peer_ping) {
    if (wire.peer_ping)
      wire.interval += ((now - wire.peer_ping_at) / (ping - wire.peer_ping) - wire.interval) / 8;
    coop.stats.wire.lost += ping - wire.peer_ping - 1;
    wire.peer_ping = ping;
    wire.peer_ping_at = now;
  } else if (epoch == wire.epoch) {
    --coop.stats.wire.lost; // late, not lost
  }
  if (echo > wire.echoed && echo <= wire.ping && wire.ping - echo < COOP_RING) {
    double sample = std::max(0.0, now - wire.ping_at[echo & (COOP_RING - 1)] - hold);
    wire.rtt = wire.rtt < 0 ? sample : wire.rtt + (sample - wire.rtt) / 8;
    wire.echoed = echo;
    coop.stats.wire.rtt_ms = (int32_t)lround(wire.rtt);
  }
  if (epoch != wire.epoch) {
    ++coop.stats.wire.stale;
    return;
  }
  if (!coop_running())
    return;
  // Ticks and acknowledgements within reach: the partner's records end at its
  // head, it acknowledges no record this machine has not produced and no hash
  // of a tick it has not confirmed, and it reports hashes only of ticks whose
  // records this machine acknowledged.
  if ((head == COOP_NONE ? count > 0 : head > INT_MAX || head + 1 < count) ||
      (ack != COOP_NONE && (ack > INT_MAX || (int)ack > coop.produced)) ||
      (hash_ack != COOP_NONE && (hash_ack > INT_MAX || (int)hash_ack > coop.confirmed)) ||
      (hashes && (hash_first > (uint32_t)INT_MAX - hashes || (int)hash_first + hashes - 1 > coop.remote)))
    return coop_fail(COOP_BAD_MESSAGE);
  for (int i = 0; i < count; ++i) {
    CoopInput record = {{}, (uint8_t)(packed >> 4 * i & 15)};
    memcpy(&record.input, inputs + i * sizeof(PortableInput), sizeof(PortableInput));
    if (!coop_record_in((int)head - count + 1 + i, record))
      return;
  }
  if (ack != COOP_NONE)
    coop.peer_ack = std::max(coop.peer_ack, (int)ack);
  if (head != COOP_NONE)
    wire.peer_head = std::max(wire.peer_head, (int)head);
  for (int i = 0; i < hashes; ++i) {
    uint32_t hash;
    memcpy(&hash, reports + i * sizeof hash, sizeof hash);
    coop_reported((int)hash_first + i, hash);
  }
  while (coop_heard(wire.hash_heard + 1))
    ++wire.hash_heard;
  if (hash_ack != COOP_NONE)
    wire.hash_ack = std::max(wire.hash_ack, (int)hash_ack);
}

static void coop_control_in(CoopReader &in, double now) {
  CoopType type = in.get<CoopType>();
  uint32_t epoch = in.get<uint32_t>();
  // Messages of another run than this one are ignored; the session's own
  // (HELLO, LEAVE, ERROR) are not, and START_RUN opens a later one.
  bool current = epoch == wire.epoch && coop_running();
  bool host = wire.seat == 0;
  switch (type) {
  case COOP_HELLO: {
    uint16_t protocol = in.get<uint16_t>();
    uint8_t size = in.get<uint8_t>();
    const uint8_t *build = in.take(size);
    uint8_t answer = in.get<uint8_t>();
    if (!in.done() || answer > 1)
      return coop_fail(COOP_BAD_MESSAGE);
    if (protocol != COOP_PROTOCOL || size != strlen(replay_client_version) ||
        memcmp(build, replay_client_version, size))
      return coop_fail(COOP_VERSION);
    wire.hello = true;
    // The partner's first, which this machine's may have missed (sent before
    // this machine connected): answered.
    if (!answer)
      coop_hello(1);
    return;
  }
  case COOP_START_RUN: {
    uint8_t delay = in.get<uint8_t>(), rmax = in.get<uint8_t>();
    PortableConfig config = in.get<PortableConfig>();
    uint8_t choice = in.get<uint8_t>();
    // The run's replay header (M3): none yet.
    in.take(in.get<uint16_t>());
    if (!in.done() || host || !wire.hello)
      return coop_fail(COOP_BAD_MESSAGE);
    // A Guest that left told the Host before this arrived.
    if (epoch <= wire.epoch || wire.left) {
      ++coop.stats.wire.stale;
      return;
    }
    cfg = config;
    if (delay < 1 || delay > COOP_DELAY || rmax > COOP_LEAD || choice > 2 || !coop_begin(delay, rmax, epoch, now))
      return coop_fail(COOP_BAD_MESSAGE);
    wire.started = true;
    CoopWriter message = coop_message(COOP_START_ACK, epoch);
    return coop_send(message);
  }
  case COOP_START_ACK:
    if (!in.done() || !host)
      return coop_fail(COOP_BAD_MESSAGE);
    if (!wire.starting || epoch != wire.epoch) {
      ++coop.stats.wire.stale;
      return;
    }
    wire.starting = false;
    wire.started = true;
    coop.hold &= ~COOP_HOLD_START;
    return;
  case COOP_START_CANCEL:
    if (!in.done() || host)
      return coop_fail(COOP_BAD_MESSAGE);
    if (!current) {
      ++coop.stats.wire.stale;
      return;
    }
    wire.started = wire.paused = false;
    wire.reason = COOP_UNANSWERED;
    coop_cancel_request();
    return coop_stop();
  case COOP_INPUT_REPAIR: {
    uint32_t start = in.get<uint32_t>();
    uint16_t count = in.get<uint16_t>();
    const uint8_t *records = in.take(count * (sizeof(PortableInput) + 1));
    if (!in.done() || start > INT_MAX - count)
      return coop_fail(COOP_BAD_MESSAGE);
    if (!current) {
      ++coop.stats.wire.stale;
      return;
    }
    for (int i = 0; i < count; ++i) {
      const uint8_t *at = records + i * (sizeof(PortableInput) + 1);
      CoopInput record = {{}, at[sizeof(PortableInput)]};
      memcpy(&record.input, at, sizeof(PortableInput));
      if (!coop_record_in((int)start + i, record))
        return;
    }
    return;
  }
  case COOP_PAUSE: {
    uint32_t seq = in.get<uint32_t>();
    uint8_t paused = in.get<uint8_t>();
    if (!in.done() || paused > 1)
      return coop_fail(COOP_BAD_MESSAGE);
    if (!current) {
      ++coop.stats.wire.stale;
      return;
    }
    return coop_pause(seq, 1 - wire.seat, paused);
  }
  case COOP_LEAVE: {
    uint32_t last = in.get<uint32_t>();
    // The partner produced at least what this machine holds of its records.
    bool run = epoch == wire.epoch && coop_running() && last != COOP_NONE;
    if (!in.done() || wire.partner_left || (run && (last > INT_MAX || (int)last < coop.remote)))
      return coop_fail(COOP_BAD_MESSAGE);
    wire.partner_left = true;
    wire.partner_tick = run ? last : COOP_NONE;
    if (!wire.left) {
      wire.reason = COOP_PARTNER_LEFT;
      coop_leave();
    }
    return coop_agree();
  }
  case COOP_NEXT_RUN: {
    uint8_t choice = in.get<uint8_t>();
    if (!in.done() || !host || choice > 2)
      return coop_fail(COOP_BAD_MESSAGE);
    if (!current) {
      ++coop.stats.wire.stale;
      return;
    }
    // The first the Host sees wins.
    if (wire.next_run < 0)
      wire.next_run = choice;
    return;
  }
  case COOP_RUN_SIGNED:
    // A co-op run's signatures (M3): none yet.
    return;
  case COOP_DESYNC: {
    int tick = in.get<int32_t>();
    uint32_t local = in.get<uint32_t>(), remote = in.get<uint32_t>();
    if (!in.done())
      return coop_fail(COOP_BAD_MESSAGE);
    if (!current) {
      ++coop.stats.wire.stale;
      return;
    }
    if (coop.desync.tick < 0)
      coop.desync = {tick, remote, local};
    coop.hold |= COOP_HOLD_STOP;
    wire.remote = wire.desync_sent = wire.closed = true;
    return;
  }
  case COOP_ERROR: {
    uint8_t code = in.get<uint8_t>();
    if (!in.done())
      return coop_fail(COOP_BAD_MESSAGE);
    wire.failed = wire.remote = wire.closed = true;
    wire.reason = (CoopReason)code;
    coop.hold |= COOP_HOLD_STOP;
    return coop_unstart();
  }
  }
  coop_fail(COOP_BAD_MESSAGE);
}

extern "C" {
// A session as seat `seat` (0 the Host, 1 the Guest) over a connected
// transport, ending any co-op run: it says hello, and answers the partner's.
// What arrived before it is gone; the partner's hello comes again as the
// answer to this one.
__attribute__((export_name("game_coop_connect"))) int game_coop_connect(int seat, double now) {
  if (seat < 0 || seat > 1)
    return 0;
  coop_stop();
  wire = {};
  wire.session = true;
  wire.seat = seat;
  wire.pause_by = wire.next_run = wire.head_sent = wire.peer_head = wire.remote_seen = wire.hash_ack =
      wire.hash_heard = -1;
  wire.close_at = wire.rtt = -1;
  wire.interval = COOP_TICK_MS;
  wire.heard_at = wire.credit_at = wire.progress_at = now;
  wire.sent_at = -1e300;
  wire.credit = 1;
  coop.stats.wire = {};
  coop_hello(0);
  return 1;
}
// The transport closed (`reason` COOP_DISCONNECTED) or the partner left the
// room (COOP_PARTNER_GONE), as client/web/coop.js saw it: the session ends, and
// the run at its last confirmed tick. 1 when it ends it.
__attribute__((export_name("game_coop_disconnect"))) int game_coop_disconnect(int reason) {
  if (!wire.session || wire.closed || (reason != COOP_DISCONNECTED && reason != COOP_PARTNER_GONE))
    return 0;
  coop_drop((CoopReason)reason);
  return 1;
}
// What this machine asks of the session: 1 when it goes, 0 when it cannot now.
// COOP_ASK_OPEN, a perk request (coop_ask); COOP_ASK_PAUSE, paused `a` (0 or
// 1); COOP_ASK_LEAVE; COOP_ASK_NEXT_RUN, the Guest's choice `a` (0 again, 1
// next, 2 setup); COOP_ASK_START, the Host's run of the config at
// portable_config with delay `a`, window `b` and choice `c`, once the last run is
// over on both sides and this machine compared the Guest's hashes up to its end
// (which finds any divergence alone).
__attribute__((export_name("game_coop_request"))) int game_coop_request(int kind, int a, int b, int c, double now) {
  if (!wire.session || wire.closed)
    return 0;
  switch (kind) {
  case COOP_ASK_OPEN:
    return coop_running() && coop_ask();
  case COOP_ASK_PAUSE: {
    if (!coop_running() || wire.left || a < 0 || a > 1)
      return 0;
    coop_pause(wire.pause_seq + 1, wire.seat, a);
    CoopWriter message = coop_message(COOP_PAUSE, wire.epoch).put(wire.pause_seq).put((uint8_t)a);
    coop_send(message);
    return 1;
  }
  case COOP_ASK_LEAVE:
    if (wire.left)
      return 0;
    wire.reason = COOP_LEFT;
    coop_leave();
    coop_agree();
    return 1;
  case COOP_ASK_NEXT_RUN: {
    if (wire.seat != 1 || !wire.hello || a < 0 || a > 2)
      return 0;
    CoopWriter message = coop_message(COOP_NEXT_RUN, wire.epoch).put((uint8_t)a);
    coop_send(message);
    return 1;
  }
  case COOP_ASK_START: {
    bool last_over = !wire.started || (coop_over() && wire.hash_heard >= coop.next - 1);
    if (wire.seat != 0 || !wire.hello || wire.starting || wire.left || !last_over || a < 1 || a > COOP_DELAY || b < 0 ||
        b > COOP_LEAD || c < 0 || c > 2 || !coop_begin(a, b, wire.epoch + 1, now))
      return 0;
    coop.hold |= COOP_HOLD_START;
    wire.starting = true;
    wire.start_at = now;
    CoopWriter message = coop_message(COOP_START_RUN, wire.epoch).put((uint8_t)a).put((uint8_t)b);
    message.put(cfg).put((uint8_t)c).put((uint16_t)0);
    coop_send(message);
    return 1;
  }
  }
  return 0;
}
// Where the next `size` bytes received go, before game_coop_receive.
__attribute__((export_name("game_coop_rx"))) uintptr_t game_coop_rx(int size) {
  wire.rx.resize(size);
  return (uintptr_t)wire.rx.data();
}
__attribute__((export_name("game_coop_receive"))) void game_coop_receive(int channel, int size, double now) {
  if (!wire.session || wire.closed || size < 0 || (size_t)size > wire.rx.size())
    return;
  wire.heard_at = now;
  CoopReader in = {wire.rx.data(), wire.rx.data() + size};
  if (channel == COOP_TICKS)
    coop_ticks_in(in, now);
  else
    coop_control_in(in, now);
  coop_update(now);
}
// The size of the next message to send on `channel` (0 none), at
// game_coop_tx_buffer: on channel 0, the frame's ticks packet; on channel 1,
// each message in turn.
__attribute__((export_name("game_coop_tx"))) int game_coop_tx(int channel, double now) {
  if (!wire.session)
    return 0;
  coop_update(now);
  if (channel == COOP_TICKS)
    return wire.closed ? 0 : coop_ticks_out(now);
  if (!wire.closed)
    coop_repair(now);
  if (wire.outbox.empty())
    return 0;
  wire.tx = std::move(wire.outbox.front());
  wire.outbox.pop_front();
  return (int)wire.tx.size();
}
__attribute__((export_name("game_coop_tx_buffer"))) uintptr_t game_coop_tx_buffer() {
  return (uintptr_t)wire.tx.data();
}
__attribute__((export_name("game_coop_status"))) uint32_t game_coop_status() {
  uint32_t status =
      (wire.session && wire.hello && !wire.closed ? COOP_CONNECTED : 0) | (coop_running() ? COOP_STARTED : 0) |
      (wire.starting ? COOP_STARTING : 0) | (wire.paused ? COOP_PAUSED : 0) |
      (coop.active && (coop.asked || coop.request >= 0) ? COOP_WAITING : 0) |
      (coop.active && coop.picking ? COOP_PICKER : 0) | (wire.left || wire.partner_left ? COOP_LEAVING : 0) |
      (coop_over() ? COOP_ENDED : 0) | (coop.active && coop.desync.tick >= 0 ? COOP_DESYNCED : 0) |
      (wire.failed ? COOP_FAILED : 0) | (wire.remote ? COOP_REMOTE : 0);
  return status | (uint32_t)wire.reason << 16 | (uint32_t)(wire.next_run + 1) << 24;
}
}
