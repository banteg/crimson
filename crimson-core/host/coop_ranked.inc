// Ranked co-op (docs/rewrite/network-coop.md §5.3, §6.1): the room attests the
// pair, and both players sign the run. The page's transport (client/web/coop.js)
// asks the game to prove the player's key to each room socket it opens
// (game_coop_prove; the key never leaves the game), and tells it each seat's key
// the room recorded (game_coop_room_key) and each seed the room issued
// (game_coop_room_seed). The Host's run starts on a seed the room issued once
// both seats' keys stand (game_coop_room_ask), and its replay records those
// keys, which START_RUN carries to the Guest. A run that ends as the board takes
// it (a death, a completed quest) waits for each end screen's name: each
// machine signs it for its seat, once the room told it both seats' keys as the
// replay records them and the run's seed, and sends its partner the signature
// (RUN_SIGNED), and with both, each queues the same upload in
// leaderboard/outbox/ (host/ranked.inc), which the service takes once. The
// room's word never holds a run up: a machine that has not heard it signs
// nothing, and the run ranks nowhere. A page that offers no ranked play (inside
// another site's page) or has no key proves none, and its sessions play
// unranked.

// The Host waits this long for the room's seed, then plays its own, unranked.
static constexpr double COOP_SEED_MS = 5000;
// The room's latest seeds kept: one a run start.
static constexpr size_t COOP_SEEDS = 16;

static struct {
  std::string room; // the room this page proved its seat to
  bool proven[2];   // each seat's key, once the room recorded it
  ReplaySeatKey keys[2];
  std::deque<uint32_t> seeds; // the room's latest seeds, oldest first
  // The Host's seed request: due for the page (game_coop_room_ask), out since
  // asked_at, and a seed new to this page the room issued since that no run
  // took.
  bool ask, asked, fresh;
  double asked_at;
  uint32_t seed;
  std::vector<ReplaySeatKey> next; // the seats' keys the Host's next run records
  ReplayHeader offered;            // the Guest's: the header of the run START_RUN offered
} coop_room;

// A finished run whose replay records the seats' keys, until both signed it:
// its replay, its digest, this machine's seat in it, the keys and its seed.
static struct {
  std::vector<uint8_t> payload;
  uint8_t digest[32];
  int seat;
  std::vector<ReplaySeatKey> keys;
  uint32_t seed;
} coop_held;

// The room recorded two seats' keys, this machine's player's in `seat`, and this
// page offers ranked play.
static bool coop_attested(int seat) {
  Identity identity;
  return ranked_offered && coop_room.proven[0] && coop_room.proven[1] && coop_room.keys[0] != coop_room.keys[1] &&
         identity_load(identity) && !memcmp(identity.public_key, coop_room.keys[seat].data(), REPLAY_SEAT_KEY_BYTES);
}
// The Host's seed request is off: none due, none out, none taken.
static void coop_unask() {
  coop_room.ask = coop_room.asked = coop_room.fresh = false;
  coop_room.asked_at = 0;
}

// The Host's run in coop_live.next can start (true): one both seats' keys stand
// for takes the room's next seed and records the keys; without them, or once the
// room kept it waiting COOP_SEED_MS, it plays its own seed, unranked.
static bool coop_seeded() {
  coop_room.next.clear();
  bool attested = coop_attested(0);
  if (attested && coop_room.fresh) {
    coop_live.next.seed = coop_room.seed;
    coop_room.next = {coop_room.keys[0], coop_room.keys[1]};
  } else if (attested) {
    double now = host_time_ms();
    if (!coop_room.asked) {
      coop_room.ask = coop_room.asked = true;
      coop_room.asked_at = now;
      return false;
    }
    if (now - coop_room.asked_at < COOP_SEED_MS)
      return false;
    coop_note("Co-op: the room sent no seed - an unranked run");
  }
  coop_unask();
  return true;
}

// The room told this machine the run's seed and both seats' keys as its replay
// records them.
static bool coop_room_attests() {
  if (coop_held.keys.size() != 2)
    return false;
  for (int seat = 0; seat < 2; ++seat)
    if (!coop_room.proven[seat] || coop_held.keys[seat] != coop_room.keys[seat])
      return false;
  return std::find(coop_room.seeds.begin(), coop_room.seeds.end(), coop_held.seed) != coop_room.seeds.end();
}

// What a seat signs: "crimson-coop-run-v1\n", the payload's SHA-256, the seat
// (one byte) and the name (service/src/runs.ts).
static std::vector<uint8_t> coop_run_message(int seat, const std::string &name) {
  static const char domain[] = "crimson-coop-run-v1\n";
  std::vector<uint8_t> message(domain, domain + sizeof domain - 1);
  message.insert(message.end(), coop_held.digest, coop_held.digest + 32);
  message.push_back((uint8_t)seat);
  message.insert(message.end(), name.begin(), name.end());
  return message;
}

// The run ended (host/coop_live.inc coop_end): held for the signatures when it
// ends as the board takes it and its replay records the seats' keys, on a page
// that offers ranked play.
static void coop_hold(const std::vector<uint8_t> &payload, const char *outcome) {
  bool finished = !strcmp(outcome, cfg.mode == GAME_MODE_QUEST ? "quest_completed" : "death");
  coop_held = {};
  if (!finished || coop_header.seat_keys.empty() || !ranked_offered)
    return;
  coop_held.payload = payload;
  sha256(payload.data(), payload.size(), coop_held.digest);
  coop_held.seat = coop.local;
  coop_held.keys = coop_header.seat_keys;
  coop_held.seed = cfg.seed;
  coop_rank_queue();
}

// This machine's player named the run at its end screen (or quit there): the
// name goes to the partner with RUN_SIGNED, and with it the player's signature
// for its seat when the run is held, its seat records the player's key and the
// room attests the run; otherwise it ranks nowhere.
static void coop_sign() {
  CoopSigner &own = coop_signers[coop.local];
  if (own.in)
    return;
  const char *name = highscore_active_record.player_name;
  own = {true, std::string(name, strnlen(name, 31))};
  Identity identity;
  if (!coop_held.payload.empty() && !coop_room_attests())
    coop_held = {};
  if (!coop_held.payload.empty() && identity_load(identity) &&
      !memcmp(identity.public_key, coop_held.keys[coop.local].data(), REPLAY_SEAT_KEY_BYTES)) {
    std::vector<uint8_t> message = coop_run_message(coop.local, own.name);
    identity_sign(identity, message.data(), message.size(), own.signature.data());
    memcpy(own.key.data(), identity.public_key, own.key.size());
    own.signs = true;
  }
  coop_rank_queue();
}

static void coop_rank_queue() {
  if (coop_held.payload.empty())
    return;
  const CoopSigner &own = coop_signers[coop_held.seat], &partner = coop_signers[1 - coop_held.seat];
  if (partner.in) {
    // The partner signs its seat's key over its name, or the run ranks nowhere.
    std::vector<uint8_t> message = coop_run_message(1 - coop_held.seat, partner.name);
    bool valid = partner.signs && partner.key == coop_held.keys[1 - coop_held.seat] &&
                 identity_verify(partner.key.data(), partner.signature.data(), message.data(), message.size());
    if (!valid) {
      coop_held = {};
      // A signature no game makes, in the run's own session.
      if (partner.signs && coop_on() && coop_live.session == wire.nonce)
        coop_fail(COOP_BAD_MESSAGE);
      return;
    }
  }
  if (!own.signs || !partner.in)
    return;
  std::string entry = "{\"replay\": \"" + base64(zstd_pack(coop_held.payload)) + "\", \"signers\": [";
  for (int seat = 0; seat < 2; ++seat) {
    const CoopSigner &signer = coop_signers[seat];
    entry += std::string(seat ? ", " : "") + "{\"seat\": " + std::to_string(seat) +
             ", \"name\": " + ranked_json_string(signer.name.c_str()) + ", \"public_key\": \"" +
             hex(signer.key.data(), signer.key.size()) + "\", \"signature\": \"" +
             hex(signer.signature.data(), signer.signature.size()) + "\"}";
  }
  ranked_queue(coop_held.digest, entry + "]}",
               "'" + coop_signers[0].name + "' and '" + coop_signers[1].name + "'");
  coop_held = {};
}

extern "C" {
// The page's text for the room's calls below, at most COOP_ROOM_TEXT bytes with
// its NUL.
static char coop_room_text[COOP_ROOM_TEXT];
__attribute__((export_name("game_coop_room_text"))) char *game_coop_room_text() { return coop_room_text; }
// A room socket's challenge to this page's seat: the text holds the room's id
// (its first `room` characters), then the challenge. The player's key signs
// "crimson-coop-seat-v1\n", the room id and the challenge, as ASCII; the answer
// is "<public key> <signature>" in hex, or empty when this page proves no key.
// Another room than the last one's proof forgets that one's keys and seeds.
__attribute__((export_name("game_coop_prove"))) const char *game_coop_prove(int room) {
  static char proof[64 + 1 + 128 + 1];
  proof[0] = 0;
  size_t size = strnlen(coop_room_text, sizeof coop_room_text);
  if (room < 0 || (size_t)room > size)
    return proof;
  std::string id(coop_room_text, room);
  if (id != coop_room.room) {
    coop_room = {};
    coop_room.room = id;
  }
  Identity identity;
  if (!ranked_offered || !identity_load(identity))
    return proof;
  std::string message = std::string("crimson-coop-seat-v1\n") + std::string(coop_room_text, size);
  uint8_t signature[64];
  identity_sign(identity, message.data(), message.size(), signature);
  snprintf(proof, sizeof proof, "%s %s", hex(identity.public_key, 32).c_str(), hex(signature, 64).c_str());
  return proof;
}
// The key the room recorded for `seat` (0 its host, 1 its guest), as hex in the
// text: 1 when it reads as one.
__attribute__((export_name("game_coop_room_key"))) int game_coop_room_key(int seat) {
  ReplaySeatKey key;
  if (seat < 0 || seat > 1 || strnlen(coop_room_text, sizeof coop_room_text) != 2 * key.size())
    return 0;
  auto digit = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
  for (size_t i = 0; i < key.size(); ++i) {
    int high = digit(coop_room_text[2 * i]), low = digit(coop_room_text[2 * i + 1]);
    if (high < 0 || low < 0)
      return 0;
    key[i] = (uint8_t)(high << 4 | low);
  }
  coop_room.proven[seat] = true;
  coop_room.keys[seat] = key;
  return 1;
}
// A seed the room issued to the pair: the Host's run takes one new to this page
// that comes while its request is out. The room says its latest again to each
// socket that opens; a run played it already.
__attribute__((export_name("game_coop_room_seed"))) void game_coop_room_seed(uint32_t seed) {
  if (std::find(coop_room.seeds.begin(), coop_room.seeds.end(), seed) != coop_room.seeds.end())
    return;
  if (coop_room.seeds.size() == COOP_SEEDS)
    coop_room.seeds.pop_front();
  coop_room.seeds.push_back(seed);
  if (coop_room.asked) {
    coop_room.fresh = true;
    coop_room.seed = seed;
  }
}
// 1 once when the Host's game asks the room for a seed ({type: "seed"}).
__attribute__((export_name("game_coop_room_ask"))) int game_coop_room_ask() {
  bool ask = coop_room.ask;
  coop_room.ask = false;
  return ask;
}
}
