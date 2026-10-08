// A run's replay (src/crimson/replay/types.py Replay), saved for every run a
// session plays as replays/<n>-<mode>.crd, numbered as the Python port numbers
// its own (src/crimson/replay/library.py) and named by its high score record
// (docs/rewrite/watch-replays.md). A ranked run uploads the same replay.
#include "../game/leaderboard.h"
#include <dirent.h>
#include <string>

// The host the replays name in their recorder (game_platform).
static const char *replay_platform = "native";

// Canonical msgpack, as msgspec writes it and the server reads it (service/src/msgpack.ts):
// the shortest header for every integer, string, array and map, float64 for every float.
struct Msgpack {
  std::vector<uint8_t> out;
  void byte(uint8_t b) { out.push_back(b); }
  void be(uint64_t value, int bytes) {
    for (int i = bytes - 1; i >= 0; --i)
      byte((uint8_t)(value >> (8 * i)));
  }
  void integer(int64_t v) {
    if (v >= 0) {
      if (v < 0x80) byte((uint8_t)v);
      else if (v < 0x100) byte(0xcc), be(v, 1);
      else if (v < 0x10000) byte(0xcd), be(v, 2);
      else if (v < 0x100000000ll) byte(0xce), be(v, 4);
      else byte(0xcf), be(v, 8);
    } else if (v >= -0x20) byte((uint8_t)v);
    else if (v >= -0x80) byte(0xd0), be((uint64_t)v, 1);
    else if (v >= -0x8000) byte(0xd1), be((uint64_t)v, 2);
    else if (v >= -0x80000000ll) byte(0xd2), be((uint64_t)v, 4);
    else byte(0xd3), be((uint64_t)v, 8);
  }
  void real(double v) {
    uint64_t bits;
    memcpy(&bits, &v, 8);
    byte(0xcb), be(bits, 8);
  }
  void boolean(bool v) { byte(v ? 0xc3 : 0xc2); }
  void nil() { byte(0xc0); }
  void header(uint32_t n, uint8_t fix, uint8_t fix_limit, uint8_t b16, uint8_t b32) {
    if (n < fix_limit) byte((uint8_t)(fix | n));
    else if (n < 0x10000) byte(b16), be(n, 2);
    else byte(b32), be(n, 4);
  }
  void array(uint32_t n) { header(n, 0x90, 16, 0xdc, 0xdd); }
  void map(uint32_t n) { header(n, 0x80, 16, 0xde, 0xdf); }
  void str(const char *s) {
    uint32_t n = (uint32_t)strlen(s);
    if (n < 32) byte((uint8_t)(0xa0 | n));
    else if (n < 0x100) byte(0xd9), be(n, 1);
    else if (n < 0x10000) byte(0xda), be(n, 2);
    else byte(0xdb), be(n, 4);
    out.insert(out.end(), s, s + n);
  }
};

// The run's result, read from the state after its last tick as the server
// derives it (service/src/verify.ts deriveResult); `outcome` is how it ended.
static void replay_result(Msgpack &m, const char *outcome) {
  int elapsed = cfg.mode == GAME_MODE_QUEST ? quest_spawn_timeline : run_elapsed_ms;
  float health = player_state_table[0].health;
  int fired = highscore_record_shots_fired > 0 ? highscore_record_shots_fired : 0;
  int hit = highscore_record_shots_hit < fired ? highscore_record_shots_hit : fired;
  int best = 1;
  for (int weapon = 2; weapon < 53; ++weapon)
    if (weapon_usage_time[weapon] > weapon_usage_time[best])
      best = weapon;
  m.map(9);
  m.str("outcome"), m.str(outcome);
  m.str("elapsed_ms"), m.integer(elapsed);
  m.str("kills"), m.integer((uint32_t)creature_kill_count);
  m.str("shots_fired"), m.integer(fired);
  m.str("shots_hit"), m.integer(hit < 0 ? 0 : hit);
  m.str("rng_state"), m.integer(rng);
  m.str("pending_perks"), m.integer((uint32_t)perk_pending_count);
  m.str("quest_final_ms");
  if (!strcmp(outcome, "quest_completed")) {
    // compute_quest_final_time for one player (src/crimson/quests/results.py).
    int final = elapsed - (int)health * 50 - perk_pending_count * 1000;
    m.integer(final == 0 ? 1 : final);
  } else
    m.nil();
  m.str("players"), m.array(1), m.map(3);
  m.str("experience"), m.integer((uint32_t)player_state_table[0].experience);
  m.str("health"), m.real(health);
  m.str("most_used_weapon_id"), m.integer(best);
}

// The replay (src/crimson/replay/types.py Replay): the run's configuration,
// its result and every tick the recording holds.
static std::vector<uint8_t> replay_payload(const char *outcome) {
  Msgpack m;
  m.map(7);
  m.str("format_version"), m.integer(CRIMSON_REPLAY_FORMAT);
  m.str("game_version"), m.str(CRIMSON_GAME_VERSION);
  m.str("rules"), m.integer(CRIMSON_REPLAY_RULES);
  m.str("recorder"), m.map(3);
  m.str("client"), m.str("crimson-core");
  m.str("version"), m.str(CRIMSON_GAME_VERSION);
  m.str("platform"), m.str(replay_platform);
  m.str("run"), m.map(14);
  m.str("game_mode_id"), m.integer(cfg.mode);
  m.str("seed"), m.integer(cfg.seed);
  m.str("quest_level");
  if (cfg.mode == GAME_MODE_QUEST)
    m.map(2), m.str("major"), m.integer(cfg.major), m.str("minor"), m.integer(cfg.minor);
  else
    m.nil();
  m.str("player_count"), m.integer(1);
  m.str("hardcore"), m.boolean(cfg.hardcore);
  m.str("preserve_bugs"), m.boolean(cfg.preserve_bugs);
  m.str("quest_fail_retry_count"), m.integer(cfg.retry);
  m.str("detail_preset"), m.integer(cfg.detail);
  m.str("violence_disabled"), m.integer(cfg.violence);
  m.str("friendly_fire"), m.boolean(cfg.friendly_fire);
  m.str("status"), m.map(3);
  m.str("quest_unlock_index"), m.integer(cfg.unlock);
  m.str("quest_unlock_index_full"), m.integer(cfg.unlock_full); // the replay format's key; name-audit: keep
  m.str("weapon_usage_counts"), m.array(53);
  for (uint32_t count : cfg.weapon_usage)
    m.integer(count);
  m.str("typo_dictionary_words"), m.array(0);
  m.str("typo_highscore_names"), m.array(0);
  m.str("typo_carry"), m.map(4);
  m.str("target_world"), m.nil();
  m.str("submit_count"), m.integer(0);
  m.str("match_count"), m.integer(0);
  m.str("highscore_names_loaded"), m.boolean(false);
  m.str("result");
  replay_result(m, outcome);
  // The recording after its configuration: each tick's input, then its commands.
  const unsigned char *at = live.replay.data() + sizeof(PortableConfig), *end = live.replay.data() + live.replay.size();
  std::vector<std::pair<PortableInput, std::vector<PortableCommand>>> ticks;
  while (at < end) {
    PortableInput input;
    uint32_t count;
    memcpy(&input, at, sizeof input), at += sizeof input;
    memcpy(&count, at, sizeof count), at += sizeof count;
    std::vector<PortableCommand> commands(count);
    memcpy(commands.data(), at, count * sizeof(PortableCommand)), at += count * sizeof(PortableCommand);
    ticks.emplace_back(input, std::move(commands));
  }
  m.str("ticks"), m.array((uint32_t)ticks.size());
  for (const auto &[input, commands] : ticks) {
    m.array(2);
    m.array(1), m.array(5);
    m.real(input.move_x), m.real(input.move_y), m.real(input.aim_x), m.real(input.aim_y);
    m.integer(input.flags);
    m.array((uint32_t)commands.size());
    for (const PortableCommand &command : commands) {
      // Kind 1 picks a perk, kind 2 opens the menu (crimson-core/checks/replay.py).
      m.map(command.type == 1 ? 3 : 2);
      m.str("type"), m.str(command.type == 1 ? "perk_pick" : "perk_menu_open");
      m.str("player_index"), m.integer(0);
      if (command.type == 1)
        m.str("choice_index"), m.integer(command.argument);
    }
  }
  return m.out;
}


// One more than the last number handed out or written. replays/.last-number
// keeps it, so a deleted replay's number is never given to a later run, which
// an old high score record would then name.
static int replay_reserve_number() {
  mkdir("replays", 0755);
  int last = 0;
  if (FILE *fp = platform_fopen("replays/.last-number", "rb")) {
    if (fscanf(fp, "%d", &last) != 1)
      last = 0;
    fclose(fp);
  }
  if (DIR *dir = opendir("replays")) {
    while (dirent *entry = readdir(dir)) {
      int number, end = 0;
      char mode[16];
      if (sscanf(entry->d_name, "%d-%15[a-z].crd%n", &number, mode, &end) == 2 && !entry->d_name[end] && end)
        last = number > last ? number : last;
    }
    closedir(dir);
  }
  ++last;
  if (FILE *fp = platform_fopen("replays/.last-number", "wb")) {
    fprintf(fp, "%d", last);
    fclose(fp);
  }
  return last;
}

// Saves the run's replay, whole or not at all: written aside, then renamed.
// Returns its number, or 0 for a run left before its first tick.
static int replay_save(const std::vector<uint8_t> &payload) {
  if (live.replay.size() <= sizeof(PortableConfig))
    return 0;
  // Sessions play Survival (1), Rush (2) and Quests (3).
  static const char *const modes[] = {"", "survival", "rush", "quest"};
  int number = replay_reserve_number();
  char name[64];
  snprintf(name, sizeof name, "replays/%d-%s.crd", number, modes[cfg.mode]);
  std::vector<uint8_t> file = zstd_pack(payload);
  if (FILE *fp = platform_fopen("replays/.writing", "wb")) {
    bool written = fwrite(file.data(), 1, file.size(), fp) == file.size();
    if (fclose(fp) == 0 && written)
      rename("replays/.writing", name);
  }
  return number;
}

extern "C" {
// The host this module runs in, named in the replays it records: 1 the
// browser, 2 a desktop.
__attribute__((export_name("game_platform"))) void game_platform(int platform) {
  replay_platform = platform == 1 ? "web" : "native";
}
}

// --- Reading a replay back, for playback --------------------------------------

// The payload ceiling the Python codec enforces (src/crimson/replay/codec.py MAX_REPLAY_PAYLOAD_BYTES).
static constexpr size_t REPLAY_MAX_PAYLOAD = 64u << 20;

// Reads msgpack one value at a time; a value it cannot read clears `ok`.
struct MsgpackReader {
  const uint8_t *at, *end;
  bool ok = true;

  uint8_t next() {
    if (at >= end)
      return ok = false, 0;
    return *at++;
  }
  uint64_t be(int bytes) {
    if (end - at < bytes)
      return ok = false, 0;
    uint64_t value = 0;
    for (int i = 0; i < bytes; ++i)
      value = value << 8 | *at++;
    return value;
  }
  bool nil() {
    if (at < end && *at == 0xc0)
      return ++at, true;
    return false;
  }
  bool boolean() {
    uint8_t b = next();
    if (b != 0xc2 && b != 0xc3)
      ok = false;
    return b == 0xc3;
  }
  int64_t integer() {
    uint8_t b = next();
    if (b < 0x80 || b >= 0xe0)
      return (int8_t)b;
    switch (b) {
    case 0xcc: return (int64_t)be(1);
    case 0xcd: return (int64_t)be(2);
    case 0xce: return (int64_t)be(4);
    case 0xcf: return (int64_t)be(8);
    case 0xd0: return (int8_t)be(1);
    case 0xd1: return (int16_t)be(2);
    case 0xd2: return (int32_t)be(4);
    case 0xd3: return (int64_t)be(8);
    }
    return ok = false, 0;
  }
  double real() {
    if (next() != 0xcb)
      return ok = false, 0;
    uint64_t bits = be(8);
    double value;
    memcpy(&value, &bits, sizeof value);
    return value;
  }
  uint32_t container(uint8_t fix, uint8_t b16, uint8_t b32) {
    uint8_t b = next();
    if ((b & 0xf0) == fix)
      return b & 0x0f;
    if (b == b16)
      return (uint32_t)be(2);
    if (b == b32)
      return (uint32_t)be(4);
    return ok = false, 0;
  }
  uint32_t array() { return container(0x90, 0xdc, 0xdd); }
  uint32_t map() { return container(0x80, 0xde, 0xdf); }
  std::string str() {
    uint8_t b = next();
    uint32_t n = (b & 0xe0) == 0xa0 ? b & 0x1f : b == 0xd9 ? (uint32_t)be(1) : b == 0xda ? (uint32_t)be(2) : b == 0xdb ? (uint32_t)be(4) : (ok = false, 0);
    if (!ok || (size_t)(end - at) < n)
      return ok = false, std::string();
    std::string text((const char *)at, n);
    at += n;
    return text;
  }
  // Any value, nested no deeper than a replay's.
  void skip(int depth = 0) {
    if (!ok || at >= end || depth > 8)
      return void(ok = false);
    uint8_t b = *at;
    if (b == 0xc0 || b == 0xc2 || b == 0xc3)
      ++at;
    else if (b == 0xcb)
      real();
    else if ((b & 0xe0) == 0xa0 || (b >= 0xd9 && b <= 0xdb))
      str();
    else if ((b & 0xf0) == 0x90 || b == 0xdc || b == 0xdd)
      for (uint32_t n = array(); ok && n; --n)
        skip(depth + 1);
    else if ((b & 0xf0) == 0x80 || b == 0xde || b == 0xdf)
      for (uint32_t n = map(); ok && n; --n)
        skip(depth + 1), skip(depth + 1);
    else
      integer();
  }
};

// A replay read for playback: the session's recording of it (the config, then
// each tick's input and commands, as live.replay holds a run), the rules and
// build it was recorded with, or why this module cannot play it.
struct LoadedReplay {
  std::vector<uint8_t> recording;
  int rules = 0;
  std::string game_version, reason;
};

static void replay_read_run(MsgpackReader &r, PortableConfig &config, LoadedReplay &out) {
  config.major = config.minor = 1;
  for (uint32_t n = r.map(); r.ok && n; --n) {
    std::string key = r.str();
    if (key == "game_mode_id") config.mode = (uint32_t)r.integer();
    else if (key == "seed") config.seed = (uint32_t)r.integer();
    else if (key == "quest_level") {
      if (!r.nil())
        for (uint32_t m = r.map(); r.ok && m; --m) {
          std::string field = r.str();
          (field == "major" ? config.major : config.minor) = (uint32_t)r.integer();
        }
    } else if (key == "player_count") {
      if (r.integer() != 1) out.reason = "This run needs the Python port";
    } else if (key == "hardcore") config.hardcore = r.boolean();
    else if (key == "preserve_bugs") config.preserve_bugs = r.boolean();
    else if (key == "quest_fail_retry_count") config.retry = (uint32_t)r.integer();
    else if (key == "detail_preset") config.detail = (uint32_t)r.integer();
    else if (key == "violence_disabled") config.violence = (uint32_t)r.integer();
    else if (key == "friendly_fire") config.friendly_fire = r.boolean();
    else if (key == "status")
      for (uint32_t m = r.map(); r.ok && m; --m) {
        std::string field = r.str();
        if (field == "quest_unlock_index") config.unlock = (uint32_t)r.integer();
        else if (field == "quest_unlock_index_full") config.unlock_full = (uint32_t)r.integer();
        else if (field == "weapon_usage_counts") {
          uint32_t count = r.array();
          for (uint32_t i = 0; r.ok && i < count; ++i) {
            uint32_t usage = (uint32_t)r.integer();
            if (i < 53) config.weapon_usage[i] = usage;
          }
        } else r.skip();
      }
    else r.skip();
  }
  if (config.mode < GAME_MODE_SURVIVAL || config.mode > GAME_MODE_QUEST)
    out.reason = "This run needs the Python port";
}

static void replay_read_ticks(MsgpackReader &r, LoadedReplay &out) {
  for (uint32_t n = r.array(); r.ok && n && out.reason.empty(); --n) {
    if (r.array() != 2 || r.array() != 1 || r.array() != 5)
      return void(out.reason = "This run needs the Python port");
    PortableInput input;
    input.move_x = (float)r.real(), input.move_y = (float)r.real();
    input.aim_x = (float)r.real(), input.aim_y = (float)r.real();
    input.flags = (uint32_t)r.integer();
    std::vector<PortableCommand> commands(r.array());
    for (PortableCommand &command : commands) {
      std::string type;
      int32_t choice = 0;
      for (uint32_t m = r.map(); r.ok && m; --m) {
        std::string field = r.str();
        if (field == "type") type = r.str();
        else if (field == "choice_index") choice = (int32_t)r.integer();
        else r.skip();
      }
      // Kind 1 picks a perk, kind 2 opens the menu (crimson-core/checks/replay.py); Typ-o's need the Python port.
      if (type == "perk_pick") command = {1, choice};
      else if (type == "perk_menu_open") command = {2, 0};
      else return void(out.reason = "This run needs the Python port");
    }
    uint32_t count = (uint32_t)commands.size();
    const auto append = [&](const void *data, size_t size) {
      out.recording.insert(out.recording.end(), (const uint8_t *)data, (const uint8_t *)data + size);
    };
    append(&input, sizeof input), append(&count, sizeof count), append(commands.data(), count * sizeof(PortableCommand));
  }
}

// Reads a .crd: true when this module can play it, else false with the reason.
static bool replay_read(const std::vector<uint8_t> &file, LoadedReplay &out) {
  out = {};
  std::vector<uint8_t> payload = zstd_unpack(file.data(), file.size(), REPLAY_MAX_PAYLOAD);
  MsgpackReader r{payload.data(), payload.data() + payload.size()};
  PortableConfig config = {};
  int format = 0;
  out.recording.resize(sizeof config);
  for (uint32_t n = payload.empty() ? (r.ok = false, 0) : r.map(); r.ok && n && out.reason.empty(); --n) {
    std::string key = r.str();
    if (key == "format_version") format = (int)r.integer();
    else if (key == "game_version") out.game_version = r.str();
    else if (key == "rules") out.rules = (int)r.integer();
    else if (key == "run") replay_read_run(r, config, out);
    else if (key == "ticks") replay_read_ticks(r, out);
    else r.skip();
  }
  // Format 30 had no rules; its replays play under rules 1 (docs/formats/replay.md).
  if (format == 30)
    out.rules = 1;
  if (!r.ok || (format != 30 && format != CRIMSON_REPLAY_FORMAT))
    out.reason = "This version cannot read its replay";
  else if (out.reason.empty() && out.rules != CRIMSON_REPLAY_RULES)
    out.reason = "Recorded under other rules (" + out.game_version.substr(0, out.game_version.find('+')) + ")";
  memcpy(out.recording.data(), &config, sizeof config);
  return out.reason.empty();
}

static LoadedReplay replay_loaded;
static char replay_path[256];

extern "C" {
// Where the host writes a replay's path for game_replay_open.
__attribute__((export_name("game_replay_path"))) char *game_replay_path() { return replay_path; }
// Reads the replay at game_replay_path: 1 when this module can play it, else 0
// with game_replay_reason.
__attribute__((export_name("game_replay_open"))) int game_replay_open() {
  std::vector<uint8_t> file;
  if (FILE *fp = platform_fopen(replay_path, "rb")) {
    uint8_t chunk[65536];
    for (size_t n; (n = fread(chunk, 1, sizeof chunk, fp)) > 0 && file.size() <= REPLAY_MAX_PAYLOAD;)
      file.insert(file.end(), chunk, chunk + n);
    fclose(fp);
  }
  return replay_read(file, replay_loaded);
}
__attribute__((export_name("game_replay_reason"))) const char *game_replay_reason() { return replay_loaded.reason.c_str(); }
__attribute__((export_name("game_replay_recording"))) const uint8_t *game_replay_recording() {
  return replay_loaded.recording.data();
}
__attribute__((export_name("game_replay_recording_size"))) int game_replay_recording_size() {
  return (int)replay_loaded.recording.size();
}
}
