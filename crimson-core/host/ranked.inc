// Ranked runs (src/crimson/replay/ranked.py): with the Play Game menu's Ranked
// box ticked, a single player's Survival or quest run plays the ranked rules on
// a detached save, and when it ends as the board takes it (a death in Survival,
// a completed quest) its replay waits for the end screen's name, then goes to
// leaderboard/outbox/ as the Python port queues it (src/crimson/leaderboard/
// client.py), signed by the player's key. The host uploads the outbox.
#include "../game/host_abi.h"
#include "../game/leaderboard.h"
#include <dirent.h>

static bool ranked_enabled; // the host takes runs to the leaderboard (game_leaderboard_enable)
extern "C" bool ranked_checked; // the Ranked box, which a launch starts unticked (play_game_menu_update)
bool ranked_checked;
static bool ranked_run;     // the run playing is a ranked attempt
static std::vector<uint8_t> ranked_held; // a finished ranked run, until the end screen names it
static const char *ranked_platform = "";

// Movement 1-4 and aim 0-4: the controls the server takes as a player's (service/src/verify.ts).
static bool ranked_controls() {
  int movement = config_blob.movement_schemes[0], aim = config_blob.aim_schemes[0];
  return movement >= 1 && movement <= 4 && aim >= 0 && aim <= 4;
}
static bool ranked_attempt() {
  return ranked_enabled && ranked_checked && config_blob.player_count == 1 && ranked_controls() &&
         (config_blob.game_mode == GAME_MODE_SURVIVAL || config_blob.game_mode == GAME_MODE_QUEST);
}

// The ranked rules (ranked_run_spec): full detail with violence on, no friendly
// fire, the documented fixes, every quest unlocked and no weapon used yet.
static void ranked_spec(PortableConfig &config) {
  config.unlock = config.unlock_full = 50;
  config.detail = 5;
  config.violence = 0;
  config.friendly_fire = 0;
  config.hardcore = config.mode == GAME_MODE_QUEST && config.hardcore;
  config.retry = 0;
  config.preserve_bugs = 0;
  memset(config.weapon_usage, 0, sizeof config.weapon_usage);
}

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

// The run's claimed result, read from the state after its last tick as the
// server derives it (service/src/verify.ts deriveResult).
static void ranked_result(Msgpack &m) {
  const char *outcome = game_state_pending == GAME_STATE_QUEST_RESULTS ? "quest_completed" : "death";
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
  if (game_state_pending == GAME_STATE_QUEST_RESULTS) {
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

// The replay (src/crimson/replay/types.py Replay, format 30): the run's
// configuration, its claimed result and every tick the recording holds.
static std::vector<uint8_t> ranked_payload() {
  Msgpack m;
  m.map(6);
  m.str("format_version"), m.integer(30);
  m.str("game_version"), m.str(CRIMSON_GAME_VERSION);
  m.str("recorder"), m.map(3);
  m.str("client"), m.str("crimson-core");
  m.str("version"), m.str(CRIMSON_GAME_VERSION);
  m.str("platform"), m.str(ranked_platform);
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
  ranked_result(m);
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

// A run the board takes is held for its name; one that ends otherwise is not.
static void ranked_finish() {
  bool finished = cfg.mode == GAME_MODE_QUEST ? game_state_pending == GAME_STATE_QUEST_RESULTS
                                               : game_state_pending == GAME_STATE_GAME_OVER;
  ranked_held = ranked_run && finished ? ranked_payload() : std::vector<uint8_t>{};
  ranked_run = false;
}

// A JSON string of a Latin-1 name, as Python's json.dumps writes it.
static std::string ranked_json_string(const char *text) {
  std::string out = "\"";
  for (const unsigned char *c = (const unsigned char *)text; *c; ++c) {
    char escape[8];
    if (*c == '"' || *c == '\\')
      out += '\\', out += (char)*c;
    else if (*c < 0x20 || *c > 0x7e)
      snprintf(escape, sizeof escape, "\\u%04x", *c), out += escape;
    else
      out += (char)*c;
  }
  return out + "\"";
}

// The held run goes to the outbox under the name the end screen took, signed
// over its digest and name (identity.py sign_run), and the host is told.
static void ranked_release() {
  if (ranked_held.empty())
    return;
  std::vector<uint8_t> payload = std::move(ranked_held);
  ranked_held.clear();
  Identity identity;
  if (!identity_load(identity))
    return;
  const char *name = highscore_active_record.player_name;
  uint8_t digest[32], signature[64];
  sha256(payload.data(), payload.size(), digest);
  std::vector<uint8_t> message((const uint8_t *)"crimson-run-v1\n", (const uint8_t *)"crimson-run-v1\n" + 15);
  message.insert(message.end(), digest, digest + 32);
  message.insert(message.end(), name, name + strlen(name));
  identity_sign(identity, message.data(), message.size(), signature);
  std::string entry = "{\"replay\": \"" + base64(zstd_pack(payload)) + "\", \"name\": " + ranked_json_string(name) +
                      ", \"public_key\": \"" + hex(identity.public_key, 32) + "\", \"signature\": \"" +
                      hex(signature, 64) + "\"}";
  mkdir("leaderboard", 0755);
  mkdir("leaderboard/outbox", 0755);
  std::string path = "leaderboard/outbox/" + hex(digest, 32) + ".json";
  if (FILE *fp = platform_fopen(path.c_str(), "wb")) {
    fwrite(entry.data(), 1, entry.size(), fp);
    fclose(fp);
  }
  host_leaderboard(HOST_LEADERBOARD_UPLOAD);
}

// Runs waiting in the outbox, for the Profile tip.
static int ranked_waiting() {
  int count = 0;
  if (DIR *dir = opendir("leaderboard/outbox")) {
    while (dirent *entry = readdir(dir))
      count += strstr(entry->d_name, ".json") != nullptr;
    closedir(dir);
  }
  return count;
}

extern "C" {
bool ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);
bool ui_button_update(float *xy, ui_button_t *button);
extern ui_element_t ui_element_slot_11, ui_element_slot_12_layout_a;

// The Ranked row under the Play Game panel's modes (screens/panels/play_game.py):
// the panel grows by it and Back moves down (ui_menu_layout_init, before the
// elements' bounds).
static const float RANKED_ROW = 40.0f;
void ranked_layout() {
  if (!ranked_enabled)
    return;
  // The panel is ui_menuPanelTallSmall's 3-slice; its bottom slice moves down.
  for (int i = 4; i < 8; ++i)
    ui_element_slot_11.vertices[i].y += RANKED_ROW;
  ui_element_slot_12_layout_a.pos_y += RANKED_ROW;
}

// The Ranked box and the Profile button, and their tips with the modes'
// (play_game_menu_update, with `base` its content origin and `tips` where it
// draws the modes' tips). Ticking the box makes the game one player's.
void ranked_menu(float *base, float *tips, bool list_open) {
  if (!ranked_enabled)
    return;
  static ui_checkbox_t box = {0, 0, 0, 0, (char *)"Ranked"};
  // As the original constructs its buttons (play_game_menu_update): drawn opaque.
  static ui_button_t profile = {(char *)"Profile", 0, 0, 1, 0, 0, 0, 1.0f};
  static int box_tip, profile_tip; // the tips' fade, as the modes' hover_anim
  static char note[48];
  if (!ranked_controls())
    ranked_checked = false;
  // Like the modes, it neither hovers nor toggles while the list is open.
  box.disabled = !ranked_controls() || list_open;
  box.checked = ranked_checked;
  const char *items[] = {"1 player", "2 players"};
  float list_width = 0;
  for (const char *item : items)
    list_width = fmaxf(list_width, (float)grim_interface_ptr->grim_measure_text_width((char *)item));
  float at[2] = {base[0] + 80.0f + list_width + 48.0f -
                     ((float)grim_interface_ptr->grim_measure_text_width(box.label) + 22.0f),
                 base[1] + 212.0f};
  if (ui_checkbox_update(at, &box)) {
    ranked_checked = box.checked;
    if (ranked_checked)
      config_blob.player_count = 1;
  }
  int dt = frame_dt_ms;
  box_tip = box.hovered ? box_tip + dt * 6 : box_tip - dt * 2;
  if (ranked_checked) {
    profile.enabled = !list_open;
    float profile_at[2] = {base[0] - 62.0f, base[1] + 204.0f};
    if (ui_button_update(profile_at, &profile)) {
      snprintf(note, sizeof note, "Opening the leaderboard site...");
      host_leaderboard(HOST_LEADERBOARD_PROFILE);
    }
    profile_tip = profile.hovered ? profile_tip + dt * 6 : profile_tip - dt * 2;
  } else
    profile_tip -= dt * 2, note[0] = 0;
  box_tip = box_tip < 0 ? 0 : box_tip > 1000 ? 1000 : box_tip;
  profile_tip = profile_tip < 0 ? 0 : profile_tip > 1000 ? 1000 : profile_tip;
  // Each tip one line, centred under the modes' buttons (the port's own tips).
  char ranked_tip[64], profile_text[64];
  const char *name = config_blob.player_name;
  snprintf(ranked_tip, sizeof ranked_tip, "Play for the online leaderboard as %s.", name);
  if (!*name || grim_interface_ptr->grim_measure_text_width(ranked_tip) >
                    grim_interface_ptr->grim_measure_text_width((char *)"Unlock new weapons and perks in Quest mode."))
    snprintf(ranked_tip, sizeof ranked_tip, "Play for the online leaderboard.");
  int waiting = ranked_waiting();
  if (note[0])
    snprintf(profile_text, sizeof profile_text, "%s", note);
  else if (waiting)
    snprintf(profile_text, sizeof profile_text, "%d run%s waiting to upload.", waiting, waiting == 1 ? "" : "s");
  else
    snprintf(profile_text, sizeof profile_text, "Open your profile in the browser.");
  const struct { int fade; const char *text; } shown[] = {{box_tip, ranked_tip}, {profile_tip, profile_text}};
  for (const auto &tip : shown) {
    if (tip.fade <= 0)
      continue;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, (float)tip.fade * 0.000900000043f);
    float x = tips[0] + 55.0f + 145.0f * 0.5f - (float)grim_interface_ptr->grim_measure_text_width((char *)tip.text) * 0.5f;
    grim_interface_ptr->grim_draw_text_small(x, tips[1], (char *)tip.text);
  }
}

// The host takes runs to the leaderboard, before the game starts: the Ranked
// box shows. `platform` names it in the replays it records (1, the browser).
__attribute__((export_name("game_leaderboard_enable"))) void game_leaderboard_enable(int platform) {
  ranked_enabled = true;
  ranked_platform = platform == 1 ? "web" : "native";
}
// The player's public key, as hex, for the host's sign-in.
__attribute__((export_name("game_identity_public_key"))) const char *game_identity_public_key() {
  static char key[65];
  Identity identity;
  if (!identity_load(identity))
    return "";
  snprintf(key, sizeof key, "%s", hex(identity.public_key, 32).c_str());
  return key;
}
// A sign-in challenge (64 hex digits) the host writes here, then its signature
// (identity.py sign_login), as hex.
static char ranked_challenge[65];
__attribute__((export_name("game_login_challenge"))) char *game_login_challenge() { return ranked_challenge; }
__attribute__((export_name("game_login_signature"))) const char *game_login_signature() {
  static char out[129];
  Identity identity;
  if (!identity_load(identity))
    return "";
  std::string message = std::string("crimson-login-v1\n") + ranked_challenge;
  uint8_t signature[64];
  identity_sign(identity, message.data(), message.size(), signature);
  snprintf(out, sizeof out, "%s", hex(signature, 64).c_str());
  return out;
}
}
