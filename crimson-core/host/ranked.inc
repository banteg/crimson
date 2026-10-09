// Ranked runs (src/crimson/replay/ranked.py): with the Play Game menu's Ranked
// box ticked, a single player's Survival or quest run plays the ranked rules on
// a detached save, and when it ends as the board takes it (a death in Survival,
// a completed quest) its replay waits for the end screen's name, then goes to
// leaderboard/outbox/ as the Python port queues it (src/crimson/leaderboard/
// client.py), signed by the player's key. The host uploads the outbox.
#include "../game/host_abi.h"
#include "../game/leaderboard.h"
#include <cctype>
#include <cmath>
#include <dirent.h>
#include <string>
#include <time.h>

static bool ranked_enabled; // the host takes runs to the leaderboard (game_leaderboard_enable)
extern "C" bool ranked_checked; // the Ranked box, which a launch starts unticked (play_game_menu_update)
bool ranked_checked;
static bool ranked_run;     // the run playing is a ranked attempt
static std::vector<uint8_t> ranked_held; // a finished ranked run, until the end screen names it

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
// fire and no weapon used yet; the documented fixes, as every run plays. The
// save has every quest done for Survival, and for a quest is the one that has
// just unlocked it (ranked_status): a hardcore quest's has the normal campaign
// done.
static void ranked_spec(PortableConfig &config) {
  if (config.mode == GAME_MODE_QUEST) {
    int quest = (config.major - 1) * 10 + (config.minor - 1);
    config.unlock = config.hardcore ? 50 : quest;
    config.unlock_full = config.hardcore ? quest : 0;
  } else {
    config.hardcore = 0;
    config.unlock = config.unlock_full = 50;
  }
  config.detail = 5;
  config.violence = 0;
  config.friendly_fire = 0;
  config.retry = 0;
  memset(config.weapon_usage, 0, sizeof config.weapon_usage);
}

// A run the board takes is held for its name; one that ends otherwise is not.
static void ranked_finish(const std::vector<uint8_t> &payload, const char *outcome) {
  bool finished = !strcmp(outcome, cfg.mode == GAME_MODE_QUEST ? "quest_completed" : "death");
  ranked_held = ranked_run && finished ? payload : std::vector<uint8_t>{};
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

// The leaderboard's runs on the high score screen, as the Python port shows
// them (screens/high_scores_view/records.py, docs/rewrite/watch-replays.md):
// each board's latest answer is kept for the session, every fetch replacing it
// whole, and nothing online is stored. While Show internet scores is ticked the
// table reads the board's runs after its own records, so the original's
// filters and order take them in; a run of the player's own that the board
// holds turns green in its place. The screen fetches a board quietly the first
// time it shows it; Update scores fetches the shown one with the original's
// status lines.
#include "crimsonland_highscore.h"
#include <map>
#include <tuple>
extern "C" {
extern int online_sync_status; // 1 while updating, 0 done, 6 failed (highscore_screen)
void highscore_sync_worker_recovered(void *arg);
void highscore_load_table_thunk(void);
char *highscore_read_record(char *buffer, FILE *fp);
void highscore_write_record(highscore_record_t *record, FILE *fp);
}
// A board: Survival's, or a quest's on either difficulty.
struct ScoresBoard {
  game_mode_id_t mode;
  int major, minor;
  unsigned char hardcore;
  auto key() const { return std::tie(mode, major, minor, hardcore); }
  bool operator<(const ScoresBoard &other) const { return key() < other.key(); }
};
// A board's run as the table reads it, and its id on the leaderboard ("" when
// the answer named none).
struct ScoresRun {
  highscore_record_t record;
  std::string run;
};
static std::map<ScoresBoard, std::vector<ScoresRun>> scores_kept;
static std::map<ScoresBoard, bool> scores_asked; // the boards fetched this session
// The runs the table read last, as it read them, for the card's Watch.
static std::vector<ScoresRun> scores_shown;
// One request is out at a time, for the board it asked: the screen's own
// settings can change while it is. Update scores pressed meanwhile waits for it.
static ScoresBoard scores_board_asked;
static bool scores_out, scores_out_quiet, scores_update_waiting;
static char scores_request[64];
static std::vector<char> scores_response;

// One-player Survival and quests have a board; other tables have none.
static bool scores_board(ScoresBoard &board) {
  bool quest = config_blob.game_mode == GAME_MODE_QUEST;
  if (config_blob.player_count != 1 || (!quest && config_blob.game_mode != GAME_MODE_SURVIVAL))
    return false;
  board = {config_blob.game_mode, quest ? quest_stage_major : 0, quest ? quest_stage_minor : 0,
           (unsigned char)(quest && config_blob.hardcore)};
  return true;
}
// Asks for a board's runs; a quiet request shows no status and its failure
// leaves the board's runs out.
static void scores_send(const ScoresBoard &board, bool quiet) {
  scores_board_asked = board;
  scores_asked[board] = true;
  scores_out = true;
  scores_out_quiet = quiet;
  if (board.mode == GAME_MODE_QUEST)
    snprintf(scores_request, sizeof scores_request, "{\"board\": \"%s\", \"quest\": \"%d.%d\"}",
             board.hardcore ? "quests-hardcore" : "quests", board.major, board.minor);
  else
    snprintf(scores_request, sizeof scores_request, "{\"board\": \"survival\", \"quest\": \"\"}");
  host_leaderboard(HOST_LEADERBOARD_SCORES);
}

#include "json.inc"

// A whole number in [0, max] under `key`.
static bool scores_count(const Json &run, const char *key, double max, double &out) {
  const Json *value = run.field(key, Json::NUMBER);
  if (!value || value->number < 0 || value->number > max || value->number != floor(value->number))
    return false;
  out = value->number;
  return true;
}

// A run of the service's board ({"scores": [{"run": ..., "name": ..., ...}]})
// as the record the original keeps for it, or false when a field is missing
// or out of the record's range.
static bool scores_record(const Json &run, const ScoresBoard &board, highscore_record_t &record) {
  const Json *name = run.field("name", Json::STRING);
  // accepted_at is in milliseconds, whole up to 2^53 as a double.
  double score, elapsed, experience, weapon, fired, hit, kills, accepted_at;
  if (!name || !scores_count(run, "score", UINT32_MAX, score) || !scores_count(run, "elapsed_ms", UINT32_MAX, elapsed) ||
      !scores_count(run, "experience", UINT32_MAX, experience) ||
      !scores_count(run, "most_used_weapon_id", std::size(game_status_blob.weapon_usage_counts) - 1, weapon) ||
      !scores_count(run, "shots_fired", UINT32_MAX, fired) || !scores_count(run, "shots_hit", UINT32_MAX, hit) ||
      !scores_count(run, "kills", UINT32_MAX, kills) || !scores_count(run, "accepted_at", 0x1p53, accepted_at))
    return false;
  bool quest = board.mode == GAME_MODE_QUEST;
  snprintf(record.player_name, sizeof record.player_name, "%s", name->text.c_str());
  record.game_mode_id = (unsigned char)board.mode;
  record.quest_stage_major = (unsigned char)board.major;
  record.quest_stage_minor = (unsigned char)board.minor;
  record.score_xp = (unsigned)experience;
  // A quest record's time is its final time, which the quest boards rank.
  record.run_elapsed_ms = (unsigned)(quest ? score : elapsed);
  record.most_used_weapon_id = (unsigned char)weapon;
  record.shots_fired = (unsigned)fired;
  record.shots_hit = (unsigned)hit;
  record.creature_kill_count = (unsigned)kills;
  // The day the board took the run.
  time_t when = (time_t)(accepted_at / 1000);
  if (struct tm *day = localtime(&when)) {
    record.day = (unsigned char)day->tm_mday;
    record.month = (unsigned char)(day->tm_mon + 1);
    record.year_offset = (unsigned char)(day->tm_year + 1900 - 2000);
    record.date_week = (unsigned char)highscore_iso_week(day->tm_year + 1900, day->tm_mon + 1, day->tm_mday);
  }
  record.flags = 1;
  record.hardcore_marker = board.hardcore ? 0x75 : 0;
  record.sentinel_pipe = 0x7c;
  record.sentinel_ff = 0xff;
  return true;
}

// A run id names a file (replays/online/<run>.crd): letters, digits, - and _.
static bool scores_run_id(const std::string &run) {
  if (run.empty() || run.size() > 64)
    return false;
  for (char c : run)
    if (!isalnum((unsigned char)c) && c != '-' && c != '_')
      return false;
  return true;
}

// The board run the table shows as `record`, or null. The table marks each
// name's best board run in its flags (highscore_load_table), so they differ.
static const std::string *scores_run(const highscore_record_t &record) {
  highscore_record_t row = record;
  for (const ScoresRun &shown : scores_shown) {
    row.flags = shown.record.flags;
    if (!shown.run.empty() && !memcmp(&shown.record, &row, sizeof row))
      return &shown.run;
  }
  return nullptr;
}

extern "C" {
// The table's file for highscore_load_table, with the shown board's kept runs
// after its own records while Show internet scores is ticked: a record the
// board holds (by name, time and experience, as the Python port matches them)
// turns green and takes the board's run instead of showing twice. Asks for a
// board it has not fetched yet. Rows earlier builds saved from the leaderboard
// (received, not the player's: the original's internet rows) stay out, since
// the board's latest answer replaces them.
FILE *highscore_table_open(char *path) {
  static char *table;
  FILE *file = platform_fopen(path, "rb");
  scores_shown.clear();
  if (!ranked_enabled)
    return file;
  ScoresBoard board;
  std::vector<ScoresRun> runs;
  if (config_blob.show_online_scores && scores_board(board)) {
    auto kept = scores_kept.find(board);
    if (kept != scores_kept.end())
      runs = kept->second;
    else if (!scores_out && !scores_asked.count(board))
      scores_send(board, true);
  }
  size_t size = 0;
  free(table);
  table = nullptr;
  FILE *out = open_memstream(&table, &size);
  highscore_record_t record;
  while (file && !feof(file)) {
    if (!highscore_read_record((char *)&record, file) || ((record.flags & 1) && !(record.flags & 2)))
      continue;
    for (size_t i = 0; i < runs.size(); ++i)
      if (!strcmp(runs[i].record.player_name, record.player_name) &&
          runs[i].record.run_elapsed_ms == record.run_elapsed_ms && runs[i].record.score_xp == record.score_xp) {
        record.flags |= 1;
        scores_shown.push_back({record, runs[i].run});
        runs.erase(runs.begin() + (ptrdiff_t)i);
        break;
      }
    highscore_write_record(&record, out);
  }
  if (file)
    fclose(file);
  for (ScoresRun &run : runs) {
    highscore_write_record(&run.record, out);
    scores_shown.push_back(run);
  }
  fclose(out);
  return fmemopen(table, size, "rb");
}
}

extern "C" {
void highscore_sync_worker(void *arg) {
  if (!ranked_enabled)
    return highscore_sync_worker_recovered(arg);
  // A table with no board is up to date, so Update all goes on past it.
  ScoresBoard board;
  if (!scores_board(board)) {
    online_sync_status = 0;
    return;
  }
  online_sync_status = 1;
  if (scores_out)
    scores_update_waiting = true;
  else
    scores_send(board, false);
}
// The board the screen asks for, as the request's JSON body.
__attribute__((export_name("game_scores_request"))) const char *game_scores_request() { return scores_request; }
// Room for the service's answer, which the host writes, then hands over
// (game_scores_received), or a negative size when it could not fetch it.
__attribute__((export_name("game_scores_buffer"))) char *game_scores_buffer(int size) {
  scores_response.assign(size + 1, 0);
  return scores_response.data();
}
__attribute__((export_name("game_scores_received"))) void game_scores_received(int size) {
  Json answer;
  const Json *runs = size >= 0 && (size_t)size < scores_response.size() && json_parse(scores_response.data(), size, answer)
                         ? answer.field("scores", Json::ARRAY)
                         : nullptr;
  scores_out = false;
  if (runs) {
    std::vector<ScoresRun> &kept = scores_kept[scores_board_asked];
    kept.clear();
    for (const Json &run : runs->items) {
      ScoresRun shown = {};
      if (!scores_record(run, scores_board_asked, shown.record))
        continue;
      if (const Json *id = run.field("run", Json::STRING); id && scores_run_id(id->text))
        shown.run = id->text;
      // The record's tag names its run (FNV-1a), so two runs with the same
      // name, numbers and day stay apart in the table.
      uint32_t tag = 2166136261u;
      for (char c : shown.run)
        tag = (tag ^ (uint8_t)c) * 16777619u;
      shown.record.random_tag = tag;
      kept.push_back(shown);
    }
  }
  if (!scores_out_quiet) {
    online_sync_status = runs ? 0 : 6;
    // As the original after a sync: all-time scores, the internet's shown.
    if (runs) {
      config_blob.highscore_date_mode = 0;
      config_blob.show_online_scores = 1;
    }
  }
  // The table reads the board's new runs, and asks for a board shown meanwhile.
  highscore_load_table_thunk();
  // Update scores pressed while a quiet request was out asks for the board shown now.
  ScoresBoard board;
  if (scores_update_waiting && !scores_out) {
    scores_update_waiting = false;
    if (scores_board(board))
      scores_send(board, false);
    else
      online_sync_status = 0;
  }
}

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
  // A fresh config's default name (config defaults) is nobody's, so the tip leaves it out.
  if (!*name || !strcmp(name, "10tons") || grim_interface_ptr->grim_measure_text_width(ranked_tip) >
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
// box shows.
__attribute__((export_name("game_leaderboard_enable"))) void game_leaderboard_enable() { ranked_enabled = true; }
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
