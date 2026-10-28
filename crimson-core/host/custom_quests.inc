// The main menu's Mods entry, which no version runs, browses the custom quests
// published on the leaderboard (docs/formats/quest-dsl.md), newest first: the
// databases' two panels, the quests in the quest list's rows on the left, which
// scroll and load more as they near the end, and the selected one on the right
// with its weapon and what it turns off. The host fetches a page at a time
// (HOST_LEADERBOARD_CUSTOM, service/src/views.ts gameCustomQuests) and a quest's
// table into quests/online/<id>.bin (HOST_LEADERBOARD_QUEST); Play starts it as a
// link to it does (watch_follow_link). It shows only where the game ranks runs,
// which a custom quest plays as: not inside another site's page.
extern "C" {
extern ui_element_t ui_element_slot_09, ui_element_slot_33;
extern unsigned char mods_menu_refresh_pending;
extern unsigned char ui_mouse_blocked;
extern char menu_label_back[];
bool ui_focus_list(void *list, float x, float y, bool up, bool down);
void ui_focus_set(int id, char reset_timer);
}
#include "crimsonland_textures_owner.h"

// A quest as the browser shows it.
struct CustomQuestShown {
  std::string id, title, author;
  int players, weapon;
  std::vector<int> no_bonuses, no_perks, no_weapons;
};
enum CustomQuestsStatus { CUSTOM_LOADING, CUSTOM_SHOWN, CUSTOM_FAILED };
// How the fetch of a quest's table ended: 0 written, 1 the leaderboard has no such quest, 2 not fetched (the
// host's results); or one written that is no table the game plays; or it has not yet.
enum CustomQuestDownload { CUSTOM_DOWNLOADED, CUSTOM_GONE, CUSTOM_DOWNLOAD_FAILED, CUSTOM_UNPLAYABLE, CUSTOM_DOWNLOADING };
static constexpr int CUSTOM_ROWS = 10; // the quest list's rows
static struct {
  std::vector<CustomQuestShown> quests;
  CustomQuestsStatus status;
  bool more;     // the leaderboard has quests past those here
  int pages;     // the pages here, the next one the one to ask for
  bool out;      // a page is asked for
  bool reopened; // the screen opened again while one was out: its answer starts the list afresh
  int selected, scroll;
  char request[32];
  std::vector<char> response;
  // The quest whose table the host fetches, the one Play waits for, and how its fetch ended.
  std::string download, playing;
  CustomQuestDownload fetched;
} custom;

static void custom_quests_send() {
  custom.out = true;
  snprintf(custom.request, sizeof custom.request, "{\"page\": %d}", custom.pages);
  host_leaderboard(HOST_LEADERBOARD_CUSTOM);
}
// The list from its first page, asked for afresh.
static void custom_quests_open() {
  custom.status = CUSTOM_LOADING;
  custom.quests.clear();
  custom.pages = 0;
  custom.selected = custom.scroll = 0;
  custom.playing.clear();
  if (custom.out)
    custom.reopened = true;
  else
    custom_quests_send();
}

// The ids an answer lists under `key`, each within [low, high]: the restrictions
// the quest's table packs (src/crimson/quests/custom.py).
static bool custom_quests_ids(const Json &quest, const char *key, int low, int high, std::vector<int> &out) {
  const Json *ids = quest.field(key, Json::ARRAY);
  if (!ids)
    return false;
  for (const Json &id : ids->items) {
    if (id.kind != Json::NUMBER || !id.integer || id.number < low || id.number > high)
      return false;
    out.push_back((int)id.number);
  }
  return true;
}
static bool custom_quests_read(const Json &item, CustomQuestShown &shown) {
  const Json *id = item.field("id", Json::STRING), *title = item.field("title", Json::STRING),
             *author = item.field("author", Json::STRING);
  double players, weapon;
  if (!id || id->text.size() != 12 || id->text.find_first_not_of("0123456789abcdef") != std::string::npos || !title ||
      !author || !scores_count(item, "players", INT32_MAX, players) ||
      !scores_count(item, "start_weapon_id", 53, weapon) || !custom_quest_weapon_valid((int)weapon) ||
      !custom_quests_ids(item, "no_bonuses", 2, 14, shown.no_bonuses) ||
      !custom_quests_ids(item, "no_perks", 1, 57, shown.no_perks) ||
      !custom_quests_ids(item, "no_weapons", 2, 33, shown.no_weapons))
    return false;
  shown.id = id->text;
  shown.title = title->text.substr(0, 64);
  shown.author = author->text.substr(0, 31);
  shown.players = (int)players;
  shown.weapon = (int)weapon;
  return true;
}

// The quest's table, read into the one a run plays, or false when it is not
// here or no table the game plays.
static bool custom_quests_load(const CustomQuestShown &shown) {
  char path[64];
  snprintf(path, sizeof path, "quests/online/%s.bin", shown.id.c_str());
  PortableQuest table;
  FILE *fp = platform_fopen(path, "rb");
  if (!fp)
    return false;
  bool read = fread(&table, 1, sizeof table, fp) == sizeof table && fgetc(fp) == EOF;
  fclose(fp);
  if (!read || !custom_quest_valid_for(table))
    return false;
  quest = table;
  snprintf(custom_quest_title, sizeof custom_quest_title, "%s", shown.title.c_str());
  snprintf(custom_quest_author, sizeof custom_quest_author, "%s", shown.author.c_str());
  return true;
}

// The custom quest at portable_quest starts as the quest list starts one, the
// player's own menu settings kept for after it (custom_quest_restore).
static void custom_quest_begin() {
  if (!custom_quest_restore_menu) {
    watch.menu = menu_shown();
    custom_quest_saved_ranked = ranked_checked;
    custom_quest_restore_menu = true;
  }
  config_blob.game_mode = GAME_MODE_QUEST;
  config_blob.hardcore = 0;
  config_blob.player_count = 1;
  quest_stage_major = 0;
  quest_stage_minor = 0;
  ranked_checked = true;
  run_active = 0;
  ui_sign_crimson.focus_disabled = 0;
  ui_transition_direction = 0;
  game_state_pending = GAME_STATE_GAMEPLAY;
  music_fade_out_all(music_track_crimson_theme_id);
  music_fade_out_all(music_track_shortie_monk_id);
  music_fade_out_all(music_track_game_playlist);
  screen_fade_ramp_flag = 1;
}

// Play: the quest starts from its table here, or once the host has fetched it,
// one table at a time; another press after a failed fetch asks again. Selecting
// another quest, leaving and co-op opening drop it. Returns what keeps it, or "".
static const char *custom_quests_play(const CustomQuestShown &shown, bool pressed) {
  if (pressed) {
    if (custom_quests_load(shown))
      return custom_quest_begin(), "";
    custom.playing = shown.id;
    custom.fetched = CUSTOM_DOWNLOADING;
  }
  if (custom.playing != shown.id) {
    custom.playing.clear();
    return "";
  }
  switch (custom.fetched) {
  case CUSTOM_DOWNLOADING:
    if (custom.download.empty()) {
      mkdir("quests", 0755);
      mkdir("quests/online", 0755);
      custom.download = shown.id;
      host_leaderboard(HOST_LEADERBOARD_QUEST);
    }
    return "Downloading the quest...";
  case CUSTOM_DOWNLOADED:
    if (custom_quests_load(shown))
      return custom.playing.clear(), custom_quest_begin(), "";
    custom.fetched = CUSTOM_UNPLAYABLE;
    [[fallthrough]];
  case CUSTOM_UNPLAYABLE:
    return "This quest cannot play here";
  case CUSTOM_GONE:
    return "This quest is no longer published";
  case CUSTOM_DOWNLOAD_FAILED:
    break;
  }
  return "Could not download this quest";
}

// `text` cut to `width` pixels of small text, with an ellipsis where it is cut.
static std::string custom_quests_fit(const std::string &text, float width) {
  IGrim2D_cpp *grim = grim_interface_ptr;
  if ((float)grim->grim_measure_text_width((char *)text.c_str()) <= width)
    return text;
  std::string cut = text;
  while (!cut.empty() && (float)grim->grim_measure_text_width((char *)(cut + "...").c_str()) > width)
    cut.pop_back();
  return cut + "...";
}

// What the quest turns off, as a label and the names, wrapped to `width`
// under the label's indent.
static std::vector<std::string> custom_quests_off(float width, const char *label, const std::vector<std::string> &names) {
  IGrim2D_cpp *grim = grim_interface_ptr;
  std::vector<std::string> lines;
  for (size_t i = 0; i < names.size(); ++i) {
    std::string word = names[i] + (i + 1 < names.size() ? "," : "");
    if (lines.empty())
      lines.push_back(std::string(label) + " " + word);
    else if ((float)grim->grim_measure_text_width((char *)(lines.back() + " " + word).c_str()) <= width)
      lines.back() += " " + word;
    else
      lines.push_back("   " + word);
  }
  return lines;
}

// The selected quest, on the right panel, as the weapon database shows a
// weapon: a dim note in its corner, the name, the weapon's icon, then the rest,
// from `x`, `y` (the name).
static void custom_quests_detail(float x, float y, const CustomQuestShown &shown) {
  IGrim2D_cpp *grim = grim_interface_ptr;
  char text[96];
  grim->grim_set_config_var(0x18, 0.43f);
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 0.4f);
  snprintf(text, sizeof text, "cleared by %d", shown.players);
  grim->grim_draw_text_small(x + 244.0f - (float)grim->grim_measure_text_width(text), y - 18.0f, text);
  grim->grim_set_config_var(0x18, 0.5f);
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
  grim->grim_draw_text_small(x, y, (char *)custom_quests_fit(shown.title, 240.0f).c_str());
  if (!shown.author.empty()) {
    snprintf(text, sizeof text, "by %s", shown.author.c_str());
    grim->grim_set_color(0.7f, 0.7f, 0.7f, 0.7f);
    grim->grim_draw_text_small(x, y + 16.0f, text);
  }
  // The weapon the quest starts with, its icon as the database draws it (the
  // atlas holds the droppable weapons' alone); with no weapon to pick up, the
  // only one.
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
  if (int icon = weapon_table[shown.weapon].hud_icon_id; icon >= 0 && icon < 32) {
    grim->grim_bind_texture(texture_handles.ui_weapon_icons_texture, 0);
    grim->grim_set_sub_rect(8, 2, 1, icon << 1);
    grim->grim_begin_batch();
    grim->grim_draw_quad(x + 16.0f, y + 34.0f, 64.0f, 32.0f);
    grim->grim_end_batch();
    grim->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
  }
  grim->grim_draw_text_small(x + 96.0f, y + 38.0f, weapon_table[shown.weapon].name);
  if (shown.no_weapons.size() == 32) {
    grim->grim_set_color(0.7f, 0.7f, 0.7f, 0.7f);
    grim->grim_draw_text_small(x + 96.0f, y + 54.0f, (char *)"No other weapons");
  }
  // What it turns off, by name while the panel holds them, the longest list
  // counted out of what drops or is offered first when it does not.
  struct Off {
    const char *label;
    int total;
    std::vector<std::string> names, lines;
  } off[3] = {{"No weapons:", 32}, {"No bonuses:", 13}, {"No perks:", 57}};
  if (shown.no_weapons.size() < 32)
    for (int id : shown.no_weapons)
      off[0].names.push_back(weapon_table[id].name);
  for (int id : shown.no_bonuses)
    off[1].names.push_back(bonus_meta_table[id].label);
  for (int id : shown.no_perks)
    off[2].names.push_back(perk_meta_table[id].name);
  for (Off &list : off)
    list.lines = custom_quests_off(228.0f, list.label, list.names);
  static constexpr size_t LINES = 5;
  for (;;) {
    Off *longest = &off[0];
    size_t lines = 0;
    for (Off &list : off) {
      lines += list.lines.size();
      if (list.lines.size() > longest->lines.size())
        longest = &list;
    }
    if (lines <= LINES || longest->lines.size() < 2)
      break;
    char count[48];
    snprintf(count, sizeof count, "%s %d of %d", longest->label, (int)longest->names.size(), longest->total);
    longest->lines.assign(1, count);
  }
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
  float at = y + 82.0f;
  for (const Off &list : off)
    for (const std::string &line : list.lines) {
      grim->grim_draw_text_small(x + 16.0f, at, (char *)line.c_str());
      at += 18.0f;
    }
}

extern "C" {
// The Mods entry shows while the host ranks runs (game_leaderboard_enable).
bool mods_any_available(void) { return ranked_offered; }

void mods_menu_update(void) {
  IGrim2D_cpp *grim = grim_interface_ptr;
  // The screen asks for its first page afresh each time it opens (game_state_set).
  if (mods_menu_refresh_pending) {
    mods_menu_refresh_pending = 0;
    custom_quests_open();
  }
  // The left panel, laid out as the databases' (unlocked_weapons_database_update).
  float x = ui_element_slot_09.pos_x + ui_element_slot_09.vertices[0].x + 300.0f + ui_element_slot_09.render_offset_x +
            44.0f - 110.0f - 32.0f;
  float y = ui_element_slot_09.pos_y + ui_element_slot_09.vertices[0].y + 40.0f + 10.0f;
  const char *title = "Custom Quests";
  int title_width = grim->grim_measure_text_width((char *)title);
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
  grim->grim_set_config_var(0x18, 0.5f);
  grim->grim_draw_text_small(x + 132.0f - (float)(title_width / 2), y, (char *)title);
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
  float separator[2] = {x + (float)(132 - title_width / 2), y + 13.0f};
  grim->grim_draw_rect_outline(separator, (float)title_width, 1.0f);

  // The rows, as the quest list draws its quests, each title with its author in
  // the list's grey. The list takes the focus as a whole: the arrow keys and the
  // pad's up/down move its selection, the wheel scrolls it, a click selects, and
  // Enter plays.
  static const float idle[4] = {0.274509817f, 0.70588237f, 0.941176474f, 0.600000024f};
  static const float lit[4] = {0.274509817f, 0.70588237f, 0.941176474f, 1.0f};
  static const float grey[4] = {0.7f, 0.7f, 0.7f, 0.7f};
  static char list;
  int count = (int)custom.quests.size();
  float row_x = x + 16.0f, rows_y = y + 40.0f, width = 236.0f;
  bool focused = ui_focus_list(&list, row_x, rows_y, custom.selected > 0, custom.selected < count - 1);
  int moved = custom.selected;
  if (grim->grim_was_key_pressed(0xc8))
    custom.selected = std::max(custom.selected - 1, 0);
  if (grim->grim_was_key_pressed(0xd0))
    custom.selected = std::max(std::min(custom.selected + 1, count - 1), 0);
  // A selection the keys move stays in view, and takes the focus for Enter;
  // the wheel scrolls past it.
  if (custom.selected != moved) {
    ui_focus_set((int)(size_t)&list, 0);
    custom.scroll = std::min(custom.scroll, custom.selected);
    custom.scroll = std::max(custom.scroll, custom.selected - CUSTOM_ROWS + 1);
  }
  bool over = ui_mouse_x > row_x - 10.0f && ui_mouse_x < row_x + width + 16.0f && ui_mouse_y > rows_y - 2.0f &&
              ui_mouse_y < rows_y + CUSTOM_ROWS * 20.0f;
  // The mouse over the rows takes the focus, as over a button.
  if (over && !ui_mouse_blocked)
    ui_focus_set((int)(size_t)&list, 0);
  float wheel = grim->grim_get_mouse_wheel_delta();
  if (over && wheel)
    custom.scroll += wheel > 0 ? -1 : 1;
  custom.scroll = std::max(std::min(custom.scroll, count - CUSTOM_ROWS), 0);
  bool enter = focused && count && grim->grim_was_key_pressed(0x1c);
  for (int row = 0; row < CUSTOM_ROWS && custom.scroll + row < count; ++row) {
    int index = custom.scroll + row;
    const CustomQuestShown &shown = custom.quests[index];
    float row_y = rows_y + row * 20.0f;
    bool hovered = !ui_mouse_blocked && ui_mouse_x > row_x - 10.0f && ui_mouse_x < row_x + width &&
                   ui_mouse_y > row_y - 2.0f && ui_mouse_y < row_y + 18.0f;
    if (hovered && input_primary_just_pressed())
      custom.selected = index;
    // The title keeps at least three fifths of the row when both do not fit,
    // the author the rest, each cut short.
    std::string by = shown.author.empty() ? "" : "by " + shown.author;
    float by_width = by.empty() ? 0.0f : (float)grim->grim_measure_text_width((char *)by.c_str()) + 8.0f;
    std::string name = custom_quests_fit(shown.title, std::max(width - by_width, width * 0.6f));
    float name_width = (float)grim->grim_measure_text_width((char *)name.c_str());
    grim->grim_set_color_ptr((float *)(hovered || index == custom.selected ? lit : idle));
    grim->grim_draw_text_small(row_x, row_y, (char *)name.c_str());
    float under[2] = {row_x, row_y + 13.0f};
    grim->grim_draw_rect_outline(under, name_width, 1.0f);
    if (!by.empty()) {
      grim->grim_set_color_ptr((float *)grey);
      grim->grim_draw_text_small(row_x + name_width + 8.0f, row_y,
                                 (char *)custom_quests_fit(by, width - name_width - 8.0f).c_str());
    }
  }
  // Past the rows, a thin track and thumb show where the list is scrolled.
  if (count > CUSTOM_ROWS) {
    float height = CUSTOM_ROWS * 20.0f - 6.0f, track[2] = {row_x + width + 12.0f, rows_y};
    grim->grim_set_color(1.0f, 1.0f, 1.0f, 0.2f);
    grim->grim_draw_rect_outline(track, 1.0f, height);
    float thumb[2] = {track[0] - 1.0f, rows_y + height * (float)custom.scroll / (float)count};
    grim->grim_draw_rect_filled(thumb, 3.0f, height * (float)CUSTOM_ROWS / (float)count, (float *)lit);
  }
  // A status in the rows' place, and more quests asked for as the list nears its end.
  const char *status = custom.status == CUSTOM_FAILED                 ? "Can't reach crimson.land"
                       : custom.status == CUSTOM_LOADING && !count    ? "Loading..."
                       : custom.status == CUSTOM_SHOWN && !count      ? "No quests published yet"
                                                                       : nullptr;
  if (status) {
    grim->grim_set_color_ptr((float *)grey);
    grim->grim_draw_text_small(row_x, rows_y, (char *)status);
  }
  if (custom.status == CUSTOM_SHOWN && custom.more && !custom.out && custom.scroll + 2 * CUSTOM_ROWS >= count)
    custom_quests_send();

  // Play and Back at the panel's foot, where the databases have Back, and above
  // them what keeps Play. While co-op is open (a session, or a room waiting for
  // one), or the screen is not the one the verifier simulates (live_eligible),
  // Play shows as the original's disabled buttons do, and says why. Once the
  // screen leaves, for a quest or the main menu, neither acts.
  float bottom = ui_element_slot_09.pos_y + ui_element_slot_09.vertices[0].y + 40.0f + 265.0f + 8.0f;
  bool screen = config_blob.screen_width == 1024 && config_blob.screen_height == 768;
  const char *blocked = coop_open() ? "Not during co-op" : !screen ? "Custom quests need the 1024x768 screen" : nullptr;
  bool leaving = !ui_transition_direction && game_state_pending != GAME_STATE_PENDING_IDLE_SENTINEL;
  static ui_button_t play = {(char *)"Play", 0, 0, 1, 0, 0, 0, 1.0f}, back = {nullptr, 0, 0, 1, 0, 0, 0, 1.0f};
  play.enabled = count > 0 && !blocked;
  play.alpha = play.enabled ? 1.0f : 0.5f;
  back.label = menu_label_back;
  float play_at[2] = {x + 46.0f, bottom}, back_at[2] = {x + 134.0f, bottom};
  bool pressed = ui_button_update(play_at, &play) || (enter && !blocked);
  if (blocked || leaving)
    custom.playing.clear();
  const char *why = count && !blocked && !leaving ? custom_quests_play(custom.quests[custom.selected], pressed) : "";
  const char *note = count && blocked ? blocked : why;
  if (*note)
    viewer_text(row_x, bottom - 18.0f, note, 1.0f, 0.5f, 0.5f, 1.0f);
  if ((ui_button_update(back_at, &back) || grim->grim_was_key_pressed(1)) && !leaving) {
    custom.playing.clear();
    ui_transition_direction = 0;
    game_state_pending = GAME_STATE_MAIN_MENU;
  }

  // The right panel, laid out as the weapon database's.
  if (count)
    custom_quests_detail(ui_element_slot_33.pos_x + ui_element_slot_33.vertices[0].x + 300.0f +
                             ui_element_slot_33.render_offset_x - 16.0f - 240.0f - 10.0f + 16.0f,
                         ui_element_slot_33.pos_y + ui_element_slot_33.vertices[0].y + 40.0f + 10.0f,
                         custom.quests[custom.selected]);
}

// The page the browser asks for, as the request's JSON body.
__attribute__((export_name("game_custom_request"))) const char *game_custom_request() { return custom.request; }
// Room for the service's answer, which the host writes, then hands over
// (game_custom_received), or a negative size when it could not fetch it.
__attribute__((export_name("game_custom_buffer"))) char *game_custom_buffer(int size) {
  custom.response.assign(size + 1, 0);
  return custom.response.data();
}
__attribute__((export_name("game_custom_received"))) void game_custom_received(int size) {
  custom.out = false;
  // The screen opened again meanwhile: its first page goes now, in place of this one.
  if (custom.reopened) {
    custom.reopened = false;
    return custom_quests_send();
  }
  Json answer;
  const Json *quests = size >= 0 && (size_t)size < custom.response.size() &&
                               json_parse(custom.response.data(), size, answer)
                           ? answer.field("quests", Json::ARRAY)
                           : nullptr;
  const Json *more = quests ? answer.field("more", Json::BOOLEAN) : nullptr;
  // A later page that fails leaves the list as it was, with no more to load.
  if (!more) {
    custom.status = custom.quests.empty() ? CUSTOM_FAILED : CUSTOM_SHOWN;
    custom.more = false;
    return;
  }
  custom.status = CUSTOM_SHOWN;
  custom.more = more->number;
  ++custom.pages;
  for (const Json &item : quests->items)
    if (CustomQuestShown shown = {}; custom_quests_read(item, shown))
      custom.quests.push_back(shown);
}
// The quest whose table the host fetches into quests/online/<id>.bin.
__attribute__((export_name("game_quest_download"))) const char *game_quest_download() { return custom.download.c_str(); }
// The host's fetch ended (CustomQuestDownload).
__attribute__((export_name("game_quest_downloaded"))) void game_quest_downloaded(int result) {
  if (custom.download == custom.playing)
    custom.fetched = result == 0 ? CUSTOM_DOWNLOADED : result == 1 ? CUSTOM_GONE : CUSTOM_DOWNLOAD_FAILED;
  custom.download.clear();
}
}
