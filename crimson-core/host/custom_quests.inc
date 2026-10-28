// The main menu's Mods entry, which no version runs, browses the custom quests
// published on the leaderboard (docs/formats/quest-dsl.md): the original's two
// database panels, the quests in the quest list's rows on the left, the one
// selected on the right with its restrictions, its board's best times, Play and
// the creator's clear to watch. The host fetches a page at a time
// (HOST_LEADERBOARD_CUSTOM, service/src/views.ts gameCustomQuests) and a quest's
// table into quests/online/<id>.bin (HOST_LEADERBOARD_QUEST); Play starts it as a
// link to it does (watch_follow_link). It shows only where the game ranks runs,
// which a custom quest plays as: not inside another site's page.
extern "C" {
extern ui_element_t ui_element_slot_09, ui_element_slot_33;
extern unsigned char mods_menu_refresh_pending;
extern unsigned char ui_mouse_blocked;
extern char menu_label_back[];
bool ui_focus_row(int row, float x, float y);
}

// A quest as the browser shows it.
struct CustomQuestShown {
  std::string id, title, author, proof;
  int players, weapon;
  int no_bonuses, no_perks, no_weapons; // how many the quest takes out
  std::vector<std::pair<std::string, double>> best;
};
enum CustomQuestsStatus { CUSTOM_LOADING, CUSTOM_SHOWN, CUSTOM_FAILED };
// Quest tables the host fetches: 0 written, 1 the leaderboard has no such quest, 2 not fetched; or one written
// that is no table the game plays.
enum CustomQuestDownload { CUSTOM_DOWNLOADED, CUSTOM_GONE, CUSTOM_DOWNLOAD_FAILED, CUSTOM_UNPLAYABLE };
static constexpr int CUSTOM_PAGE = 10; // the quest list's rows, a page's quests (service/src/index.ts)
static struct {
  std::vector<CustomQuestShown> quests;
  CustomQuestsStatus status;
  bool more, popular;
  int page, selected;
  // One page is asked for at a time; one wanted meanwhile waits for it.
  bool out, wanted_popular;
  int wanted_page;
  char request[64];
  std::vector<char> response;
  // The quest whose table the host fetches, and the one Play waits for.
  std::string download, playing;
  std::map<std::string, CustomQuestDownload> downloads;
} custom;

static void custom_quests_send(bool popular, int page) {
  custom.out = true;
  custom.status = CUSTOM_LOADING;
  custom.wanted_popular = popular;
  custom.wanted_page = page;
  snprintf(custom.request, sizeof custom.request, "{\"sort\": \"%s\", \"page\": %d}", popular ? "popular" : "newest", page);
  host_leaderboard(HOST_LEADERBOARD_CUSTOM);
}
// Asks for a page; one asked for while another is out goes when that one is back.
static void custom_quests_ask(bool popular, int page) {
  custom.popular = popular;
  custom.page = page;
  custom.selected = 0;
  if (custom.out)
    custom.status = CUSTOM_LOADING;
  else
    custom_quests_send(popular, page);
}

// A quest's ids that an answer lists under `key`, counted: a count past the
// table's is no quest the game plays.
static bool custom_quests_count(const Json &quest, const char *key, int max, int &count) {
  const Json *ids = quest.field(key, Json::ARRAY);
  count = ids ? (int)ids->items.size() : 0;
  return ids && count <= max;
}
static bool custom_quests_read(const Json &item, CustomQuestShown &shown) {
  const Json *id = item.field("id", Json::STRING), *title = item.field("title", Json::STRING),
             *author = item.field("author", Json::STRING), *proof = item.field("proof", Json::STRING),
             *best = item.field("best", Json::ARRAY);
  double players, weapon;
  size_t weapons = sizeof(weapon_storage_table_t) / sizeof(weapon_storage_entry_t);
  if (!id || id->text.size() != 12 || id->text.find_first_not_of("0123456789abcdef") != std::string::npos || !title ||
      !author || !proof || !scores_run_id(proof->text) || !best || !scores_count(item, "players", INT32_MAX, players) ||
      !scores_count(item, "start_weapon_id", weapons - 1, weapon) ||
      !custom_quests_count(item, "no_bonuses", 13, shown.no_bonuses) ||
      !custom_quests_count(item, "no_perks", 57, shown.no_perks) ||
      !custom_quests_count(item, "no_weapons", 32, shown.no_weapons))
    return false;
  shown.id = id->text;
  shown.title = title->text.substr(0, 64);
  shown.author = author->text.substr(0, 31);
  shown.proof = proof->text;
  shown.players = (int)players;
  shown.weapon = (int)weapon;
  for (const Json &run : best->items) {
    const Json *name = run.field("name", Json::STRING);
    double score;
    if (name && scores_count(run, "score", UINT32_MAX, score))
      shown.best.emplace_back(name->text.substr(0, 31), score);
  }
  return true;
}

static void custom_quests_path(const std::string &id, char *path, size_t size) {
  snprintf(path, size, "quests/online/%s.bin", id.c_str());
}
// The quest's table, read into the one a run plays, or false when it is not
// here or no table the game plays.
static bool custom_quests_load(const CustomQuestShown &shown) {
  char path[64];
  custom_quests_path(shown.id, path, sizeof path);
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
// another quest drops it. The line under the button says what keeps it.
static const char *custom_quests_play(const CustomQuestShown &shown, bool pressed) {
  if (pressed) {
    if (custom_quests_load(shown))
      return custom_quest_begin(), "";
    custom.playing = shown.id;
    custom.downloads.erase(shown.id);
  }
  if (custom.playing != shown.id) {
    custom.playing.clear();
    return "";
  }
  auto known = custom.downloads.find(shown.id);
  if (known == custom.downloads.end()) {
    if (custom.download.empty()) {
      mkdir("quests", 0755);
      mkdir("quests/online", 0755);
      custom.download = shown.id;
      host_leaderboard(HOST_LEADERBOARD_QUEST);
    }
    return "Downloading the quest...";
  }
  switch (known->second) {
  case CUSTOM_DOWNLOADED:
    if (custom_quests_load(shown))
      return custom.playing.clear(), custom_quest_begin(), "";
    known->second = CUSTOM_UNPLAYABLE;
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

// Watch proof: the replay of the quest's first clear, which published it, as
// the high score card's Watch plays a board run (highscore_watch). Returns what
// keeps it, or "".
static const char *custom_quests_proof(float *at, const CustomQuestShown &shown, bool coop) {
  static ui_button_t button = {(char *)"Watch proof", 0, 0, 1, 0, 0, 0, 1.0f};
  static std::string shown_proof;
  static int downloads_seen = -1;
  static LoadedReplay target;
  static std::string note;
  static bool playable;
  if (shown.proof != shown_proof || downloads_seen != watch_downloads_done) {
    if (shown.proof != shown_proof)
      ++watch_pins;
    shown_proof = shown.proof;
    downloads_seen = watch_downloads_done;
    char path[96];
    watch_online_path(shown.proof, path, sizeof path);
    playable = false;
    if (access(path, F_OK))
      note = watch_online_note(shown.proof);
    else if (!replay_read_file(path, target))
      note = target.reason;
    else if (config_blob.screen_width != 1024 || config_blob.screen_height != 768)
      note = "Watching needs the 1024x768 screen";
    else
      playable = true, note.clear();
  }
  button.enabled = playable && !coop;
  button.alpha = button.enabled ? 1.0f : 0.5f;
  if (ui_button_update(at, &button))
    watch_start(target, watch_card(target, shown.author.c_str(), 0, 0, 0, 2000), shown.proof);
  return note.c_str();
}

// A quest's time on its board, in seconds, as the leaderboard shows it.
static std::string custom_quests_time(double ms) {
  char text[32];
  snprintf(text, sizeof text, "%.2f s", ms / 1000.0);
  return text;
}

// The selected quest, on the right panel (the database's detail panel), from
// its top: what it is, what it takes out of the run, and its board's best times.
static void custom_quests_detail(float x, float y, const CustomQuestShown &shown) {
  IGrim2D_cpp *grim = grim_interface_ptr;
  auto line = [&](float alpha, const char *text) {
    grim->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim->grim_draw_text_small(x, y, (char *)text);
    y += 15.0f;
  };
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
  grim->grim_draw_text_small(x, y, (char *)shown.title.c_str());
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
  float under[2] = {x, y + 13.0f};
  grim->grim_draw_rect_outline(under, 200.0f, 1.0f);
  y += 16.0f;
  char text[96];
  if (!shown.author.empty()) {
    snprintf(text, sizeof text, "by %s", shown.author.c_str());
    line(0.7f, text);
  }
  y += 2.0f;
  snprintf(text, sizeof text, "Weapon: %s", weapon_table[shown.weapon].name);
  line(0.9f, text);
  // Weapons from 2 on drop, bonuses drop and perks are offered, unless the quest takes them out.
  if (shown.no_weapons == 32)
    line(0.9f, "No weapons drop");
  else if (shown.no_weapons) {
    snprintf(text, sizeof text, shown.no_weapons == 1 ? "1 weapon never drops" : "%d weapons never drop",
             shown.no_weapons);
    line(0.9f, text);
  }
  if (shown.no_bonuses) {
    snprintf(text, sizeof text, shown.no_bonuses == 1 ? "1 bonus never drops" : "%d bonuses never drop",
             shown.no_bonuses);
    line(0.9f, text);
  }
  if (shown.no_perks) {
    snprintf(text, sizeof text, shown.no_perks == 1 ? "1 perk is never offered" : "%d perks are never offered",
             shown.no_perks);
    line(0.9f, text);
  }
  y += 2.0f;
  snprintf(text, sizeof text, "%d player%s cleared it", shown.players, shown.players == 1 ? "" : "s");
  line(0.7f, text);
  for (size_t i = 0; i < shown.best.size(); ++i) {
    snprintf(text, sizeof text, "%d. %s", (int)i + 1, shown.best[i].first.c_str());
    grim->grim_set_color(1.0f, 1.0f, 1.0f, 0.9f);
    grim->grim_draw_text_small(x + 8.0f, y, text);
    std::string time = custom_quests_time(shown.best[i].second);
    grim->grim_draw_text_small(x + 200.0f - (float)grim->grim_measure_text_width((char *)time.c_str()), y,
                               (char *)time.c_str());
    y += 15.0f;
  }
}

extern "C" {
// The Mods entry shows while the host ranks runs (game_leaderboard_enable).
bool mods_any_available(void) { return ranked_offered; }

void mods_menu_update(void) {
  IGrim2D_cpp *grim = grim_interface_ptr;
  // The screen asks for the first page afresh each time it opens (game_state_set).
  if (mods_menu_refresh_pending) {
    mods_menu_refresh_pending = 0;
    custom_quests_ask(custom.popular, 0);
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
  y += 26.0f;

  static ui_checkbox_t popular = {0, 0, 0, 0, (char *)"Most played"};
  popular.checked = custom.popular;
  float box_at[2] = {x + 150.0f, y - 2.0f};
  if (ui_checkbox_update(box_at, &popular))
    custom_quests_ask(popular.checked, 0);
  char status[64];
  if (custom.status == CUSTOM_LOADING)
    snprintf(status, sizeof status, "Loading...");
  else if (custom.status == CUSTOM_FAILED)
    snprintf(status, sizeof status, "Can't reach crimson.land");
  else if (custom.quests.empty())
    snprintf(status, sizeof status, custom.page ? "No more quests" : "No quests published yet");
  else
    snprintf(status, sizeof status, "Page %d", custom.page + 1);
  grim->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
  grim->grim_draw_text_small(x + 8.0f, y, status);
  y += 24.0f;

  // The rows, as the quest list draws its quests: a click selects one, as the
  // focus does when it moves to it, and Enter on the focused one plays it.
  static const float idle[4] = {0.274509817f, 0.70588237f, 0.941176474f, 0.600000024f};
  static const float hover[4] = {0.274509817f, 0.70588237f, 0.941176474f, 1.0f};
  static int focused_last = -1;
  bool shown = custom.status == CUSTOM_SHOWN;
  float row_x = x + 18.0f, row_y = y;
  bool enter = false;
  int focused = -1;
  for (int row = 0; shown && row < (int)custom.quests.size(); ++row, row_y += 20.0f) {
    if (ui_focus_row(row, row_x, row_y)) {
      focused = row;
      if (focused_last != row)
        custom.selected = row;
      if (grim->grim_was_key_pressed(0x1c))
        enter = true, custom.selected = row;
    }
    bool hovered = ui_mouse_x > row_x - 10.0f && row_y - 2.0f < ui_mouse_y && row_x + 210.0f > ui_mouse_x &&
                   row_y + 18.0f > ui_mouse_y && !ui_mouse_blocked;
    if (hovered && input_primary_just_pressed())
      custom.selected = row;
    grim->grim_set_color_ptr((float *)(hovered || row == custom.selected ? hover : idle));
    char number[8];
    snprintf(number, sizeof number, "%d", custom.page * CUSTOM_PAGE + row + 1);
    grim->grim_draw_text_small(row_x, row_y, number);
    const std::string &name = custom.quests[row].title;
    grim->grim_draw_text_small(row_x + 32.0f, row_y, (char *)name.c_str());
    float under[2] = {row_x, row_y + 13.0f};
    grim->grim_draw_rect_outline(under, (float)(grim->grim_measure_text_width((char *)name.c_str()) + 32), 1.0f);
  }
  focused_last = focused;
  // Left and right page through the quests, as they page the quest list's stages.
  int page = custom.page;
  if (grim->grim_was_key_pressed(203) && page > 0)
    --page;
  if (grim->grim_was_key_pressed(205) && shown && custom.more)
    ++page;

  float bottom = ui_element_slot_09.pos_y + ui_element_slot_09.vertices[0].y + 40.0f + 265.0f + 8.0f;
  static ui_button_t previous = {(char *)"<", 0, 0, 1, 0, 0, 0, 1.0f}, next = {(char *)">", 0, 0, 1, 0, 0, 0, 1.0f},
                     back = {nullptr, 0, 0, 1, 0, 0, 0, 1.0f};
  previous.enabled = custom.page > 0;
  next.enabled = shown && custom.more;
  previous.alpha = previous.enabled ? 1.0f : 0.5f;
  next.alpha = next.enabled ? 1.0f : 0.5f;
  float previous_at[2] = {x - 10.0f, bottom}, next_at[2] = {x + 66.0f, bottom}, back_at[2] = {x + 134.0f, bottom};
  if (ui_button_update(previous_at, &previous))
    --page;
  if (ui_button_update(next_at, &next))
    ++page;
  if (page != custom.page)
    custom_quests_ask(custom.popular, page);
  back.label = menu_label_back;
  if (ui_button_update(back_at, &back) || grim->grim_was_key_pressed(1)) {
    ui_transition_direction = 0;
    game_state_pending = GAME_STATE_MAIN_MENU;
  }

  // The right panel, laid out as the databases'.
  if (!shown || custom.quests.empty())
    return;
  const CustomQuestShown &selected = custom.quests[std::min(custom.selected, (int)custom.quests.size() - 1)];
  float px = ui_element_slot_33.pos_x + ui_element_slot_33.vertices[0].x + 300.0f + ui_element_slot_33.render_offset_x -
             16.0f - 240.0f - 10.0f + 36.0f;
  float py = ui_element_slot_33.pos_y + ui_element_slot_33.vertices[0].y + 40.0f + 10.0f - 18.0f;
  custom_quests_detail(px, py, selected);
  // Play and Watch proof at the panel's foot, and under it, where the Play
  // Game panel draws its tips, what keeps them. While co-op is open (a
  // session, or a room waiting for one), they show as the original's disabled
  // buttons do, and say why.
  bool coop = coop_open();
  static ui_button_t play = {(char *)"Play", 0, 0, 1, 0, 0, 0, 1.0f};
  play.enabled = !coop;
  play.alpha = coop ? 0.5f : 1.0f;
  float play_at[2] = {px - 13.0f, py + 160.0f}, proof_at[2] = {px + 75.0f, py + 160.0f};
  const char *why = custom_quests_play(selected, ui_button_update(play_at, &play) || (enter && !coop));
  const char *proof = custom_quests_proof(proof_at, selected, coop);
  const char *note = coop ? "Not during co-op" : *why ? why : proof;
  if (*note)
    viewer_text(px, py + 212.0f, note, 1.0f, 0.5f, 0.5f, 1.0f);
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
  // A page wanted meanwhile goes now, in place of this one.
  if (custom.wanted_popular != custom.popular || custom.wanted_page != custom.page)
    return custom_quests_send(custom.popular, custom.page);
  Json answer;
  const Json *quests = size >= 0 && (size_t)size < custom.response.size() &&
                               json_parse(custom.response.data(), size, answer)
                           ? answer.field("quests", Json::ARRAY)
                           : nullptr;
  const Json *more = quests ? answer.field("more", Json::BOOLEAN) : nullptr;
  custom.status = more ? CUSTOM_SHOWN : CUSTOM_FAILED;
  custom.quests.clear();
  custom.more = more && more->number;
  for (size_t i = 0; more && i < quests->items.size() && custom.quests.size() < CUSTOM_PAGE; ++i)
    if (CustomQuestShown shown = {}; custom_quests_read(quests->items[i], shown))
      custom.quests.push_back(shown);
  custom.selected = 0;
}
// The quest whose table the host fetches into quests/online/<id>.bin.
__attribute__((export_name("game_quest_download"))) const char *game_quest_download() { return custom.download.c_str(); }
// The host's fetch ended (CustomQuestDownload).
__attribute__((export_name("game_quest_downloaded"))) void game_quest_downloaded(int result) {
  if (custom.download.empty())
    return;
  custom.downloads[custom.download] =
      result == 0 ? CUSTOM_DOWNLOADED : result == 1 ? CUSTOM_GONE : CUSTOM_DOWNLOAD_FAILED;
  custom.download.clear();
}
}
