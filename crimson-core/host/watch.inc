// Watching a replay (docs/rewrite/watch-replays.md): the high score screen's
// Watch starts the run its replay recorded, as its Play a game starts one, and
// the session feeds each tick the recording's input and commands in place of
// the player's. Nothing the replay plays reaches the player: no setting or
// progress carries over (live_step), nothing is saved, and the menu settings it
// plays under are put back when it ends. Escape returns to the scores.
//
// The replay plays in the one world the game has, so a finished run's end
// screen, which the scores were opened from, is gone once one plays: the
// screen's Back then leaves for the Statistics menu.
#include <algorithm>
#include <deque>
#include <map>
#include <sys/stat.h>
extern "C" {
extern unsigned char run_active, screen_fade_ramp_flag;
extern ui_element_t ui_sign_crimson;
void music_fade_out_all(int sfx_id);
void music_play_exclusive(int sfx_id);
}

// A perk pick as the menu showed it: its choices, the one taken, and the level
// it came with.
struct WatchPick {
  int level, chosen, count, offered[7];
};
static const float watch_speeds[] = {0.25f, 0.5f, 1, 2, 4, 8};
static constexpr int WATCH_NORMAL_SPEED = 2;
// A skip runs every tick, this many a frame, so a long one keeps the window live.
static constexpr int WATCH_SKIP_TICKS_PER_FRAME = 600;
// How long a pick's popup shows, in the viewer's seconds.
static constexpr float WATCH_PICK_SECONDS = 3;

static struct {
  bool armed;          // Watch was pressed: the next run started plays `replay`
  LoadedReplay replay; // its own copy: the host can read another meanwhile
  // The player's time played, both counts, which a replay adds nothing to.
  unsigned play_time;
  int time_played;
  // The player's menu settings, while the replay's are in their place.
  struct {
    decltype(config_blob.game_mode) mode;
    decltype(config_blob.hardcore) hardcore;
    decltype(config_blob.player_count) player_count;
    int major, minor;
  } menu;
  size_t at;       // the next tick's place in the recording
  int tick, ticks; // ticks played, and the recording's
  int speed;       // in watch_speeds
  int skip;        // ticks a skip has still to run
  bool paused, step, ended;
  std::string stopped; // why it stopped before the recording's end
  bool played;         // at the end: the run ended as it recorded
  std::deque<WatchPick> picks;
  float pick_left; // seconds the first pick's popup still shows
} watch;

// The replay's run is the menu's: its mode, quest and difficulty, one player.
// Watch pressed again before the run starts keeps the player's menu settings.
static void watch_arm(const LoadedReplay &replay) {
  watch.replay = replay;
  PortableConfig recorded;
  memcpy(&recorded, replay.recording.data(), sizeof recorded);
  if (!watch.armed)
    watch.menu = {config_blob.game_mode, config_blob.hardcore, config_blob.player_count, quest_stage_major,
                  quest_stage_minor};
  config_blob.game_mode = (decltype(config_blob.game_mode))recorded.mode;
  config_blob.hardcore = (decltype(config_blob.hardcore))recorded.hardcore;
  config_blob.player_count = 1;
  if (recorded.mode == GAME_MODE_QUEST) {
    quest_stage_major = (int)recorded.major;
    quest_stage_minor = (int)recorded.minor;
  }
  watch.armed = true;
}
// The replay's run starts as the high score screen's Play a game starts one.
static void watch_start(const LoadedReplay &replay) {
  watch_arm(replay);
  run_active = 0;
  ui_sign_crimson.focus_disabled = 0;
  ui_transition_direction = 0;
  game_state_pending = GAME_STATE_GAMEPLAY;
  music_fade_out_all(music_track_crimson_theme_id);
  music_fade_out_all(music_track_shortie_monk_id);
  music_fade_out_all(music_track_game_playlist);
  screen_fade_ramp_flag = 1;
}
static void watch_disarm() {
  config_blob.game_mode = watch.menu.mode;
  config_blob.hardcore = watch.menu.hardcore;
  config_blob.player_count = watch.menu.player_count;
  quest_stage_major = watch.menu.major;
  quest_stage_minor = watch.menu.minor;
  watch.armed = false;
}

static void watch_leave();
static void watch_begin() {
  watch.armed = false;
  watch.play_time = play_time_ms;
  watch.time_played = time_played_ms;
  memcpy(&cfg, watch.replay.recording.data(), sizeof cfg);
  ranked_run = false;
  if (!live_start())
    return watch_leave();
  live.watching = true;
  watch.at = sizeof cfg;
  watch.tick = watch.ticks = watch.skip = 0;
  for (size_t at = sizeof cfg; at < watch.replay.recording.size(); ++watch.ticks) {
    uint32_t count;
    memcpy(&count, &watch.replay.recording[at + sizeof(PortableInput)], sizeof count);
    at += sizeof(PortableInput) + sizeof count + count * sizeof(PortableCommand);
  }
  watch.speed = WATCH_NORMAL_SPEED;
  watch.paused = watch.step = watch.ended = watch.played = false;
  watch.stopped.clear();
  watch.picks.clear();
}

// The replay stops, and the menu settings are the player's again.
static void watch_stop() {
  if (live.watching) {
    play_time_ms = watch.play_time;
    time_played_ms = watch.time_played;
  }
  live.watching = false;
  game_live = game_session = false;
  watch_disarm();
  watch.picks.clear();
}

// Back to the scores, with the menu's music.
static void watch_leave() {
  watch_stop();
  run_active = 0;
  game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  music_fade_out_all(music_track_crimson_theme_id);
  music_fade_out_all(music_track_shortie_monk_id);
  music_fade_out_all(music_track_game_playlist);
  music_play_exclusive(music_track_crimson_theme_id);
  ui_elements_timeline = 0;
  game_state_set_recovered(GAME_STATE_HIGHSCORES);
}

// The recording ran out, or a tick of it was refused (`stopped`). A run that
// played to its end, or to where it was left, ends with the result recorded.
static void watch_end(const char *stopped) {
  watch.ended = true;
  watch.stopped = stopped;
  if (*stopped)
    return;
  const char *outcome = !run_ended()                                   ? "incomplete"
                        : game_state_pending == GAME_STATE_QUEST_RESULTS ? "quest_completed"
                                                                         : "death";
  Msgpack m;
  replay_result(m, outcome);
  watch.played = m.out == watch.replay.result;
}

// One recorded tick; false once the replay has ended.
static bool watch_tick() {
  const std::vector<uint8_t> &recording = watch.replay.recording;
  if (watch.at >= recording.size())
    return watch_end(""), false;
  uint32_t count;
  memcpy(&in, &recording[watch.at], sizeof in);
  memcpy(&count, &recording[watch.at + sizeof in], sizeof count);
  memcpy(commands, &recording[watch.at + sizeof in + sizeof count], count * sizeof(PortableCommand));
  watch.at += sizeof in + sizeof count + count * sizeof(PortableCommand);
  // The menu's choices, as portable_step_many counts them, before the pick can
  // add one (Perk Expert, Perk Master); of a tick's picks, the popup shows the last.
  const int *counts = player_state_table[0].perk_counts;
  int choices = counts[PERK_ID_PERK_MASTER] > 0 ? 7 : counts[PERK_ID_PERK_EXPERT] > 0 ? 6 : 5, chosen = -1;
  for (uint32_t i = 0; i < count; ++i)
    if (commands[i].type == 1)
      chosen = commands[i].argument;
  // The perk menu the replay opens stays shut: its pick comes with a later tick.
  live.requested = GAME_STATE_PENDING_IDLE_SENTINEL;
  if (!live_step(count)) {
    char stopped[64];
    snprintf(stopped, sizeof stopped, "This run stops playing here (tick %d)", watch.tick);
    watch_end(stopped);
    return false;
  }
  ++watch.tick;
  if (chosen >= 0) {
    WatchPick pick = {player_state_table[0].level, chosen, choices, {}};
    memcpy(pick.offered, perk_choice_ids, choices * sizeof(int));
    if (watch.picks.empty())
      watch.pick_left = WATCH_PICK_SECONDS;
    watch.picks.push_back(pick);
  }
  live_timeline();
  if (ui_elements_timeline < 0)
    ui_elements_timeline = 0;
  return true;
}

static void watch_skip(int seconds) {
  watch.skip = std::min(watch.ticks - watch.tick, watch.skip + seconds * 60);
}

// game_live_frame for a replay: the viewer's keys, then the ticks this pass
// runs. A paused replay draws its world still; once it has ended, its last
// frame stays.
static int watch_frame() {
  auto pressed = [](int key) { return session_grim.IGrim2D_cpp::grim_was_key_pressed(key) != 0; };
  // Escape: the scores show from the next pass, which their own Escape would
  // otherwise take as well.
  if (pressed(1)) {
    watch_leave();
    return 0;
  }
  if (pressed(57)) // Space
    watch.paused = !watch.paused;
  watch.step |= watch.paused && pressed(0x34); // period: one tick
  if (pressed(0x1a)) // [
    watch.speed = std::max(watch.speed - 1, 0);
  if (pressed(0x1b)) // ]
    watch.speed = std::min(watch.speed + 1, (int)(sizeof watch_speeds / sizeof *watch_speeds) - 1);
  if (pressed(0x02)) // 1
    watch.speed = WATCH_NORMAL_SPEED;
  if (pressed(0xcd)) // Right
    watch_skip(5);
  if (pressed(0xd1)) // Page Down
    watch_skip(30);
  // The frame counts a run's time as played (game_frame_update): a replay's
  // never adds up.
  play_time_ms = watch.play_time;
  time_played_ms = watch.time_played;
  if (watch.ended)
    return 0;
  float dt = fminf(grim_frame_dt, 0.1f);
  if (!watch.picks.empty() && !watch.skip && (watch.pick_left -= dt) <= 0) {
    watch.picks.pop_front();
    watch.pick_left = watch.picks.empty() ? 0 : WATCH_PICK_SECONDS;
  }
  if (watch.skip)
    live.due = std::min(watch.skip, WATCH_SKIP_TICKS_PER_FRAME);
  else if (watch.paused)
    live.due = watch.step ? 1 : 0;
  else {
    live.banked += dt * watch_speeds[watch.speed];
    live.due = (int)(live.banked * 60.0f + 1e-4f);
    live.banked -= live.due / 60.0f;
  }
  watch.step = false;
  return live.due || watch.paused ? 1 : 0;
}

static void watch_text(float x, float y, const char *text, float r, float g, float b, float a) {
  grim_interface_ptr->grim_set_color(r, g, b, a);
  grim_interface_ptr->grim_draw_text_small(x, y, (char *)text);
}
static float watch_text_width(const char *text) {
  return (float)grim_interface_ptr->grim_measure_text_width((char *)text);
}
static void watch_panel(float x, float y, float w, float h) {
  float at[2] = {x, y}, fill[4] = {0, 0, 0, 0.75f};
  grim_interface_ptr->grim_draw_rect_filled(at, w, h, fill);
  grim_interface_ptr->grim_set_color(0.47f, 0.47f, 0.55f, 0.78f);
  grim_interface_ptr->grim_draw_rect_outline(at, w, h);
}
static void watch_clock(char *out, size_t size, int seconds) {
  snprintf(out, size, "%d:%02d", seconds / 60, seconds % 60);
}

// What the replay shows over its world (modes/replay_playback_mode.py): where
// it is and how fast it plays, the last perk pick, and at the end, how the run
// ended and whether it played as recorded.
static void watch_draw() {
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  char line[96], elapsed[16], total[16];
  float x = (float)config_blob.screen_width - 192.0f, y = 11.0f, w = 182.0f;
  snprintf(line, sizeof line, "%s %.2fx", watch.paused ? "PAUSE" : "REPLAY", watch_speeds[watch.speed]);
  if (watch.paused)
    watch_text(x, y, line, 0.96f, 0.82f, 0.47f, 0.9f);
  else
    watch_text(x, y, line, 0.9f, 0.9f, 0.9f, 0.86f);
  watch_clock(elapsed, sizeof elapsed, watch.tick / 60);
  watch_clock(total, sizeof total, watch.ticks / 60);
  float total_x = x + w - 4.0f - watch_text_width(total), bar_x = x + watch_text_width(elapsed) + 6.0f;
  float bar_w = fmaxf(8.0f, total_x - 6.0f - bar_x), progress = watch.ticks ? (float)watch.tick / watch.ticks : 1;
  float bar[2] = {bar_x, y + 23.0f}, back[4] = {0.18f, 0.26f, 0.38f, 0.59f}, fill[4] = {0.27f, 0.51f, 0.86f, 0.88f};
  grim_interface_ptr->grim_draw_rect_filled(bar, bar_w, 4.0f, back);
  grim_interface_ptr->grim_draw_rect_filled(bar, bar_w * progress, 4.0f, fill);
  watch_text(x, y + 18.0f, elapsed, 0.86f, 0.86f, 0.86f, 0.82f);
  watch_text(total_x, y + 18.0f, total, 0.86f, 0.86f, 0.86f, 0.82f);

  if (!watch.picks.empty() && !watch.skip) {
    const WatchPick &pick = watch.picks.front();
    float line_h = 16.0f, fade = fminf(1.0f, watch.pick_left / 0.5f);
    float px = 12.0f, py = (float)config_blob.screen_height * 0.5f - (pick.count + 1) * line_h * 0.5f;
    watch_panel(px - 6.0f, py - 6.0f, 230.0f, (pick.count + 1) * line_h + 12.0f);
    snprintf(line, sizeof line, "Level %d: perk picked", pick.level);
    watch_text(px, py, line, 0.9f, 0.9f, 0.9f, 0.9f * fade);
    for (int i = 0; i < pick.count; ++i) {
      bool chosen = i == pick.chosen;
      snprintf(line, sizeof line, "%c %s", chosen ? '>' : ' ', perk_meta_table[pick.offered[i]].name);
      if (chosen)
        watch_text(px, py + line_h * (i + 1), line, 0.5f, 1.0f, 0.6f, fade);
      else
        watch_text(px, py + line_h * (i + 1), line, 0.59f, 0.59f, 0.63f, 0.78f * fade);
    }
  }

  if (!watch.ended)
    return;
  const LoadedReplay &replay = watch.replay;
  char ending[64], score[64];
  if (replay.outcome == "death") {
    watch_clock(elapsed, sizeof elapsed, (int)(replay.elapsed_ms / 1000));
    snprintf(ending, sizeof ending, "Died at %s", elapsed);
  } else if (replay.outcome == "quest_completed")
    snprintf(ending, sizeof ending, "Quest completed, final time %.2f s",
             (replay.quest_final_ms >= 0 ? replay.quest_final_ms : replay.elapsed_ms) / 1000.0);
  else
    snprintf(ending, sizeof ending, "Left before the end");
  snprintf(score, sizeof score, "Experience %lld, kills %lld", (long long)replay.experience, (long long)replay.kills);
  struct Line {
    const char *text;
    float r, g, b, a;
  } lines[] = {
      {ending, 0.9f, 0.9f, 0.9f, 0.94f},
      {score, 0.78f, 0.78f, 0.82f, 0.9f},
      !watch.stopped.empty() ? Line{watch.stopped.c_str(), 1.0f, 0.5f, 0.5f, 0.94f}
      : watch.played         ? Line{"Played as recorded", 0.5f, 1.0f, 0.6f, 0.94f}
                             : Line{"This run played differently", 1.0f, 0.5f, 0.5f, 0.94f},
      {"Esc returns", 0.59f, 0.59f, 0.63f, 0.86f},
  };
  float line_h = 18.0f, width = 0;
  for (const auto &l : lines)
    width = fmaxf(width, watch_text_width(l.text));
  width += 24.0f;
  float px = ((float)config_blob.screen_width - width) * 0.5f, py = (float)config_blob.screen_height * 0.5f - 2 * line_h;
  watch_panel(px, py - 8.0f, width, 4 * line_h + 12.0f);
  for (int i = 0; i < 4; ++i)
    watch_text(px + 12.0f, py + i * line_h, lines[i].text, lines[i].r, lines[i].g, lines[i].b, lines[i].a);
}

// gameplay_update_and_render for a replay: the frame's ticks, a skip's muted and
// drawn only at its last, then what the replay shows over them.
static void watch_render() {
  int due = live.due, ran = 0;
  bool skipping = watch.skip > 0;
  float volume = live.run.config.sfx_volume;
  if (skipping)
    live.run.config.sfx_volume = 0;
  for (; ran < due; ++ran) {
    grim_render_disabled = skipping && ran + 1 < due;
    if (!watch_tick())
      break;
  }
  grim_render_disabled = 0;
  live.run.config.sfx_volume = volume;
  if (skipping) {
    watch.skip -= ran;
    if (watch.ended || !watch.skip) {
      // Of the picks the skip passed, the popup shows the last.
      watch.skip = 0;
      while (watch.picks.size() > 1)
        watch.picks.pop_front();
      watch.pick_left = watch.picks.empty() ? 0 : WATCH_PICK_SECONDS;
    }
  }
  if (ran == 0 || (skipping && ran < due))
    gameplay_render_world();
  watch_draw();
}

// A board run's replay, which the host fetches from /runs/<run>.crd into
// replays/online/<run>.crd (HOST_LEADERBOARD_REPLAY), one at a time; the
// newest few stay there for the next watch.
enum WatchDownload { WATCH_DOWNLOADING, WATCH_GONE, WATCH_FAILED };
static std::map<std::string, WatchDownload> watch_downloads;
static std::map<std::string, int> watch_failed_pin; // the pin a failed download failed under
static int watch_pins; // counts pins, each of which the card looks at afresh
static std::string watch_download; // the run the host is fetching
static int watch_downloads_done;   // counts finished downloads, which the card looks at again
static constexpr int WATCH_ONLINE_KEPT = 32;

static void watch_online_path(const std::string &run, char *path, size_t size) {
  snprintf(path, size, "replays/online/%s.crd", run.c_str());
}
// Makes room for one more download: the oldest past the newest few go.
static void watch_online_prune() {
  std::vector<std::pair<time_t, std::string>> files;
  if (DIR *dir = opendir("replays/online")) {
    while (dirent *entry = readdir(dir)) {
      std::string path = std::string("replays/online/") + entry->d_name;
      struct stat st;
      if (strstr(entry->d_name, ".crd") && !stat(path.c_str(), &st))
        files.emplace_back(st.st_mtime, path);
    }
    closedir(dir);
  }
  std::sort(files.begin(), files.end());
  for (size_t i = 0; i + WATCH_ONLINE_KEPT <= files.size(); ++i)
    unlink(files[i].second.c_str());
}
// The card's note for a board run whose replay is not here yet: asks the host
// for it, or says why it does not come.
static const char *watch_online_note(const std::string &run) {
  auto known = watch_downloads.find(run);
  if (known != watch_downloads.end() && known->second == WATCH_GONE)
    return "This run is no longer on the leaderboard";
  // A failed download shows while its pin lasts; the next pin tries again.
  if (known != watch_downloads.end() && known->second == WATCH_FAILED) {
    if (watch_failed_pin[run] == watch_pins)
      return "Could not download this run";
    watch_downloads.erase(known);
  }
  if (watch_download.empty()) {
    mkdir("replays", 0755);
    mkdir("replays/online", 0755);
    watch_online_prune();
    watch_download = run;
    watch_downloads[run] = WATCH_DOWNLOADING;
    host_leaderboard(HOST_LEADERBOARD_REPLAY);
  }
  return "Downloading the run...";
}

// The numbered replay a local high score record names (replay_save), or none.
static bool replay_numbered(int number, char *path, size_t size) {
  bool found = false;
  if (DIR *dir = opendir("replays")) {
    while (dirent *entry = readdir(dir)) {
      int named, end = 0;
      char mode[16];
      if (sscanf(entry->d_name, "%d-%15[a-z].crd%n", &named, mode, &end) == 2 && !entry->d_name[end] && end &&
          named == number) {
        snprintf(path, size, "replays/%s", entry->d_name);
        found = true;
        break;
      }
    }
    closedir(dir);
  }
  return found;
}

extern "C" {
// The pinned row (highscore_screen): a click on a row pins its card in place of
// the panel's settings, and on the same row again lets it go; the card shows the
// hovered row before it. Returns the row the card shows, or -1.
int highscore_watch_row(int hovered, int rows, int *selected) {
  static highscore_record_t pinned;
  static bool has_pin, down;
  bool now = session_grim.IGrim2D_cpp::grim_is_mouse_button_down(0) != 0, click = now && !down;
  down = now;
  int row = -1;
  for (int i = 0; has_pin && i < rows && row < 0; ++i)
    if (!memcmp(&highscore_table[i], &pinned, sizeof pinned))
      row = i;
  if (click && hovered >= 0) {
    ++watch_pins;
    has_pin = hovered != row;
    row = has_pin ? hovered : -1;
    if (has_pin)
      pinned = highscore_table[hovered];
  }
  // The original lights the row a click selects; the pinned one is that row.
  *selected = row;
  return hovered >= 0 ? hovered : row;
}

// The pinned card's Watch (highscore_screen, `card` where the card is drawn):
// the record's replay plays, or the card says why not.
void highscore_watch(float *card, highscore_record_t *record) {
  static highscore_record_t shown;
  static std::string shown_run;
  static int downloads_seen, pins_seen;
  static LoadedReplay target;
  static std::string note;
  static bool named, playable;
  static ui_button_t button = {(char *)"Watch", 0, 0, 1, 0, 0, 0, 1.0f};
  const std::string *run = scores_run(*record);
  if (memcmp(record, &shown, sizeof shown) || (run ? *run : "") != shown_run || downloads_seen != watch_downloads_done ||
      pins_seen != watch_pins) {
    shown = *record;
    shown_run = run ? *run : "";
    downloads_seen = watch_downloads_done;
    pins_seen = watch_pins;
    // A local run's replay by its number; a board run's by its id.
    int number;
    memcpy(&number, record->reserved0, sizeof number);
    char path[96];
    bool local = number > 0 && replay_numbered(number, path, sizeof path);
    named = number > 0 || run;
    playable = false;
    if (!local && run)
      watch_online_path(*run, path, sizeof path);
    if (!named)
      note.clear();
    else if (!local && !run)
      note = "Its replay was not saved";
    else if (!local && access(path, F_OK))
      note = watch_online_note(*run);
    else if (!replay_read_file(path, target))
      note = target.reason;
    else if (config_blob.screen_width != 1024 || config_blob.screen_height != 768)
      // The session simulates the verifier's screen (live_eligible).
      note = "Watching needs the 1024x768 screen";
    else {
      playable = true;
      // The release a build came from, without its commit.
      note = target.game_version == CRIMSON_GAME_VERSION
                 ? ""
                 : "Recorded with " + target.game_version.substr(0, target.game_version.find('+'));
    }
  }
  if (!named)
    return;
  float at[2] = {card[0], card[1] + 150.0f};
  bool pressed = playable && ui_button_update(at, &button);
  if (playable)
    at[0] += 92.0f;
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  if (!note.empty()) {
    if (playable)
      watch_text(at[0], at[1] + 4.0f, note.c_str(), 0.75f, 0.75f, 0.78f, 1.0f);
    else
      watch_text(at[0], at[1] + 4.0f, note.c_str(), 1.0f, 0.5f, 0.5f, 1.0f);
  }
  if (pressed)
    watch_start(target);
}

// The board run whose replay the host fetches into replays/online/<run>.crd.
__attribute__((export_name("game_replay_download"))) const char *game_replay_download() { return watch_download.c_str(); }
// The host's fetch ended: 0 the file is written, 1 the leaderboard no longer
// has the run, 2 it could not be fetched.
__attribute__((export_name("game_replay_downloaded"))) void game_replay_downloaded(int result) {
  if (watch_download.empty())
    return;
  if (result == 0)
    watch_downloads.erase(watch_download);
  else
    watch_downloads[watch_download] = result == 1 ? WATCH_GONE : WATCH_FAILED;
  watch_failed_pin[watch_download] = watch_pins;
  watch_download.clear();
  ++watch_downloads_done;
}

// Plays the replay game_replay_open read, as Watch plays one (a link to a run,
// checks/game_watch.mjs): 0 when it cannot, with a run playing or a replay this
// module cannot play.
__attribute__((export_name("game_watch"))) int game_watch() {
  if (game_live || !replay_loaded.reason.empty() || replay_loaded.recording.empty() || config_blob.screen_width != 1024 ||
      config_blob.screen_height != 768)
    return 0;
  watch_start(replay_loaded);
  return 1;
}
// Where a replay is: -1 none plays, 0 playing, then how it ended: 1 as
// recorded, 2 differently, 3 stopped before its end.
__attribute__((export_name("game_watch_status"))) int game_watch_status() {
  return !live.watching ? -1 : !watch.ended ? 0 : !watch.stopped.empty() ? 3 : watch.played ? 1 : 2;
}
}
