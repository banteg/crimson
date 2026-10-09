// Watching a replay (docs/rewrite/watch-replays.md, docs/rewrite/replay-viewer.md):
// the high score screen's Watch starts the run its replay recorded, as its Play
// a game starts one, and the session feeds each tick the recording's input and
// commands in place of the player's. Nothing the replay plays reaches the
// player: no setting or progress carries over (live_step), nothing is saved,
// and the menu settings it plays under are put back when it ends. Escape
// returns to the scores.
//
// Before it plays, a preparing pass runs the whole replay undrawn: it keeps a
// keyframe every few seconds and logs every bake into the terrain
// (host/keyframes.inc), so the viewer seeks anywhere, backwards too, and it
// collects the marks the scrub bar shows (Survival's milestone waves, Energizer
// drops, perk picks) and whether the run plays to the result it recorded. While
// it plays, a frame draws only its last tick; the others bake the terrain
// undrawn, and a frame with no tick shows the last drawn one again
// (host_frame_hold) under the viewer (host/viewer.inc).
//
// The replay plays in the one world the game has, so a finished run's end
// screen, which the scores were opened from, is gone once one plays: the
// screen's Back then leaves for the Statistics menu.
#include <algorithm>
#include <deque>
#include <map>
#include <sys/stat.h>
extern "C" {
extern unsigned char run_active, screen_fade_ramp_flag, startup_skip_requested;
extern ui_element_t ui_sign_crimson;
void music_fade_out_all(int sfx_id);
void music_play_exclusive(int sfx_id);
void sfx_entry_stop(sfx_entry_t *entry);
extern music_entry_t music_entry_table[];
extern sfx_volume_table_t music_track_volume;
extern music_fade_out_flags_t music_fade_out_flags;
}

// A perk pick as the menu showed it: when, its choices, the one taken, and the
// level it came with.
struct WatchPick {
  int tick, level, chosen, count, offered[7];
};
// A mark on the scrub bar: a Survival milestone wave (its stage), an Energizer
// drop, or a perk pick (its index in the picks).
enum WatchMarkKind { WATCH_WAVE, WATCH_ENERGIZER, WATCH_PICK };
struct WatchMark {
  int tick;
  WatchMarkKind kind;
  int value;
};
enum WatchPhase { WATCH_PREPARING, WATCH_PLAYING, WATCH_ENDED };
// A tune the run starts playing at a tick (its music track).
struct WatchTune {
  int tick, track;
};

static const float watch_speeds[] = {0.25f, 0.5f, 1, 2, 4, 8, 16, 32};
static constexpr int WATCH_NORMAL_SPEED = 2;
static constexpr int WATCH_SPEEDS = (int)(sizeof watch_speeds / sizeof *watch_speeds);
// A frame's share of the preparing pass, in milliseconds, which keeps the window live.
static constexpr unsigned WATCH_PASS_MS = 28;
// Keyframes start 2 s apart and spread out, every other one dropped, past the budget.
static constexpr int WATCH_KEY_TICKS = 120;
static constexpr size_t WATCH_KEY_BYTES = 256u << 20;
// How long a pick's card shows, in the viewer's seconds.
static constexpr float WATCH_PICK_SECONDS = 3;

// A run's score card, as the high score screen draws it, and its rank there.
struct WatchCard {
  highscore_record_t record;
  int rank;
};

static struct {
  bool linked;         // a host asked for `link` (game_watch): it plays once the screen settles
  LoadedReplay link;
  WatchCard link_card;
  bool armed;          // Watch was pressed: the next run started plays `replay`
  LoadedReplay replay; // its own copy: the host can read another meanwhile
  WatchCard run;       // and its card
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
  WatchPhase phase;
  size_t at;       // the next tick's place in the recording
  int tick, ticks; // ticks played, and the run's: the recording's, or up to a refused tick
  int speed;       // in watch_speeds
  bool paused, step;
  int seek;            // a tick the viewer asked for (from 1), or 0
  std::string stopped; // why it stops before the recording's end
  bool played;         // the run ends as it recorded
  std::vector<Keyframe> keys;
  int key_ticks; // keyframe spacing
  size_t key_bytes;
  std::vector<WatchPick> picks;
  std::vector<WatchMark> marks;
  std::vector<WatchTune> tunes; // the tunes the run starts, which a seek plays (watch_tune)
  int stage;              // the Survival spawn stage before the tick (the pass)
  bool energizer[16];     // bonus slots holding an Energizer before the tick (the pass)
  size_t next_pick;       // the first pick still ahead of playback
  int card;               // the pick the card shows, or -1
  float card_left;        // the card's seconds
  bool drawn;             // a tick drew this frame
  float mouse_x, mouse_y; // the viewer's cursor, which ticks replace with the replay's aim
  bool leave;             // the end screen's High scores, taken at the next pass
  int stop_at;           // playback pauses on reaching this tick (game_watch_stop_at), or 0
} watch;

// A tick the viewer asks for, from the first.
static void watch_ask(int at) { watch.seek = std::max(1, at); }

// A board run's card, from its replay's result, under the name, rank and date
// the host gives (a link to the run): the record the original would have kept.
static WatchCard watch_card(const LoadedReplay &replay, const char *name, int rank, int day, int month, int year) {
  PortableConfig recorded;
  memcpy(&recorded, replay.recording.data(), sizeof recorded);
  highscore_record_t record = {};
  snprintf(record.player_name, sizeof record.player_name, "%s", name);
  record.run_elapsed_ms = (unsigned)(replay.outcome == "quest_completed" ? replay.quest_final_ms : replay.elapsed_ms);
  record.score_xp = (unsigned)replay.experience;
  record.game_mode_id = (unsigned char)recorded.mode;
  record.quest_stage_major = (unsigned char)recorded.major;
  record.quest_stage_minor = (unsigned char)recorded.minor;
  // A weapon the table has: the card looks its name and icon up there.
  size_t weapons = sizeof(weapon_storage_table_t) / sizeof(weapon_storage_entry_t);
  record.most_used_weapon_id = (unsigned char)((uint64_t)replay.most_used_weapon_id < weapons ? replay.most_used_weapon_id : 0);
  record.shots_fired = (unsigned)replay.shots_fired;
  record.shots_hit = (unsigned)replay.shots_hit;
  record.creature_kill_count = (unsigned)replay.kills;
  record.day = (unsigned char)day;
  record.month = (unsigned char)month;
  record.year_offset = (unsigned char)(year > 2000 ? year - 2000 : 0);
  record.flags = 1; // "Score from the Internet"
  return {record, rank};
}

#include "viewer.inc"

// The replay's run is the menu's: its mode, quest and difficulty, one player.
// Watch pressed again before the run starts keeps the player's menu settings.
static void watch_arm(const LoadedReplay &replay, const WatchCard &card) {
  watch.replay = replay;
  watch.run = card;
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
static void watch_start(const LoadedReplay &replay, const WatchCard &card) {
  watch_arm(replay, card);
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

static void watch_keep() {
  if (watch.phase == WATCH_PREPARING)
    terrain_shoot(watch.tick);
  watch.keys.push_back(keyframe_capture(watch.tick, watch.at, terrain.batches.size()));
  watch.key_bytes += watch.keys.back().packed.size();
  // Past the budget, every other keyframe goes and the spacing doubles.
  while (watch.key_bytes > WATCH_KEY_BYTES && watch.keys.size() > 2) {
    std::vector<Keyframe> kept;
    watch.key_bytes = 0;
    for (size_t i = 0; i < watch.keys.size(); i += 2) {
      watch.key_bytes += watch.keys[i].packed.size();
      kept.push_back(std::move(watch.keys[i]));
    }
    watch.keys = std::move(kept);
    watch.key_ticks *= 2;
  }
}

static void watch_leave();
static void watch_begin() {
  watch.armed = false;
  watch.play_time = play_time_ms;
  watch.time_played = time_played_ms;
  memcpy(&cfg, watch.replay.recording.data(), sizeof cfg);
  ranked_run = false;
  terrain_reset();
  if (!live_start())
    return watch_leave();
  live.watching = true;
  watch.phase = WATCH_PREPARING;
  watch.at = sizeof cfg;
  watch.tick = watch.ticks = 0;
  watch.speed = WATCH_NORMAL_SPEED;
  watch.paused = watch.step = watch.played = false;
  watch.stopped.clear();
  watch.keys.clear();
  watch.key_ticks = WATCH_KEY_TICKS;
  watch.key_bytes = 0;
  watch.picks.clear();
  watch.marks.clear();
  watch.tunes.clear();
  watch.stage = survival_spawn_stage;
  for (int i = 0; i < 16; ++i)
    watch.energizer[i] = bonus_pool[i].bonus_id == BONUS_ID_ENERGIZER;
  watch.card = -1;
  watch.next_pick = 0;
  viewer_reset();
  watch_keep();
  terrain.logging = true;
}
// The ticks playback runs this frame, short of a tick it stops at.
static int watch_due(int due) {
  if (watch.stop_at > watch.tick && watch.tick + due >= watch.stop_at) {
    watch.paused = true;
    return watch.stop_at - watch.tick;
  }
  return due;
}

// The replay stops, and the menu settings are the player's again.
static void watch_stop() {
  if (live.watching) {
    play_time_ms = watch.play_time;
    time_played_ms = watch.time_played;
  }
  live.watching = false;
  terrain.logging = terrain.baking = false;
  game_live = game_session = false;
  watch_disarm();
  watch.keys.clear();
  watch.keys.shrink_to_fit();
  watch.seek = watch.stop_at = 0;
  terrain_reset();
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

// The pass reached the run's end: the recording ran out, or a tick of it was
// refused (`stopped`). A run that played to its end, or to where it was left,
// ends with the result recorded.
static void watch_judge(const char *stopped) {
  watch.ticks = watch.tick;
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

// The pass's marks for the tick just played.
static void watch_mark(int chosen, int choices) {
  if (chosen >= 0) {
    WatchPick pick = {watch.tick, player_state_table[0].level, chosen, choices, {}};
    memcpy(pick.offered, perk_choice_ids, choices * sizeof(int));
    watch.marks.push_back({watch.tick, WATCH_PICK, (int)watch.picks.size()});
    watch.picks.push_back(pick);
  }
  if (survival_spawn_stage != watch.stage)
    watch.marks.push_back({watch.tick, WATCH_WAVE, survival_spawn_stage});
  watch.stage = survival_spawn_stage;
  for (int i = 0; i < 16; ++i) {
    bool energizer = bonus_pool[i].bonus_id == BONUS_ID_ENERGIZER && !bonus_pool[i].picked;
    if (energizer && !watch.energizer[i])
      watch.marks.push_back({watch.tick, WATCH_ENERGIZER, i});
    watch.energizer[i] = energizer;
  }
}

// One recorded tick; false once the run has no more (the pass judges it).
static bool watch_tick() {
  const std::vector<uint8_t> &recording = watch.replay.recording;
  if (watch.phase == WATCH_PREPARING ? watch.at >= recording.size() : watch.tick >= watch.ticks)
    return false;
  uint32_t count;
  memcpy(&in, &recording[watch.at], sizeof in);
  memcpy(&count, &recording[watch.at + sizeof in], sizeof count);
  memcpy(commands, &recording[watch.at + sizeof in + sizeof count], count * sizeof(PortableCommand));
  // The menu's choices, as portable_step_many counts them, before the pick can
  // add one (Perk Expert, Perk Master); of a tick's picks, the card shows the last.
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
    watch_judge(stopped);
    return false;
  }
  watch.at += sizeof in + sizeof count + count * sizeof(PortableCommand);
  ++watch.tick;
  if (watch.phase == WATCH_PREPARING)
    watch_mark(chosen, choices);
  live_timeline();
  if (ui_elements_timeline < 0)
    ui_elements_timeline = 0;
  return true;
}

// Ticks nobody hears (the preparing pass, a seek) start no sound, and the music
// plays on as it was: they still pick the in-game tune as the run did (the
// playlist latch and its random draw are the run's), but the tracks' volumes
// and fades, which the music calls set, come back after them.
struct WatchUnheard {
  bool unheard; // the outermost of nested passes keeps the music
  sfx_volume_table_t volume;
  music_fade_out_flags_t fades;
  explicit WatchUnheard(bool quiet) : unheard(quiet && !sound_unheard) {
    if (!unheard)
      return;
    memcpy(volume, music_track_volume, sizeof volume);
    memcpy(fades, music_fade_out_flags, sizeof fades);
    sound_unheard = true;
  }
  ~WatchUnheard() {
    if (!unheard)
      return;
    memcpy(music_track_volume, volume, sizeof volume);
    memcpy(music_fade_out_flags, fades, sizeof fades);
    sound_unheard = false;
  }
};

// The tune playing: the track a music call started and none faded since, or -1.
static int watch_playing() {
  for (int track = 0; track < 128; ++track)
    if (!music_fade_out_flags[track] && music_track_volume[track] > 0)
      return track;
  return -1;
}
extern "C" {
void music_play_exclusive_recovered(int sfx_id);
// The run's music calls (the first hit's in-game tune, the game over tune), as
// the original makes them; the preparing pass notes the tune each one picks,
// whatever plays: the in-game tune is the playlist's entry the call's random
// draw chose, drawn again from where the stream stood.
void music_play_exclusive(int sfx_id) {
  uint32_t stream = rng;
  unsigned char latched = music_playlist_randomized_latch;
  music_play_exclusive_recovered(sfx_id);
  if (!live.watching || watch.phase != WATCH_PREPARING)
    return;
  int track = sfx_id;
  if (sfx_id == music_track_game_playlist) {
    if (latched || !music_playlist_randomized_latch)
      return;
    uint32_t after = rng;
    rng = stream;
    track = music_playlist[crt_rand() % music_playlist_entry_count];
    rng = after;
  }
  if (watch.tunes.empty() || watch.tunes.back().track != track)
    watch.tunes.push_back({watch.tick + 1, track});
}
}
// After a seek, the tune the run has there: the one it last started, or before
// the first, an in-game tune already playing (a scrub back keeps it) and none
// other. The music calls clear the run's playlist latch, which stays the run's.
static void watch_tune() {
  auto next = std::upper_bound(watch.tunes.begin(), watch.tunes.end(), watch.tick,
                               [](int t, const WatchTune &tune) { return t < tune.tick; });
  int want = next == watch.tunes.begin() ? -1 : (next - 1)->track, playing = watch_playing();
  if (want == playing)
    return;
  bool in_game = std::find(music_playlist, music_playlist + music_playlist_entry_count, playing) !=
                 music_playlist + music_playlist_entry_count;
  if (want < 0 && (playing < 0 || in_game))
    return;
  unsigned char latch = music_playlist_randomized_latch;
  if (want < 0)
    music_fade_out_all(playing);
  else {
    music_play_exclusive_recovered(want);
    // A tune still fading out (scrubbing back from just after the death) comes
    // back up, which the call leaves to one that has stopped.
    if (music_track_volume[want] > 0)
      music_fade_out_flags[want] = 0;
  }
  music_playlist_randomized_latch = latch;
}

// `count` ticks, at most to the run's end, drawing only the last; a quiet run
// (a seek) is unheard. The terrain takes every tick's bake.
static int watch_run(int count, bool quiet) {
  count = std::min(count, watch.ticks - watch.tick);
  WatchUnheard unheard(quiet);
  terrain.baking = true;
  int ran = 0;
  for (; ran < count; ++ran) {
    grim_render_disabled = ran + 1 < count;
    if (!watch_tick())
      break;
  }
  grim_render_disabled = 0;
  terrain.baking = false;
  // The last tick drew unless the run ended first.
  if (ran > 0 && ran == count)
    watch.drawn = true;
  return ran;
}

// Playback goes to `target` (a tick count from the start, at least one, so a
// tick draws): forward from where it is when no keyframe is nearer, else from
// the nearest keyframe before it, with the terrain rebuilt to it.
static void watch_seek(int target) {
  target = std::max(1, std::min(target, watch.ticks));
  auto key = std::upper_bound(watch.keys.begin(), watch.keys.end(), target - 1,
                              [](int t, const Keyframe &k) { return t < k.tick; }) -
             1;
  if (watch.tick >= target || watch.tick < key->tick) {
    terrain_rebuild(key->batches);
    keyframe_restore(*key);
    watch.tick = key->tick;
    watch.at = key->at;
  }
  watch_run(target - watch.tick, true);
  watch_tune();
  watch.next_pick = std::upper_bound(watch.picks.begin(), watch.picks.end(), watch.tick,
                                     [](int t, const WatchPick &p) { return t < p.tick; }) -
                    watch.picks.begin();
  watch.card = -1;
  viewer.card = 0;
  watch.phase = watch.tick >= watch.ticks ? WATCH_ENDED : WATCH_PLAYING;
  if (watch.stop_at && watch.tick == watch.stop_at)
    watch.paused = true;
}

// A frame's share of the preparing pass; at the run's end, playback starts.
static void watch_prepare() {
  grim_render_disabled = 1;
  // The pass bakes the terrain as it goes, for the copies it keeps.
  terrain.baking = true;
  unsigned start = host_time_ms();
  bool done = false;
  {
    WatchUnheard unheard(true);
    for (int n = 1;; ++n) {
      if (!watch_tick()) {
        done = true;
        break;
      }
      if (watch.tick % watch.key_ticks == 0)
        watch_keep();
      if (n % 64 == 0 && host_time_ms() - start >= WATCH_PASS_MS)
        break;
    }
  }
  grim_render_disabled = 0;
  terrain.baking = false;
  if (!done)
    return;
  if (watch.stopped.empty() && watch.at >= watch.replay.recording.size())
    watch_judge("");
  terrain.logging = false;
  watch.phase = WATCH_PLAYING;
  // A host may have asked for a tick meanwhile (game_watch_seek).
  watch_seek(watch.seek ? watch.seek : 1);
  watch.seek = 0;
}

// The replay a host asked for starts on a menu once it has come in whole and
// stays, with no run of the player's and no Watch of the screen's own under way.
static bool watch_on_menu() {
  switch (game_state_id) {
  case GAME_STATE_MAIN_MENU:
  case GAME_STATE_PLAY_GAME_MENU:
  case GAME_STATE_OPTIONS_MENU:
  case GAME_STATE_CONTROLS_MENU:
  case GAME_STATE_STATISTICS_MENU:
  case GAME_STATE_HIGHSCORES:
  case GAME_STATE_QUEST_SELECT:
  case GAME_STATE_WEAPON_DATABASE:
  case GAME_STATE_PERK_DATABASE:
  case GAME_STATE_CREDITS:
    return true;
  default:
    return false;
  }
}
// A link skips the intro, as a click does (game_startup_init), and starts as
// the menu comes in after it, cutting straight to the replay.
static void watch_follow_link() {
  if (!watch.linked)
    return;
  startup_skip_requested = 1;
  if (!game_live && !run_active && !watch.armed && watch_on_menu() && ui_transition_direction &&
      ui_elements_max_timeline() > 0 && ui_elements_timeline > 0) {
    watch.linked = false;
    watch_start(watch.link, watch.link_card);
    ui_elements_timeline = 0;
    // The menu's theme, which the skipped intro started, stops at once: the link
    // cut the menu, and the theme's fade would play over the preparing pass.
    music_track_volume[music_track_crimson_theme_id] = 0;
    sfx_entry_stop(&music_entry_table[music_track_crimson_theme_id]);
  }
}

// game_live_frame for a replay: the viewer's keys. Every pass draws, so the
// viewer follows the cursor; Escape leaves.
static int watch_frame() {
  auto pressed = [](int key) { return session_grim.IGrim2D_cpp::grim_was_key_pressed(key) != 0; };
  // Escape: the scores show from the next pass, which their own Escape would
  // otherwise take as well.
  if (pressed(1) || watch.leave) {
    watch.leave = false;
    watch_leave();
    return 0;
  }
  // The frame counts a run's time as played (game_frame_update): a replay's
  // never adds up.
  play_time_ms = watch.play_time;
  time_played_ms = watch.time_played;
  if (watch.phase == WATCH_PREPARING)
    return 1;
  int second = 60;
  if (pressed(57)) // Space: pause, or from the end, play again
    watch.phase == WATCH_ENDED ? (void)(watch_ask(1), watch.paused = false) : (void)(watch.paused = !watch.paused);
  if (pressed(0x34) && watch.paused) // period: a tick on
    watch.step = true;
  if (pressed(0x33) && watch.paused) // comma: a tick back
    watch_ask(watch.tick - 1);
  if (pressed(0x1a)) // [
    watch.speed = std::max(watch.speed - 1, 0);
  if (pressed(0x1b)) // ]
    watch.speed = std::min(watch.speed + 1, WATCH_SPEEDS - 1);
  if (pressed(0x02)) // 1
    watch.speed = WATCH_NORMAL_SPEED;
  if (pressed(0xcb)) // Left
    watch_ask(watch.tick - 5 * second);
  if (pressed(0xcd)) // Right
    watch_ask(watch.tick + 5 * second);
  if (pressed(0xc9)) // Page Up
    watch_ask(watch.tick - 30 * second);
  if (pressed(0xd1)) // Page Down
    watch_ask(watch.tick + 30 * second);
  if (pressed(0xc7)) // Home
    watch_ask(1);
  if (pressed(0xcf)) // End
    watch_ask(watch.ticks);
  return 1;
}

// gameplay_update_and_render for a replay: the frame's ticks, or the viewer's
// seek, then the viewer over the last drawn frame.
static void watch_render() {
  watch.mouse_x = ui_mouse_x;
  watch.mouse_y = ui_mouse_y;
  watch.drawn = false;
  float dt = fminf(grim_frame_dt, 0.1f);
  if (watch.phase == WATCH_PREPARING)
    watch_prepare();
  else {
    viewer_update(dt);
    if (watch.seek) {
      watch_seek(watch.seek);
      watch.seek = 0;
    } else if (watch.phase == WATCH_PLAYING && (!watch.paused || watch.step)) {
      int due = 1;
      if (!watch.paused) {
        live.banked += dt * watch_speeds[watch.speed];
        due = (int)(live.banked * 60.0f + 1e-4f);
        live.banked -= due / 60.0f;
      }
      int from = watch.tick;
      due = watch_due(due);
      if (due)
        watch_run(due, false);
      // The card shows the last pick playback passed.
      while (watch.next_pick < watch.picks.size() && watch.picks[watch.next_pick].tick <= watch.tick) {
        if (watch.picks[watch.next_pick].tick > from) {
          watch.card = (int)watch.next_pick;
          watch.card_left = WATCH_PICK_SECONDS;
        }
        ++watch.next_pick;
      }
      if (watch.tick >= watch.ticks)
        watch.phase = WATCH_ENDED;
    }
    watch.step = false;
  }
  // Ticks put the replay's aim on the cursor: the viewer's comes back.
  ui_mouse_x = watch.mouse_x;
  ui_mouse_y = watch.mouse_y;
  if (watch.drawn)
    host_frame_hold(HOST_FRAME_SAVE);
  else if (watch.phase != WATCH_PREPARING)
    host_frame_hold(HOST_FRAME_SHOW);
  viewer_draw(dt);
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
      viewer_text(at[0], at[1] + 4.0f, note.c_str(), 0.75f, 0.75f, 0.78f, 1.0f);
    else
      viewer_text(at[0], at[1] + 4.0f, note.c_str(), 1.0f, 0.5f, 0.5f, 1.0f);
  }
  // The screen's card is the table's row.
  if (pressed)
    watch_start(target, {*record, (int)(record - highscore_table) + 1});
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
// checks/game_watch.mjs), once a menu comes in (watch_follow_link): until then
// the startup sequence, which it cuts short, sets up its own screens. A run the player starts
// meanwhile drops it. 0 when it cannot, with a run playing or a replay this
// module cannot play.
//
// Its card names the runner (game_watch_name, which the host fills first) with
// the board's rank and the day the board took the run.
static char watch_name[32];
__attribute__((export_name("game_watch_name"))) char *game_watch_name() { return watch_name; }
__attribute__((export_name("game_watch"))) int game_watch(int rank, int day, int month, int year) {
  if (game_live || !replay_loaded.reason.empty() || replay_loaded.recording.empty() || config_blob.screen_width != 1024 ||
      config_blob.screen_height != 768)
    return 0;
  watch.link = replay_loaded;
  watch.link_card = watch_card(replay_loaded, watch_name, rank, day, month, year);
  watch.linked = true;
  return 1;
}
// Where playback is and the run's length, in ticks (0 until the replay is
// prepared); a tick to go to, and one to pause on reaching, as the viewer's
// seeks and a link to a moment use them.
__attribute__((export_name("game_watch_tick"))) int game_watch_tick() { return watch.tick; }
__attribute__((export_name("game_watch_ticks"))) int game_watch_ticks() { return watch.ticks; }
__attribute__((export_name("game_watch_seek"))) void game_watch_seek(int at) { watch_ask(at); }
__attribute__((export_name("game_watch_stop_at"))) void game_watch_stop_at(int at) { watch.stop_at = at; }
// Where a replay is: -1 none plays, 0 playing, then how it ended: 1 as
// recorded, 2 differently, 3 stopped before its end.
__attribute__((export_name("game_watch_status"))) int game_watch_status() {
  return !live.watching ? -1 : watch.phase != WATCH_ENDED ? 0 : !watch.stopped.empty() ? 3 : watch.played ? 1 : 2;
}
}
