// A run the client plays: the verifier's session inside the running original.
// The original's menus start the run and its screens follow it; the run itself
// is fixed 60 Hz ticks, each fed the player's input as the replay records it,
// so the recording replays in the verifier exactly as it played
// (portable_step_many). The perk screen and the pause menu run between ticks
// and reach the run only as commands.
//
// The settings, progress and key codes a tick reads are the verifier's
// (portable_init sets them up); between ticks the original shows and keeps the
// player's. What a tick changes carries over: the counters it advances add to
// the player's progress, and the settings it changes replace the player's.
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
extern game_status_t game_status_blob;
extern "C" {
void game_state_set_recovered(game_state_id_t state);
void gameplay_update_and_render_recovered();
extern float grim_frame_dt;
extern int ui_elements_timeline;
extern unsigned char console_open_flag, ui_transition_direction;
int ui_elements_max_timeline(void);
extern cvar_float_t *cv_padAimDistMul, *cv_bodiesFade;
extern float perk_prompt_origin_x, perk_prompt_origin_y, perk_prompt_bounds_min_x, perk_prompt_bounds_min_y,
    perk_prompt_bounds_max_x, perk_prompt_bounds_max_y;
}
// The quests unlocked, which the save takes from these globals (game_save_status).
struct LiveUnlocks {
  int normal, hardcore;
};
struct LiveSettings {
  crimson_cfg_t config;
  game_status_t status;
  LiveUnlocks unlocks;
  float bodies_fade;      // which keeps or removes corpses
  float friendly_fire;    // whether players' shots hit each other
  player_input_t keys[2]; // the codes each player's input reads
};

static struct {
  LiveSettings run;     // the verifier's, between ticks
  LiveSettings outside; // the player's, while a tick runs
  float banked; // seconds of play not yet ticked
  int due;      // ticks this frame
  // Presses since the last tick, which only the next tick sees.
  bool fire_down, reload_down, pick_down, fire_pressed, reload_pressed, open_requested;
  bool click_down; // the left button, as the last pass of play saw it
  bool pausing; // Escape: the timeline runs down to the pause menu
  bool picked;  // the perk menu, once opened, takes one choice
  float move_target_x, move_target_y; // point-click movement's target
  float aim_heading; // where the aim last faced, which a resting pad stick keeps
  PortableCommand queued[16];
  int queued_count;
  game_state_id_t requested; // a state a tick asked for
  std::vector<unsigned char> replay;
  bool watching; // the run plays a replay (watch.inc)
} live;

#include "replay.inc"
#include "ranked.inc"

// Runs a single player plays in Survival, Rush or Quests, at the resolution the
// verifier simulates (1024x768); the rest play as the original.
static bool live_eligible() {
  return game_original && config_blob.player_count == 1 && config_blob.screen_width == 1024 &&
         config_blob.screen_height == 768 &&
         (config_blob.game_mode == GAME_MODE_SURVIVAL || config_blob.game_mode == GAME_MODE_RUSH ||
          config_blob.game_mode == GAME_MODE_QUEST);
}

static void live_append(const void *data, size_t size) {
  live.replay.insert(live.replay.end(), (const unsigned char *)data, (const unsigned char *)data + size);
}

static LiveSettings live_settings() {
  return {config_blob,
          game_status_blob,
          {quest_unlock_index, quest_unlock_index_hardcore},
          cv_bodiesFade->value,
          cv_friendlyFire->value,
          {player_state_table[0].input, player_state_table[1].input}};
}
static void live_install(const LiveSettings &settings) {
  config_blob = settings.config;
  game_status_blob = settings.status;
  quest_unlock_index = settings.unlocks.normal;
  quest_unlock_index_hardcore = settings.unlocks.hardcore;
  cv_bodiesFade->value = settings.bodies_fade;
  cv_friendlyFire->value = settings.friendly_fire;
  for (int i = 0; i < 2; ++i)
    player_state_table[i].input = settings.keys[i];
}
// The run's settings in place of the player's, kept in live.outside. The run
// draws with the player's display choices (direction arrows, detail, the perk
// prompt's hint): the verifier sets none of them (host.cpp), and only drawing
// reads them. A replay's viewer picks no perks, so it shows no hint to.
static void live_enter_run() {
  live.outside = live_settings();
  auto &run = live.run.config;
  const auto &player = live.outside.config;
  memcpy(run.direction_arrow_flags, player.direction_arrow_flags, sizeof run.direction_arrow_flags);
  run.shadows_enabled = player.shadows_enabled;
  run.flame_glow_enabled = player.flame_glow_enabled;
  run.smoke_enabled = player.smoke_enabled;
  run.ui_info_texts = live.watching ? 0 : player.ui_info_texts;
  live_install(live.run);
}
// Word by word, what the tick changed reaches the player's settings: a status
// counter by its increase, anything else by its new value.
template <class T> static void live_carry(const T &before, const T &after, T &player, bool add) {
  auto *b = (const uint32_t *)&before, *a = (const uint32_t *)&after;
  auto *p = (uint32_t *)&player;
  for (size_t i = 0; i < sizeof(T) / 4; ++i)
    if (a[i] != b[i])
      p[i] = add ? p[i] + (a[i] - b[i]) : a[i];
}
// A tick between the verifier's settings.
static int live_step(uint32_t count) {
  live_enter_run();
  int accepted = portable_step_many(count);
  LiveSettings after = live_settings();
  // A replay changes nothing of the player's; a ranked run plays on a detached
  // save, so its progress stays its own.
  if (!live.watching)
    live_carry(live.run.config, after.config, live.outside.config, false);
  if (!live.watching && !ranked_run) {
    live_carry(live.run.status, after.status, live.outside.status, true);
    live_carry(live.run.unlocks, after.unlocks, live.outside.unlocks, false);
  }
  live.run = after;
  live_install(live.outside);
  return accepted;
}

// The session takes the place of the run the original has set up
// (game_state_set), from `cfg`: false when the verifier cannot start it.
static bool live_start() {
  LiveSettings player = live_settings();
  // The console's flag pauses parts of a tick; a run keeps it closed.
  if (console_log_queue.open)
    console_log_queue.console_set_open(0);
  // The run's strings live in the session's arena, which the next run reuses.
  bool heap_strings = game_heap_strings;
  game_heap_strings = false;
  // The end screen offers the name the original set up for the run, which the
  // verifier's setup clears.
  char name[sizeof highscore_active_record.player_name];
  memcpy(name, highscore_active_record.player_name, sizeof name);
  bool ready = portable_init(cfg.seed, cfg.mode, cfg.major, cfg.minor);
  memcpy(highscore_active_record.player_name, name, sizeof name);
  game_heap_strings = heap_strings;
  live.run = live_settings();
  // The verifier keeps corpses (cv_bodiesFade, host.cpp).
  live.run.bodies_fade = 1;
  live_install(player);
  if (!ready) {
    game_session = false;
    return false;
  }
  game_live = true;
  live.banked = 0;
  live.fire_down = live.reload_down = live.pick_down = false;
  live.fire_pressed = live.reload_pressed = live.open_requested = live.pausing = live.picked = false;
  live.move_target_x = live.move_target_y = -1;
  live.aim_heading = player_state_table[0].aim_heading;
  live.queued_count = 0;
  return true;
}

// A run the player plays: seeded afresh, with their progress and settings.
static void live_begin() {
  cfg = {};
  getentropy(&cfg.seed, sizeof cfg.seed);
  cfg.mode = config_blob.game_mode;
  cfg.major = cfg.mode == GAME_MODE_QUEST ? quest_stage_major : 1;
  cfg.minor = cfg.mode == GAME_MODE_QUEST ? quest_stage_minor : 1;
  cfg.unlock = game_status_blob.quest_unlock_index;
  cfg.unlock_full = game_status_blob.quest_unlock_index_hardcore;
  cfg.detail = config_blob.detail_preset;
  cfg.violence = config_blob.violence_disabled;
  cfg.friendly_fire = cv_friendlyFire->value != 0;
  cfg.hardcore = config_blob.hardcore;
  cfg.retry = quest_fail_retry_count;
  cfg.preserve_bugs = 0; // the port's policy: the documented fixes (docs/rewrite/original-bugs.md)
  memcpy(cfg.weapon_usage, game_status_blob.weapon_usage_counts, sizeof cfg.weapon_usage);
  ranked_run = ranked_attempt();
  if (ranked_run)
    ranked_spec(cfg);
  if (!live_start())
    return;
  live.replay.clear();
  live_append(&cfg, sizeof cfg);
}

// The run is over (`outcome`: "death", "quest_completed", or "incomplete" for a
// run left before its end): its replay is saved and its high score record
// names it, and a ranked run the board takes is held for its name.
static void live_end(const char *outcome) {
  std::vector<uint8_t> payload = replay_payload(outcome);
  int number = replay_save(payload);
  memcpy(highscore_active_record.reserved0, &number, sizeof highscore_active_record.reserved0);
  ranked_finish(payload, outcome);
  game_live = game_session = false;
}

// The screens a tick draws name keys by the configuration, which then holds the
// verifier's codes for fire, reload and the perk key (portable_init): they name
// the player's own.
static int game_live_key(int code) {
  if (!game_live || !game_ticking)
    return code;
  const crimson_cfg_t &config = live.outside.config;
  return code == 100   ? config.input_config[0].fire_key
         : code == 101 ? config.key_reload
         : code == 102 ? config.key_pick_perk
                       : code;
}
static bool live_down(int code) { return session_grim.IGrim2D_cpp::grim_is_key_active(code); }
static bool live_down_or_arrow(int code, int arrow) { return live_down(code) || live_down(arrow); }
static float live_axis(int code) { return session_grim.IGrim2D_cpp::grim_get_config_float(code); }

// Every pass of the run loop: presses between ticks reach the next one.
static void live_poll() {
  const player_input_config_t &keys = config_blob.input_config[0];
  bool fire = live_down(keys.fire_key), reload = live_down(config_blob.key_reload),
       pick = live_down(config_blob.key_pick_perk);
  // Escape asks for the pause menu (game_frame_update), also on a pass with no tick.
  if (session_grim.IGrim2D_cpp::grim_was_key_pressed(1)) {
    ui_transition_direction = 0;
    live.pausing = true;
  }
  live.fire_pressed |= fire && !live.fire_down;
  live.reload_pressed |= reload && !live.reload_down;
  // gameplay_update_and_render opens the perk menu on the pick key, Space or
  // keypad plus; a run takes the request as a command.
  live.open_requested |= (pick && !live.pick_down) || session_grim.IGrim2D_cpp::grim_was_key_pressed(57) ||
                         session_grim.IGrim2D_cpp::grim_was_key_pressed(78);
  live.fire_down = fire;
  live.reload_down = reload;
  live.pick_down = pick;
}

// The tick's input as the player's scheme reads it (src/crimson/local_input.py).
static PortableInput live_input() {
  const player_input_config_t &keys = config_blob.input_config[0];
  const player_state_t &player = player_state_table[0];
  int move_mode = config_blob.movement_schemes[0], aim_scheme = config_blob.aim_schemes[0];
  bool forward = live_down_or_arrow(keys.move_key_forward, 0xc8),
       backward = live_down_or_arrow(keys.move_key_backward, 0xd0),
       left = live_down_or_arrow(keys.turn_key_left, 0xcb), right = live_down_or_arrow(keys.turn_key_right, 0xcd);
  float world_x = ui_mouse_x - camera_offset_x, world_y = ui_mouse_y - camera_offset_y;
  PortableInput input = {0, 0, player.aim.x, player.aim.y, 0};
  if (move_mode == 1) { // relative
    input.move_x = (float)right - (float)left;
    input.move_y = (float)backward - (float)forward;
  } else if (move_mode == 2) { // static, in player_update's precedence
    input.move_x = right ? 1.0f : left ? -1.0f : 0.0f;
    if (forward || backward) {
      input.move_x = left ? -1.0f : right ? 1.0f : 0.0f;
      input.move_y = backward ? 1.0f : -1.0f;
    }
  } else if (move_mode == 3) { // dual-action pad
    input.move_x = fminf(fmaxf(live_axis(keys.axis_move_x), -1.0f), 1.0f);
    input.move_y = fminf(fmaxf(live_axis(keys.axis_move_y), -1.0f), 1.0f);
  } else if (move_mode == 4) { // point and click: the reload key drops the target
    if (live_down(config_blob.key_reload)) {
      live.move_target_x = world_x;
      live.move_target_y = world_y;
    }
    input.move_x = live.move_target_x;
    input.move_y = live.move_target_y;
  }
  bool turn_left = false, turn_right = false;
  if (aim_scheme == 0) { // mouse: the world point under the cursor
    input.aim_x = world_x;
    input.aim_y = world_y;
  } else if (aim_scheme == 1) { // keyboard
    turn_left = live_down(keys.aim_key_left);
    turn_right = live_down(keys.aim_key_right);
  } else if (aim_scheme == 3) { // mouse relative: the cursor itself
    input.aim_x = ui_mouse_x;
    input.aim_y = ui_mouse_y;
  } else if (aim_scheme == 4) { // dual-action pad: the stick's reach
    float x = live_axis(keys.axis_aim_x), y = live_axis(keys.axis_aim_y), length = sqrtf(x * x + y * y);
    if (length > 0.2f) {
      // A ranked run's pad reach is the registered default (ranked.py).
      float reach = fminf(length, 1.0f) * (ranked_run ? 96.0f : cv_padAimDistMul->value) + 42.0f;
      input.aim_x = x / length * reach;
      input.aim_y = y / length * reach;
    } else { // original bug 31: a resting stick keeps the aim's direction, 60 units out
      input.aim_x = cosf(live.aim_heading - (float)M_PI_2) * 60.0f;
      input.aim_y = sinf(live.aim_heading - (float)M_PI_2) * 60.0f;
    }
  } else if (aim_scheme == 2 || aim_scheme == -1) { // joystick hat
    int hat = session_grim.IGrim2D_cpp::grim_get_joystick_pov(0);
    turn_left = hat == config_blob.aim_pov_left;
    turn_right = hat == config_blob.aim_pov_right;
  }
  // The pad's aim is an offset from the player; the others are points.
  float facing_x = aim_scheme == 4 ? input.aim_x : input.aim_x - player.position.x,
        facing_y = aim_scheme == 4 ? input.aim_y : input.aim_y - player.position.y;
  if (facing_x * facing_x + facing_y * facing_y > 1e-9f)
    live.aim_heading = atan2f(facing_y, facing_x) + (float)M_PI_2;
  input.flags = (live.fire_down ? 1u : 0) | (live.fire_pressed ? 2u : 0) | (live.reload_pressed ? 4u : 0) |
                8u | (forward ? 16u : 0) | (backward ? 32u : 0) | (left ? 64u : 0) | (right ? 128u : 0) |
                0x100u | (unsigned)(move_mode & 7) << 9 | 0x1000u | (unsigned)(aim_scheme & 7) << 13 |
                (live.reload_down ? 1u << 16 : 0) | (live_down(0x22) ? 1u << 17 : 0) |
                (turn_left ? 1u << 18 : 0) | (turn_right ? 1u << 19 : 0);
  return input;
}

// Whether the verifier takes a perk command now (portable_step_many): not in
// Rush, not once dead, and only with a perk to pick.
static bool live_perk_command_valid() {
  return config_blob.game_mode != GAME_MODE_RUSH && player_state_table[0].health > 0 && perk_pending_count > 0;
}
static void live_queue(PortableCommand command) {
  if (live.queued_count < 16)
    live.queued[live.queued_count++] = command;
}

// The screen's timeline runs by the ticks' time (ui_elements_update_and_render,
// which a tick leaves alone).
static void live_timeline() {
  if (!console_open_flag)
    ui_elements_timeline += ui_transition_direction ? frame_dt_ms : -frame_dt_ms;
  if (ui_elements_timeline > ui_elements_max_timeline())
    ui_elements_timeline = ui_elements_max_timeline();
}

// One recorded tick; false once the run stops ticking this frame. A tick takes
// at most one perk command, judged by the state it starts from: a pick can use
// up the last perk or kill the player (Grim Deal), so the next command waits
// for the next tick, and one the verifier would refuse is dropped, as the
// original ignores it.
static bool live_tick() {
  in = live_input();
  if (live.open_requested)
    live_queue({2, 0});
  uint32_t count = 0;
  while (live.queued_count && !count) {
    if (live_perk_command_valid())
      commands[count++] = live.queued[0];
    memmove(live.queued, live.queued + 1, --live.queued_count * sizeof(PortableCommand));
  }
  live_append(&in, sizeof in);
  live_append(&count, sizeof count);
  live_append(commands, count * sizeof(PortableCommand));
  live.fire_pressed = live.reload_pressed = live.open_requested = false;
  live.requested = GAME_STATE_PENDING_IDLE_SENTINEL;
  if (!live_step(count)) {
    // The run is over: its screen follows, as the timeline would have shown it.
    live.replay.resize(live.replay.size() - sizeof in - sizeof count - count * sizeof(PortableCommand));
    live_end(game_state_pending == GAME_STATE_QUEST_RESULTS ? "quest_completed" : "death");
    ui_elements_timeline = 0;
    game_state_set_recovered(game_state_pending);
    game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
    return false;
  }
  if (live.requested == GAME_STATE_PERK_SELECTION) {
    // The menu is open: requests still queued are spent, and it takes a choice.
    live.picked = false;
    int kept = 0;
    for (int i = 0; i < live.queued_count; ++i)
      if (live.queued[i].type != 2)
        live.queued[kept++] = live.queued[i];
    live.queued_count = kept;
    game_state_set_recovered(GAME_STATE_PERK_SELECTION);
    return false;
  }
  // Escape asked for the pause menu (game_frame_update): the timeline runs down
  // while the run plays on, then the menu opens and the run waits.
  live_timeline();
  if (live.pausing && ui_elements_timeline < 0) {
    ui_elements_timeline = 0;
    live.pausing = false;
    game_state_set_recovered(GAME_STATE_PAUSE_MENU);
    return false;
  }
  return true;
}

#include "keyframes.inc"
#include "watch.inc"

extern "C" {
// game_frame (game/frame.cpp), after polling input: the ticks this pass runs,
// or -1 when no run is playing. A pass with none draws nothing new.
int game_live_frame() {
  watch_follow_link();
  if (!game_live || game_state_id != GAME_STATE_GAMEPLAY)
    return -1;
  if (live.watching)
    return watch_frame();
  live_poll();
  live.banked += fminf(grim_frame_dt, 0.1f);
  live.due = (int)(live.banked * 60.0f + 1e-4f);
  live.banked -= live.due / 60.0f;
  return live.due;
}
// Drawn between ticks too (the perk menu, a paused replay), the world takes a
// guarded weapon away by the quests unlocked: the run's, as its ticks see them.
void gameplay_render_world_recovered();
void gameplay_render_world() {
  if (!game_live || game_ticking)
    return gameplay_render_world_recovered();
  live_enter_run();
  gameplay_render_world_recovered();
  live_install(live.outside);
}
void gameplay_update_and_render() {
  if (!game_live || game_ticking) {
    gameplay_update_and_render_recovered();
    return;
  }
  if (live.watching)
    return watch_render();
  // A click on the perk prompt, where the original laid it out, also asks for
  // the perk menu, with this frame's cursor; a tick never hit-tests it, as the
  // verifier lays out no prompt (game/changes/live-run.patch).
  // A press is the button going down since the last pass of play.
  bool down = session_grim.IGrim2D_cpp::grim_is_mouse_button_down(0) != 0, pressed = down && !live.click_down;
  live.click_down = down;
  float x = ui_mouse_x - perk_prompt_origin_x, y = ui_mouse_y - perk_prompt_origin_y;
  live.open_requested |= pressed && live_perk_command_valid() && x > perk_prompt_bounds_min_x &&
                         y > perk_prompt_bounds_min_y && x < perk_prompt_bounds_max_x && y < perk_prompt_bounds_max_y;
  for (int i = 0; i < live.due && live_tick(); ++i) {
  }
}
// The perk screen's choice (perk_selection_screen_update) reaches the run as a
// command with its next tick.
bool game_live_run() { return game_live; }
// The game quits (game/frame.cpp): an unfinished run still keeps its recording.
void game_live_quit() {
  // A replay's menu settings give way to the player's, which the game saves.
  if (live.watching)
    watch_stop();
  else if (game_live)
    live_end("incomplete");
  ranked_release();
}
bool game_live_pause() {
  live.pausing |= game_live;
  return game_live;
}
char *input_key_name_recovered(int code);
char *input_key_name(int code) { return input_key_name_recovered(game_live_key(code)); }
// One choice per opening: clicks while the menu closes pick nothing, which keeps
// them from spending a perk the pick itself earns on choices never shown.
void game_live_pick(int choice) {
  if (!live.picked)
    live_queue({1, choice});
  live.picked = true;
}
// A run's metadata strings (perks_init_database, bonus_metadata_init) live in
// the session's arena with the rest, which the next run reuses.
char *wrap_text_to_width_alloc_recovered(char *text, int max_width_px);
char *wrap_text_to_width_alloc(char *text, int max_width_px) {
  char *wrapped = wrap_text_to_width_alloc_recovered(text, max_width_px);
  if (game_heap_strings)
    return wrapped;
  char *kept = strdup_malloc(wrapped);
  delete[] wrapped;
  return kept;
}
void game_state_set(game_state_id_t state) {
  if (game_ticking) {
    game_state_pending = state;
    live.requested = state;
    return;
  }
  // Leaving the end screen names the ranked run it held (ranked.inc).
  ranked_release();
  // A replay plays from the run its Watch starts; any other screen drops it.
  bool watches = watch.armed && state == GAME_STATE_GAMEPLAY && !run_active && live_eligible();
  if (watch.armed && !watches)
    watch_disarm();
  // The player's own run comes before a replay a link asked for.
  if ((state == GAME_STATE_GAMEPLAY || state == GAME_STATE_TYPO_GAMEPLAY) && !watches)
    watch.linked = false;
  // A replay stops for any screen; leaving a run for anything but its own
  // screens (the perk menu, and the pause menu with its options) ends it
  // unfinished.
  if (live.watching && state != GAME_STATE_GAMEPLAY)
    watch_stop();
  else if (game_live && state != GAME_STATE_GAMEPLAY && state != GAME_STATE_PERK_SELECTION &&
           state != GAME_STATE_PAUSE_MENU && state != GAME_STATE_OPTIONS_MENU && state != GAME_STATE_CONTROLS_MENU)
    live_end("incomplete");
  bool starts = state == GAME_STATE_GAMEPLAY && !run_active && live_eligible();
  // The run a replay starts counts in none of the player's statistics.
  game_status_t status = game_status_blob;
  game_state_set_recovered(state);
  if (watches) {
    game_status_blob = status;
    watch_begin();
  } else if (starts)
    live_begin();
  if (starts)
    live.banked = 0;
  // Back from a menu, the run picks up where it stopped, without catching up,
  // and the click that left the menu is no press on the perk prompt.
  if (game_live && state == GAME_STATE_GAMEPLAY) {
    live.banked = 0;
    live.click_down = true;
  }
}
// A tick's save would write the verifier's settings; the player's own reach the
// save after it (live_step), with the next one outside a tick.
void game_save_status_recovered();
void game_save_status() {
  if (!game_ticking)
    game_save_status_recovered();
}
__attribute__((export_name("game_replay"))) const unsigned char *game_replay() { return live.replay.data(); }
__attribute__((export_name("game_replay_size"))) int game_replay_size() { return (int)live.replay.size(); }
}
