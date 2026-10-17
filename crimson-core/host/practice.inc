// A replay branch stays on Watch's detached save. Its input is live, but its
// original recording, keyframes and terrain log remain immutable.
enum PracticePhase {
  PRACTICE_NONE,
  PRACTICE_PLAYING,
  PRACTICE_PAUSED,
  PRACTICE_ENDED
};
static struct {
  PracticePhase phase;
  Keyframe anchor;
  int speed, action, xp;
  bool completed;
  bool fire_held; // fire held as play (re)starts, the button's click: let go first
  ui_button_t resume, retry, original;
  char retry_label[48];
} practice;

static void practice_stop() {
  host_frame_hold(HOST_FRAME_ANCHOR_DROP);
  live.practicing = false;
  practice = {};
}
static const char *practice_reason() {
  if (!live.watching || live.practicing)
    return "";
  if (coop_on())
    return "Not during co-op";
  if (watch.phase == WATCH_PREPARING)
    return "Preparing";
  if (watch.seek || viewer.dragging)
    return "Seeking";
  if (player_state_table[0].health <= 0)
    return "Player is dead";
  if (watch.phase == WATCH_ENDED || running_down || run_ended())
    return "Run over";
  return nullptr;
}
// Play starts at once from the frozen frame, aimed where the cursor is.
static void practice_start(bool clear_commands = true) {
  practice.phase = PRACTICE_PLAYING;
  practice.fire_held = live_down(config_blob.input_config[0].fire_key);
  live.banked = 0;
  live.due = 0;
  live.fire_down = live.reload_down = live.pick_down = false;
  live.fire_pressed = live.reload_pressed = live.open_requested = live.pausing =
      false;
  live.click_down = true;
  live.move_target_x = live.move_target_y = -1;
  live.aim_heading = player_state_table[0].aim_heading;
  if (clear_commands)
    live.queued_count = 0;
}
static bool practice_take() {
  if (practice_reason())
    return false;
  practice.anchor = keyframe_capture(watch.tick, watch.at, 0);
  practice.speed = watch.speed;
  practice.xp = survival_xp_smoothed;
  host_frame_hold(HOST_FRAME_ANCHOR_SAVE);
  const ui_button_t plate = {(char *)"", 0, 0, 1, 0, 0, 0, 1.0f, 0, 0};
  practice.resume = practice.retry = practice.original = plate;
  practice.resume.label = (char *)"Resume";
  char time[16];
  viewer_clock(time, sizeof time, watch.tick);
  snprintf(practice.retry_label, sizeof practice.retry_label, "Retry from %s",
           time);
  practice.retry.label = practice.retry_label;
  practice.original.label = (char *)"Watch the original";
  ranked_run = false;
  live.practicing = true;
  practice_start();
  ++play_generation;
  return true;
}
// Re-render the original moment through the proven seek path, then restore the
// exact anchor state. Practice has never appended bakes to the original log.
static void practice_restore() {
  run_restore([] {
    watch.tick = watch.ticks;
    watch_seek(practice.anchor.tick);
    keyframe_restore(practice.anchor);
  });
  watch.tick = practice.anchor.tick;
  watch.at = practice.anchor.at;
  watch.paused = true;
  watch.seek = watch.stop_at = 0;
  game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  survival_xp_smoothed = practice.xp;
  host_frame_hold(HOST_FRAME_ANCHOR_RESTORE);
}
static void practice_return() {
  practice_restore();
  watch.speed = practice.speed;
  practice_stop();
  viewer_reset();
  viewer.down = session_grim.IGrim2D_cpp::grim_is_mouse_button_down(0) != 0;
}
static void practice_end() {
  practice.completed = game_state_pending == GAME_STATE_QUEST_RESULTS;
  practice.phase = PRACTICE_ENDED;
  live.banked = 0;
  live.due = 0;
  game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
}
static int practice_frame() {
  play_time_ms = watch.play_time;
  time_played_ms = watch.time_played;
  int action = practice.action;
  practice.action = 0;
  if (session_grim.IGrim2D_cpp::grim_was_key_pressed(1)) {
    if (practice.phase == PRACTICE_PLAYING)
      practice.phase = PRACTICE_PAUSED;
    else if (practice.phase == PRACTICE_PAUSED)
      action = 1;
    else
      action = 3;
  }
  if (action == 2 || action == 3) {
    // Rebuilding terrain draws: defer it until the frame's rendering pass.
    practice.action = action;
    live.due = 0;
    return 1;
  }
  if (action == 1 && practice.phase == PRACTICE_PAUSED)
    practice_start(false);
  live.due = 0;
  if (practice.phase == PRACTICE_PLAYING) {
    live_poll();
    if (practice.fire_held) {
      practice.fire_held = live.fire_down;
      live.fire_down = live.fire_pressed = false;
    }
    live.banked += fminf(grim_frame_dt, 0.1f);
    live.due = (int)(live.banked * 60.0f + 1e-4f);
    live.banked -= live.due / 60.0f;
  }
  return 1; // paused states still draw their overlay
}
// Play draws only the game; the pause and end menu name the branch.
static void practice_draw() {
  if (practice.phase == PRACTICE_PLAYING)
    return;
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  char time[16], status[96];
  viewer_clock(time, sizeof time, practice.anchor.tick);
  snprintf(status, sizeof status, "Practice - Unranked - from %s", time);
  float corner[2];
  viewer_over_panel(0, corner);
  bool ended = practice.phase == PRACTICE_ENDED;
  if (ended)
    ui_draw_textured_quad((int)(corner[0] - 2), (int)corner[1], 256, 64,
                          practice.completed ? ui_text_well_done_texture
                                             : ui_text_reaper_texture);
  else
    viewer_text(corner[0] + 38, corner[1] + 30, "Practice paused", 1, 1, 1, 1);
  viewer_text(corner[0] + 38, corner[1] + 70, status, 0.8f, 0.85f, 0.9f, 1);
  if (ended) {
    char duration[64];
    snprintf(duration, sizeof duration, "%d seconds played from this moment",
             (int)(tick - practice.anchor.tick) / 60);
    viewer_text(corner[0] + 38, corner[1] + 100, duration, 1, 1, 1, 1);
    viewer_text(corner[0] + 38, corner[1] + 122,
                "Attempt not saved - no scores submitted", 0.8f, 0.8f, 0.8f, 1);
  }
  float at[2] = {corner[0] + 52, corner[1] + 165};
  if (!ended) {
    if (ui_button_update(at, &practice.resume))
      practice.action = 1;
    at[1] += 32;
  }
  if (ui_button_update(at, &practice.retry))
    practice.action = 2;
  at[1] += 32;
  if (ui_button_update(at, &practice.original))
    practice.action = 3;
  ui_cursor_render();
}
static void practice_render() {
  int action = practice.action;
  practice.action = 0;
  if (action == 3) {
    practice_return();
    return watch_render();
  }
  if (action == 2) {
    practice_restore();
    practice_start();
    ++play_generation;
  }
  bool drew = false;
  if (practice.phase == PRACTICE_PLAYING)
    live_poll_prompt();
  terrain.baking = true;
  for (int i = 0; i < live.due && practice.phase == PRACTICE_PLAYING; ++i) {
    unsigned before = tick;
    bool again = live_tick();
    drew |= tick != before;
    if (!again)
      break;
  }
  terrain.baking = false;
  if (drew)
    host_frame_hold(HOST_FRAME_SAVE);
  else
    host_frame_hold(HOST_FRAME_SHOW);
  if (game_state_id == GAME_STATE_GAMEPLAY)
    practice_draw();
}
extern "C" {
void game_live_focus_lost() {
  if (live.practicing && game_state_id == GAME_STATE_GAMEPLAY &&
      practice.phase == PRACTICE_PLAYING)
    practice.phase = PRACTICE_PAUSED;
}
// Host-facing practice controls, also used by the end-to-end branch check.
__attribute__((export_name("game_practice_take"))) int game_practice_take() {
  return practice_take();
}
__attribute__((export_name("game_practice_state"))) int game_practice_state() {
  return (int)practice.phase;
}
__attribute__((export_name("game_practice_ticks"))) int game_practice_ticks() {
  return live.practicing ? (int)tick - practice.anchor.tick : 0;
}
__attribute__((export_name("game_practice_action"))) void
game_practice_action(int action) {
  if (live.practicing && action >= 1 && action <= 3)
    practice.action = action;
}
}
