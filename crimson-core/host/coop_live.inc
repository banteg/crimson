// A co-op session inside the running original (docs/rewrite/network-coop.md
// §5): the transport opens it (game_coop_connect) and it lives across the menus
// and the runs. While it is on, the menus show every quest unlocked, and the
// buttons that start a run start a co-op run: the Host's click picks it (the
// Guest's tells the Host which run comes next from an end screen), and both
// machines' screens come to it the way the original starts a run, its fade to
// gameplay, where game_state_set starts the run (coop_start_run). A run plays
// the ranked profile for two players on neither player's save; its end saves
// its replay as the client's runs do, and ranks nowhere yet.
//
// Every pass of the game runs the session (game_coop_pump), whatever the
// screen and with the window in the background too: the partner waits on this
// machine's records. A pass of a run produces this machine's records and runs
// the engine's ticks (host/coop.inc), the newest drawing, as watch and practice
// play theirs; a pass that draws no tick shows the last drawn one again.
//
// The transport talks to the session through host/coop_wire.inc's exports, on
// the clock host_time_ms reads: game_coop_connect when its channels open,
// game_coop_disconnect when they close or the partner leaves the room,
// game_coop_rx and game_coop_receive for each message that arrives, and after
// every pass game_coop_tx on both channels until it has nothing more to send;
// game_coop_status says how the session stands.

// The session goes on: the transport is open and nothing closed it.
static bool coop_on() { return wire.session && !wire.closed; }

static void coop_note(const char *note) {
  coop_live.note = note;
  coop_live.note_at = host_time_ms();
}

// The menus' unlocks: every quest's while the session is on, else the player's.
static void coop_overlay(bool on) {
  if (on == coop_live.overlay)
    return;
  if (on) {
    coop_live.own = {quest_unlock_index, quest_unlock_index_hardcore};
    quest_unlock_index = quest_unlock_index_hardcore = 50;
  } else {
    quest_unlock_index = coop_live.own.normal;
    quest_unlock_index_hardcore = coop_live.own.hardcore;
  }
  coop_live.overlay = on;
}

// The player's menu settings give way to a co-op run's, which its screens read
// (two players' high scores, the quest's results), and come back for the menus.
static void coop_menu_keep() {
  if (coop_live.menu_saved)
    return;
  coop_live.menu = {config_blob.game_mode, config_blob.hardcore, config_blob.player_count, quest_stage_major,
                    quest_stage_minor};
  coop_live.menu_saved = true;
}
static void coop_menu_restore() {
  if (!coop_live.menu_saved)
    return;
  config_blob.game_mode = coop_live.menu.mode;
  config_blob.hardcore = coop_live.menu.hardcore;
  config_blob.player_count = coop_live.menu.player_count;
  quest_stage_major = coop_live.menu.major;
  quest_stage_minor = coop_live.menu.minor;
  coop_live.menu_saved = false;
}

// The screen comes to the run `config` names as the original's start buttons
// bring it: the menu settings name the run, and the fade ends in gameplay.
static void coop_enter_run(const PortableConfig &config) {
  // A replay playing gives way to the run, from the scores it was watched from.
  if (live.watching)
    watch_leave();
  coop_menu_keep();
  config_blob.game_mode = (decltype(config_blob.game_mode))config.mode;
  config_blob.hardcore = (decltype(config_blob.hardcore))config.hardcore;
  config_blob.player_count = 2;
  if (config.mode == GAME_MODE_QUEST) {
    quest_stage_major = (int)config.major;
    quest_stage_minor = (int)config.minor;
  }
  coop_live.next = config;
  coop_live.entering = true;
  coop_live.latched = coop_live.ended = false;
  coop_live.note = nullptr;
  run_active = 0;
  ui_sign_crimson.focus_disabled = 0;
  ui_transition_direction = 0;
  game_state_pending = GAME_STATE_GAMEPLAY;
  music_fade_out_all(music_track_crimson_theme_id);
  music_fade_out_all(music_track_shortie_monk_id);
  music_fade_out_all(music_track_game_playlist);
  screen_fade_ramp_flag = 1;
}

// The Host's choice of run, which starts once the Guest can start one: a fresh
// seed and the ranked profile for two players (ranked_spec).
static void coop_latch(int mode, int major, int minor, int hardcore, int choice) {
  PortableConfig &config = coop_live.next;
  config = {};
  getentropy(&config.seed, sizeof config.seed);
  config.mode = (uint32_t)mode;
  config.major = mode == GAME_MODE_QUEST ? (uint32_t)major : 1;
  config.minor = mode == GAME_MODE_QUEST ? (uint32_t)minor : 1;
  config.hardcore = mode == GAME_MODE_QUEST && hardcore;
  config.players = 2;
  config.preserve_bugs = 0;
  ranked_spec(config);
  coop_live.choice = choice;
  coop_live.latched = true;
}
// The run after the last: the same again (0), or the next quest (1).
static void coop_latch_next(int choice) {
  const PortableConfig &last = coop_live.last;
  int major = (int)last.major, minor = (int)last.minor + (choice == 1);
  if (minor > 10)
    ++major, minor = 1;
  coop_latch((int)last.mode, major, minor, (int)last.hardcore, choice);
}
// The Host's run setup after a failed quest: its quest list, as Play Another
// opens it.
static void coop_setup() {
  ui_transition_direction = 0;
  game_state_pending = GAME_STATE_QUEST_SELECT;
  ui_sign_crimson.focus_disabled = 0;
  music_fade_out_all(music_track_crimson_theme_id);
  music_fade_out_all(music_track_shortie_monk_id);
  music_fade_out_all(music_track_game_playlist);
  music_play_exclusive(music_track_crimson_theme_id);
}

// Back to the main menu with its music: the session ended, or this machine's run
// stopped before its end.
static void coop_to_menu() {
  coop_menu_restore();
  coop_live.ended = coop_live.entering = false;
  run_active = 0;
  game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  music_fade_out_all(music_track_crimson_theme_id);
  music_fade_out_all(music_track_shortie_monk_id);
  music_fade_out_all(music_track_game_playlist);
  music_play_exclusive(music_track_crimson_theme_id);
  ui_elements_timeline = 0;
  game_state_set_recovered(GAME_STATE_MAIN_MENU);
}

// game_state_set brings the screen to gameplay for the run coop_enter_run
// named: the Host starts it (START_RUN) with an input delay from the round
// trip, lockstep; the Guest takes the Host's (START_ACK). The run records as the
// client's runs do. False when it cannot start.
static bool coop_start_run() {
  coop_live.entering = false;
  cfg = coop_live.next;
  double now = host_time_ms();
  bool started;
  if (wire.seat == 0) {
    double rtt = wire.rtt >= 0 ? wire.rtt : COOP_RTT_GUESS_MS;
    int delay = std::clamp((int)ceil(rtt / 2 / COOP_TICK_MS) + 1, 1, COOP_DELAY);
    started = game_coop_request(COOP_ASK_START, delay, 0, coop_live.choice, now);
  } else {
    // The offer stands unless the Host cancelled it or either side left; a
    // config this machine cannot start is a protocol error.
    bool offered = coop_live.offered && !wire.left && !wire.partner_left;
    started = offered && coop_accept(coop_live.delay, coop_live.rmax, coop_live.epoch, now);
    if (offered && !started)
      coop_fail(COOP_BAD_MESSAGE);
    coop_live.offered = false;
  }
  if (!started)
    return false;
  live.replay.clear();
  live.pickers.clear();
  live_append(&cfg, sizeof cfg);
  live.aim_heading = player_state_table[wire.seat].aim_heading;
  coop_live.last = cfg;
  coop_live.playing = true;
  coop_live.banked = 0;
  coop_live.shown = coop_live.choosing = coop_live.escape = false;
  coop_live.ticked_at = host_time_ms();
  return true;
}

// The run is over at the state after its last confirmed tick (`outcome`:
// "death", "quest_completed", or "incomplete" for a run left before its end):
// its replay is saved and its high score record names it. It ranks nowhere yet.
// The engine keeps the run for the session, which still exchanges its last
// hashes, until the next starts.
static void coop_end(const char *outcome) {
  std::vector<uint8_t> payload = replay_payload(outcome);
  int number = replay_save(payload);
  memcpy(highscore_active_record.reserved0, &number, sizeof highscore_active_record.reserved0);
  game_live = game_session = false;
  coop_live.playing = coop_live.choosing = false;
  coop_live.ended = true;
}
// This machine leaves its run before the run's end (another screen, the game
// quits): the partner is told, and the run ends where it was confirmed.
static void coop_quit() {
  game_coop_request(COOP_ASK_LEAVE, 0, 0, 0, host_time_ms());
  coop_end("incomplete");
}

// A START_RUN inside the original: the Guest's screen comes to the run first
// (game_coop_pump), which takes it there.
static void coop_offer(const PortableConfig &config, int delay, int rmax, uint32_t epoch) {
  coop_live.next = config;
  coop_live.delay = delay;
  coop_live.rmax = rmax;
  coop_live.epoch = epoch;
  coop_live.offered = true;
}
// START_CANCEL for the run offered: true when it was.
static bool coop_withdraw(uint32_t epoch) {
  if (!coop_live.offered || epoch != coop_live.epoch)
    return false;
  coop_live.offered = false;
  return true;
}

// game_state_set's screens while a session is on: a fade to gameplay coop_enter_run
// began starts its run (true); the end screen's Main Menu leaves the session; the
// menus show the player's settings; another screen drops the Host's choice, and
// the run it was coming to (the Guest's comes again).
static bool coop_screen_set(game_state_id_t state) {
  bool starts = state == GAME_STATE_GAMEPLAY && !run_active && coop_live.entering;
  if (!starts)
    coop_live.latched = coop_live.entering = false;
  if (coop_live.ended && state == GAME_STATE_MAIN_MENU && coop_on())
    game_coop_request(COOP_ASK_LEAVE, 0, 0, 0, host_time_ms());
  if (state == GAME_STATE_MAIN_MENU || state == GAME_STATE_PLAY_GAME_MENU || state == GAME_STATE_QUEST_SELECT)
    coop_menu_restore();
  coop_live.ended &= state == GAME_STATE_GAME_OVER || state == GAME_STATE_QUEST_RESULTS ||
                     state == GAME_STATE_QUEST_FAILED || state == GAME_STATE_HIGHSCORES ||
                     state == GAME_STATE_FINAL_QUEST_END_NOTE;
  return starts;
}

// What the screen tells the player of the session, or null: in a run, why it
// stopped or waits; in the menus, the Host's run waiting for the Guest, or what
// became of a click.
static const char *coop_line() {
  static char line[64];
  unsigned now = host_time_ms();
  if (!coop_live.playing) {
    if (coop_live.latched)
      return "Waiting for partner";
    return coop_live.note && now - coop_live.note_at < 3000 ? coop_live.note : nullptr;
  }
  uint32_t status = game_coop_status();
  if (status & COOP_DESYNCED) {
    snprintf(line, sizeof line, "Desync at tick %d - Esc leaves", coop.desync.tick);
    return line;
  }
  if (status & COOP_FAILED) {
    snprintf(line, sizeof line, "Co-op error %d - Esc leaves", (int)wire.reason);
    return line;
  }
  if (!coop_on())
    return "Connection lost";
  if (status & COOP_LEAVING)
    return "Leaving the run";
  if (status & COOP_PAUSED)
    return "Paused - Esc resumes";
  // Half a second without a tick: lockstep waits for the partner's records.
  if ((status & COOP_STARTING) || now - coop_live.ticked_at > 500)
    return "Waiting for partner";
  return nullptr;
}
static void coop_draw_line() {
  if (const char *line = coop_line()) {
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    viewer_text(16, viewer_h() - 40, line, 1, 1, 1, 1);
  }
}

// The record of this machine's player for the next tick: its input, or with
// the window in the background no buttons, no movement (or the point-click
// target), its schemes and its last aim.
static PortableInput coop_sample() {
  if (!coop_live.unfocused)
    return live_input(coop.local);
  int move_mode = config_blob.movement_schemes[0], aim_scheme = config_blob.aim_schemes[0];
  const PortableInput &last = coop.records[coop.local][coop.produced & (COOP_RING - 1)].record.input;
  PortableInput input = {0, 0, last.aim_x, last.aim_y,
                         8u | 0x100u | (unsigned)(move_mode & 7) << 9 | 0x1000u | (unsigned)(aim_scheme & 7) << 13};
  if (move_mode == 4) {
    input.move_x = live.move_target_x;
    input.move_y = live.move_target_y;
  }
  return input;
}

// game_live_frame for a co-op run: the presses, and the pass's play time. Every
// pass draws.
static int coop_frame() {
  live_poll();
  coop_live.banked += fminf(grim_frame_dt, 0.1f);
  live.due = (int)(coop_live.banked * 60.0f + 1e-4f);
  return 1;
}

// gameplay_update_and_render for a co-op run: Escape and the perk requests go to
// the session; this machine's records for the pass's ticks, then the ticks the
// engine runs, the newest drawing; once the run reached its last tick, its end.
// A tick that ran pays for its time, and a pass held back keeps at most a few
// ticks' worth, so play resumes without a burst.
static void coop_render() {
  double now = host_time_ms();
  // Escape pauses or resumes; a run stopped (a desync, an error) it leaves.
  if (coop_live.escape) {
    coop_live.escape = false;
    if (coop.hold & COOP_HOLD_STOP) {
      coop_quit();
      return coop_to_menu();
    }
    game_coop_request(COOP_ASK_PAUSE, !wire.paused, 0, 0, now);
  }
  // Starting failed: the Host's partner never answered, or the Host cancelled.
  if (!coop.active) {
    game_live = game_session = coop_live.playing = false;
    return coop_to_menu();
  }
  live_poll_prompt();
  if (live.open_requested)
    game_coop_request(COOP_ASK_OPEN, 0, 0, 0, now);
  live.open_requested = false;
  if (!coop.picking)
    coop_live.choosing = false;
  int due = live.due;
  for (int i = 0; i < due; ++i) {
    coop.scratch[coop.local].input = coop_sample();
    if (game_coop_produce(now) < 0)
      break;
    live.fire_pressed = live.reload_pressed = false;
  }
  int draws = coop.draws;
  int ran = game_coop_advance(due, now);
  if (ran)
    coop_live.ticked_at = host_time_ms();
  coop_live.banked -= ran / 60.0f;
  if (ran < due)
    coop_live.banked = fminf(coop_live.banked, 4.0f / 60.0f);
  if (coop.draws != draws) {
    host_frame_hold(HOST_FRAME_SAVE);
    coop_live.shown = true;
  } else if (coop_live.shown) {
    host_frame_hold(HOST_FRAME_SHOW);
  } else {
    gameplay_render_world();
  }
  if (coop_over()) {
    // The run's last tick: its end screen once that tick is confirmed (the
    // death's or quest's), or the menu when it ended early (a leave, a lost
    // connection).
    bool terminal = run_down_ms < 0;
    game_state_id_t screen = coop.screen.pending;
    coop_end(!terminal ? "incomplete" : screen == GAME_STATE_QUEST_RESULTS ? "quest_completed" : "death");
    if (!terminal)
      return coop_to_menu();
    ui_elements_timeline = 0;
    return game_state_set_recovered(screen);
  }
  // This machine's player picks the perk the open menu offers: the original's
  // perk screen, whose choice (game_live_pick) goes with its next record.
  if (coop.picking && !coop_live.choosing) {
    coop_live.choosing = true;
    live.picked = false;
    coop.scratch[coop.local].cmd = 0;
    return game_state_set_recovered(GAME_STATE_PERK_SELECTION);
  }
  coop_draw_line();
}

extern "C" {
// A pass of the game (game/frame.cpp), whatever its screen: the menus' unlocks
// follow the session; the Host starts the run it chose once the Guest can, and
// takes the Guest's choice of the next; the Guest's screen comes to the run the
// Host started; a session that ended takes its end screens back to the menu.
// True while a session is on.
bool game_coop_pump() {
  // A perk screen whose pick the session no longer takes (a leave) closes as
  // its Cancel does.
  if (coop_live.choosing && !coop.picking && game_state_id == GAME_STATE_PERK_SELECTION &&
      game_state_pending == GAME_STATE_PENDING_IDLE_SENTINEL) {
    ui_transition_direction = 0;
    game_state_pending = GAME_STATE_GAMEPLAY;
  }
  bool on = coop_on();
  coop_overlay(on);
  if (!on) {
    coop_live.latched = coop_live.offered = false;
    if (coop_live.ended)
      coop_to_menu();
    else if (!coop_live.playing && !coop_live.entering)
      coop_menu_restore();
    return false;
  }
  if (coop_live.playing || coop_live.entering)
    return true;
  if (wire.seat == 1) {
    if (coop_live.offered && !wire.left && !wire.partner_left)
      coop_enter_run(coop_live.next);
    return true;
  }
  // The first choice the Host sees wins: its own click, or the Guest's from its
  // end screen, which takes the Host's there too.
  if (wire.next_run >= 0) {
    if (!coop_live.latched && coop_live.ended) {
      if (wire.next_run == 2)
        coop_setup();
      else
        coop_latch_next(wire.next_run);
    }
    wire.next_run = -1;
  }
  if (coop_live.latched && coop_can_start())
    coop_enter_run(coop_live.next);
  return true;
}
// The original's buttons that start a run from the menus (game/changes/coop-run.patch):
// true when the session takes the click. The Host's picks the run; the Guest's
// waits for the Host's. Co-op plays Survival and the stock quests.
bool game_coop_setup_run(int mode, int major, int minor) {
  if (!coop_on())
    return false;
  if (mode != GAME_MODE_SURVIVAL && mode != GAME_MODE_QUEST)
    coop_note("Co-op plays Survival and the quests");
  else if (wire.seat == 1)
    coop_note("The host picks the run");
  else
    coop_latch(mode, major, minor, config_blob.hardcore, 2);
  return true;
}
// An end screen's button that starts the next run (`choice` 0 again, 1 next, 2
// another from the run setup): true when the session takes the click. The
// Guest tells the Host, which starts it; its Play Another opens its quest list
// too. Play Next past the last quest shows the end note, which starts nothing.
bool game_coop_next_run(int choice) {
  if (!coop_on() || !coop_live.ended || (choice == 1 && coop_live.last.major == 5 && coop_live.last.minor == 10))
    return false;
  if (wire.seat == 1) {
    game_coop_request(COOP_ASK_NEXT_RUN, choice, 0, 0, host_time_ms());
    coop_note("Waiting for the host");
    return choice != 2;
  }
  if (choice == 2)
    return false;
  coop_latch_next(choice);
  return true;
}
// The window's focus (game/frame.cpp): with a session on, the game plays on in
// the background, this machine's records neutral, and the presses so far drop.
// True while it plays on.
bool game_coop_focus(int active) {
  coop_live.unfocused = !active;
  if (!active)
    live.fire_down = live.reload_down = live.pick_down = live.fire_pressed = live.reload_pressed =
        live.open_requested = false;
  return coop_on();
}
}
// The menus' line (ui_elements_update_and_render).
static void coop_menus_draw() {
  if (wire.session && !coop_live.playing)
    coop_draw_line();
}
