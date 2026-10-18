// A co-op session inside the running original (docs/rewrite/network-coop.md
// §5): the transport opens it (game_coop_connect) and it lives across the menus
// and the runs. The page tells the game too when it holds a seat in a co-op
// room (game_coop_in_room): before the partner's game connects, while it
// reconnects, between sessions. While co-op is open, a session or a room, the
// menus show every quest unlocked; in a room without a session the buttons that
// start a run start nothing, and say the run waits for the partner. In a
// session they start a co-op run: the Host's click picks it (the
// Guest's tells the Host which run comes next from an end screen), and both
// machines' screens come to it the way the original starts a run, its fade to
// gameplay, where game_state_set starts the run (coop_start_run). A run plays
// the ranked profile for two players on neither player's save; its end saves
// its replay as the client's runs do, and ranks once the room attested it and
// both players signed it (host/coop_ranked.inc). The next run waits for both
// end screens to pass their name entries (RUN_SIGNED), and a run
// comes to no screen while it changes, so a click that leaves the end screen
// (Main Menu is Leave) wins over a run that arrives after it. A run of the
// player's own, playing as the session or the room opened (any mode, the
// tutorial too), plays out on the player's own save first.
//
// Every pass of the game runs the session (game_coop_pump), whatever the
// screen and with the window in the background too: the partner waits on this
// machine's records. A pass of a run produces this machine's records and runs
// the engine's ticks (host/coop.inc), the newest drawing, as watch and practice
// play theirs; a pass that draws no tick shows the last drawn one again. Over
// it go the replay viewer's dim bands (host/viewer.inc): the pause and a stopped
// run's banner, the partner's perk pick, and why the run waits; the menus show
// a line on the session.
//
// The transport talks to the session through host/coop_wire.inc's exports, on
// the clock host_time_ms reads: game_coop_connect when its channels open,
// game_coop_disconnect when they close or the partner leaves the room,
// game_coop_rx and game_coop_receive for each message that arrives, and after
// every pass game_coop_tx on both channels until it has nothing more to send;
// game_coop_status says how the session stands.

// The session goes on: the transport is open and nothing closed it.
static bool coop_on() { return wire.session && !wire.closed; }
// Co-op is open: a session, or a seat in a room that waits for one.
static bool coop_open() { return coop_on() || coop_live.room >= 0; }
// What a run's start waits for in a room without a session: the partner.
static const char *coop_waiting() { return coop_live.room == 0 ? "Co-op: waiting for Player 2" : "Co-op: waiting for Player 1"; }

// What the session shows over a run and the menus.
static struct {
  bool was_on;     // the session was on, last pass
  bool banner;     // a banner with buttons showed, last pass (game/pad.cpp steps its focus)
  bool asked_next; // the Guest's next-run choice went to the Host, whose run has yet to come
  bool fire_held;  // fire held as play resumes under a banner: let go first
  ui_button_t resume, leave;
  // The partner's perk menu on the card (viewer_card): its offers from the
  // tick that opened it (pick.tick), its picker, and the choice once the next
  // tick took it.
  bool card, picking;
  WatchPick pick;
  float left; // the card's seconds, once picked
} coop_ui;

static constexpr unsigned COOP_NOTE_MS = 5000;
static void coop_note(const char *note) {
  coop_live.note = note;
  coop_live.note_at = host_time_ms();
}
// Why the session or its run stopped, for the player, or null (this machine
// left, or nothing stopped).
static const char *coop_why() {
  static char line[64];
  int partner = 2 - wire.seat;
  if (coop_running() && coop.desync.tick >= 0) {
    snprintf(line, sizeof line, "Desync at tick %d", coop.desync.tick);
    return line;
  }
  switch (wire.reason) {
  case COOP_VERSION:
    return "The other player has another version of the game";
  case COOP_BAD_RECORD:
    return "Co-op error: an input no player could make";
  case COOP_BAD_MESSAGE:
    return "Co-op error: a message no game sends";
  case COOP_STALLED:
  case COOP_SILENT:
  case COOP_DISCONNECTED:
    return "The connection was lost";
  case COOP_UNANSWERED:
    snprintf(line, sizeof line, "Player %d did not start the run", partner);
    return line;
  case COOP_PARTNER_LEFT:
  case COOP_PARTNER_GONE:
    snprintf(line, sizeof line, "Player %d left", partner);
    return line;
  case COOP_DIVERGED:
    return "The two games ran differently";
  default:
    return nullptr;
  }
}

// This machine's player is busy with a run of its own, whatever its mode and
// however it plays (as the client's runs, as the original's, practice; not a
// replay, which gives way, and not co-op's): one that played as the session or
// the room opened, or that the screen fades to then. It plays on the player's
// own save and keeps the window's focus as alone; the session's unlocks and runs
// wait for it, and for its end screen's name entry (coop_live.naming). Its
// setup reads the menus' unlocks (the weapons and perks it hands out), so the
// fade is busy too.
static bool coop_busy() {
  if (coop_live.playing || (live.watching && !live.practicing))
    return false;
  if (!coop_live.entering &&
      (game_state_pending == GAME_STATE_GAMEPLAY || game_state_pending == GAME_STATE_TYPO_GAMEPLAY))
    return true;
  switch (game_state_id) {
  case GAME_STATE_GAMEPLAY:
  case GAME_STATE_TYPO_GAMEPLAY:
  case GAME_STATE_PERK_SELECTION:
  case GAME_STATE_PAUSE_MENU:
  case GAME_STATE_OPTIONS_MENU:
  case GAME_STATE_CONTROLS_MENU:
    return run_active;
  default:
    return false;
  }
}
// The screen shows the end of a co-op run whose session ended: it closed, or
// another began.
static bool coop_gone() { return coop_live.ended && (!coop_on() || coop_live.session != wire.nonce); }
// Co-op plays Survival and the stock quests.
static bool coop_playable(int mode, int major, int minor) {
  return mode == GAME_MODE_SURVIVAL ||
         (mode == GAME_MODE_QUEST && major >= 1 && major <= 5 && minor >= 1 && minor <= 10);
}

// The menus' unlocks: every quest's while co-op is open, else the player's.
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
  coop_live.menu = menu_shown();
  coop_live.menu_saved = true;
}
static void coop_menu_restore() {
  if (!coop_live.menu_saved)
    return;
  menu_install(coop_live.menu);
  coop_live.menu_saved = false;
}

// The screen comes to the run `config` names as the original's start buttons
// bring it: the menu settings name the run, and the fade ends in gameplay. The
// end screen it leaves stays the last run's until the run starts: its Main Menu
// still leaves.
static void coop_enter_run(const PortableConfig &config) {
  // A replay playing gives way to the run, from the scores it was watched from;
  // a replay's or a custom quest's menu settings give way to the player's,
  // which the co-op run's take the place of.
  if (live.watching)
    watch_leave();
  if (watch.armed)
    watch_disarm();
  custom_quest_restore();
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
  coop_live.entered = wire.nonce;
  coop_live.latched = false;
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
// seed, which the room's takes the place of (coop_seeded), and the ranked
// profile for two players (ranked_spec).
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
// The quest after `major`.`minor`.
static void coop_next_quest(int &major, int &minor) {
  if (++minor > 10)
    ++major, minor = 1;
}
// The run after the last: the same again (0), or the next quest (1).
static void coop_latch_next(int choice) {
  const PortableConfig &last = coop_live.last;
  int major = (int)last.major, minor = (int)last.minor;
  if (choice == 1)
    coop_next_quest(major, minor);
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
  coop_live.ended = coop_live.entering = coop_live.naming = false;
  run_active = 0;
  game_state_pending = GAME_STATE_PENDING_IDLE_SENTINEL;
  music_fade_out_all(music_track_crimson_theme_id);
  music_fade_out_all(music_track_shortie_monk_id);
  music_fade_out_all(music_track_game_playlist);
  music_play_exclusive(music_track_crimson_theme_id);
  ui_elements_timeline = 0;
  game_state_set_recovered(GAME_STATE_MAIN_MENU);
}

// A co-op run's input delay and window (§1, §3.3): the run runs up to eight
// ticks past the last confirmed one on predictions (COOP_LATE_RMAX late in a
// long Survival run, host/coop.inc), and each machine's records go at least two
// ticks ahead of its run, more when the narrowed window alone would not cover a
// one-way trip of the round trip measured: the partner's records would come
// past it, and both runs would wait for them all the while.
static constexpr int COOP_RUN_DELAY = 2, COOP_RUN_RMAX = 8;
static int coop_run_delay() {
  double rtt = wire.rtt >= 0 ? wire.rtt : COOP_RTT_GUESS_MS;
  return std::clamp((int)ceil(rtt / 2 / COOP_TICK_MS) - COOP_LATE_RMAX + 1, COOP_RUN_DELAY, COOP_DELAY);
}

// game_state_set brings the screen to gameplay for the run coop_enter_run
// named: the Host starts it (START_RUN) with the run's input delay and window;
// the Guest takes the Host's (START_ACK). The run records as the client's runs
// do. False when it cannot start.
static bool coop_start_run() {
  coop_live.entering = false;
  // A fade the last session began starts nothing in this one (coop_forget).
  if (coop_live.entered != wire.nonce)
    return false;
  cfg = coop_live.next;
  double now = host_time_ms();
  bool started;
  if (wire.seat == 0) {
    coop_header = {};
    coop_header.seat_keys = coop_room.next;
    started = game_coop_request(COOP_ASK_START, coop_run_delay(), COOP_RUN_RMAX, coop_live.choice, now);
  } else {
    coop_header = coop_room.offered;
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
  coop_held = {};
  live.aim_heading = player_state_table[wire.seat].aim_heading;
  coop_live.last = cfg;
  coop_live.session = wire.nonce;
  coop_live.playing = true;
  coop_live.banked = 0;
  coop_live.shown = coop_live.choosing = coop_live.escape = false;
  coop_live.ticked_at = host_time_ms();
  const ui_button_t plate = {(char *)"", 0, 0, 1, 0, 0, 0, 1.0f, 0, 1};
  coop_ui.resume = coop_ui.leave = plate;
  coop_ui.resume.label = (char *)"Resume";
  coop_ui.leave.label = (char *)"Leave";
  coop_ui.card = coop_ui.fire_held = coop_ui.banner = false;
  viewer.card = 0;
  return true;
}

// The run is over at the state after its last confirmed tick (`outcome`:
// "death", "quest_completed", or "incomplete" for a run left before its end):
// its replay, the same on both machines, is saved and its high score record
// names it, and one the board takes waits for both players' signatures
// (host/coop_ranked.inc). The engine keeps the run for the session, which still
// exchanges its last hashes, until the next starts.
static void coop_end(const char *outcome) {
  std::vector<uint8_t> payload = replay_payload(outcome, coop_header);
  coop_hold(payload, outcome);
  int number = replay_save(payload);
  memcpy(highscore_active_record.reserved0, &number, sizeof highscore_active_record.reserved0);
  game_live = game_session = false;
  coop_live.playing = coop_live.choosing = coop_ui.banner = false;
  coop_live.ended = true;
}
// This machine leaves its run before the run's end (another screen, the game
// quits, a stopped run's Leave): the partner is told, and the run ends where it
// was confirmed, the state its replay and score card read going back there from
// any predictions past it.
static void coop_quit() {
  game_coop_request(COOP_ASK_LEAVE, 0, 0, 0, host_time_ms());
  coop_settle();
  coop_end("incomplete");
}

// A START_RUN inside the original: the Guest's screen comes to the run first
// (game_coop_pump), which takes it there.
static void coop_offer(const PortableConfig &config, const ReplayHeader &header, int delay, int rmax, uint32_t epoch) {
  coop_live.next = config;
  coop_room.offered = header;
  coop_live.delay = delay;
  coop_live.rmax = rmax;
  coop_live.epoch = epoch;
  coop_live.offered = true;
}
// A new session (coop_session) takes no choice of the last: the Host's run and
// its seed request, the Guest's choice of the next, the run START_RUN offered,
// and a fade to the last one's run (coop_start_run).
static void coop_forget() {
  coop_live.latched = coop_live.offered = coop_ui.asked_next = false;
  coop_unask();
}
// START_CANCEL for the run offered: true when it was.
static bool coop_withdraw(uint32_t epoch) {
  if (!coop_live.offered || epoch != coop_live.epoch)
    return false;
  coop_live.offered = false;
  return true;
}

// game_state_set's screens while a session is on: a fade to gameplay coop_enter_run
// began starts its run (true); the end screen's Main Menu leaves the session, also
// once a fade to the next run began; the menus show the player's settings;
// another screen drops the Host's choice, and the run it was coming to (the
// Guest's comes again). An end screen shows its name entry first.
static bool coop_screen_set(game_state_id_t state) {
  bool starts = state == GAME_STATE_GAMEPLAY && !run_active && coop_live.entering;
  if (!starts)
    coop_live.latched = coop_live.entering = false;
  coop_live.naming =
      state == GAME_STATE_GAME_OVER || state == GAME_STATE_QUEST_RESULTS || state == GAME_STATE_QUEST_FAILED;
  if (coop_live.ended && !coop_gone() && state == GAME_STATE_MAIN_MENU)
    game_coop_request(COOP_ASK_LEAVE, 0, 0, 0, host_time_ms());
  if (state == GAME_STATE_MAIN_MENU || state == GAME_STATE_PLAY_GAME_MENU || state == GAME_STATE_QUEST_SELECT)
    coop_menu_restore();
  coop_live.ended &= state == GAME_STATE_GAME_OVER || state == GAME_STATE_QUEST_RESULTS ||
                     state == GAME_STATE_QUEST_FAILED || state == GAME_STATE_HIGHSCORES ||
                     state == GAME_STATE_FINAL_QUEST_END_NOTE;
  return starts;
}

// A line for the player at the bottom left, in a dim box.
static void coop_draw_line(const char *line) {
  float at[2] = {8, viewer_h() - 46}, dim[4] = {0, 0, 0, 0.55f};
  grim_interface_ptr->grim_draw_rect_filled(at, viewer_text_w(line) + 16, 24, dim);
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  viewer_text(16, viewer_h() - 40, line, 1, 1, 1, 1);
}
// The menus' line on co-op: what became of a click or why the session ended, a
// while; in a room without a session, that runs wait for the partner; a run of
// the player's own first; the Host's run
// waiting for the Guest (or for this player's name), the Guest's choice
// waiting for the Host; else that it is on (none while the screen fades to a
// run).
static const char *coop_menu_line() {
  if (coop_live.note && host_time_ms() - coop_live.note_at < COOP_NOTE_MS)
    return coop_live.note;
  if (coop_live.entering)
    return nullptr;
  if (!coop_on())
    return coop_live.room >= 0 ? coop_waiting() : nullptr;
  if (!wire.hello)
    return "Co-op: connecting";
  if (coop_busy())
    return "Co-op: connected - after this run";
  if (coop_live.latched)
    return coop_live.naming ? "Co-op: Player 2 is waiting for you" : "Co-op: waiting for Player 2";
  if (coop_ui.asked_next)
    return "Co-op: waiting for Player 1";
  if (coop_live.ended)
    return "Co-op: connected";
  return wire.seat == 0 ? "Co-op: connected - pick a run" : "Co-op: connected - the host picks the run";
}

// A banner across the middle of the run's frame, in the replay viewer's dim
// look: a title, a line under it, and buttons the mouse, the keys (Tab, Enter)
// and a pad (game/pad.cpp: the d-pad, A, the right stick) reach as they reach
// the original's, the focus on the first as it shows (a screen of its own to
// the pad's focus). The button activated, or -1.
static int coop_banner(const char *title, const char *line, std::initializer_list<ui_button_t *> buttons) {
  constexpr float HEIGHT = 104, BUTTON = 145, GAP = 16;
  coop_ui.banner = true;
  float w = viewer_w(), y = floorf((viewer_h() - HEIGHT) * 0.5f);
  float band[2] = {0, y}, dim[4] = {0, 0, 0, 0.55f}, blue[4] = {0.27f, 0.51f, 0.86f, 0.9f};
  grim_interface_ptr->grim_draw_rect_filled(band, w, HEIGHT, dim);
  grim_interface_ptr->grim_draw_rect_filled(band, w, 2, blue);
  grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
  viewer_shadowed(floorf((w - viewer_text_w(title)) * 0.5f), y + 14, title, 1, 1, 1, 1);
  viewer_text(floorf((w - viewer_text_w(line)) * 0.5f), y + 32, line, 0.75f, 0.78f, 0.82f, 0.9f);
  float x = floorf((w - buttons.size() * (BUTTON + GAP) + GAP) * 0.5f);
  int activated = -1, i = 0;
  for (ui_button_t *button : buttons) {
    float at[2] = {x + i * (BUTTON + GAP), y + 58};
    if (ui_button_update(at, button))
      activated = i;
    ++i;
  }
  ui_cursor_render();
  return activated;
}

// The record of this machine's player for the next tick: its input, or with
// the window in the background (`away`) no buttons, no movement (or the
// point-click target), its schemes and its last aim.
static PortableInput coop_sample(bool away) {
  if (!away)
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

// The picker's choice from its perk screen (game_live_pick), as its record at
// once, a paused run's too: the screen plays nothing, so the record holds what
// the background's does. A leave that follows ends the run after it. Should
// the partner lag far behind, it goes with the next record instead.
static void coop_pick(int choice) {
  if (!coop.picking)
    return;
  coop.scratch[coop.local] = {coop_sample(true), (uint8_t)(choice + 1)};
  game_coop_produce(host_time_ms());
}

// game_live_frame for a co-op run: the presses, and the pass's play time, which
// runs up to 2% fast or slow by how far the partner's run is ahead (§3.3): the
// run ahead slows and the one behind catches up, so both predict about as deep.
// Every pass draws.
static int coop_frame() {
  live_poll();
  coop_live.banked += fminf(grim_frame_dt, 0.1f) * std::clamp(1 + 0.01f * coop_ahead(), 0.98f, 1.02f);
  live.due = (int)(coop_live.banked * 60.0f + 1e-4f);
  return 1;
}

// The partner's perk menu on the card, once the tick that opened it is
// confirmed: "picking" until the next tick takes its choice, which lights for
// WATCH_PICK_SECONDS of play (a cancel slides it away at once).
static void coop_card(float dt) {
  int open = coop.next - 1;
  if (perk_menu_open && perk_picker != coop.local && coop.confirmed >= open &&
      !(coop_ui.card && coop_ui.pick.tick == open)) {
    int offered = coop_offered();
    coop_ui.pick = {open, player_state_table[0].level, -1, offered, {}, perk_picker};
    memcpy(coop_ui.pick.offered, perk_choice_ids, offered * sizeof(int));
    coop_ui.card = coop_ui.picking = true;
  }
  if (!coop_ui.card)
    return;
  if (coop_ui.picking && coop.confirmed > coop_ui.pick.tick) {
    const CoopTick &next = coop.ticks[(coop_ui.pick.tick + 1) & (COOP_RING - 1)];
    coop_ui.picking = false;
    coop_ui.pick.chosen = next.commands && next.command.type == 1 ? next.command.argument : -1;
    coop_ui.left = coop_ui.pick.chosen >= 0 ? WATCH_PICK_SECONDS : 0;
  }
  if (!coop_ui.picking && !wire.paused)
    coop_ui.left -= dt;
  char header[48];
  viewer_card_header(coop_ui.pick, coop_ui.picking, header, sizeof header);
  bool in = coop_ui.picking || coop_ui.left > 0;
  coop_ui.card = viewer_card(coop_ui.pick, header, in, dt) || in;
}

// This machine's run ends where it stopped (a desync, an error) and the screen
// goes to the menu.
static void coop_abandon() {
  coop_quit();
  coop_to_menu();
}

// What the run's frame shows over the world: a stopped run's banner, whose Leave
// (or Escape) goes to the menu; the pause's, with Resume (Escape) and Leave;
// else the partner's perk pick, and why the run waits or ends. Play resumes
// under a banner only once fire is let go.
static void coop_overlay_draw(float dt) {
  char line[64];
  int partner = 2 - wire.seat;
  bool banner = (coop.hold & COOP_HOLD_STOP) || (wire.paused && !(game_coop_status() & COOP_LEAVING));
  if (banner) {
    coop_ui.fire_held = true;
    live.fire_pressed = live.reload_pressed = false;
  } else {
    coop_ui.banner = false;
  }
  if (coop.hold & COOP_HOLD_STOP) {
    const char *why = coop_why();
    bool desync = coop.desync.tick >= 0;
    if (coop_banner(desync ? why : "Co-op error", desync ? "The two games ran differently from here" : why ? why : "",
                    {&coop_ui.leave}) == 0)
      coop_abandon();
    return;
  }
  coop_card(dt);
  if (banner) {
    // A pad player's Start, as the original's pause menu takes it.
    const char *key = config_blob.movement_schemes[0] == 3 ? "Start" : "Esc";
    if (wire.pause_by == wire.seat)
      snprintf(line, sizeof line, "%s resumes the run", key);
    else
      snprintf(line, sizeof line, "Player %d paused the run - %s resumes it", partner, key);
    int activated = coop_banner("Paused", line, {&coop_ui.resume, &coop_ui.leave});
    if (activated == 0)
      game_coop_request(COOP_ASK_PAUSE, 0, 0, 0, host_time_ms());
    else if (activated == 1)
      game_coop_request(COOP_ASK_LEAVE, 0, 0, 0, host_time_ms());
    return;
  }
  uint32_t status = game_coop_status();
  if (!coop_on() || (status & COOP_LEAVING)) {
    const char *why = coop_why();
    coop_draw_line(why ? why : "Leaving the run");
  } else if (!coop_ui.card && ((status & COOP_STARTING) || host_time_ms() - coop_live.ticked_at > 500)) {
    // Half a second without a tick: the run waits for the partner's records.
    snprintf(line, sizeof line, "Waiting for Player %d", partner);
    coop_draw_line(line);
  }
}

// This machine's records up to the input delay ahead of its run, the pass's
// input in each (its presses in the first).
static void coop_produce(double now) {
  for (;;) {
    coop.scratch[coop.local].input = coop_sample(coop_live.unfocused);
    if (game_coop_produce(now) < 0)
      return;
    live.fire_pressed = live.reload_pressed = false;
  }
}

// gameplay_update_and_render for a co-op run: Escape and the perk requests go to
// the session; this machine's records up to the input delay ahead (the first
// cancels for a picker back from its perk screen without a choice), the ticks
// the engine runs, the newest drawing, and the records those ticks made room
// for, which the pass's ticks packet carries; once the run reached its last
// tick, its end. A tick that ran pays for its time, and a pass held back keeps
// at most a few ticks' worth, so play resumes without a burst. The overlays go
// on top.
static void coop_render() {
  double now = host_time_ms();
  // Escape pauses or resumes; a run stopped (a desync, an error) it leaves.
  if (coop_live.escape) {
    coop_live.escape = false;
    if (coop.hold & COOP_HOLD_STOP)
      return coop_abandon();
    game_coop_request(COOP_ASK_PAUSE, !wire.paused, 0, 0, now);
  }
  // Starting failed: the Host's partner never answered, or the Host cancelled.
  if (!coop.active) {
    game_live = game_session = coop_live.playing = false;
    if (const char *why = coop_why())
      coop_note(why);
    return coop_to_menu();
  }
  live_poll_prompt();
  if (live.open_requested)
    game_coop_request(COOP_ASK_OPEN, 0, 0, 0, now);
  live.open_requested = false;
  if (!coop.picking)
    coop_live.choosing = false;
  if (coop_ui.fire_held) {
    coop_ui.fire_held = live.fire_down;
    live.fire_down = live.fire_pressed = false;
  }
  int due = live.due;
  coop_produce(now);
  int draws = coop.draws;
  int ran = game_coop_advance(due, now);
  // A picker's next record is its choice, from the perk screen this pass opens.
  if (!coop.picking)
    coop_produce(now);
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
    coop_live.naming = true;
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
  coop_overlay_draw(fminf(grim_frame_dt, 0.1f));
}

extern "C" {
// A pass of the game (game/frame.cpp), whatever its screen: the menus' unlocks
// follow the session; the Host starts the run it chose once the Guest can and
// both end screens passed their name entries, and takes the Guest's choice of
// the next; the Guest's screen comes to the run the Host started, or to its run
// setup. Every session ends the same way, closed or followed by another: its
// run ends where it was confirmed, and its end screens keep the run's settings
// and go back to the menu once this player's name is in. A screen that changes
// takes nothing until it shows, and the end screens' Main Menu leaves at the
// click. True while the game plays on for the session, in the background too
// (not under a run of the player's own), and for a co-op run still to end.
bool game_coop_pump() {
  // A perk screen whose pick the session no longer takes (a leave) closes as
  // its Cancel does.
  if (coop_live.choosing && !coop.picking && game_state_id == GAME_STATE_PERK_SELECTION &&
      game_state_pending == GAME_STATE_PENDING_IDLE_SENTINEL) {
    ui_transition_direction = 0;
    game_state_pending = GAME_STATE_GAMEPLAY;
  }
  bool on = coop_on(), busy = coop_busy(), gone = coop_gone();
  coop_overlay(coop_open() && !busy);
  // A session that ended says why, a while.
  if (coop_ui.was_on && !on)
    if (const char *why = coop_why())
      coop_note(why);
  coop_ui.was_on = on;
  if (!on || !coop_live.ended || gone)
    coop_ui.asked_next = false;
  if (gone && !coop_live.naming)
    coop_to_menu();
  if (!on) {
    coop_live.latched = coop_live.offered = false;
    if (!coop_live.playing && !coop_live.entering && !coop_live.ended)
      coop_menu_restore();
    return coop_live.playing;
  }
  if (coop_live.playing || coop_live.entering || gone)
    return true;
  // A click on the screen fades it out to the pending one.
  bool changing = !ui_transition_direction && game_state_pending != GAME_STATE_PENDING_IDLE_SENTINEL;
  if (changing && coop_live.ended && game_state_pending == GAME_STATE_MAIN_MENU)
    game_coop_request(COOP_ASK_LEAVE, 0, 0, 0, host_time_ms());
  if (changing || busy)
    return !busy;
  if (wire.seat == 1) {
    // The Host opened its run setup from the end screen.
    if (wire.next_run == 2 && coop_live.ended)
      coop_setup();
    wire.next_run = -1;
    if (coop_live.offered && !wire.left && !wire.partner_left && !coop_live.naming)
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
  // A run that cannot start yet asks the room for no seed: a later start asks
  // afresh.
  bool named = !coop_live.naming && (!wire.started || wire.partner_signed);
  if (!coop_live.latched || !named || !coop_can_start())
    coop_unask();
  else if (coop_seeded())
    coop_enter_run(coop_live.next);
  return true;
}
// The original's buttons that start a run from the menus, the high scores and
// the end note (game/changes/coop-run.patch): true when the session takes the
// click. The Host's picks the run (on an end screen's, after a choice the Host
// already took); the Guest's waits for the Host's. Co-op plays Survival and the
// stock quests. A click while the screen comes to a run starts nothing more; in
// a room without a session, none starts anything: the run waits for the partner.
bool game_coop_setup_run(int mode, int major, int minor) {
  if (!coop_open())
    return false;
  if (coop_live.entering)
    return true;
  if (!coop_playable(mode, major, minor))
    coop_note("Co-op plays Survival and the quests");
  else if (!coop_on())
    coop_note(coop_waiting());
  else if (wire.seat == 1)
    coop_note("The host picks the run");
  else if (!(coop_live.ended && coop_live.latched))
    coop_latch(mode, major, minor, config_blob.hardcore, 2);
  return true;
}
// An end screen's button that starts the next run (`choice` 0 again, 1 next, 2
// another from the run setup): true when the session takes the click. The
// Guest tells the Host, which starts it, the first choice it saw winning; Play
// Another opens the quest list on both. Play Next past the last quest shows the
// end note, which starts nothing. The end screen of a run of the player's own
// starts the session's run as the menus do, and in a room without a session
// none; a co-op run's starts nothing once its session ended (the next pass goes
// to the menu), nor while the screen comes to the next run.
bool game_coop_next_run(int choice) {
  if ((!coop_on() || coop_gone()) && (coop_live.ended || coop_live.room < 0))
    return coop_live.ended;
  if (coop_live.entering)
    return true;
  bool ours = coop_live.ended;
  int major = ours ? (int)coop_live.last.major : quest_stage_major,
      minor = ours ? (int)coop_live.last.minor : quest_stage_minor;
  if (choice == 1 && major == 5 && minor == 10)
    return false;
  if (!ours) {
    if (choice == 1)
      coop_next_quest(major, minor);
    return choice != 2 && game_coop_setup_run(config_blob.game_mode, major, minor);
  }
  if (wire.seat == 1) {
    coop_ui.asked_next = game_coop_request(COOP_ASK_NEXT_RUN, choice, 0, 0, host_time_ms());
    return choice != 2;
  }
  if (coop_live.latched)
    return true;
  if (choice == 2) {
    game_coop_request(COOP_ASK_NEXT_RUN, 2, 0, 0, host_time_ms());
    return false;
  }
  coop_latch_next(choice);
  return true;
}
// An end screen past its name entry (or with none), each pass it shows its
// buttons: a co-op run's signs the run with the name and tells the partner, once.
void game_coop_end_ready() {
  if (!coop_live.naming)
    return;
  coop_live.naming = false;
  if (!coop_live.ended)
    return;
  coop_sign();
  game_coop_request(COOP_ASK_SIGNED, 0, 0, 0, host_time_ms());
}
// The window's focus (game/frame.cpp): with a session on, the game plays on in
// the background, this machine's records neutral, the presses so far dropped
// and the input devices at rest (game/dinput.cpp); a run of the player's own
// pauses as alone. True while it plays on.
bool game_coop_focus(int active) {
  coop_live.unfocused = !active;
  if (!active)
    live.fire_down = live.reload_down = live.pick_down = live.fire_pressed = live.reload_pressed =
        live.open_requested = false;
  return coop_on() && !coop_busy();
}
// A co-op run's banner shows its buttons (game/pad.cpp): the pad steps their
// focus as outside gameplay.
bool game_coop_banner() { return coop_live.playing && coop_ui.banner; }
// The page holds `seat` (0 the room's host, 1 its guest) in a co-op room, from
// when it opens or joins one until it leaves it or co-op ends there (-1): while
// it does, co-op is open whether or not a session runs (coop_open). 1 when the
// game took it.
__attribute__((export_name("game_coop_in_room"))) int game_coop_in_room(int seat) {
  if (seat < -1 || seat > 1)
    return 0;
  coop_live.room = seat;
  return 1;
}
// Why the session or its run stopped, as the game tells its player (coop_why),
// for the page's panel; null when this machine left or nothing stopped.
__attribute__((export_name("game_coop_why"))) const char *game_coop_why() { return coop_why(); }
}
// The menus' line (ui_elements_update_and_render).
static void coop_menus_draw() {
  if ((!wire.session && coop_live.room < 0) || coop_live.playing)
    return;
  if (const char *line = coop_menu_line())
    coop_draw_line(line);
}
