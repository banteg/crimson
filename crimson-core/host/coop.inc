// Two-player online co-op's engine (docs/rewrite/network-coop.md): both peers
// run the same 2-player run from both players' recorded inputs. Each tick waits
// for this machine's input; the partner's comes over the network, and while it
// is late the tick runs on a prediction, which a rollback corrects when the input
// arrives: the run goes back to the state before that tick, kept in a ring of the
// last ticks' states, and plays the ticks again. A tick's perk command comes from
// the players' requests (coop_command), judged by the state it starts from.
//
// A tick runs between its run's own settings (live.run) and its own screen state
// (the menu a death asks for, the transition it turns down), which the picker's
// perk screen and this machine's menus never reach. What a tick presents reaches
// this machine in tick order once it is final: its terrain bake in the tick when
// every tick before it is confirmed and it runs on both seats' real records,
// else once it is confirmed; its music once it is confirmed. Sound plays once: a
// tick played again is silent.
//
// Solo (game_coop_start with local -1), the caller produces both seats' records,
// and checks/game_coop.mjs drives the same engine against a plain run and through
// forced rollbacks. Between two peers, the session (host/coop_wire.inc) carries
// the records and holds the run back while it pauses, waits for a start or ends.
#include <deque>

extern "C" {
extern unsigned char game_paused_flag;
extern int telekinetic_bonus_hover_timer_ms[2];
extern unsigned char game_image_exe[];
extern music_entry_t music_entry_table[128];
bool game_sound_playing(LPDIRECTSOUNDBUFFER buffer);
// The run's globals the snapshot leaves out that a tick reads (coop_words).
extern float perk_fire_cough_trigger_interval_s, perk_hot_tempered_trigger_interval_s,
    perk_man_bomb_trigger_interval_s, player_spread_damping_gate, player_spread_damping_scalar, player_aim_screen_x[4],
    survival_first_kill_pos[6];
extern int creature_update_tick, projectile_update_tick, demo_time_limit_ms, demo_trial_elapsed_ms,
    player_alt_weapon_swap_cooldown_ms;
extern bool mouse_button_down;
// And those it leaves out on purpose (COOP_UNHASHED).
extern char bonus_label_format_buffer[128], default_player_name[7], s_unhandled_creature_type[25];
extern vec2f_t fx_rotated_pos_x[64];
extern float fx_rotated_scale[64], fx_rotated_rotation[64];
extern int fx_rotated_creature_type_id[64];
extern effect_color_t fx_rotated_color_r[64];
extern effect_id_entry_t effect_id_table[19];
extern unsigned char bonus_hud_slot_table[512], demo_trial_overlay_active, gameplay_transition_latch, perk_prompt_hover_active,
    player_overlay_suppressed_latch, plugin_runtime_active_latch, survival_reward_handout_aux_enabled;
extern float bonus_render_anim_phase, game_time_s, frame_dt_copy, effect_uv_step_2, effect_uv_step_4, effect_uv_step_8,
    effect_uv_step_16, gameplay_reset_unused_timer, render_scratch_f0, render_scratch_f2,
    effect_template_position[2];
extern int demo_trial_overlay_alpha_ms, pause_keybind_help_alpha_ms, perk_prompt_pulse, perk_prompt_timer,
    player_overlay_auto_target_line_perk_id, creature_type_count, effect_defaults_reserved_zero,
    effect_pool_reserved_zero, quest_spawn_last_time_ms, quest_spawn_total_creatures, tutorial_stage_index,
    tutorial_stage_timer, tutorial_stage_transition_timer, frame_dt_ms, online_sync_status, terrain_render_target;
extern char *perk_slot_1_name_wrapped_primary, *perk_slot_1_name_wrapped_alternate, *perk_slot_1_desc_wrapped_primary,
    *perk_slot_1_desc_wrapped_alternate;
extern quest_meta_t *quest_monster_vision_meta;
extern game_state_id_t game_state_prev;
extern unsigned char main_menu_full_version_layout_latch, screen_fade_ramp_flag, startup_skip_requested;
extern ui_element_t ui_sign_crimson;
}

// A seat's record for a tick: its input, and a perk request (0 none, 1..7 the
// choice picked, COOP_OPEN the menu).
struct CoopInput {
  PortableInput input;
  uint8_t cmd;
};
enum { COOP_OPEN = 8 };
// Ticks of records and per-tick results kept; states and held bakes kept; the
// most ticks a run may run past its last confirmed one; the most ticks a seat's
// records may run ahead of the run; the most records a peer produces past the
// last its partner acknowledged.
static constexpr int COOP_RING = 256, COOP_SLOTS = 16, COOP_LEAD = 12, COOP_DELAY = 8, COOP_UNACKED = 120;
// Late in a long Survival run, where ticks cost the most, the window a run may
// predict narrows: past 15 minutes of the run, to 4 ticks.
static constexpr int COOP_LATE_RMAX = 4, COOP_LATE_MS = 900000;
// A frame's time running ticks, by the milliseconds each bucket holds up to:
// under 1, 2, 4, 8, 16, and longer.
static constexpr int COOP_FRAME_BUCKETS = 6;
// A rollback reaches back at most to the first unconfirmed tick, and a held bake
// waits only until its tick is confirmed: both stay within the lead.
static_assert(COOP_LEAD < COOP_SLOTS, "a slot or held bake comes round again before its tick is confirmed");
static_assert(COOP_LEAD + COOP_DELAY < COOP_RING, "records ahead of the run overwrite unconfirmed ones");
static const PortableInput COOP_NEUTRAL = {0, 0, 512, 512, 0};
// What holds a run back (the session, host/coop_wire.inc): the Host's run waits
// for the Guest's acknowledgement; a pause or a leave stops production; a desync
// or a protocol error stops everything.
enum : uint32_t { COOP_HOLD_START = 1, COOP_HOLD_PAUSE = 2, COOP_HOLD_LEAVE = 4, COOP_HOLD_STOP = 8 };
static constexpr int COOP_NO_END = INT_MAX;

// The screen state a run reads and writes in its ticks, apart from this machine's.
struct CoopScreen {
  game_state_id_t pending;
  int timeline;
  unsigned char direction;
};
struct CoopRecord {
  CoopInput record;
  int tick; // the tick it is for, -1 none
  bool real; // false for one the caller stood in for the partner's (solo)
};
// What a tick ran with and left.
struct CoopTick {
  int tick;
  CoopInput used[2];
  // The derived command (none or one) and the picker, for the recording.
  uint32_t commands;
  PortableCommand command;
  int picker;
  uint32_t hash, bake; // the state's hash after it; its bake's digest
  // Every bake and tune up to it in the order this machine presented them,
  // once it presented its own.
  uint32_t terrain, music;
  uint32_t state; // the raw state's digest after it, when kept (game_coop_states)
  bool held;      // its bake waits in bakes[] for its confirmation
  uint8_t living; // which players live after it (bits 0 and 1)
};
// The state before a tick, which a rollback puts back.
struct CoopSlot {
  uint32_t epoch;
  int tick;
  std::vector<uint8_t> state;
  bool overflow_free; // the effect overflow had freed entries to reuse
};
// A held tick's bake, drawn into the terrain once the tick is confirmed.
struct CoopBake {
  uint32_t epoch;
  int tick;
  std::vector<fx_queue_entry_t> queue; // the fx queue's, then the overflow's
  std::vector<RotatedDecal> rotated;
};
struct CoopTune {
  int tick;
  CoopTuneKind kind;
  int track;
  float volume;
};
// A confirmed tick's hash between two peers, kept until the partner holds it and
// this machine compared the partner's (host/coop_wire.inc): whether it was
// compared, and when a ticks packet last carried it.
struct CoopHash {
  uint32_t hash;
  bool checked;
  double sent_at;
};
// A hash the peer reported for a tick, and the first that differed from this
// machine's.
struct CoopReported {
  int tick;
  uint32_t hash;
};
struct CoopDesync {
  int tick;
  uint32_t local, remote;
};
// The session's counters over every run (host/coop_wire.inc): ticks packets
// sent, received, and lost on the way (by their sequence numbers); packets and
// messages of another run ignored; repairs sent and the records they carried;
// the round trip (ms).
struct CoopWireStats {
  int32_t sent, received, lost, stale, repairs, repaired, rtt_ms;
};
// The session's counters over every run, as the run's own below, for the
// telemetry its page reports when it ends (game_coop_telemetry): ticks run and
// run again, frames whose due ticks all waited, rollbacks by depth, and frames
// by the time their ticks took.
struct CoopSessionStats {
  int32_t ticks, resimulated, stalled_frames;
  int32_t depths[COOP_LEAD], frame_ms[COOP_FRAME_BUCKETS];
};
// Counters for the gate and the session's telemetry. checks/coop_link.mjs reads
// them by position.
struct CoopStats {
  int32_t ticks, resimulated, rollbacks, max_depth, stalls;
  // Ticks run on a record not yet real, corrections, and waits for the open
  // menu's picker, by the seat; the furthest past the last confirmed tick a
  // tick ran on a record not yet real.
  int32_t guesses[2], mispredictions[2], picker_waits[2], guessed_lead;
  int32_t opens[2], double_opens, dropped_opens, survivor_menus, extra_picks;
  // Restores with the effect overflow in use, and with freed overflow entries
  // in the states they undo; held bakes with overflow decals; held bakes drawn
  // while the queues held the next tick's; final bakes on ticks not drawn.
  int32_t overflow_rollbacks, overflow_free_rollbacks, overflow_decal_holds, queued_commits, unseen_bakes;
  int32_t slot_bytes;
  // The furthest past the last confirmed tick the run got.
  int32_t max_lead;
  int32_t checked; // ticks whose hash the peer's was compared with
  // Rollbacks by how many ticks they took back (1 to COOP_LEAD).
  int32_t depths[COOP_LEAD];
  // Frames (game_coop_advance) that ran ticks or ran them again, by the time
  // that took (COOP_FRAME_BUCKETS), and the longest (µs); frames with ticks due
  // that ran none, waiting for records, the window or the picker (not a pause);
  // the most ticks a frame ran again.
  int32_t frame_ms[COOP_FRAME_BUCKETS], worst_frame_us, stalled_frames, frame_resimulated;
  // Ticks run under the late window, and the furthest past the last confirmed
  // tick one of them ran on a record not yet real.
  int32_t late_ticks, late_lead;
  // Ticks run again that left the players living otherwise than their last run
  // had: a death a correction took back or brought; and among them those that
  // left nobody or somebody living otherwise, a team wipe.
  int32_t revised_deaths, revised_wipes;
  CoopWireStats wire;
  CoopSessionStats session;
};

static struct {
  bool active;
  int local; // the seat this machine plays, -1 both
  int delay, rmax;
  uint32_t epoch;
  // The frontiers: the last tick produced, acknowledged by the peer, confirmed,
  // baked into the terrain and played; the partner's records held without a gap
  // (two peers); the next tick to run; the last tick ever run (heard).
  int produced, peer_ack, confirmed, baked, played, remote, next, heard;
  uint32_t hold; // COOP_HOLD_*
  int end;       // the last tick to run, once the peers agreed to end (COOP_NO_END)
  // This machine's perk request (two peers): an open asked for the next tick it
  // produces; the tick it went on, until that tick is confirmed (-1 none); the
  // picker's choice due on the next tick it produces.
  bool asked, picking;
  int request;
  CoopReported reported[COOP_RING];
  // The kept hashes (two peers), of ticks `hashes_from` on, up to `confirmed`.
  std::deque<CoopHash> hashes;
  int hashes_from;
  CoopDesync desync;
  bool running; // a co-op tick runs
  bool quiet;   // the tick running ran before
  bool drawing; // the tick running draws
  int draws;    // ticks that drew
  int drawn;    // the tick whose state the frame shows, -1 once a rollback took it back
  int late_ms = COOP_LATE_MS; // the run time a Survival run's window narrows at
  bool states;  // keep each tick's raw state digest (checks/game_coop.mjs)
  int baking;   // the tick running, once it baked
  CoopScreen screen;
  size_t strings; // the arena as run start left it
  uint32_t terrain, music; // the digests at `baked` and `played`
  CoopInput scratch[2];
  CoopRecord records[2][COOP_RING];
  CoopTick ticks[COOP_RING];
  std::vector<CoopSlot> slots;
  std::vector<CoopBake> bakes;
  std::vector<CoopTune> tunes;
  CoopStats stats;
} coop;

static const int COOP_PRESENTATION[] = {
#include "presentation.inc"
};

// The run stops, and the session's with it (host/coop_wire.inc).
static void coop_stop();

static CoopScreen coop_screen() { return {game_state_pending, ui_elements_timeline, ui_transition_direction}; }
static void coop_screen_install(const CoopScreen &screen) {
  game_state_pending = screen.pending;
  ui_elements_timeline = screen.timeline;
  ui_transition_direction = screen.direction;
}

// The run's surroundings for a tick or its hash: its screen state, and inside
// the original its settings, with the player's cursor kept.
struct CoopRun {
  CoopScreen screen = coop_screen();
  float mouse_x = ui_mouse_x, mouse_y = ui_mouse_y;
  CoopRun() {
    coop_screen_install(coop.screen);
    if (game_live)
      live_enter_run();
  }
  ~CoopRun() {
    coop.screen = coop_screen();
    if (game_live) {
      live.run = live_settings();
      live_install(live.outside);
      ui_mouse_x = mouse_x;
      ui_mouse_y = mouse_y;
    }
    coop_screen_install(screen);
  }
};

// xxHash32 (seed 0): every input bit reaches every bit of the digest, so
// changes in two words do not cancel, as they can under FNV-1a's word steps,
// which carry a change only towards the high bits (two sign flips). Four lanes
// keep a tick's state quick to digest.
static uint32_t coop_digest(const void *data, size_t size) {
  constexpr uint32_t P1 = 2654435761u, P2 = 2246822519u, P3 = 3266489917u, P4 = 668265263u, P5 = 374761393u;
  auto rotl = [](uint32_t x, int r) { return x << r | x >> (32 - r); };
  auto word = [](const uint8_t *p) {
    uint32_t w;
    memcpy(&w, p, 4);
    return w;
  };
  const uint8_t *p = (const uint8_t *)data, *end = p + size;
  uint32_t h;
  if (size >= 16) {
    uint32_t v[4] = {P1 + P2, P2, 0, 0u - P1};
    for (; end - p >= 16; p += 16)
      for (int i = 0; i < 4; ++i)
        v[i] = rotl(v[i] + word(p + 4 * i) * P2, 13) * P1;
    h = rotl(v[0], 1) + rotl(v[1], 7) + rotl(v[2], 12) + rotl(v[3], 18);
  } else {
    h = P5;
  }
  h += (uint32_t)size;
  for (; end - p >= 4; p += 4)
    h = rotl(h + word(p) * P3, 17) * P4;
  for (; p < end; ++p)
    h = rotl(h + *p * P5, 11) * P1;
  h = (h ^ h >> 15) * P2;
  h = (h ^ h >> 13) * P3;
  return h ^ h >> 16;
}
// A digest of what came before, then one more thing.
static uint32_t coop_chain(uint32_t chain, uint32_t digest) {
  uint32_t words[] = {chain, digest};
  return coop_digest(words, sizeof words);
}

static void coop_put(uint32_t x) {
  if (used >= 262144)
    abort();
  output[used++] = x;
}
template <class T> static void coop_put_words(const T &value) {
  static_assert(sizeof(T) % 4 == 0);
  uint32_t words[sizeof(T) / 4];
  memcpy(words, &value, sizeof words);
  for (uint32_t w : words)
    coop_put(w);
}
static void coop_put_float(float x) {
  uint32_t w;
  memcpy(&w, &x, 4);
  coop_put(w);
}
static int coop_overflow_index(const effect_entry_t *entry) {
  return !entry ? -1 : entry == &effect_discard_entry ? -2 : int(entry - game_effect_overflow.entries);
}

// The run's state as both peers hold it, as words at portable_output: the
// snapshot less what only presentation reads, the session's fields, the run's
// globals the snapshot leaves out, the run's settings less the player's own,
// and the effect overflow's entries. Field by field: no padding or pointer
// reaches it. game_coop_audit holds it to every byte of the run's state.
static int coop_words() {
  int n = portable_snapshot();
  for (int i : COOP_PRESENTATION)
    output[i] = 0;
  used = n;
  // game_state_pending is the snapshot's, the run's own (CoopRun).
  coop_put(rng);
  coop_put(tick);
  coop_put(menu_requested);
  coop_put(perk_menu_open);
  coop_put(perk_picker);
  coop_put(running_down);
  coop_put(run_down_ms);
  coop_put(game_paused_flag);
  coop_put(game_effect_overflow.active);
  coop_put(game_effect_overflow.extent);
  coop_put(coop_overflow_index(game_effect_overflow.free));
  coop_put(telekinetic_bonus_hover_timer_ms[0]);
  coop_put(telekinetic_bonus_hover_timer_ms[1]);
  // The run's globals the snapshot leaves out that a tick reads
  // (game_coop_audit): perk and weapon clocks, the last tick's time step (a
  // pick reads it), update counters, the players' cursors, the screen and menu
  // flags the tick checks, where Survival's first kill fell, the effect
  // template spawns copy, the late weapons' usage.
  for (float f : {perk_lean_mean_exp_tick_timer_s, perk_fire_cough_trigger_interval_s,
                  perk_hot_tempered_trigger_interval_s, perk_man_bomb_trigger_interval_s, player_heading_turn_delta,
                  player_spread_damping_gate, player_spread_damping_scalar, frame_dt})
    coop_put_float(f);
  for (int i : {creature_update_tick, projectile_update_tick, current_player_index, player_alt_weapon_swap_cooldown_ms,
                quest_fail_retry_count, quest_stage_major, quest_stage_minor, demo_time_limit_ms, demo_trial_elapsed_ms})
    coop_put(i);
  for (int flag : {(int)run_active, (int)console_open_flag, (int)demo_mode_active, (int)mouse_button_down})
    coop_put(flag);
  coop_put_words(player_aim_screen_x);
  coop_put_words(survival_first_kill_pos);
  coop_put_words(effect_template);
  coop_put_words(weapon_usage_time);
  // The run draws with the player's display choices and plays at the player's
  // volumes (live_enter_run, game_run_ready): those differ by machine, and only
  // drawing and audio read them.
  const LiveSettings run = live_settings();
  crimson_cfg_t config = run.config;
  memset(config.direction_arrow_flags, 0, sizeof config.direction_arrow_flags);
  config.shadows_enabled = config.flame_glow_enabled = config.smoke_enabled = config.ui_info_texts = 0;
  config.sfx_volume = config.music_volume = 0;
  coop_put_words(config);
  coop_put_words(run.status);
  coop_put_words(run.unlocks);
  coop_put_float(run.bodies_fade);
  coop_put_float(run.friendly_fire);
  coop_put_words(run.keys);
  // The playlist past its count, which no tick reads, holds the tunes this
  // machine's original loaded past the verifier's (portable_init).
  GameMusic music = run.music;
  std::fill(music.playlist + music.playlist_count, std::end(music.playlist), 0);
  coop_put_words(music);
  for (int i = 0; i < game_effect_overflow.extent; ++i) {
    const effect_entry_t &e = game_effect_overflow.entries[i];
    for (float f : {e.pos_x, e.pos_y})
      coop_put_float(f);
    coop_put(e.effect_id);
    for (float f : {e.vel_x, e.vel_y, e.rotation, e.scale, e.half_width, e.half_height, e.age, e.lifetime})
      coop_put_float(f);
    coop_put(e.flags);
    for (float f : {e.color.r, e.color.g, e.color.b, e.color.a, e.rotation_step, e.scale_step})
      coop_put_float(f);
    coop_put(coop_overflow_index(e.next_free));
  }
  return used;
}

// The run's bytes no canonical word holds (game_coop_audit holds the list to the
// run's state, byte for byte): a global, a field of every element of a table,
// or a span between two globals.
struct CoopBytes {
  const void *at;
  uint32_t size, stride, count;
};
#define COOP_GLOBAL(name) {&name, sizeof name, 0, 1}
#define COOP_FIELD(table, field) {&table[0].field, sizeof table[0].field, sizeof table[0], std::size(table)}
#define COOP_SPAN(first, last) {&first, uint32_t((const uint8_t *)(&last + 1) - (const uint8_t *)&first), 0, 1}
static const CoopBytes COOP_UNHASHED[] = {
    // Padding, and a sink: spawns past the full effect and bonus pools write
    // there, and nothing reads it back.
    COOP_FIELD(player_state_table, _pad_entity_active), COOP_FIELD(player_state_table, _pad_entity_flags),
    COOP_FIELD(player_state_table, _pad0), COOP_FIELD(player_state_table, _pad1), COOP_FIELD(player_state_table, _pad2),
    COOP_FIELD(player_state_table, _pad3), COOP_FIELD(player_state_table, _pad_entity_link),
    COOP_FIELD(player_state_table, _pad6), COOP_FIELD(player_state_table, _pad_reload_active),
    COOP_FIELD(player_state_table, _pad_alt_reload_active), COOP_FIELD(creature_pool, _pad0),
    COOP_FIELD(creature_pool, _pad1), COOP_FIELD(creature_pool, _pad2), COOP_FIELD(creature_pool, _pad_force_target),
    COOP_FIELD(creature_pool, _pad_target_player), COOP_FIELD(projectile_pool, _pad0),
    COOP_FIELD(secondary_projectile_pool, _pad0), COOP_FIELD(particle_pool, _pad0), COOP_FIELD(particle_pool, _pad1),
    COOP_FIELD(sprite_effect_pool, _pad0), COOP_FIELD(bonus_pool, _pad0), COOP_FIELD(effect_pool, _pad0),
    COOP_FIELD(weapon_table, _pad0), COOP_FIELD(weapon_table, _pad1), COOP_FIELD(weapon_table, _pad2),
    COOP_FIELD(weapon_table, _pad3), COOP_FIELD(perk_meta_table, _pad_available), COOP_FIELD(bonus_meta_table, _pad0),
    {&perk_choices_dirty + 1, 3, 0, 1}, COOP_GLOBAL(effect_discard_entry), COOP_GLOBAL(bonus_pool_sentinel),
    // What only drawing, sound and the menus read: the effects' quad corners;
    // the terrain's queued decals and corpses (the bake digest holds those); the
    // HUD, the perk prompt and screen, the cursor, the screen's fades and
    // transitions; the run's high score card and the high score table; the
    // weapons' names and sounds; the player's display and audio choices (live_enter_run).
    COOP_FIELD(effect_pool, vertices), COOP_GLOBAL(fx_queue), COOP_GLOBAL(fx_rotated_pos_x),
    COOP_GLOBAL(fx_rotated_scale), COOP_GLOBAL(fx_rotated_rotation), COOP_GLOBAL(fx_rotated_creature_type_id),
    COOP_GLOBAL(fx_rotated_color_r), COOP_GLOBAL(render_scratch_f0), COOP_GLOBAL(render_scratch_f2),
    COOP_GLOBAL(bonus_hud_slot_table), COOP_GLOBAL(bonus_label_format_buffer), COOP_GLOBAL(bonus_render_anim_phase),
    COOP_GLOBAL(player_weapon_popup_timer), COOP_GLOBAL(survival_xp_smoothed), COOP_GLOBAL(perk_prompt_hover_active),
    COOP_GLOBAL(perk_prompt_pulse), COOP_GLOBAL(perk_prompt_timer), COOP_GLOBAL(perk_slot_1_name_wrapped_primary),
    COOP_GLOBAL(perk_slot_1_name_wrapped_alternate), COOP_GLOBAL(perk_slot_1_desc_wrapped_primary),
    COOP_GLOBAL(perk_slot_1_desc_wrapped_alternate), COOP_GLOBAL(player_overlay_suppressed_latch),
    COOP_GLOBAL(ui_mouse_x), COOP_GLOBAL(ui_mouse_y), COOP_GLOBAL(game_time_s), COOP_GLOBAL(frame_dt_copy),
    COOP_GLOBAL(screen_fade_alpha), COOP_GLOBAL(screen_fade_ramp_flag), COOP_GLOBAL(gameplay_transition_latch),
    COOP_GLOBAL(ui_sign_crimson), COOP_GLOBAL(main_menu_full_version_layout_latch),
    COOP_GLOBAL(pause_keybind_help_alpha_ms), COOP_GLOBAL(startup_skip_requested), COOP_GLOBAL(online_sync_status),
    COOP_GLOBAL(demo_trial_overlay_active), COOP_GLOBAL(demo_trial_overlay_alpha_ms),
    COOP_GLOBAL(terrain_render_target), COOP_GLOBAL(highscore_active_record.player_name),
    COOP_SPAN(highscore_active_record.score_xp, highscore_active_record.most_used_weapon_id),
    COOP_SPAN(highscore_active_record.random_tag, highscore_active_record.sentinel_ff), COOP_GLOBAL(highscore_table),
    COOP_GLOBAL(default_player_name), COOP_FIELD(weapon_table, name), COOP_FIELD(weapon_table, shot_sfx_base_id),
    COOP_FIELD(weapon_table, reload_sfx_id), COOP_GLOBAL(config_blob.direction_arrow_flags),
    COOP_GLOBAL(config_blob.shadows_enabled), COOP_GLOBAL(config_blob.flame_glow_enabled),
    COOP_GLOBAL(config_blob.smoke_enabled), COOP_GLOBAL(config_blob.ui_info_texts), COOP_GLOBAL(config_blob.sfx_volume),
    COOP_GLOBAL(config_blob.music_volume),
    // The screen before this one: a tick skips its Telekinetic pickup and corpse
    // fading only after the mods menu or a plugin, which no co-op run follows,
    // and each machine came to the run its own way. The mods' runtime, which no
    // run starts.
    COOP_GLOBAL(game_state_prev), COOP_GLOBAL(plugin_runtime_active_latch),
    // Tables the game sets up at startup and no tick writes: the perk ids, the
    // quest, perk, bonus, weapon and effect tables' fixed parts (the weapons'
    // storage view, weapon_ammo_class, starts four bytes before the table), the
    // effects' atlas steps, a message, and the Grim interface.
    COOP_SPAN(perk_id_antiperk, perk_id_max), COOP_GLOBAL(quest_meta_table), COOP_GLOBAL(quest_meta_cursor),
    COOP_GLOBAL(quest_monster_vision_meta), COOP_FIELD(perk_meta_table, name), COOP_FIELD(perk_meta_table, description),
    COOP_FIELD(bonus_meta_table, label), COOP_FIELD(bonus_meta_table, description),
    COOP_FIELD(bonus_meta_table, icon_id), COOP_GLOBAL(effect_id_table), COOP_GLOBAL(effect_uv_step_2),
    COOP_GLOBAL(effect_uv_step_4), COOP_GLOBAL(effect_uv_step_8), COOP_GLOBAL(effect_uv_step_16),
    COOP_GLOBAL(player_overlay_auto_target_line_perk_id), COOP_GLOBAL(s_unhandled_creature_type),
    {(const uint8_t *)&weapon_table - 4, 4, 0, 1}, COOP_GLOBAL(grim_interface_ptr),
    // What a run start or the host sets before a tick reads it, or nothing in a
    // tick reads: the time step in milliseconds (portable_step_many), the
    // screen every co-op tick runs on (GAMEPLAY), and globals run start writes
    // for nothing or for the tutorial alone.
    COOP_GLOBAL(frame_dt_ms), COOP_GLOBAL(game_state_id), COOP_GLOBAL(creature_type_count),
    COOP_GLOBAL(effect_defaults_reserved_zero), COOP_GLOBAL(effect_pool_reserved_zero),
    COOP_GLOBAL(gameplay_reset_unused_timer), COOP_GLOBAL(gameplay_run_reserved_zero),
    COOP_GLOBAL(player_reset_reserved_zero), COOP_GLOBAL(survival_reward_handout_aux_enabled),
    COOP_GLOBAL(quest_spawn_last_time_ms), COOP_GLOBAL(quest_spawn_total_creatures),
    COOP_GLOBAL(effect_template_position), COOP_GLOBAL(tutorial_stage_index), COOP_GLOBAL(tutorial_stage_timer),
    COOP_GLOBAL(tutorial_stage_transition_timer),
};
// Pointers the words hold as the index of the entry they point at: a change
// that stays within the entry names the same one.
static const CoopBytes COOP_INDEXED[] = {COOP_GLOBAL(effect_free_list_head), COOP_FIELD(effect_pool, next_free)};
// The entry of `list` that holds the byte at `p`, or null.
template <size_t N> static const CoopBytes *coop_listed(const CoopBytes (&list)[N], const uint8_t *p) {
  for (const CoopBytes &bytes : list) {
    uint32_t offset = uint32_t(p - (const uint8_t *)bytes.at);
    if (p >= (const uint8_t *)bytes.at && offset < (bytes.stride ? bytes.stride * bytes.count : bytes.size) &&
        (!bytes.stride || offset % bytes.stride < bytes.size))
      return &bytes;
  }
  return nullptr;
}

// A bake's digest: its decals and corpses, less the corpses' alpha, which the
// player's terrain transparency setting scales (fx_queue_add_rotated).
static uint32_t coop_bake_digest(const CoopBake &bake) {
  std::vector<uint32_t> words(bake.queue.size() * sizeof bake.queue[0] / 4);
  memcpy(words.data(), bake.queue.data(), words.size() * 4);
  for (const RotatedDecal &d : bake.rotated) {
    float floats[] = {d.pos.x, d.pos.y, d.scale, d.rotation, d.color.r, d.color.g, d.color.b};
    uint32_t corpse[8];
    memcpy(corpse, floats, sizeof floats);
    corpse[7] = (uint32_t)d.creature_type_id;
    words.insert(words.end(), corpse, corpse + 8);
  }
  return coop_digest(words.data(), words.size() * 4);
}

// A tick's bake reached the terrain, after every one before it.
static void coop_baked(CoopTick &entry) {
  coop.terrain = entry.terrain = coop_chain(coop.terrain, entry.bake);
  coop.baked = entry.tick;
}

// The tick's bake (fx_queue_render), its digest kept. A tick held (on a guess,
// or after a tick still held) keeps it for its confirmation and takes it off the
// queues as the bake would; any other bakes it into the terrain now, where the
// module draws even when the tick does not, as a replay does
// (terrain.baking). True in a co-op tick.
static bool coop_bake() {
  if (!coop.running)
    return false;
  int t = (int)tick;
  // A tick drawn again (coop_redraw) whose bake reached the terrain the first
  // time: the queues go as the bake takes them.
  if (t <= coop.baked) {
    fx_queue_count = fx_queue_rotated = game_effect_overflow.decal_count = 0;
    coop.baking = t;
    return true;
  }
  CoopBake &bake = coop.bakes[t & (COOP_SLOTS - 1)];
  // A held bake reaches the terrain before its slot comes round again.
  if (bake.epoch == coop.epoch && bake.tick > coop.baked && bake.tick != t)
    abort();
  bake.epoch = coop.epoch;
  bake.tick = coop.baking = t;
  bake.queue.assign(fx_queue, fx_queue + fx_queue_count);
  bake.queue.insert(bake.queue.end(), game_effect_overflow.decals,
                    game_effect_overflow.decals + game_effect_overflow.decal_count);
  bake.rotated.resize(fx_queue_rotated);
  for (int i = 0; i < fx_queue_rotated; ++i)
    bake.rotated[i] = fx_rotated(i);
  CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
  entry.bake = coop_bake_digest(bake);
  if (entry.held) {
    coop.stats.overflow_decal_holds += game_effect_overflow.decal_count > 0;
    fx_queue_count = fx_queue_rotated = game_effect_overflow.decal_count = 0;
    return true;
  }
  coop_baked(entry);
  coop.stats.unseen_bakes += !coop.drawing;
  unsigned char disabled = grim_render_disabled;
  if (game_original)
    grim_render_disabled = 0;
  game_effects_render_decals();
  grim_render_disabled = disabled;
  return true;
}

// A co-op tick's music call keeps its simulation effect (host.cpp's
// music_play_exclusive, and music_fade_out_all's latch below); what it plays,
// fades or turns down waits for the tick's confirmation, in order: this
// machine's music is never undone, and a tick drawn again (coop_redraw) after
// its music played plays none. True when it waits.
static bool coop_defer(CoopTuneKind kind, int track, float volume) {
  if (!coop.running)
    return false;
  if ((int)tick > coop.played)
    coop.tunes.push_back({(int)tick, kind, track, volume});
  return true;
}
extern "C" void music_fade_out_all_recovered(int sfx_id);
static void coop_tune_play(const CoopTune &tune) {
  uint32_t words[] = {(uint32_t)tune.kind, (uint32_t)tune.track, 0};
  memcpy(&words[2], &tune.volume, 4);
  coop.music = coop_chain(coop.music, coop_digest(words, sizeof words));
  if (!game_original || tune.track < 0)
    return;
  if (tune.kind == COOP_PLAY || tune.kind == COOP_GAME_TUNE)
    return game_music_start(tune.track, tune.kind == COOP_GAME_TUNE);
  GameShellMusic ids;
  unsigned char latch = music_playlist_randomized_latch;
  if (tune.kind == COOP_FADE)
    music_fade_out_all_recovered(tune.track);
  else
    music_track_volume[tune.track] = tune.volume;
  music_playlist_randomized_latch = latch;
}

extern "C" {
int sfx_play_recovered(int sfx_id, float volume);
int sfx_play_panned_recovered(int sfx_id, const vec2f_t *pos, float volume);
// A tick a rollback runs again played its sounds and started their cooldowns
// the first time; it plays none and leaves the cooldowns be (game/audio_timing.cpp).
int sfx_play(int sfx_id, float volume) { return coop.quiet ? -1 : sfx_play_recovered(sfx_id, volume); }
int sfx_play_panned(int sfx_id, const vec2f_t *pos, float volume) {
  return coop.quiet ? -1 : sfx_play_panned_recovered(sfx_id, pos, volume);
}
bool game_coop_quiet() { return coop.quiet; }
// In a co-op tick a fade only clears the playlist latch, as the original's
// does in the verifier's run (music on, ready); it fades on confirmation.
void music_fade_out_all(int sfx_id) {
  if (!coop.running)
    return music_fade_out_all_recovered(sfx_id);
  if (music_ready && !config_blob.music_disabled && !config_blob.sound_disabled)
    music_playlist_randomized_latch = 0;
  coop_defer(COOP_FADE, game_shell_track(sfx_id), 0);
}
void game_music_volume(int id, float volume) {
  int track = game_shell_track(id);
  if (!coop_defer(COOP_VOLUME, track, volume))
    music_track_volume[track] = volume;
}
}

static bool coop_same(const CoopInput &a, const CoopInput &b) {
  return !memcmp(&a.input, &b.input, sizeof a.input) && a.cmd == b.cmd;
}
static bool coop_real(int seat, int t) {
  const CoopRecord &r = coop.records[seat][t & (COOP_RING - 1)];
  return r.tick == t && r.real;
}
static bool coop_final(int t) { return coop_real(0, t) && coop_real(1, t); }
// A seat's record for a tick: the one received (or stood in), else a guess
// from its last real one before, which holds the same axes, aim and keys but
// no presses and no perk request.
static CoopInput coop_record(int seat, int t, bool &guessed) {
  const CoopRecord &r = coop.records[seat][t & (COOP_RING - 1)];
  guessed = r.tick != t || !r.real;
  if (r.tick == t)
    return r.record;
  for (int s = t - 1; s >= 0 && s > t - COOP_RING; --s) {
    const CoopRecord &last = coop.records[seat][s & (COOP_RING - 1)];
    if (last.tick == s && last.real) {
      CoopInput guess = {last.record.input, 0};
      guess.input.flags &= ~(2u | 4u);
      return guess;
    }
  }
  return {COOP_NEUTRAL, 0};
}

// Whether the state allows a perk command, as portable_step_many checks it.
static bool coop_perk_valid() {
  return cfg.mode != GAME_MODE_RUSH && any_player_alive() && perk_pending_count > 0;
}

// How far past the last confirmed tick the next tick may run on predictions:
// the run's window, narrowed late in a long Survival run. It bounds only this
// machine's speculation: each peer narrows its own.
static int coop_window() {
  bool late = cfg.mode == GAME_MODE_SURVIVAL && (int)run_elapsed_ms > coop.late_ms;
  return late ? std::min(coop.rmax, COOP_LATE_RMAX) : coop.rmax;
}

// The choices the open perk menu offers, as portable_step_many counts them.
static int coop_offered() {
  return player_state_table[0].perk_counts[PERK_ID_PERK_MASTER] > 0   ? 7
         : player_state_table[0].perk_counts[PERK_ID_PERK_EXPERT] > 0 ? 6
                                                                      : 5;
}

// The tick's perk command from the seats' requests, on the state it starts
// from, as portable_step_many takes commands: with the menu closed, an open
// request (player one's first) opens it and makes its player the picker; with
// it open, only the picker's request counts, a choice offered (the choices are
// fresh: the tick that opened the menu made them) or none, which cancels.
static uint32_t coop_command(const CoopInput *seats) {
  bool valid = coop_perk_valid();
  bool open[2] = {seats[0].cmd == COOP_OPEN, seats[1].cmd == COOP_OPEN};
  if (perk_menu_open) {
    coop.stats.dropped_opens += open[0] + open[1];
    int choice = seats[perk_picker].cmd - 1;
    if (!valid || choice < 0 || choice >= coop_offered() || perk_choice_ids[choice] <= 0)
      return 0;
    coop.stats.extra_picks += choice >= 5;
    commands[0] = {1, choice};
    return 1;
  }
  if (!open[0] && !open[1])
    return 0;
  if (!valid) {
    coop.stats.dropped_opens += open[0] + open[1];
    return 0;
  }
  perk_picker = open[0] ? 0 : 1;
  ++coop.stats.opens[perk_picker];
  coop.stats.double_opens += open[0] && open[1];
  coop.stats.survivor_menus += player_state_table[0].health <= 0 || player_state_table[1].health <= 0;
  commands[0] = {2, 0};
  return 1;
}

static void coop_capture(int t) {
  // Overflow decals wait only within a tick: effects_update queues them, and
  // the same tick's world draw bakes them (coop_bake).
  if (string_used != coop.strings || game_effect_overflow.decal_count)
    abort();
  CoopSlot &slot = coop.slots[t & (COOP_SLOTS - 1)];
  slot.epoch = coop.epoch;
  slot.tick = t;
  slot.state.resize(run_state_size());
  run_state_write(slot.state.data());
  slot.overflow_free = game_effect_overflow.free != nullptr;
  coop.stats.slot_bytes = std::max(coop.stats.slot_bytes, (int32_t)slot.state.size());
}

// The run goes back to the state before tick `t`, which runs next. This
// machine's screen, cursor, settings and music stay; nothing draws gameplay RNG;
// the music ticks from `t` on queued is dropped, and a frame showing a state it
// took back shows none.
static void coop_rewind(int t) {
  const CoopSlot &slot = coop.slots[t & (COOP_SLOTS - 1)];
  if (slot.epoch != coop.epoch || slot.tick != t || game_state_id != GAME_STATE_GAMEPLAY)
    abort();
  CoopScreen screen = coop_screen();
  LiveSettings outside;
  if (game_live)
    outside = live_settings();
  run_restore([&] { run_state_read(slot.state.data()); });
  coop.screen = coop_screen();
  coop_screen_install(screen);
  if (game_live)
    live_install(outside);
  auto dropped =
      std::find_if(coop.tunes.begin(), coop.tunes.end(), [&](const CoopTune &tune) { return tune.tick >= t; });
  coop.tunes.erase(dropped, coop.tunes.end());
  for (int s = t; s < coop.next; ++s)
    coop.ticks[s & (COOP_RING - 1)].tick = -1;
  if (coop.drawn >= t)
    coop.drawn = -1;
  coop.next = t;
}
// A rollback to the state before tick `t`.
static void coop_restore(int t) {
  bool overflow = game_effect_overflow.active > 0, freed = game_effect_overflow.free != nullptr;
  for (int s = t; s < coop.next; ++s)
    freed |= coop.slots[s & (COOP_SLOTS - 1)].overflow_free;
  ++coop.stats.rollbacks;
  ++coop.stats.depths[coop.next - t - 1];
  ++coop.stats.session.depths[coop.next - t - 1];
  coop.stats.max_depth = std::max(coop.stats.max_depth, coop.next - t);
  coop_rewind(t);
  coop.stats.overflow_rollbacks += overflow || game_effect_overflow.active > 0;
  coop.stats.overflow_free_rollbacks += freed;
}

// The run goes back to the state after its last confirmed tick, which its
// recording ends on, from any it ran past it on predictions.
static void coop_settle() {
  if (coop.next - 1 > coop.confirmed)
    coop_rewind(coop.confirmed + 1);
}

// One tick, from the state before it: `quiet` when it ran before, `draw` for
// the frame's newest.
static void coop_tick(int t, bool quiet, bool draw) {
  bool guessed[2];
  CoopInput used[2] = {coop_record(0, t, guessed[0]), coop_record(1, t, guessed[1])};
  for (int seat = 0; seat < 2; ++seat)
    coop.stats.guesses[seat] += guessed[seat];
  bool late = coop_window() < coop.rmax;
  coop.stats.late_ticks += late;
  if (guessed[0] || guessed[1]) {
    coop.stats.guessed_lead = std::max(coop.stats.guessed_lead, t - coop.confirmed);
    if (late)
      coop.stats.late_lead = std::max(coop.stats.late_lead, t - coop.confirmed);
  }
  CoopRun run;
  if (game_paused_flag)
    abort();
  coop_capture(t);
  // A tick that ran before left who lived after it there, and one drawn again
  // (coop_redraw) its bake and music, which it presented the first time.
  CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
  const CoopTick before = entry;
  bool baked = t <= coop.baked, played = t <= coop.played;
  bool held = !baked && (guessed[0] || guessed[1] || coop.baked != t - 1);
  entry = {t, {used[0], used[1]}, 0, {}, -1, 0, 0, 0, 0, 0, held, 0};
  in[0] = used[0].input;
  in[1] = used[1].input;
  entry.commands = coop_command(used);
  entry.command = commands[0];
  entry.picker = perk_picker;
  unsigned char disabled = grim_render_disabled;
  grim_render_disabled = disabled || !draw;
  coop.running = true;
  coop.quiet = quiet;
  coop.drawing = draw;
  coop.draws += draw;
  coop.baking = -1;
  bool accepted = portable_step_many(entry.commands);
  // Inside the original the run's screen fades in by its ticks' time, as the
  // client's runs' does (live_timeline): its HUD shows through it.
  if (game_live)
    live_timeline();
  coop.running = coop.quiet = false;
  grim_render_disabled = disabled;
  // Every tick draws its world, which bakes.
  if (!accepted || coop.baking != t)
    abort();
  if (!perk_menu_open)
    perk_picker = -1;
  if (baked) {
    entry.bake = before.bake;
    entry.terrain = before.terrain;
  }
  if (played)
    entry.music = before.music;
  entry.living = (uint8_t)((player_state_table[0].health > 0) | (player_state_table[1].health > 0) << 1);
  if (quiet) {
    coop.stats.revised_deaths += entry.living != before.living;
    coop.stats.revised_wipes += !entry.living != !before.living;
  }
  if (draw)
    coop.drawn = t;
  entry.hash = coop_digest(output, coop_words() * 4);
  if (coop.states) {
    // Less what a restore keeps of this machine's (run_restore).
    std::vector<uint8_t> state(run_state_size());
    run_restore([&] {
      ui_mouse_x = ui_mouse_y = 0;
      survival_xp_smoothed = 0;
      run_state_write(state.data());
    });
    entry.state = coop_digest(state.data(), state.size());
  }
  coop.heard = std::max(coop.heard, t);
  coop.next = t + 1;
}

// The frame's newest tick drew nothing: the run stopped sooner than the frame's
// ticks were counted (its end, a perk menu waiting for its picker), or went back
// past an end the peers agreed on. It runs again, quiet, and draws, so the frame
// shows no state a rollback took back. What it presented stays as it was.
static void coop_redraw() {
  int t = coop.next - 1;
  coop_rewind(t);
  coop_tick(t, true, true);
  ++coop.stats.resimulated;
}

// This machine's kept hash of a confirmed tick from `hashes_from` on.
static CoopHash &coop_hash(int t) { return coop.hashes[t - coop.hashes_from]; }
// The peer's hash for a tick both confirmed: another than this machine's stops
// the run.
static void coop_check(int t, uint32_t hash) {
  CoopHash &entry = coop_hash(t);
  coop.stats.checked += !entry.checked;
  entry.checked = true;
  if (entry.hash == hash || coop.desync.tick >= 0)
    return;
  coop.desync = {t, entry.hash, hash};
  coop.hold |= COOP_HOLD_STOP;
}
// A hash the peer reported for one of its confirmed ticks: checked now when this
// machine confirmed the tick too, else once it does; one already let go was
// compared.
static void coop_reported(int t, uint32_t hash) {
  if (t > coop.confirmed)
    coop.reported[t & (COOP_RING - 1)] = {t, hash};
  else if (t >= coop.hashes_from)
    coop_check(t, hash);
}
// The peer's hash for tick `t` arrived: compared, or kept for its confirmation.
static bool coop_heard(int t) {
  return t < coop.hashes_from || coop.reported[t & (COOP_RING - 1)].tick == t ||
         (t <= coop.confirmed && coop_hash(t).checked);
}
// The kept hashes up to tick `t` go: the partner holds them and this machine
// compared the partner's.
static void coop_release(int t) {
  for (; coop.hashes_from <= t; ++coop.hashes_from)
    coop.hashes.pop_front();
}
// A confirmed tick joins the recording of a run inside the original
// (host/session.inc live.replay), as the verifier reads a 2-player run: both
// players' inputs, then its command, whose player live.pickers names.
static void coop_record(const CoopTick &entry) {
  live_append(&entry.used[0].input, sizeof(PortableInput));
  live_append(&entry.used[1].input, sizeof(PortableInput));
  live_append(&entry.commands, sizeof entry.commands);
  live_append(&entry.command, entry.commands * sizeof entry.command);
  if (entry.commands)
    live.pickers.push_back(entry.picker);
}
// A tick is confirmed once it ran on both seats' real records, as every tick
// before it did. Between two peers its hash is kept from then on.
static void coop_confirm() {
  while (coop.confirmed + 1 < coop.next && coop_final(coop.confirmed + 1)) {
    int t = ++coop.confirmed;
    if (game_live)
      coop_record(coop.ticks[t & (COOP_RING - 1)]);
    if (coop.local < 0)
      continue;
    coop.hashes.push_back({coop.ticks[t & (COOP_RING - 1)].hash, false, -INFINITY});
    const CoopReported &reported = coop.reported[t & (COOP_RING - 1)];
    if (reported.tick == t)
      coop_check(t, reported.hash);
  }
}
// The run reached its last tick and confirmed it: the run's end, or the one the
// peers agreed on.
static bool coop_over() {
  return coop.active && coop.confirmed == coop.next - 1 && (run_down_ms < 0 || coop.next - 1 >= coop.end);
}

// What confirmed ticks presented, in tick order, before any later tick runs:
// the held bakes into the terrain, drawn where the module draws, and the music.
static void coop_commit() {
  if (coop.baked < coop.confirmed) {
    coop.stats.queued_commits += fx_queue_count || fx_queue_rotated || game_effect_overflow.decal_count;
    terrain_bakes(game_original, [] {
      while (coop.baked < coop.confirmed) {
        CoopTick &entry = coop.ticks[(coop.baked + 1) & (COOP_RING - 1)];
        const CoopBake &bake = coop.bakes[(coop.baked + 1) & (COOP_SLOTS - 1)];
        if (!entry.held || bake.epoch != coop.epoch || bake.tick != coop.baked + 1)
          abort();
        terrain_bake(bake.queue.data(), bake.queue.size(), bake.rotated.data(), bake.rotated.size());
        coop_baked(entry);
      }
    });
  }
  auto tune = coop.tunes.begin();
  for (; coop.played < coop.confirmed; ++coop.played) {
    for (; tune != coop.tunes.end() && tune->tick == coop.played + 1; ++tune)
      coop_tune_play(*tune);
    coop.ticks[(coop.played + 1) & (COOP_RING - 1)].music = coop.music;
  }
  coop.tunes.erase(coop.tunes.begin(), tune);
}

// A rollback to the first unconfirmed tick that ran on a record other than the
// one known now: a guess or stand-in the real record contradicts.
static void coop_correct() {
  for (int t = coop.confirmed + 1; t < coop.next; ++t) {
    const CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
    for (int seat = 0; seat < 2; ++seat) {
      const CoopRecord &r = coop.records[seat][t & (COOP_RING - 1)];
      if (r.tick == t && !coop_same(r.record, entry.used[seat])) {
        ++coop.stats.mispredictions[seat];
        coop_restore(t);
        return;
      }
    }
  }
}

static bool coop_valid(const CoopInput &record) {
  return portable_input_valid(record.input) && record.cmd <= COOP_OPEN;
}

// A seat's record for a tick from elsewhere (the partner's, or the caller's in
// solo): 1 when taken; 0 when it changes nothing, for a tick already confirmed
// or a record already held (the ticks packets send each again); -1 for one no
// peer sends, a protocol error: an invalid record, a tick out of reach (a peer
// produces at most COOP_UNACKED past what this machine acknowledged, its
// remote), another record for a tick already known, or this machine's own seat.
// Solo, a record can also stand in for the real one until it comes (`real` 0),
// or be taken back as not yet arrived (-1), so the engine guesses it; a
// rollback corrects either.
static int coop_take(int seat, int t, const CoopInput &record, int real) {
  bool solo = coop.local < 0;
  int reach = solo ? coop.confirmed + COOP_RING : coop.remote + COOP_UNACKED;
  if (!coop.active || seat < 0 || seat > 1 || t < 0 || t > reach || !coop_valid(record) ||
      (!solo && (seat == coop.local || real != 1)))
    return -1;
  CoopRecord &r = coop.records[seat][t & (COOP_RING - 1)];
  if (!solo && r.tick == t && r.real)
    return coop_same(r.record, record) ? 0 : -1;
  if (t <= coop.confirmed)
    return 0;
  r = {record, real < 0 ? -1 : t, real > 0};
  while (!solo && coop_real(seat, coop.remote + 1))
    ++coop.remote;
  return 1;
}

// This machine's perk request (Pick Perk, its key, the prompt's click): it goes
// on the next tick produced when the latest state run allows the command, the
// menu is closed and no request of its own waits.
static bool coop_ask() {
  if (!coop.active || coop.local < 0 || coop.hold || coop.asked || coop.request >= 0 || coop.picking ||
      perk_menu_open || !coop_perk_valid())
    return false;
  coop.asked = true;
  return true;
}

extern "C" {
// A co-op run of the 2-player run portable_init set up: this machine plays seat
// `local` (-1 both), `delay` ticks ahead of the run (1 to COOP_DELAY), which may
// run `rmax` ticks (up to COOP_LEAD) past its last confirmed one on
// predictions. Its first `delay` ticks' records are neutral until
// game_coop_seed sets them. 1 when it starts.
__attribute__((export_name("game_coop_start"))) int game_coop_start(int local, int delay, int rmax, uint32_t epoch) {
  if (!ready || tick != 0 || cfg.players != 2 || local < -1 || local > 1 || delay < 1 || delay > COOP_DELAY ||
      rmax < 0 || rmax > COOP_LEAD)
    return 0;
  if (coop.slots.empty()) {
    coop.slots.resize(COOP_SLOTS);
    coop.bakes.resize(COOP_SLOTS);
  }
  for (CoopSlot &slot : coop.slots)
    slot.tick = -1;
  for (CoopBake &bake : coop.bakes)
    bake.tick = -1;
  for (auto &seat : coop.records)
    for (CoopRecord &r : seat)
      r.tick = -1;
  for (CoopTick &entry : coop.ticks)
    entry.tick = -1;
  for (CoopReported &reported : coop.reported)
    reported.tick = -1;
  coop.hashes.clear();
  coop.hashes_from = 0;
  coop.desync = {-1, 0, 0};
  coop.tunes.clear();
  CoopWireStats wire = coop.stats.wire;
  CoopSessionStats session = coop.stats.session;
  coop.stats = {};
  coop.stats.wire = wire;
  coop.stats.session = session;
  coop.local = local;
  coop.delay = delay;
  coop.rmax = rmax;
  coop.epoch = epoch;
  coop.produced = coop.peer_ack = coop.remote = delay - 1;
  coop.hold = 0;
  coop.end = COOP_NO_END;
  coop.asked = coop.picking = false;
  coop.request = -1;
  coop.confirmed = coop.baked = coop.played = coop.heard = coop.drawn = -1;
  coop.next = 0;
  coop.terrain = coop.music = 0;
  for (int t = 0; t < delay; ++t)
    for (auto &seat : coop.records)
      seat[t] = {{COOP_NEUTRAL, 0}, t, true};
  coop.scratch[0] = coop.scratch[1] = {COOP_NEUTRAL, 0};
  coop.screen = coop_screen();
  coop.strings = string_used;
  perk_picker = -1;
  coop.active = true;
  return 1;
}
// Where a seat's record for one of the first `delay` ticks goes, before the
// first advance.
__attribute__((export_name("game_coop_seed"))) uintptr_t game_coop_seed(int seat, int t) {
  if (!coop.active || coop.next || seat < 0 || seat > 1 || t < 0 || t >= coop.delay)
    abort();
  return (uintptr_t)&coop.records[seat][t].record;
}
// Where the next record of a seat this machine plays goes (CoopInput).
__attribute__((export_name("game_coop_input_for"))) uintptr_t game_coop_input_for(int seat) {
  return (uintptr_t)&coop.scratch[seat];
}
__attribute__((export_name("game_coop_input"))) uintptr_t game_coop_input() {
  return game_coop_input_for(std::max(coop.local, 0));
}
// The next tick's records of the seats this machine plays, which never change
// after: the tick, or -1 while the run is `delay` ticks ahead, the peer is far
// behind acknowledging them, the session holds production or this machine's
// perk request waits for its tick's confirmation. A peer's record asks for
// the menu when game_coop_request did; the picker's, on the tick after its
// request opened the menu, takes the choice its input names (0 cancels). A
// pause holds back the players' input but not the picker's choice, which the
// run waits on: a leave that follows ends the run after it.
__attribute__((export_name("game_coop_produce"))) int game_coop_produce(double) {
  uint32_t hold = coop.picking ? coop.hold & ~COOP_HOLD_PAUSE : coop.hold;
  if (!coop.active || hold || coop.request >= 0 || coop.produced >= coop.next + coop.delay ||
      coop.produced - coop.peer_ack >= COOP_UNACKED)
    return -1;
  int t = coop.produced + 1;
  for (int seat = 0; seat < 2; ++seat) {
    if (coop.local >= 0 && seat != coop.local)
      continue;
    CoopInput record = coop.scratch[seat];
    if (coop.local >= 0 && !coop.picking)
      record.cmd = coop.asked ? COOP_OPEN : 0;
    if (!coop_valid(record) || (coop.picking && record.cmd == COOP_OPEN))
      abort();
    coop.records[seat][t & (COOP_RING - 1)] = {record, t, true};
  }
  if (coop.asked)
    coop.request = t;
  coop.asked = coop.picking = false;
  coop.produced = t;
  if (coop.local < 0)
    coop.peer_ack = t;
  return t;
}
// Test hook: a seat's record for a tick from game_coop_input_for(seat), as the
// wire takes the partner's (coop_take).
__attribute__((export_name("game_coop_deliver"))) int game_coop_deliver(int seat, int t, int real) {
  return seat < 0 || seat > 1 ? -1 : coop_take(seat, t, coop.scratch[seat], real);
}
// The frame's ticks: a rollback when a record turned out other than the one a
// tick ran on, then ticks while their records allow, at most `budget` new ones
// (ticks run again are free), each tick's confirmation presenting what it
// waited for before the next runs. Only the newest tick draws. Ticks run only
// while this machine shows the run, and not past an end the peers agreed on.
__attribute__((export_name("game_coop_advance"))) int game_coop_advance(int budget, double) {
  if (!coop.active || (coop.hold & (COOP_HOLD_START | COOP_HOLD_STOP)) || game_state_id != GAME_STATE_GAMEPLAY ||
      game_state_pending != GAME_STATE_PENDING_IDLE_SENTINEL)
    return 0;
  double start = host_clock_ms();
  // Predictions ran past the agreed end: back to the state after it.
  if (coop.next - 1 > coop.end)
    coop_restore(coop.end + 1);
  coop_correct();
  coop_confirm();
  coop_commit();
  // The newest tick the records, the window and the budget let run, final
  // ticks confirming on the way: it alone draws. A menu or the run's end
  // stopping sooner draws the tick it stopped at again (coop_redraw).
  int last = std::min({coop.produced, coop.heard + budget, coop.end});
  for (int t = coop.next, confirmed = coop.confirmed; t <= last; ++t) {
    int lead = t - (confirmed + 1);
    if (lead >= COOP_LEAD || (!coop_final(t) && lead >= coop_window())) {
      last = t - 1;
      break;
    }
    if (confirmed == t - 1 && coop_final(t))
      confirmed = t;
  }
  int fresh = 0, again = 0;
  bool stalled = false;
  for (;;) {
    int t = coop.next, lead = t - (coop.confirmed + 1);
    bool quiet = t <= coop.heard;
    if (!quiet && fresh >= budget)
      break;
    if (run_down_ms < 0 || t > coop.end || (coop.hold & COOP_HOLD_STOP))
      break;
    if (t > coop.produced || lead >= COOP_LEAD || (!coop_final(t) && lead >= coop_window())) {
      ++coop.stats.stalls;
      stalled = true;
      break;
    }
    if (perk_menu_open && !coop_real(perk_picker, t)) {
      ++coop.stats.stalls;
      ++coop.stats.picker_waits[perk_picker];
      stalled = true;
      break;
    }
    coop_tick(t, quiet, t == last);
    ++(quiet ? coop.stats.resimulated : coop.stats.ticks);
    ++(quiet ? coop.stats.session.resimulated : coop.stats.session.ticks);
    fresh += !quiet;
    again += quiet;
    coop_confirm();
    coop_commit();
    coop.stats.max_lead = std::max(coop.stats.max_lead, coop.next - (coop.confirmed + 1));
  }
  if (coop.next > 0 && coop.drawn != coop.next - 1) {
    coop_redraw();
    ++again;
  }
  // This machine's perk request, once its tick is confirmed (the state after it
  // is the one run, production having stopped there): its seat picks when its
  // request opened the menu, else production resumes.
  if (coop.request >= 0 && coop.confirmed >= coop.request) {
    coop.picking = perk_menu_open && perk_picker == coop.local;
    coop.request = -1;
  }
  if (fresh || again) {
    double ms = host_clock_ms() - start;
    int bucket = 0;
    while (bucket < COOP_FRAME_BUCKETS - 1 && ms >= 1 << bucket)
      ++bucket;
    ++coop.stats.frame_ms[bucket];
    ++coop.stats.session.frame_ms[bucket];
    coop.stats.worst_frame_us = std::max(coop.stats.worst_frame_us, (int32_t)(ms * 1000));
  }
  bool waited = stalled && budget > 0 && !fresh && !(coop.hold & COOP_HOLD_PAUSE);
  coop.stats.stalled_frames += waited;
  coop.stats.session.stalled_frames += waited;
  coop.stats.frame_resimulated = std::max(coop.stats.frame_resimulated, again);
  return fresh;
}
__attribute__((export_name("game_coop_stats"))) uintptr_t game_coop_stats() { return (uintptr_t)&coop.stats; }
// Test hook: the tick whose state the frame shows, -1 for none or one a rollback
// took back.
__attribute__((export_name("game_coop_drawn"))) int game_coop_drawn() { return coop.drawn; }
// Test hook: a Survival run's window narrows once the run's time passes `ms`
// (COOP_LATE_MS).
__attribute__((export_name("game_coop_late"))) void game_coop_late(int ms) { coop.late_ms = ms; }
__attribute__((export_name("game_coop_confirmed"))) int game_coop_confirmed() { return coop.confirmed; }
__attribute__((export_name("game_coop_next"))) int game_coop_next() { return coop.next; }
__attribute__((export_name("game_coop_produced"))) int game_coop_produced() { return coop.produced; }
__attribute__((export_name("game_coop_remote"))) int game_coop_remote() { return coop.remote; }
// The first tick whose hashes differed: {tick (-1 none), this machine's, the peer's}.
__attribute__((export_name("game_coop_desync"))) uintptr_t game_coop_desync() { return (uintptr_t)&coop.desync; }
// The run's canonical words at portable_output (coop_words), co-op or not.
__attribute__((export_name("game_coop_canonical"))) int game_coop_canonical() {
  if (!coop.active)
    return coop_words();
  CoopRun run;
  return coop_words();
}
__attribute__((export_name("game_coop_hash"))) uint32_t game_coop_hash() {
  return coop_digest(output, game_coop_canonical() * 4);
}
// What tick `t` left, from its last run, 0 for a tick not run or out of the
// ring: the state's hash, its bake's digest, and once it presented them, the
// terrain's and music's digests (every bake and tune up to it, in order).
static const CoopTick *coop_tick_at(int t) {
  const CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
  return t >= 0 && entry.tick == t ? &entry : nullptr;
}
__attribute__((export_name("game_coop_hash_at"))) uint32_t game_coop_hash_at(int t) {
  return coop_tick_at(t) ? coop_tick_at(t)->hash : 0;
}
// Test hook: the record tick `t` last ran with for `seat` (CoopInput), 0 for a tick not run.
__attribute__((export_name("game_coop_used"))) uintptr_t game_coop_used(int t, int seat) {
  return coop_tick_at(t) ? (uintptr_t)&coop_tick_at(t)->used[seat & 1] : 0;
}
__attribute__((export_name("game_coop_bake_at"))) uint32_t game_coop_bake_at(int t) {
  return coop_tick_at(t) ? coop_tick_at(t)->bake : 0;
}
__attribute__((export_name("game_coop_terrain_at"))) uint32_t game_coop_terrain_at(int t) {
  return coop_tick_at(t) && t <= coop.baked ? coop_tick_at(t)->terrain : 0;
}
__attribute__((export_name("game_coop_music_at"))) uint32_t game_coop_music_at(int t) {
  return coop_tick_at(t) && t <= coop.played ? coop_tick_at(t)->music : 0;
}
// Test hook: each tick keeps a digest of the run's state after it, the keyframe
// codec's raw bytes (game_coop_state_at, like the other digests).
__attribute__((export_name("game_coop_states"))) void game_coop_states(int keep) { coop.states = keep; }
__attribute__((export_name("game_coop_state_at"))) uint32_t game_coop_state_at(int t) {
  return coop_tick_at(t) ? coop_tick_at(t)->state : 0;
}
// Test hook: a digest of this machine's music, the tracks' volumes and fades
// and which tracks' buffers play.
__attribute__((export_name("game_coop_music"))) uint32_t game_coop_music() {
  uint8_t music[sizeof music_track_volume + sizeof music_fade_out_flags + std::size(music_entry_table)];
  memcpy(music, music_track_volume, sizeof music_track_volume);
  memcpy(music + sizeof music_track_volume, music_fade_out_flags, sizeof music_fade_out_flags);
  for (size_t i = 0; i < std::size(music_entry_table); ++i)
    music[sizeof music_track_volume + sizeof music_fade_out_flags + i] =
        game_sound_playing(music_entry_table[i].buffers[0]);
  return coop_digest(music, sizeof music);
}
// Test hook: every byte of the run's state (game.py's run spans) either reaches
// a canonical word, so that flipping it changes the words, or is one
// COOP_UNHASHED names. Writes the bytes that break this, as [start, end)
// offsets into the executable's image, at portable_output; their count.
__attribute__((export_name("game_coop_audit"))) int game_coop_audit() {
  int n = game_coop_canonical();
  std::vector<uint32_t> words(output, output + n), wrong;
  auto flipped = [&](auto bytes) {
    for (uint8_t bit : {0x01, 0x80, 0xff}) {
      bytes([&](uint8_t *p) { *p ^= bit; });
      bool changed = game_coop_canonical() != n || memcmp(output, words.data(), n * 4);
      bytes([&](uint8_t *p) { *p ^= bit; });
      if (changed)
        return true;
    }
    return false;
  };
  // A listed entry flipped whole leaves the words alone; one that does not has
  // its bytes tried one by one.
  std::vector<const CoopBytes *> mixed;
  for (const CoopBytes &entry : COOP_UNHASHED)
    if (flipped([&](auto flip) {
          for (uint32_t i = 0; i < entry.count; ++i)
            for (uint32_t b = 0; b < entry.size; ++b)
              flip((uint8_t *)entry.at + i * entry.stride + b);
        }))
      mixed.push_back(&entry);
  for (int i = 0; i < game_run_span_count; ++i)
    for (uint32_t b = 0; b < game_run_spans[i].size; ++b) {
      uint8_t *p = game_run_spans[i].at + b;
      const CoopBytes *listed = coop_listed(COOP_UNHASHED, p);
      if (coop_listed(COOP_INDEXED, p) || (listed && std::find(mixed.begin(), mixed.end(), listed) == mixed.end()))
        continue;
      if (flipped([&](auto flip) { flip(p); }) != (listed != nullptr))
        continue;
      uint32_t at = uint32_t(p - game_image_exe);
      if (!wrong.empty() && wrong.back() == at)
        wrong.back() = at + 1;
      else
        wrong.insert(wrong.end(), {at, at + 1});
    }
  std::copy(wrong.begin(), wrong.end(), output);
  return (int)wrong.size() / 2;
}
// Test hook: a forced rollback to the state before tick `t`, one of the last
// COOP_LEAD run, confirmed or not. Confirmed ticks run again as they ran (their
// bakes and music would land twice in a module that draws).
__attribute__((export_name("game_coop_restore"))) int game_coop_restore(int t) {
  if (!coop.active || t < 0 || t >= coop.next || t < coop.next - COOP_LEAD)
    return 0;
  coop_restore(t);
  const CoopTick *before = coop_tick_at(t - 1);
  coop.confirmed = std::min(coop.confirmed, t - 1);
  if (coop.baked >= t) {
    coop.baked = t - 1;
    coop.terrain = before ? before->terrain : 0;
  }
  if (coop.played >= t) {
    coop.played = t - 1;
    coop.music = before ? before->music : 0;
  }
  return 1;
}
// Test hook: changes a field family the hash covers: 0 a snapshot field, 1 a
// session field, 2 a hover timer, 3 a run status counter, 4 an effect overflow
// entry (none without one), 5 two floats' signs, 6 the corpse fade, 7 friendly
// fire. 1 when changed.
__attribute__((export_name("game_coop_corrupt"))) int game_coop_corrupt(int kind) {
  if (kind == 0)
    player_state_table[1].health += 1;
  else if (kind == 1)
    ++run_down_ms;
  else if (kind == 2)
    ++telekinetic_bonus_hover_timer_ms[1];
  else if (kind == 3)
    ++(game_live ? live.run.status : game_status_blob).weapon_usage_counts[1];
  else if (kind == 4 && game_effect_overflow.extent > 0)
    game_effect_overflow.entries[0].age += 1;
  else if (kind == 5 && player_state_table[0].pos_x && player_state_table[1].pos_y) {
    player_state_table[0].pos_x = -player_state_table[0].pos_x;
    player_state_table[1].pos_y = -player_state_table[1].pos_y;
  } else if (kind == 6)
    cv_bodiesFade->value += 1;
  else if (kind == 7)
    cv_friendlyFire->value = !cv_friendlyFire->value;
  else
    return 0;
  return 1;
}
}
