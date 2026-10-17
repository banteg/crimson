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
// perk screen and this machine's menus never reach. What a tick presents waits
// for its confirmation, both inputs final: its terrain bake when the tick ran on
// a prediction, and its music. Sound plays once: a tick played again is silent.
//
// Solo (game_coop_start with local -1), the caller produces both seats' records,
// and checks/game_coop.mjs drives the same engine against a plain run and through
// forced rollbacks.

extern "C" {
extern unsigned char game_paused_flag;
extern int telekinetic_bonus_hover_timer_ms[2];
}

// A seat's record for a tick: its input, and a perk request (0 none, 1..7 the
// choice picked, COOP_OPEN the menu).
struct CoopInput {
  PortableInput input;
  uint8_t cmd;
};
enum { COOP_OPEN = 8 };
// Ticks of records and per-tick results kept, states kept, and the most ticks a
// run may run ahead of its last confirmed one.
static constexpr int COOP_RING = 256, COOP_SLOTS = 16, COOP_LEAD = 12;
static const PortableInput COOP_NEUTRAL = {0, 0, 512, 512, 0};

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
  bool speculative; // run on a guess: its bake waits in bakes[]
};
// The state before a tick, and the music tables then, which a rollback puts back.
struct CoopSlot {
  uint32_t epoch;
  int tick;
  std::vector<uint8_t> state;
  sfx_volume_table_t volume;
  music_fade_out_flags_t fades;
};
// A speculative tick's bake, drawn into the terrain once the tick is confirmed.
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
// Counters for the gate and the session's telemetry. checks/game_coop.mjs reads
// them by position.
struct CoopStats {
  int32_t ticks, resimulated, rollbacks, max_depth, predictions, mispredictions, stalls;
  int32_t opens[2], double_opens, dropped_opens, survivor_menus, overflow_rollbacks;
  int32_t slot_bytes;
};

static struct {
  bool active;
  int local; // the seat this machine plays, -1 both
  int delay, rmax;
  uint32_t epoch;
  // The frontiers: the last tick produced, acknowledged by the peer, confirmed
  // and baked; the next tick to run; the last tick ever run (heard).
  int produced, peer_ack, confirmed, baked, next, heard;
  bool running; // a co-op tick runs
  bool quiet;   // the tick running ran before
  CoopScreen screen;
  size_t strings; // the arena as run start left it
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

static void coop_stop() { coop.active = false; }

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
// snapshot less what only presentation reads, the session's fields, the
// Telekinetic hover timers, the run's settings less the player's own, and the
// effect overflow's entries. Field by field: no padding or pointer reaches it.
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
  coop_put_words(run.music);
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

// FNV-1a a word at a time: a byte at a time costs a tick's hash four times as
// long, and any one word changed still changes it.
static constexpr uint32_t FNV_OFFSET = 2166136261u;
static uint32_t coop_fnv(uint32_t hash, const uint32_t *words, size_t count) {
  for (size_t i = 0; i < count; ++i)
    hash = (hash ^ words[i]) * 16777619u;
  return hash;
}

// A bake's digest: its decals and corpses, less the corpses' alpha, which the
// player's terrain transparency setting scales (fx_queue_add_rotated).
static uint32_t coop_bake_digest(const fx_queue_entry_t *queue, size_t queued, const RotatedDecal *rotated,
                                 size_t corpses) {
  uint32_t hash = coop_fnv(FNV_OFFSET, (const uint32_t *)queue, queued * sizeof *queue / 4);
  for (size_t i = 0; i < corpses; ++i) {
    const RotatedDecal &d = rotated[i];
    float words[] = {d.pos.x, d.pos.y, d.scale, d.rotation, d.color.r, d.color.g, d.color.b};
    hash = coop_fnv(hash, (const uint32_t *)words, 7);
    hash = coop_fnv(hash, (const uint32_t *)&d.creature_type_id, 1);
  }
  return hash;
}

// The tick's bake (fx_queue_render): its digest, and on a speculative tick the
// bake itself, held for the tick's confirmation and taken off the queues as the
// bake would. True when held.
static bool coop_bake_held() {
  if (!coop.running)
    return false;
  CoopBake &bake = coop.bakes[tick & (COOP_SLOTS - 1)];
  bake.queue.assign(fx_queue, fx_queue + fx_queue_count);
  bake.queue.insert(bake.queue.end(), game_effect_overflow.decals,
                    game_effect_overflow.decals + game_effect_overflow.decal_count);
  bake.rotated.resize(fx_queue_rotated);
  for (int i = 0; i < fx_queue_rotated; ++i)
    bake.rotated[i] = {fx_rotated_pos_x[i], fx_rotated_scale[i], fx_rotated_rotation[i],
                       fx_rotated_creature_type_id[i], fx_rotated_color_r[i]};
  CoopTick &entry = coop.ticks[tick & (COOP_RING - 1)];
  entry.bake = coop_bake_digest(bake.queue.data(), bake.queue.size(), bake.rotated.data(), bake.rotated.size());
  if (!entry.speculative) {
    bake.tick = -1;
    return false;
  }
  bake.epoch = coop.epoch;
  bake.tick = (int)tick;
  fx_queue_count = fx_queue_rotated = game_effect_overflow.decal_count = 0;
  return true;
}

// A co-op tick's music call keeps its simulation effect (host.cpp's
// music_play_exclusive, and music_fade_out_all's latch below); what it plays,
// fades or turns down waits for the tick's confirmation, in order. True when
// it waits.
static bool coop_defer(CoopTuneKind kind, int track, float volume) {
  if (!coop.running)
    return false;
  coop.tunes.push_back({(int)tick, kind, track, volume});
  return true;
}
extern "C" void music_fade_out_all_recovered(int sfx_id);
static void coop_tune_play(const CoopTune &tune) {
  if (!game_original)
    return;
  unsigned char latch = music_playlist_randomized_latch;
  if (tune.kind == COOP_PLAY)
    music_play_exclusive_recovered(tune.track);
  else if (tune.kind == COOP_FADE)
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

// The tick's perk command from the seats' requests, on the state it starts
// from, as portable_step_many takes commands: with the menu closed, an open
// request (player one's first) opens it and makes its player the picker; with
// it open, only the picker's request counts, a choice offered (the choices are
// fresh: the tick that opened the menu made them) or none, which cancels.
static uint32_t coop_command(const CoopInput *seats) {
  bool valid = cfg.mode != GAME_MODE_RUSH && any_player_alive() && perk_pending_count > 0;
  bool open[2] = {seats[0].cmd == COOP_OPEN, seats[1].cmd == COOP_OPEN};
  if (perk_menu_open) {
    coop.stats.dropped_opens += open[0] + open[1];
    int choice = seats[perk_picker].cmd - 1;
    int offered = player_state_table[0].perk_counts[PERK_ID_PERK_MASTER] > 0   ? 7
                  : player_state_table[0].perk_counts[PERK_ID_PERK_EXPERT] > 0 ? 6
                                                                               : 5;
    if (!valid || choice < 0 || choice >= offered || perk_choice_ids[choice] <= 0)
      return 0;
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
  if (string_used != coop.strings)
    abort();
  CoopSlot &slot = coop.slots[t & (COOP_SLOTS - 1)];
  slot.epoch = coop.epoch;
  slot.tick = t;
  slot.state.resize(run_state_size());
  run_state_write(slot.state.data());
  memcpy(slot.volume, music_track_volume, sizeof slot.volume);
  memcpy(slot.fades, music_fade_out_flags, sizeof slot.fades);
  coop.stats.slot_bytes = std::max(coop.stats.slot_bytes, (int32_t)slot.state.size());
}

// The run goes back to the state before tick `t`, which runs next. This
// machine's screen, cursor and settings stay; nothing draws gameplay RNG; what
// the ticks from `t` on presented and had not confirmed is dropped.
static void coop_restore(int t) {
  const CoopSlot &slot = coop.slots[t & (COOP_SLOTS - 1)];
  if (slot.epoch != coop.epoch || slot.tick != t || game_state_id != GAME_STATE_GAMEPLAY)
    abort();
  bool overflow = game_effect_overflow.active > 0;
  CoopScreen screen = coop_screen();
  LiveSettings outside;
  if (game_live)
    outside = live_settings();
  run_restore([&] { run_state_read(slot.state.data()); });
  coop.screen = coop_screen();
  coop_screen_install(screen);
  if (game_live)
    live_install(outside);
  memcpy(music_track_volume, slot.volume, sizeof slot.volume);
  memcpy(music_fade_out_flags, slot.fades, sizeof slot.fades);
  ++coop.stats.rollbacks;
  coop.stats.max_depth = std::max(coop.stats.max_depth, coop.next - t);
  coop.stats.overflow_rollbacks += overflow || game_effect_overflow.active > 0;
  auto dropped =
      std::find_if(coop.tunes.begin(), coop.tunes.end(), [&](const CoopTune &tune) { return tune.tick >= t; });
  coop.tunes.erase(dropped, coop.tunes.end());
  for (int s = t; s < coop.next; ++s)
    coop.ticks[s & (COOP_RING - 1)].tick = -1;
  coop.next = t;
}

// One tick, from the state before it: `quiet` when it ran before, `draw` for
// the frame's newest.
static void coop_tick(int t, bool quiet, bool draw) {
  bool guessed[2];
  CoopInput used[2] = {coop_record(0, t, guessed[0]), coop_record(1, t, guessed[1])};
  coop.stats.predictions += guessed[0] || guessed[1];
  CoopRun run;
  if (game_paused_flag)
    abort();
  coop_capture(t);
  CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
  entry = {t, {used[0], used[1]}, 0, {}, -1, 0, FNV_OFFSET, guessed[0] || guessed[1] || coop.confirmed != t - 1};
  in[0] = used[0].input;
  in[1] = used[1].input;
  entry.commands = coop_command(used);
  entry.command = commands[0];
  entry.picker = perk_picker;
  unsigned char disabled = grim_render_disabled;
  grim_render_disabled = disabled || !draw;
  coop.running = true;
  coop.quiet = quiet;
  bool accepted = portable_step_many(entry.commands);
  coop.running = coop.quiet = false;
  grim_render_disabled = disabled;
  if (!accepted)
    abort();
  if (!perk_menu_open)
    perk_picker = -1;
  entry.hash = coop_fnv(FNV_OFFSET, output, coop_words());
  coop.heard = std::max(coop.heard, t);
  coop.next = t + 1;
}

// A tick is confirmed once it ran on both seats' real records, as every tick
// before it did.
static void coop_confirm() {
  while (coop.confirmed + 1 < coop.next && coop_final(coop.confirmed + 1))
    ++coop.confirmed;
}

// What confirmed ticks presented: the held bakes into the terrain, where the
// module draws, and the music, in order.
static void coop_commit() {
  std::vector<const CoopBake *> held;
  for (int t = coop.baked + 1; t <= coop.confirmed; ++t) {
    if (!coop.ticks[t & (COOP_RING - 1)].speculative)
      continue;
    const CoopBake &bake = coop.bakes[t & (COOP_SLOTS - 1)];
    if (bake.epoch != coop.epoch || bake.tick != t)
      abort();
    held.push_back(&bake);
  }
  if (game_live && !held.empty())
    terrain_bakes([&] {
      for (const CoopBake *bake : held)
        terrain_bake(bake->queue.data(), bake->queue.size(), bake->rotated.data(), bake->rotated.size());
    });
  coop.baked = coop.confirmed;
  auto played = coop.tunes.begin();
  for (; played != coop.tunes.end() && played->tick <= coop.confirmed; ++played)
    coop_tune_play(*played);
  coop.tunes.erase(coop.tunes.begin(), played);
}

// A rollback to the first unconfirmed tick that ran on a record other than the
// one known now: a guess or stand-in the real record contradicts.
static void coop_correct() {
  for (int t = coop.confirmed + 1; t < coop.next; ++t) {
    const CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
    for (int seat = 0; seat < 2; ++seat) {
      const CoopRecord &r = coop.records[seat][t & (COOP_RING - 1)];
      if (r.tick == t && !coop_same(r.record, entry.used[seat])) {
        ++coop.stats.mispredictions;
        coop_restore(t);
        return;
      }
    }
  }
}

static bool coop_valid(const CoopInput &record) {
  return portable_input_valid(record.input) && record.cmd <= COOP_OPEN;
}

extern "C" {
// A co-op run of the 2-player run portable_init set up: this machine plays seat
// `local` (-1 both), `delay` ticks ahead of the run, which may run `rmax` ticks
// past its last confirmed one on predictions. Its first `delay` ticks' records
// are neutral until game_coop_seed sets them. 1 when it starts.
__attribute__((export_name("game_coop_start"))) int game_coop_start(int local, int delay, int rmax, uint32_t epoch) {
  if (!ready || tick != 0 || cfg.players != 2 || local < -1 || local > 1 || delay < 1 || delay > 8 || rmax < 0 ||
      rmax > COOP_LEAD)
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
  coop.tunes.clear();
  coop.stats = {};
  coop.local = local;
  coop.delay = delay;
  coop.rmax = rmax;
  coop.epoch = epoch;
  coop.produced = coop.peer_ack = delay - 1;
  coop.confirmed = coop.baked = coop.heard = -1;
  coop.next = 0;
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
// after: the tick, or -1 while the run is `delay` ticks ahead or the peer is far
// behind acknowledging them.
__attribute__((export_name("game_coop_produce"))) int game_coop_produce(int) {
  if (!coop.active || coop.produced >= coop.next + coop.delay || coop.produced - coop.peer_ack >= 120)
    return -1;
  int t = coop.produced + 1;
  for (int seat = 0; seat < 2; ++seat) {
    if (coop.local >= 0 && seat != coop.local)
      continue;
    if (!coop_valid(coop.scratch[seat]))
      abort();
    coop.records[seat][t & (COOP_RING - 1)] = {coop.scratch[seat], t, true};
  }
  coop.produced = t;
  if (coop.local < 0)
    coop.peer_ack = t;
  return t;
}
// A seat's record for an unconfirmed tick from game_coop_input_for(seat), as
// the partner's arrive: `real` 1. Solo, a record can also stand in for the real
// one until it comes (0), or be taken back as not yet arrived (-1), so the
// engine guesses it; a rollback corrects either. 0 for an invalid record.
__attribute__((export_name("game_coop_deliver"))) int game_coop_deliver(int seat, int t, int real) {
  if (!coop.active || seat < 0 || seat > 1 || t <= coop.confirmed || t > coop.confirmed + COOP_RING ||
      !coop_valid(coop.scratch[seat]))
    return 0;
  coop.records[seat][t & (COOP_RING - 1)] = {coop.scratch[seat], real < 0 ? -1 : t, real > 0};
  return 1;
}
// The frame's ticks: a rollback when a record turned out other than the one a
// tick ran on, then ticks while their records allow, at most `budget` new ones
// (ticks run again are free), then confirmation and what it presents. Only the
// newest tick draws. Ticks run only while this machine shows the run.
__attribute__((export_name("game_coop_advance"))) int game_coop_advance(int budget, int) {
  if (!coop.active || game_state_id != GAME_STATE_GAMEPLAY ||
      game_state_pending != GAME_STATE_PENDING_IDLE_SENTINEL)
    return 0;
  coop_correct();
  coop_confirm();
  // The newest tick the records, the lead and the budget let run, final ticks
  // confirming on the way: it alone draws. A menu or the run's end stopping
  // sooner leaves the frame undrawn.
  int last = std::min(coop.produced, coop.heard + budget);
  for (int t = coop.next, confirmed = coop.confirmed; t <= last; ++t) {
    int lead = t - (confirmed + 1);
    if (lead >= COOP_LEAD || (!coop_final(t) && lead >= coop.rmax)) {
      last = t - 1;
      break;
    }
    if (confirmed == t - 1 && coop_final(t))
      confirmed = t;
  }
  int fresh = 0;
  for (;;) {
    int t = coop.next, lead = t - (coop.confirmed + 1);
    bool quiet = t <= coop.heard;
    if (!quiet && fresh >= budget)
      break;
    if (run_down_ms < 0)
      break;
    if (t > coop.produced || lead >= COOP_LEAD || (!coop_final(t) && lead >= coop.rmax) ||
        (perk_menu_open && !coop_real(perk_picker, t))) {
      ++coop.stats.stalls;
      break;
    }
    coop_tick(t, quiet, t == last);
    ++(quiet ? coop.stats.resimulated : coop.stats.ticks);
    fresh += !quiet;
    coop_confirm();
  }
  coop_commit();
  return fresh;
}
__attribute__((export_name("game_coop_stats"))) uintptr_t game_coop_stats() { return (uintptr_t)&coop.stats; }
__attribute__((export_name("game_coop_confirmed"))) int game_coop_confirmed() { return coop.confirmed; }
__attribute__((export_name("game_coop_next"))) int game_coop_next() { return coop.next; }
__attribute__((export_name("game_coop_produced"))) int game_coop_produced() { return coop.produced; }
// The run's canonical words at portable_output (coop_words), co-op or not.
__attribute__((export_name("game_coop_canonical"))) int game_coop_canonical() {
  if (!coop.active)
    return coop_words();
  CoopRun run;
  return coop_words();
}
__attribute__((export_name("game_coop_hash"))) uint32_t game_coop_hash() {
  return coop_fnv(FNV_OFFSET, output, game_coop_canonical());
}
// The hash after tick `t` and its bake's digest, from its last run; 0 for a
// tick not run or out of the ring.
__attribute__((export_name("game_coop_hash_at"))) uint32_t game_coop_hash_at(int t) {
  const CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
  return t >= 0 && entry.tick == t ? entry.hash : 0;
}
__attribute__((export_name("game_coop_bake_at"))) uint32_t game_coop_bake_at(int t) {
  const CoopTick &entry = coop.ticks[t & (COOP_RING - 1)];
  return t >= 0 && entry.tick == t ? entry.bake : 0;
}
// Test hook: a forced rollback to the state before tick `t`, one of the last
// COOP_SLOTS run, confirmed or not. Confirmed ticks run again as they ran (their
// bakes and music would land twice in a module that draws).
__attribute__((export_name("game_coop_restore"))) int game_coop_restore(int t) {
  if (!coop.active || t < 0 || t >= coop.next || t < coop.next - COOP_SLOTS)
    return 0;
  coop_restore(t);
  coop.confirmed = std::min(coop.confirmed, t - 1);
  coop.baked = std::min(coop.baked, t - 1);
  return 1;
}
// Test hook: changes one word of a field family the hash covers: 0 a snapshot
// field, 1 a session field, 2 a hover timer, 3 a run status counter, 4 an effect
// overflow entry (none without one). 1 when changed.
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
  else
    return 0;
  return 1;
}
}
