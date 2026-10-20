// A replay's keyframes and terrain history, for seeking (host/watch.inc,
// docs/rewrite/replay-viewer.md). A keyframe is the run's state at a tick: the
// executable's per-run globals (game.py's run spans, which a run start resets)
// and the session's own (host.cpp's), zstd-packed. The terrain is a render
// target that drawn ticks bake decals and corpses into (fx_queue_render), so a
// seek rebuilds it: from the nearest copy of it the host keeps (the preparing
// pass bakes every tick and copies the terrain as the run starts and every
// half minute after), then every logged bake up to the keyframe, through the
// original's own fx_queue_render.
#include <algorithm>
#include "effect_overflow.h"

extern "C" {
struct GameSpan {
  unsigned char *at;
  uint32_t size;
};
extern const GameSpan game_run_spans[];
extern const int game_run_span_count;
void fx_queue_render_recovered();
int platform_texture_host_id(int handle);
extern int terrain_render_target;
}

// The session's own state a tick reads or writes (host.cpp), and the effect
// overflow's (game/effect_overflow.cpp).
struct KeyframeHost {
  PortableConfig config;
  uint32_t rng, tick;
  bool ready, menu_requested, perk_menu_open, running_down;
  int perk_picker;
  int run_down_ms;
  size_t string_used;
  unsigned char preserve_bugs;
  // The first hit's music latch (projectile_update): it decides whether a hit
  // draws a random sound, and a run keeps it with the music it starts.
  unsigned char music_latch;
  // The screen's transition, which a death turns down and the HUD and world
  // fade by (gameplay_render_world); the run keeps it with the screen's elements.
  unsigned char transition_direction;
  int timeline;
  LiveSettings run;
  effect_entry_t *overflow_free;
  int overflow_active, overflow_extent, overflow_decals;
};

struct Keyframe {
  int tick;       // ticks played before it
  size_t at;      // the next tick's place in the recording
  size_t batches; // logged bakes before it
  std::vector<uint8_t> packed;
};

// The run's state as raw bytes, for a copy kept on this machine: the run spans,
// the session's fields, and the effect overflow's entries in use and decals
// queued. The run's strings stay out: only run start adds to them.
static size_t run_state_size() {
  size_t size = sizeof(KeyframeHost) + (size_t)game_effect_overflow.extent * sizeof(effect_entry_t) +
                (size_t)game_effect_overflow.decal_count * sizeof(fx_queue_entry_t);
  for (int i = 0; i < game_run_span_count; ++i)
    size += game_run_spans[i].size;
  return size;
}

static uint8_t *run_state_write(uint8_t *out) {
  for (int i = 0; i < game_run_span_count; ++i)
    out = (uint8_t *)memcpy(out, game_run_spans[i].at, game_run_spans[i].size) + game_run_spans[i].size;
  // Padding zeroed: copies of one state are the same bytes (checks/game_coop.mjs).
  KeyframeHost host;
  memset(&host, 0, sizeof host);
  host.config = cfg;
  host.rng = rng;
  host.tick = tick;
  host.ready = ready;
  host.menu_requested = menu_requested;
  host.perk_menu_open = perk_menu_open;
  host.running_down = running_down;
  host.perk_picker = perk_picker;
  host.run_down_ms = run_down_ms;
  host.string_used = string_used;
  host.preserve_bugs = portable_preserve_bugs;
  host.music_latch = music_playlist_randomized_latch;
  host.transition_direction = ui_transition_direction;
  host.timeline = ui_elements_timeline;
  host.run = live.run;
  host.overflow_free = game_effect_overflow.free;
  host.overflow_active = game_effect_overflow.active;
  host.overflow_extent = game_effect_overflow.extent;
  host.overflow_decals = game_effect_overflow.decal_count;
  out = (uint8_t *)memcpy(out, &host, sizeof host) + sizeof host;
  size_t entries = (size_t)host.overflow_extent * sizeof(effect_entry_t),
         decals = (size_t)host.overflow_decals * sizeof(fx_queue_entry_t);
  out = (uint8_t *)memcpy(out, game_effect_overflow.entries, entries) + entries;
  return (uint8_t *)memcpy(out, game_effect_overflow.decals, decals) + decals;
}

static const uint8_t *run_state_read(const uint8_t *in) {
  for (int i = 0; i < game_run_span_count; ++i) {
    memcpy(game_run_spans[i].at, in, game_run_spans[i].size);
    in += game_run_spans[i].size;
  }
  KeyframeHost host;
  memcpy(&host, in, sizeof host);
  in += sizeof host;
  cfg = host.config;
  rng = host.rng;
  tick = host.tick;
  ready = host.ready;
  menu_requested = host.menu_requested;
  perk_menu_open = host.perk_menu_open;
  running_down = host.running_down;
  perk_picker = host.perk_picker;
  run_down_ms = host.run_down_ms;
  string_used = host.string_used;
  portable_preserve_bugs = host.preserve_bugs;
  music_playlist_randomized_latch = host.music_latch;
  ui_transition_direction = host.transition_direction;
  ui_elements_timeline = host.timeline;
  live.run = host.run;
  game_effect_overflow.free = host.overflow_free;
  game_effect_overflow.active = host.overflow_active;
  game_effect_overflow.extent = host.overflow_extent;
  game_effect_overflow.decal_count = host.overflow_decals;
  size_t entries = (size_t)host.overflow_extent * sizeof(effect_entry_t),
         decals = (size_t)host.overflow_decals * sizeof(fx_queue_entry_t);
  memcpy(game_effect_overflow.entries, in, entries);
  memcpy(game_effect_overflow.decals, in + entries, decals);
  portable_custom_quest =
      (cfg.mode == GAME_MODE_QUEST && cfg.major == 0 && cfg.minor == 0) ? &custom_quest_meta : nullptr;
  return in + entries + decals;
}

// A keyframe packs the run's state with its strings.
static Keyframe keyframe_capture(int at_tick, size_t at, size_t batches) {
  std::vector<uint8_t> state(run_state_size() + string_used);
  memcpy(run_state_write(state.data()), string_arena, string_used);
  return {at_tick, at, batches, zstd_pack(state, 1)};
}

static void keyframe_restore(const Keyframe &key) {
  std::vector<uint8_t> state = zstd_unpack(key.packed.data(), key.packed.size(), 64u << 20);
  memcpy(string_arena, run_state_read(state.data()), string_used);
}

// A run restored where the player plays on (practice's retry, a co-op
// rollback) keeps what only this machine shows: the cursor, and the HUD's XP
// bar, which would jump back.
extern "C" int survival_xp_smoothed;
template <class Restore> static void run_restore(Restore restore) {
  float mouse_x = ui_mouse_x, mouse_y = ui_mouse_y;
  int xp = survival_xp_smoothed;
  restore();
  ui_mouse_x = mouse_x;
  ui_mouse_y = mouse_y;
  survival_xp_smoothed = xp;
}

// A corpse fx_queue_render bakes (fx_queue_add_rotated's arrays, one entry).
struct RotatedDecal {
  vec2f_t pos;
  float scale, rotation;
  int creature_type_id;
  effect_color_t color;
};
static RotatedDecal fx_rotated(int i) {
  return {fx_rotated_pos_x[i], fx_rotated_scale[i], fx_rotated_rotation[i], fx_rotated_creature_type_id[i],
          fx_rotated_color_r[i]};
}
static void fx_rotated_set(int i, const RotatedDecal &d) {
  fx_rotated_pos_x[i] = d.pos;
  fx_rotated_scale[i] = d.scale;
  fx_rotated_rotation[i] = d.rotation;
  fx_rotated_creature_type_id[i] = d.creature_type_id;
  fx_rotated_color_r[i] = d.color;
}

// One bake: the tick it came with, and where its decals and corpses start in the logs.
struct DecalBatch {
  int tick;
  size_t queue, rotated;
};

// A copy of the terrain after the first `batches` bakes, the host's texture `id`.
struct TerrainShot {
  size_t batches;
  int tick, id;
};
// Copies of the terrain start this far apart and spread out, every other one
// dropped, past the cap: each holds a whole render target.
static constexpr int TERRAIN_SHOT_TICKS = 1800;
// The host draws ground targets at 2x density: eight default 2048-square RGBA
// copies retain the previous 128 MiB budget (32 copies at 1024 square).
static constexpr size_t TERRAIN_SHOTS = 8;
static constexpr int TERRAIN_SHOT_IDS = 1 << 30; // host texture ids the copies take

// A bake log, zstd-packed a block at a time: a long run bakes millions of
// entries, more than the browser's memory holds as they are.
template <typename T> struct PackedLog {
  static constexpr size_t BLOCK = 1 << 16; // entries a block holds
  std::vector<std::vector<uint8_t>> blocks;
  std::vector<T> open; // the entries after the last whole block
  std::vector<uint8_t> unpacked;
  size_t unpacked_block = SIZE_MAX;

  size_t size() const { return blocks.size() * BLOCK + open.size(); }
  void push(const T &entry) {
    open.push_back(entry);
    if (open.size() < BLOCK)
      return;
    const uint8_t *bytes = (const uint8_t *)open.data();
    blocks.push_back(zstd_pack(std::vector<uint8_t>(bytes, bytes + BLOCK * sizeof(T)), 1));
    open.clear();
  }
  void clear() { *this = {}; }
  // Entries [from, to) into `out`.
  void read(size_t from, size_t to, T *out) {
    for (size_t at = from; at < to;) {
      size_t block = at / BLOCK, offset = at % BLOCK, n = std::min(to - at, BLOCK - offset);
      const T *entries = open.data();
      if (block < blocks.size()) {
        if (block != unpacked_block)
          unpacked = zstd_unpack(blocks[block].data(), blocks[block].size(), BLOCK * sizeof(T)), unpacked_block = block;
        entries = (const T *)unpacked.data();
      }
      out = std::copy(entries + offset, entries + offset + n, out);
      at += n;
    }
  }
};

static struct {
  bool logging, baking; // log bakes, bake on undrawn ticks
  std::vector<DecalBatch> batches;
  PackedLog<fx_queue_entry_t> queue;
  PackedLog<RotatedDecal> rotated;
  std::vector<TerrainShot> shots;
  int shot_ticks, next_shot_id;
} terrain;

static void terrain_log_batch(int at_tick) {
  terrain.batches.push_back({at_tick, terrain.queue.size(), terrain.rotated.size()});
  for (int i = 0; i < fx_queue_count; ++i)
    terrain.queue.push(fx_queue[i]);
  for (int i = 0; i < game_effect_overflow.decal_count; ++i)
    terrain.queue.push(game_effect_overflow.decals[i]);
  for (int i = 0; i < fx_queue_rotated; ++i)
    terrain.rotated.push(fx_rotated(i));
}

static void terrain_reset() {
  terrain.batches.clear();
  terrain.queue.clear();
  terrain.rotated.clear();
  for (const TerrainShot &shot : terrain.shots)
    host_texture_release(shot.id);
  terrain.shots.clear();
  terrain.shot_ticks = TERRAIN_SHOT_TICKS;
}

static int terrain_host_id() { return platform_texture_host_id(terrain_render_target); }

// A copy of the terrain as it stands, at `at_tick`: the run's start, then every
// shot_ticks.
static void terrain_shoot(int at_tick) {
  if (!terrain.shots.empty() && at_tick - terrain.shots.back().tick < terrain.shot_ticks)
    return;
  if (terrain.shots.size() >= TERRAIN_SHOTS) {
    // Release before allocating the next copy, so the peak also fits the cap.
    std::vector<TerrainShot> kept;
    for (size_t i = 0; i < terrain.shots.size(); ++i)
      if (i % 2 == 0)
        kept.push_back(terrain.shots[i]);
      else
        host_texture_release(terrain.shots[i].id);
    terrain.shots = kept;
    terrain.shot_ticks *= 2;
  }
  int id = TERRAIN_SHOT_IDS + terrain.next_shot_id++;
  host_texture_copy(id, terrain_host_id());
  terrain.shots.push_back({terrain.batches.size(), at_tick, id});
}

// One logged bake through the original's fx_queue_render: `queued` decals (the
// fx queue's, then the effect overflow's) and `corpses` corpses.
static void terrain_bake(const fx_queue_entry_t *queue, size_t queued, const RotatedDecal *rotated, size_t corpses) {
  fx_queue_count = (int)std::min(queued, (size_t)GAME_FX_QUEUE_MAX_COUNT);
  std::copy(queue, queue + fx_queue_count, fx_queue);
  game_effect_overflow.decal_count = (int)(queued - fx_queue_count);
  std::copy(queue + fx_queue_count, queue + queued, game_effect_overflow.decals);
  fx_queue_rotated = (int)corpses;
  for (int i = 0; i < fx_queue_rotated; ++i)
    fx_rotated_set(i, rotated[i]);
  game_effects_render_decals();
}

// What the run's queues hold between ticks for the next tick's bake (a Nuke
// taken after the world drew queues its kills' blood), put back after bakes
// drawn between ticks: the whole queues, past their counts too (run state, as
// the last tick left them, whenever a peer drew its bakes). fx_queue_add
// writes one entry past the most it keeps, fx_queue_add_rotated keeps 0x40.
struct TerrainQueued {
  int queued = fx_queue_count, decal_count = game_effect_overflow.decal_count, corpses = fx_queue_rotated;
  std::vector<fx_queue_entry_t> queue{fx_queue, fx_queue + GAME_FX_QUEUE_MAX_COUNT + 1},
      decals{std::begin(game_effect_overflow.decals), std::end(game_effect_overflow.decals)};
  std::vector<RotatedDecal> rotated;
  TerrainQueued() {
    for (int i = 0; i < 0x40; ++i)
      rotated.push_back(fx_rotated(i));
  }
  ~TerrainQueued() {
    fx_queue_count = queued;
    std::copy(queue.begin(), queue.end(), fx_queue);
    game_effect_overflow.decal_count = decal_count;
    std::copy(decals.begin(), decals.end(), game_effect_overflow.decals);
    fx_queue_rotated = corpses;
    for (int i = 0; i < 0x40; ++i)
      fx_rotated_set(i, rotated[i]);
  }
};

// Logged bakes drawn into the terrain between ticks, where the module draws
// (`draw`), at the run's settings (its texture scale), as its ticks draw them.
// The run's queues stay as they were.
template <class Bakes> static void terrain_bakes(bool draw, Bakes bakes) {
  TerrainQueued queued;
  unsigned char disabled = grim_render_disabled;
  if (draw)
    grim_render_disabled = 0;
  if (game_live)
    live_enter_run();
  bakes();
  if (game_live)
    live_install(live.outside);
  grim_render_disabled = disabled;
}

// The terrain as it stood after the first `batches` bakes: the nearest copy at or
// before them, then the bakes after it.
static void terrain_rebuild(size_t batches) {
  auto shot = std::upper_bound(terrain.shots.begin(), terrain.shots.end(), batches,
                               [](size_t b, const TerrainShot &s) { return b < s.batches; }) -
              1;
  host_texture_copy(terrain_host_id(), shot->id);
  terrain_bakes(true, [&] {
    std::vector<fx_queue_entry_t> queue;
    std::vector<RotatedDecal> rotated;
    for (size_t b = shot->batches; b < batches; ++b) {
      size_t queue_end = b + 1 < terrain.batches.size() ? terrain.batches[b + 1].queue : terrain.queue.size();
      size_t rotated_end = b + 1 < terrain.batches.size() ? terrain.batches[b + 1].rotated : terrain.rotated.size();
      queue.resize(queue_end - terrain.batches[b].queue);
      terrain.queue.read(terrain.batches[b].queue, queue_end, queue.data());
      rotated.resize(rotated_end - terrain.batches[b].rotated);
      terrain.rotated.read(terrain.batches[b].rotated, rotated_end, rotated.data());
      terrain_bake(queue.data(), queue.size(), rotated.data(), rotated.size());
    }
  });
}

extern "C" {
// A tick's bake into the terrain (gameplay_render_world): a replay logs it, and
// bakes it on the ticks it does not draw too, so the terrain holds every tick's.
// A co-op tick's bakes in tick order (coop_bake).
void fx_queue_render() {
  if (coop_bake())
    return;
  if (terrain.logging && (fx_queue_count || game_effect_overflow.decal_count || fx_queue_rotated))
    terrain_log_batch((int)tick);
  if (!terrain.baking)
    return game_effects_render_decals();
  unsigned char disabled = grim_render_disabled;
  grim_render_disabled = 0;
  game_effects_render_decals();
  grim_render_disabled = disabled;
}
}
