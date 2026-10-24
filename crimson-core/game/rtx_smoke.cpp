// RTX fluid smoke, after the Python port's src/crimson/render/rtx/gpu_smoke.py
// and smoke.py: native smoke spawns, captured as each tick makes them, feed one
// persistent density field the host simulates and draws (game/host_abi.h's
// host_smoke and host_smoke_draw). The sprite effects and explosion puffs the
// original would draw are left out while it runs. Capture reads the run and
// never writes it: no RNG, no state, nothing a replay or the verifier sees.
#include "crimsonland_gameplay.h"
#include "crimsonland_config_owner.h"
#include "host_abi.h"
#include <algorithm>
#include <deque>
#include <math.h>
#include <string.h>
#include <vector>

bool platform_outputs();

extern "C" {
extern int rtx_render_mode;
extern int terrain_texture_width, terrain_texture_height;
extern vec2f_t camera_offset;
int rtx_collect_sights(float *out, int capacity);
}

namespace {

const float STEP_SECONDS = 1.0f / 60.0f, FADE_SECONDS = 2.0f, GUARD_BAND = 128;
enum { GRID_SIZE = 320, PRESSURE_ITERATIONS = 12, MAX_PENDING = 1024, MAX_IMPULSES = 64, MAX_BLASTS = 16 };
// A minute of ticks, should frames stop draining them.
enum { MAX_BATCHES = 3600 };
enum Profile { ORDINARY, NUKE, MUZZLE, ROCKET };
enum Kind { BLAST, MUZZLE_JET, WAKE }; // in the order the solver ranks them

// A copied spawn (sim/smoke_events.py's SmokeEmission): scale is the full world
// diameter, expansion radial units a second.
struct Emission {
  float x, y, vx, vy, scale, r, g, b, a, rotation;
  bool effect;
  float delay, expansion, retention;
  Profile profile;
  float flow_x, flow_y;
};
// Presentation-only airflow (AtmosphereImpulse): a world-units-a-second impulse
// along start to end, or for a blast over its duration as its front expands.
struct Impulse {
  float sx, sy, ex, ey, radius, strength, curl;
  Kind kind;
  float duration, expansion_speed;
  float rank() const { return strength * radius; }
};
struct Batch {
  std::vector<Emission> emissions;
  float dt, fade;
  std::vector<Impulse> impulses;
};

// What a source's spawns take from it (smoke_source, smoke_retention): their
// retention, profile and flow, and their velocity: as spawned, given, or along
// the flow at the spawned speed (muzzle puffs, which native spawns sideways).
struct Source {
  float retention = 10;
  Profile profile = ORDINARY;
  float flow_x = 0, flow_y = 0;
  enum { SPAWNED, GIVEN, ALONG_FLOW } velocity = SPAWNED;
  float vx = 0, vy = 0;
};
// The tick being captured. A sprite's caller colors it after fx_spawn_sprite
// returns, so the last spawn waits for the next, the pool's update or the
// tick's end before it is read.
struct {
  std::vector<Emission> emissions;
  std::vector<Impulse> impulses;
  int counts[3];
  Source source;
  int pending = -1;
  Source pending_source;
} capture;

// The field's state (GpuSmokeSimulation): one domain, its retention, pending
// delayed emissions, batches waiting for a frame, and the solver's clocks.
struct {
  bool field;
  float idle, retention = 10;
  std::vector<std::pair<float, Emission>> pending;
  std::deque<Batch> batches;
  std::vector<Impulse> waiting;
  std::vector<std::pair<Impulse, float>> blasts;
  float accumulator, decay = 0.20f;
  bool dirty_reset = true;
  float size_x, size_y;
} smoke;

float field_fade() { return std::min(1.0f, std::max(0.0f, (smoke.retention - smoke.idle) / FADE_SECONDS)); }

void clear_field() {
  smoke.field = false;
  smoke.batches.clear();
  smoke.waiting.clear();
  smoke.blasts.clear();
  smoke.accumulator = 0;
  smoke.dirty_reset = true;
}

bool finite(std::initializer_list<float> values) {
  return std::all_of(values.begin(), values.end(), [](float v) { return isfinite(v); });
}

// One tick's emissions and impulses into the field's queue (consume).
void consume(std::vector<Emission> &emissions, std::vector<Impulse> &impulses, float dt) {
  std::vector<Emission> ready;
  std::vector<std::pair<float, Emission>> waiting;
  for (auto &[age, emission] : smoke.pending) {
    float aged = age + dt;
    if (aged >= 0)
      ready.push_back(emission);
    else
      waiting.push_back({aged, emission});
  }
  smoke.pending = waiting;
  for (const Emission &e : emissions) {
    if (e.a <= 0 || std::max(e.scale, e.expansion * 2 * STEP_SECONDS) <= 0 ||
        !finite({e.x, e.y, e.vx, e.vy, e.scale, e.r, e.g, e.b, e.a, e.delay, e.expansion, e.retention, e.rotation,
                 e.flow_x, e.flow_y}))
      continue;
    if (e.delay > 0) {
      if (smoke.pending.size() < MAX_PENDING)
        smoke.pending.push_back({-e.delay, e});
    } else {
      ready.push_back(e);
    }
  }
  std::vector<Impulse> valid;
  for (const Impulse &i : impulses)
    if (i.radius > 0 && i.strength >= 0 && i.duration > 0 &&
        finite({i.sx, i.sy, i.ex, i.ey, i.radius, i.strength, i.curl, i.duration, i.expansion_speed}))
      valid.push_back(i);
  std::stable_sort(valid.begin(), valid.end(), [](const Impulse &a, const Impulse &b) {
    return a.kind != b.kind ? a.kind < b.kind : a.rank() > b.rank();
  });
  if (valid.size() > MAX_IMPULSES)
    valid.resize(MAX_IMPULSES);
  // Air without smoke is invisible: keep its motion only when a medium or a
  // pending deposit can reveal it.
  if (ready.empty() && !smoke.field && smoke.pending.empty())
    valid.clear();
  if (!valid.empty() && !smoke.field && !smoke.pending.empty())
    smoke.field = true, smoke.idle = 0, smoke.retention = 10;
  // Elapsed empty ticks stay: frame grouping must not change transport.
  if (!ready.empty() || smoke.field) {
    float fade = !ready.empty() && smoke.field ? field_fade() : 1;
    if (smoke.batches.size() >= MAX_BATCHES)
      smoke.batches.pop_front();
    smoke.batches.push_back({ready, dt, fade, valid});
  }
  if (!ready.empty()) {
    if (!smoke.field)
      smoke.field = true, smoke.idle = 0, smoke.retention = 10;
    float retention = smoke.retention - smoke.idle;
    for (const Emission &e : ready)
      retention = std::max(retention, std::min(15.0f, std::max(2.0f, e.retention)));
    smoke.retention = retention;
    smoke.idle = 0;
  }
  if (smoke.field)
    smoke.idle += dt;
  // Fully expired material cannot affect a later domain: exact lifetime culling.
  if (smoke.field && field_fade() <= 0)
    clear_field();
}

// --- Solver commands (prepare, _inject, _inject_impulses) ------------------------
std::vector<float> commands;

void splat(const Emission &e) {
  float size = std::max(e.scale, e.expansion * 2 * STEP_SECONDS);
  if (e.profile == MUZZLE)
    size = std::max(16.0f, size); // the narrow axis resolved on the 4-world-unit grid
  float speed = sqrtf(e.vx * e.vx + e.vy * e.vy);
  float dx = speed > 1e-5f ? e.vx / speed : 1, dy = speed > 1e-5f ? e.vy / speed : 0;
  float flow = sqrtf(e.flow_x * e.flow_x + e.flow_y * e.flow_y);
  if (flow > 1e-5f)
    dx = e.flow_x / flow, dy = e.flow_y / flow;
  float cx = e.x + dx * (size * 0.35f) + GUARD_BAND, cy = e.y + dy * (size * 0.35f) + GUARD_BAND;
  float strength = e.a;
  if (e.effect)
    strength *= std::min(1.0f, std::max(0.0f, e.r * 0.2126f + e.g * 0.7152f + e.b * 0.0722f));
  if (e.profile == MUZZLE)
    strength *= 0.8f;
  else if (e.profile == ROCKET)
    strength *= 0.4f;
  else if (e.profile == ORDINARY && e.effect)
    strength *= 0.6f;
  if (e.profile == NUKE) {
    strength *= 8;
    smoke.decay = 0.12f;
  }
  float radius = std::max(16.0f, size * 2.5f);
  commands.insert(commands.end(),
                  {(float)SMOKE_SPLAT, (cx - radius) / smoke.size_x, (cy - radius) / smoke.size_y,
                   radius * 2 / smoke.size_x, radius * 2 / smoke.size_y, cx / smoke.size_x, cy / smoke.size_y, size,
                   strength, e.vx, e.vy, e.expansion, (float)(e.profile == NUKE), e.rotation, dx, dy,
                   (float)(e.profile == MUZZLE), 0});
}

void impulse(const Impulse &i, float age, float fraction) {
  float sx = i.sx + GUARD_BAND, sy = i.sy + GUARD_BAND, ex = i.ex + GUARD_BAND, ey = i.ey + GUARD_BAND;
  float radius = std::max(4.0f, i.radius), expansion = std::max(0.0f, i.expansion_speed);
  float lo_x, lo_y, hi_x, hi_y;
  if (i.kind == BLAST) {
    float extent = radius + age * expansion;
    extent += 3 * std::max(6.0f, radius * 0.35f + age * expansion * 0.08f);
    lo_x = sx - extent, lo_y = sy - extent, hi_x = sx + extent, hi_y = sy + extent;
  } else {
    float extent = radius * 5;
    lo_x = std::min(sx, ex) - extent, lo_y = std::min(sy, ey) - extent;
    hi_x = std::max(sx, ex) + extent, hi_y = std::max(sy, ey) + extent;
  }
  lo_x = std::max(0.0f, lo_x), lo_y = std::max(0.0f, lo_y);
  hi_x = std::min(smoke.size_x, hi_x), hi_y = std::min(smoke.size_y, hi_y);
  if (hi_x <= lo_x || hi_y <= lo_y)
    return;
  const float kinds[] = {2, 0, 1}; // the shader's: muzzle 0, wake 1, blast 2
  commands.insert(commands.end(),
                  {(float)SMOKE_IMPULSE, lo_x / smoke.size_x, lo_y / smoke.size_y, (hi_x - lo_x) / smoke.size_x,
                   (hi_y - lo_y) / smoke.size_y, sx, sy, ex, ey, i.radius, std::min(800.0f, i.strength),
                   std::max(-400.0f, std::min(400.0f, i.curl)), kinds[i.kind], age, fraction, expansion, i.duration});
}

// The queued batches as solver passes: deposits, then fixed 60 Hz steps.
void prepare() {
  commands.clear();
  if (!smoke.field && smoke.batches.empty())
    return;
  float size_x = terrain_texture_width + 2 * GUARD_BAND, size_y = terrain_texture_height + 2 * GUARD_BAND;
  if (size_x != smoke.size_x || size_y != smoke.size_y)
    smoke.size_x = size_x, smoke.size_y = size_y, smoke.dirty_reset = true;
  if (smoke.dirty_reset) {
    commands.insert(commands.end(), {(float)SMOKE_RESET, (float)GRID_SIZE, size_x, size_y, STEP_SECONDS,
                                     (float)PRESSURE_ITERATIONS});
    smoke.dirty_reset = false;
  }
  while (!smoke.batches.empty()) {
    Batch batch = std::move(smoke.batches.front());
    smoke.batches.pop_front();
    for (const Impulse &i : batch.impulses)
      if (i.kind == BLAST)
        smoke.blasts.push_back({i, 0.0f});
      else
        smoke.waiting.push_back(i);
    std::stable_sort(smoke.blasts.begin(), smoke.blasts.end(),
                     [](const auto &a, const auto &b) { return a.first.rank() > b.first.rank(); });
    if (smoke.blasts.size() > MAX_BLASTS)
      smoke.blasts.resize(MAX_BLASTS);
    std::stable_sort(smoke.waiting.begin(), smoke.waiting.end(), [](const Impulse &a, const Impulse &b) {
      return (a.kind == MUZZLE_JET) != (b.kind == MUZZLE_JET) ? a.kind == MUZZLE_JET : a.rank() > b.rank();
    });
    if (smoke.waiting.size() > MAX_IMPULSES)
      smoke.waiting.resize(MAX_IMPULSES);
    if (batch.fade < 1)
      commands.insert(commands.end(), {(float)SMOKE_FADE, batch.fade});
    for (const Emission &e : batch.emissions)
      splat(e);
    smoke.accumulator += batch.dt;
    while (smoke.accumulator + 1e-9f >= STEP_SECONDS) {
      for (const Impulse &i : smoke.waiting)
        impulse(i, 0, 1);
      smoke.waiting.clear();
      commands.push_back((float)SMOKE_PROJECT);
      // Blast fronts come after projection, which would otherwise erase their expansion.
      std::vector<std::pair<Impulse, float>> lasting;
      for (auto &[i, age] : smoke.blasts) {
        impulse(i, age, std::min(STEP_SECONDS, std::max(0.0f, i.duration - age)) / i.duration);
        if (age + STEP_SECONDS < i.duration - 1e-9f)
          lasting.push_back({i, age + STEP_SECONDS});
      }
      smoke.blasts = lasting;
      smoke.decay += STEP_SECONDS * (0.20f - smoke.decay) * 0.07f;
      commands.insert(commands.end(), {(float)SMOKE_TRANSPORT, smoke.decay});
      smoke.accumulator = std::max(0.0f, smoke.accumulator - STEP_SECONDS);
    }
  }
}

// --- Display (SmokeRenderer.select_lights, prepare) -------------------------------
// The smoke's 16 lights: those whose reach overlaps the domain, by their
// scattering strength, gains past four capped.
int smoke_lights(const float *lights, int count, float *out) {
  std::vector<std::pair<float, const float *>> ranked;
  for (int i = 0; i < count; ++i) {
    const float *l = lights + i * RTX_LIGHT_FLOATS;
    float illumination = l[12];
    if (illumination <= 0)
      continue;
    float reach = l[2] + l[11] * 0.5f + l[7];
    float ox = -GUARD_BAND, oy = -GUARD_BAND;
    float dx = std::max({ox - l[0], 0.0f, l[0] - ox - smoke.size_x});
    float dy = std::max({oy - l[1], 0.0f, l[1] - oy - smoke.size_y});
    if (dx * dx + dy * dy < reach * reach)
      ranked.push_back({std::max({l[4], l[5], l[6]}) * std::min(4.0f, illumination) * l[19] * l[2], l});
  }
  std::stable_sort(ranked.begin(), ranked.end(), [](const auto &a, const auto &b) { return a.first > b.first; });
  int n = std::min((int)ranked.size(), (int)SMOKE_MAX_LIGHTS);
  for (int i = 0; i < n; ++i) {
    const float *l = ranked[i].second;
    const float packed[SMOKE_LIGHT_FLOATS] = {l[0], l[1], l[3], l[2], l[4], l[5], l[6], std::min(4.0f, l[12]) * l[19],
                                              l[8], l[9], l[11] * 0.5f, l[7], l[16]};
    std::copy(packed, packed + SMOKE_LIGHT_FLOATS, out + i * SMOKE_LIGHT_FLOATS);
  }
  return n;
}

} // namespace

extern "C" {
void rtx_smoke_flush();
void rtx_smoke_impulse(float sx, float sy, float ex, float ey, float radius, float strength, float curl, int kind,
                       float duration, float expansion_speed);
int rtx_smoke_on = 1; // the console's rtxsmoke (game/rtx.cpp), on by default

// Whether fluid smoke runs: RTX shown, the console's switch, and the Smoke
// display setting, as RenderResources.sync_smoke_mode.
bool rtx_smoke_active() {
  return rtx_render_mode && rtx_smoke_on && platform_outputs() && config_blob.smoke_enabled;
}

// Clears the field and everything queued for it: a mode change, a new run, a
// replay's seek. New emissions start afresh.
void rtx_smoke_reset() {
  smoke.pending.clear();
  clear_field();
  smoke.decay = 0.20f;
  capture.emissions.clear();
  capture.impulses.clear();
  capture.pending = -1;
}

// A native smoke spawn (fx_spawn_sprite) into sprite slot `index`.
void rtx_smoke_spawned(int index) {
  rtx_smoke_flush();
  if (!rtx_smoke_active())
    return;
  capture.pending = index;
  capture.pending_source = capture.source;
}

// The waiting spawn as its caller left it. A muzzle puff pushes a short jet of
// air ahead of the gun as it goes (weapon_runtime/fire.py's muzzle_sprite).
void rtx_smoke_flush() {
  if (capture.pending < 0)
    return;
  const sprite_effect_t &sprite = sprite_effect_pool[capture.pending];
  const Source &source = capture.pending_source;
  capture.pending = -1;
  float vx = sprite.vel_x, vy = sprite.vel_y;
  if (source.velocity == Source::GIVEN) {
    vx = source.vx, vy = source.vy;
  } else if (source.velocity == Source::ALONG_FLOW) {
    float speed = sqrtf(vx * vx + vy * vy);
    vx = source.flow_x * speed, vy = source.flow_y * speed;
  }
  capture.emissions.push_back({sprite.pos_x, sprite.pos_y, vx, vy, sprite.scale, sprite.color_r, sprite.color_g,
                               sprite.color_b, sprite.color_a, sprite.rotation, false, 0, 0, source.retention,
                               source.profile, source.flow_x, source.flow_y});
  if (source.profile == MUZZLE)
    rtx_smoke_impulse(sprite.pos_x, sprite.pos_y, sprite.pos_x + source.flow_x * 40, sprite.pos_y + source.flow_y * 40,
                      10, 80 * sprite.color_a, 20 * sprite.color_a, MUZZLE_JET, 0.15f, 0);
}

// A general explosion puff (effect_spawn): its delay is its negative age, its
// growth the expansion of a scaling effect.
void rtx_smoke_puff(const effect_entry_t *e) {
  if (!rtx_smoke_active())
    return;
  float half = std::max(e->half_width, e->half_height);
  float rgba[4];
  memcpy(rgba, &e->color, sizeof rgba);
  capture.emissions.push_back({e->pos_x, e->pos_y, e->vel_x, e->vel_y, 2 * half * e->scale, rgba[0], rgba[1], rgba[2],
                               rgba[3], e->rotation, true, std::max(0.0f, -e->age),
                               e->flags & 8 ? half * e->scale_step : 0.0f, capture.source.retention,
                               capture.source.profile, 0, 0});
}

// The player's gun firing toward its aim `heading`: its puffs leave along it.
void rtx_smoke_muzzle(float heading) {
  capture.source = Source{};
  capture.source.profile = MUZZLE;
  capture.source.flow_x = cosf(heading - 1.5707964f), capture.source.flow_y = sinf(heading - 1.5707964f);
  capture.source.velocity = Source::ALONG_FLOW;
}
// A rocket's exhaust or detonation sprites: their flow and velocity given.
void rtx_smoke_rocket(float flow_x, float flow_y, float vx, float vy) {
  capture.source = Source{};
  capture.source.profile = ROCKET;
  capture.source.flow_x = flow_x, capture.source.flow_y = flow_y;
  capture.source.velocity = Source::GIVEN;
  capture.source.vx = vx, capture.source.vy = vy;
}
// The nuke's explosion: its smoke kept 15 s, in its own billowing profile.
void rtx_smoke_nuke() {
  capture.source = Source{};
  capture.source.retention = 15;
  capture.source.profile = NUKE;
}
// Back to ordinary sources.
void rtx_smoke_source_end() { capture.source = Source{}; }

// An explosion's expanding front through the air (spawn_explosion_burst, a
// rocket's detonation): it moves smoke, but makes none.
void rtx_smoke_blast(float x, float y, float scale) {
  rtx_smoke_impulse(x, y, x, y, std::max(6.0f, 12 * scale), 80 * scale, 0, BLAST, 0.45f, 180 * scale);
}

// A projectile's wake along its path this tick: ion, fire and plasma stir more.
void rtx_smoke_wake(int type, float sx, float sy, float ex, float ey, float dt) {
  bool energetic = type == PROJECTILE_TYPE_ION_RIFLE || type == PROJECTILE_TYPE_ION_MINIGUN ||
                   type == PROJECTILE_TYPE_ION_CANNON || type == PROJECTILE_TYPE_FIRE_BULLETS ||
                   type == PROJECTILE_TYPE_PLASMA_RIFLE || type == PROJECTILE_TYPE_PLASMA_MINIGUN ||
                   type == PROJECTILE_TYPE_PLASMA_CANNON;
  rtx_smoke_impulse(sx, sy, ex, ey, energetic ? 9.0f : 5.0f, (energetic ? 420.0f : 180.0f) * dt,
                    (energetic ? 120.0f : 60.0f) * dt, WAKE, 0.15f, 0);
}

// Airflow (atmosphere_impulse), each kind on its own budget: a volley's wakes
// cannot starve blasts or muzzle jets.
void rtx_smoke_impulse(float sx, float sy, float ex, float ey, float radius, float strength, float curl, int kind,
                       float duration, float expansion_speed) {
  if (!rtx_smoke_active())
    return;
  int limit = kind == WAKE ? 192 : 32;
  float dx = ex - sx, dy = ey - sy;
  if (capture.counts[kind] >= limit || (kind != BLAST && dx * dx + dy * dy <= 1e-8f))
    return;
  ++capture.counts[kind];
  capture.impulses.push_back({sx, sy, ex, ey, radius, strength, curl, (Kind)kind, duration, expansion_speed});
}

// The end of a tick of `dt` seconds: its capture joins the field's queue.
void rtx_smoke_tick(float dt) {
  rtx_smoke_flush();
  if (!rtx_smoke_active()) {
    if (smoke.field || !smoke.batches.empty() || !smoke.pending.empty())
      rtx_smoke_reset();
    return;
  }
  consume(capture.emissions, capture.impulses, dt);
  capture.emissions.clear();
  capture.impulses.clear();
  capture.counts[0] = capture.counts[1] = capture.counts[2] = 0;
}

// The field after the world's sprites, at the world's transition `alpha`:
// the queued solver passes, then its display under the frame's lights.
void rtx_smoke_draw(const float *lights, int light_count, float alpha) {
  prepare();
  if (!commands.empty())
    host_smoke(commands.data(), (int)commands.size());
  if (!smoke.field)
    return;
  float ox = -GUARD_BAND, oy = -GUARD_BAND;
  const float view[9] = {ox + camera_offset.x, oy + camera_offset.y, smoke.size_x, smoke.size_y,
                         ox, oy, smoke.size_x, smoke.size_y, alpha * field_fade()};
  static float packed[SMOKE_MAX_LIGHTS * SMOKE_LIGHT_FLOATS], sights[SMOKE_MAX_SIGHTS * 4];
  int lit = smoke_lights(lights, light_count, packed);
  int sight_count = rtx_collect_sights(sights, SMOKE_MAX_SIGHTS);
  host_smoke_draw(view, packed, lit, sights, sight_count);
}
}
