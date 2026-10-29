// The RTX world's light sources, after the Python port's
// src/crimson/render/rtx/material_lights.py: finite luminous discs, tapered
// segments and annuli read from the frame's projectiles, muzzle flashes, perks,
// rockets, detonations and flame particles. RGB is linear source radiance; the
// illumination and reflection gains and reaches are art controls. A volley's
// co-located shots are one source. Each response keeps its 28 strongest sources
// for the view, fading them across that edge by a per-source ident, and their
// union of at most 28 (taking turns past that) goes to the host (game/rtx.cpp)
// with sources fading out, at most 32. Ion arcs' contacts glow on
// the ground instead (rtx_contact_glows). Reading the run only: nothing here
// writes it.
#include "crimsonland_gameplay.h"
#include "crimsonland_config_owner.h"
#include "render_passes.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <algorithm>
#include <array>
#include <iterator>
#include <math.h>
#include <string.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

extern "C" {
extern int perk_id_radioactive, perk_id_sharpshooter, perk_id_ion_gun_master;
extern float game_time_s;
extern vec2f_t camera_offset;
extern unsigned int grim_backbuffer_width, grim_backbuffer_height;
extern int run_elapsed_ms;
bool rtx_drawing();
int creature_find_in_radius(float *pos, float radius, int start_index);
// How far a Fire Bullets shot has flown since the arena's edge stopped it (game/patches/52-fire-bullets-fly-off.patch).
float projectile_fire_flown(const projectile_t *projectile);
void effect_select_texture(int effect_id);
void rtx_pressure_ring(float x, float y, float radius, float alpha);
}
extern IGrim2D_cpp *grim_interface_ptr;

namespace {

const float HALF_PI = 1.5707964f;
const float INF = 1e30f;
// MAX_SELECTED: each response's budget, and their union's (material_lights.py's MAX_SELECTED_SOURCES).
enum { MAX_SELECTED = 28, MAX_EXPLOSIONS = 128, MAX_FLAME_CELLS = 128 };
// Every source a frame can hold, so selection sees them all: each player's aura,
// sight and muzzle; each projectile and its four arcs; each secondary; each
// explosion's shell and fireball; each flame cell.
const int MAX_SOURCES = 2 * 3 + (int)std::size(projectile_pool) * 5 + (int)std::size(secondary_projectile_pool) +
                        MAX_EXPLOSIONS * 2 + MAX_FLAME_CELLS;
// A volley's pellets light as one source while their heads lie this close to
// the lead's; a source fades across a budget's edge over this many ticks.
const float VOLLEY_UNITS = 28;
const float SLEW_TICKS = 6;

// Source idents (source_ident): the kind in the top byte, its slot below.
enum { IDENT_PLAYER = 1, IDENT_SHOT, IDENT_ARC, IDENT_SECONDARY, IDENT_EXPLOSION, IDENT_FLAME, IDENT_VOLLEY };
int source_ident(int kind, int number) { return kind << 24 | (number & 0xffffff); }
// One trigger pull's pellets share a kind, an owner and a spawn point (their
// origin): their volley's ident (material_lights.py's volley_ident).
int volley_ident(const projectile_t &p) {
  unsigned x = (unsigned)(int)floorf(p.fields.origin_x), y = (unsigned)(int)floorf(p.fields.origin_y);
  unsigned number = x * 73856093u ^ y * 19349663u ^ (unsigned)p.fields.type_id * 83492791u ^
                    (unsigned)p.fields.owner_id * 2654435761u;
  return source_ident(IDENT_VOLLEY, (int)(number & 0xffffff));
}

// A luminous disc, tapered segment or annulus (MaterialLight). A beam's streak
// (its stamp radius, spacing and head size) lights the ground as one source.
struct Light {
  float x, y, radius, r, g, b;
  float height = 18, dx = 0, dy = 0, length = 0, width = 3;
  float illumination = 1, reflection = 1, reach = -1, ring = 0;
  float tail = 0.18f;
  bool broad = false;
  float beam_radius = 0, beam_step = 0, beam_head = 0;
  bool beam_ion = false;
  float smoke_gain = 1; // fluid smoke's scattering response, apart from the ground's and creatures'
  int ident = -1;       // which source this is, the same from frame to frame
  int volley = -1;      // a shot's volley (volley_ident): a pellet leaving it starts from its place in the budgets
  float travel = 0;     // how far a shot has flown from its spawn point: a reused slot's new shot starts over
  float reflection_reach() const { return reach < 0 ? radius : reach; }
};
Light sources[MAX_SOURCES];
int source_count;

Light &add(int ident, float x, float y, float radius, float r, float g, float b) {
  static Light overflow;
  Light &light = source_count < MAX_SOURCES ? sources[source_count++] : overflow;
  light = Light{x, y, radius, r, g, b};
  light.ident = ident;
  return light;
}

// A heading's direction: headings point up the screen at zero.
void heading_direction(float heading, float &dx, float &dy) {
  dx = cosf(heading - HALF_PI);
  dy = sinf(heading - HALF_PI);
}
float normalize(float &x, float &y) {
  float length = sqrtf(x * x + y * y);
  if (length > 0) {
    x /= length;
    y /= length;
  }
  return length;
}

// Ion and Fire Bullets streak scales (render/beam_profiles.py).
float streak_scale(int type) {
  switch (type) {
  case PROJECTILE_TYPE_ION_MINIGUN: return 1.05f;
  case PROJECTILE_TYPE_ION_RIFLE: return 2.2f;
  case PROJECTILE_TYPE_ION_CANNON: return 3.5f;
  case PROJECTILE_TYPE_FIRE_BULLETS: return 0.8f;
  default: return 0;
  }
}

struct Emission {
  float r, g, b, radius, width, height, illumination, reflection, reach, tail, fade_power;
  bool broad = false;
};
// Art-directed radiance, not calibrated watts. The visible source remains native.
const Emission TRACER = {0.22f, 0.21f, 0.18f, 60, 0.65f, 28, 0, 1, 100, INF, 2.2f};
const Emission *emission(int type) {
  static const Emission gauss = {0.054f, 0.102f, 0.192f, 75, 1, 40, 0.15f, 1, 150, INF, 2.2f};
  static const Emission ion_rifle = {0.55f, 0.82f, 1.45f, 195, 3, 24, 6, 1, 195, 256, 1, true};
  static const Emission ion_minigun = {0.50f, 0.78f, 1.35f, 160, 2, 24, 4, 1, 160, 256, 1, true};
  static const Emission ion_cannon = {0.65f, 0.90f, 1.65f, 240, 5, 24, 8, 1, 240, 256, 1, true};
  static const Emission fire_bullets = {1.40f, 0.68f, 0.20f, 155, 3, 24, 4, 1, 155, 256, 1, true};
  static const Emission plasma_minigun = {0.72f, 0.37f, 0.08f, 100, 2, 18, 2.4f, 1, 125, 4.2f, 1, true};
  static const Emission plasma_rifle = {1.1f, 0.57f, 0.12f, 140, 5, 18, 3.2f, 1, 175, 17.5f, 1, true};
  static const Emission plasma_cannon = {1.5f, 0.76f, 0.16f, 190, 9, 18, 4, 1, 250, 44.2f, 1, true};
  static const Emission spider_plasma = {0.08f, 0.65f, 0.025f, 100, 2, 18, 0.5f, 1, 140, 4.2f, 1};
  static const Emission shrinkifier = {0.06f, 0.03f, 0.18f, 65, 2, 18, 0.15f, 1, 120, 4.2f, 1};
  static const Emission pulse = {0.06f, 0.5f, 0.13f, 110, 3, 18, 3, 1, 140, 0, 1};
  switch (type) {
  case PROJECTILE_TYPE_PISTOL:
  case PROJECTILE_TYPE_ASSAULT_RIFLE:
  case PROJECTILE_TYPE_SHOTGUN:
  case PROJECTILE_TYPE_SUBMACHINE_GUN:
  case PROJECTILE_TYPE_SPLITTER_GUN: return &TRACER;
  case PROJECTILE_TYPE_GAUSS_GUN: return &gauss;
  case PROJECTILE_TYPE_ION_RIFLE: return &ion_rifle;
  case PROJECTILE_TYPE_ION_MINIGUN: return &ion_minigun;
  case PROJECTILE_TYPE_ION_CANNON: return &ion_cannon;
  case PROJECTILE_TYPE_FIRE_BULLETS: return &fire_bullets;
  case PROJECTILE_TYPE_PLASMA_MINIGUN: return &plasma_minigun;
  case PROJECTILE_TYPE_PLASMA_RIFLE: return &plasma_rifle;
  case PROJECTILE_TYPE_PLASMA_CANNON: return &plasma_cannon;
  case PROJECTILE_TYPE_SPIDER_PLASMA: return &spider_plasma;
  case PROJECTILE_TYPE_SHRINKIFIER: return &shrinkifier;
  case PROJECTILE_TYPE_PULSE_GUN: return &pulse;
  default: return nullptr;
  }
}
bool plasma(int type) {
  return type == PROJECTILE_TYPE_PLASMA_MINIGUN || type == PROJECTILE_TYPE_PLASMA_RIFLE ||
         type == PROJECTILE_TYPE_PLASMA_CANNON || type == PROJECTILE_TYPE_SPIDER_PLASMA ||
         type == PROJECTILE_TYPE_SHRINKIFIER;
}

void projectile_source(const projectile_t &p, int ident) {
  int type = p.fields.type_id;
  const Emission *e = emission(type);
  float life = p.fields.life_timer;
  if (!p.active || !e || life <= 0)
    return;
  float gain = powf(fminf(1, life * 2.5f), e->fade_power);
  float dx = p.fields.pos_x - p.fields.origin_x, dy = p.fields.pos_y - p.fields.origin_y;
  float distance = normalize(dx, dy);
  // A stopped Fire Bullets shot flies on as it is drawn.
  float flown = projectile_fire_flown(&p), head_x = p.fields.pos_x + dx * flown, head_y = p.fields.pos_y + dy * flown;
  distance += flown;
  float span = fminf(distance, e->tail);
  float r = e->r, g = e->g, b = e->b, width = e->width;
  if (plasma(type)) {
    // The sprite's short tail follows its stored heading and speed scale.
    heading_direction(p.angle, dx, dy);
    span = fminf(distance, e->tail * p.fields.speed_scale);
    if (life < 0.4f) {
      // All five plasma variants switch to the same untinted warm 56px glow.
      r = 1.1f, g = 0.57f, b = 0.12f, width = 5, span = 0;
    }
  } else if (type == PROJECTILE_TYPE_PULSE_GUN && distance > 0) {
    // A segment across the shot's front edge, so its reflection stretches along
    // it; on impact the white sprite lights pale green.
    bool impact = life < 0.4f;
    span = 1.4f * (impact ? 28 : distance * 0.08f);
    float across_x = -dy, across_y = dx;
    dx = across_x, dy = across_y;
    head_x += dx * span * 0.5f, head_y += dy * span * 0.5f;
    if (impact)
      r = 0.4f, g = 0.75f, b = 0.5f;
  }
  if (streak_scale(type) && dx == 0 && dy == 0)
    heading_direction(p.angle, dx, dy);
  Light &light = add(ident, head_x - dx * span * 0.5f, head_y - dy * span * 0.5f, e->radius,
                     r * gain, g * gain, b * gain);
  light.volley = volley_ident(p);
  light.travel = hypotf(p.fields.pos_x - p.fields.origin_x, p.fields.pos_y - p.fields.origin_y);
  light.height = e->height;
  light.dx = dx, light.dy = dy, light.length = span;
  light.width = width;
  light.illumination = e->illumination;
  light.reflection = e->reflection;
  light.reach = e->reach;
  light.broad = e->broad;
  if (float scale = streak_scale(type)) {
    bool fire = type == PROJECTILE_TYPE_FIRE_BULLETS;
    light.beam_radius = 16 * scale, light.beam_step = fminf(scale * 3.1f, 9), light.beam_head = fire ? 1.35f : 1.05f;
    light.beam_ion = !fire;
    light.tail = 0; // a streak's stamps fade in from nothing at its tail
  }
}

// Up to four visible arc targets of an ion impact, nearest the view first
// (render/ion_arcs.py), and the arcs' color; the arcs reach what
// projectile_render's impact pass does.
struct ArcTarget {
  float x, y, segment, endpoint;
};
int ion_arc_targets(projectile_t &p, float view_x, float view_y, ArcTarget (&targets)[4], float rgb[3]) {
  int type = p.fields.type_id;
  float life = p.fields.life_timer;
  if (!p.active || !(life > 0 && life < 0.4f) || type == PROJECTILE_TYPE_FIRE_BULLETS || !streak_scale(type))
    return 0;
  float reach = streak_scale(type) * (perk_count_get(perk_id_ion_gun_master) ? 1.2f : 1.0f) * 40.0f;
  int count = 0;
  for (int i = creature_find_in_radius(&p.fields.pos_x, reach, 1); i != -1;
       i = creature_find_in_radius(&p.fields.pos_x, reach, i + 1)) {
    float tx = creature_pool[i].pos_x, ty = creature_pool[i].pos_y;
    float ddx = tx - p.fields.pos_x, ddy = ty - p.fields.pos_y;
    float length_sq = ddx * ddx + ddy * ddy;
    if (length_sq <= 1e-6f)
      continue;
    // Rank by distance from the view center to the visible segment, then to its end.
    float ox = view_x - p.fields.pos_x, oy = view_y - p.fields.pos_y;
    float along = fmaxf(0, fminf(1, (ox * ddx + oy * ddy) / length_sq));
    float sx = ox - ddx * along, sy = oy - ddy * along;
    ArcTarget t = {tx, ty, sx * sx + sy * sy, (tx - view_x) * (tx - view_x) + (ty - view_y) * (ty - view_y)};
    int at = count < 4 ? count++ : 4;
    while (at > 0 && (t.segment < targets[at - 1].segment ||
                      (t.segment == targets[at - 1].segment && t.endpoint < targets[at - 1].endpoint))) {
      if (at < 4)
        targets[at] = targets[at - 1];
      --at;
    }
    if (at < 4)
      targets[at] = t;
  }
  const Emission *e = emission(type);
  float energy = fminf(1, life * 2.5f);
  rgb[0] = e->r * energy, rgb[1] = e->g * energy, rgb[2] = e->b * energy;
  return count;
}

// An ion impact's arcs as lights, numbered from `ident`.
void ion_arc_sources(projectile_t &p, float view_x, float view_y, int ident) {
  ArcTarget targets[4];
  float rgb[3];
  int count = ion_arc_targets(p, view_x, view_y, targets, rgb);
  float width = streak_scale(p.fields.type_id) * 1.5f;
  for (int i = 0; i < count; ++i) {
    float dx = targets[i].x - p.fields.pos_x, dy = targets[i].y - p.fields.pos_y;
    float length = normalize(dx, dy);
    Light &arc = add(ident + i, (p.fields.pos_x + targets[i].x) * 0.5f, (p.fields.pos_y + targets[i].y) * 0.5f, 100,
                     rgb[0], rgb[1], rgb[2]);
    arc.dx = dx, arc.dy = dy, arc.length = length, arc.width = width;
    arc.illumination = 0.75f, arc.reflection = 0.5f, arc.reach = 120;
    arc.tail = 1, arc.broad = true;
  }
}

// The native Sharpshooter sight (render/laser_sight.py): from beside the gun to 512 units out.
void sight_geometry(const player_state_t &player, float &near_x, float &near_y, float &far_x, float &far_y) {
  float heading = player.aim_heading - HALF_PI;
  far_x = player.pos_x + cosf(heading) * 512, far_y = player.pos_y + sinf(heading) * 512;
  float near_heading = heading - 0.150915f;
  near_x = player.pos_x + cosf(near_heading) * 15, near_y = player.pos_y + sinf(near_heading) * 15;
}

void player_sources(const player_state_t &player, int number) {
  if (perk_count_get(perk_id_radioactive)) {
    // Follow the visible aura, including its native post-death presence.
    float pulse = ((sinf(game_time_s) + 1) * 0.1875f + 0.25f) / 0.4375f;
    Light &aura = add(source_ident(IDENT_PLAYER, number * 4), player.pos_x, player.pos_y, 100, 0.10f, 0.70f, 0.07f);
    aura.width = 13;
    aura.illumination = 3.8f * pulse, aura.reflection = 0.8f * pulse, aura.reach = 100;
    aura.broad = true;
  }
  if (player.health > 0 && perk_count_get(perk_id_sharpshooter)) {
    // Red at the gun, black at its far end, so the source axis points back toward the gun.
    float near_x, near_y, far_x, far_y;
    sight_geometry(player, near_x, near_y, far_x, far_y);
    float dx = near_x - far_x, dy = near_y - far_y;
    float length = normalize(dx, dy);
    Light &sight = add(source_ident(IDENT_PLAYER, number * 4 + 1), (near_x + far_x) * 0.5f, (near_y + far_y) * 0.5f,
                       40, 1.3f, 0, 0);
    sight.height = 28;
    sight.dx = dx, sight.dy = dy, sight.length = length, sight.width = 1.2f;
    sight.illumination = 0, sight.reflection = 1, sight.reach = 100;
    sight.tail = 0;
  }
  float gain = fmaxf(0, fminf(1, player.muzzle_flash_alpha));
  // Match the visible muzzle pass, including weapons which suppress that sprite.
  if (gain <= 0.02f || player.health <= 0 || weapon_table[player.weapon_id].flags & 8)
    return;
  int weapon = player.weapon_id;
  bool energetic = weapon == 9 || weapon == 10 || weapon == 11 || weapon == 14 || weapon == 23 || weapon == 28 ||
                   player.fire_bullets_timer > 0; // the plasma guns and the Ion Cannon
  // The shared fire muzzle (math_parity.native_fire_muzzle_pos); its flash is
  // warm artwork, even when the gun's projectile is blue.
  float heading = player.aim_heading - HALF_PI - 0.150915f;
  Light &muzzle = add(source_ident(IDENT_PLAYER, number * 4 + 2), player.pos_x + cosf(heading) * 16,
                      player.pos_y + sinf(heading) * 16, energetic ? 130.0f : 65.0f, 1.6f * gain, 1.0f * gain,
                      0.4f * gain);
  muzzle.height = 28, muzzle.width = 4;
  muzzle.illumination = energetic ? 0.8f : 0.12f, muzzle.reflection = 0.6f, muzzle.reach = 140;
  muzzle.broad = energetic;
}

bool fireball_owns_secondary(int slot);
void secondary_sources(const secondary_projectile_t &s, int slot) {
  if (!s.active)
    return;
  int type = s.fields.type_id;
  if (type == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
    if (fireball_owns_secondary(slot))
      return;
    // A detonation keeps its progress and scale in its velocity.
    float t = fmaxf(0, fminf(1, s.fields.vel_x)), scale = s.fields.vel_y;
    float gain = powf(1 - t, 1.35f);
    if (gain > 0.02f) {
      Light &blast = add(source_ident(IDENT_SECONDARY, slot), s.fields.pos_x, s.fields.pos_y, 360 * fmaxf(0.35f, scale),
                         1.75f * gain, 1.05f * gain, 0.38f * gain);
      blast.height = 34, blast.width = 3 + 28 * t * scale;
      blast.broad = true;
    }
  } else if (type == SECONDARY_PROJECTILE_TYPE_ROCKET || type == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET ||
             type == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
    if (!config_blob.flame_glow_enabled)
      return;
    float scale = type == SECONDARY_PROJECTILE_TYPE_ROCKET ? 1.0f : type == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET ? 0.7f
                                                                                                               : 0.4f;
    float dx, dy;
    heading_direction(s.angle, dx, dy);
    Light &exhaust = add(source_ident(IDENT_SECONDARY, slot), s.fields.pos_x - dx * 12, s.fields.pos_y - dy * 12,
                         110 * scale, 0.9f * scale, 0.47f * scale, 0.1f * scale);
    exhaust.height = 22;
    exhaust.dx = dx, exhaust.dy = dy, exhaust.length = 6 * scale, exhaust.width = 5 * scale, exhaust.reach = 140;
    exhaust.broad = true;
    exhaust.smoke_gain = 6;
  }
}

// --- Explosion lights (effects.py's ExplosionVisual, render/rtx/explosion_shell.py) ---
// Each explosion burst's flash and fireball, kept apart from the effect slots
// that draw it: its fireball sprites as they spawned and whether its ring did,
// aged with the effects. Only light reads them; the run never does.
// A fireball sprite as it spawned (ExplosionFireball.initial) and its slot while
// it holds it.
struct Fireball {
  float x, y, vx, vy, half_width, half_height, scale, scale_step, rotation, rotation_step, lifetime;
  float rgb[3];
  const effect_entry_t *entry;
  // The sprite at `age` along its own course (ExplosionFireball.sample).
  float half() const { return fmaxf(half_width, half_height); }
};
// The shared pressure shell (render/rtx/explosion_shell.py): a warm visible
// front and its nearby light travel together for 0.65 s after the first 0.05.
struct Shell {
  float radius, strength, alpha, energy;
};
bool explosion_shell(float age, float scale, Shell &shell) {
  float elapsed = age - 0.05f;
  if (elapsed < 0 || elapsed >= 0.65f)
    return false;
  float fade = fminf(1, fmaxf(0, (elapsed - 0.28f) / 0.37f));
  shell.strength = 1 - fade * fade * (3 - 2 * fade);
  float radius = 30 + 650 * elapsed, dilution = fminf(1, 100 / radius);
  shell.radius = radius * fmaxf(0.1f, scale);
  shell.alpha = 0.36f * shell.strength * powf(dilution, 0.65f);
  shell.energy = shell.strength * sqrtf(dilution);
  return true;
}
struct Explosion {
  float x, y, scale, age;
  bool emit_light, ring_spawned;
  int rocket_slot;
  const effect_entry_t *ring; // its ring's slot, while it holds it
  int fireball_count;
  Fireball fireballs[4];
  bool has_shell(Shell &shell) const { return emit_light && ring_spawned && explosion_shell(age, scale, shell); }
  bool archives_fireballs() const { return emit_light && age >= 0 && age < lifetime(); }
  float lifetime() const { return emit_light ? 1.4f : 0.7f; }
  bool has_fireball_light() const {
    if (age < 0 || age >= lifetime())
      return false;
    if (emit_light)
      return fireball_count > 0;
    for (int i = 0; i < fireball_count; ++i)
      if (fireballs[i].entry)
        return true;
    return false;
  }
  // The moving sprites' bounds give the emitting footprint; the luminous core
  // fills about 35% of them.
  float fireball_radius() const {
    float age = this->age * (emit_light ? 0.5f : 1.f), extent = fireball_count ? 0.0f : 32 * scale;
    for (int i = 0; i < fireball_count; ++i) {
      const Fireball &f = fireballs[i];
      if (!emit_light && !f.entry)
        continue;
      float dx = f.vx * age + f.x - x, dy = f.vy * age + f.y - y;
      extent = fmaxf(extent, sqrtf(dx * dx + dy * dy) + f.half() * (f.scale + f.scale_step * age));
    }
    return fmaxf(12 * scale, fminf(90 * scale, extent * 0.35f));
  }
};
std::vector<Explosion> explosions;
Explosion *bursting; // the burst being spawned
int rocket_burst_slot = -1; // rocket fireballs keep native timing and own this detonation's light

bool fireball_owns_secondary(int slot) {
  for (const Explosion &e : explosions)
    if (e.rocket_slot == slot && e.has_fireball_light())
      return true;
  return false;
}

void explosion_sources() {
  for (const Explosion &e : explosions) {
    // An explosion keeps its spot for its whole life: its position names it.
    int spot = ((int)floorf(e.x) & 0x7ff) << 12 | ((int)floorf(e.y) & 0x7ff) << 1;
    float scale = fmaxf(0.1f, e.scale);
    Shell front;
    if (e.has_shell(front)) {
      float energy = front.energy;
      Light &shell = add(source_ident(IDENT_EXPLOSION, spot), e.x, e.y, 85 * scale, 0.60f * energy, 0.39f * energy,
                         0.18f * energy);
      shell.height = 16 * scale, shell.ring = front.radius, shell.width = 8 * scale;
      shell.illumination = 1.8f, shell.reflection = 0.65f, shell.reach = 100 * scale, shell.broad = true;
    }
    if (!e.has_fireball_light())
      continue;
    if (!e.emit_light) {
      // Native rocket fireballs outlive their gameplay detonation. One source
      // follows the visible flame, expanding and cooling after the impact flash.
      float t = e.age, phase = std::clamp(t / e.lifetime(), 0.f, 1.f);
      float gain = .35f * expf(-t / .045f) + .9f * powf(1 - phase, 1.1f);
      float rise = phase * phase * (3 - 2 * phase), rocket_scale = scale / .4f;
      Light &fireball = add(source_ident(IDENT_EXPLOSION, spot | 1), e.x, e.y, 240 * rocket_scale,
                            1.8f * gain, (1.05f - .35f * phase) * gain, (.38f - .24f * phase) * gain);
      fireball.height = (24 + 40 * rise) * rocket_scale, fireball.width = e.fireball_radius();
      fireball.illumination = 6, fireball.reflection = 1.2f, fireball.broad = true;
      continue;
    }
    // A fast flash, the visible fireball sustained, then a fade with its retimed alpha.
    float t = e.age;
    float fade = fminf(1, fmaxf(0, 1 - t / e.lifetime()) / 0.75f);
    float gain = 0.2f * expf(-t / 0.08f) + 0.8f * powf(fade, 1.1f);
    float rise = fminf(t / 0.8f, 1);
    rise = rise * rise * (3 - 2 * rise);
    Light &fireball = add(source_ident(IDENT_EXPLOSION, spot | 1), e.x, e.y, 330 * scale, 1.8f * gain, 0.92f * gain,
                          0.3f * gain);
    fireball.height = (12 + 68 * rise) * scale, fireball.width = e.fireball_radius();
    fireball.illumination = 6, fireball.reflection = 1.2f, fireball.broad = true;
  }
}

// Flame particles grouped into 64-unit cells per style: dense streams stay bounded.
void flame_sources() {
  enum { BUBBLEGUN = 8 };
  struct Cell {
    int x, y, style;
    float weight, x_sum, y_sum, vx, vy, rgb[3];
  } cells[MAX_FLAME_CELLS];
  int count = 0;
  for (const particle_t &p : particle_pool) {
    if (!p.active || p.style_id == BUBBLEGUN || p.color_a <= 0.02f)
      continue;
    int x = (int)floorf(p.pos_x / 64), y = (int)floorf(p.pos_y / 64);
    Cell *cell = nullptr;
    for (int i = 0; i < count && !cell; ++i)
      if (cells[i].x == x && cells[i].y == y && cells[i].style == p.style_id)
        cell = &cells[i];
    if (!cell) {
      cell = &cells[count++];
      *cell = Cell{x, y, p.style_id};
    }
    float a = p.color_a;
    cell->weight += a;
    cell->x_sum += p.pos_x * a, cell->y_sum += p.pos_y * a;
    cell->vx += p.vel_x * a, cell->vy += p.vel_y * a;
    // The warm atlas modulated by the particle's evolving tint.
    const float tint[3] = {1.0f, 0.52f, 0.11f}, aura[3] = {0.06f, 0.03f, 0.006f};
    const float color[3] = {p.color_r, p.color_g, p.color_b};
    for (int c = 0; c < 3; ++c)
      cell->rgb[c] += (powf(color[c], 2.2f) * tint[c] + aura[c]) * a;
  }
  for (int i = 0; i < count; ++i) {
    Cell &cell = cells[i];
    float rgb[3] = {cell.rgb[0] * 0.45f, cell.rgb[1] * 0.45f, cell.rgb[2] * 0.45f};
    float scale = fminf(1, 1.8f / fmaxf(fmaxf(rgb[0], fmaxf(rgb[1], rgb[2])), 0.001f));
    float dx = cell.vx, dy = cell.vy;
    float speed = normalize(dx, dy);
    Light &flame = add(source_ident(IDENT_FLAME, (cell.x & 0x3ff) << 14 | (cell.y & 0x3ff) << 4 | (cell.style & 0xf)),
                       cell.x_sum / cell.weight, cell.y_sum / cell.weight, 110, rgb[0] * scale, rgb[1] * scale,
                       rgb[2] * scale);
    flame.height = 20;
    flame.dx = dx, flame.dy = dy, flame.length = speed > 0 ? 28.0f : 0.0f, flame.width = 5, flame.reach = 140;
    flame.broad = true;
  }
}

// From the point to where the source reaches it, as the shaders place it: an
// annulus's nearest point; a segment's nearest point for reflections, its energy
// centroid for illumination (source_geometry.glsl's illuminationSource), which a
// streak's dark tail at the muzzle does not pull back.
float distance_sq(const Light &light, float x, float y, bool reflection) {
  float px = x - light.x, py = y - light.y;
  if (light.ring > 0) {
    float d = sqrtf(px * px + py * py) - light.ring;
    return d * d;
  }
  float ax = light.dx, ay = light.dy;
  if (ax * ax + ay * ay > 0.0001f)
    normalize(ax, ay);
  else
    ax = ay = 0;
  float along = reflection ? fmaxf(-light.length * 0.5f, fminf(light.length * 0.5f, px * ax + py * ay))
                           : light.length * (1 - light.tail) / (6 * (1 + light.tail));
  float qx = px - ax * along, qy = py - ay * along;
  return qx * qx + qy * qy;
}

float score(const Light &light, bool reflection, float view_x, float view_y) {
  float gain = reflection ? light.reflection : light.illumination;
  float radius = reflection ? light.reflection_reach() : light.radius;
  return fmaxf(light.r, fmaxf(light.g, light.b)) * gain /
         (1 + distance_sq(light, view_x, view_y, reflection) / fmaxf(1, radius * radius));
}

// The MAX_SELECTED best-scoring sources of one response, as their ranks (-1
// for the rest); ties go to the lower ident.
void select(const float *scores, int *ranks) {
  std::fill(ranks, ranks + source_count, -1);
  for (int n = 0; n < MAX_SELECTED; ++n) {
    int best = -1;
    for (int i = 0; i < source_count; ++i)
      if (ranks[i] < 0 && scores[i] > 0 &&
          (best < 0 || scores[i] > scores[best] || (scores[i] == scores[best] && sources[i].ident < sources[best].ident)))
        best = i;
    if (best < 0)
      break;
    ranks[best] = n;
  }
}

// Each source's place in the two budgets, by ident (LightSelection): a weight
// that moves toward 1 while it is selected and 0 while it is not, by
// 1 / SLEW_TICKS per tick of the run's clock. A source seen for the first time
// starts where it belongs, so a new shot lights at once; a rewind or a gap
// over a second starts over.
struct Selection {
  std::unordered_map<int, float> weights[2];
  // The volleys' history (merge_volleys): when each shot was born (and how far
  // it had flown), the pellets that have left their volley, and how much of
  // each one's light its volley still carries.
  struct Born {
    float travel;
    int tick;
  };
  std::unordered_map<int, Born> born;
  std::unordered_set<int> split;
  std::unordered_map<int, float> handoff;
  float elapsed_ms = -1, ticks = 0;
  void advance(float now_ms) {
    float gap = now_ms - elapsed_ms;
    if (elapsed_ms < 0 || gap < 0 || gap > 1000) {
      reset();
      gap = 0;
    }
    elapsed_ms = now_ms, ticks = gap * 60 / 1000;
  }
  void reset() {
    weights[0].clear(), weights[1].clear();
    born.clear(), split.clear(), handoff.clear();
    elapsed_ms = -1, ticks = 0;
  }
  // The sources' weights in one response; idents no longer present are dropped.
  // A source seen for the first time starts where it belongs, unless it is a
  // pellet leaving its volley: that starts where the volley was.
  void slew(bool reflection, const bool *chosen, float *out) {
    std::unordered_map<int, float> &previous = weights[reflection], next;
    float step = ticks / SLEW_TICKS;
    for (int i = 0; i < source_count; ++i) {
      float target = chosen[i] ? 1.0f : 0.0f;
      auto found = previous.find(sources[i].ident);
      if (found == previous.end())
        found = previous.find(sources[i].volley);
      float weight = found == previous.end() ? target : found->second;
      weight = target > weight ? fminf(target, weight + step) : fmaxf(target, weight - step);
      previous[sources[i].ident] = next[sources[i].ident] = out[i] = weight;
    }
    previous.swap(next);
  }
};
Selection selection;

// One trigger pull's pellets (Light::volley, born on one tick), from `first`
// on, as one source while their heads lie within VOLLEY_UNITS of the lead's,
// the lowest ident still in the volley (material_lights.py's merge_volleys).
// Unrelated shots never merge, however close they pass, nor do a gun's trigger
// pulls from one spot. A pellet that strays leaves for good
// and hands its light over across SLEW_TICKS: the volley keeps a fading share
// of it where it was, while the pellet's own light comes up from the volley's
// place in the budgets. Radiance adds, so a volley fanning out keeps its total
// light. The merged source keeps one shot's width (every body's shadow margin
// follows the widest source) and the volley's ident.
void merge_volleys(int first) {
  auto head = [](const Light &l, float *out) {
    out[0] = l.x + l.dx * l.length * 0.5f, out[1] = l.y + l.dy * l.length * 0.5f;
  };
  float step = selection.ticks / SLEW_TICKS;
  std::unordered_set<int> present;
  for (int i = first; i < source_count; ++i)
    present.insert(sources[i].ident);
  for (auto it = selection.handoff.begin(); it != selection.handoff.end();) {
    it->second -= step;
    it = it->second <= 0 || !present.count(it->first) ? selection.handoff.erase(it) : std::next(it);
  }
  for (auto it = selection.split.begin(); it != selection.split.end();)
    it = present.count(*it) ? std::next(it) : selection.split.erase(it);
  for (auto it = selection.born.begin(); it != selection.born.end();)
    it = present.count(it->first) ? std::next(it) : selection.born.erase(it);
  int tick = (int)lroundf(selection.elapsed_ms * 0.06f);
  std::vector<Light> shots(sources + first, sources + source_count);
  for (Light &shot : shots) {
    if (shot.volley < 0)
      continue;
    // A shot is born when first seen, or when it is nearer its spawn point
    // than before: a reused slot's new shot.
    auto seen = selection.born.find(shot.ident);
    bool fresh = seen == selection.born.end() || shot.travel < seen->second.travel;
    int born = fresh ? tick : seen->second.tick;
    if (fresh) {
      selection.split.erase(shot.ident);
      selection.handoff.erase(shot.ident);
    }
    selection.born[shot.ident] = {shot.travel, born};
    shot.volley = source_ident(IDENT_VOLLEY, (int)((unsigned)shot.volley ^ (unsigned)born * 2654435761u));
  }
  // By volley, then ident: each volley's members together, its lead first.
  std::sort(shots.begin(), shots.end(), [](const Light &a, const Light &b) {
    return a.volley != b.volley ? a.volley < b.volley : a.ident < b.ident;
  });
  source_count = first;
  for (size_t begin = 0; begin < shots.size();) {
    size_t end = begin + 1;
    while (end < shots.size() && shots[end].volley == shots[begin].volley)
      ++end;
    if (shots[begin].volley < 0) {
      for (size_t i = begin; i < end; ++i)
        sources[source_count++] = shots[i];
      begin = end;
      continue;
    }
    const Light *lead = nullptr;
    for (size_t i = begin; i < end && !lead; ++i)
      if (!selection.split.count(shots[i].ident))
        lead = &shots[i];
    float lead_head[2] = {0, 0};
    if (lead)
      head(*lead, lead_head);
    // The volley's own light: its pellets inside, and the shares still handing over.
    struct Part {
      const Light *light;
      float share;
    };
    std::vector<Part> parts;
    int inside = 0;
    for (size_t i = begin; i < end; ++i) {
      const Light &shot = shots[i];
      float h[2];
      head(shot, h);
      if (lead && !selection.split.count(shot.ident) && hypotf(h[0] - lead_head[0], h[1] - lead_head[1]) <= VOLLEY_UNITS) {
        parts.push_back({&shot, 1});
        ++inside;
        continue;
      }
      if (!selection.split.count(shot.ident)) {
        selection.split.insert(shot.ident);
        selection.handoff[shot.ident] = 1;
      }
      auto handing = selection.handoff.find(shot.ident);
      float share = handing == selection.handoff.end() ? 0 : handing->second;
      Light &own = sources[source_count++] = shot;
      own.r *= 1 - share, own.g *= 1 - share, own.b *= 1 - share;
      if (share > 0)
        parts.push_back({&shot, share});
    }
    begin = end;
    if (parts.size() == 1 && inside == 1) {
      sources[source_count++] = *parts[0].light;
      continue;
    }
    if (parts.empty())
      continue;
    // Heads and tails average by brightness.
    float head_xy[2] = {0, 0}, tail_xy[2] = {0, 0}, total = 0, r = 0, g = 0, b = 0;
    for (const Part &part : parts) {
      const Light &l = *part.light;
      float weight = fmaxf(fmaxf(l.r, fmaxf(l.g, l.b)), 1e-6f) * part.share;
      float h[2];
      head(l, h);
      head_xy[0] += h[0] * weight, head_xy[1] += h[1] * weight;
      tail_xy[0] += (l.x - l.dx * l.length * 0.5f) * weight, tail_xy[1] += (l.y - l.dy * l.length * 0.5f) * weight;
      total += weight;
      r += l.r * part.share, g += l.g * part.share, b += l.b * part.share;
    }
    Light &light = sources[source_count++] = *parts[0].light;
    float head_x = head_xy[0] / total, head_y = head_xy[1] / total;
    float tail_x = tail_xy[0] / total, tail_y = tail_xy[1] / total;
    float dx = head_x - tail_x, dy = head_y - tail_y, length = normalize(dx, dy);
    light.x = (head_x + tail_x) * 0.5f, light.y = (head_y + tail_y) * 0.5f;
    if (length > 1e-3f)
      light.dx = dx, light.dy = dy;
    light.length = length;
    light.r = r, light.g = g, light.b = b;
    light.ident = light.volley;
  }
}

// --- Beam energy (render/rtx/continuous_beam.py) ----------------------------------
// A streak lights the ground as one source: a ramp of its stamps from the tail
// to the head, and the head's own stamp as a uniform stretch around the head
// end. An appearance approximation, as in Python, in its double precision.
const double SUPPORT = 0.85998995;

const double *radial_marginal() {
  static double values[65];
  static bool made;
  for (int i = 0; i < 65 && !made; ++i) {
    double x = SUPPORT * i / 64, total = 0;
    for (int j = 0; j < 33; ++j) {
      double y = SUPPORT * j / 32, radius = hypot(x, y);
      double density = fmin(1.0, fmax(0.0, 1.3 * exp(-4.8 * radius - radius * radius) - 0.01));
      total += density * (j == 0 || j == 32 ? 0.5 : 1.0);
    }
    values[i] = total * 2 * SUPPORT / 32;
  }
  made = true;
  return values;
}

// A stamp's longitudinal extent as a uniform stretch of equal variance, in stamp radii.
double stamp_half_width() {
  static double width;
  if (!width) {
    const double *radial = radial_marginal();
    double step = SUPPORT / 64, mass = 0, second = 0;
    for (int i = 0; i < 65; ++i) {
      double weight = radial[i] * (i == 0 || i == 64 ? 0.5 : 1.0);
      mass += weight, second += weight * (i * step) * (i * step);
    }
    width = sqrt(3 * second / mass);
  }
  return width;
}

// beam_shape: the head's share of the beam's energy (each stamp holds its radius
// squared times the same projected mass; the ramp's stamps weigh their position
// over the length), the head's half-width, Ion, and the support's half-extent:
// the half length plus the head's halo. Zero for unselected lamps and
// reflection-only sources.
void beam_shape(const Light &light, float illumination, float *out) {
  memset(out, 0, 4 * sizeof(float));
  if (!light.beam_radius || illumination <= 0)
    return;
  double length = light.length, radius = light.beam_radius, head_radius = radius * light.beam_head;
  int stamps = length > 0 ? (int)ceil(length / light.beam_step) : 0;
  double ramp = stamps > 1 ? radius * radius * light.beam_step * stamps * (stamps - 1) / (2 * length) : 0;
  out[0] = (float)(head_radius * head_radius / (head_radius * head_radius + ramp));
  out[1] = (float)(stamp_half_width() * head_radius);
  out[2] = light.beam_ion;
  out[3] = (float)(length * 0.5 + head_radius * SUPPORT);
}

// Whether one response of the source can give the view anything, by the
// receivers' cutoffs (ground_lit.frag): its light within its radius of its
// segment (a beam's support, if longer) or ring, its reflection within its
// reach of its segment or ring. Boxed (material_lights.py's _reaches_view).
bool reaches_view(const Light &light, bool reflection, float view_x, float view_y, float half_width,
                  float half_height) {
  float reach = fmaxf(1, reflection ? light.reflection_reach() : light.radius), extent_x, extent_y;
  if (light.ring > 0) {
    extent_x = extent_y = light.ring + reach;
  } else {
    float ax = light.dx, ay = light.dy, shape[4];
    if (ax * ax + ay * ay > 0.0001f)
      normalize(ax, ay);
    else
      ax = 1, ay = 0;
    beam_shape(light, light.illumination, shape);
    float half = reflection ? light.length * 0.5f : fmaxf(light.length * 0.5f, shape[3]);
    extent_x = fabsf(ax) * half + reach, extent_y = fabsf(ay) * half + reach;
  }
  return fabsf(light.x - view_x) < half_width + extent_x && fabsf(light.y - view_y) < half_height + extent_y;
}

// A source's place in one response's budget for the view around (view_x,
// view_y): none when that response cannot reach it, however bright.
float view_score(const Light &light, bool reflection, float view_x, float view_y, float half_width,
                 float half_height) {
  return reaches_view(light, reflection, view_x, view_y, half_width, half_height)
             ? score(light, reflection, view_x, view_y)
             : 0;
}

} // namespace

// --- Body shadows (render/rtx/reflection_occlusion.py) ------------------------------
// One rotated, size-scaled ellipsoid per standard creature, fitted to its body's
// central mass (local x right, y down, as fractions of the drawn size: center,
// planar radii, height), packed into a grid of cells for the shader to walk.

namespace {
const float BODY_PROFILES[5][5] = {
    {-0.0625f, 0, 0.0975f, 0.13f, 0.46f}, // zombie
    {0.105f, 0, 0.115f, 0.09f, 0.32f},    // lizard
    {-0.08f, 0, 0.08f, 0.13f, 0.36f},     // alien
    {-0.13f, 0, 0.255f, 0.09f, 0.36f},    // spider SP1
    {-0.12f, 0, 0.245f, 0.12f, 0.40f},    // spider SP2
};
struct Body {
  float x, y, rx, ry, height, angle, opacity, owner_x, owner_y;
};
// A cell with more bodies standing in it than this is a crowd
// (reflection_occlusion.py): it holds their density and height instead of their
// list, and rays cross it as an absorbing medium (light_visibility.glsl), at a
// cost that no longer grows with the crowd.
const int CROWD_BODIES = 16;
const float PENUMBRA_WIDTH = 8;

bool body_of(const creature_t &c, Body &body) {
  if (!c.active || c.size <= 0 || c.death_timer <= 0 || c.type_id < 0 || c.type_id > 4)
    return false;
  // The drawn body slides down as it dies; its shadow follows that timer.
  float remaining = fminf(1, c.death_timer / 16);
  float height_scale = remaining * remaining * (3 - 2 * remaining);
  float fade = fminf(1, remaining * 4);
  float opacity = fminf(1, fmaxf(0, c.tint_a)) * fade * fade * (3 - 2 * fade);
  if (opacity <= 0)
    return false;
  const float *p = BODY_PROFILES[c.type_id];
  float angle = c.heading - HALF_PI;
  float right_x = cosf(angle), right_y = sinf(angle), down_x = -right_y, down_y = right_x;
  body = {c.pos_x + (right_x * p[0] + down_x * p[1]) * c.size, c.pos_y + (right_y * p[0] + down_y * p[1]) * c.size,
          p[2] * c.size, p[3] * c.size, p[4] * c.size * height_scale, angle, opacity, c.pos_x, c.pos_y};
  return true;
}

// A living player's torso: one ellipsoid facing its aim (half depth, half shoulder width, height, in units of its size).
const float PLAYER_BODY[3] = {0.125f, 0.22f, 0.46f};
// A bonus shell: the 32-unit dome bonus.frag draws, and its height.
const float BONUS_SHELL_RADIUS = 16 * 0.885f, BONUS_SHELL_HEIGHT = 10;

bool body_of(const player_state_t &player, Body &body) {
  if (player.health <= 0)
    return false;
  body = {player.pos_x, player.pos_y, PLAYER_BODY[0] * player.size, PLAYER_BODY[1] * player.size,
          PLAYER_BODY[2] * player.size, player.aim_heading - HALF_PI, 1, player.pos_x, player.pos_y};
  return true;
}

// The shell's fade as bonus_render draws it (blinking out over its last two seconds).
bool body_of(const bonus_entry_t &bonus, Body &body) {
  if (bonus.bonus_id == BONUS_ID_NONE)
    return false;
  float fade = 1, age = bonus.time.time_max - bonus.time.time_left;
  if (bonus.time.time_left < 2)
    fade = bonus.time.time_left * (sinf(bonus.time.time_left * 18.849556f) > 0 ? 0.25f : 0.5f);
  if (age < 0.5f)
    fade = age + age;
  float opacity = fminf(1, fmaxf(0, fade)) * 0.9f;
  if (opacity <= 0)
    return false;
  body = {bonus.time.pos_x, bonus.time.pos_y, BONUS_SHELL_RADIUS, BONUS_SHELL_RADIUS, BONUS_SHELL_HEIGHT, 0, opacity,
          bonus.time.pos_x, bonus.time.pos_y};
  return true;
}

std::vector<float> grid_values;
} // namespace

// The body grid for the selected lights (packed as rtx_collect_lights writes
// them): every body near a source's support, no nearest-N cap. `grid` gets the
// origin, columns (0 for no bodies), rows and cell size; the values are cell
// headers, body transforms and cell lists, four floats per texel. A header's
// xy holds its ordinary list; zw is reserved. All production visibility rays
// use that list, including the coarse ground atlas's nearest-emitter rays.
// A cell where more than CROWD_BODIES bodies stand holds their footprint-weighted
// top height and negative opacity-weighted footprint over the cell's area.
// A body centered in a crowd is listed only where it stands, outside crowd cells.
extern "C" const float *rtx_build_occlusion(const float *lights, int count, bool shadows, float *grid, int *value_count) {
  grid[0] = grid[1] = grid[2] = grid[3] = 0;
  grid[4] = 64;
  *value_count = 0;
  // Ground and creature visibility are both disabled. Return before scanning
  // the body pools or sources, and tell the host not to upload a stale grid.
  if (!shadows || count <= 0)
    return nullptr;
  Body bodies[std::size(creature_pool) + 2 + std::size(bonus_pool)];
  int body_total = 0;
  for (const creature_t &c : creature_pool)
    body_total += body_of(c, bodies[body_total]);
  for (int i = 0; i < config_blob.player_count && i < 2; ++i)
    body_total += body_of(player_state_table[i], bodies[body_total]);
  for (const bonus_entry_t &bonus : bonus_pool)
    body_total += body_of(bonus, bodies[body_total]);
  const float cell = 64;
  float padding = 0, lo_x = -cell, lo_y = -cell;
  float hi_x = terrain_texture_width + cell, hi_y = terrain_texture_height + cell;
  struct Support {
    float x, y, ax, ay, half, reach;
  } supports[32];
  int support_count = 0;
  for (int i = 0; i < count; ++i) {
    // A beam's head halo lengthens its support (prepare_beam_lights).
    float l[16];
    memcpy(l, lights + i * RTX_LIGHT_FLOATS, sizeof l);
    const float *cells = lights + i * RTX_LIGHT_FLOATS + 20;
    if (cells[3] > 0) {
      if (l[8] * l[8] + l[9] * l[9] <= 0.0001f)
        l[8] = 1, l[9] = 0;
      l[11] += 2 * lights[i * RTX_LIGHT_FLOATS + 18];
    }
    float illumination = l[12], reflection = l[13];
    if (!(reflection > 0 || illumination > 0))
      continue;
    // A body shadow's penumbra follows sources up to PENUMBRA_WIDTH wide (reflection_occlusion.py).
    padding = fminf(PENUMBRA_WIDTH, fmaxf(padding, fmaxf(0.1f, l[15])));
    float ax = l[8], ay = l[9];
    if (ax * ax + ay * ay > 0.0001f)
      normalize(ax, ay);
    else
      ax = ay = 0;
    float reach = fmaxf(reflection > 0 ? l[14] : 0, illumination > 0 ? l[2] : 0);
    supports[support_count++] = {l[0], l[1], ax, ay, l[11] * 0.5f, reach + l[7]};
    float ex = fabsf(ax * l[11] * 0.5f) + l[7], ey = fabsf(ay * l[11] * 0.5f) + l[7];
    lo_x = fminf(lo_x, l[0] - ex - cell), lo_y = fminf(lo_y, l[1] - ey - cell);
    hi_x = fmaxf(hi_x, l[0] + ex + cell), hi_y = fmaxf(hi_y, l[1] + ey + cell);
  }
  if (!support_count || !body_total)
    return nullptr;
  float origin_x = floorf(lo_x / cell) * cell, origin_y = floorf(lo_y / cell) * cell;
  int columns = (int)ceilf((hi_x - origin_x) / cell), rows = (int)ceilf((hi_y - origin_y) / cell);
  // Mark each source's conservative support once; bodies then cull against all of them.
  std::vector<unsigned char> active((size_t)columns * rows);
  auto span = [&](float center, float extent, float origin, int limit, int &first, int &last) {
    first = std::max(0, (int)floorf((center - extent - origin) / cell));
    last = std::min(limit - 1, (int)floorf((center + extent - origin) / cell));
  };
  for (int i = 0; i < support_count; ++i) {
    const Support &s = supports[i];
    int x0, x1, y0, y1;
    span(s.x, fabsf(s.ax) * s.half + s.reach, origin_x, columns, x0, x1);
    span(s.y, fabsf(s.ay) * s.half + s.reach, origin_y, rows, y0, y1);
    for (int y = y0; y <= y1; ++y)
      for (int x = x0; x <= x1; ++x)
        active[(size_t)y * columns + x] = 1;
  }
  // Each body's footprint, shared among the cells its planar extent overlaps by
  // area: how many bodies stand in a cell, and their cover and top height there.
  size_t total = (size_t)columns * rows;
  std::vector<int> standing(total);
  std::vector<float> crowd_cover(total), crowd_top(total);
  for (int b = 0; b < body_total; ++b) {
    const Body &body = bodies[b];
    float c = cosf(body.angle), s = sinf(body.angle);
    float ex = hypotf(c * body.rx, s * body.ry), ey = hypotf(s * body.rx, c * body.ry);
    float footprint = 3.14159265f * body.rx * body.ry * body.opacity / (cell * cell);
    int x0, x1, y0, y1;
    span(body.x, ex, origin_x, columns, x0, x1);
    span(body.y, ey, origin_y, rows, y0, y1);
    for (int y = y0; y <= y1; ++y) {
      float top = fminf(body.y + ey, origin_y + (y + 1) * cell) - fmaxf(body.y - ey, origin_y + y * cell);
      for (int x = x0; x <= x1; ++x) {
        float side = fminf(body.x + ex, origin_x + (x + 1) * cell) - fmaxf(body.x - ex, origin_x + x * cell);
        float share = fmaxf(0, side) * fmaxf(0, top) / (4 * ex * ey);
        if (share > 0) {
          size_t i = (size_t)y * columns + x;
          ++standing[i];
          crowd_cover[i] += footprint * share;
          crowd_top[i] += body.height * footprint * share;
        }
      }
    }
  }
  auto crowd = [&](size_t i) { return standing[i] > CROWD_BODIES; };
  std::vector<std::vector<int>> cells(total);
  grid_values.assign(total * 4, 0.0f);
  int placed = 0;
  for (int b = 0; b < body_total; ++b) {
    const Body &body = bodies[b];
    float c = cosf(body.angle), s = sinf(body.angle);
    float radius = fmaxf(body.rx, body.ry);
    float soft_margin = fmaxf(0.015f * radius, padding * radius / fminf(body.rx, body.ry));
    int home_x = (int)floorf((body.x - origin_x) / cell), home_y = (int)floorf((body.y - origin_y) / cell);
    bool member = home_x >= 0 && home_y >= 0 && home_x < columns && home_y < rows &&
                  crowd((size_t)home_y * columns + home_x);
    // A crowd's member shades the cells around it only where it stands; its crowd's medium stands for it.
    float margin = member ? 0 : soft_margin;
    float rx = hypotf(c * body.rx, s * body.ry) + margin, ry = hypotf(s * body.rx, c * body.ry) + margin;
    int address = (int)grid_values.size() / 4;
    bool occupies = false;
    int x0, x1, y0, y1;
    span(body.x, rx, origin_x, columns, x0, x1);
    span(body.y, ry, origin_y, rows, y0, y1);
    for (int y = y0; y <= y1; ++y)
      for (int x = x0; x <= x1; ++x)
        if (active[(size_t)y * columns + x] && !crowd((size_t)y * columns + x)) {
          cells[(size_t)y * columns + x].push_back(address);
          occupies = true;
        }
    if (!occupies)
      continue;
    ++placed;
    const float transform[12] = {body.x, body.y, body.height * 0.4f, radius + soft_margin,
                                 1 / body.rx, 1 / body.ry, 1 / (body.height * 0.6f), body.owner_x,
                                 c, s, body.opacity, body.owner_y};
    grid_values.insert(grid_values.end(), transform, transform + 12);
  }
  for (size_t i = 0; i < total; ++i) {
    if (crowd(i)) {
      grid_values[i * 4] = crowd_top[i] / crowd_cover[i];
      grid_values[i * 4 + 1] = -crowd_cover[i];
      continue;
    }
    grid_values[i * 4] = (float)(grid_values.size() / 4);
    grid_values[i * 4 + 1] = (float)cells[i].size();
    for (int address : cells[i])
      grid_values.insert(grid_values.end(), {(float)address, 0, 0, 0});
  }
  if (!placed && std::none_of(standing.begin(), standing.end(), [](int n) { return n > CROWD_BODIES; }))
    return nullptr;
  grid[0] = origin_x, grid[1] = origin_y, grid[2] = (float)columns, grid[3] = (float)rows, grid[4] = cell;
  *value_count = (int)grid_values.size();
  return grid_values.data();
}

// A beam's ground gain: ion beams', then Fire Bullets' (render/rtx/continuous_beam.py).
extern "C" const float rtx_beam_gain[2] = {4.0f, 3.0f};

// The frame's lights for the view, RTX_LIGHT_FLOATS each: position, radius,
// height; linear RGB, ring radius; direction, 0, length; illumination and
// reflection gains, reflection reach, source width; reflection tail, broad
// illumination, a beam's padding past its ends, its smoke gain; its energy
// shape (beam_shape).
// At most `capacity`.
extern "C" int rtx_collect_lights(float *out, int capacity) {
  source_count = 0;
  float view_x = grim_backbuffer_width * 0.5f - camera_offset.x;
  float view_y = grim_backbuffer_height * 0.5f - camera_offset.y;
  for (int i = 0; i < config_blob.player_count && i < 2; ++i)
    player_sources(player_state_table[i], i);
  // A slot's next shot is another source, even on the next frame: its spawn point tells them apart.
  auto number = [](int slot) {
    const projectile_t &p = projectile_pool[slot];
    return slot | ((int)floorf(p.fields.origin_x) & 0x7f) << 7 | ((int)floorf(p.fields.origin_y) & 0x7f) << 14;
  };
  int shots = source_count;
  for (int slot = 0; slot < (int)std::size(projectile_pool); ++slot)
    if (projectile_pool[slot].active)
      projectile_source(projectile_pool[slot], source_ident(IDENT_SHOT, number(slot)));
  selection.advance((float)run_elapsed_ms);
  merge_volleys(shots);
  for (int slot = 0; slot < (int)std::size(projectile_pool); ++slot)
    if (projectile_pool[slot].active)
      ion_arc_sources(projectile_pool[slot], view_x, view_y, source_ident(IDENT_ARC, number(slot) * 4));
  int slot = 0;
  for (const secondary_projectile_t &s : secondary_projectile_pool)
    secondary_sources(s, slot++);
  explosion_sources();
  flame_sources();

  // Each response selects independently; past MAX_SELECTED their union takes
  // the responses' sources rank by rank. Each fades across its budget's edge;
  // a source chosen by one alone has the other's gain zeroed.
  static float scores[2][MAX_SOURCES], weights[2][MAX_SOURCES];
  static int ranks[2][MAX_SOURCES], first_rank[MAX_SOURCES], order[MAX_SOURCES];
  static bool selected[MAX_SOURCES], chosen[2][MAX_SOURCES];
  for (int reflection = 0; reflection < 2; ++reflection) {
    for (int i = 0; i < source_count; ++i)
      scores[reflection][i] = view_score(sources[i], reflection, view_x, view_y, grim_backbuffer_width * 0.5f,
                                         grim_backbuffer_height * 0.5f);
    select(scores[reflection], ranks[reflection]);
  }
  int ranked = 0;
  for (int i = 0; i < source_count; ++i)
    if (ranks[0][i] >= 0 || ranks[1][i] >= 0) {
      first_rank[i] = ranks[1][i] < 0 || (ranks[0][i] >= 0 && ranks[0][i] < ranks[1][i]) ? ranks[0][i] : ranks[1][i];
      order[ranked++] = i;
    }
  std::sort(order, order + ranked, [&](int a, int b) {
    return first_rank[a] != first_rank[b] ? first_rank[a] < first_rank[b] : sources[a].ident < sources[b].ident;
  });
  memset(selected, 0, sizeof selected);
  for (int n = 0; n < std::min(ranked, (int)MAX_SELECTED); ++n)
    selected[order[n]] = true;
  for (int reflection = 0; reflection < 2; ++reflection) {
    for (int i = 0; i < source_count; ++i)
      chosen[reflection][i] = selected[i] && ranks[reflection][i] >= 0;
    selection.slew(reflection, chosen[reflection], weights[reflection]);
  }
  // The union, brightest first (both responses' delivered scores summed); past
  // `capacity` the faintest fading sources give way, never a selected one.
  static float delivered[MAX_SOURCES];
  int union_count = 0;
  for (int i = 0; i < source_count; ++i)
    if (weights[0][i] > 0 || weights[1][i] > 0) {
      delivered[i] = scores[0][i] * weights[0][i] + scores[1][i] * weights[1][i];
      order[union_count++] = i;
    }
  auto brighter = [&](int a, int b) {
    return delivered[a] != delivered[b] ? delivered[a] > delivered[b] : sources[a].ident < sources[b].ident;
  };
  std::sort(order, order + union_count, [&](int a, int b) { return selected[a] != selected[b] ? selected[a] : brighter(a, b); });
  int count = std::min(union_count, capacity);
  std::sort(order, order + count, brighter);
  for (int n = 0; n < count; ++n) {
    int i = order[n];
    const Light &l = sources[i];
    float illumination = l.illumination * weights[0][i];
    float *packed = out + n * RTX_LIGHT_FLOATS;
    const float head[20] = {l.x, l.y, l.radius, l.height, l.r, l.g, l.b, l.ring, l.dx, l.dy, 0, l.length,
                            illumination, l.reflection * weights[1][i], l.reflection_reach(), l.width,
                            l.tail, (float)l.broad, (float)(l.beam_radius * l.beam_head * SUPPORT), l.smoke_gain};
    memcpy(packed, head, sizeof head);
    beam_shape(l, illumination, packed + 20);
  }
  return count;
}

// An ion arc's contact glow, a 60-unit disc on its creature (ion_contact_glows),
// drawn on the ground in contact_glow.frag instead of taking a light, at the
// world's transition `alpha`. The color carries the arcs' hue at full value and
// their peak over GLOW_PEAK in alpha. The original sets its own state after.
extern "C" void rtx_contact_glows(float alpha) {
  const float RADIUS = 60, GLOW_PEAK = 4;
  if (!rtx_drawing() || alpha <= 1e-3f)
    return;
  float view_x = grim_backbuffer_width * 0.5f - camera_offset.x;
  float view_y = grim_backbuffer_height * 0.5f - camera_offset.y;
  bool drawing = false;
  for (projectile_t &p : projectile_pool) {
    ArcTarget targets[4];
    float rgb[3];
    int count = ion_arc_targets(p, view_x, view_y, targets, rgb);
    float peak = fmaxf(fmaxf(rgb[0], fmaxf(rgb[1], rgb[2])), 1e-6f);
    for (int i = 0; i < count; ++i) {
      if (!drawing) {
        grim_interface_ptr->grim_flush_batch();
        grim_interface_ptr->grim_set_config_var(0x13, 2u); // D3DBLEND_ONE, added
        grim_interface_ptr->grim_set_config_var(0x14, 2u);
        host_render_pass(HOST_PASS_GLOW);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
        grim_interface_ptr->grim_set_rotation(0);
        drawing = true;
      }
      grim_interface_ptr->grim_set_color(fminf(1, rgb[0] / peak), fminf(1, rgb[1] / peak), fminf(1, rgb[2] / peak),
                                         fminf(1, peak / GLOW_PEAK * alpha));
      grim_interface_ptr->grim_draw_quad(camera_offset.x + targets[i].x - RADIUS, camera_offset.y + targets[i].y - RADIUS,
                                         RADIUS * 2, RADIUS * 2);
    }
  }
  if (!drawing)
    return;
  grim_interface_ptr->grim_end_batch();
  grim_interface_ptr->grim_flush_batch();
  host_render_pass(HOST_PASS_SPRITES);
}

// The living players' Sharpshooter sights, near and far ends: fluid smoke
// scatters them as narrow red beams (render/rtx/smoke.py).
extern "C" int rtx_collect_sights(float *out, int capacity) {
  int count = 0;
  if (!perk_count_get(perk_id_sharpshooter))
    return 0;
  for (int i = 0; i < config_blob.player_count && i < 2 && count < capacity; ++i)
    if (player_state_table[i].health > 0) {
      sight_geometry(player_state_table[i], out[count * 4], out[count * 4 + 1], out[count * 4 + 2], out[count * 4 + 3]);
      ++count;
    }
  return count;
}

// An explosion burst starting at (x, y) (effect_spawn_explosion_burst), until rtx_explosion_end.
extern "C" void rtx_explosion_begin(float x, float y, float scale) {
  if (explosions.size() >= MAX_EXPLOSIONS)
    explosions.erase(explosions.begin());
  explosions.push_back({x, y, scale, 0, rocket_burst_slot < 0, false, rocket_burst_slot, nullptr, 0, {}});
  bursting = &explosions.back();
}
extern "C" void rtx_explosion_end() { bursting = nullptr; }
extern "C" void rtx_explosion_rocket(int slot) { rocket_burst_slot = slot; }
// A reused projectile slot must not inherit the old fireball's light ownership.
// The old visible fireball continues to light its own position until it fades.
extern "C" void rtx_secondary_spawn(int slot) {
  for (Explosion &e : explosions)
    if (e.rocket_slot == slot)
      e.rocket_slot = -1;
}

// An effect the burst spawned (effect_spawn): its ring, and its fireball sprites
// as they start out.
extern "C" void rtx_explosion_effect(int effect_id, const effect_entry_t *entry) {
  if (!bursting)
    return;
  if (effect_id == 0x01) {
    bursting->ring_spawned = true;
    bursting->ring = entry;
  } else if (effect_id == 0x0c && bursting->fireball_count < 4) {
    float rgba[4];
    memcpy(rgba, &entry->color, sizeof rgba);
    bursting->fireballs[bursting->fireball_count++] = {
        entry->pos_x,    entry->pos_y,         entry->vel_x,    entry->vel_y,    entry->half_width,
        entry->half_height, entry->scale,      entry->scale_step, entry->rotation, entry->rotation_step,
        entry->lifetime, {rgba[0], rgba[1], rgba[2]}, entry};
  }
}

// A freed slot (effect_free) is no longer any explosion's: a later effect may reuse it.
// Only a ring or a fireball can be one's (rtx_explosion_effect), so a burst of
// blood or ice expiring never searches the archive.
extern "C" void rtx_explosion_release(const effect_entry_t *entry) {
  if (entry->effect_id != 0x01 && entry->effect_id != 0x0c)
    return;
  for (Explosion &e : explosions) {
    if (e.ring == entry)
      e.ring = nullptr;
    for (int i = 0; i < e.fireball_count; ++i)
      if (e.fireballs[i].entry == entry)
        e.fireballs[i].entry = nullptr;
  }
}

// Whether RTX draws a native effect itself (effects_render): a lit explosion's
// ring becomes its pressure shell, and its fireballs are drawn at half speed
// from how they spawned. A rocket's ring keeps its native timing and uses the analytic profile.
extern "C" int rtx_explosion_owns(const effect_entry_t *entry) {
  for (const Explosion &e : explosions) {
    if (e.ring == entry && entry->effect_id == 0x01)
      return e.emit_light;
    if (e.archives_fireballs())
      for (int i = 0; i < e.fireball_count; ++i)
        if (e.fireballs[i].entry == entry)
          return 1;
  }
  return 0;
}

// Unretimed rocket rings keep the pressure profile too. Select by provenance,
// since projectile impacts and bonus pulses share exactly the same atlas cell.
extern "C" bool rtx_explosion_ring(const effect_entry_t *entry) {
  for (const Explosion &e : explosions)
    if (e.ring == entry && entry->effect_id == 0x01)
      return true;
  return false;
}

// The shells and retimed fireballs, added after the native additive effects:
// each fireball sampled at half the explosion's age, so it lasts 1.4 s.
extern "C" void rtx_explosions_draw() {
  auto quad = [](int effect_id, float x, float y, float half_width, float half_height, float scale, float rotation,
                 float r, float g, float b, float a) {
    float w = half_width * 2 * scale, h = half_height * 2 * scale;
    if (w <= 0 || h <= 0)
      return;
    grim_interface_ptr->grim_set_color(r, g, b, a);
    grim_interface_ptr->grim_set_rotation(rotation);
    effect_select_texture(effect_id);
    grim_interface_ptr->grim_draw_quad(camera_offset.x + x - w * 0.5f, camera_offset.y + y - h * 0.5f, w, h);
  };
  for (const Explosion &e : explosions) {
    Shell shell;
    if (e.has_shell(shell))
      rtx_pressure_ring(e.x, e.y, shell.radius, shell.alpha);
    if (!e.archives_fireballs())
      continue;
    float age = e.age * 0.5f;
    for (int i = 0; i < e.fireball_count; ++i) {
      const Fireball &f = e.fireballs[i];
      quad(0x0c, f.x + f.vx * age, f.y + f.vy * age, f.half_width, f.half_height, f.scale + f.scale_step * age,
           f.rotation + f.rotation_step * age, f.rgb[0], f.rgb[1], f.rgb[2], fmaxf(0, 1 - age / f.lifetime));
    }
  }
}

// The pressure fronts the host displaces the world by (shockwaves.py), the last
// 16: center and radii on the screen, and strength.
extern "C" int rtx_collect_fronts(float *out, int capacity) {
  int count = 0;
  for (const Explosion &e : explosions) {
    Shell shell;
    if (!e.has_shell(shell))
      continue;
    if (count == capacity) {
      memmove(out, out + 4, (capacity - 1) * 4 * sizeof(float));
      --count;
    }
    const float front[4] = {e.x + camera_offset.x, e.y + camera_offset.y, shell.radius, shell.strength};
    memcpy(out + count++ * 4, front, sizeof front);
  }
  return count;
}

// The effects' update (effects_update): explosions age with them and go at the
// end of their light.
extern "C" void rtx_explosions_age(float dt) {
  for (Explosion &e : explosions)
    e.age += dt;
  explosions.erase(std::remove_if(explosions.begin(), explosions.end(),
                                  [](const Explosion &e) { return e.age >= e.lifetime(); }),
                   explosions.end());
}
// What the lights keep beside a run: the explosions and the budgets' fades.
extern "C" void rtx_lights_reset() {
  explosions.clear();
  bursting = nullptr;
  rocket_burst_slot = -1;
  selection.reset();
}
