// The RTX world's light sources, after the Python port's
// src/crimson/render/rtx/material_lights.py: finite luminous discs, tapered
// segments and annuli read from the frame's projectiles, muzzle flashes, perks,
// rockets, detonations and flame particles. RGB is linear source radiance; the
// illumination and reflection gains and reaches are art controls. Each response
// keeps its 16 strongest sources for the view, and their union goes to the host
// (game/rtx.cpp), at most 32. Reading the run only: nothing here writes it.
#include "crimsonland_gameplay.h"
#include "crimsonland_config_owner.h"
#include "render_passes.h"
#include "grim2d_cpp.h"
#include <algorithm>
#include <math.h>
#include <string.h>
#include <vector>

extern "C" {
extern int perk_id_radioactive, perk_id_sharpshooter, perk_id_ion_gun_master, perk_id_monster_vision;
extern float game_time_s;
extern vec2f_t camera_offset;
extern unsigned int grim_backbuffer_width, grim_backbuffer_height;
int creature_find_in_radius(float *pos, float radius, int start_index);
void effect_select_texture(int effect_id);
}
extern IGrim2D_cpp *grim_interface_ptr;

namespace {

const float HALF_PI = 1.5707964f;
const float INF = 1e30f;
enum { MAX_ILLUMINATION = 16, MAX_REFLECTION = 16, MAX_SOURCES = 256 };

// A luminous disc, tapered segment or annulus (MaterialLight). A beam's streak
// (its stamp radius, spacing and head size) lights the ground in energy sections.
struct Light {
  float x, y, radius, r, g, b;
  float height = 18, dx = 0, dy = 0, length = 0, width = 3;
  float illumination = 1, reflection = 1, reach = -1, ring = 0;
  float tail = 0.18f;
  bool broad = false;
  float beam_radius = 0, beam_step = 0, beam_head = 0;
  bool beam_ion = false;
  float smoke_gain = 1; // fluid smoke's scattering response, apart from the ground's and creatures'
  float reflection_reach() const { return reach < 0 ? radius : reach; }
};
Light sources[MAX_SOURCES];
int source_count;

Light &add(float x, float y, float radius, float r, float g, float b) {
  static Light overflow;
  Light &light = source_count < MAX_SOURCES ? sources[source_count++] : overflow;
  light = Light{x, y, radius, r, g, b};
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
  static const Emission pulse = {0.025f, 0.24f, 0.04f, 75, 5, 18, 0.15f, 1, 130, 0, 1};
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

void projectile_source(const projectile_t &p) {
  int type = p.fields.type_id;
  const Emission *e = emission(type);
  float life = p.fields.life_timer;
  if (!p.active || !e || life <= 0)
    return;
  float gain = powf(fminf(1, life * 2.5f), e->fade_power);
  float dx = p.fields.pos_x - p.fields.origin_x, dy = p.fields.pos_y - p.fields.origin_y;
  float distance = normalize(dx, dy);
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
  } else if (type == PROJECTILE_TYPE_PULSE_GUN) {
    width = fminf(18, fmaxf(1, distance * 0.035f));
    if (life < 0.4f)
      r = 0.7f, g = 0.36f, b = 0.08f, width = 5;
  }
  if (streak_scale(type) && dx == 0 && dy == 0)
    heading_direction(p.angle, dx, dy);
  Light &light = add(p.fields.pos_x - dx * span * 0.5f, p.fields.pos_y - dy * span * 0.5f, e->radius, r * gain,
                     g * gain, b * gain);
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
  }
}

// Up to four arcs of an ion impact, and their contact glows, nearest the view
// first (render/ion_arcs.py); the arcs reach what projectile_render's impact
// pass does.
void ion_arc_sources(projectile_t &p, float view_x, float view_y) {
  int type = p.fields.type_id;
  float life = p.fields.life_timer;
  if (!p.active || !(life > 0 && life < 0.4f) || type == PROJECTILE_TYPE_FIRE_BULLETS || !streak_scale(type))
    return;
  float scale = streak_scale(type);
  float reach = scale * (perk_count_get(perk_id_ion_gun_master) ? 1.2f : 1.0f) * 40.0f;
  struct Target {
    float x, y, segment, endpoint;
  } targets[4];
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
    Target t = {tx, ty, sx * sx + sy * sy, (tx - view_x) * (tx - view_x) + (ty - view_y) * (ty - view_y)};
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
  float width = scale * 1.5f;
  for (int i = 0; i < count; ++i) {
    float dx = targets[i].x - p.fields.pos_x, dy = targets[i].y - p.fields.pos_y;
    float length = normalize(dx, dy);
    Light &arc = add((p.fields.pos_x + targets[i].x) * 0.5f, (p.fields.pos_y + targets[i].y) * 0.5f, 100,
                     e->r * energy, e->g * energy, e->b * energy);
    arc.dx = dx, arc.dy = dy, arc.length = length, arc.width = width;
    arc.illumination = 0.75f, arc.reflection = 0.5f, arc.reach = 120;
    arc.tail = 1, arc.broad = true;
    Light &glow = add(targets[i].x, targets[i].y, 60, e->r * energy, e->g * energy, e->b * energy);
    glow.width = width * 1.5f;
    glow.illumination = 0.25f, glow.reflection = 0.25f, glow.reach = 90;
    glow.broad = true;
  }
}

// The native Sharpshooter sight (render/laser_sight.py): from beside the gun to 512 units out.
void sight_geometry(const player_state_t &player, float &near_x, float &near_y, float &far_x, float &far_y) {
  float heading = player.aim_heading - HALF_PI;
  far_x = player.pos_x + cosf(heading) * 512, far_y = player.pos_y + sinf(heading) * 512;
  float near_heading = heading - 0.150915f;
  near_x = player.pos_x + cosf(near_heading) * 15, near_y = player.pos_y + sinf(near_heading) * 15;
}

void player_sources(const player_state_t &player) {
  if (perk_count_get(perk_id_radioactive)) {
    // Follow the visible aura, including its native post-death presence.
    float pulse = ((sinf(game_time_s) + 1) * 0.1875f + 0.25f) / 0.4375f;
    Light &aura = add(player.pos_x, player.pos_y, 100, 0.10f, 0.70f, 0.07f);
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
    Light &sight = add((near_x + far_x) * 0.5f, (near_y + far_y) * 0.5f, 40, 1.3f, 0, 0);
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
  Light &muzzle = add(player.pos_x + cosf(heading) * 16, player.pos_y + sinf(heading) * 16, energetic ? 130.0f : 65.0f,
                      1.6f * gain, 1.0f * gain, 0.4f * gain);
  muzzle.height = 28, muzzle.width = 4;
  muzzle.illumination = energetic ? 0.8f : 0.12f, muzzle.reflection = 0.6f, muzzle.reach = 140;
  muzzle.broad = energetic;
}

void secondary_sources(const secondary_projectile_t &s) {
  if (!s.active)
    return;
  int type = s.fields.type_id;
  if (type == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
    // A detonation keeps its progress and scale in its velocity.
    float t = fmaxf(0, fminf(1, s.fields.vel_x)), scale = s.fields.vel_y;
    float gain = powf(1 - t, 1.35f);
    if (gain > 0.02f) {
      Light &blast = add(s.fields.pos_x, s.fields.pos_y, 360 * fmaxf(0.35f, scale), 1.75f * gain, 1.05f * gain,
                         0.38f * gain);
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
    Light &exhaust = add(s.fields.pos_x - dx * 12, s.fields.pos_y - dy * 12, 110 * scale, 0.9f * scale, 0.47f * scale,
                         0.1f * scale);
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
  const effect_entry_t *ring; // its ring's slot, while it holds it
  int fireball_count;
  Fireball fireballs[4];
  bool has_shell(Shell &shell) const { return emit_light && ring_spawned && explosion_shell(age, scale, shell); }
  bool archives_fireballs() const { return emit_light && age >= 0 && age < lifetime(); }
  float lifetime() const { return emit_light ? 1.4f : 0.7f; }
  // The moving sprites' bounds give the emitting footprint; the luminous core
  // fills about 35% of them.
  float fireball_radius() const {
    float age = this->age * 0.5f, extent = fireball_count ? 0.0f : 32 * scale;
    for (int i = 0; i < fireball_count; ++i) {
      const Fireball &f = fireballs[i];
      float dx = f.vx * age + f.x - x, dy = f.vy * age + f.y - y;
      extent = fmaxf(extent, sqrtf(dx * dx + dy * dy) + f.half() * (f.scale + f.scale_step * age));
    }
    return fmaxf(12 * scale, fminf(90 * scale, extent * 0.35f));
  }
};
std::vector<Explosion> explosions;
Explosion *bursting; // the burst being spawned
bool dark_bursts;    // a rocket hit's burst: its detonation lights it instead

void explosion_sources() {
  for (const Explosion &e : explosions) {
    float scale = fmaxf(0.1f, e.scale);
    Shell front;
    if (e.has_shell(front)) {
      float energy = front.energy;
      Light &shell = add(e.x, e.y, 85 * scale, 0.60f * energy, 0.39f * energy, 0.18f * energy);
      shell.height = 16 * scale, shell.ring = front.radius, shell.width = 8 * scale;
      shell.illumination = 1.8f, shell.reflection = 0.65f, shell.reach = 100 * scale, shell.broad = true;
    }
    if (!e.emit_light || !e.fireball_count || e.age < 0 || e.age >= e.lifetime())
      continue;
    // A fast flash, the visible fireball sustained, then a fade with its retimed alpha.
    float t = e.age;
    float fade = fminf(1, fmaxf(0, 1 - t / e.lifetime()) / 0.75f);
    float gain = 0.2f * expf(-t / 0.08f) + 0.8f * powf(fade, 1.1f);
    float rise = fminf(t / 0.8f, 1);
    rise = rise * rise * (3 - 2 * rise);
    Light &fireball = add(e.x, e.y, 330 * scale, 1.8f * gain, 0.92f * gain, 0.3f * gain);
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
  } cells[128];
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
    Light &flame = add(cell.x_sum / cell.weight, cell.y_sum / cell.weight, 110, rgb[0] * scale, rgb[1] * scale,
                       rgb[2] * scale);
    flame.height = 20;
    flame.dx = dx, flame.dy = dy, flame.length = speed > 0 ? 28.0f : 0.0f, flame.width = 5, flame.reach = 140;
    flame.broad = true;
  }
}

float distance_sq(const Light &light, float x, float y) {
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
  float along = fmaxf(-light.length * 0.5f, fminf(light.length * 0.5f, px * ax + py * ay));
  float qx = px - ax * along, qy = py - ay * along;
  return qx * qx + qy * qy;
}

float score(const Light &light, bool reflection, float view_x, float view_y) {
  float gain = reflection ? light.reflection : light.illumination;
  float radius = reflection ? light.reflection_reach() : light.radius;
  return fmaxf(light.r, fmaxf(light.g, light.b)) * gain /
         (1 + distance_sq(light, view_x, view_y) / fmaxf(1, radius * radius));
}

// The `limit` best-scoring sources of one response, as flags.
void select(bool reflection, int limit, float view_x, float view_y, bool *chosen) {
  float scores[MAX_SOURCES];
  for (int i = 0; i < source_count; ++i)
    scores[i] = score(sources[i], reflection, view_x, view_y);
  for (int n = 0; n < limit; ++n) {
    int best = -1;
    for (int i = 0; i < source_count; ++i)
      if (!chosen[i] && scores[i] > 0 && (best < 0 || scores[i] > scores[best]))
        best = i;
    if (best < 0)
      break;
    chosen[best] = true;
  }
}

// --- Beam energy sections (render/rtx/continuous_beam.py) ---------------------------
// A streak lights the ground as three energy-weighted sections of its stamps
// and head: mass, offset from the beam's midpoint, longitudinal half-span, and
// whether it is an ion beam. An appearance approximation, as in Python, in its
// double precision.
const double SUPPORT = 0.85998995, MAX_SECTION_HALFSPAN = 4.0;
enum { SOURCE_CELLS = 3 };

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

double radial_density(double r) {
  const double *radial = radial_marginal();
  r = fabs(r);
  if (r >= SUPPORT)
    return 0;
  double t = r / SUPPORT * 64;
  int index = (int)t;
  return radial[index] + (radial[index + 1] - radial[index]) * (t - index);
}

// source_cells: each cell samples the authored stamps near it plus the head.
void source_cells(double length, double radius, double step, double head_multiplier, float *out) {
  double support = radius * SUPPORT, head_radius = radius * head_multiplier, pad = head_radius * SUPPORT;
  double span = length + 2 * pad;
  int stamp_count = (int)ceil(length / step), samples = 32;
  double values[SOURCE_CELLS * 4], total = 0;
  for (int cell = 0; cell < SOURCE_CELLS; ++cell) {
    double mass = 0, first = 0, second = 0;
    for (int j = 0; j < samples; ++j) {
      double u = (cell + (j + 0.5) / samples) / SOURCE_CELLS, x = -pad + u * span;
      double energy = head_radius * radial_density((x - length) / head_radius);
      if (length > 0) {
        int lo = std::max(0, (int)ceil((x - support) / step));
        int hi = std::min(stamp_count - 1, (int)floor((x + support) / step));
        for (int k = lo; k <= hi; ++k) {
          double position = k * step;
          energy += position / length * radius * radial_density((x - position) / radius);
        }
      }
      mass += energy, first += energy * u, second += energy * u * u;
    }
    double mean = mass ? first / mass : (cell + 0.5) / SOURCE_CELLS;
    double half_span = mass ? sqrt(fmax(0.0, 3 * (second / mass - mean * mean))) : 0.0;
    double cell_values[4] = {mass, -pad + mean * span - length * 0.5, half_span * span, 0};
    memcpy(values + cell * 4, cell_values, sizeof cell_values);
    total += mass;
  }
  for (int i = 0; i < SOURCE_CELLS * 4; ++i)
    out[i] = (float)(i % 4 == 0 ? values[i] / total : values[i]);
}

// beam_cells: unselected lamps stay dark, as do reflection-only sources.
void beam_cells(const Light &light, float illumination, float *out) {
  memset(out, 0, SOURCE_CELLS * 4 * sizeof(float));
  if (!light.beam_radius || illumination <= 0)
    return;
  source_cells(light.length, light.beam_radius, light.beam_step, light.beam_head, out);
  for (int i = 0; i < SOURCE_CELLS * 4; ++i)
    if (i % 4 == 3)
      out[i] = light.beam_ion;
    else if (i % 4 == 2)
      out[i] = (float)fmin(out[i], MAX_SECTION_HALFSPAN);
}

} // namespace

// --- Creature shadows (render/rtx/reflection_occlusion.py) --------------------------
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

std::vector<float> grid_values;
} // namespace

// The body grid for the selected lights (packed as rtx_collect_lights writes
// them): every body near a source's support, no nearest-N cap. `grid` gets the
// origin, columns (0 for no bodies), rows and cell size; the values are cell
// headers, body transforms and cell lists, four floats per texel.
extern "C" const float *rtx_build_occlusion(const float *lights, int count, bool shadows, float *grid, int *value_count) {
  Body bodies[385];
  int body_total = 0;
  for (const creature_t &c : creature_pool)
    if (body_total < 385 && body_of(c, bodies[body_total]))
      ++body_total;
  grid[0] = grid[1] = grid[2] = grid[3] = 0;
  grid[4] = 64;
  *value_count = 0;
  float cell = body_total >= 512 ? 32.0f : 64.0f;
  float padding = 0, lo_x = -cell, lo_y = -cell;
  float hi_x = terrain_texture_width + cell, hi_y = terrain_texture_height + cell;
  struct Support {
    float x, y, ax, ay, half, reach;
  } supports[32];
  int support_count = 0;
  for (int i = 0; i < count; ++i) {
    // A beam's sections widen and lengthen its support (prepare_beam_lights).
    float l[16];
    memcpy(l, lights + i * RTX_LIGHT_FLOATS, sizeof l);
    const float *cells = lights + i * RTX_LIGHT_FLOATS + 20;
    if (cells[0] > 0) {
      if (l[8] * l[8] + l[9] * l[9] <= 0.0001f)
        l[8] = 1, l[9] = 0;
      l[15] += fmaxf(cells[2], fmaxf(cells[6], cells[10]));
      l[11] += 2 * lights[i * RTX_LIGHT_FLOATS + 18];
    }
    float illumination = l[12], reflection = l[13];
    if (!(reflection > 0 || (shadows && illumination > 0)))
      continue;
    padding = fmaxf(padding, fmaxf(0.1f, l[15]));
    float ax = l[8], ay = l[9];
    if (ax * ax + ay * ay > 0.0001f)
      normalize(ax, ay);
    else
      ax = ay = 0;
    float reach = fmaxf(reflection > 0 ? l[14] : 0, shadows && illumination > 0 ? l[2] : 0);
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
  std::vector<std::vector<int>> cells((size_t)columns * rows);
  grid_values.assign((size_t)columns * rows * 4, 0.0f);
  int placed = 0;
  for (int b = 0; b < body_total; ++b) {
    const Body &body = bodies[b];
    float c = cosf(body.angle), s = sinf(body.angle);
    float radius = fmaxf(body.rx, body.ry);
    float soft_margin = fmaxf(0.015f * radius, padding * radius / fminf(body.rx, body.ry));
    float rx = hypotf(c * body.rx, s * body.ry) + soft_margin, ry = hypotf(s * body.rx, c * body.ry) + soft_margin;
    int x0, x1, y0, y1;
    span(body.x, rx, origin_x, columns, x0, x1);
    span(body.y, ry, origin_y, rows, y0, y1);
    int address = (int)grid_values.size() / 4;
    bool occupies = false;
    for (int y = y0; y <= y1; ++y)
      for (int x = x0; x <= x1; ++x)
        if (active[(size_t)y * columns + x]) {
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
  if (!placed)
    return nullptr;
  for (size_t i = 0; i < cells.size(); ++i) {
    grid_values[i * 4] = (float)(grid_values.size() / 4);
    grid_values[i * 4 + 1] = (float)cells[i].size();
    for (int address : cells[i])
      grid_values.insert(grid_values.end(), {(float)address, 0, 0, 0});
  }
  grid[0] = origin_x, grid[1] = origin_y, grid[2] = (float)columns, grid[3] = (float)rows, grid[4] = cell;
  *value_count = (int)grid_values.size();
  return grid_values.data();
}

// A beam section's ground gain and the ambient dip around it: ion beams', then
// Fire Bullets' (render/rtx/continuous_beam.py).
extern "C" const float rtx_beam_tuning[4] = {4.0f, 0.25f, 3.0f, 0.15f};

// The frame's lights for the view, RTX_LIGHT_FLOATS each: position, radius,
// height; linear RGB, ring radius; direction, 0, length; illumination and
// reflection gains, reflection reach, source width; reflection tail, broad
// illumination, a beam's padding past its ends, its smoke gain; its three
// energy sections.
// At most `capacity`.
extern "C" int rtx_collect_lights(float *out, int capacity) {
  source_count = 0;
  float view_x = grim_backbuffer_width * 0.5f - camera_offset.x;
  float view_y = grim_backbuffer_height * 0.5f - camera_offset.y;
  for (int i = 0; i < config_blob.player_count && i < 2; ++i)
    player_sources(player_state_table[i]);
  for (projectile_t &p : projectile_pool) {
    projectile_source(p);
    ion_arc_sources(p, view_x, view_y);
  }
  for (const secondary_projectile_t &s : secondary_projectile_pool)
    secondary_sources(s);
  explosion_sources();
  flame_sources();

  // Each response selects independently; a source chosen by one alone has the other's gain zeroed.
  bool lit[MAX_SOURCES] = {}, reflected[MAX_SOURCES] = {};
  select(false, MAX_ILLUMINATION, view_x, view_y, lit);
  select(true, MAX_REFLECTION, view_x, view_y, reflected);
  int count = 0;
  for (int i = 0; i < source_count && count < capacity; ++i) {
    if (!lit[i] && !reflected[i])
      continue;
    const Light &l = sources[i];
    float illumination = lit[i] ? l.illumination : 0;
    float *packed = out + count++ * RTX_LIGHT_FLOATS;
    const float head[20] = {l.x, l.y, l.radius, l.height, l.r, l.g, l.b, l.ring, l.dx, l.dy, 0, l.length,
                            illumination, reflected[i] ? l.reflection : 0, l.reflection_reach(), l.width,
                            l.tail, (float)l.broad, (float)(l.beam_radius * l.beam_head * SUPPORT), l.smoke_gain};
    memcpy(packed, head, sizeof head);
    beam_cells(l, illumination, packed + 20);
  }
  return count;
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
  if (explosions.size() >= 128)
    explosions.erase(explosions.begin());
  explosions.push_back({x, y, scale, 0, !dark_bursts, false, nullptr, 0, {}});
  bursting = &explosions.back();
}
extern "C" void rtx_explosion_end() { bursting = nullptr; }
// Whether the next bursts are rocket hits, which the detonation lights instead.
extern "C" void rtx_explosion_dark(int dark) { dark_bursts = dark; }

// An effect the burst spawned (effect_spawn): its ring, and its fireball sprites
// as they start out.
extern "C" void rtx_explosion_effect(int effect_id, const effect_entry_t *entry) {
  if (!bursting)
    return;
  if (effect_id == 0x01) {
    bursting->ring_spawned = true;
    bursting->ring = entry;
  } else if (effect_id == 0x0c && bursting->emit_light && bursting->fireball_count < 4) {
    float rgba[4];
    memcpy(rgba, &entry->color, sizeof rgba);
    bursting->fireballs[bursting->fireball_count++] = {
        entry->pos_x,    entry->pos_y,         entry->vel_x,    entry->vel_y,    entry->half_width,
        entry->half_height, entry->scale,      entry->scale_step, entry->rotation, entry->rotation_step,
        entry->lifetime, {rgba[0], rgba[1], rgba[2]}, entry};
  }
}

// A freed slot (effect_free) is no longer any explosion's: a later effect may reuse it.
extern "C" void rtx_explosion_release(const effect_entry_t *entry) {
  for (Explosion &e : explosions) {
    if (e.ring == entry)
      e.ring = nullptr;
    for (int i = 0; i < e.fireball_count; ++i)
      if (e.fireballs[i].entry == entry)
        e.fireballs[i].entry = nullptr;
  }
}

// Whether RTX draws a native effect itself (effects_render): an explosion's ring
// becomes its pressure shell (or nothing, for a rocket's), and a lit explosion's
// fireballs are drawn at half speed from how they spawned.
extern "C" int rtx_explosion_owns(const effect_entry_t *entry) {
  for (const Explosion &e : explosions) {
    if (e.ring == entry && entry->effect_id == 0x01)
      return 1;
    if (e.archives_fireballs())
      for (int i = 0; i < e.fireball_count; ++i)
        if (e.fireballs[i].entry == entry)
          return 1;
  }
  return 0;
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
      quad(0x01, e.x, e.y, shell.radius, shell.radius, 1, 0, 190 / 255.0f, 163 / 255.0f, 122 / 255.0f, shell.alpha);
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
extern "C" void rtx_explosions_reset() {
  explosions.clear();
  bursting = nullptr;
}

// Monster Vision's ground light (render/rtx/perk_lighting.py): each living or
// fading creature's aura whose 60-unit support meets the view, at its native
// death fade and the world's transition `alpha`, as x, y, alpha. No cap.
extern "C" int rtx_collect_monster_vision(float *out, int capacity, float alpha) {
  if (!perk_count_get(perk_id_monster_vision) || alpha <= 1e-3f)
    return 0;
  const float radius = 60;
  float lo_x = -camera_offset.x, lo_y = -camera_offset.y;
  float hi_x = lo_x + grim_backbuffer_width, hi_y = lo_y + grim_backbuffer_height;
  int count = 0;
  for (const creature_t &c : creature_pool) {
    if (!c.active || count >= capacity)
      continue;
    float fade = c.death_timer >= 0 ? 1.0f : fminf(1, fmaxf(0, (c.death_timer + 10) * 0.1f));
    float a = fade * fminf(1, fmaxf(0, alpha));
    if (a <= 1e-3f || c.pos_x + radius <= lo_x || c.pos_y + radius <= lo_y || c.pos_x - radius >= hi_x ||
        c.pos_y - radius >= hi_y)
      continue;
    out[count * 3] = c.pos_x, out[count * 3 + 1] = c.pos_y, out[count * 3 + 2] = a;
    ++count;
  }
  return count;
}
