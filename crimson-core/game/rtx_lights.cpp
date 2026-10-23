// The RTX world's light sources, after the Python port's
// src/crimson/render/rtx/material_lights.py: finite luminous discs, tapered
// segments and annuli read from the frame's projectiles, muzzle flashes, perks,
// rockets, detonations and flame particles. RGB is linear source radiance; the
// illumination and reflection gains and reaches are art controls. Each response
// keeps its 16 strongest sources for the view, and their union goes to the host
// (game/rtx.cpp), at most 32. Reading the run only: nothing here writes it.
#include "crimsonland_gameplay.h"
#include "crimsonland_config_owner.h"
#include <math.h>
#include <string.h>

extern "C" {
extern int perk_id_radioactive, perk_id_sharpshooter, perk_id_ion_gun_master;
extern float game_time_s;
extern vec2f_t camera_offset;
extern unsigned int grim_backbuffer_width, grim_backbuffer_height;
int creature_find_in_radius(float *pos, float radius, int start_index);
}

namespace {

const float HALF_PI = 1.5707964f;
const float INF = 1e30f;
enum { MAX_ILLUMINATION = 16, MAX_REFLECTION = 16, MAX_SOURCES = 256 };

struct Light {
  float x, y, radius, r, g, b;
  float height = 18, dx = 0, dy = 0, length = 0, width = 3;
  float illumination = 1, reflection = 1, reach = -1, ring = 0;
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
};
// Art-directed radiance, not calibrated watts. The visible source remains native.
const Emission TRACER = {0.22f, 0.21f, 0.18f, 60, 0.65f, 28, 0, 1, 100, INF, 2.2f};
const Emission *emission(int type) {
  static const Emission gauss = {0.054f, 0.102f, 0.192f, 75, 1, 40, 0.15f, 1, 150, INF, 2.2f};
  static const Emission ion_rifle = {0.55f, 0.82f, 1.45f, 195, 3, 24, 6, 1, 195, 256, 1};
  static const Emission ion_minigun = {0.50f, 0.78f, 1.35f, 160, 2, 24, 4, 1, 160, 256, 1};
  static const Emission ion_cannon = {0.65f, 0.90f, 1.65f, 240, 5, 24, 8, 1, 240, 256, 1};
  static const Emission fire_bullets = {1.40f, 0.68f, 0.20f, 155, 3, 24, 4, 1, 155, 256, 1};
  static const Emission plasma_minigun = {0.72f, 0.37f, 0.08f, 100, 2, 18, 2.4f, 1, 125, 4.2f, 1};
  static const Emission plasma_rifle = {1.1f, 0.57f, 0.12f, 140, 5, 18, 3.2f, 1, 175, 17.5f, 1};
  static const Emission plasma_cannon = {1.5f, 0.76f, 0.16f, 190, 9, 18, 4, 1, 250, 44.2f, 1};
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
    Light &glow = add(targets[i].x, targets[i].y, 60, e->r * energy, e->g * energy, e->b * energy);
    glow.width = width * 1.5f;
    glow.illumination = 0.25f, glow.reflection = 0.25f, glow.reach = 90;
  }
}

void player_sources(const player_state_t &player) {
  if (perk_count_get(perk_id_radioactive)) {
    // Follow the visible aura, including its native post-death presence.
    float pulse = ((sinf(game_time_s) + 1) * 0.1875f + 0.25f) / 0.4375f;
    Light &aura = add(player.pos_x, player.pos_y, 100, 0.10f, 0.70f, 0.07f);
    aura.width = 13;
    aura.illumination = 3.8f * pulse, aura.reflection = 0.8f * pulse, aura.reach = 100;
  }
  if (player.health > 0 && perk_count_get(perk_id_sharpshooter)) {
    // The native sight (render/laser_sight.py): red at the gun, black at its far
    // end, so the source axis points back toward the gun.
    float heading = player.aim_heading - HALF_PI;
    float far_x = player.pos_x + cosf(heading) * 512, far_y = player.pos_y + sinf(heading) * 512;
    float near_heading = heading - 0.150915f;
    float near_x = player.pos_x + cosf(near_heading) * 15, near_y = player.pos_y + sinf(near_heading) * 15;
    float dx = near_x - far_x, dy = near_y - far_y;
    float length = normalize(dx, dy);
    Light &sight = add((near_x + far_x) * 0.5f, (near_y + far_y) * 0.5f, 40, 1.3f, 0, 0);
    sight.height = 28;
    sight.dx = dx, sight.dy = dy, sight.length = length, sight.width = 1.2f;
    sight.illumination = 0, sight.reflection = 1, sight.reach = 100;
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

} // namespace

// The frame's lights for the view, 16 floats each: position, radius, height;
// linear RGB, ring radius; direction, 0, length; illumination and reflection
// gains, reflection reach, source width. At most `capacity`.
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
    const float packed[16] = {l.x, l.y, l.radius, l.height, l.r, l.g, l.b, l.ring, l.dx, l.dy, 0, l.length,
                              lit[i] ? l.illumination : 0, reflected[i] ? l.reflection : 0, l.reflection_reach(),
                              l.width};
    memcpy(out + count++ * 16, packed, sizeof packed);
  }
  return count;
}
