// Geometry emitted by the ballistic and energy passes of 0x40b570, in Grim draw order.
#include "game.h"
#include <algorithm>
#include <cmath>
namespace freeware {
void projectile_draws(std::vector<ShotDraw> &out, vec2f_t camera, float seconds, bool effects) {
  out.clear();
  const bool fire = bonus_fire_bullets_timer > 0;
  auto rect = [&](ShotTexture texture, float x, float y, float size, float angle, effect_color_t color, bool add) {
    out.push_back({texture, {{camera.x + x, camera.y + y}}, size, angle, color, add});
  };
  for (const auto &p : projectile_pool) {
    auto &s = p.fields;
    int type = int(s.type_id);
    if (!p.active || type == 7 || type == 9 || (!fire && (type == 17 || type == 18)))
      continue;
    float w = fire         ? (type == 1 || type == 4 ? 3.f : 1.f)
              : type == 1  ? 1.f
              : type == 4  ? 1.3f
              : type == 10 ? 1.2f
                           : .7f;
    vec2f_t delta{s.vel_x * w, s.vel_y * w};
    float ox = camera.x + s.origin.x, oy = camera.y + s.origin.y, x = camera.x + p.pos_x,
          y = camera.y + p.position.y;
    float alpha = std::clamp(s.life_timer, 0.f, 1.f);
    effect_color_t tint =
        type == 10 && !fire ? effect_color_t{.2f, .5f, 1, alpha} : effect_color_t{.8f, .6f, .6f, alpha};
    out.push_back({fire ? ShotTexture::Particle : ShotTexture::Trail,
                   {{ox - delta.x, oy - delta.y},
                    {ox + delta.x, oy + delta.y},
                    {x + delta.x, y + delta.y},
                    {x - delta.x, y - delta.y}},
                   0,
                   0,
                   tint,
                   fire});
  }
  const auto &player = player_state_table[current_player_index].freeware;
  if (player.muzzle_flash > 0) {
    double a = (double)player.aim_heading - 1.5707964f - .150915f;
    rect(ShotTexture::Particle, player.position.x + std::cos(a) * 15 - 80,
         player.position.y + std::sin(a) * 15 - 80, 160, 0, {1, 1, 1, player.muzzle_flash}, true);
  }
  for (auto &p : projectile_pool) {
    if (!p.active)
      continue;
    int type = p.fields.type_id;
    if (type != 7 && type != 9)
      continue;
    float x = p.pos_x, y = p.position.y;
    if (p.fields.life_timer != .4f) {
      rect(ShotTexture::Particle, x - 28, y - 28, 56, 0,
           {1, 1, 1, std::clamp(p.fields.life_timer * 2.5f, 0.f, 1.f)}, true);
      continue;
    }
    bool heavy = type == 7;
    float spacing = (heavy ? 2.5f : 2.1f) * p.fields.speed_scale;
    int n = std::min(heavy ? 8 : 3,
                     int(std::hypot(x - p.fields.origin.x, y - p.fields.origin.y)) / std::max(1, int(spacing)));
    float dx = std::cos(p.angle + 1.5707964f) * spacing, dy = std::sin(p.angle + 1.5707964f) * spacing,
          size = heavy ? 22 : 12;
    for (int i = 0; i < n; ++i)
      rect(ShotTexture::Particle, x + i * dx - size / 2, y + i * dy - size / 2, size, 0, {1, 1, 1, .4f}, true);
    size = heavy ? 56 : 16;
    rect(ShotTexture::Particle, x - size / 2, y - size / 2, size, 0, {1, 1, 1, heavy ? .45f : .5f}, true);
    if (effects) {
      size = heavy ? 256 : 120;
      rect(ShotTexture::Particle, x - size / 2, y - size / 2, size, 0, {1, 1, 1, heavy ? .3f : .15f}, true);
    }
  }
  for (int type : {18, 17})
    for (int i = 0; i < 64; ++i) {
      const auto &p = projectile_pool[i];
      if (!p.active || p.fields.type_id != type)
        continue;
      const float x = p.pos_x, y = p.position.y;
      if (p.fields.life_timer != .4f) {
        float alpha = std::clamp(p.fields.life_timer * 2.5f, 0.f, 1.f);
        float size = type == 18 ? 76 + 80 * alpha : 32 + 40 * alpha;
        rect(ShotTexture::Glow, x - size / 2, y - size / 2, size, 0, {1, 1, 1, alpha}, true);
        continue;
      }
      const double phase = double(seconds) * 9 + i;
      rect(ShotTexture::Glow, x - 30, y - 30, 60, 0, {1, 1, 1, 1}, true);
      if (type == 18) {
        for (int k = 0; k < 3; ++k) {
          double a = phase + k * 2.0943952f;
          rect(ShotTexture::Glow, x - 21 + std::cos(a) * 13, y - 21 + std::sin(a) * 13, 42, 0,
               {k == 0 ? 1.f : .2f, k == 1 ? 1.f : .2f, k == 2 ? 1.f : .2f, .9f}, true);
        }
      } else {
        rect(ShotTexture::Glow, x - 30 + std::cos(p.angle + 1.5707964f) * 15,
             y - 30 + std::sin(p.angle + 1.5707964f) * 15, 60, 0, {1, 1, 1, 1}, true);
        double c = std::cos(phase), b = phase + 2.0943952f, a = phase + 4.1887903f;
        rect(ShotTexture::Glow, x - 31 + c * c, y - 31 + std::sin(phase) * 11, 52, 0, {1, 1, 1, 1}, true);
        rect(ShotTexture::Glow, x - 31 + std::cos(b) * 10, y - 31 + std::sin(b) * 10, 62, 0, {1, 1, 1, 1}, true);
        rect(ShotTexture::Glow, x - 31 + std::cos(a) * 10, y - 31 + std::sin(a) * std::sin(b), 62, 0, {1, 1, 1, 1},
             true);
      }
    }
  for (auto &p : projectile_pool) {
    if (!p.active || p.fields.life_timer != .4f)
      continue;
    if (fire)
      rect(ShotTexture::Particle, p.pos_x - 32, p.position.y - 32, 64, p.angle,
           {1, 1, 1, std::min(1.f, bonus_fire_bullets_timer * .25f)}, true);
  }
  for (auto &p : projectile_pool) {
    if (!p.active)
      continue;
    int type = p.fields.type_id;
    if (type == 0) {
      p.active = 0;
      continue;
    }
    if (p.fields.life_timer != .4f || type == 7 || type == 9)
      continue;
    float size = type == 1 ? 6 : type == 4 ? 8 : 4;
    rect(ShotTexture::Bullet, p.pos_x - size / 2, p.position.y - size / 2, size, p.angle, {.8f, .8f, .8f, .9f},
         false);
  }
  for (int layer = 0; layer < 3; ++layer)
    for (const auto &r : secondary_projectile_pool) {
      if (!r.active)
        continue;
      if (layer == 1) {
        if (r.fields.type_id != SECONDARY_PROJECTILE_TYPE_EXPLODING)
          rect(ShotTexture::Rocket, r.pos_x - 5, r.position.y - 5, 10, r.angle, {.8f, .8f, .8f, .9f}, false);
      } else if (effects) {
        float reach = layer == 0 ? 5 : 9, size = layer == 0 ? 140 : 60;
        rect(ShotTexture::Particle, r.pos_x - std::cos(r.angle - 1.5707964f) * reach - size / 2,
             r.position.y - std::sin(r.angle - 1.5707964f) * reach - size / 2, size, r.angle,
             {1, 1, 1, layer == 0 ? .48f : .68f}, true);
      }
    }
}
} // namespace freeware
