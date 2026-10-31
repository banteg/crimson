// The combat particles in 0x4094e0 occupy a different pool from bullets and rockets.
#include "game.h"
#include <algorithm>
#include <cmath>

namespace freeware {
void Game::update_particles(float dt) {
  for (auto &p : particle_pool) {
    if (!p.active)
      continue;
    bool bubble = p.style_id == 8;
    p.intensity -= dt * (bubble ? .11f : .9f);
    p.rotation += dt * (bubble ? 5.f : 1.f);
    const float cutoff = p.style_id == 0 ? 0.f : .8f;
    if (p.intensity <= cutoff) {
      if (bubble && !p.in_flight && p.target_id >= 0 && p.target_id < 512) {
        auto &c = creature_pool[p.target_id];
        if (c.active && !c.ai_mode) {
          kill(p.target_id, run.particle_owner[&p - particle_pool]);
          c.active = 0;
        }
      }
      p.active = 0;
      continue;
    }
    float scale = bubble ? 1.f : 2.5f;
    if (!bubble || p.in_flight) {
      p.position.x += dt * p.velocity.x * std::max(.15f, p.intensity) * scale;
      p.position.y += dt * p.velocity.y * std::max(.15f, p.intensity) * scale;
    }
    if (!p.in_flight)
      continue;
    p.angle -= (crt_rand() % 100 - 50) * .06f * dt * p.intensity * (p.style_id == 0 ? 1.96f : 1.1f);
    float speed = bubble ? 62.f : 82.f;
    p.velocity = {std::cos(p.angle) * speed, std::sin(p.angle) * speed};
    int target = creature_find_in_radius(&p.position, p.intensity * 8);
    if (target < 0)
      continue;
    p.in_flight = 0;
    auto &c = creature_pool[target];
    if (bubble) {
      p.position = c.position;
      p.velocity = {};
      p.target_id = target;
      c.ai_mode = 0;
      c.activation_radius = 0;
    } else {
      c.health -= p.intensity * 10;
      c.ai_mode = 1;
      auto &s = c.freeware;
      if (s.color.r + s.color.g + s.color.b > .6f) {
        float darken = 1 - p.intensity * .18f;
        s.color.r *= darken;
        s.color.g *= darken;
        s.color.b *= darken;
      }
      if (c.health <= 0)
        kill(target, run.particle_owner[&p - particle_pool]);
    }
  }
}
} // namespace freeware
