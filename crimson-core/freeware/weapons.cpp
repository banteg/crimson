// Weapon firing arms of 0x4126e0. IDs here are the freeware IDs, including the secret weapons.
#include "game.h"
#include <algorithm>
#include <cmath>
namespace freeware {
struct Weapon {
  int projectile, count;
  float cooldown, jitter, ammo;
  Sound sound;
};
static constexpr Weapon weapons[] = {{},
                                     {4, 1, .7117f, .001f, 1, Sound::Pistol},
                                     {1, 1, .117f, .001f, 1, Sound::Shot},
                                     {2, 12, .688117f, .0013f, 1, Sound::Shotgun},
                                     {2, 12, .788117f, .0033f, 1, Sound::Shotgun},
                                     {5, 1, .008113f, .001f, .1f, Sound::Flame},
                                     {2, 1, .088117f, .001f, 1, Sound::Shot},
                                     {7, 1, .290812f, .003f, 1, Sound::Plasma},
                                     {7, 3, .640812f, .003f, 1, Sound::Plasma},
                                     {9, 1, .109081f, .003f, 1, Sound::PlasmaFast},
                                     {10, 1, .950812f, .003f, 1, Sound::Plasma},
                                     {11, 1, .740812f, .003f, 1, Sound::Rocket},
                                     {12, 1, .310812f, .003f, 1, Sound::Rocket},
                                     {4, 1, .07f, .012f, 1, Sound::Burst},
                                     {9, 14, .288117f, .0013f, 1, Sound::Shotgun},
                                     {15, 1, .006113f, .001f, .05f, Sound::Flame},
                                     {},
                                     {17, 1, .2f, .001f, 1, Sound::Plasma},
                                     {18, 1, .2f, .001f, 1, Sound::Plasma},
                                     {19, 1, .1613f, .001f, .15f, Sound::Plasma}};
extern "C" int fx_spawn_secondary_projectile(const vec2f_t *, float, secondary_projectile_type_id_t);
void Game::fire_weapon(int index) {
  auto &p = actor(index);
  auto &w = player_state_table[index].freeware;
  // IDs 16 and 20 have names and clips but no firing arm in the released executable.
  if (w.weapon == 16 || w.weapon == 20) {
    w.ammo -= 1;
    return;
  }
  if (w.weapon < 1 || w.weapon >= int(sizeof(weapons) / sizeof(*weapons)) ||
      (w.weapon == 18 && (!freeware_secret_weapon_unlocked || p.health >= 5)))
    return;
  const auto &def = weapons[w.weapon];
  if (!def.count)
    return;
  const float angle = p.aim_angle - 1.5707964f - .25f;
  vec2f_t muzzle{p.player.x + std::cos(angle) * 12, p.player.y + std::sin(angle) * 12};
  for (int i = 0; i < def.count; ++i) {
    const bool shotgun = w.weapon == 3 || w.weapon == 4 || w.weapon == 14;
    const bool wide = shotgun || w.weapon == 1 || w.weapon == 2;
    float jitter =
        float(crt_rand() % (wide ? 200 : 20) - (wide ? 100 : 10)) * def.jitter * (shotgun ? 1 : p.spread);
    if (w.weapon == 8)
      jitter += (i - 1) * .31415927f;
    if (w.weapon == 5 || w.weapon == 15 || w.weapon == 19) {
      float heading = p.aim_angle - 1.5707964f;
      int slot = w.weapon == 19 ? fx_spawn_particle_slow(&muzzle, heading, nullptr)
                                : fx_spawn_particle(&muzzle, heading, nullptr, 1);
      if (w.weapon == 15)
        particle_pool[slot].style_id = 1;
      run.particle_owner[slot] = index;
    } else if (w.weapon == 11 || w.weapon == 12) {
      int slot = fx_spawn_secondary_projectile(&muzzle, p.aim_angle + jitter,
                                               static_cast<secondary_projectile_type_id_t>(w.weapon - 10));
      run.rocket_owner[slot] = index;
    } else {
      int slot = projectile_spawn(&muzzle, p.aim_angle + jitter, def.projectile);
      run.shot_owner[slot] = index;
      if (shotgun)
        projectile_pool[slot].fields.speed_scale = 1 + (crt_rand() % 100) * .01f;
    }
  }
  if (shell_marks && (w.weapon <= 4 || w.weapon == 6 || w.weapon == 13))
    shells.push_back({p.player.x + std::cos(p.aim_angle) * 12, p.player.y + std::sin(p.aim_angle) * 12});
  p.cooldown = def.cooldown * (run.perks[14] ? .88f : 1) * (run.perks[3] ? 1.05f : 1);
  w.ammo -= def.ammo * (run.perks[11] ? .8f : 1);
  play_sound(def.sound);
}
extern "C" {
int perk_id_fastloader = 5;
int sfx_play_panned(int sample, float, float) {
  if (sample == 16)
    play_sound(Sound::Reload);
  return 0;
}
void player_start_reload();
}

void Game::step_player(int index, float dt, const Input &in) {
  auto &p = actor(index);
  if (p.health <= 0)
    return;
  auto &w = player_state_table[index].freeware;
  current_player_index = index;
  float dx = index ? float(in.right2) - float(in.left2) : float(in.right) - float(in.left);
  float dy = index ? float(in.down2) - float(in.up2) : float(in.down) - float(in.up);
  if (movement[index] == 2) {
    dx = in.stick_x[index] - pad_center[index].x;
    dy = in.stick_y[index] - pad_center[index].y;
    if (std::abs(dx) < pad_threshold[index])
      dx = 0;
    if (std::abs(dy) < pad_threshold[index])
      dy = 0;
  }
  float distance;
  if (movement[index] == 1) {
    if (dx != 0)
      p.turn_speed = std::min(7.f, p.turn_speed + dt * 10);
    else
      p.turn_speed = std::max(1.f, p.turn_speed - dt * 10);
    player_state_table[index].heading += dx * p.turn_speed * dt * .5f;
    float forwards = std::max(0.f, -dy);
    p.move_speed = forwards ? std::min(run.perks[4] ? 2.8f : 2.f, p.move_speed + dt * 5)
                            : std::max(0.f, p.move_speed - dt * 15);
    distance = (2 * p.move_speed * 25 - std::max(0.f, dy) * 35) * dt;
    if (dx || dy)
      run.moved = true;
  } else if (dx || dy) {
    run.moved = true;
    float direction = std::atan2(dy, dx) + 1.5707964f;
    if (direction < 0)
      direction += 6.2831855f;
    const float turn = player_heading_approach_target(direction);
    p.move_speed =
        std::min(run.perks[4] ? 2.8f : 2.f, p.move_speed + dt * (run.perks[4] && p.move_speed >= 2 ? 1 : 5));
    if (w.weapon == 13)
      p.move_speed = std::min(p.move_speed, .8f);
    distance = (3.14159265f - turn) * 2 * p.move_speed * 7.957747f * dt;
  } else {
    p.move_speed = std::max(0.f, p.move_speed - dt * 15);
    distance = 2 * p.move_speed * 25 * dt;
  }
  p.body_angle = player_state_table[index].heading;
  p.player.x = std::clamp(p.player.x + std::cos(p.body_angle - 1.5707964f) * distance, 24.f, float(arena - 24));
  p.player.y = std::clamp(p.player.y + std::sin(p.body_angle - 1.5707964f) * distance, 24.f, float(arena - 24));
  p.walk = std::fmod(p.walk + dt * p.move_speed * 19, 14.f);
  bool trigger = index ? in.fire2 || (aiming[index] < 2 && (in.mouse_fire || in.click)) : in.fire || in.click;
  if (aiming[index] == 3) {
    if (std::hypot(in.aim_x[index], in.aim_y[index]) > pad_threshold[index])
      p.aim_angle = std::atan2(in.aim_y[index], in.aim_x[index]) -
                    std::atan2(hat_right[index].y, hat_right[index].x) + 1.5707964f;
    trigger |= in.pad_fire[index];
  } else if (aiming[index] == 1) {
    p.aim_angle += mouse_dx * .012f;
  } else if (aiming[index] == 2) {
    if (movement[index] == 1)
      p.aim_angle = p.body_angle + 3.14159265f / 6;
    else {
      if (!p.firing || !trigger)
        p.locked_aim = p.body_angle;
      p.aim_angle = p.locked_aim;
    }
  } else
    p.aim_angle =
        std::atan2(in.y - camera_y(*this) - p.player.y, in.x - camera_x(*this) - p.player.x) + 1.5707964f;
  bool trigger_pressed = trigger && !p.firing;
  p.firing = trigger;
  // The homing rocket acquires its target from the current player's world-space aim point.
  auto &aim = w.aim;
  aim = aiming[index] != 0
            ? vec2f_t{p.player.x + 60 * std::sin(p.aim_angle), p.player.y - 60 * std::cos(p.aim_angle)}
            : vec2f_t{in.x - camera_x(*this), in.y - camera_y(*this)};
  p.cooldown = std::max(0.f, p.cooldown - dt);
  p.shield = std::max(0.f, p.shield - dt);
  p.spread = run.perks[3] ? .1f : std::max(dx || dy ? .5f : .25f, p.spread - dt * (dx || dy ? 1 : 2));
  if (run.perks[7] || run.perks[18]) {
    int target = creature_find_in_radius(&aim, 10);
    if (target >= 0) {
      auto &c = creature_pool[target];
      if (run.perks[18] && run.freeze <= 0) {
        c.pos_x -= c.vel_x;
        c.pos_y -= c.vel_y;
      }
      if (run.perks[7] && c.health > 0) {
        c.anim_phase -= dt;
        if (c.anim_phase < 0) {
          c.anim_phase = .5f;
          c.health -= 3;
          if (c.health <= 0)
            kill(target, index);
        }
      }
    }
  }
  if (run.berserk > 10 && p.cooldown <= 0) {
    int target = creature_find_nearest(&p.player);
    auto &c = creature_pool[target];
    if (c.active && std::hypot(c.pos_x - p.player.x, c.pos_y - p.player.y) < 500) {
      float a = std::atan2(c.pos_y - p.player.y, c.pos_x - p.player.x) + 1.5707964f;
      vec2f_t muzzle{p.player.x + 12 * std::sin(a), p.player.y - 12 * std::cos(a)};
      run.shot_owner[projectile_spawn(&muzzle, a, 1)] = index;
      p.cooldown = .1f;
      play_sound(Sound::Shot);
      return;
    }
  }
  if (survival) {
    w.weapon = 2;
    w.ammo = 30;
    w.reload = 0;
  }
  if (w.reload > 0) {
    w.reload -= dt;
    if (trigger_pressed && run.perks[22])
      w.reload -= .05f;
    if (w.reload <= 0) {
      w.ammo = w.clip_size;
      w.reload = 0;
    }
  } else {
    if (trigger && p.cooldown <= 0 && w.ammo > 0)
      fire_weapon(index);
    if (!survival && (w.ammo <= 0 || (in.reload && w.ammo < w.clip_size))) {
      player_start_reload();
    }
  }
}
} // namespace freeware
