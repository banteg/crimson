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
                                     {2, 1, .088117f, .003f, 1, Sound::Burst},
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
                                     {17, 1, .2f, .012f, 1, Sound::Plasma},
                                     {18, 1, .2f, .012f, 1, Sound::Plasma},
                                     {19, 1, .1613f, .001f, .15f, Sound::Plasma}};
extern "C" int fx_spawn_secondary_projectile(const vec2f_t *, float, secondary_projectile_type_id_t);
void Game::fire_weapon(int index) {
  auto &p = actor(index);
  auto &w = player_state_table[index].freeware;
  if (w.weapon < 1 || w.weapon > 20)
    return;
  const double forward = (double)p.aim_angle - 1.57079637f;
  float dx = std::cos(p.aim_angle), dy = std::sin(p.aim_angle);
  vec2f_t shell{p.player.x + (crt_rand() % 10) * dx * .5f, p.player.y + (crt_rand() % 10) * dy * .5f};
  vec2f_t muzzle{p.player.x + float(std::cos(forward - .150915f) * 16),
                 p.player.y + float(std::sin(forward - .150915f) * 16)};
  // Even the two unused weapon IDs enter the common ammunition/recoil tail.
  const Weapon empty{0, 0, 0, 0, 1, Sound::Hit};
  const auto &def = w.weapon == 16 || w.weapon == 20 ? empty : weapons[w.weapon];
  if (w.weapon == 18 && freeware_secret_weapon_unlocked && p.health >= 5)
    return;
  auto smoke = [&](float first, float second) {
    float speed = 25;
    int scale = 1;
    for (float alpha : {first, second}) {
      vec2f_t velocity{dx * speed, dy * speed};
      auto &fx = sprite_effect_pool[fx_spawn_sprite(&muzzle, &velocity, float(scale++))];
      fx.color = {.5f, .5f, .5f, alpha};
      speed = 15;
    }
  };
  switch (w.weapon) {
  case 2:
  case 6:
    smoke(.23f, .213f);
    break;
  case 3:
    smoke(.25f, .223f);
    break;
  case 4:
    smoke(.26f, .233f);
    break;
  case 10:
    smoke(.33f, .263f);
    break;
  case 11:
    smoke(.34f, .283f);
    break;
  case 12:
    smoke(.31f, .243f);
    break;
  }
  const bool unlocked = (w.weapon != 17 && w.weapon != 18) || freeware_secret_weapon_unlocked;
  for (int i = 0; i < def.count && unlocked; ++i) {
    const bool shotgun = w.weapon == 3 || w.weapon == 4 || w.weapon == 14;
    const bool wide = shotgun || w.weapon == 1 || w.weapon == 2;
    if (w.weapon == 5 || w.weapon == 15 || w.weapon == 19) {
      float heading = p.aim_angle - 1.5707964f;
      int slot = w.weapon == 19 ? fx_spawn_particle_slow(&muzzle, heading, nullptr)
                                : fx_spawn_particle(&muzzle, heading, nullptr, 1);
      if (w.weapon == 15)
        particle_pool[slot].style_id = 1;
    } else {
      float jitter =
          float(crt_rand() % (wide ? 200 : 20) - (wide ? 100 : 10)) * def.jitter * (shotgun ? 1 : p.spread);
      float heading = p.aim_angle + jitter;
      if (w.weapon == 8)
        heading += (i - 1) * .31415927f;
      if (w.weapon == 11 || w.weapon == 12)
        fx_spawn_secondary_projectile(&muzzle, heading,
                                      static_cast<secondary_projectile_type_id_t>(w.weapon - 10));
      else {
        int slot = projectile_spawn(&muzzle, heading, def.projectile);
        if (shotgun)
          projectile_pool[slot].fields.speed_scale = 1 + (crt_rand() % 100) * .01f;
      }
    }
  }
  if (w.weapon == 1)
    smoke(.23f, .213f);
  if (shell_marks && def.count && unlocked && w.weapon != 5 && w.weapon != 15 && w.weapon != 19 &&
      w.weapon != 11 && w.weapon != 12)
    shells.push_back(shell);
  if (def.count && unlocked) {
    static const float flash[] = {0,    .22f, .07f, .12f,  .12f, 0, .082f, .182f, .32f, .097f,
                                  .42f, .42f, .42f, .062f, .1f,  0, 0,     .04f,  .09f, 0};
    w.muzzle_flash = std::min(.8f, std::min(1.f, w.muzzle_flash) + flash[w.weapon]);
    p.cooldown = def.cooldown;
    play_sound(def.sound);
  }
  p.cooldown *= (run.perks[14] ? .88f : 1) * (run.perks[3] ? 1.05f : 1);
  if (!run.perks[3])
    p.spread += run.speed_scale * frame_dt * 150;
  p.spread = std::min(run.speed_scale * 2, p.spread) * run.speed_scale;
  w.ammo -= def.ammo * (run.perks[11] ? .8f : 1);
}
extern "C" {
int perk_id_fastloader = 5;
int sfx_play_panned(int sample, float, float) {
  play_original_sample(sample);
  return 0;
}
void player_start_reload();
}

void Game::step_player(int index, float dt, const Input &in, vec2f_t mouse_world) {
  auto &p = actor(index);
  if (!two_players && !survival && run.health > 0) {
    float dist = std::hypot(run.player.x - run.first_kill_pos.x, run.player.y - run.first_kill_pos.y);
    if (run.health < 100 && dist >= 48)
      run.first_kill_xp = -10;
    if (run.health < 5 && dist < 48 && run.first_kill_xp == run.experience &&
        player_state_table[0].freeware.weapon != 18) {
      freeware_secret_weapon_unlocked = 1;
      weapon_assign_player(0, 18);
    }
    if (!run.experience && run.seconds >= 120 && !highscore_record_shots_fired && run.health == 100) {
      run.experience = 1;
      freeware_secret_weapon_unlocked = 1;
      weapon_assign_player(0, 19);
    }
  }
  if (p.health <= 0)
    return;
  auto &w = player_state_table[index].freeware;
  current_player_index = index;
  w.muzzle_flash = std::max(0.f, w.muzzle_flash - dt * 2);
  p.cooldown = std::max(0.f, p.cooldown - dt);
  if (run.berserk > 10) {
    if (p.cooldown > 0)
      return;
    for (int attempt = 0; attempt < 50; ++attempt) {
      const auto &c = creature_pool[crt_rand() % 512];
      if (c.active && std::hypot(c.pos_x - p.player.x, c.pos_y - p.player.y) < 500) {
        w.aim = c.position;
        break;
      }
    }
    p.aim_angle = std::atan2(p.player.y - w.aim.y, p.player.x - w.aim.x) - 1.5707964f;
    float angle = p.aim_angle - 1.5707964f - .25f;
    vec2f_t muzzle{p.player.x + 12 * std::cos(angle), p.player.y + 12 * std::sin(angle)};
    projectile_spawn(&muzzle, p.aim_angle, 1);
    p.cooldown = .1f;
    play_sound(Sound::Shot);
    return;
  }
  run.speed_scale = run.slow > 0 ? std::max(.3f, run.speed_scale - dt) : std::min(1.f, run.speed_scale + dt * .8f);
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
    distance = (2 * p.move_speed * 25 - std::max(0.f, dy) * 30) * dt;
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
    p.aim_angle = std::atan2(p.player.y - mouse_world.y, p.player.x - mouse_world.x) - 1.5707964f;
  p.firing = trigger;
  // The homing rocket acquires its target from the current player's world-space aim point.
  auto &aim = w.aim;
  aim = aiming[index] != 0
            ? vec2f_t{p.player.x + 60 * std::sin(p.aim_angle), p.player.y - 60 * std::cos(p.aim_angle)}
            : mouse_world;
  p.shield = std::max(0.f, p.shield - dt);
  if (movement[index] == 0 && !dx && !dy)
    p.spread = std::max(.25f, p.spread - dt);
  p.spread = run.perks[3] ? 0.f : std::max(.5f, p.spread - dt);
  if (w.reload > 0 && in.click && run.perks[22]) {
    w.reload -= .05f;
    if (w.reload <= 0)
      w.reload = dt * .8f;
  }
  if (w.reload > 0 && w.reload - dt < 0)
    w.ammo = w.clip_size;
  w.reload = std::max(0.f, w.reload - dt);
  if (in.reload && w.reload == 0)
    player_start_reload();
  if (trigger && p.cooldown == 0 && w.reload == 0) {
    fire_weapon(index);
    if (w.ammo <= 0)
      player_start_reload();
  }
  w.position = p.player;
  w.aim_heading = p.aim_angle;
}
} // namespace freeware
