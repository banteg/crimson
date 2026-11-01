// Exercise the movement/aim path used by both SDL and the browser.
#include "../freeware/game.h"
#include <cstdio>
#include <cstring>

extern "C" {
extern unsigned freeware_rng_state;
extern vec2f_t freeware_aim_screen;
}

void check_player_motion() {
  using namespace freeware;
  struct Case { int movement, aiming, actor; };
  // Host controls: static/relative/stick movement; mouse/keyboard/hat aim.
  const Case cases[] = {{0, 0, 0}, {1, 0, 0}, {0, 2, 0}, {1, 2, 0}, {0, 2, 1}, {2, 3, 1}};
  const unsigned directions[] = {5, 5, 5, 9, 13, 2, 6, 10, 0, 9, 0, 2};
  for (const auto &c : cases) {
    if (FREEWARE_EDITION == 10002 && c.aiming != 0)
      continue;
    Game g;
    g.two_players = c.actor != 0;
    g.movement[c.actor] = c.movement;
    g.aiming[c.actor] = c.aiming;
    std::memset(player_state_table, 0, sizeof(player_state_table));
    g.start();
    auto &p = player_state_table[c.actor].freeware;
    auto &fighter = g.actor(c.actor);
    fighter.player = {26, 26};
    fighter.cooldown = .375f;
    fighter.spread = 1.875f;
    fighter.aim_angle = -.75f;
    p.heading = .25f;
    p.aim = {66, 62};
    p.muzzle_flash = 1.25f;
    p.turn_speed = 1.25f;
    p.walk_phase = 13.875f;
    seed_random(123);
    for (int tick = 0; tick < int(sizeof(directions) / sizeof(*directions)); ++tick) {
      Input in{};
      const unsigned mask = directions[tick];
      // In solo play tick 9 uses the alternate direction keys. Co-op drives only player two.
      const bool alternate = c.actor || tick == 9;
      (alternate ? in.up2 : in.up) = mask & 1;
      (alternate ? in.down2 : in.down) = mask & 2;
      (alternate ? in.left2 : in.left) = mask & 4;
      (alternate ? in.right2 : in.right) = mask & 8;
      in.stick_x[c.actor] = float(bool(mask & 8)) - float(bool(mask & 4));
      in.stick_y[c.actor] = float(bool(mask & 2)) - float(bool(mask & 1));
      in.aim_x[c.actor] = tick % 3 == 0 ? -1 : tick % 3 == 2 ? 1 : 0;
      in.ctrl = tick == 4 || tick == 5;
      in.fire_edge[c.actor] = tick == 4;
      in.mouse_fire = tick == 7;
      in.pad_fire[c.actor] = tick == 9;
      (c.actor ? in.fire2 : in.fire) = tick == 11;
      in.x = float(70 + tick * 5);
      in.y = float(54 - tick * 2);
      g.update_projectiles(.0625f);
      float flash_before_player = p.muzzle_flash;
      g.step_player(c.actor, .0625f, in, {in.x - 19, in.y + 13});
      std::printf("motion %d %d %d %d %u %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g %.9g "
                  "%.9g %.9g %.9g %.9g %.9g %u\n",
                  c.movement, c.aiming, c.actor, tick, mask, p.position.x, p.position.y, p.movement.x, p.movement.y,
                  p.heading, p.move_speed, p.walk_phase, p.spread, p.aim.x, p.aim.y, p.aim_heading, p.turn_speed,
                  freeware_aim_screen.x, freeware_aim_screen.y, flash_before_player, p.muzzle_flash, p.ammo,
                  p.cooldown, projectile_pool[0].angle, freeware_rng_state);
    }
  }
}
