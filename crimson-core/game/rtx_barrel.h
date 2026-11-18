#pragma once

#include "crimsonland_gameplay.h"
#include <algorithm>
#include <cmath>

inline vec2f_t rtx_barrel_offset(const player_state_t &player) {
  // Barrel tips measured in the fifteen 64-pixel torso cells.
  static constexpr float forward[] = {22.5f, 21.5f, 20.5f, 19.5f, 20.5f, 20.5f, 21.5f, 22.5f,
                                      22.5f, 23.5f, 22.5f, 22.5f, 22.5f, 22.5f, 22.5f};
  static constexpr float side[] = {-2.83f, -3.26f, -3.70f, -3.70f, -3.56f, -3.23f, -3.00f, -2.78f,
                                   -2.65f, -2.60f, -2.59f, -2.60f, -2.61f, -2.73f, -2.79f};
  int frame = std::clamp((int)(player.move_phase + .5f), 0, 14);
  float heading = player.aim_heading - 1.5707964f;
  float c = cosf(heading), s = sinf(heading), scale = player.size / 64.f;
  float x = forward[frame] * scale - 12 * player.muzzle_flash_alpha;
  float y = side[frame] * scale;
  return {c * x - s * y, s * x + c * y};
}
