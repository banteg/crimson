#pragma once
#include <stdint.h>
struct PortableCommand {
  int32_t type, argument;
};
struct PortableInput {
  float move_x, move_y, aim_x, aim_y;
  uint32_t flags;
};
struct PortableConfig {
  uint32_t seed, mode, major, minor, unlock, unlock_full, detail, violence,
      friendly_fire, hardcore, retry, preserve_bugs;
  uint32_t weapon_usage[53];
};
static_assert(sizeof(PortableConfig) == 260);
static_assert(sizeof(PortableInput) == 20);
static_assert(sizeof(PortableCommand) == 8);
static_assert(sizeof(float) == 4 && sizeof(int) == 4);
extern "C" {
uintptr_t portable_config();
uintptr_t portable_input();
uintptr_t portable_output();
uintptr_t portable_commands();
int portable_step_many(uint32_t command_count);
int portable_init(uint32_t seed, int mode, int quest_major, int quest_minor);
int portable_step(int command, int argument);
int portable_snapshot();
// The tick's aim: a world point under mouse aim, the stick's reach under pad aim.
float portable_aim_x();
float portable_aim_y();
// Point-click movement records its move target; the POV hat its turn keys.
float portable_move_x();
float portable_move_y();
bool portable_aim_turn_left();
bool portable_aim_turn_right();
// Player one's position and health and the screen shake, for the ranked aim bound.
float portable_player_x();
float portable_player_y();
float portable_player_health();
float portable_shake_x();
float portable_shake_y();
int portable_math_probe(uint32_t operation, uint32_t a, uint32_t b);
int portable_builder_probe(uint32_t seed, uint32_t index, uint32_t hardcore,
                           uint32_t players);
}
