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
      friendly_fire, hardcore, retry;
  uint32_t weapon_usage[53];
};
static_assert(sizeof(PortableConfig) == 256);
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
int portable_builder_probe(uint32_t seed, uint32_t index, uint32_t hardcore,
                           uint32_t players);
}
