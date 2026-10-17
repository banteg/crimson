#pragma once
#include <stdint.h>
struct PortableCommand {
  int32_t type, argument;
};
struct PortableInput {
  float move_x, move_y, aim_x, aim_y;
  uint32_t flags;
};
// `players` is the run's player count (1 or 2); each tick then reads that many inputs.
struct PortableConfig {
  uint32_t seed, mode, major, minor, unlock, unlock_full, detail, violence,
      friendly_fire, hardcore, retry, preserve_bugs, players;
  uint32_t weapon_usage[53];
};
// Player one after a tick, for a run's timeline (service/src/timeline.ts). `damage` is the health creatures have
// lost since the run started (overkill excluded) and `nukes` the Nukes picked up; `pick_ids` are the perks picked
// since the previous read. The timers are Double Experience, Weapon Power Up, Fire Bullets, Freeze, Reflex Boost,
// Energizer, Shield and Speed.
struct PortableProbe {
  float x, y, health, damage;
  int32_t elapsed_ms, experience, level, weapon_id, kills, nukes, picks;
  int32_t pick_ids[8];
  float timers[8];
};
// What a tick baked into the terrain (fx_queue_render), for a run's ground (service/src/ground.ts): its decals, as
// fx_queue holds them, then its corpses, as fx_queue_add_rotated's arrays do. A decal's position is its centre; a
// corpse's its top left. Each draws the cell `frame` of an atlas cut `grid` cells a side (effect_select_texture for
// particles.png, creature_type_table's corpse_frame of effect_uv4's for bodyset.png). Colours are 0..1.
struct PortableBake {
  float x, y, width, height, rotation, r, g, b, a;
  int32_t grid, frame;
};
struct PortableBakes {
  int32_t decals, corpses;
  PortableBake decal[0x80], corpse[0x40];
};
// A custom quest (src/crimson/quests/custom.py CustomQuest): the table one variant plays, with base counts, which
// portable_init loads for a quest started at stage 0.0 where a stock quest's builder runs.
struct PortableSpawn {
  float x, y, heading;
  int32_t template_id, trigger_ms, count;
};
struct PortableQuest {
  uint32_t weapon_id, terrain[3], count;
  uint32_t disable_bonuses, disable_perks[2], disable_weapons[2];
  PortableSpawn entries[256];
};
static_assert(sizeof(PortableConfig) == 264);
static_assert(sizeof(PortableSpawn) == 24);
static_assert(sizeof(PortableQuest) == 6184);
static_assert(sizeof(PortableProbe) == 108);
static_assert(sizeof(PortableBake) == 44);
static_assert(sizeof(PortableInput) == 20);
static_assert(sizeof(PortableCommand) == 8);
static_assert(sizeof(float) == 4 && sizeof(int) == 4);
extern "C" {
uintptr_t portable_config();
// Where the caller writes a custom quest before portable_init(seed, quest mode, 0, 0).
uintptr_t portable_quest();
// One input per player, player one first: `PortableInput[2]`.
uintptr_t portable_input();
uintptr_t portable_output();
uintptr_t portable_commands();
int portable_step_many(uint32_t command_count);
// Human-readable reason for the last step, empty after a successful step. Copy before stepping again;
// wording is not a machine-readable contract. Initialization failures are not diagnosed here.
uintptr_t portable_refusal();
int portable_init(uint32_t seed, int mode, int quest_major, int quest_minor);
int portable_step(int command, int argument);
int portable_snapshot();
// The updating player's input (current_player_index) for the tick.
// Its aim: a world point under mouse aim, the stick's reach under pad aim.
float portable_aim_x();
float portable_aim_y();
// The updating player's cursor: mouse-relative aim's recorded cursor, else the world aim
// through the camera the tick started with.
float portable_aim_screen_x();
float portable_aim_screen_y();
// Point-click movement records its move target; the POV hat its turn keys.
float portable_move_x();
float portable_move_y();
bool portable_aim_turn_left();
bool portable_aim_turn_right();
// A player's position and health (0 is player one, 1 player two in co-op), for the ranked aim bound, the co-op
// camera and input signals.
float portable_player_x(uint32_t player);
float portable_player_y(uint32_t player);
float portable_player_health(uint32_t player);
// The distance from a world point to the nearest living creature's centre, infinity with none, for the service's
// input signals (docs/rewrite/bots.md).
float portable_nearest_creature(float x, float y);
// Reads the tick into the probe and returns its address; portable_init starts its counts over.
uintptr_t portable_probe();
// The bakes of the last tick.
uintptr_t portable_bakes();
int portable_math_probe(uint32_t operation, uint32_t a, uint32_t b);
int portable_builder_probe(uint32_t seed, uint32_t index, uint32_t hardcore,
                           uint32_t players);
}
