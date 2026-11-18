#include "../freeware/game.h"
#include <cstdio>
#include <cstring>

extern "C" unsigned freeware_rng_state;

namespace {
enum PoolCase { Empty, NearSlotZero, NearSlotOne, RadiusEdge, Full, InfectedSlot, FullBlocked };

void spawn(unsigned seed, int xp, PoolCase layout) {
  constexpr int capacity = FREEWARE_EDITION == 10002 ? 128 : 512;
  const vec2f_t pos{512, 384};
  const int occupancy[] = {0, 1, 2, 2, capacity, 2, capacity};
  int occupied = occupancy[layout], slot = occupied == capacity ? 0 : occupied;
  std::memset(creature_pool, 0, sizeof(creature_pool));
  for (int i = 0; i < occupied; ++i) {
    creature_pool[i].active = 1;
    creature_pool[i].position = {64, 64};
  }
  int peer_id = layout == NearSlotZero ? 0 : 1;
  if (layout != Empty && layout != Full) {
    auto &peer = creature_pool[peer_id];
    peer.position = {pos.x + (layout == RadiusEdge ? 45.f : 44.f), pos.y};
    peer.plague_infected = layout != InfectedSlot;
  }
  auto &c = creature_pool[slot];
  std::memset(&c, 0xa5, sizeof(c)); // Distinguish reset fields from retained bytes in a reused slot.
  c.active = occupied == capacity;
  c.plague_infected = layout == InfectedSlot;
  c.health = 25;
  c.freeware.reward = 777;
  current_player_index = FREEWARE_EDITION == 10300 ? seed % 2 : 0;
  player_state_table[1 - current_player_index].freeware.experience = xp + 10;
  player_state_table[current_player_index].freeware.experience = xp;
  creature_spawned_count = occupied;
  plaguebearer_infection_count = 0;
  freeware::seed_random(seed);
  unsigned ok = creature_spawn_random(&pos);
  std::printf("randomspawn %u %d %d %u %d %u %u ", seed, xp, int(layout), ok, creature_spawned_count,
              freeware_rng_state, unsigned(creature_pool[peer_id].plague_infected));
  auto bytes = reinterpret_cast<const unsigned char *>(&c);
  for (size_t j = 0; j < sizeof(c); ++j)
    std::printf("%02x", unsigned(bytes[j]));
  std::putchar('\n');
}
} // namespace

void check_random_spawns() {
  // Plain, red, green, blue, purple, yellow, red+yellow, and purple+yellow respectively.
  for (unsigned seed : {0u, 45u, 25u, 214u, 565u, 53u, 10047u, 60423u})
    spawn(seed, 5432, Empty);
  constexpr int cap = FREEWARE_EDITION == 10002 ? 60000 : 46200;
  for (int xp : {-2, 0, cap - 1, cap, cap + 1, 16777217})
    spawn(0, xp, Empty);
  for (PoolCase layout : {NearSlotZero, NearSlotOne, RadiusEdge, Full, InfectedSlot, FullBlocked})
    spawn(1, 100, layout);
}
