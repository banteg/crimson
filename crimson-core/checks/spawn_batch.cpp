// Differential harness for the adapted allocator and Survival spawn bodies.
#include "crimsonland_gameplay.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <initializer_list>

extern "C" void baseline_survival_spawn_creature(const vec2f_t *pos);
extern "C" int baseline_creature_alloc_slot(void);
creature_t creature_pool[385];
player_state_t player_state_table[2];
int creature_spawned_count;
console_queue_t::console_queue_t() {}
console_queue_t::~console_queue_t() {}
console_queue_t console_log_queue;
static cvar_float_t verbose;
cvar_float_t *cv_verbose = &verbose;
static uint32_t rng;
static int logs;
extern "C" int crt_rand(void) {
    rng = rng * 214013u + 2531011u;
    return (rng >> 16) & 0x7fff;
}
extern "C" void console_printf(console_queue_t *, char *, ...) { ++logs; }

struct snapshot {
    creature_t pool[385];
    uint32_t random;
    int spawned, messages;
    void save() {
        memcpy(pool, creature_pool, sizeof(pool));
        random = rng; spawned = creature_spawned_count; messages = logs;
    }
    void restore() const {
        memcpy(creature_pool, pool, sizeof(pool));
        rng = random; creature_spawned_count = spawned; logs = messages;
    }
    void check() const {
        assert(memcmp(pool, creature_pool, sizeof(pool)) == 0);
        assert(random == rng && spawned == creature_spawned_count && messages == logs);
    }
};

int main() {
    int cases = 0;
    for (int experience : {0, 11999, 12000, 24999, 25000, 41999, 42000,
                           49999, 50000, 89999, 90000, 99999, 100000,
                           109999, 110000, 143802723}) {
        for (int free_count : {0, 1, 3, 31, 384}) {
            for (int log : {0, 1}) {
                for (int count : {0, 1, 400, 5600}) {
                    // Dirty bytes expose overflow fields that spawns intentionally retain.
                    memset(creature_pool, 0x5a, sizeof(creature_pool));
                    for (int i = 0; i < 384; ++i) creature_pool[i].active = 1;
                    for (int i = 0; i < free_count; ++i)
                        creature_pool[(i * 157 + 383) % 384].active = 0;
                    player_state_table[0].experience = experience;
                    verbose.value = (float)log;
                    rng = 0xfedcba97u; creature_spawned_count = 17; logs = 0;
                    snapshot before, expected;
                    before.save();
                    vec2f_t pos = {-40.0f, 1024.0f};
                    for (int i = 0; i < count; ++i) baseline_survival_spawn_creature(&pos);
                    expected.save();
                    before.restore();
                    int cursor = 0;
                    for (int i = 0; i < count; ++i)
                        cursor = survival_spawn_creature_from(&pos, cursor);
                    expected.check();
                    // A later batch can reuse an earlier slot. Other spawn callers still search from zero.
                    creature_pool[0].active = 0;
                    creature_pool[17].active = 0;
                    before.save();
                    baseline_survival_spawn_creature(&pos);
                    baseline_survival_spawn_creature(&pos);
                    int baseline_slot = baseline_creature_alloc_slot();
                    expected.save();
                    before.restore();
                    cursor = survival_spawn_creature_from(&pos, 0);
                    survival_spawn_creature_from(&pos, cursor);
                    assert(creature_alloc_slot() == baseline_slot);
                    expected.check();
                    ++cases;
                }
            }
        }
    }
    printf("spawn batches: %d cases; all pool bytes, RNG, counter and logs match\n", cases);
}
