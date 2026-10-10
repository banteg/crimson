// Differential harness for the adapted allocator, Survival spawn bodies and wave batches.
#include "crimsonland_gameplay.h"
#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <initializer_list>

extern "C" void baseline_survival_spawn_creature(const vec2f_t *pos);
extern "C" int baseline_creature_alloc_slot(void);
extern "C" void survival_update(void);
extern "C" void baseline_survival_update(void);
creature_t creature_pool[385];
player_state_t player_state_table[2];
int creature_spawned_count;
console_queue_t::console_queue_t() {}
console_queue_t::~console_queue_t() {}
console_queue_t console_log_queue;
static cvar_float_t verbose;
cvar_float_t *cv_verbose = &verbose;
static uint32_t rng;
static int logs, templates;
extern "C" uint32_t *crt_rand_stream() { return &rng; }
extern "C" int crt_rand(void) { return crt_rand_step(&rng); }
extern "C" void console_printf(console_queue_t *, char *, ...) { ++logs; }

// What survival_update reads besides the pool; stage 10 is past every milestone.
int current_player_index, run_elapsed_ms, survival_spawn_stage;
unsigned char demo_mode_active, run_active;
extern "C" {
int config_player_count, frame_dt_ms, survival_spawn_cooldown, quest_spawn_timeline, demo_time_limit_ms;
int survival_reward_weapon_guard_id, survival_first_kill_count;
unsigned char console_open_flag, survival_reward_fire_seen, survival_shrinkifier_handout_enabled;
float survival_first_kill_pos[6];
void demo_mode_start(void) {}
}
unsigned char survival_reward_damage_seen;
creature_t *creature_spawn_template(int, const vec2f_t *, float) { ++templates; return nullptr; }
void weapon_assign_player(int, int) {}
#ifdef __APPLE__
#define SYMBOL "_"
#else
#define SYMBOL ""
#endif
// terrain_render_target names the start of the terrain block, as data.cpp lays it out.
extern "C" terrain_original_t terrain_block;
terrain_original_t terrain_block;
asm(".globl " SYMBOL "terrain_render_target\n.set " SYMBOL "terrain_render_target, " SYMBOL "terrain_block\n");

struct snapshot {
    creature_t pool[385];
    uint32_t random;
    int spawned, messages, cooldown, timeline, spawned_templates;
    void save() {
        memcpy(pool, creature_pool, sizeof(pool));
        random = rng; spawned = creature_spawned_count; messages = logs;
        cooldown = survival_spawn_cooldown; timeline = quest_spawn_timeline; spawned_templates = templates;
    }
    void restore() const {
        memcpy(creature_pool, pool, sizeof(pool));
        rng = random; creature_spawned_count = spawned; logs = messages;
        survival_spawn_cooldown = cooldown; quest_spawn_timeline = timeline; templates = spawned_templates;
    }
    void check() const {
        assert(memcmp(pool, creature_pool, sizeof(pool)) == 0);
        assert(random == rng && spawned == creature_spawned_count && messages == logs);
        assert(cooldown == survival_spawn_cooldown && timeline == quest_spawn_timeline && spawned_templates == templates);
    }
};

// Three updates from one state, a few creatures dying between them: the
// baseline's, then the optimized ones', which must leave every byte as they did.
static int wave_batches() {
    int cases = 0;
    survival_spawn_stage = 10;
    survival_reward_damage_seen = survival_reward_fire_seen = 1;
    terrain_block.width = terrain_block.height = 1024;
    for (int elapsed : {0, 898200, 900000, 901799, 901800, 905400, 1200000, 2154555, 3260139}) {
        for (int dt : {1, 16, 33}) {
            for (int players : {1, 2}) {
                for (int cooldown : {-40, 0, 7}) {
                    for (int experience : {0, 11999, 12000, 24999, 25000, 41999, 42000, 100000, 143802723}) {
                        for (int free_count : {0, 1, 3, 31, 384}) {
                            for (int log : {0, 1}) {
                                memset(creature_pool, 0x5a, sizeof(creature_pool));
                                for (int i = 0; i < 384; ++i) creature_pool[i].active = 1;
                                for (int i = 0; i < free_count; ++i)
                                    creature_pool[(i * 157 + 383) % 384].active = 0;
                                run_elapsed_ms = elapsed;
                                frame_dt_ms = dt;
                                config_player_count = players;
                                survival_spawn_cooldown = cooldown;
                                player_state_table[0].experience = experience;
                                verbose.value = (float)log;
                                rng = 0x13579bdfu + (uint32_t)cases; creature_spawned_count = 17; logs = 0;
                                snapshot start, expected[3];
                                start.save();
                                for (int tick = 0; tick < 3; ++tick) {
                                    baseline_survival_update();
                                    expected[tick].save();
                                    creature_pool[(tick * 101 + 5) % 384].active = 0;
                                }
                                start.restore();
                                for (int tick = 0; tick < 3; ++tick) {
                                    survival_update();
                                    expected[tick].check();
                                    creature_pool[(tick * 101 + 5) % 384].active = 0;
                                }
                                ++cases;
                            }
                        }
                    }
                }
            }
        }
    }
    return cases;
}

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
    printf("wave batches: %d cases of three updates; all pool bytes, RNG, counters and logs match\n", wave_batches());
}
