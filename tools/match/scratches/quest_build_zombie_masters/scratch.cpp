#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    void set(float x_value, float y_value) {
        x = x_value;
        y = y_value;
    }
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;
};

extern "C" void quest_build_zombie_masters(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos.set(256.0f, 256.0f);
    spawns[0].template_id = SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00;
    spawns[0].trigger_time_ms = 1000;
    spawns[0].count = config_blob.player_count;

    spawns[1].pos.set(512.0f, 256.0f);
    spawns[1].template_id = SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00;
    spawns[1].trigger_time_ms = 6000;
    spawns[1].count = 1;

    spawns[2].pos.set(768.0f, 256.0f);
    spawns[2].template_id = SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00;
    spawns[2].trigger_time_ms = 14000;
    spawns[2].count = config_blob.player_count;

    spawns[3].pos.set(768.0f, 768.0f);
    spawns[3].template_id = SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00;
    spawns[3].trigger_time_ms = 18000;
    spawns[3].count = 1;

    *count = 4;
}
