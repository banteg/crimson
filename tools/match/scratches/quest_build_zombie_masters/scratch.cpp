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

    void set_spawn(int spawn_template_id, int spawn_trigger_time_ms) {
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
    }
};

extern "C" void quest_build_zombie_masters(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos.set(256.0f, 256.0f);
    spawns[0].set_spawn(SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 1000);
    spawns[0].count = config_blob.player_count;

    spawns[1].pos.set(512.0f, 256.0f);
    spawns[1].set_spawn(SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 6000);
    spawns[1].count = 1;

    spawns[2].pos.set(768.0f, 256.0f);
    spawns[2].set_spawn(SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 14000);
    spawns[2].count = config_blob.player_count;

    spawns[3].pos.set(768.0f, 768.0f);
    spawns[3].set_spawn(SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00, 18000);
    spawns[3].count = 1;

    *count = 4;
}
