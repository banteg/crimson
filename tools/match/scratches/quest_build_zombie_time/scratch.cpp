#include "crimsonland_gameplay.h"

struct quest_entry_original_t {
    float pos_x;
    float pos_y;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;

    void set_spawn(int spawn_template_id, int time_ms, int spawn_count)
    {
        template_id = spawn_template_id;
        trigger_time_ms = time_ms;
        count = spawn_count;
    }
};

struct quest_spawn_builder_t {
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_zombie_time(quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    for (int trigger_time = 1500; trigger_time < 97500; trigger_time += 8000) {
        builder.spawns[builder.count].pos_x =
            (float)(terrain_texture_width + 64);
        builder.spawns[builder.count].pos_y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41, trigger_time, 8);
        ++builder.count;

        builder.spawns[builder.count].pos_x = -64.0f;
        builder.spawns[builder.count].pos_y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.spawns[builder.count].trigger_time_ms = trigger_time;
        builder.spawns[builder.count].count = 8;
        ++builder.count;
    }

    *count = builder.count;
}
