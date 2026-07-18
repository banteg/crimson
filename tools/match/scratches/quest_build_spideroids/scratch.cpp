#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    void set(float x_value, float y_value)
    {
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

    void set_spawn(int spawn_template_id, int spawn_trigger_time_ms)
    {
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
    }
};

extern "C" void quest_build_spideroids(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    int splitter_template_id = SPAWN_ID_SPIDER_SP2_SPLITTER_01;
    spawns[0].pos.set(1088.0f, 512.0f);
    spawns[0].set_spawn(splitter_template_id, 1000);
    spawns[0].count = 1;

    spawns[1].pos.set(-64.0f, 512.0f);
    spawns[1].set_spawn(splitter_template_id, 3000);
    spawns[1].count = 1;

    spawns[2].pos.set(1088.0f, 256.0f);
    spawns[2].set_spawn(splitter_template_id, 6000);
    spawns[2].count = 1;

    int entry_count = 3;
    if (config_hardcore != 0) {
        spawns[3].pos.set(1088.0f, 762.0f);
        spawns[3].set_spawn(splitter_template_id, 9000);
        spawns[3].count = 1;

        spawns[4].pos.set(512.0f, 1088.0f);
        spawns[4].set_spawn(splitter_template_id, 9000);
        spawns[4].count = 1;
        entry_count = 5;
    }

    if (config_blob.player_count >= 2 || config_hardcore != 0) {
        quest_entry_original_t *spawn = &spawns[entry_count++];
        spawn->pos.set(-64.0f, 762.0f);
        spawn->set_spawn(splitter_template_id, 9000);
        spawn->count = 1;
    }

    *count = entry_count;
}
