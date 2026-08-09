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

    int entry_count = 0;
    int splitter_template_id = SPAWN_ID_SPIDER_SP2_SPLITTER_01;
    spawns[entry_count].pos.x = 1088.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].set_spawn(splitter_template_id, 1000);
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.set(-64.0f, 512.0f);
    spawns[entry_count].set_spawn(splitter_template_id, 3000);
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos.set(1088.0f, 256.0f);
    spawns[entry_count].set_spawn(splitter_template_id, 6000);
    spawns[entry_count].count = 1;
    ++entry_count;

    if (config_hardcore != 0) {
        spawns[entry_count].pos.set(1088.0f, 762.0f);
        spawns[entry_count].set_spawn(splitter_template_id, 9000);
        spawns[entry_count].count = 1;
        ++entry_count;

        spawns[entry_count].pos.set(512.0f, 1088.0f);
        spawns[entry_count].set_spawn(splitter_template_id, 9000);
        spawns[entry_count].count = 1;
        ++entry_count;
    }

    if (config_blob.player_count >= 2 || config_hardcore != 0) {
        quest_entry_original_t *spawn = &spawns[entry_count++];
        spawn->pos.set(-64.0f, 762.0f);
        spawn->set_spawn(splitter_template_id, 9000);
        spawn->count = 1;
    }

    *count = entry_count;
}
