#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;
};

extern "C" void quest_build_spideroids(
    quest_spawn_entry_t *entries, int *count)
{
    entries->pos_x = 1088.0f;
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    int splitter_template_id = SPAWN_ID_SPIDER_SP2_SPLITTER_01;
    spawns[0].pos.y = 512.0f;
    spawns[0].template_id = splitter_template_id;
    spawns[0].trigger_time_ms = 1000;
    spawns[0].count = 1;

    spawns[1].pos.x = -64.0f;
    spawns[1].pos.y = 512.0f;
    spawns[1].template_id = splitter_template_id;
    spawns[1].trigger_time_ms = 3000;
    spawns[1].count = 1;

    spawns[2].pos.x = 1088.0f;
    spawns[2].pos.y = 256.0f;
    spawns[2].template_id = splitter_template_id;
    spawns[2].trigger_time_ms = 6000;
    spawns[2].count = 1;

    int entry_count = 3;
    if (config_hardcore != 0) {
        spawns[3].pos.x = 1088.0f;
        spawns[3].pos.y = 762.0f;
        spawns[3].template_id = splitter_template_id;
        spawns[3].trigger_time_ms = 9000;
        spawns[3].count = 1;

        spawns[4].pos.x = 512.0f;
        spawns[4].pos.y = 1088.0f;
        spawns[4].template_id = splitter_template_id;
        spawns[4].trigger_time_ms = 9000;
        spawns[4].count = 1;
        entry_count = 5;
    }

    if (config_blob.player_count >= 2 || config_hardcore != 0) {
        quest_entry_original_t *spawn = &spawns[entry_count++];
        spawn->pos.x = -64.0f;
        spawn->pos.y = 762.0f;
        spawn->template_id = splitter_template_id;
        spawn->trigger_time_ms = 9000;
        spawn->count = 1;
    }

    *count = entry_count;
}
