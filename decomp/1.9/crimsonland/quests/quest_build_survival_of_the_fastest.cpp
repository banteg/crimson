#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    quest_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;

};

extern "C" void quest_build_survival_of_the_fastest(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int x;
    int y;
    int trigger_time_ms;
    int path_index;
    int entry_count = 0;
    for (path_index = 0; path_index < 6; ++path_index) {
        spawns[entry_count].pos =
            quest_vec2_t((float)(path_index * 72 + 256), 256.0f);
        spawns[entry_count].template_id = SPAWN_ID_DEN_SPIDER_WEAK_10;
        spawns[entry_count].trigger_time_ms = path_index * 900 + 500;
        spawns[entry_count].count = 1;
        ++entry_count;
    }
    for (; path_index < 12; ++path_index) {
        spawns[entry_count].pos =
            quest_vec2_t(688.0f, (float)((path_index - 6) * 72 + 256));
        spawns[entry_count].template_id = SPAWN_ID_DEN_SPIDER_WEAK_10;
        spawns[entry_count].trigger_time_ms = path_index * 900 + 500;
        spawns[entry_count].count = 1;
        ++entry_count;
    }
    while (path_index < 16) {
        x = 1552 - path_index * 72;
        trigger_time_ms = path_index * 900 + 500;
        spawns[entry_count].pos = quest_vec2_t((float)x, 688.0f);
        spawns[entry_count].template_id = SPAWN_ID_DEN_SPIDER_WEAK_10;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;
        ++entry_count;
        ++path_index;
    }

    while (path_index < 20) {
        y = 1840 - path_index * 72;
        trigger_time_ms = path_index * 900 + 500;
        spawns[entry_count].pos = quest_vec2_t(400.0f, (float)y);
        spawns[entry_count].template_id = SPAWN_ID_DEN_SPIDER_WEAK_10;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;
        ++entry_count;
        ++path_index;
    }

    while (path_index < 22) {
        x = path_index * 72 - 1040;
        trigger_time_ms = path_index * 900 + 500;
        spawns[entry_count].pos = quest_vec2_t((float)x, 400.0f);
        spawns[entry_count].template_id = SPAWN_ID_DEN_SPIDER_WEAK_10;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;
        ++entry_count;
        ++path_index;
    }

    spawns[entry_count].pos =
        quest_vec2_t(128.0f, 128.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_DEN_SPIDER_WEAK_10;
    spawns[entry_count].trigger_time_ms =
        path_index * 900 + 2500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos =
        quest_vec2_t(896.0f, 128.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_DEN_ALIEN_BASIC_07;
    spawns[entry_count].trigger_time_ms =
        path_index * 900 + 2500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos =
        quest_vec2_t(128.0f, 896.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_DEN_ALIEN_BASIC_07;
    spawns[entry_count].trigger_time_ms =
        path_index * 900 + 4500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(896.0f, 896.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_DEN_SPIDER_WEAK_10;
    spawns[entry_count].trigger_time_ms =
        path_index * 900 + 4500;
    spawns[entry_count].count = 1;
    ++entry_count;

    *count = entry_count;
}
