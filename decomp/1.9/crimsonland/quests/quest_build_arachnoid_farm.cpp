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

extern int config_player_count;

extern "C" void quest_build_arachnoid_farm(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int spawn_count = 0;
    int top_index = 0;

    if (config_player_count + 4 > 0) {
        do {
            spawns[spawn_count].pos = quest_vec2_t(
                (float)top_index * 102.4f + 256.0f,
                256.0f);
            spawns[spawn_count].template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            spawns[spawn_count].trigger_time_ms = top_index * 500 + 500;
            spawns[spawn_count].count = 1;
            ++spawn_count;
            ++top_index;
        } while (top_index < config_player_count + 4);
    }

    int bottom_index = 0;
    if (config_player_count + 4 > 0) {
        do {
            spawns[spawn_count].pos = quest_vec2_t(
                (float)bottom_index * 102.4f + 256.0f,
                768.0f);
            spawns[spawn_count].template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            spawns[spawn_count].trigger_time_ms = bottom_index * 500 + 10500;
            spawns[spawn_count].count = 1;
            ++spawn_count;
            ++bottom_index;
        } while (bottom_index < config_player_count + 4);
    }

    int middle_index = 0;
    if (config_player_count + 7 > 0) {
        do {
            spawns[spawn_count].pos = quest_vec2_t(
                (float)middle_index * 64.0f + 256.0f,
                512.0f);
            spawns[spawn_count].template_id = SPAWN_ID_DEN_SPIDER_WEAK_10;
            spawns[spawn_count].trigger_time_ms = middle_index * 3500 + 40500;
            spawns[spawn_count].count = 1;
            ++spawn_count;
            ++middle_index;
        } while (middle_index < config_player_count + 7);

        *count = spawn_count;
        return;
    }

    *count = spawn_count;
}
