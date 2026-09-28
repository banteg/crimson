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

    void set_spawn(
        int spawn_template_id,
        int spawn_trigger_time_ms,
        int spawn_count)
    {
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
        count = spawn_count;
    }
};

extern int config_player_count;

extern "C" void quest_build_arachnoid_farm(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int spawn_count = 0;
    int top_index = 0;

    if (config_player_count + 4 > 0) {
        int trigger_time_ms = 500;
        do {
            spawns[spawn_count].pos = quest_vec2_t(
                (float)top_index * 102.4f + 256.0f,
                256.0f);
            spawns[spawn_count].set_spawn(
                SPAWN_ID_DEN_SPIDER_BASIC_0A,
                trigger_time_ms,
                1);
            ++spawn_count;
            ++top_index;
            trigger_time_ms += 500;
        } while (top_index < config_player_count + 4);
    }

    int bottom_index = 0;
    if (config_player_count + 4 > 0) {
        int trigger_time_ms = 10500;
        do {
            spawns[spawn_count].pos = quest_vec2_t(
                (float)bottom_index * 102.4f + 256.0f,
                768.0f);
            spawns[spawn_count].set_spawn(
                SPAWN_ID_DEN_SPIDER_BASIC_0A,
                trigger_time_ms,
                1);
            ++spawn_count;
            ++bottom_index;
            trigger_time_ms += 500;
        } while (bottom_index < config_player_count + 4);
    }

    int middle_index = 0;
    if (config_player_count + 7 > 0) {
        int trigger_time_ms = 40500;
        do {
            spawns[spawn_count].pos = quest_vec2_t(
                (float)middle_index * 64.0f + 256.0f,
                512.0f);
            spawns[spawn_count].set_spawn(
                SPAWN_ID_DEN_SPIDER_WEAK_10,
                trigger_time_ms,
                1);
            ++spawn_count;
            ++middle_index;
            trigger_time_ms += 3500;
        } while (middle_index < config_player_count + 7);

        *count = spawn_count;
        return;
    }

    *count = spawn_count;
}
