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

extern "C" void quest_build_hidden_evil(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_HIDDEN_1_21;
    spawns[entry_count].trigger_time_ms = 500;
    spawns[entry_count].count = 50;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_HIDDEN_2_22;
    spawns[entry_count].trigger_time_ms = 15000;
    spawns[entry_count].count = 30;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_HIDDEN_3_23;
    spawns[entry_count].trigger_time_ms = 25000;
    spawns[entry_count].count = 20;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_HIDDEN_3_23;
    spawns[entry_count].trigger_time_ms = 30000;
    spawns[entry_count].count = 30;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_HIDDEN_2_22;
    spawns[entry_count].trigger_time_ms = 35000;
    spawns[entry_count].count = 30;
    ++entry_count;

    *count = entry_count;
}
