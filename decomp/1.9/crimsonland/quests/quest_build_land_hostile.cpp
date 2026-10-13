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

extern "C" void quest_build_land_hostile(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
    spawns[entry_count].trigger_time_ms = 500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(-64.0f, 1088.0f);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
    spawns[entry_count].trigger_time_ms = 2500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(-64.0f, -64.0f);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
    spawns[entry_count].trigger_time_ms = 6500;
    spawns[entry_count].count = 3;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(1088.0f, -64.0f);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
    spawns[entry_count].trigger_time_ms = 11500;
    spawns[entry_count].count = 4;
    ++entry_count;

    *count = entry_count;
}
