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

extern "C" void quest_build_fallback(quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    console_printf(&console_log_queue, "Generating a fallback quest.\n");

    spawns[0].pos = quest_vec2_t(-50.0f, (float)terrain_texture_height * 0.5f);
    spawns[0].template_id = 0x40;
    spawns[0].trigger_time_ms = 500;
    spawns[0].count = 10;

    spawns[1].pos = quest_vec2_t(-50.0f, (float)terrain_texture_height * 0.5f);
    spawns[1].template_id = 0x40;
    spawns[1].trigger_time_ms = 5000;
    spawns[1].count = 20;

    *count = 2;
}
