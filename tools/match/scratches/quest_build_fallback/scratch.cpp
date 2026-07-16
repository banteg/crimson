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

extern "C" void quest_build_fallback(quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    console_printf(&console_log_queue, "Generating a fallback quest.\n");

    spawns[0].pos = quest_vec2_t(-50.0f, (float)terrain_texture_height * 0.5f);
    spawns[0].set_spawn(0x40, 500, 10);

    spawns[1].pos = quest_vec2_t(-50.0f, (float)terrain_texture_height * 0.5f);
    spawns[1].set_spawn(0x40, 5000, 20);

    *count = 2;
}
