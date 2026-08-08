#include <math.h>

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

extern "C" void quest_build_the_spanking_of_the_dead(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(256.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_BONUS_CARRIER_27;
    spawns[entry_count].trigger_time_ms = 500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(768.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_BONUS_CARRIER_27;
    spawns[entry_count].trigger_time_ms = 500;
    spawns[entry_count].count = 1;
    ++entry_count;

    int step_index = 0;
    int trigger_time_ms = 5000;
    while (trigger_time_ms < 0xA988) {
        float step = (float)step_index;
        float angle = step * 0.333333343f;
        float radius = 512.0f - step * 3.79999995f;

        spawns[entry_count].pos = quest_vec2_t(
            (float)cos(angle) * radius + 512.0f,
            (float)sin(angle) * radius + 512.0f);
        spawns[entry_count].heading = angle;
        spawns[entry_count].template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;

        ++entry_count;
        trigger_time_ms += 300;
        ++step_index;
    }

    int trigger_offset_ms = step_index * 300;
    spawns[entry_count].pos.x = 1280.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].set_spawn(
        SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
        trigger_offset_ms + 10000,
        16);
    ++entry_count;

    spawns[entry_count].pos.x = -256.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].set_spawn(
        SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
        trigger_offset_ms + 20000,
        16);
    ++entry_count;

    *count = entry_count;
}
