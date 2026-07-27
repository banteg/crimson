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

    spawns[0].pos = quest_vec2_t(256.0f, 512.0f);
    spawns[0].set_spawn(SPAWN_ID_ALIEN_BONUS_CARRIER_27, 500, 1);

    spawns[1].pos = quest_vec2_t(768.0f, 512.0f);
    spawns[1].set_spawn(SPAWN_ID_ALIEN_BONUS_CARRIER_27, 500, 1);

    int trigger_time_ms = 5000;
    int step_index = 0;
    while (trigger_time_ms < 0xA988) {
        float step = (float)step_index;
        float angle = step * 0.333333343f;
        float radius = 512.0f - step * 3.79999995f;

        quest_entry_original_t *spawn = &spawns[step_index + 2];
        spawn->pos = quest_vec2_t(
            (float)cos(angle) * radius + 512.0f,
            (float)sin(angle) * radius + 512.0f);
        spawn->heading = angle;
        spawn->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;

        trigger_time_ms += 300;
        ++step_index;
    }

    int trigger_offset_ms = step_index * 300;
    spawns[130].pos.x = 1280.0f;
    spawns[130].pos.y = 512.0f;
    spawns[130].set_spawn(
        SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
        trigger_offset_ms + 10000,
        16);

    spawns[131].pos.x = -256.0f;
    spawns[131].pos.y = 512.0f;
    spawns[131].set_spawn(
        SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
        trigger_offset_ms + 20000,
        16);

    *count = 132;
}
