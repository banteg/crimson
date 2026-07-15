#include <math.h>

#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    quest_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    void set(float x_value, float y_value) {
        x = x_value;
        y = y_value;
    }
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;

    void set(
        const quest_vec2_t &position,
        int spawn_template_id,
        int spawn_trigger_time_ms,
        int spawn_count)
    {
        pos = position;
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
        count = spawn_count;
    }

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

extern "C" void quest_build_lizard_kings(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].set(
        quest_vec2_t(1152.0f, 512.0f),
        SPAWN_ID_FORMATION_CHAIN_LIZARD_4_11,
        1500,
        1);
    spawns[1].set(
        quest_vec2_t(-128.0f, 512.0f),
        SPAWN_ID_FORMATION_CHAIN_LIZARD_4_11,
        1500,
        1);
    spawns[2].set(
        quest_vec2_t(1152.0f, 896.0f),
        SPAWN_ID_FORMATION_CHAIN_LIZARD_4_11,
        1500,
        1);

    quest_entry_original_t *cursor = &spawns[3];
    int trigger_time_ms = 1500;
    for (int angle_index = 0; angle_index < 28; ++angle_index) {
        float angle = (float)angle_index * 0.34906587f;
        cursor->pos.set(
            (float)cos(angle) * 256.0f + 512.0f,
            (float)sin(angle) * 256.0f + 512.0f);
        cursor->set_spawn(
            SPAWN_ID_LIZARD_RANDOM_31,
            trigger_time_ms,
            1);
        cursor->heading = (float)angle_index * -0.34906587f;
        ++cursor;
        trigger_time_ms += 900;
    }

    *count = 31;
}
