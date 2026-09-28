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
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(1152.0f, 512.0f);
    int chain_template_id = SPAWN_ID_FORMATION_CHAIN_LIZARD_4_11;
    spawns[entry_count].template_id = chain_template_id;
    int trigger_time_ms = 1500;
    int one = 1;
    spawns[entry_count].trigger_time_ms = trigger_time_ms;
    spawns[entry_count].count = one;
    quest_vec2_t next_position_1(-128.0f, 512.0f);
    ++entry_count;

    spawns[entry_count].pos = next_position_1;
    spawns[entry_count].template_id = chain_template_id;
    quest_vec2_t next_position_2(1152.0f, 896.0f);
    spawns[entry_count].trigger_time_ms = trigger_time_ms;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos = next_position_2;
    spawns[entry_count].template_id = chain_template_id;
    spawns[entry_count].trigger_time_ms = trigger_time_ms;
    int angle_index = 0;
    spawns[entry_count].count = one;
    ++entry_count;

    for (; angle_index < 28; ++angle_index) {
        float angle = (float)angle_index * 0.34906587f;
        spawns[entry_count + angle_index].pos.x =
            (float)cos(angle) * 256.0f + 512.0f;
        spawns[entry_count + angle_index].pos.y =
            (float)sin(angle) * 256.0f + 512.0f;
        spawns[entry_count + angle_index].template_id =
            SPAWN_ID_LIZARD_RANDOM_31;
        spawns[entry_count + angle_index].trigger_time_ms = trigger_time_ms;
        spawns[entry_count + angle_index].count = 1;
        spawns[entry_count + angle_index].heading =
            (float)angle_index * -0.34906587f;
        trigger_time_ms += 900;
    }

    *count = 31;
}
