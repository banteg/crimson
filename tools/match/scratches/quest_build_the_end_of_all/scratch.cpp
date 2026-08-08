#include <math.h>

#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    void set(float x_value, float y_value)
    {
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

extern "C" void quest_build_the_end_of_all(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;
    spawns[entry_count].pos.x = 128.0f;
    int corner_template_id = SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
    spawns[entry_count].pos.y = 128.0f;
    spawns[entry_count].template_id = corner_template_id;
    int one = 1;
    spawns[entry_count].trigger_time_ms = 3000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.set(896.0f, 128.0f);
    spawns[entry_count].set_spawn(
        corner_template_id,
        6000,
        one);
    ++entry_count;

    spawns[entry_count].pos.set(128.0f, 896.0f);
    spawns[entry_count].set_spawn(
        corner_template_id,
        9000,
        one);
    ++entry_count;

    spawns[entry_count].pos.set(896.0f, 896.0f);
    spawns[entry_count].template_id = corner_template_id;
    int ring_index;
    spawns[entry_count].trigger_time_ms = 12000;
    spawns[entry_count].count = one;
    ring_index = 0;
    ++entry_count;

    int trigger_time_ms = 13000;
    do {
        float angle = (float)ring_index * 1.04719758f;
        spawns[entry_count].pos.set(
            (float)cos(angle) * 80.0f + 512.0f,
            (float)sin(angle) * 80.0f + 512.0f);
        spawns[entry_count].set_spawn(
            SPAWN_ID_DEN_ALIEN_BASIC_07,
            trigger_time_ms,
            one);
        ++entry_count;
        ++ring_index;
        trigger_time_ms += 300;
    } while (trigger_time_ms < 14800);

    spawns[entry_count].pos.x = 512.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].template_id =
        SPAWN_ID_DEN_SPIDER_PLASMA_SHOOTERS_0B;
    spawns[entry_count].trigger_time_ms = ring_index * 300 + 13000;
    spawns[entry_count].count = one;
    ++entry_count;

    int edge_y = 256;
    int edge_index = 0;
    int spawn_count = 2;
    trigger_time_ms = 18000;
    do {
        if ((edge_index & 1) != 0) {
            spawns[entry_count].pos.x = 1152.0f;
        } else {
            spawns[entry_count].pos.x = -128.0f;
        }
        spawns[entry_count].pos.y = (float)edge_y;
        spawns[entry_count].template_id =
            SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = spawn_count;
        ++entry_count;
        edge_y += 128;
        ++edge_index;
        trigger_time_ms += 1000;
    } while (edge_y < 768);

    ring_index = 0;
    trigger_time_ms = 43000;
    do {
        float angle =
            (float)ring_index * 1.04719758f + 0.52359879f;
        spawns[entry_count].pos.set(
            (float)cos(angle) * 80.0f + 512.0f,
            (float)sin(angle) * 80.0f + 512.0f);
        spawns[entry_count].set_spawn(
            SPAWN_ID_DEN_ALIEN_BASIC_07,
            trigger_time_ms,
            one);
        ++entry_count;
        ++ring_index;
        trigger_time_ms += 300;
    } while (trigger_time_ms < 44800);

    if (config_hardcore != 0) {
        ring_index = 0;
        trigger_time_ms = 62800;
        do {
            float angle =
                ((float)ring_index + 1.0f) * 0.52359879f;
            spawns[entry_count].pos.set(
                (float)cos(angle) * 180.0f + 512.0f,
                (float)sin(angle) * 180.0f + 512.0f);
            spawns[entry_count].set_spawn(
                SPAWN_ID_DEN_ALIEN_BASIC_07,
                trigger_time_ms,
                one);
            ++entry_count;
            ++ring_index;
            trigger_time_ms += 500;
        } while (trigger_time_ms < 68800);
    }

    edge_index = 0;
    trigger_time_ms = 48000;
    edge_y = 256;
    do {
        if ((edge_index & 1) != 0) {
            spawns[entry_count].pos.x = 1152.0f;
        } else {
            spawns[entry_count].pos.x = -128.0f;
        }
        spawns[entry_count].pos.y = (float)edge_y;
        spawns[entry_count].template_id =
            SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = spawn_count;
        ++entry_count;
        edge_y += 128;
        ++edge_index;
        trigger_time_ms += 1000;
    } while (edge_y < 768);

    *count = entry_count;
}
