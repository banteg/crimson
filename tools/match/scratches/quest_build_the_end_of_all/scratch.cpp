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
    int one = 1;
    int corner_template_id =
        SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;

    spawns[0].pos.set(128.0f, 128.0f);
    spawns[0].set_spawn(
        corner_template_id,
        3000,
        one);

    spawns[1].pos.set(896.0f, 128.0f);
    spawns[1].set_spawn(
        corner_template_id,
        6000,
        one);

    spawns[2].pos.set(128.0f, 896.0f);
    spawns[2].set_spawn(
        corner_template_id,
        9000,
        one);

    spawns[3].pos.set(896.0f, 896.0f);
    spawns[3].set_spawn(
        corner_template_id,
        12000,
        one);

    int ring_index = 0;
    int trigger_time_ms = 13000;
    quest_entry_original_t *spawn = &spawns[4];
    do {
        float angle = (float)ring_index * 1.04719758f;
        spawn->pos.set(
            (float)cos(angle) * 80.0f + 512.0f,
            (float)sin(angle) * 80.0f + 512.0f);
        spawn->set_spawn(
            SPAWN_ID_DEN_ALIEN_BASIC_07,
            trigger_time_ms,
            one);
        ++spawn;
        ++ring_index;
        trigger_time_ms += 300;
    } while (trigger_time_ms < 14800);

    spawns[10].pos.x = 512.0f;
    spawns[10].pos.y = 512.0f;
    spawns[10].set_spawn(
        SPAWN_ID_DEN_SPIDER_PLASMA_SHOOTERS_0B,
        ring_index * 300 + 13000,
        one);

    int edge_y = 256;
    int edge_index = 0;
    int spawn_count = 2;
    trigger_time_ms = 18000;
    spawn = &spawns[11];
    do {
        if ((edge_index & 1) != 0) {
            spawn->pos.x = 1152.0f;
        } else {
            spawn->pos.x = -128.0f;
        }
        spawn->pos.y = (float)edge_y;
        spawn->template_id = SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++spawn;
        edge_y += 128;
        ++edge_index;
        trigger_time_ms += 1000;
    } while (edge_y < 768);

    ring_index = 0;
    trigger_time_ms = 43000;
    spawn = &spawns[15];
    int entry_count = 21;
    do {
        float angle =
            (float)ring_index * 1.04719758f + 0.52359879f;
        spawn->pos.set(
            (float)cos(angle) * 80.0f + 512.0f,
            (float)sin(angle) * 80.0f + 512.0f);
        spawn->set_spawn(
            SPAWN_ID_DEN_ALIEN_BASIC_07,
            trigger_time_ms,
            one);
        ++spawn;
        ++ring_index;
        trigger_time_ms += 300;
    } while (trigger_time_ms < 44800);

    if (config_hardcore != 0) {
        ring_index = 0;
        trigger_time_ms = 62800;
        spawn = &spawns[21];
        entry_count = 33;
        do {
            float angle =
                ((float)ring_index + 1.0f) * 0.52359879f;
            spawn->pos.set(
                (float)cos(angle) * 180.0f + 512.0f,
                (float)sin(angle) * 180.0f + 512.0f);
            spawn->set_spawn(
                SPAWN_ID_DEN_ALIEN_BASIC_07,
                trigger_time_ms,
                one);
            ++spawn;
            ++ring_index;
            trigger_time_ms += 500;
        } while (trigger_time_ms < 68800);
    }

    edge_y = 256;
    edge_index = 0;
    trigger_time_ms = 48000;
    spawn = &spawns[entry_count];
    entry_count += 4;
    do {
        if ((edge_index & 1) != 0) {
            spawn->pos.x = 1152.0f;
        } else {
            spawn->pos.x = -128.0f;
        }
        spawn->pos.y = (float)edge_y;
        spawn->template_id = SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++spawn;
        edge_y += 128;
        ++edge_index;
        trigger_time_ms += 1000;
    } while (edge_y < 768);

    *count = entry_count;
}
