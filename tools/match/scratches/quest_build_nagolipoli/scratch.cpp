#include <math.h>

#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    quest_vec2_t() {}
    quest_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }

    void add(float value)
    {
        x += value;
        y += value;
    }
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;

    void set_position_and_template(
        const quest_vec2_t &position,
        int spawn_template_id)
    {
        pos = position;
        template_id = spawn_template_id;
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

    void set_heading_and_template(float spawn_heading, int spawn_template_id)
    {
        template_id = spawn_template_id;
        heading = spawn_heading;
    }

};

extern "C" void quest_build_nagolipoli(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;
    quest_entry_original_t *spawn = spawns;

    while (entry_count < 8) {
        float angle = (float)entry_count * 0.785398185f;
        spawn->pos.set(
            (float)cos(angle) * 128.0f,
            (float)sin(angle) * 128.0f);
        spawn->pos.add(512.0f);
        spawn->set_heading_and_template(
            angle,
            SPAWN_ID_SPIDER_SMALL_BLUE_40);
        spawn->trigger_time_ms = 2000;
        spawn->count = 1;
        ++entry_count;
        ++spawn;
    }

    int ring_index = 0;
    while (ring_index < 12) {
        float angle = (float)ring_index * 0.52359879f;
        spawns[entry_count + ring_index].pos.set(
            (float)cos(angle) * 178.0f,
            (float)sin(angle) * 178.0f);
        spawns[entry_count + ring_index].pos.add(512.0f);
        spawns[entry_count + ring_index].set_heading_and_template(
            angle,
            SPAWN_ID_SPIDER_SMALL_BLUE_40);
        spawns[entry_count + ring_index].trigger_time_ms = 8000;
        spawns[entry_count + ring_index].count = 1;
        ++ring_index;
    }
    entry_count += 12;

    quest_vec2_t top_left;
    top_left.x = -64.0f;
    top_left.y = -64.0f;
    quest_vec2_t top_right;
    top_right.x = 1088.0f;
    top_right.y = -64.0f;
    quest_vec2_t bottom_left;
    bottom_left.x = -64.0f;
    bottom_left.y = 1088.0f;
    quest_vec2_t bottom_right;
    bottom_right.x = 1088.0f;
    bottom_right.y = 1088.0f;

    int wave = 0;
    int trigger_time_ms = 13000;
    while (trigger_time_ms < 0x96c8) {
        spawns[entry_count].set_position_and_template(
            top_left,
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C);
        spawns[entry_count].heading = 1.04719758f;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = wave / 8 + 1;
        ++entry_count;

        spawns[entry_count].set_position_and_template(
            top_right,
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C);
        spawns[entry_count].heading = -1.04719758f;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = wave / 8 + 1;
        ++entry_count;

        spawns[entry_count].set_position_and_template(
            bottom_left,
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C);
        spawns[entry_count].heading = -1.04719758f;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = wave / 8 + 1;
        ++entry_count;

        spawns[entry_count].set_position_and_template(
            bottom_right,
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C);
        spawns[entry_count].heading = 3.926991f;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = wave / 8 + 1;
        ++entry_count;

        trigger_time_ms += 800;
        ++wave;
    }

    int line_index = 0;
    trigger_time_ms = (wave * 5 + 150) * 160;
    bottom_left.x = 64.0f;
    while (line_index < 6) {
        bottom_left.y = (float)line_index * 85.3333359f + 256.0f;
        spawns[entry_count + line_index].pos = bottom_left;
        spawns[entry_count + line_index].template_id =
            SPAWN_ID_DEN_SPIDER_BASIC_0A;
        spawns[entry_count + line_index].heading = 0.0f;
        spawns[entry_count + line_index].trigger_time_ms = trigger_time_ms;
        spawns[entry_count + line_index].count = 1;
        ++line_index;
        trigger_time_ms += 100;
    }
    entry_count += 6;

    line_index = 0;
    trigger_time_ms = wave * 800 + 25000;
    bottom_left.x = 960.0f;
    while (line_index < 6) {
        bottom_left.y = (float)line_index * 85.3333359f + 256.0f;
        spawns[entry_count + line_index].pos = bottom_left;
        spawns[entry_count + line_index].template_id =
            SPAWN_ID_DEN_SPIDER_BASIC_0A;
        spawns[entry_count + line_index].heading = 0.0f;
        spawns[entry_count + line_index].trigger_time_ms = trigger_time_ms;
        spawns[entry_count + line_index].count = 1;
        ++line_index;
        trigger_time_ms += 100;
    }
    entry_count += 6;

    trigger_time_ms = (wave * 5 + 175) * 160;
    spawn = &spawns[entry_count];
    spawn->set_position_and_template(
        quest_vec2_t(512.0f, 256.0f),
        SPAWN_ID_DEN_SPIDER_PLASMA_SHOOTERS_0B);
    spawn->heading = 3.14159274f;
    spawn->trigger_time_ms = trigger_time_ms;
    spawn->count = 1;
    ++entry_count;

    spawn = &spawns[entry_count];
    spawn->set_position_and_template(
        quest_vec2_t(512.0f, 768.0f),
        SPAWN_ID_DEN_SPIDER_PLASMA_SHOOTERS_0B);
    spawn->heading = 3.14159274f;
    spawn->trigger_time_ms = trigger_time_ms;
    spawn->count = 1;
    ++entry_count;

    trigger_time_ms = wave * 800 + 0x6f54;
    spawn = &spawns[entry_count];
    spawn->set_position_and_template(
        quest_vec2_t(512.0f, 1088.0f),
        SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C);
    spawn->heading = 3.926991f;
    spawn->trigger_time_ms = trigger_time_ms;
    spawn->count = 8;
    ++entry_count;

    spawn = &spawns[entry_count];
    spawn->set_position_and_template(
        quest_vec2_t(512.0f, -64.0f),
        SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C);
    spawn->heading = 3.926991f;
    spawn->trigger_time_ms = trigger_time_ms;
    spawn->count = 8;
    ++entry_count;

    *count = entry_count;
}
