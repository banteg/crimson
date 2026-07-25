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

struct quest_spawn_builder_t {
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_nagolipoli(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    quest_spawn_builder_t builder(spawns);
    quest_entry_original_t *spawn = spawns;

    while (builder.count < 8) {
        float angle = (float)builder.count * 0.785398185f;
        spawn->pos.set(
            (float)cos(angle) * 128.0f,
            (float)sin(angle) * 128.0f);
        spawn->pos.add(512.0f);
        spawn->heading = angle;
        spawn->set_spawn(
            SPAWN_ID_SPIDER_SMALL_BLUE_40,
            2000,
            1);
        ++builder.count;
        ++spawn;
    }

    int ring_index = 0;
    spawn = &spawns[builder.count];
    builder.count += 12;
    while (ring_index < 12) {
        float angle = (float)ring_index * 0.52359879f;
        spawn->pos.set(
            (float)cos(angle) * 178.0f,
            (float)sin(angle) * 178.0f);
        spawn->pos.add(512.0f);
        spawn->heading = angle;
        spawn->set_spawn(
            SPAWN_ID_SPIDER_SMALL_BLUE_40,
            8000,
            1);
        ++spawn;
        ++ring_index;
    }

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
    spawn = &spawns[builder.count];
    while (trigger_time_ms < 0x96c8) {
        int spawn_count = wave / 8 + 1;

        spawn->pos = top_left;
        spawn->heading = 1.04719758f;
        spawn->set_spawn(
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
            trigger_time_ms,
            spawn_count);
        ++builder.count;
        ++spawn;

        spawn->pos = top_right;
        spawn->heading = -1.04719758f;
        spawn->set_spawn(
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
            trigger_time_ms,
            spawn_count);
        ++builder.count;
        ++spawn;

        spawn->pos = bottom_left;
        spawn->heading = -1.04719758f;
        spawn->set_spawn(
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
            trigger_time_ms,
            spawn_count);
        ++builder.count;
        ++spawn;

        spawn->pos = bottom_right;
        spawn->heading = 3.926991f;
        spawn->set_spawn(
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
            trigger_time_ms,
            spawn_count);
        ++builder.count;
        ++spawn;

        trigger_time_ms += 800;
        ++wave;
    }

    int line_index = 0;
    trigger_time_ms = (wave * 5 + 150) * 160;
    bottom_left.x = 64.0f;
    spawn = &spawns[builder.count];
    builder.count += 6;
    while (line_index < 6) {
        bottom_left.y = (float)line_index * 85.3333359f + 256.0f;
        spawn->pos = bottom_left;
        spawn->set_spawn(
            SPAWN_ID_DEN_SPIDER_BASIC_0A,
            trigger_time_ms,
            1);
        spawn->heading = 0.0f;
        ++line_index;
        ++spawn;
        trigger_time_ms += 100;
    }

    line_index = 0;
    trigger_time_ms = wave * 800 + 25000;
    bottom_left.x = 960.0f;
    spawn = &spawns[builder.count];
    builder.count += 6;
    while (line_index < 6) {
        bottom_left.y = (float)line_index * 85.3333359f + 256.0f;
        spawn->pos = bottom_left;
        spawn->set_spawn(
            SPAWN_ID_DEN_SPIDER_BASIC_0A,
            trigger_time_ms,
            1);
        spawn->heading = 0.0f;
        ++line_index;
        ++spawn;
        trigger_time_ms += 100;
    }

    quest_vec2_t tail_pos;

    trigger_time_ms = (wave * 5 + 175) * 160;
    spawn = &spawns[builder.count];
    tail_pos.x = 512.0f;
    tail_pos.y = 256.0f;
    spawn->pos = tail_pos;
    spawn->heading = 3.14159274f;
    spawn->set_spawn(
        SPAWN_ID_DEN_SPIDER_PLASMA_SHOOTERS_0B,
        trigger_time_ms,
        1);
    ++builder.count;

    spawn = &spawns[builder.count];
    tail_pos.x = 512.0f;
    tail_pos.y = 768.0f;
    spawn->pos = tail_pos;
    spawn->heading = 3.14159274f;
    spawn->set_spawn(
        SPAWN_ID_DEN_SPIDER_PLASMA_SHOOTERS_0B,
        trigger_time_ms,
        1);
    ++builder.count;

    trigger_time_ms = wave * 800 + 0x6f54;
    spawn = &spawns[builder.count];
    tail_pos.x = 512.0f;
    tail_pos.y = 1088.0f;
    spawn->pos = tail_pos;
    spawn->heading = 3.926991f;
    spawn->set_spawn(
        SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
        trigger_time_ms,
        8);
    ++builder.count;

    spawn = &spawns[builder.count];
    tail_pos.x = 512.0f;
    tail_pos.y = -64.0f;
    spawn->pos = tail_pos;
    spawn->heading = 3.926991f;
    spawn->set_spawn(
        SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
        trigger_time_ms,
        8);
    ++builder.count;

    *count = builder.count;
}
