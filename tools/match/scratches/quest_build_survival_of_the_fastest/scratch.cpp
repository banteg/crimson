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

struct quest_spawn_builder_t {
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_survival_of_the_fastest(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int x = 256;
    int trigger_time_ms = 500;
    quest_entry_original_t *spawn = builder.spawns;
    while (x < 688) {
        spawn->pos = quest_vec2_t((float)x, 256.0f);
        spawn->set_spawn(
            SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_time_ms,
            1);
        ++builder.count;
        ++spawn;
        x += 72;
        trigger_time_ms += 900;
    }

    int path_index = builder.count;
    int y = 256;
    trigger_time_ms = 5900;
    spawn = &builder.spawns[builder.count];
    while (y < 688) {
        spawn->pos = quest_vec2_t(688.0f, (float)y);
        spawn->set_spawn(
            SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_time_ms,
            1);
        ++builder.count;
        ++spawn;
        ++path_index;
        y += 72;
        trigger_time_ms += 900;
    }

    int entry_count = builder.count;
    while (path_index < 16) {
        x = 1552 - path_index * 72;
        trigger_time_ms = path_index * 900 + 500;
        quest_entry_original_t *spawn = &builder.spawns[entry_count];
        spawn->pos = quest_vec2_t((float)x, 688.0f);
        spawn->set_spawn(
            SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_time_ms,
            1);
        ++entry_count;
        ++path_index;
    }

    while (path_index < 20) {
        y = 1840 - path_index * 72;
        trigger_time_ms = path_index * 900 + 500;
        quest_entry_original_t *spawn = &builder.spawns[entry_count];
        spawn->pos = quest_vec2_t(400.0f, (float)y);
        spawn->set_spawn(
            SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_time_ms,
            1);
        ++entry_count;
        ++path_index;
    }

    while (path_index < 22) {
        x = path_index * 72 - 1040;
        trigger_time_ms = path_index * 900 + 500;
        quest_entry_original_t *spawn = &builder.spawns[entry_count];
        spawn->pos = quest_vec2_t((float)x, 400.0f);
        spawn->set_spawn(
            SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_time_ms,
            1);
        ++entry_count;
        ++path_index;
    }

    int first_corner_trigger_ms = path_index * 900 + 2500;
    builder.spawns[entry_count].pos.x = 128.0f;
    builder.spawns[entry_count].pos.y = 128.0f;
    builder.spawns[entry_count].template_id =
        SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10;
    builder.spawns[entry_count].trigger_time_ms = first_corner_trigger_ms;
    builder.spawns[entry_count].count = 1;
    ++entry_count;

    builder.spawns[entry_count].pos.x = 896.0f;
    builder.spawns[entry_count].pos.y = 128.0f;
    builder.spawns[entry_count].template_id =
        SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07;
    builder.spawns[entry_count].trigger_time_ms = first_corner_trigger_ms;
    builder.spawns[entry_count].count = 1;
    ++entry_count;

    int second_corner_trigger_ms = path_index * 900 + 4500;
    builder.spawns[entry_count].pos.x = 128.0f;
    builder.spawns[entry_count].pos.y = 896.0f;
    builder.spawns[entry_count].template_id =
        SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07;
    builder.spawns[entry_count].trigger_time_ms = second_corner_trigger_ms;
    builder.spawns[entry_count].count = 1;
    ++entry_count;

    builder.spawns[entry_count].pos.x = 896.0f;
    builder.spawns[entry_count].pos.y = 896.0f;
    builder.spawns[entry_count].template_id =
        SPAWN_ID_ALIEN_SPAWNER_CHILD_32_FAST_10;
    builder.spawns[entry_count].trigger_time_ms = second_corner_trigger_ms;
    builder.spawns[entry_count].count = 1;
    ++entry_count;

    *count = entry_count;
}
