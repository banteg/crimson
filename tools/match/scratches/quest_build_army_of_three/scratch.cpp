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

extern "C" void quest_build_army_of_three(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(-64.0f, 256.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15;
    int one = 1;
    spawns[entry_count].trigger_time_ms = 500;
    spawns[entry_count].count = one;
    quest_vec2_t next_position_1(-64.0f, 512.0f);
    ++entry_count;

    spawns[entry_count].pos = next_position_1;
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15, 5500, one);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(-64.0f, 768.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15;
    quest_vec2_t next_position_3(-64.0f, 768.0f);
    spawns[entry_count].trigger_time_ms = 15000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos = next_position_3;
    spawns[entry_count].template_id =
        SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17;
    quest_vec2_t next_position_4(-64.0f, 512.0f);
    spawns[entry_count].trigger_time_ms = 19500;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos = next_position_4;
    spawns[entry_count].template_id =
        SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17;
    quest_vec2_t next_position_5(-64.0f, 256.0f);
    spawns[entry_count].trigger_time_ms = 22500;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos = next_position_5;
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17, 26500, one);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(-64.0f, 256.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16;
    quest_vec2_t next_position_7(-64.0f, 512.0f);
    spawns[entry_count].trigger_time_ms = 35500;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos = next_position_7;
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16, 39500, one);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(-64.0f, 768.0f);
    spawns[entry_count].template_id =
        SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16;
    spawns[entry_count].trigger_time_ms = 42500;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(512.0f, 1152.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15, 52500, 3);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(512.0f, -256.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17, 56500, 3);
    ++entry_count;

    *count = entry_count;
}
