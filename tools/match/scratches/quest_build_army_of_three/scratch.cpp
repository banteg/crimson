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

    spawns[0].pos = quest_vec2_t(-64.0f, 256.0f);
    int *first_trigger = &spawns[0].trigger_time_ms;
    first_trigger[-1] = SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15;
    first_trigger[0] = 500;
    first_trigger[1] = 1;

    spawns[1].pos = quest_vec2_t(-64.0f, 512.0f);
    spawns[1].set_spawn(SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15, 5500, 1);

    spawns[2].pos = quest_vec2_t(-64.0f, 768.0f);
    spawns[2].set_spawn(SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15, 15000, 1);

    spawns[3].pos = quest_vec2_t(-64.0f, 768.0f);
    spawns[3].set_spawn(SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17, 19500, 1);

    spawns[4].pos = quest_vec2_t(-64.0f, 512.0f);
    spawns[4].set_spawn(SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17, 22500, 1);

    spawns[5].pos = quest_vec2_t(-64.0f, 256.0f);
    spawns[5].set_spawn(SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17, 26500, 1);

    spawns[6].pos = quest_vec2_t(-64.0f, 256.0f);
    spawns[6].set_spawn(SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16, 35500, 1);

    spawns[7].pos = quest_vec2_t(-64.0f, 512.0f);
    spawns[7].set_spawn(SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16, 39500, 1);

    spawns[8].pos = quest_vec2_t(-64.0f, 768.0f);
    spawns[8].set_spawn(SPAWN_ID_FORMATION_GRID_LIZARD_WHITE_16, 42500, 1);

    spawns[9].pos = quest_vec2_t(512.0f, 1152.0f);
    spawns[9].set_spawn(SPAWN_ID_FORMATION_GRID_ALIEN_WHITE_15, 52500, 3);

    spawns[10].pos = quest_vec2_t(512.0f, -256.0f);
    spawns[10].set_spawn(SPAWN_ID_FORMATION_GRID_SPIDER_SP1_WHITE_17, 56500, 3);

    *count = 11;
}
