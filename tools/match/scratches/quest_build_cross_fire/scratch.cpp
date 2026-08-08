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

extern "C" void quest_build_cross_fire(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos = quest_vec2_t(
        1074.0f,
        (float)terrain_texture_height * 0.5f);
    int *first_trigger = &spawns[0].trigger_time_ms;
    first_trigger[-1] = SPAWN_ID_SPIDER_SMALL_BLUE_40;
    first_trigger[0] = 100;
    first_trigger[1] = 6;

    spawns[1].pos = quest_vec2_t(-40.0f, 512.0f);
    spawns[1].set_spawn(
        SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C, 5500, 4);

    spawns[2].pos = quest_vec2_t(-40.0f, 512.0f);
    spawns[2].set_spawn(
        SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C, 15500, 6);

    spawns[3].pos = quest_vec2_t(512.0f, 512.0f);
    spawns[3].set_spawn(SPAWN_ID_SPIDER_SP2_SPLITTER_01, 18500, 2);

    spawns[4].pos = quest_vec2_t(-100.0f, 512.0f);
    spawns[4].set_spawn(
        SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C, 25500, 8);

    spawns[5].pos = quest_vec2_t(512.0f, 1152.0f);
    spawns[5].set_spawn(SPAWN_ID_SPIDER_SMALL_BLUE_40, 26000, 6);

    spawns[6].pos = quest_vec2_t(512.0f, -128.0f);
    spawns[6].set_spawn(SPAWN_ID_SPIDER_SMALL_BLUE_40, 26000, 6);

    *count = 7;
}
