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
};

extern "C" void quest_build_the_gathering(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].set(
        quest_vec2_t(256.0f, 512.0f),
        SPAWN_ID_SPIDER_SP2_SPLITTER_01,
        500,
        1);

    spawns[1].set(
        quest_vec2_t(768.0f, 512.0f),
        SPAWN_ID_SPIDER_SP2_SPLITTER_01,
        9500,
        2);

    spawns[2].set(
        quest_vec2_t(256.0f, 512.0f),
        SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
        15500,
        2);

    spawns[3].set(
        quest_vec2_t(768.0f, 512.0f),
        SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
        24500,
        2);

    spawns[4].set(
        quest_vec2_t(256.0f, 512.0f),
        SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00,
        30500,
        2);

    spawns[5].set(
        quest_vec2_t(768.0f, 512.0f),
        SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00,
        39500,
        2);

    spawns[6].set(
        quest_vec2_t(64.0f, 64.0f),
        SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
        54500,
        2);

    spawns[7].set(
        quest_vec2_t(960.0f, 64.0f),
        SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
        54500,
        1);

    spawns[8].set(
        quest_vec2_t(64.0f, 960.0f),
        SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
        54500,
        2);

    spawns[9].set(
        quest_vec2_t(960.0f, 960.0f),
        SPAWN_ID_SPIDER_SP1_CONST_RANGED_VARIANT_3C,
        54500,
        1);

    spawns[10].set(
        quest_vec2_t(-128.0f, 512.0f),
        SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A,
        90500,
        6);

    spawns[11].set(
        quest_vec2_t(1152.0f, 512.0f),
        SPAWN_ID_SPIDER_SP2_SPLITTER_01,
        99500,
        4);

    spawns[12].set(
        quest_vec2_t(1152.0f, 512.0f),
        SPAWN_ID_SPIDER_SP2_SPLITTER_01,
        109500,
        2);

    *count = 13;
}
