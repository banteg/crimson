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
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(256.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_SP2_SPLITTER_01;
    spawns[entry_count].trigger_time_ms = 500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(768.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_SP2_SPLITTER_01;
    spawns[entry_count].trigger_time_ms = 9500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(256.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_BOSS_3A;
    spawns[entry_count].trigger_time_ms = 15500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].set(
        quest_vec2_t(768.0f, 512.0f),
        SPAWN_ID_SPIDER_BOSS_3A,
        24500,
        2);
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(256.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00;
    spawns[entry_count].trigger_time_ms = 30500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(768.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_ZOMBIE_BOSS_SPAWNER_00;
    spawns[entry_count].trigger_time_ms = 39500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(64.0f, 64.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
    spawns[entry_count].trigger_time_ms = 54500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(960.0f, 64.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
    spawns[entry_count].trigger_time_ms = 54500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(64.0f, 960.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
    spawns[entry_count].trigger_time_ms = 54500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(960.0f, 960.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_PLASMA_SHOOTER_3C;
    spawns[entry_count].trigger_time_ms = 54500;
    spawns[entry_count].count = 1;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(-128.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_BOSS_3A;
    spawns[entry_count].trigger_time_ms = 90500;
    spawns[entry_count].count = 6;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(1152.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_SP2_SPLITTER_01;
    spawns[entry_count].trigger_time_ms = 99500;
    spawns[entry_count].count = 4;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(1152.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_SPIDER_SP2_SPLITTER_01;
    spawns[entry_count].trigger_time_ms = 109500;
    spawns[entry_count].count = 2;
    ++entry_count;

    *count = entry_count;
}
