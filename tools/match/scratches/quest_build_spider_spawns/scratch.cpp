#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;
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

extern "C" void quest_build_spider_spawns(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    float corner_low = 128.0f;
    spawns[0].pos.x = corner_low;
    int den_template = SPAWN_ID_DEN_SPIDER_WEAK_10;
    spawns[0].pos.y = corner_low;
    int den_trigger_time_ms = 1500;
    spawns[0].template_id = den_template;
    int one = 1;
    spawns[0].trigger_time_ms = den_trigger_time_ms;
    float corner_high = 896.0f;
    spawns[0].count = one;

    spawns[1].pos.x = corner_high;
    spawns[1].pos.y = corner_high;
    spawns[1].template_id = den_template;
    spawns[1].trigger_time_ms = den_trigger_time_ms;
    spawns[1].count = one;

    spawns[2].pos.x = corner_high;
    spawns[2].pos.y = corner_low;
    spawns[2].template_id = den_template;
    spawns[2].trigger_time_ms = den_trigger_time_ms;
    spawns[2].count = one;

    spawns[3].pos.x = corner_low;
    spawns[3].pos.y = corner_high;
    spawns[3].template_id = den_template;
    spawns[3].trigger_time_ms = den_trigger_time_ms;
    spawns[3].count = one;

    spawns[4].pos.x = -64.0f;
    spawns[4].pos.y = 512.0f;
    spawns[4].set_spawn(
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38, 3000, 2);

    spawns[5].pos.x = 512.0f;
    spawns[5].pos.y = 512.0f;
    spawns[5].set_spawn(
        SPAWN_ID_DEN_SPIDER_BASIC_0A, 18000, one);

    spawns[6].pos.x = 448.0f;
    spawns[6].pos.y = 448.0f;
    spawns[6].set_spawn(
        den_template, 20500, one);

    spawns[7].pos.x = 576.0f;
    spawns[7].pos.y = 448.0f;
    spawns[7].set_spawn(
        den_template, 26000, one);

    spawns[8].pos.x = 1088.0f;
    spawns[8].pos.y = 512.0f;
    spawns[8].set_spawn(
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38, 21000, 2);

    spawns[9].pos.x = 576.0f;
    spawns[9].pos.y = 576.0f;
    spawns[9].set_spawn(
        den_template, 31500, one);

    spawns[10].pos.x = 448.0f;
    spawns[10].pos.y = 576.0f;
    spawns[10].set_spawn(
        den_template, 22000, one);

    *count = 11;
}
