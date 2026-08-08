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
    int entry_count = 0;

    float corner_low = 128.0f;
    spawns[entry_count].pos.x = corner_low;
    int den_template = SPAWN_ID_DEN_SPIDER_WEAK_10;
    spawns[entry_count].pos.y = corner_low;
    int den_trigger_time_ms = 1500;
    spawns[entry_count].template_id = den_template;
    int one = 1;
    spawns[entry_count].trigger_time_ms = den_trigger_time_ms;
    float corner_high = 896.0f;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.x = corner_high;
    spawns[entry_count].pos.y = corner_high;
    spawns[entry_count].template_id = den_template;
    spawns[entry_count].trigger_time_ms = den_trigger_time_ms;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.x = corner_high;
    spawns[entry_count].pos.y = corner_low;
    spawns[entry_count].template_id = den_template;
    spawns[entry_count].trigger_time_ms = den_trigger_time_ms;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.x = corner_low;
    spawns[entry_count].pos.y = corner_high;
    spawns[entry_count].template_id = den_template;
    spawns[entry_count].trigger_time_ms = den_trigger_time_ms;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.x = -64.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].set_spawn(
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38, 3000, 2);
    ++entry_count;

    spawns[entry_count].pos.x = 512.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
    spawns[entry_count].trigger_time_ms = 18000;
    float inner_low = 448.0f;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.x = inner_low;
    spawns[entry_count].pos.y = inner_low;
    spawns[entry_count].template_id = den_template;
    spawns[entry_count].trigger_time_ms = 20500;
    float inner_high = 576.0f;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.x = inner_high;
    spawns[entry_count].pos.y = inner_low;
    spawns[entry_count].set_spawn(
        den_template, 26000, one);
    ++entry_count;

    spawns[entry_count].pos.x = 1088.0f;
    spawns[entry_count].pos.y = 512.0f;
    spawns[entry_count].set_spawn(
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38, 21000, 2);
    ++entry_count;

    spawns[entry_count].pos.x = inner_high;
    spawns[entry_count].pos.y = inner_high;
    spawns[entry_count].set_spawn(
        den_template, 31500, one);
    ++entry_count;

    spawns[entry_count].pos.x = inner_low;
    spawns[entry_count].pos.y = inner_high;
    spawns[entry_count].set_spawn(
        den_template, 22000, one);
    ++entry_count;

    *count = entry_count;
}
