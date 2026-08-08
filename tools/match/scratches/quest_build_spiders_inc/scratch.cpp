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

struct quest_spawn_builder_t {
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_spiders_inc(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    builder.spawns[builder.count].pos.y =
        (float)(terrain_texture_width + 64);
    builder.spawns[builder.count].pos.x =
        (float)(terrain_texture_width / 2);
    builder.spawns[builder.count].set_spawn(
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
        500,
        1);
    ++builder.count;

    builder.spawns[builder.count].pos.y =
        (float)(terrain_texture_width + 64);
    builder.spawns[builder.count].pos.x =
        (float)(terrain_texture_width / 2 + 64);
    builder.spawns[builder.count].set_spawn(
        SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
        500,
        1);
    ++builder.count;

    builder.spawns[builder.count].pos.y = -64.0f;
    builder.spawns[builder.count].pos.x =
        (float)(terrain_texture_width / 2);
    builder.spawns[builder.count].set_spawn(
        SPAWN_ID_SPIDER_SMALL_BLUE_40,
        500,
        4);
    ++builder.count;

    for (int trigger_time_ms = 17000, step_count = 0;
         trigger_time_ms < 107000;
         trigger_time_ms += 6000, ++step_count) {
        quest_entry_original_t *wave_spawn =
            &builder.spawns[builder.count];
        int wave_count = step_count / 2 + 3;
        wave_spawn->pos.y = (float)(terrain_texture_width + 64);
        wave_spawn->pos.x = (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
            trigger_time_ms,
            wave_count);
        ++builder.count;

        quest_entry_original_t *second_wave_spawn =
            &builder.spawns[builder.count];
        second_wave_spawn->pos.y = -64.0f;
        second_wave_spawn->pos.x = (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_SPIDER_SP1_AI7_TIMER_38,
            trigger_time_ms,
            wave_count);
        ++builder.count;
    }

    *count = builder.count;
}
