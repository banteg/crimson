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

extern "C" void quest_build_the_collaboration(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int wave = 0;
    int trigger_time_ms = 1500;

    while (trigger_time_ms < 177500) {
        int spawn_count = (int)((float)wave * 0.8f + 7.0f);

        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A,
            trigger_time_ms,
            spawn_count);

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width / 2);
        spawn->pos.y = (float)(terrain_texture_width + 64);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B,
            trigger_time_ms,
            spawn_count);

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C,
            trigger_time_ms,
            spawn_count);

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = 512.0f;
        spawn->pos.y = -64.0f;
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            spawn_count);

        trigger_time_ms += 11000;
        ++wave;
    }

    *count = builder.count;
}
