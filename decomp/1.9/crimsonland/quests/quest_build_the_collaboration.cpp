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

#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer, which frees the
        // metadata stores to schedule ahead of the float conversions.
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++builder.count;

        spawn = &builder.spawns[builder.count];
        spawn->pos.y = (float)(terrain_texture_width + 64);
        spawn->pos.x = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++builder.count;

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++builder.count;

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = 512.0f;
        spawn->pos.y = -64.0f;
        spawn->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
#else
        builder.spawns[builder.count].pos.x =
            (float)(terrain_texture_width + 64);
        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].template_id =
            SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        builder.spawns[builder.count].trigger_time_ms = trigger_time_ms;
        builder.spawns[builder.count].count = spawn_count;
        ++builder.count;

        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width + 64);
        builder.spawns[builder.count].pos.x =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].template_id =
            SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
        builder.spawns[builder.count].trigger_time_ms = trigger_time_ms;
        builder.spawns[builder.count].count = spawn_count;
        ++builder.count;

        builder.spawns[builder.count].pos.x = -64.0f;
        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].template_id =
            SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C;
        builder.spawns[builder.count].trigger_time_ms = trigger_time_ms;
        builder.spawns[builder.count].count = spawn_count;
        ++builder.count;

        builder.spawns[builder.count].pos.x = 512.0f;
        builder.spawns[builder.count].pos.y = -64.0f;
        builder.spawns[builder.count].template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.spawns[builder.count].trigger_time_ms = trigger_time_ms;
        builder.spawns[builder.count].count = spawn_count;
#endif
        ++builder.count;

        ++wave;
        trigger_time_ms += 11000;
    }

    *count = builder.count;
}
