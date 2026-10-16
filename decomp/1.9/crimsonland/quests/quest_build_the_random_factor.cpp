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

extern "C" void quest_build_the_random_factor(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    for (int trigger_time_ms = 1500;
         trigger_time_ms < 101500;
         trigger_time_ms += 10000) {
#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer, which frees the
        // metadata stores to schedule ahead of the float conversions.
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_ALIEN_RANDOM_1D;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = config_blob.player_count * 2 + 4;
        ++builder.count;

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_ALIEN_RANDOM_1D;
        spawn->trigger_time_ms = trigger_time_ms + 200;
        spawn->count = 6;
#else
        builder.spawns[builder.count].pos.x =
            (float)(terrain_texture_width + 64);
        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
        builder.spawns[builder.count].trigger_time_ms = trigger_time_ms;
        builder.spawns[builder.count].count = config_blob.player_count * 2 + 4;
        ++builder.count;

        builder.spawns[builder.count].pos.x = -64.0f;
        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].template_id = SPAWN_ID_ALIEN_RANDOM_1D;
        builder.spawns[builder.count].trigger_time_ms = trigger_time_ms + 200;
        builder.spawns[builder.count].count = 6;
#endif
        ++builder.count;

        if (crt_rand() % 5 == 3) {
#if CL_BUILD == 10908
            spawn = &builder.spawns[builder.count];
            spawn->pos.x = (float)(terrain_texture_width / 2);
            spawn->pos.y = 1088.0f;
            spawn->template_id = SPAWN_ID_ALIEN_BIG_GRAY_29;
            spawn->trigger_time_ms = trigger_time_ms;
            spawn->count = config_blob.player_count;
#else
            builder.spawns[builder.count].pos.x =
                (float)(terrain_texture_width / 2);
            builder.spawns[builder.count].pos.y = 1088.0f;
            builder.spawns[builder.count].template_id =
                SPAWN_ID_ALIEN_BIG_GRAY_29;
            builder.spawns[builder.count].trigger_time_ms = trigger_time_ms;
            builder.spawns[builder.count].count = config_blob.player_count;
#endif
            ++builder.count;
        }
    }

    *count = builder.count;
}
