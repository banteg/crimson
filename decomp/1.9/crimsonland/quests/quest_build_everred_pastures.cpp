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
    quest_entry_original_t *cursor;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : cursor(spawn_entries), count(0) {}
};

extern "C" void quest_build_everred_pastures(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int wave = 0;

    while (wave < 8) {
        int wave_count = wave + 1;

#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer and counts it after
        // the metadata, which frees the stores to schedule ahead of the float
        // conversions.
        quest_entry_original_t *spawn = builder.cursor;
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_32;
        spawn->trigger_time_ms = wave * 13000 + 1500;
        spawn->count = wave_count;
        ++builder.count;
        ++builder.cursor;

        spawn = builder.cursor;
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_RED_33;
        spawn->trigger_time_ms = wave * 13000 + 1500;
        spawn->count = wave_count;
        ++builder.count;
        ++builder.cursor;

        spawn = builder.cursor;
        spawn->pos.x = (float)(terrain_texture_width / 2);
        spawn->pos.y = (float)(terrain_texture_width + 64);
        spawn->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_GREEN_34;
        spawn->trigger_time_ms = wave * 13000 + 1500;
        spawn->count = wave_count;
        ++builder.count;
        ++builder.cursor;

        spawn = builder.cursor;
        spawn->pos.x = (float)(terrain_texture_width / 2);
        spawn->pos.y = -64.0f;
        spawn->template_id = SPAWN_ID_SPIDER_SP2_RANDOM_35;
        spawn->trigger_time_ms = wave * 13000 + 1500;
        spawn->count = wave_count;
        ++builder.count;
#else
        builder.cursor->pos.x = (float)(terrain_texture_width + 64);
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.cursor->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_32;
        builder.cursor->trigger_time_ms = wave * 13000 + 1500;
        builder.cursor->count = wave_count;
        ++builder.cursor;

        builder.cursor->pos.x = -64.0f;
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.cursor->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_RED_33;
        builder.cursor->trigger_time_ms = wave * 13000 + 1500;
        builder.cursor->count = wave_count;
        ++builder.cursor;

        builder.cursor->pos.x = (float)(terrain_texture_width / 2);
        builder.cursor->pos.y = (float)(terrain_texture_width + 64);
        ++builder.count;
        builder.cursor->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_GREEN_34;
        builder.cursor->trigger_time_ms = wave * 13000 + 1500;
        builder.cursor->count = wave_count;
        ++builder.cursor;

        builder.cursor->pos.x = (float)(terrain_texture_width / 2);
        builder.cursor->pos.y = -64.0f;
        ++builder.count;
        builder.cursor->template_id = SPAWN_ID_SPIDER_SP2_RANDOM_35;
        builder.cursor->trigger_time_ms = wave * 13000 + 1500;
        builder.cursor->count = wave_count;
#endif
        ++builder.cursor;

        if (wave == 3) {
#if CL_BUILD == 10908
            spawn = builder.cursor;
            spawn->pos.x = (float)(terrain_texture_width / 2);
            spawn->pos.y = -64.0f;
            spawn->template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
            spawn->trigger_time_ms = 40500;
            spawn->count = 8;
            ++builder.count;
            ++builder.cursor;

            spawn = builder.cursor;
            spawn->pos.x = (float)(terrain_texture_width / 2);
            spawn->pos.y = 1088.0f;
            spawn->template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
            spawn->trigger_time_ms = 40500;
            spawn->count = 8;
            ++builder.count;
#else
            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->pos.y = -64.0f;
            ++builder.count;
            builder.cursor->template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
            builder.cursor->trigger_time_ms = 40500;
            builder.cursor->count = 8;
            ++builder.cursor;

            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->pos.y = 1088.0f;
            ++builder.count;
            builder.cursor->template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
            builder.cursor->trigger_time_ms = 40500;
            builder.cursor->count = 8;
#endif
            ++builder.cursor;
        }

        ++wave;
    }

    *count = builder.count;
}
