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
};

struct quest_spawn_builder_t {
    quest_entry_original_t *cursor;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : cursor(spawn_entries), count(0) {}
};

extern "C" void quest_build_two_fronts(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int wave = 0;

    while (wave < 40) {
#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer and counts it after
        // the metadata, which frees the stores to schedule ahead of the float
        // conversions.
        quest_entry_original_t *spawn = builder.cursor;
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        spawn->trigger_time_ms = wave * 2000 + 1000;
        spawn->count = 1;
        ++builder.count;
        ++builder.cursor;

        spawn = builder.cursor;
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
        spawn->trigger_time_ms = (wave * 5 + 5) * 400;
        spawn->count = 1;
#else
        builder.cursor->pos.x = (float)(terrain_texture_width + 64);
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        builder.cursor->template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        builder.cursor->trigger_time_ms = wave * 2000 + 1000;
        builder.cursor->count = 1;
        ++builder.count;
        ++builder.cursor;

        builder.cursor->pos.x = -64.0f;
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        builder.cursor->template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
        builder.cursor->trigger_time_ms = (wave * 5 + 5) * 400;
        builder.cursor->count = 1;
#endif
        ++builder.count;
        ++builder.cursor;

        if (wave == 10 || wave == 20) {
            int trigger_time_ms = wave * 2000 + 2500;

#if CL_BUILD == 10908
            spawn = builder.cursor;
            spawn->pos = quest_vec2_t(256.0f, 256.0f);
            spawn->template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            spawn->trigger_time_ms = trigger_time_ms;
            spawn->count = 1;
            ++builder.count;
            ++builder.cursor;

            spawn = builder.cursor;
            spawn->pos = quest_vec2_t(768.0f, 768.0f);
            spawn->template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
            spawn->trigger_time_ms = trigger_time_ms;
            spawn->count = 1;
#else
            builder.cursor->pos = quest_vec2_t(256.0f, 256.0f);
            builder.cursor->template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = 1;
            ++builder.cursor;

            builder.cursor->pos = quest_vec2_t(768.0f, 768.0f);
            ++builder.count;
            builder.cursor->template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = 1;
#endif
            ++builder.count;
            ++builder.cursor;
        }

        if (wave == 30) {
#if CL_BUILD == 10908
            spawn = builder.cursor;
            spawn->pos = quest_vec2_t(768.0f, 256.0f);
            spawn->template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            spawn->trigger_time_ms = 62500;
            spawn->count = 1;
            ++builder.count;
            ++builder.cursor;

            spawn = builder.cursor;
            spawn->pos = quest_vec2_t(256.0f, 768.0f);
            spawn->template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
            spawn->trigger_time_ms = 62500;
            spawn->count = 1;
#else
            builder.cursor->pos = quest_vec2_t(768.0f, 256.0f);
            builder.cursor->template_id = SPAWN_ID_DEN_SPIDER_BASIC_0A;
            builder.cursor->trigger_time_ms = 62500;
            builder.cursor->count = 1;
            ++builder.count;
            ++builder.cursor;

            builder.cursor->pos = quest_vec2_t(256.0f, 768.0f);
            builder.cursor->template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
            builder.cursor->trigger_time_ms = 62500;
            builder.cursor->count = 1;
#endif
            ++builder.count;
            ++builder.cursor;
        }

        ++wave;
    }

    *count = builder.count;
}
