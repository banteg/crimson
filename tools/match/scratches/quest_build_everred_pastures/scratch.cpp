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

        builder.cursor->pos.x = (float)(terrain_texture_width + 64);
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        int trigger_time_ms = wave * 13000 + 1500;
        builder.cursor->template_id = SPAWN_ID_SPIDER_SP1_RANDOM_32;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = wave_count;
        ++builder.cursor;

        builder.cursor->pos.x = -64.0f;
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.cursor->set_spawn(
            SPAWN_ID_SPIDER_SP1_RANDOM_RED_33,
            trigger_time_ms,
            wave_count);
        ++builder.cursor;

        builder.cursor->pos.x = (float)(terrain_texture_width / 2);
        builder.cursor->pos.y = (float)(terrain_texture_width + 64);
        ++builder.count;
        builder.cursor->set_spawn(
            SPAWN_ID_SPIDER_SP1_RANDOM_GREEN_34,
            trigger_time_ms,
            wave_count);
        ++builder.cursor;

        builder.cursor->pos.x = (float)(terrain_texture_width / 2);
        builder.cursor->pos.y = -64.0f;
        ++builder.count;
        builder.cursor->set_spawn(
            SPAWN_ID_SPIDER_SP2_RANDOM_35,
            trigger_time_ms,
            wave_count);
        ++builder.cursor;

        if (wave == 3) {
            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->pos.y = -64.0f;
            ++builder.count;
            builder.cursor->set_spawn(
                SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B,
                40500,
                8);
            ++builder.cursor;

            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->pos.y = 1088.0f;
            ++builder.count;
            builder.cursor->set_spawn(
                SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B,
                40500,
                8);
            ++builder.cursor;
        }

        ++wave;
    }

    *count = builder.count;
}
