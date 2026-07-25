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

    void set_spawn(
        int spawn_template_id,
        int spawn_trigger_time_ms)
    {
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
    }
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
        builder.cursor->pos.x = (float)(terrain_texture_width + 64);
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        builder.cursor->set_spawn(
            SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A,
            wave * 2000 + 1000);
        builder.cursor->count = 1;
        ++builder.count;
        ++builder.cursor;

        builder.cursor->pos.x = -64.0f;
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        builder.cursor->set_spawn(
            SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B,
            (wave * 5 + 5) * 400);
        builder.cursor->count = 1;
        ++builder.count;
        ++builder.cursor;

        if (wave == 10 || wave == 20) {
            int trigger_time_ms = wave * 2000 + 2500;

            builder.cursor->pos = quest_vec2_t(256.0f, 256.0f);
            builder.cursor->set_spawn(
                SPAWN_ID_DEN_SPIDER_BASIC_0A,
                trigger_time_ms);
            builder.cursor->count = 1;
            ++builder.cursor;

            builder.cursor->pos = quest_vec2_t(768.0f, 768.0f);
            ++builder.count;
            builder.cursor->set_spawn(
                SPAWN_ID_DEN_ALIEN_BASIC_07,
                trigger_time_ms);
            builder.cursor->count = 1;
            ++builder.count;
            ++builder.cursor;
        }

        if (wave == 30) {
            builder.cursor->pos = quest_vec2_t(768.0f, 256.0f);
            builder.cursor->set_spawn(
                SPAWN_ID_DEN_SPIDER_BASIC_0A,
                62500);
            builder.cursor->count = 1;
            ++builder.count;
            ++builder.cursor;

            builder.cursor->pos = quest_vec2_t(256.0f, 768.0f);
            builder.cursor->set_spawn(
                SPAWN_ID_DEN_ALIEN_BASIC_07,
                62500);
            builder.cursor->count = 1;
            ++builder.count;
            ++builder.cursor;
        }

        ++wave;
    }

    *count = builder.count;
}
