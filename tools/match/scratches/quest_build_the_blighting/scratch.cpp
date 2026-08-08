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

    quest_spawn_builder_t(
        quest_entry_original_t *spawn_cursor,
        int spawn_count)
        : cursor(spawn_cursor), count(spawn_count) {}
};

extern "C" void quest_build_the_blighting(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int spawn_template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
    int entry_count = 0;

    spawns[entry_count].pos.x = (float)(terrain_texture_width + 128);
    spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
    spawns[entry_count].set_spawn(SPAWN_ID_ALIEN_DEADLY_FAST_2B, 1500, 2);
    ++entry_count;

    spawns[entry_count].pos.x = -128.0f;
    spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
    spawns[entry_count].set_spawn(SPAWN_ID_ALIEN_DEADLY_FAST_2B, 1500, 2);
    ++entry_count;

    spawns[entry_count].pos.y = 128.0f;
    spawns[entry_count].pos.x = 896.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
    int one = 1;
    spawns[entry_count].trigger_time_ms = 2000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.y = 128.0f;
    spawns[entry_count].pos.x = 128.0f;
    spawns[entry_count].set_spawn(SPAWN_ID_DEN_ALIEN_BASIC_07, 2000, one);
    ++entry_count;

    spawns[entry_count].pos.y = 896.0f;
    spawns[entry_count].pos.x = 128.0f;
    spawns[entry_count].set_spawn(SPAWN_ID_DEN_ALIEN_BASIC_07, 2000, one);
    ++entry_count;

    spawns[entry_count].pos.y = 896.0f;
    spawns[entry_count].pos.x = 896.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
    spawns[entry_count].trigger_time_ms = 2000;
    spawns[entry_count].count = one;
    ++entry_count;

    int wave = 0;
    int trigger_time_ms = 4000;
    quest_spawn_builder_t builder(&spawns[entry_count], entry_count);
    while (wave < 8) {
        int parity = wave % 2;

        if (wave == 2 || wave == 4) {
            builder.cursor->pos.x = -128.0f;
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            builder.cursor->set_spawn(
                SPAWN_ID_ALIEN_DEADLY_FAST_2B,
                trigger_time_ms,
                4);
            ++builder.count;
            ++builder.cursor;
        }

        if (wave == 3 || wave == 5) {
            builder.cursor->pos.x = 1152.0f;
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            builder.cursor->set_spawn(
                SPAWN_ID_ALIEN_DEADLY_FAST_2B,
                trigger_time_ms,
                4);
            ++builder.count;
            ++builder.cursor;
        }

        if (parity == 0) {
            spawn_template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        } else if (parity == 1) {
            spawn_template_id = SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C;
        }

        int layout = wave % 5;
        if (layout == 0) {
            builder.cursor->pos.x = (float)(terrain_texture_width + 64);
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            builder.cursor->set_spawn(
                spawn_template_id,
                trigger_time_ms,
                12);
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 15000;
        } else if (layout == 1) {
            builder.cursor->pos.x = -64.0f;
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            builder.cursor->set_spawn(
                spawn_template_id,
                trigger_time_ms,
                12);
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 15000;
        } else if (layout == 2) {
            builder.cursor->pos.y = (float)(terrain_texture_width + 64);
            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->set_spawn(
                spawn_template_id,
                trigger_time_ms,
                12);
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 15000;
        } else if (layout == 3) {
            builder.cursor->pos.y = -64.0f;
            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->set_spawn(
                spawn_template_id,
                trigger_time_ms,
                12);
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 15000;
        }

        trigger_time_ms += 1000;
        ++wave;
    }

    *count = builder.count;
}
