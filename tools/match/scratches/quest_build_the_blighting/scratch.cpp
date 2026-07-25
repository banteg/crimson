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

    spawns[0].pos.x = (float)(terrain_texture_width + 128);
    spawns[0].pos.y = (float)(terrain_texture_width / 2);
    spawns[0].set_spawn(SPAWN_ID_ALIEN_DEADLY_FAST_2B, 1500, 2);

    spawns[1].pos.x = -128.0f;
    spawns[1].pos.y = (float)(terrain_texture_width / 2);
    spawns[1].set_spawn(SPAWN_ID_ALIEN_DEADLY_FAST_2B, 1500, 2);

    spawns[2].pos.y = 128.0f;
    spawns[2].pos.x = 896.0f;
    spawns[2].set_spawn(SPAWN_ID_DEN_ALIEN_BASIC_07, 2000, 1);

    spawns[3].pos.y = 128.0f;
    spawns[3].pos.x = 128.0f;
    spawns[3].set_spawn(SPAWN_ID_DEN_ALIEN_BASIC_07, 2000, 1);

    spawns[4].pos.y = 896.0f;
    spawns[4].pos.x = 128.0f;
    spawns[4].set_spawn(SPAWN_ID_DEN_ALIEN_BASIC_07, 2000, 1);

    spawns[5].pos.y = 896.0f;
    spawns[5].pos.x = 896.0f;
    spawns[5].set_spawn(SPAWN_ID_DEN_ALIEN_BASIC_07, 2000, 1);

    int wave = 0;
    quest_spawn_builder_t builder(&spawns[6], 6);
    int trigger_time_ms = 4000;
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
