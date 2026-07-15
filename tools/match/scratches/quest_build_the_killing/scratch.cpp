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

extern "C" void quest_build_the_killing(
    quest_spawn_entry_t *entries, int *count)
{
    int trigger_time_ms = 2000;
    int spawn_template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
    int wave = 0;
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    while (wave < 10) {
        crt_rand();
        int spawn_cycle = wave % 3;
        if (spawn_cycle == 0) {
            spawn_template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        } else if (spawn_cycle == 1) {
            spawn_template_id = SPAWN_ID_AI1_SPIDER_SP1_BLUE_TINT_1B;
        } else if (spawn_cycle == 2) {
            spawn_template_id = SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C;
        }

        crt_rand();
        int layout = wave % 5;
        if (layout == 0) {
            builder.cursor->pos.x = (float)(terrain_texture_width + 64);
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            builder.cursor->template_id = spawn_template_id;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = 12;
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 5000;
        } else if (layout == 1) {
            builder.cursor->pos.x = -64.0f;
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            builder.cursor->template_id = spawn_template_id;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = 12;
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 5000;
        } else if (layout == 2) {
            builder.cursor->pos.y = (float)(terrain_texture_width + 64);
            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->template_id = spawn_template_id;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = 12;
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 5000;
        } else if (layout == 3) {
            builder.cursor->pos.y = -64.0f;
            builder.cursor->pos.x = (float)(terrain_texture_width / 2);
            builder.cursor->template_id = spawn_template_id;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = 12;
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 5000;
        } else if (layout == 4) {
            builder.cursor->pos.y = (float)(crt_rand() % 768 + 128);
            builder.cursor->pos.x = (float)(crt_rand() % 768 + 128);
            builder.cursor->template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = 3;
            ++builder.count;
            ++builder.cursor;

            builder.cursor->pos.y = (float)(crt_rand() % 768 + 128);
            builder.cursor->pos.x = (float)(crt_rand() % 768 + 128);
            builder.cursor->template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07;
            builder.cursor->trigger_time_ms = trigger_time_ms + 1000;
            builder.cursor->count = 3;
            ++builder.count;
            ++builder.cursor;

            builder.cursor->pos.y = (float)(crt_rand() % 768 + 128);
            builder.cursor->pos.x = (float)(crt_rand() % 768 + 128);
            builder.cursor->template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07;
            builder.cursor->trigger_time_ms = trigger_time_ms + 2000;
            builder.cursor->count = 3;
            ++builder.count;
            ++builder.cursor;
            trigger_time_ms += 5000;
        }

        trigger_time_ms += 1000;
        ++wave;
    }

    *count = builder.count;
}
