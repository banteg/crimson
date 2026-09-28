#include "crimsonland_gameplay.h"

struct quest_spawn_builder_t {
    quest_spawn_entry_t *cursor;
    int count;

    quest_spawn_builder_t(quest_spawn_entry_t *spawn_entries)
        : cursor(spawn_entries), count(0) {}
};

extern "C" void quest_build_frontline_assault(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder(entries);
    int trigger_step_ms = 2500;

    for (int wave = 2; wave < 22; ++wave) {
        builder.cursor->pos_x = (float)(terrain_texture_width / 2);
        builder.cursor->pos_y = 1088.0f;
        if (wave <= 4) {
            builder.cursor->template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
        } else if (wave >= 10) {
            builder.cursor->template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
        } else {
            builder.cursor->template_id =
                SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        }
        builder.cursor->trigger_time_ms =
            wave * trigger_step_ms - 5000;
        builder.cursor->count = 1;
        ++builder.cursor;
        ++builder.count;

        if (wave > 4) {
            builder.cursor->pos_x = -64.0f;
            builder.cursor->pos_y = -64.0f;
            builder.cursor->template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
            builder.cursor->trigger_time_ms =
                wave * trigger_step_ms - 5000;
            builder.cursor->count = 1;
            ++builder.count;
            ++builder.cursor;
        }

        if (wave > 10) {
            builder.cursor->pos_x = 1088.0f;
            builder.cursor->pos_y = -64.0f;
            builder.cursor->template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
            builder.cursor->trigger_time_ms =
                wave * trigger_step_ms - 5000;
            builder.cursor->count = 1;
            ++builder.count;
            ++builder.cursor;
        }

        if (wave == 10) {
            int burst_trigger_ms = (trigger_step_ms * 5 - 2500) * 2;
            int big_gray_template_id = SPAWN_ID_ALIEN_BIG_GRAY_29;

            builder.cursor->pos_x = 1088.0f;
            builder.cursor->pos_y = 512.0f;
            builder.cursor->template_id = big_gray_template_id;
            builder.cursor->trigger_time_ms = burst_trigger_ms;
            builder.cursor->count = 1;
            ++builder.cursor;
            ++builder.count;

            builder.cursor->pos_x = -64.0f;
            builder.cursor->pos_y = 512.0f;
            builder.cursor->template_id = big_gray_template_id;
            builder.cursor->trigger_time_ms = burst_trigger_ms;
            builder.cursor->count = 1;
            ++builder.count;
            ++builder.cursor;
        }

        trigger_step_ms -= 50;
        if (trigger_step_ms < 1800) {
            trigger_step_ms = 1800;
        }
    }

    *count = builder.count;
}
