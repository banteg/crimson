#include "crimsonland_gameplay.h"

struct quest_spawn_builder_t {
    quest_spawn_entry_t *cursor;
    int count;

    quest_spawn_builder_t(quest_spawn_entry_t *spawn_cursor, int spawn_count)
        : cursor(spawn_cursor), count(spawn_count) {}
};

extern "C" void quest_build_8_legged_terror(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_entry_t *cursor = entries;
    float near_edge = -25.0f;
    int wave_template_id = SPAWN_ID_SPIDER_SP1_RANDOM_3D;
    float far_edge = 1049.0f;

    cursor->pos_x = (float)(terrain_texture_width - 256);
    cursor->pos_y = (float)(terrain_texture_width / 2);
    quest_spawn_entry_t *opening = cursor++;
    quest_spawn_builder_t builder(cursor, 1);
    opening->template_id = SPAWN_ID_SPIDER_BOSS_3A;
    opening->trigger_time_ms = 1000;
    opening->count = 1;
    for (int trigger_time_ms = 6000;
         trigger_time_ms < 36800;
         trigger_time_ms += 2200) {
        ++builder.count;
        builder.cursor->pos_x = near_edge;
        builder.cursor->pos_y = near_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = config_blob.player_count;
        ++builder.cursor;

        ++builder.count;
        builder.cursor->pos_x = far_edge;
        builder.cursor->pos_y = near_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
        ++builder.cursor;

        ++builder.count;
        builder.cursor->pos_x = near_edge;
        builder.cursor->pos_y = far_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = config_blob.player_count;
        ++builder.cursor;

        ++builder.count;
        builder.cursor->pos_x = far_edge;
        builder.cursor->pos_y = far_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
        ++builder.cursor;
    }

    *count = builder.count;
}
