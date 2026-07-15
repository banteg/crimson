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

    quest_spawn_builder_t(quest_entry_original_t *spawn_cursor, int spawn_count)
        : cursor(spawn_cursor), count(spawn_count) {}
};

extern "C" void quest_build_8_legged_terror(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *cursor = (quest_entry_original_t *)entries;
    float near_edge = -25.0f;
    int wave_template_id = SPAWN_ID_SPIDER_SP1_RANDOM_3D;
    float far_edge = 1049.0f;

    cursor->pos.x = (float)(terrain_texture_width - 256);
    cursor->pos.y = (float)(terrain_texture_width / 2);
    cursor->template_id = SPAWN_ID_SPIDER_SP1_CONST_SHOCK_BOSS_3A;
    cursor->trigger_time_ms = 1000;
    cursor->count = 1;
    ++cursor;

    quest_spawn_builder_t builder(cursor, 1);
    for (int trigger_time_ms = 6000;
         trigger_time_ms < 36800;
         trigger_time_ms += 2200) {
        ++builder.count;
        builder.cursor->pos.x = near_edge;
        builder.cursor->pos.y = near_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = config_blob.player_count;
        ++builder.cursor;

        ++builder.count;
        builder.cursor->pos.x = far_edge;
        builder.cursor->pos.y = near_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
        ++builder.cursor;

        ++builder.count;
        builder.cursor->pos.x = near_edge;
        builder.cursor->pos.y = far_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = config_blob.player_count;
        ++builder.cursor;

        ++builder.count;
        builder.cursor->pos.x = far_edge;
        builder.cursor->pos.y = far_edge;
        builder.cursor->template_id = wave_template_id;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
        ++builder.cursor;
    }

    *count = builder.count;
}
