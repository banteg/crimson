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

extern "C" void quest_build_evil_zombies_at_large(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int spawn_count = 4;
    int trigger_time_ms = 1500;

    while (spawn_count - 4 < 10) {
        builder.cursor->pos.x = (float)(terrain_texture_width + 64);
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos.x = -64.0f;
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos.x = (float)(terrain_texture_width / 2);
        builder.cursor->pos.y = (float)(terrain_texture_width + 64);
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos.x = (float)(terrain_texture_width / 2);
        builder.cursor->pos.y = -64.0f;
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        trigger_time_ms += 5500;
        ++spawn_count;
    }

    *count = builder.count;
}
