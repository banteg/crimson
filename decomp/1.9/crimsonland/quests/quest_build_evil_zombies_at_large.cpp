#include "crimsonland_gameplay.h"

struct quest_spawn_builder_t {
    quest_spawn_entry_t *cursor;
    int count;

    quest_spawn_builder_t(quest_spawn_entry_t *spawn_entries)
        : cursor(spawn_entries), count(0) {}
};

extern "C" void quest_build_evil_zombies_at_large(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder(entries);
    int spawn_count = 4;
    int trigger_time_ms = 1500;

    while (spawn_count - 4 < 10) {
#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer, which frees the
        // metadata stores to schedule ahead of the float conversions.
        quest_spawn_entry_t *spawn = builder.cursor;
        spawn->pos_x = (float)(terrain_texture_width + 64);
        spawn->pos_y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        spawn = builder.cursor;
        spawn->pos_x = -64.0f;
        spawn->pos_y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        spawn = builder.cursor;
        spawn->pos_x = (float)(terrain_texture_width / 2);
        spawn->pos_y = (float)(terrain_texture_width + 64);
        spawn->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        spawn = builder.cursor;
        spawn->pos_x = (float)(terrain_texture_width / 2);
        spawn->pos_y = -64.0f;
        spawn->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = spawn_count;
#else
        builder.cursor->pos_x = (float)(terrain_texture_width + 64);
        builder.cursor->pos_y = (float)(terrain_texture_width / 2);
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos_x = -64.0f;
        builder.cursor->pos_y = (float)(terrain_texture_width / 2);
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos_x = (float)(terrain_texture_width / 2);
        builder.cursor->pos_y = (float)(terrain_texture_width + 64);
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos_x = (float)(terrain_texture_width / 2);
        builder.cursor->pos_y = -64.0f;
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = spawn_count;
#endif
        ++builder.cursor;
        ++builder.count;

        trigger_time_ms += 5500;
        ++spawn_count;
    }

    *count = builder.count;
}
