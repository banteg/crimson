#include "crimsonland_gameplay.h"

struct quest_spawn_builder_t {
    quest_spawn_entry_t *cursor;
    int count;

    quest_spawn_builder_t(quest_spawn_entry_t *spawn_entries)
        : cursor(spawn_entries), count(0) {}
};

extern "C" void quest_build_surrounded_by_reptiles(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_entry_t *spawns = entries;
    quest_spawn_builder_t builder(spawns);
    int line_offset = 0;
    int trigger_time_ms;

    for (trigger_time_ms = 1000;
         trigger_time_ms < 5000;
        trigger_time_ms += 800) {
        float axis = (float)line_offset * 0.2f + 256.0f;

#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer, which frees the
        // metadata stores to schedule ahead of the float conversions.
        quest_spawn_entry_t *spawn = builder.cursor;
        spawn->pos_x = 256.0f;
        spawn->pos_y = axis;
        spawn->template_id = SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
        ++builder.cursor;
        ++builder.count;

        spawn = builder.cursor;
        spawn->pos_x = 768.0f;
        spawn->pos_y = axis;
        spawn->template_id = SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
#else
        builder.cursor->pos_x = 256.0f;
        builder.cursor->pos_y = axis;
        builder.cursor->template_id =
            SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos_x = 768.0f;
        builder.cursor->pos_y = axis;
        builder.cursor->template_id =
            SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
#endif
        ++builder.count;
        ++builder.cursor;
        line_offset += 512;
    }

    line_offset = 0;
    builder.cursor = &spawns[builder.count];
    for (trigger_time_ms = 8000;
         trigger_time_ms < 12000;
        trigger_time_ms += 800) {
        float axis = (float)line_offset * 0.2f + 256.0f;

#if CL_BUILD == 10908
        quest_spawn_entry_t *spawn = builder.cursor;
        spawn->pos_y = 256.0f;
        spawn->pos_x = axis;
        spawn->template_id = SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
        ++builder.cursor;
        ++builder.count;

        spawn = builder.cursor;
        spawn->pos_y = 768.0f;
        spawn->pos_x = axis;
        spawn->template_id = SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = 1;
#else
        builder.cursor->pos_y = 256.0f;
        builder.cursor->pos_x = axis;
        builder.cursor->template_id =
            SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
        ++builder.cursor;
        ++builder.count;

        builder.cursor->pos_y = 768.0f;
        builder.cursor->pos_x = axis;
        builder.cursor->template_id =
            SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = 1;
#endif
        ++builder.count;
        ++builder.cursor;
        line_offset += 512;
    }

    *count = builder.count;
}
