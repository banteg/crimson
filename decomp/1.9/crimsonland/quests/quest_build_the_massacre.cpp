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

extern "C" void quest_build_the_massacre(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int wave = 0;
    int trigger_time_ms = 1500;

    while (trigger_time_ms < 0x1656c) {
        int next_wave = wave + 1;
#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer and counts it after
        // its metadata, which frees the stores to schedule ahead of the
        // conversions.
        quest_entry_original_t *spawn = builder.cursor;
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = next_wave + 2;
        ++builder.count;
        ++builder.cursor;
#else
        builder.cursor->pos.x = (float)(terrain_texture_width + 64);
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.cursor->template_id = SPAWN_ID_ZOMBIE_RANDOM_41;
        builder.cursor->trigger_time_ms = trigger_time_ms;
        builder.cursor->count = next_wave + 2;
        ++builder.cursor;
#endif

        if (wave % 2 == 0) {
#if CL_BUILD == 10908
            spawn = builder.cursor;
            spawn->pos.x = (float)(terrain_texture_width + 128);
            spawn->pos.y = (float)(terrain_texture_width / 2);
            spawn->template_id = SPAWN_ID_ALIEN_DEADLY_FAST_2B;
            spawn->trigger_time_ms = trigger_time_ms;
            spawn->count = next_wave;
            ++builder.count;
            ++builder.cursor;
#else
            builder.cursor->pos.x = (float)(terrain_texture_width + 128);
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            ++builder.count;
            builder.cursor->template_id = SPAWN_ID_ALIEN_DEADLY_FAST_2B;
            builder.cursor->trigger_time_ms = trigger_time_ms;
            builder.cursor->count = next_wave;
            ++builder.cursor;
#endif
        }

        trigger_time_ms += 5000;
        wave = next_wave;
    }

    *count = builder.count;
}
