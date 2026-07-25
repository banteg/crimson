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
        int time_ms,
        int spawn_count)
    {
        template_id = spawn_template_id;
        trigger_time_ms = time_ms;
        count = spawn_count;
    }
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
        builder.cursor->pos.x = (float)(terrain_texture_width + 64);
        builder.cursor->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.cursor->set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            next_wave + 2);
        ++builder.cursor;

        if (wave % 2 == 0) {
            builder.cursor->pos.x = (float)(terrain_texture_width + 128);
            builder.cursor->pos.y = (float)(terrain_texture_width / 2);
            ++builder.count;
            builder.cursor->set_spawn(
                SPAWN_ID_ALIEN_CONST_RED_FAST_2B,
                trigger_time_ms,
                next_wave);
            ++builder.cursor;
        }

        trigger_time_ms += 5000;
        wave = next_wave;
    }

    *count = builder.count;
}
