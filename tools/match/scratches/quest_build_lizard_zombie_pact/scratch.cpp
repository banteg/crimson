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
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_lizard_zombie_pact(
    quest_spawn_entry_t *entries, int *count)
{
    int wave = 0;
    int trigger_time_ms = 1500;
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    do {
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            6);

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            6);
        ++builder.count;

        if (wave % 5 == 0) {
            int group = wave / 5;
            int y_offset = group * 180;

            spawn = &builder.spawns[builder.count];
            spawn->pos.x = 356.0f;
            spawn->pos.y = (float)(y_offset + 256);
            ++builder.count;
            spawn->set_spawn(
                SPAWN_ID_DEN_LIZARD_WEAK_0C,
                trigger_time_ms,
                group + 1);

            spawn = &builder.spawns[builder.count];
            spawn->pos.x = 356.0f;
            spawn->pos.y = (float)(y_offset + 384);
            ++builder.count;
            spawn->set_spawn(
                SPAWN_ID_DEN_LIZARD_WEAK_0C,
                trigger_time_ms,
                group + 2);
        }

        trigger_time_ms += 7000;
        ++wave;
    } while (trigger_time_ms < 113500);

    *count = builder.count;
}
