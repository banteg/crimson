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

    void set_spawn(int spawn_template_id, int time_ms, int spawn_count) {
        template_id = spawn_template_id;
        trigger_time_ms = time_ms;
        count = spawn_count;
    }
};

struct quest_spawn_builder_t {
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_the_lizquidation(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    for (int wave = 0; wave < 10; ++wave) {
        int spawn_count = wave + 6;
        int trigger_time_ms = wave * 8000 + 1500;
        quest_entry_original_t *spawn = &builder.spawns[builder.count];

        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_LIZARD_RANDOM_2E, trigger_time_ms, spawn_count);

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_LIZARD_RANDOM_2E, trigger_time_ms, spawn_count);

        if (wave == 4) {
            spawn = &builder.spawns[builder.count];
            spawn->pos.x = (float)(terrain_texture_width + 128);
            spawn->pos.y = (float)(terrain_texture_width / 2);
            ++builder.count;
            spawn->set_spawn(
                SPAWN_ID_ALIEN_CONST_RED_FAST_2B, 1500, 2);
        }
    }

    *count = builder.count;
}
