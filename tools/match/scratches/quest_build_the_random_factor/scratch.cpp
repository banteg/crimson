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
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_the_random_factor(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    for (int trigger_time_ms = 1500;
         trigger_time_ms < 101500;
         trigger_time_ms += 10000) {
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->template_id = SPAWN_ID_ALIEN_RANDOM_1D;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = config_blob.player_count * 2 + 4;

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->template_id = SPAWN_ID_ALIEN_RANDOM_1D;
        spawn->trigger_time_ms = trigger_time_ms + 200;
        spawn->count = 6;

        if (crt_rand() % 5 == 3) {
            spawn = &builder.spawns[builder.count];
            spawn->pos.x = (float)(terrain_texture_width / 2);
            spawn->pos.y = 1088.0f;
            ++builder.count;
            spawn->template_id = SPAWN_ID_ALIEN_BIG_GRAY_29;
            spawn->trigger_time_ms = trigger_time_ms;
            spawn->count = config_blob.player_count;
        }
    }

    *count = builder.count;
}
