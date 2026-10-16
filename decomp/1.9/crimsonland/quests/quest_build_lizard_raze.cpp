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

extern "C" void quest_build_lizard_raze(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int trigger_time_ms = 1500;
    int wave_count = 6;

    while (trigger_time_ms < 91500) {
#if CL_BUILD == 10908
        // 1.9.8 fills each record through a record pointer and counts it after
        // its metadata; 1.9.93 is built from the shape in #else.
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_LIZARD_RANDOM_2E;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = wave_count;
        ++builder.count;

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->template_id = SPAWN_ID_LIZARD_RANDOM_2E;
        spawn->trigger_time_ms = trigger_time_ms;
        spawn->count = wave_count;
        ++builder.count;
        trigger_time_ms += 6000;
#else
        int right_spawn_index = builder.count;
        quest_entry_original_t *spawn = &builder.spawns[right_spawn_index];
        quest_vec2_t *right_spawn_pos = &spawn->pos;
        right_spawn_pos->x = (float)(terrain_texture_width + 64);
        right_spawn_pos->y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.spawns[right_spawn_index].template_id =
            SPAWN_ID_LIZARD_RANDOM_2E;
        builder.spawns[right_spawn_index].trigger_time_ms = trigger_time_ms;
        builder.spawns[right_spawn_index].count = wave_count;

        int left_spawn_index = builder.count;
        spawn = &builder.spawns[left_spawn_index];
        quest_vec2_t *left_spawn_pos = &spawn->pos;
        left_spawn_pos->x = -64.0f;
        left_spawn_pos->y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.spawns[left_spawn_index].template_id =
            SPAWN_ID_LIZARD_RANDOM_2E;
        builder.spawns[left_spawn_index].trigger_time_ms = trigger_time_ms;
        trigger_time_ms += 6000;
        builder.spawns[left_spawn_index].count = wave_count;
#endif
    }

    int spawner_template_id = SPAWN_ID_DEN_LIZARD_WEAK_0C;
    int spawner_trigger_time_ms = 10000;
    int one = 1;

    quest_entry_original_t *spawn = &builder.spawns[builder.count];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 256.0f;
    spawn->template_id = spawner_template_id;
    spawn->trigger_time_ms = spawner_trigger_time_ms;
    spawn->count = one;
    ++builder.count;

    spawn = &builder.spawns[builder.count];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 384.0f;
    spawn->template_id = spawner_template_id;
    spawn->trigger_time_ms = spawner_trigger_time_ms;
    spawn->count = one;
    ++builder.count;

#if CL_BUILD == 10908
    spawn = &builder.spawns[builder.count];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 512.0f;
    spawn->template_id = spawner_template_id;
    spawn->trigger_time_ms = spawner_trigger_time_ms;
    spawn->count = one;
#else
    int final_spawn_index = builder.count;
    builder.spawns[final_spawn_index].pos.x = 128.0f;
    builder.spawns[final_spawn_index].pos.y = 512.0f;
    builder.spawns[final_spawn_index].template_id = spawner_template_id;
    builder.spawns[final_spawn_index].trigger_time_ms =
        spawner_trigger_time_ms;
    builder.spawns[final_spawn_index].count = one;
#endif
    ++builder.count;

    *count = builder.count;
}
