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

extern "C" void quest_build_lizard_raze(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int trigger_time_ms = 1500;
    int wave_count = 6;

    while (trigger_time_ms < 91500) {
        int right_spawn_index = builder.count;
        quest_entry_original_t *spawn = &builder.spawns[right_spawn_index];
        quest_vec2_t *right_spawn_pos = &spawn->pos;
        right_spawn_pos->x = (float)(terrain_texture_width + 64);
        right_spawn_pos->y = (float)(terrain_texture_width / 2);
        ++builder.count;
        builder.spawns[right_spawn_index].set_spawn(
            SPAWN_ID_LIZARD_RANDOM_2E, trigger_time_ms, wave_count);

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
    }

    int spawner_template_id = SPAWN_ID_DEN_LIZARD_WEAK_0C;
    int spawner_trigger_time_ms = 10000;
    int one = 1;

    quest_entry_original_t *spawn = &builder.spawns[builder.count];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 256.0f;
    spawn->set_spawn(spawner_template_id, spawner_trigger_time_ms, one);
    ++builder.count;

    spawn = &builder.spawns[builder.count];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 384.0f;
    spawn->set_spawn(spawner_template_id, spawner_trigger_time_ms, one);
    ++builder.count;

    int final_spawn_index = builder.count;
    builder.spawns[final_spawn_index].pos.x = 128.0f;
    builder.spawns[final_spawn_index].pos.y = 512.0f;
    builder.spawns[final_spawn_index].template_id = spawner_template_id;
    builder.spawns[final_spawn_index].trigger_time_ms =
        spawner_trigger_time_ms;
    builder.spawns[final_spawn_index].count = one;
    ++builder.count;

    *count = builder.count;
}
