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
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_LIZARD_RANDOM_2E, trigger_time_ms, wave_count);

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        ++builder.count;
        spawn->set_spawn(
            SPAWN_ID_LIZARD_RANDOM_2E, trigger_time_ms, wave_count);

        trigger_time_ms += 6000;
    }

    int spawner_template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_31_FAST_0C;
    int spawner_trigger_time_ms = 10000;
    int one = 1;

    quest_entry_original_t *spawn = &builder.spawns[builder.count++];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 256.0f;
    spawn->set_spawn(spawner_template_id, spawner_trigger_time_ms, one);

    spawn = &builder.spawns[builder.count++];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 384.0f;
    spawn->set_spawn(spawner_template_id, spawner_trigger_time_ms, one);

    spawn = &builder.spawns[builder.count++];
    spawn->pos.x = 128.0f;
    spawn->pos.y = 512.0f;
    spawn->set_spawn(spawner_template_id, spawner_trigger_time_ms, one);

    *count = builder.count;
}
