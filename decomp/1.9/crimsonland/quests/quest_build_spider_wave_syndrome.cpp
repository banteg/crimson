#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    void set(float x_value, float y_value) {
        x = x_value;
        y = y_value;
    }
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;

    void set_spawn(int spawn_template_id, int time_ms) {
        template_id = spawn_template_id;
        trigger_time_ms = time_ms;
    }

};

struct quest_spawn_builder_t {
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}

};

extern "C" void quest_build_spider_wave_syndrome(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    for (int trigger_time_ms = 1500;
         trigger_time_ms < 100500;
         trigger_time_ms += 5500) {
#if CL_BUILD == 10908
        // 1.9.8 publishes the wave through a record pointer, which frees the
        // metadata stores to schedule ahead of the y conversion.
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y =
            (float)(terrain_texture_width / 2);
        spawn->set_spawn(
            SPAWN_ID_SPIDER_SMALL_BLUE_40,
            trigger_time_ms);
        spawn->count =
            config_blob.player_count * 2 + 6;
#else
        builder.spawns[builder.count].pos.x = -64.0f;
        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_SPIDER_SMALL_BLUE_40,
            trigger_time_ms);
        builder.spawns[builder.count].count =
            config_blob.player_count * 2 + 6;
#endif
        ++builder.count;
    }
    *count = builder.count;
}
