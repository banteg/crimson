#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"

struct quest_vec2_t {
    float x;
    float y;
};

struct quest_spawn_metadata_t {
    int template_id;
    int trigger_time_ms;
    int count;
    quest_spawn_metadata_t(int type, int time, int amount)
        : template_id(type), trigger_time_ms(time), count(amount) {}
    quest_spawn_metadata_t &operator=(const quest_spawn_metadata_t &other) {
        template_id = other.template_id;
        trigger_time_ms = other.trigger_time_ms;
        count = other.count;
        return *this;
    }
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    quest_spawn_metadata_t metadata;

    void set_spawn(
        int spawn_template_id,
        int spawn_trigger_time_ms,
        int spawn_count)
    {
        metadata.template_id = spawn_template_id;
        metadata.trigger_time_ms = spawn_trigger_time_ms;
        metadata.count = spawn_count;
    }
};

struct quest_spawn_builder_t {
    quest_entry_original_t *spawns;
    int count;

    quest_spawn_builder_t(quest_entry_original_t *spawn_entries)
        : spawns(spawn_entries), count(0) {}
};

extern "C" void quest_build_spiders_inc(
    quest_spawn_entry_t *entries, int *count)
{
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);

    builder.spawns[builder.count].pos.y =
        (float)(terrain_texture_width + 64);
    builder.spawns[builder.count].pos.x =
        (float)(terrain_texture_width / 2);
    builder.spawns[builder.count].metadata.template_id =
        SPAWN_ID_SPIDER_SP1_STOP_AND_GO_38;
    builder.spawns[builder.count].metadata.trigger_time_ms = 500;
    builder.spawns[builder.count].metadata.count = 1;
    ++builder.count;

    builder.spawns[builder.count].pos.y =
        (float)(terrain_texture_width + 64);
    builder.spawns[builder.count].pos.x =
        (float)(terrain_texture_width / 2 + 64);
    builder.spawns[builder.count].set_spawn(
        SPAWN_ID_SPIDER_SP1_STOP_AND_GO_38,
        500,
        1);
    ++builder.count;

    builder.spawns[builder.count].pos.y = -64.0f;
    builder.spawns[builder.count].pos.x =
        (float)(terrain_texture_width / 2);
    builder.spawns[builder.count].metadata.template_id = SPAWN_ID_SPIDER_SMALL_BLUE_40;
    builder.spawns[builder.count].metadata.trigger_time_ms = 500;
    builder.spawns[builder.count].metadata.count = 4;
    ++builder.count;

    for (int trigger_time_ms = 17000, step_count = 0;
         trigger_time_ms < 107000;
         ++step_count, trigger_time_ms += 6000) {
        quest_spawn_metadata_t wave(SPAWN_ID_SPIDER_SP1_STOP_AND_GO_38, trigger_time_ms, step_count / 2 + 3);
        quest_entry_original_t *wave_spawn =
            &builder.spawns[builder.count];

        wave_spawn->pos.y = (float)(terrain_texture_width + 64);
        wave_spawn->pos.x = (float)(terrain_texture_width / 2);
        wave_spawn->metadata = wave;
        ++builder.count;

        quest_entry_original_t *second_wave_spawn =
            &builder.spawns[builder.count];
        second_wave_spawn->pos.y = -64.0f;
        second_wave_spawn->pos.x = (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_SPIDER_SP1_STOP_AND_GO_38,
            trigger_time_ms,
            step_count / 2 + 3);
        ++builder.count;
    }

    *count = builder.count;
}
