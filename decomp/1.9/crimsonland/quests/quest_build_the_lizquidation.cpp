#include "crimsonland_gameplay.h"

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

    void set_spawn(int spawn_template_id, int time_ms, int spawn_count) {
        metadata.template_id = spawn_template_id;
        metadata.trigger_time_ms = time_ms;
        metadata.count = spawn_count;
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
    int wave = 0;

    for (; wave < 10; ++wave) {
        quest_spawn_metadata_t metadata(
            SPAWN_ID_LIZARD_RANDOM_2E,
            wave * 8000 + 1500,
            wave + 6);
        quest_entry_original_t *spawn = &builder.spawns[builder.count];
        spawn->pos.x = (float)(terrain_texture_width + 64);
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->metadata = metadata;
        ++builder.count;

        spawn = &builder.spawns[builder.count];
        spawn->pos.x = -64.0f;
        spawn->pos.y = (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_LIZARD_RANDOM_2E,
            wave * 8000 + 1500,
            wave + 6);
        ++builder.count;

        if (wave == 4) {
            builder.spawns[builder.count].pos.x =
                (float)(terrain_texture_width + 128);
            builder.spawns[builder.count].pos.y =
                (float)(terrain_texture_width / 2);
            builder.spawns[builder.count].set_spawn(
                SPAWN_ID_ALIEN_DEADLY_FAST_2B, 1500, 2);
            ++builder.count;
        }
    }

    *count = builder.count;
}
