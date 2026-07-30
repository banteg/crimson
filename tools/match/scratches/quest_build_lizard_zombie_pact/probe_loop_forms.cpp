#include "crimsonland_gameplay.h"

#ifndef CRIMSON_LIZARD_LOOP_FORM
#define CRIMSON_LIZARD_LOOP_FORM 0
#endif

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
#if CRIMSON_LIZARD_LOOP_FORM == 0
    int wave = 0;
    int trigger_time_ms = 1500;
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    do {
#elif CRIMSON_LIZARD_LOOP_FORM == 1
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    int wave;
    int trigger_time_ms;
    for (wave = 0, trigger_time_ms = 1500;
         trigger_time_ms < 113500;
         trigger_time_ms += 7000, ++wave) {
#elif CRIMSON_LIZARD_LOOP_FORM == 2
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    for (int wave = 0, trigger_time_ms = 1500;
         trigger_time_ms < 113500;
         trigger_time_ms += 7000, ++wave) {
#elif CRIMSON_LIZARD_LOOP_FORM == 3
    int wave = 0;
    int trigger_time_ms = 1500;
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    while (trigger_time_ms < 113500) {
#elif CRIMSON_LIZARD_LOOP_FORM == 4
    int trigger_time_ms = 1500;
    int wave = 0;
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    while (trigger_time_ms < 113500) {
#elif CRIMSON_LIZARD_LOOP_FORM == 5
    int trigger_time_ms = 1500;
    quest_spawn_builder_t builder((quest_entry_original_t *)entries);
    for (int wave = 0;
         trigger_time_ms < 113500;
         ++wave, trigger_time_ms += 7000) {
#else
#error Unsupported CRIMSON_LIZARD_LOOP_FORM
#endif
        builder.spawns[builder.count].pos.x =
            (float)(terrain_texture_width + 64);
        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            6);
        ++builder.count;

        builder.spawns[builder.count].pos.x = -64.0f;
        builder.spawns[builder.count].pos.y =
            (float)(terrain_texture_width / 2);
        builder.spawns[builder.count].set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            6);
        ++builder.count;

        if (wave % 5 == 0) {
            int group = wave / 5;
            int y_offset = group * 180;

            builder.spawns[builder.count].pos.x = 356.0f;
            builder.spawns[builder.count].pos.y =
                (float)(y_offset + 256);
            builder.spawns[builder.count].set_spawn(
                SPAWN_ID_DEN_LIZARD_WEAK_0C,
                trigger_time_ms,
                group + 1);
            ++builder.count;

            builder.spawns[builder.count].pos.x = 356.0f;
            builder.spawns[builder.count].pos.y =
                (float)(y_offset + 384);
            builder.spawns[builder.count].set_spawn(
                SPAWN_ID_DEN_LIZARD_WEAK_0C,
                trigger_time_ms,
                group + 2);
            ++builder.count;
        }

#if CRIMSON_LIZARD_LOOP_FORM == 0 || \
    CRIMSON_LIZARD_LOOP_FORM == 3 || \
    CRIMSON_LIZARD_LOOP_FORM == 4
        trigger_time_ms += 7000;
        ++wave;
#endif
#if CRIMSON_LIZARD_LOOP_FORM == 0
    } while (trigger_time_ms < 113500);
#else
    }
#endif

    *count = builder.count;
}
