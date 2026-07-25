#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    quest_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}
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

extern "C" void quest_build_knee_deep_in_the_dead(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos = quest_vec2_t(
        -50.0f,
        (float)terrain_texture_height * 0.5f);
    int entry_count = 1;
    spawns[0].set_spawn(
        SPAWN_ID_ZOMBIE_CONST_GREEN_BRUTE_43,
        100,
        entry_count);

    int wave = 0;
    int trigger_time_ms = 500;
    while (trigger_time_ms < 0x178f4) {
        if (wave % 8 == 0) {
            spawns[entry_count].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f);
            spawns[entry_count].set_spawn(
                SPAWN_ID_ZOMBIE_CONST_GREEN_BRUTE_43,
                trigger_time_ms - 2,
                1);
            ++entry_count;
        }

        int spawn_count = wave > 0x20 ? 2 : 1;
        spawns[entry_count].pos = quest_vec2_t(
            -50.0f,
            (float)terrain_texture_height * 0.5f);
        spawns[entry_count].set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            spawn_count);
        ++entry_count;

        if (trigger_time_ms > 0x30d4) {
            spawns[entry_count].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f + 158.0f);
            spawns[entry_count].set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms + 500,
                1);
            ++entry_count;
        }

        if (trigger_time_ms > 0x5fb4) {
            spawns[entry_count].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f - 158.0f);
            spawns[entry_count].set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms + 1000,
                1);
            ++entry_count;
        }

        if (trigger_time_ms > 0x8e94) {
            spawns[entry_count].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f - 258.0f);
            spawns[entry_count].set_spawn(
                SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
                trigger_time_ms + 0x514,
                1);
            ++entry_count;
        }

        if (trigger_time_ms > 0xbd74) {
            spawns[entry_count].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f + 258.0f);
            spawns[entry_count].set_spawn(
                SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
                trigger_time_ms + 300,
                1);
            ++entry_count;
        }

        trigger_time_ms += 0x5dc;
        ++wave;
    }

    *count = entry_count;
}
