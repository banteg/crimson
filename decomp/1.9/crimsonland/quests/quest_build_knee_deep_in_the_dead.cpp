#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    quest_vec2_t() {}
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
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(
        -50.0f,
        (float)terrain_texture_height * 0.5f);
    spawns[entry_count].template_id = SPAWN_ID_ZOMBIE_CONST_GREEN_BRUTE_43;
    spawns[entry_count].trigger_time_ms = 100;
    spawns[entry_count].count = 1;
    ++entry_count;

    int wave = 0;
    quest_vec2_t normal_position;
    normal_position.x = -50.0f;
    ++spawns;
#if CL_BUILD == 10908
    // 1.9.8 fills each wave record through a record pointer, which frees the
    // metadata stores to schedule ahead of the float conversions.
    quest_entry_original_t *spawn;
#endif
    int trigger_time_ms = 500;
    while (trigger_time_ms < 0x178f4) {
        if (wave % 8 == 0) {
#if CL_BUILD == 10908
            spawn = &spawns[entry_count - 1];
            spawn->pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_CONST_GREEN_BRUTE_43,
                trigger_time_ms - 2,
                1);
#else
            spawns[entry_count - 1].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f);
            spawns[entry_count - 1].set_spawn(
                SPAWN_ID_ZOMBIE_CONST_GREEN_BRUTE_43,
                trigger_time_ms - 2,
                1);
#endif
            ++entry_count;
        }

        int spawn_count = wave > 0x20 ? 2 : 1;
        normal_position.y =
            (float)terrain_texture_height * 0.5f;
#if CL_BUILD == 10908
        spawn = &spawns[entry_count - 1];
        spawn->pos = normal_position;
        spawn->set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            spawn_count);
#else
        spawns[entry_count - 1].pos = normal_position;
        spawns[entry_count - 1].set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            spawn_count);
#endif
        ++entry_count;

        if (trigger_time_ms > 0x30d4) {
#if CL_BUILD == 10908
            spawn = &spawns[entry_count - 1];
            spawn->pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f + 158.0f);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms + 500,
                1);
#else
            spawns[entry_count - 1].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f + 158.0f);
            spawns[entry_count - 1].set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms + 500,
                1);
#endif
            ++entry_count;
        }

        if (trigger_time_ms > 0x5fb4) {
#if CL_BUILD == 10908
            spawn = &spawns[entry_count - 1];
            spawn->pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f - 158.0f);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms + 1000,
                1);
#else
            spawns[entry_count - 1].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f - 158.0f);
            spawns[entry_count - 1].set_spawn(
                SPAWN_ID_ZOMBIE_RANDOM_41,
                trigger_time_ms + 1000,
                1);
#endif
            ++entry_count;
        }

        if (trigger_time_ms > 0x8e94) {
#if CL_BUILD == 10908
            spawn = &spawns[entry_count - 1];
            spawn->pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f - 258.0f);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
                trigger_time_ms + 0x514,
                1);
#else
            spawns[entry_count - 1].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f - 258.0f);
            spawns[entry_count - 1].set_spawn(
                SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
                trigger_time_ms + 0x514,
                1);
#endif
            ++entry_count;
        }

        if (trigger_time_ms > 0xbd74) {
#if CL_BUILD == 10908
            spawn = &spawns[entry_count - 1];
            spawn->pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f + 258.0f);
            spawn->set_spawn(
                SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
                trigger_time_ms + 300,
                1);
#else
            spawns[entry_count - 1].pos = quest_vec2_t(
                -50.0f,
                (float)terrain_texture_height * 0.5f + 258.0f);
            spawns[entry_count - 1].set_spawn(
                SPAWN_ID_ZOMBIE_SMALL_WHITE_42,
                trigger_time_ms + 300,
                1);
#endif
            ++entry_count;
        }

        trigger_time_ms += 0x5dc;
        ++wave;
    }

    *count = entry_count;
}
