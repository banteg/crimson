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

extern "C" void quest_build_lizard_zombie_pact(
    quest_spawn_entry_t *entries, int *count)
{
    int wave = 0;
    int trigger_time_ms = 1500;
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    do {
        spawns[entry_count].pos.x =
            (float)(terrain_texture_width + 64);
        spawns[entry_count].pos.y =
            (float)(terrain_texture_width / 2);
        spawns[entry_count].set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            6);
        ++entry_count;

        spawns[entry_count].pos.x = -64.0f;
        spawns[entry_count].pos.y =
            (float)(terrain_texture_width / 2);
        spawns[entry_count].set_spawn(
            SPAWN_ID_ZOMBIE_RANDOM_41,
            trigger_time_ms,
            6);
        ++entry_count;

        if (wave % 5 == 0) {
            int group = wave / 5;
            int y_offset = group * 180;

            spawns[entry_count].pos.x = 356.0f;
            spawns[entry_count].pos.y =
                (float)(y_offset + 256);
            spawns[entry_count].set_spawn(
                SPAWN_ID_DEN_LIZARD_WEAK_0C,
                trigger_time_ms,
                group + 1);
            ++entry_count;

            spawns[entry_count].pos.x = 356.0f;
            spawns[entry_count].pos.y =
                (float)(y_offset + 384);
            spawns[entry_count].set_spawn(
                SPAWN_ID_DEN_LIZARD_WEAK_0C,
                trigger_time_ms,
                group + 2);
            ++entry_count;
        }

        trigger_time_ms += 7000;
        ++wave;
    } while (trigger_time_ms < 113500);

    *count = entry_count;
}
