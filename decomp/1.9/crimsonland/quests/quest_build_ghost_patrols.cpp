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

extern "C" void quest_build_ghost_patrols(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int one = 1;
    int entry_count = 0;

    spawns[entry_count].pos.x = (float)(terrain_texture_width + 128);
    spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
    spawns[entry_count].set_spawn(
        SPAWN_ID_ALIEN_DEADLY_FAST_2B,
        1500,
        2);
    ++entry_count;

    int trigger_time_ms = 2500;
    int wave = 0;

    do {
        if (wave % 2 == 0) {
            spawns[entry_count].pos.x = -128.0f;
        } else {
            spawns[entry_count].pos.x = 1152.0f;
        }
        spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
        spawns[entry_count].set_spawn(
            SPAWN_ID_FORMATION_RING_ALIEN_5_19,
            trigger_time_ms,
            one);

        ++entry_count;
        ++wave;
        trigger_time_ms += 2500;
    } while (trigger_time_ms < 32500);

    spawns[entry_count].pos.x = -264.0f;
    spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_DEADLY_FAST_2B;
    spawns[entry_count].trigger_time_ms = (wave - 1) * 2500;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.x = -128.0f;
    spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
    spawns[entry_count].template_id = SPAWN_ID_FORMATION_GRID_ALIEN_BRONZE_18;
    spawns[entry_count].trigger_time_ms = (wave * 5 + 15) * 500;
    spawns[entry_count].count = one;

    *count = 15;
}
