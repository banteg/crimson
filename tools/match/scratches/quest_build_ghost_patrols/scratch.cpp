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

    spawns[0].pos.x = (float)(terrain_texture_width + 128);
    spawns[0].pos.y = (float)(terrain_texture_width / 2);
    spawns[0].set_spawn(
        SPAWN_ID_ALIEN_DEADLY_FAST_2B,
        1500,
        2);

    int trigger_time_ms = 2500;
    int wave = 0;

    do {
        quest_entry_original_t *spawn = &spawns[wave + 1];
        if (wave % 2 == 0) {
            spawn->pos.x = -128.0f;
        } else {
            spawn->pos.x = 1152.0f;
        }
        spawn->pos.y = (float)(terrain_texture_width / 2);
        spawn->set_spawn(
            SPAWN_ID_FORMATION_RING_ALIEN_5_19,
            trigger_time_ms,
            one);

        ++wave;
        trigger_time_ms += 2500;
    } while (trigger_time_ms < 32500);

    spawns[13].pos.x = -264.0f;
    spawns[13].pos.y = (float)(terrain_texture_width / 2);
    spawns[13].set_spawn(
        SPAWN_ID_ALIEN_DEADLY_FAST_2B,
        (wave - 1) * 2500,
        one);

    spawns[14].pos.x = -128.0f;
    spawns[14].pos.y = (float)(terrain_texture_width / 2);
    spawns[14].set_spawn(
        SPAWN_ID_FORMATION_GRID_ALIEN_BRONZE_18,
        (wave * 5 + 15) * 500,
        one);

    *count = 15;
}
