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

extern "C" void quest_build_the_annihilation(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int trigger_time_ms = 500;

    spawns[0].pos.x = 128.0f;
    spawns[0].pos.y = (float)(terrain_texture_width / 2);
    int index = 0;
    int y_offset = 0;
    quest_entry_original_t *spawn = &spawns[1];
    spawns[0].template_id = SPAWN_ID_ALIEN_CONST_RED_FAST_2B;
    spawns[0].trigger_time_ms = trigger_time_ms;
    spawns[0].count = 2;

    do {
        spawn->pos.y = (float)(y_offset / 12 + 128);
        if ((index & 1) != 0) {
            spawn->pos.x = 896.0f;
        } else {
            spawn->pos.x = 832.0f;
        }
        spawn->set_spawn(
            SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);

        trigger_time_ms += 500;
        y_offset += 768;
        ++spawn;
        ++index;
    } while (index < 12);

    index = 0;
    y_offset = 0;
    trigger_time_ms = 45000;
    spawn = &spawns[13];
    do {
        spawn->pos.y = (float)(y_offset / 12 + 128);
        if ((index & 1) != 0) {
            spawn->pos.x = 832.0f;
        } else {
            spawn->pos.x = 896.0f;
        }
        spawn->set_spawn(
            SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_time_ms,
            1);

        ++spawn;
        trigger_time_ms += 300;
        ++index;
        y_offset += 768;
    } while (trigger_time_ms < 48600);

    *count = 25;
}
