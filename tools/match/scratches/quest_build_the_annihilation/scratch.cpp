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
    int entry_count = 0;
    int trigger_time_ms = 500;

    spawns[entry_count].pos.x = 128.0f;
    spawns[entry_count].pos.y =
        (float)(terrain_texture_width / 2);
    int index = 0;
    int y_offset = 0;
    spawns[entry_count].set_spawn(
        SPAWN_ID_ALIEN_DEADLY_FAST_2B,
        trigger_time_ms,
        2);
    ++entry_count;

    do {
        quest_entry_original_t *spawn = &spawns[entry_count];
        spawn->pos.y = (float)(y_offset / 12 + 128);
        if ((index & 1) != 0) {
            spawn->pos.x = 896.0f;
        } else {
            spawn->pos.x = 832.0f;
        }
        spawn->set_spawn(
            SPAWN_ID_DEN_ALIEN_BASIC_07,
            trigger_time_ms,
            1);

        trigger_time_ms += 500;
        y_offset += 768;
        ++entry_count;
        ++index;
    } while (index < 12);

    index = 0;
    y_offset = 0;
    trigger_time_ms = 45000;
    do {
        quest_entry_original_t *spawn = &spawns[entry_count];
        spawn->pos.y = (float)(y_offset / 12 + 128);
        if ((index & 1) != 0) {
            spawn->pos.x = 832.0f;
        } else {
            spawn->pos.x = 896.0f;
        }
        spawn->set_spawn(
            SPAWN_ID_DEN_ALIEN_BASIC_07,
            trigger_time_ms,
            1);

        ++entry_count;
        trigger_time_ms += 300;
        ++index;
        y_offset += 768;
    } while (trigger_time_ms < 48600);

    *count = 25;
}
