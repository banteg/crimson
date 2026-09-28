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

extern "C" void quest_build_the_fortress(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(
        -50.0f,
        (float)terrain_texture_height * 0.5f);
    int y_seed = 0x200;
    spawns[entry_count].set_spawn(
        SPAWN_ID_SPIDER_SMALL_BLUE_40,
        100,
        6);
    ++entry_count;

    int trigger_time_ms = 1100;
    while (trigger_time_ms < 0x14B4) {
        spawns[entry_count].pos = quest_vec2_t(
            768.0f,
            (float)y_seed * 0.125f + 256.0f);
        spawns[entry_count].template_id =
            SPAWN_ID_DEN_ALIEN_WEAK_SMALL_09;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;
        ++entry_count;
        trigger_time_ms += 600;
        y_seed += 0x200;
    }

    spawns[entry_count].pos = quest_vec2_t(128.0f, 512.0f);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SPAWNER_RING_24_0E;
    spawns[entry_count].trigger_time_ms = 6500;
    spawns[entry_count].count = 1;
    int x_seed = 0x180;
    while (x_seed <= 0x900) {
        trigger_time_ms = entry_count * 600 + 0x157C;
        int row = 1;
        int *grid_trigger = &spawns[entry_count].trigger_time_ms;
        while (row <= 6) {
            if (row != 1 || (x_seed != 0x480 && x_seed != 0x600)) {
                quest_entry_original_t *grid_entry =
                    (quest_entry_original_t *)(grid_trigger - 4);
                grid_entry->pos = quest_vec2_t(
                    (float)x_seed * 0.166666672f + 256.0f,
                    512.0f - (float)(row * 0x180) * 0.166666672f);
                ++entry_count;
                int *grid_template = grid_trigger - 1;
                *grid_template = SPAWN_ID_DEN_SPIDER_BASIC_0A;
                grid_trigger[0] = trigger_time_ms;
                grid_trigger[1] = 1;
                trigger_time_ms += 600;
                grid_trigger += 6;
            }
            ++row;
        }
        x_seed += 0x180;
    }

    *count = entry_count;
}
