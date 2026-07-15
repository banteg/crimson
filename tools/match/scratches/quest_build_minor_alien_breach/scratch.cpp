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

extern "C" void quest_build_minor_alien_breach(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos = quest_vec2_t(256.0f, 256.0f);
    spawns[0].template_id = SPAWN_ID_ALIEN_CONST_PALE_GREEN_26;
    int entry_count = 2;
    spawns[0].trigger_time_ms = 1000;
    spawns[0].count = entry_count;

    spawns[1].pos = quest_vec2_t(256.0f, 128.0f);
    spawns[1].template_id = SPAWN_ID_ALIEN_CONST_PALE_GREEN_26;
    spawns[1].trigger_time_ms = 1700;
    spawns[1].count = entry_count;

    int wave = entry_count;
    while (wave <= 17) {
        spawns[entry_count].pos = quest_vec2_t(
            (float)(terrain_texture_width + 64),
            (float)(terrain_texture_height / 2));
        spawns[entry_count].template_id = SPAWN_ID_ALIEN_CONST_PALE_GREEN_26;
        int trigger_time_ms = (wave * 5 - 10) * 720;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;
        ++entry_count;

        if (wave > 6) {
            spawns[entry_count].pos = quest_vec2_t(
                (float)(terrain_texture_width + 64),
                (float)(terrain_texture_height / 2 - 256));
            spawns[entry_count].set_spawn(
                SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                trigger_time_ms,
                1);
            ++entry_count;
        }

        if (wave == 13) {
            spawns[entry_count].pos = quest_vec2_t(
                (float)(terrain_texture_width / 2),
                (float)(terrain_texture_height + 64));
            spawns[entry_count].set_spawn(
                SPAWN_ID_ALIEN_CONST_GREY_BRUTE_29,
                39600,
                1);
            ++entry_count;
        }

        if (wave > 10) {
            spawns[entry_count].pos = quest_vec2_t(
                -64.0f,
                (float)(terrain_texture_height / 2 + 256));
            spawns[entry_count].set_spawn(
                SPAWN_ID_ALIEN_CONST_PALE_GREEN_26,
                trigger_time_ms,
                1);
            ++entry_count;
        }

        ++wave;
    }

    *count = entry_count;
}
