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

extern "C" void quest_build_hidden_evil(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[0].set_spawn(
        SPAWN_ID_ALIEN_HIDDEN_1_21,
        500,
        50);

    spawns[1].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[1].set_spawn(
        SPAWN_ID_ALIEN_HIDDEN_2_22,
        15000,
        30);

    spawns[2].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[2].set_spawn(
        SPAWN_ID_ALIEN_HIDDEN_3_23,
        25000,
        20);

    spawns[3].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[3].set_spawn(
        SPAWN_ID_ALIEN_HIDDEN_3_23,
        30000,
        30);

    spawns[4].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    spawns[4].set_spawn(
        SPAWN_ID_ALIEN_HIDDEN_2_22,
        35000,
        30);

    *count = 5;
}
