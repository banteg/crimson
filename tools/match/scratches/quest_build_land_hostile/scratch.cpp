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

    void set(
        const quest_vec2_t &position,
        int spawn_template_id,
        int spawn_trigger_time_ms,
        int spawn_count)
    {
        pos = position;
        template_id = spawn_template_id;
        trigger_time_ms = spawn_trigger_time_ms;
        count = spawn_count;
    }
};

extern "C" void quest_build_land_hostile(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].set(
        quest_vec2_t(
            (float)(terrain_texture_width / 2),
            (float)(terrain_texture_height + 64)),
        SPAWN_ID_ALIEN_SMALL_GRAY_26,
        500,
        1);
    spawns[1].set(
        quest_vec2_t(-64.0f, 1088.0f),
        SPAWN_ID_ALIEN_SMALL_GRAY_26,
        2500,
        2);
    spawns[2].set(
        quest_vec2_t(-64.0f, -64.0f),
        SPAWN_ID_ALIEN_SMALL_GRAY_26,
        6500,
        3);
    spawns[3].set(
        quest_vec2_t(1088.0f, -64.0f),
        SPAWN_ID_ALIEN_SMALL_GRAY_26,
        11500,
        4);

    *count = 4;
}
