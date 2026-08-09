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

    void set_position_and_template(
        const quest_vec2_t &position,
        int spawn_template_id)
    {
        pos = position;
        template_id = spawn_template_id;
    }

};

extern "C" void quest_build_land_hostile(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(
        (float)(terrain_texture_width / 2),
        (float)(terrain_texture_height + 64));
    int *first_trigger = &spawns[entry_count].trigger_time_ms;
    first_trigger[-1] = SPAWN_ID_ALIEN_SMALL_GRAY_26;
    first_trigger[0] = 500;
    first_trigger[1] = 1;
    ++entry_count;

    spawns[entry_count].set(
        quest_vec2_t(-64.0f, 1088.0f),
        SPAWN_ID_ALIEN_SMALL_GRAY_26,
        2500,
        2);
    ++entry_count;

    spawns[entry_count].set_position_and_template(
        quest_vec2_t(-64.0f, -64.0f),
        SPAWN_ID_ALIEN_SMALL_GRAY_26);
    spawns[entry_count].trigger_time_ms = 6500;
    spawns[entry_count].count = 3;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(1088.0f, -64.0f);
    int *fourth_trigger = &spawns[entry_count].trigger_time_ms;
    fourth_trigger[-1] = SPAWN_ID_ALIEN_SMALL_GRAY_26;
    fourth_trigger[0] = 11500;
    fourth_trigger[1] = 4;
    ++entry_count;

    *count = entry_count;
}
