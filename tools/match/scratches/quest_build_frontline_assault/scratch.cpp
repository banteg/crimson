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
};

extern "C" void quest_build_frontline_assault(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *cursor = (quest_entry_original_t *)entries;
    int entry_count = 0;
    int trigger_step_ms = 2500;

    for (int wave = 2; wave < 22; ++wave) {
        cursor->pos.x = (float)(terrain_texture_width / 2);
        cursor->pos.y = 1088.0f;
        if (wave <= 4) {
            cursor->template_id = SPAWN_ID_ALIEN_CONST_PALE_GREEN_26;
        } else if (wave < 10) {
            cursor->template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        } else {
            cursor->template_id = SPAWN_ID_ALIEN_CONST_PALE_GREEN_26;
        }
        int trigger_time_ms = wave * trigger_step_ms - 5000;
        cursor->trigger_time_ms = trigger_time_ms;
        cursor->count = 1;
        ++cursor;
        ++entry_count;

        if (wave > 4) {
            cursor->pos.x = -64.0f;
            cursor->pos.y = -64.0f;
            cursor->template_id = SPAWN_ID_ALIEN_CONST_PALE_GREEN_26;
            cursor->trigger_time_ms = trigger_time_ms;
            cursor->count = 1;
            ++entry_count;
            ++cursor;
        }

        if (wave > 10) {
            cursor->pos.x = 1088.0f;
            cursor->pos.y = -64.0f;
            cursor->template_id = SPAWN_ID_ALIEN_CONST_PALE_GREEN_26;
            cursor->trigger_time_ms = trigger_time_ms;
            cursor->count = 1;
            ++entry_count;
            ++cursor;
        }

        if (wave == 10) {
            int burst_trigger_ms = (trigger_step_ms * 5 - 2500) * 2;
            int brute_template_id = SPAWN_ID_ALIEN_CONST_GREY_BRUTE_29;

            cursor->pos.x = 1088.0f;
            cursor->pos.y = 512.0f;
            cursor->template_id = brute_template_id;
            cursor->trigger_time_ms = burst_trigger_ms;
            cursor->count = 1;
            ++cursor;
            ++entry_count;

            cursor->pos.x = -64.0f;
            cursor->pos.y = 512.0f;
            cursor->template_id = brute_template_id;
            cursor->trigger_time_ms = burst_trigger_ms;
            cursor->count = 1;
            ++entry_count;
            ++cursor;
        }

        trigger_step_ms -= 50;
        if (trigger_step_ms < 1800) {
            trigger_step_ms = 1800;
        }
    }

    *count = entry_count;
}
