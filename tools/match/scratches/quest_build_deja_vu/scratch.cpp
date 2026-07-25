#include <math.h>

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

extern "C" void quest_build_deja_vu(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *cursor = (quest_entry_original_t *)entries;
    int trigger_time_ms = 2000;

    for (int trigger_step_ms = 2000;
         trigger_step_ms > 560;
         trigger_step_ms -= 80) {
        float angle = (float)(crt_rand() % 612) * 0.01f;
        float angle_cos = (float)cos(angle);
        float angle_sin = (float)sin(angle);
        quest_entry_original_t *wave_entry = cursor;
        cursor += 4;

        for (int radius = 84; radius < 252; radius += 42) {
            quest_vec2_t offset(
                (float)radius * angle_cos,
                (float)radius * angle_sin);
            wave_entry->set(
                quest_vec2_t(
                    offset.x + 512.0f,
                    offset.y + 512.0f),
                SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D,
                trigger_time_ms,
                1);
            ++wave_entry;
        }

        trigger_time_ms += trigger_step_ms;
    }

    *count = 72;
}
