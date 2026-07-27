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
    int *wave_trigger =
        &((quest_entry_original_t *)entries)->trigger_time_ms;
    int trigger_time_ms = 2000;

    for (int trigger_step_ms = 2000;
         trigger_step_ms > 560;
         trigger_step_ms -= 80) {
        float angle = (float)(crt_rand() % 612) * 0.01f;
        float angle_cos = (float)cos(angle);
        float angle_sin = (float)sin(angle);
        int *entry_trigger = wave_trigger;
        wave_trigger += 24;

        for (int radius = 84; radius < 252; radius += 42) {
            quest_vec2_t offset(
                (float)radius * angle_cos,
                (float)radius * angle_sin);
            quest_entry_original_t *wave_entry =
                (quest_entry_original_t *)(entry_trigger - 4);
            wave_entry->set(
                quest_vec2_t(
                    offset.x + 512.0f,
                    offset.y + 512.0f),
                SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D,
                trigger_time_ms,
                1);
            entry_trigger += 6;
        }

        trigger_time_ms += trigger_step_ms;
    }

    *count = 72;
}
