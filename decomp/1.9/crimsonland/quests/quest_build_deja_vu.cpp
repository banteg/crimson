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
};

extern "C" void quest_build_deja_vu(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;
    int trigger_time_ms = 2000;
    int trigger_step_ms = 2000;

    while (trigger_step_ms > 560) {
        float angle = (float)(crt_rand() % 612) * 0.01f;
        float angle_cos = (float)cos(angle);
        float angle_sin = (float)sin(angle);

        for (int radius = 84; radius < 252; radius += 42) {
            quest_vec2_t offset(
                (float)radius * angle_cos,
                (float)(radius * angle_sin));
            spawns[entry_count].pos = quest_vec2_t(
                offset.x + 512.0f,
                offset.y + 512.0f);
            spawns[entry_count].template_id = SPAWN_ID_DEN_LIZARD_WEAK_SLOWER_0D;
            spawns[entry_count].trigger_time_ms = trigger_time_ms;
            spawns[entry_count].count = 1;
            ++entry_count;
        }

        trigger_time_ms += trigger_step_ms;
        trigger_step_ms -= 80;
    }

    *count = entry_count;
}
