#include <math.h>

#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    quest_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    quest_vec2_t operator-(const quest_vec2_t &other) const
    {
        return quest_vec2_t(x - other.x, y - other.y);
    }

    float angle() const
    {
        return (float)atan2(y, x);
    }
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

extern "C" void quest_build_target_practice(
    quest_spawn_entry_t *entries, int *count)
{
    int trigger_time_ms = 2000;
    int trigger_step_ms = 2000;
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    do {
        float angle = (float)(crt_rand() % 612) * 0.01f;
        int radius = (crt_rand() % 8 + 2) * 32;
        quest_vec2_t offset(
            (float)radius * (float)cos(angle),
            (float)radius * (float)sin(angle));

        quest_vec2_t position(
            offset.x + 512.0f,
            offset.y + 512.0f);
        spawns[entry_count].pos = position;
        spawns[entry_count].template_id = SPAWN_ID_ALIEN_AI7_ORBITER_36;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;
        spawns[entry_count].heading =
            (spawns[entry_count].pos - quest_vec2_t(512.0f, 512.0f)).angle()
            - 1.57079637f;
        ++entry_count;

        int trigger_increment_ms = trigger_step_ms;
        if (trigger_increment_ms < 1100) {
            trigger_increment_ms = 1100;
        }
        trigger_step_ms -= 50;
        trigger_time_ms += trigger_increment_ms;
    } while (trigger_step_ms > 500);

    *count = 30;
}
