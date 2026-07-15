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

extern "C" void quest_build_alien_dens(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int spawn_template_id = SPAWN_ID_ALIEN_SPAWNER_CHILD_1D_SLOW_08;
    int one = 1;
    int trigger_time_ms = 1500;

    spawns[0].pos = quest_vec2_t(256.0f, 256.0f);
    spawns[0].template_id = spawn_template_id;
    spawns[0].trigger_time_ms = trigger_time_ms;
    spawns[0].count = one;

    spawns[1].pos = quest_vec2_t(768.0f, 768.0f);
    spawns[1].template_id = spawn_template_id;
    spawns[1].trigger_time_ms = trigger_time_ms;
    spawns[1].count = one;

    spawns[2].pos = quest_vec2_t(512.0f, 512.0f);
    spawns[2].template_id = spawn_template_id;
    spawns[2].trigger_time_ms = 23500;
    spawns[2].count = config_blob.player_count;

    trigger_time_ms = 38500;
    spawns[3].pos = quest_vec2_t(256.0f, 768.0f);
    spawns[3].template_id = spawn_template_id;
    spawns[3].trigger_time_ms = trigger_time_ms;
    spawns[3].count = one;

    spawns[4].pos = quest_vec2_t(768.0f, 256.0f);
    spawns[4].template_id = spawn_template_id;
    spawns[4].trigger_time_ms = trigger_time_ms;
    spawns[4].count = one;

    *count = 5;
}
