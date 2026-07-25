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

extern "C" void quest_build_alien_squads(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos = quest_vec2_t(-256.0f, 256.0f);
    spawns[0].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 1500, 1);
    spawns[1].pos = quest_vec2_t(-256.0f, 768.0f);
    spawns[1].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 2500, 1);
    spawns[2].pos = quest_vec2_t(768.0f, -256.0f);
    spawns[2].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 5500, 1);
    spawns[3].pos = quest_vec2_t(768.0f, 1280.0f);
    spawns[3].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 8500, 1);
    spawns[4].pos = quest_vec2_t(1280.0f, 1280.0f);
    spawns[4].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 14500, 1);
    spawns[5].pos = quest_vec2_t(1280.0f, 768.0f);
    spawns[5].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 18500, 1);
    spawns[6].pos = quest_vec2_t(-256.0f, 256.0f);
    spawns[6].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 25000, 1);
    spawns[7].pos = quest_vec2_t(-256.0f, 768.0f);
    spawns[7].set_spawn(SPAWN_ID_FORMATION_RING_ALIEN_8_12, 30000, 1);

    int entry_count = 8;
    int trigger_time_ms = 36200;
    while (trigger_time_ms < 83000) {
        spawns[entry_count].pos.x = -64.0f;
        spawns[entry_count].pos.y = -64.0f;
        spawns[entry_count].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
        spawns[entry_count].trigger_time_ms = trigger_time_ms - 400;
        spawns[entry_count].count = 1;
        ++entry_count;

        spawns[entry_count].pos.x = 1088.0f;
        spawns[entry_count].pos.y = 1088.0f;
        spawns[entry_count].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
        spawns[entry_count].trigger_time_ms = trigger_time_ms;
        spawns[entry_count].count = 1;
        ++entry_count;

        trigger_time_ms += 1800;
    }

    *count = entry_count;
}
