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
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(-256.0f, 256.0f);
    spawns[entry_count].template_id = SPAWN_ID_FORMATION_RING_ALIEN_8_12;
    spawns[entry_count].trigger_time_ms = 1500;
    spawns[entry_count].count = 1;
    ++entry_count;
    spawns[entry_count].pos = quest_vec2_t(-256.0f, 768.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_RING_ALIEN_8_12, 2500, 1);
    ++entry_count;
    spawns[entry_count].pos = quest_vec2_t(768.0f, -256.0f);
    spawns[entry_count].template_id = SPAWN_ID_FORMATION_RING_ALIEN_8_12;
    spawns[entry_count].trigger_time_ms = 5500;
    spawns[entry_count].count = 1;
    ++entry_count;
    spawns[entry_count].pos = quest_vec2_t(768.0f, 1280.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_RING_ALIEN_8_12, 8500, 1);
    ++entry_count;
    spawns[entry_count].pos = quest_vec2_t(1280.0f, 1280.0f);
    spawns[entry_count].template_id = SPAWN_ID_FORMATION_RING_ALIEN_8_12;
    spawns[entry_count].trigger_time_ms = 14500;
    spawns[entry_count].count = 1;
    ++entry_count;
    spawns[entry_count].pos = quest_vec2_t(1280.0f, 768.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_RING_ALIEN_8_12, 18500, 1);
    ++entry_count;
    spawns[entry_count].pos = quest_vec2_t(-256.0f, 256.0f);
    spawns[entry_count].template_id = SPAWN_ID_FORMATION_RING_ALIEN_8_12;
    spawns[entry_count].trigger_time_ms = 25000;
    spawns[entry_count].count = 1;
    ++entry_count;
    spawns[entry_count].pos = quest_vec2_t(-256.0f, 768.0f);
    spawns[entry_count].set_spawn(
        SPAWN_ID_FORMATION_RING_ALIEN_8_12, 30000, 1);
    ++entry_count;

    int first_wave_entry = entry_count;
    quest_entry_original_t *wave_spawns = &spawns[first_wave_entry];
    int trigger_time_ms = 36200;
    while (trigger_time_ms < 83000) {
        wave_spawns[entry_count - first_wave_entry].pos.x = -64.0f;
        wave_spawns[entry_count - first_wave_entry].pos.y = -64.0f;
        wave_spawns[entry_count - first_wave_entry].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
        wave_spawns[entry_count - first_wave_entry].trigger_time_ms = trigger_time_ms - 400;
        wave_spawns[entry_count++ - first_wave_entry].count = 1;

        wave_spawns[entry_count - first_wave_entry].pos.x = 1088.0f;
        wave_spawns[entry_count - first_wave_entry].pos.y = 1088.0f;
        wave_spawns[entry_count - first_wave_entry].template_id = SPAWN_ID_ALIEN_SMALL_GRAY_26;
        wave_spawns[entry_count - first_wave_entry].trigger_time_ms = trigger_time_ms;
        wave_spawns[entry_count++ - first_wave_entry].count = 1;

        trigger_time_ms += 1800;
    }

    *count = entry_count;
}
