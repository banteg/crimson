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

extern "C" void quest_build_land_of_lizards(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(256.0f, 256.0f);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SPAWNER_RING_24_0E;
    int one = 1;
    spawns[entry_count].trigger_time_ms = 2000;
    spawns[entry_count].count = one;
    quest_vec2_t next_position_1(768.0f, 256.0f);
    ++entry_count;

    spawns[entry_count].pos = next_position_1;
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SPAWNER_RING_24_0E;
    quest_vec2_t next_position_2(256.0f, 768.0f);
    spawns[entry_count].trigger_time_ms = 12000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos = next_position_2;
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_SPAWNER_RING_24_0E;
    quest_vec2_t next_position_3(768.0f, 768.0f);
    spawns[entry_count].trigger_time_ms = 22000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].set(
        next_position_3,
        SPAWN_ID_ALIEN_SPAWNER_RING_24_0E,
        32000,
        one);
    ++entry_count;

    *count = entry_count;
}
