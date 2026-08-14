#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"

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

    void set_trigger(int spawn_trigger_time_ms)
    {
        trigger_time_ms = spawn_trigger_time_ms;
    }
};

extern "C" void quest_build_the_gang_wars(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int spawn_index = 0;

    spawns[spawn_index].pos = quest_vec2_t(
        -150.0f,
        (float)terrain_texture_height * 0.5f);
    spawns[spawn_index].template_id = SPAWN_ID_FORMATION_RING_ALIEN_8_12;
    int one = 1;
    spawns[spawn_index].trigger_time_ms = 100;
    spawns[spawn_index].count = one;
    ++spawn_index;

    spawns[spawn_index].pos = quest_vec2_t(
        1174.0f,
        (float)terrain_texture_height * 0.5f);
    spawns[spawn_index].template_id = SPAWN_ID_FORMATION_RING_ALIEN_8_12;
    spawns[spawn_index].trigger_time_ms = 2500;
    spawns[spawn_index].count = one;
    ++spawn_index;

    int trigger_time_ms = 5500;
    int waves_remaining = 10;
    do {
        spawns[spawn_index].pos = quest_vec2_t(
            1174.0f,
            (float)terrain_texture_height * 0.5f);
        spawns[spawn_index].template_id =
            SPAWN_ID_FORMATION_RING_ALIEN_8_12;
        spawns[spawn_index].trigger_time_ms = trigger_time_ms;
        spawns[spawn_index].count = 2;
        ++spawn_index;
        trigger_time_ms += 4000;
    } while (--waves_remaining != 0);

    spawns[12].pos = quest_vec2_t(512.0f, 1152.0f);
    spawns[12].template_id = SPAWN_ID_FORMATION_CHAIN_ALIEN_10_13;
    spawns[12].set_trigger(50500);
    spawns[12].count = 1;

    spawn_index = 13;
    trigger_time_ms = 59500;
    do {
        spawns[spawn_index].pos = quest_vec2_t(
            -150.0f,
            (float)terrain_texture_height * 0.5f);
        spawns[spawn_index].template_id =
            SPAWN_ID_FORMATION_RING_ALIEN_8_12;
        spawns[spawn_index].trigger_time_ms = trigger_time_ms;
        spawns[spawn_index].count = 2;
        ++spawn_index;
        trigger_time_ms += 4000;
    } while (trigger_time_ms < 0x184AC);

    spawns[23].pos = quest_vec2_t(512.0f, 1152.0f);
    spawns[23].template_id = SPAWN_ID_FORMATION_CHAIN_ALIEN_10_13;
    spawns[23].set_trigger(107500);
    spawns[23].count = 3;

    *count = 24;
}
