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

extern "C" void quest_build_the_gang_wars(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;

    spawns[0].pos = quest_vec2_t(
        -150.0f,
        (float)terrain_texture_height * 0.5f);
    spawns[0].set_spawn(
        SPAWN_ID_FORMATION_RING_ALIEN_8_12,
        100,
        1);

    spawns[1].pos = quest_vec2_t(
        1174.0f,
        (float)terrain_texture_height * 0.5f);
    spawns[1].set_spawn(
        SPAWN_ID_FORMATION_RING_ALIEN_8_12,
        2500,
        1);

    int spawn_index = 2;
    int trigger_time_ms = 5500;
    int waves_remaining = 10;
    do {
        spawns[spawn_index].pos = quest_vec2_t(
            1174.0f,
            (float)terrain_texture_height * 0.5f);
        spawns[spawn_index].set_spawn(
            SPAWN_ID_FORMATION_RING_ALIEN_8_12,
            trigger_time_ms,
            2);
        ++spawn_index;
        trigger_time_ms += 4000;
    } while (--waves_remaining != 0);

    spawns[12].pos = quest_vec2_t(512.0f, 1152.0f);
    spawns[12].set_spawn(
        SPAWN_ID_FORMATION_CHAIN_ALIEN_10_13,
        50500,
        1);

    spawn_index = 13;
    trigger_time_ms = 59500;
    do {
        spawns[spawn_index].pos = quest_vec2_t(
            -150.0f,
            (float)terrain_texture_height * 0.5f);
        spawns[spawn_index].set_spawn(
            SPAWN_ID_FORMATION_RING_ALIEN_8_12,
            trigger_time_ms,
            2);
        ++spawn_index;
        trigger_time_ms += 4000;
    } while (trigger_time_ms < 0x184AC);

    spawns[23].pos = quest_vec2_t(512.0f, 1152.0f);
    spawns[23].set_spawn(
        SPAWN_ID_FORMATION_CHAIN_ALIEN_10_13,
        107500,
        3);

    *count = 24;
}
