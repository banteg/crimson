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

    spawns[0].set(
        quest_vec2_t(256.0f, 256.0f),
        SPAWN_ID_ALIEN_SPAWNER_RING_24_0E,
        2000,
        1);
    spawns[1].set(
        quest_vec2_t(768.0f, 256.0f),
        SPAWN_ID_ALIEN_SPAWNER_RING_24_0E,
        12000,
        1);
    spawns[2].set(
        quest_vec2_t(256.0f, 768.0f),
        SPAWN_ID_ALIEN_SPAWNER_RING_24_0E,
        22000,
        1);
    spawns[3].set(
        quest_vec2_t(768.0f, 768.0f),
        SPAWN_ID_ALIEN_SPAWNER_RING_24_0E,
        32000,
        1);

    *count = 4;
}
