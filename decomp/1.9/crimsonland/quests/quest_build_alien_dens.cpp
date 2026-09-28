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

extern "C" void quest_build_alien_dens(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int spawn_template_id = SPAWN_ID_DEN_ALIEN_BASIC_SLOWER_08;
    int one = 1;
    int trigger_time_ms = 1500;
    int entry_count = 0;

    spawns[entry_count].pos = quest_vec2_t(256.0f, 256.0f);
    spawns[entry_count].template_id = spawn_template_id;
    spawns[entry_count].trigger_time_ms = trigger_time_ms;
    spawns[entry_count].count = one;
    ++entry_count;

    quest_vec2_t *entry_one_pos = &spawns[entry_count].pos;
    *entry_one_pos = quest_vec2_t(768.0f, 768.0f);
    spawns[entry_count].template_id = spawn_template_id;
    spawns[entry_count].trigger_time_ms = trigger_time_ms;
    spawns[entry_count].count = one;
    ++entry_count;

    quest_vec2_t *entry_two_pos = &spawns[entry_count].pos;
    *entry_two_pos = quest_vec2_t(512.0f, 512.0f);
    spawns[entry_count].template_id = spawn_template_id;
    spawns[entry_count].trigger_time_ms = 23500;
    spawns[entry_count].count = config_blob.player_count;
    ++entry_count;

    trigger_time_ms = 38500;
    quest_entry_original_t *entry_three = &spawns[entry_count];
    entry_three->pos = quest_vec2_t(256.0f, 768.0f);
    entry_three->template_id = spawn_template_id;
    entry_three->trigger_time_ms = trigger_time_ms;
    entry_three->count = one;
    ++entry_count;

    spawns[entry_count].pos = quest_vec2_t(768.0f, 256.0f);
    spawns[entry_count].set_spawn(spawn_template_id, trigger_time_ms, one);
    ++entry_count;

    *count = entry_count;
}
