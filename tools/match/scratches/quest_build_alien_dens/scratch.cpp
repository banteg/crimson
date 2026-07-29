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

    spawns[0].pos = quest_vec2_t(256.0f, 256.0f);
    spawns[0].template_id = spawn_template_id;
    spawns[0].trigger_time_ms = trigger_time_ms;
    spawns[0].count = one;

    quest_vec2_t *entry_one_pos = &spawns[1].pos;
    *entry_one_pos = quest_vec2_t(768.0f, 768.0f);
    spawns[1].template_id = spawn_template_id;
    spawns[1].trigger_time_ms = trigger_time_ms;
    spawns[1].count = one;

    quest_vec2_t *entry_two_pos = &spawns[2].pos;
    *entry_two_pos = quest_vec2_t(512.0f, 512.0f);
    spawns[2].template_id = spawn_template_id;
    spawns[2].trigger_time_ms = 23500;
    spawns[2].count = config_blob.player_count;

    trigger_time_ms = 38500;
    quest_entry_original_t *entry_three = &spawns[3];
    entry_three->pos = quest_vec2_t(256.0f, 768.0f);
    entry_three->template_id = spawn_template_id;
    entry_three->trigger_time_ms = trigger_time_ms;
    entry_three->count = one;

    spawns[4].pos = quest_vec2_t(768.0f, 256.0f);
    spawns[4].set_spawn(spawn_template_id, trigger_time_ms, one);

    *count = 5;
}
