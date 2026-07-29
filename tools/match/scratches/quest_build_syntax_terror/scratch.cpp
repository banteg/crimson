#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
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

extern "C" void quest_build_syntax_terror(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int entry_count = 0;

    if (config_hardcore != 0) {
        config_blob.player_count += 4;
    }

    int outer_index = 0;
    int trigger_base = 1500;
    int outer_seed = 0x14c9;

    do {
        int inner_index = 0;
        if (config_blob.player_count + 9 > 0) {
            int outer_x_term = outer_seed * outer_index;
            int outer_y_term =
                (outer_index * outer_index * 0x4c + 0x1b) * outer_index;
            int inner_seed = 0x4c5;
            int trigger_time_ms = trigger_base;

            do {
                spawns[entry_count].pos.set(
                    (float)(
                        (((inner_index * inner_index * 0x4c + 0xec) *
                          inner_index + outer_x_term) %
                         0x380) + 0x40),
                    (float)(
                        ((inner_seed * inner_index + outer_y_term) %
                         0x380) + 0x40));
                spawns[entry_count].set_spawn(
                    SPAWN_ID_DEN_ALIEN_BASIC_07,
                    trigger_time_ms,
                    1);
                ++entry_count;
                ++inner_index;

                trigger_time_ms += 300;
                inner_seed += 0x15;
            } while (inner_index < config_blob.player_count + 9);
        }

        ++outer_index;
        outer_seed += 0x35;
        trigger_base += 30000;
    } while (outer_seed < 0x159d);

    if (config_hardcore != 0) {
        config_blob.player_count -= 4;
    }

    *count = entry_count;
}
