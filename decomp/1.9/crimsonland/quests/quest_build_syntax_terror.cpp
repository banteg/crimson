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

    for (int outer_index = 0; outer_index < 4; ++outer_index) {
        int outer_seed = outer_index * 0x35 + 0x14c9;
        int trigger_base = outer_index * 30000 + 1500;
        int inner_index = 0;
        if (config_blob.player_count + 9 > 0) {
            int outer_x_term = outer_seed * outer_index;
            int outer_y_term =
                (outer_index * outer_index * 0x4c + 0x1b) * outer_index;
            int inner_seed = 0x4c5;
            int trigger_time_ms = trigger_base;

            do {
#if CL_BUILD == 10908
                // 1.9.8 fills the record through a record pointer, which frees
                // the metadata stores to schedule ahead of the coordinate
                // math.
                quest_entry_original_t *spawn = &spawns[entry_count];
                spawn->pos.set(
                    (float)(
                        (((inner_index * inner_index * 0x4c + 0xec) *
                          inner_index + outer_x_term) %
                         0x380) + 0x40),
                    (float)(
                        ((inner_seed * inner_index + outer_y_term) %
                         0x380) + 0x40));
                spawn->set_spawn(
                    SPAWN_ID_DEN_ALIEN_BASIC_07,
                    trigger_time_ms,
                    1);
#else
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
#endif
                ++entry_count;
                ++inner_index;

                trigger_time_ms += 300;
                inner_seed += 0x15;
            } while (inner_index < config_blob.player_count + 9);
        }

    }

    if (config_hardcore != 0) {
        config_blob.player_count -= 4;
    }

    *count = entry_count;
}
