#include "crimsonland_gameplay.h"

struct quest_vec2_t {
    float x;
    float y;
};

struct quest_entry_original_t {
    quest_vec2_t pos;
    float heading;
    int template_id;
    int trigger_time_ms;
    int count;
};

extern "C" void quest_build_the_blighting(
    quest_spawn_entry_t *entries, int *count)
{
    quest_entry_original_t *spawns = (quest_entry_original_t *)entries;
    int spawn_template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
    int entry_count = 0;

    spawns[entry_count].pos.x = (float)(terrain_texture_width + 128);
    spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_DEADLY_FAST_2B;
    spawns[entry_count].trigger_time_ms = 1500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos.x = -128.0f;
    spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
    spawns[entry_count].template_id = SPAWN_ID_ALIEN_DEADLY_FAST_2B;
    spawns[entry_count].trigger_time_ms = 1500;
    spawns[entry_count].count = 2;
    ++entry_count;

    spawns[entry_count].pos.y = 128.0f;
    spawns[entry_count].pos.x = 896.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
    int one = 1;
    spawns[entry_count].trigger_time_ms = 2000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.y = 128.0f;
    spawns[entry_count].pos.x = 128.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
    spawns[entry_count].trigger_time_ms = 2000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.y = 896.0f;
    spawns[entry_count].pos.x = 128.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
    spawns[entry_count].trigger_time_ms = 2000;
    spawns[entry_count].count = one;
    ++entry_count;

    spawns[entry_count].pos.y = 896.0f;
    spawns[entry_count].pos.x = 896.0f;
    spawns[entry_count].template_id = SPAWN_ID_DEN_ALIEN_BASIC_07;
    spawns[entry_count].trigger_time_ms = 2000;
    spawns[entry_count].count = one;
    ++entry_count;

    int trigger_time_ms = 4000;
    int wave = 0;
    while (wave < 8) {
        int parity = wave % 2;

        if (wave == 2 || wave == 4) {
            spawns[entry_count].pos.x = -128.0f;
            spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
            spawns[entry_count].template_id = SPAWN_ID_ALIEN_DEADLY_FAST_2B;
            spawns[entry_count].trigger_time_ms = trigger_time_ms;
            spawns[entry_count].count = 4;
            ++entry_count;
        }

        if (wave == 3 || wave == 5) {
            spawns[entry_count].pos.x = 1152.0f;
            spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
            spawns[entry_count].template_id = SPAWN_ID_ALIEN_DEADLY_FAST_2B;
            spawns[entry_count].trigger_time_ms = trigger_time_ms;
            spawns[entry_count].count = 4;
            ++entry_count;
        }

        if (parity == 0) {
            spawn_template_id = SPAWN_ID_AI1_ALIEN_BLUE_TINT_1A;
        } else if (parity == 1) {
            spawn_template_id = SPAWN_ID_AI1_LIZARD_BLUE_TINT_1C;
        }

        int layout = wave % 5;
        if (layout == 0) {
            spawns[entry_count].pos.x = (float)(terrain_texture_width + 64);
            spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
            spawns[entry_count].template_id = spawn_template_id;
            spawns[entry_count].trigger_time_ms = trigger_time_ms;
            spawns[entry_count].count = 12;
            ++entry_count;
            trigger_time_ms += 15000;
        } else if (layout == 1) {
            spawns[entry_count].pos.x = -64.0f;
            spawns[entry_count].pos.y = (float)(terrain_texture_width / 2);
            spawns[entry_count].template_id = spawn_template_id;
            spawns[entry_count].trigger_time_ms = trigger_time_ms;
            spawns[entry_count].count = 12;
            ++entry_count;
            trigger_time_ms += 15000;
        } else if (layout == 2) {
            spawns[entry_count].pos.y = (float)(terrain_texture_width + 64);
            spawns[entry_count].pos.x = (float)(terrain_texture_width / 2);
            spawns[entry_count].template_id = spawn_template_id;
            spawns[entry_count].trigger_time_ms = trigger_time_ms;
            spawns[entry_count].count = 12;
            ++entry_count;
            trigger_time_ms += 15000;
        } else if (layout == 3) {
            spawns[entry_count].pos.y = -64.0f;
            spawns[entry_count].pos.x = (float)(terrain_texture_width / 2);
            spawns[entry_count].template_id = spawn_template_id;
            spawns[entry_count].trigger_time_ms = trigger_time_ms;
            spawns[entry_count].count = 12;
            ++entry_count;
            trigger_time_ms += 15000;
        }

        trigger_time_ms += 1000;
        ++wave;
    }

    *count = entry_count;
}
