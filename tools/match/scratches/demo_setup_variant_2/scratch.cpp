#include "crimsonland_gameplay.h"

extern "C" int demo_time_limit_ms;

extern "C" void demo_setup_variant_2(void)
{
    int y;
    config_blob.player_count = 1;
    demo_time_limit_ms = 5000;

    int row = 0;
    y = 128;
    for (; y < 848; ++row, y += 60) {
        int side = row % 2;
        float row_y;

        vec2f_t pos_0;
        pos_0.x = (float)(side * 64 + 32);
        pos_0.y = row_y = (float)y;
        creature_spawn_template(SPAWN_ID_ZOMBIE_RANDOM_41, &pos_0, -100.0f);

        vec2f_t pos_1;
        pos_1.x = (float)((side + 2) * 64);
        pos_1.y = row_y;
        creature_spawn_template(SPAWN_ID_ZOMBIE_RANDOM_41, &pos_1, -100.0f);

        vec2f_t pos_2;
        pos_2.x = (float)(side * 64 - 64);
        pos_2.y = row_y;
        creature_spawn_template(SPAWN_ID_ZOMBIE_RANDOM_41, &pos_2, -100.0f);

        vec2f_t pos_3;
        pos_3.x = (float)((side + 12) * 64);
        pos_3.y = row_y;
        creature_spawn_template(SPAWN_ID_ZOMBIE_RANDOM_41, &pos_3, -100.0f);

    }

    weapon_assign_player(0, 21);
}
