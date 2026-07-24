#include "crimsonland_gameplay.h"

extern "C" int demo_time_limit_ms;

extern "C" void demo_setup_variant_0(void)
{
    int y;
    config_blob.player_count = 2;
    demo_time_limit_ms = 4000;

    int row = 0;
    y = 256;
    for (; y < 1696; ++row, y += 80) {
        int side = row % 2;
        float row_y;

        vec2f_t left_pos;
        left_pos.x = (float)((side + 2) * 64);
        left_pos.y = row_y = (float)y;
        creature_spawn_template(SPAWN_ID_SPIDER_SP1_AI7_TIMER_38, &left_pos.x, -100.0f);

        vec2f_t right_pos;
        right_pos.x = (float)(side * 64 + 798);
        right_pos.y = row_y;
        creature_spawn_template(SPAWN_ID_SPIDER_SP1_AI7_TIMER_38, &right_pos.x, -100.0f);
    }

    vec2f_t player_0_pos;
    player_0_pos.x = 448.0f;
    player_0_pos.y = 384.0f;
    *(vec2f_t *)&player_state_table[0].pos_x = player_0_pos;

    vec2f_t player_1_pos;
    player_1_pos.x = 546.0f;
    player_1_pos.y = 654.0f;
    *(vec2f_t *)&player_state_table[1].pos_x = player_1_pos;
    weapon_assign_player(0, 11);
    weapon_assign_player(1, 11);
}
