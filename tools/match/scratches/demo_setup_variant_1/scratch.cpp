#include "crimsonland_gameplay.h"

extern "C" int demo_time_limit_ms;
extern "C" void terrain_generate(quest_meta_t *quest);

extern "C" void demo_setup_variant_1(void)
{
    config_blob.player_count = 2;
    terrain_generate(&quest_selected_meta[11]);
    demo_time_limit_ms = 5000;

    float large_x;
    float large_y;
    float large_pos[2];
    float small_x;
    float small_y;
    float small_pos[2];
    for (int index = 0; index < 20; ++index) {
        large_x = (float)(crt_rand() % 200 + 32);
        large_y = (float)(crt_rand() % 899 + 64);
        large_pos[0] = large_x;
        large_pos[1] = large_y;
        creature_spawn_template(
            SPAWN_ID_SPIDER_SP1_RANDOM_GREEN_34,
            (const vec2f_t *)large_pos,
            -100.0f);

        if (index % 3 != 0) {
            small_x = (float)(crt_rand() % 30 + 32);
            small_y = (float)(crt_rand() % 899 + 64);
            small_pos[0] = small_x;
            small_pos[1] = small_y;
            creature_spawn_template(
                SPAWN_ID_SPIDER_SP2_RANDOM_35,
                (const vec2f_t *)small_pos,
                -100.0f);
        }
    }

    vec2f_t player_0_pos;
    player_0_pos.x = 490.0f;
    player_0_pos.y = 448.0f;
    player_state_table[0].position = player_0_pos;

    vec2f_t player_1_pos;
    player_1_pos.x = 480.0f;
    player_1_pos.y = 576.0f;
    player_state_table[1].position = player_1_pos;

    weapon_assign_player(0, 5);
    weapon_assign_player(1, 5);
    bonus_weapon_power_up_timer = 15.0f;
}
