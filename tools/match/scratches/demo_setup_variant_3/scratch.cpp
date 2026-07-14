#include "crimsonland_gameplay.h"

extern "C" int demo_time_limit_ms;
extern "C" void terrain_generate(quest_meta_t *quest);
extern "C" void *creature_spawn_template(int template_id, float *pos, float heading);

extern "C" void demo_setup_variant_3(void)
{
    config_blob.player_count = 1;
    terrain_generate(&quest_selected_meta[0]);
    demo_time_limit_ms = 4000;

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
        creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_24, large_pos, 0.0f);

        if (index % 3 != 0) {
            small_x = (float)(crt_rand() % 30 + 32);
            small_y = (float)(crt_rand() % 899 + 64);
            small_pos[0] = small_x;
            small_pos[1] = small_y;
            creature_spawn_template(SPAWN_ID_ALIEN_CONST_GREEN_SMALL_25, small_pos, 0.0f);
        }
    }

    vec2f_t player_pos;
    player_pos.x = 512.0f;
    player_pos.y = 512.0f;
    *(vec2f_t *)&player_state_table[0].pos_x = player_pos;
    weapon_assign_player(0, 18);
}
