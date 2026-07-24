#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" unsigned char console_open_flag;
extern "C" int config_player_count;
extern "C" int frame_dt_ms;
extern "C" int survival_spawn_cooldown;
extern "C" int quest_spawn_timeline;
extern "C" int demo_time_limit_ms;

extern "C" int creature_spawn(
    const vec2f_t *pos,
    const effect_color_t *color,
    int type_id);
extern "C" void demo_mode_start(void);

extern "C" void rush_mode_update(void)
{
    player_state_table[0].weapon_id = WEAPON_ID_ASSAULT_RIFLE;
    player_state_table[0].ammo = 30.0f;
    player_state_table[1].weapon_id = WEAPON_ID_ASSAULT_RIFLE;
    player_state_table[1].ammo = 30.0f;

    if (console_open_flag) {
        return;
    }

    survival_spawn_cooldown -= frame_dt_ms * config_player_count;
    while (survival_spawn_cooldown < 0) {
        survival_spawn_cooldown += 250;

        int tint_time = survival_elapsed_ms + 1;
        float elapsed = (float)tint_time;
        effect_color_t tint;
        tint.a = 1.0f;
        tint.r = elapsed * 0.00000833333343f + 0.3f;
        tint.g = elapsed * 10000.0f + 0.3f;
        tint.b = (float)sin(elapsed * 0.000100000005f) + 0.3f;

        if (tint.r < 0.0f) {
            tint.r = 0.0f;
        } else if (tint.r > 1.0f) {
            tint.r = 1.0f;
        }
        if (tint.g < 0.0f) {
            tint.g = 0.0f;
        } else if (tint.g > 1.0f) {
            tint.g = 1.0f;
        }
        if (tint.b < 0.0f) {
            tint.b = 0.0f;
        } else if (tint.b > 1.0f) {
            tint.b = 1.0f;
        }

        vec2f_t right;
        right.x = (float)terrain_texture_width + 64.0f;
        right.y = (float)cos((float)survival_elapsed_ms * 0.001f)
            * 256.0f
            + (float)terrain_texture_height * 0.5f;
        int creature_id = creature_spawn(
            &right,
            &tint,
            CREATURE_TYPE_ALIEN
        );
        creature_pool[creature_id].ai_mode = CREATURE_AI_ORBIT_PLAYER_WIDE;

        vec2f_t left;
        left.x = -64.0f;
        left.y = (float)sin((float)survival_elapsed_ms * 0.001f)
            * 256.0f
            + (float)terrain_texture_height * 0.5f;
        creature_id = creature_spawn(
            &left,
            &tint,
            CREATURE_TYPE_SPIDER_SP1
        );
        creature_pool[creature_id].ai_mode = CREATURE_AI_ORBIT_PLAYER_WIDE;
        creature_pool[creature_id].flags |= CREATURE_FLAG_AI7_LINK_TIMER;
        creature_pool[creature_id].move_speed *= 1.4f;
    }

    if (demo_mode_active && quest_spawn_timeline > demo_time_limit_ms) {
        render_pass_mode = 0;
        demo_mode_start();
    }
}
