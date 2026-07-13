#include <string.h>

#include "crimsonland_gameplay.h"

void player_reset_all(void)
{
    if (cv_verbose->value != 0.0f) {
        console_printf(&console_log_queue, "- Reseting players.\n");
    }

    render_overlay_player_index = 0;
    do {
        int player_index = render_overlay_player_index;
        player_state_t *player = &player_state_table[player_index];
        vec2f_t center;

        center.x = (float)terrain_texture_width * 0.5f;
        center.y = (float)terrain_texture_height * 0.5f;

        player_reset_reserved_zero = 0;
        player->speed_bonus_timer = 0.0f;
        player->shield_timer = 0.0f;
        player->state_aux = 0;
        player_plaguebearer_active[player_index * sizeof(player_state_t)] = 0;
        player->pos_x = center.x;
        player->pos_y = center.y;
        player->health = 100.0f;

        if (player_index % 2 == 0) {
            float offset = (float)(player_index * 0x50);
            player->pos_x = offset + player->pos_x;
            player->pos_y = (float)(player_index * 0x50) + player->pos_y;
        } else {
            float offset = (float)(player_index * 0x50);
            player->pos_x = player->pos_x - offset;
            player->pos_y = player->pos_y - (float)(player_index * 0x50);
        }

        player_index = render_overlay_player_index;
        {
            int alt_reload_time;
            char demo_active;

            player_state_table[player_index].size = 48.0f;
            player_state_table[player_index].speed_multiplier = 2.0f;
            player_state_table[player_index].level = 1;
            player_state_table[player_index].heading = 0.0f;
            player_state_table[player_index].experience = 0;
            player_state_table[player_index].reset_reserved_b0 = 0;
            player_state_table[player_index].spread_heat = 0.0f;
            player_state_table[player_index].move_speed = 0.0f;
            player_state_table[player_index].ammo = 10.0f;
            player_state_table[player_index].clip_size = 10.0f;
            player_state_table[player_index].reload_timer_max = 1.0f;
            player_state_table[player_index].reload_timer = 0.0f;
            player_state_table[player_index].alt_weapon_id = 1;
            player_state_table[player_index].alt_clip_size = (float)weapon_table[1].clip_size;
            player_state_table[player_index].alt_reload_active = 0;
            player_state_table[player_index].alt_ammo = player_state_table[player_index].alt_clip_size;
            alt_reload_time = *(int *)&weapon_table[1].reload_time;
            player_state_table[player_index].alt_reload_timer = 0.0f;
            player_state_table[player_index].alt_shot_cooldown = 0.0f;
            *(int *)&player_state_table[player_index].alt_reload_timer_max = alt_reload_time;
            demo_active = demo_mode_active;
            player_state_table[player_index].shot_cooldown = 0.8f;
            player_state_table[player_index].weapon_id = 1;
            player_state_table[player_index].reset_reserved_zero = 0;
            player_state_table[player_index].death_timer = 16.0f;

            if (!demo_active) {
                vec2f_t mouse_pos;
                mouse_pos.x = 320.0f;
                mouse_pos.y = 140.0f;
                ui_mouse_x = mouse_pos.x;
                ui_mouse_y = mouse_pos.y;
            }
        }

        memset(
            player_state_table[player_index].perk_counts,
            0,
            sizeof(player_state_table[player_index].perk_counts));

        {
            unsigned char *collision_flag = &creature_pool[0].collision_flag;
            do {
                *collision_flag = 0;
                collision_flag += sizeof(creature_t);
            } while ((int)collision_flag < (int)&creature_pool[0x180].collision_flag);
        }

        render_overlay_player_index += 1;
    } while (render_overlay_player_index < 2);

    render_overlay_player_index = 0;
}
