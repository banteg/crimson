#include "crimsonland_gameplay.h"

void weapon_assign_player(int player_index, int weapon_id)
{
    int original_weapon_id = weapon_id;
    if (!demo_mode_active) {
        ++weapon_usage_counts[weapon_id];
    }

    player_state_table[player_index].weapon_id = weapon_id;
    {
        int perk_id = perk_id_ammo_maniac;
        player_state_table[player_index].clip_size = (float)weapon_table[weapon_id].clip_size;

        if (perk_count_get(perk_id) != 0) {
            weapon_id = (int)(player_state_table[player_index].clip_size * 0.25f);
            if (weapon_id <= 1) {
                weapon_id = 1;
            }
            player_state_table[player_index].clip_size += (float)weapon_id;
        }

        perk_id = perk_id_my_favourite_weapon;
        if (perk_count_get(perk_id) != 0) {
            player_state_table[player_index].clip_size += 2.0f;
        }
    }

    {
        float *player_pos = &player_state_table[player_index].pos_x;
        int reload_sfx_id = weapon_table[original_weapon_id].reload_sfx_id;
        float ammo = player_state_table[player_index].clip_size;
        player_state_table[player_index].ammo = ammo;
        player_state_table[player_index].weapon_reset_latch = 0;
        player_state_table[player_index].shot_cooldown = 0.0f;
        player_state_table[player_index].reload_timer = 0.0f;
        player_aux_timer[player_index] = 2.0f;
        sfx_play_panned(reload_sfx_id, player_pos, 1.0f);
    }
}
