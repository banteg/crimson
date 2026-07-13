#include "crimsonland_gameplay.h"

void weapon_assign_player(int player_index, int weapon_id)
{
    int original_weapon_id = weapon_id;
    if (!demo_mode_active) {
        ++weapon_usage_counts[weapon_id];
    }

    player_state_table[player_index].weapon_id = weapon_id;
    player_state_table[player_index].clip_size = (float)weapon_table[weapon_id].clip_size;

    if (perk_count_get(perk_id_ammo_maniac) != 0) {
        int extra_ammo = (int)(player_state_table[player_index].clip_size * 0.25f);
        if (extra_ammo <= 1) {
            extra_ammo = 1;
        }
        player_state_table[player_index].clip_size += (float)extra_ammo;
    }

    if (perk_count_get(perk_id_my_favourite_weapon) != 0) {
        player_state_table[player_index].clip_size += 2.0f;
    }

    {
        float *player_pos = &player_state_table[player_index].pos_x;
        int reload_sfx_id = weapon_table[original_weapon_id].reload_sfx_id;
        player_state_table[player_index].ammo = player_state_table[player_index].clip_size;
        player_state_table[player_index].weapon_reset_latch = 0;
        player_state_table[player_index].shot_cooldown = 0.0f;
        player_state_table[player_index].reload_timer = 0.0f;
        player_aux_timer[player_index] = 2.0f;
        sfx_play_panned(reload_sfx_id, player_pos, 1.0f);
    }
}
