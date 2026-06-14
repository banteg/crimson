#include "crimsonland_gameplay.h"

void player_start_reload(void)
{
    if (!player_state_table[render_overlay_player_index].reload_active
        || (perk_count_get(perk_id_ammunition_within) == 0
            && perk_count_get(perk_id_regression_bullets) == 0)) {
        int player_index = render_overlay_player_index;
        if (!player_state_table[render_overlay_player_index].reload_active) {
            int weapon_id = player_state_table[render_overlay_player_index].weapon_id;
            float *pos = &player_state_table[render_overlay_player_index].pos_x;
            sfx_play_panned(weapon_table[weapon_id].reload_sfx_id, pos, 1.0f);
            player_index = render_overlay_player_index;
            player_state_table[render_overlay_player_index].reload_active = 1;
        }

        {
            int perk_id = perk_id_fastloader;
            float reload_time = weapon_table[player_state_table[player_index].weapon_id].reload_time;
            player_state_table[player_index].reload_timer = reload_time;
            if (player_state_table[0].perk_counts[perk_id] > 0) {
                player_state_table[player_index].reload_timer = reload_time * 0.7f;
            }
            if (bonus_weapon_power_up_timer > 0.0f) {
                player_state_table[player_index].reload_timer = player_state_table[player_index].reload_timer * 0.6f;
            }
            player_state_table[player_index].reload_timer_max = player_state_table[player_index].reload_timer;
        }
    }
}
