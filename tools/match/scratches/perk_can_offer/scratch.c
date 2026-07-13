#include "crimsonland_gameplay.h"

unsigned char perk_can_offer(int perk_index)
{
    game_mode_id_t game_mode = config_blob.game_mode;

    if (
        game_mode == GAME_MODE_QUEST && config_blob.hardcore && quest_stage_minor == 10
        && quest_stage_major == 2
        && (
            perk_index == perk_id_poison_bullets || perk_index == perk_id_veins_of_poison
            || perk_index == perk_id_plaguebearer
        )
    ) {
        return 0;
    }

    if (config_blob.player_count == 2 && (perk_meta_table[perk_index].flags & 2) == 0) {
        return 0;
    }
    if (game_mode == GAME_MODE_QUEST && (perk_meta_table[perk_index].flags & 1) == 0) {
        return 0;
    }

    {
        int prerequisite = perk_meta_table[perk_index].prerequisite;
        if (prerequisite == -1) {
            return 1;
        }
        if (player_state_table[0].perk_counts[prerequisite] > 0) {
            return 1;
        }

        if (
            !(unsigned char)game_is_full_version() && perk_index != perk_id_living_fortress
            && perk_index != perk_id_man_bomb && perk_index != perk_id_fire_caugh
            && perk_index != perk_id_tough_reloader
        ) {
            return 0;
        }
    }

    return 0;
}
