#include "crimsonland_gameplay.h"

extern "C" bonus_id_t bonus_pick_random_type(void)
{
    int retries = 0;
    bool has_fire_bullets_drop = false;
    unsigned char *bonus_state = &bonus_pool[0].state;
    do {
        if (*(bonus_id_t *)(bonus_state - 4) == BONUS_ID_FIRE_BULLETS && !*bonus_state) {
            has_fire_bullets_drop = true;
        }
        bonus_state += sizeof(bonus_entry_t);
    } while ((int)bonus_state < (int)&bonus_pool[0x10].state);

    bonus_id_t bonus_id;
    do {
        bonus_id = BONUS_ID_NONE;
        int bucket = crt_rand() % 0xa2 + 1;
        if (bucket <= 13) {
            bonus_id = BONUS_ID_POINTS;
        }
        bucket -= 13;
        if (bonus_id == BONUS_ID_NONE && bucket <= 1) {
            bonus_id = BONUS_ID_ENERGIZER;
        }
        --bucket;

        if (bonus_id == BONUS_ID_ENERGIZER) {
            if ((crt_rand() & 0x3f) == 0) {
                goto selected;
            }
            bonus_id = BONUS_ID_NONE;
        } else if (bonus_id != BONUS_ID_NONE) {
            goto selected;
        }

        {
            bonus_id_t bucket_id = BONUS_ID_WEAPON;
            while (bucket_id < 15) {
                if (bucket <= 10) {
                    bonus_id = bucket_id;
                    break;
                }
                bucket -= 10;
                bucket_id = (bonus_id_t)(bucket_id + 1);
            }
        }

selected:
        if (shock_chain_links_left > 0 && bonus_id == BONUS_ID_SHOCK_CHAIN) {
            continue;
        }

        if (config_blob.game_mode == GAME_MODE_QUEST) {
            if (config_blob.hardcore && quest_stage_major == 3) {
                if (quest_stage_minor == 10 && bonus_id == BONUS_ID_NUKE) {
                    continue;
                }
            } else if (
                quest_stage_major == 2 && quest_stage_minor == 10 && bonus_id == BONUS_ID_NUKE
            ) {
                continue;
            }

            if (config_blob.hardcore && quest_stage_major == 2) {
                if (quest_stage_minor == 10 && bonus_id == BONUS_ID_FREEZE) {
                    continue;
                }
            } else if (quest_stage_major == 4) {
                if (quest_stage_minor == 10) {
                    if (bonus_id == BONUS_ID_NUKE) {
                        continue;
                    }
                    if (bonus_id == BONUS_ID_FREEZE) {
                        continue;
                    }
                }
            } else if (quest_stage_major == 5) {
                if (quest_stage_minor == 10 && bonus_id == BONUS_ID_NUKE) {
                    continue;
                }
            }
        }

        if (bonus_freeze_timer > 0.0f && bonus_id == BONUS_ID_FREEZE) {
            continue;
        }
        if (
            (player_state_table[0].shield_timer > 0.0f || player_state_table[1].shield_timer > 0.0f)
            && bonus_id == BONUS_ID_SHIELD
        ) {
            continue;
        }
        if (perk_count_get(perk_id_my_favourite_weapon) != 0 && bonus_id == BONUS_ID_WEAPON) {
            continue;
        }
        if (perk_count_get(perk_id_death_clock) != 0 && bonus_id == BONUS_ID_MEDIKIT) {
            continue;
        }
        if (bonus_id == BONUS_ID_WEAPON && has_fire_bullets_drop) {
            continue;
        }
        if (bonus_meta_table[bonus_id].enabled) {
            return bonus_id;
        }
    } while (retries++ < 100);
    return BONUS_ID_POINTS;
}
