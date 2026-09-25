#include "crimsonland_gameplay.h"

extern "C" {
extern int perk_id_fatal_lottery;
extern int perk_id_lifeline_50_50;
extern int perk_id_breathing_room;
extern int perk_id_random_weapon;
extern int perk_id_infernal_contract;
extern int perk_id_grim_deal;
extern int perk_id_greater_regeneration;
extern int perk_id_regeneration;
extern int perk_id_bandage;
extern int perk_pending_count;
extern int config_player_count;
extern float player_health;
extern int player_experience;
}

extern "C" void perk_apply(int perk_id)
{
    int player_count;
    float value;
    int i;
    int weapon_id;
    int experience;

    sfx_play(sfx_ui_bonus, 1.0f);
    player_state_table[0].perk_counts[perk_id] += 1;

    if (perk_id == perk_id_instant_winner) {
        player_state_table[0].experience += 2500;
    } else if (perk_id == perk_id_fatal_lottery) {
        if ((crt_rand() & 1) == 0) {
            player_state_table[0].experience += 10000;
        } else {
            player_state_table[0].health = -1.0f;
        }
    } else if (perk_id == perk_id_lifeline_50_50) {
        for (i = 0; i < 384; i++) {
            if ((i & 1) != 0
                && creature_pool[i].active != 0
                && creature_pool[i].health <= 500.0f
                && (creature_pool[i].flags & CREATURE_FLAG_ANIM_PING_PONG) == 0) {
                creature_pool[i].active = 0;
                effect_spawn_burst(
                    &creature_pool[i].position,
                    4);
            }
        }
    } else if (perk_id == perk_id_thick_skinned) {
        for (i = 0; i < config_player_count; ++i) {
            if (player_state_table[i].health > 0.0f) {
                player_state_table[i].health -=
                    player_state_table[i].health * 0.33333334f;
                if (player_state_table[i].health <= 0.0f) {
                    player_state_table[i].health = 1.0f;
                }
            }
        }
    } else if (perk_id == perk_id_breathing_room) {
        for (i = 0; i < config_player_count; ++i) {
            player_state_table[i].health -= player_state_table[i].health * 0.6666667f;
        }

        for (i = 0; i < 384; i++) {
            if (creature_pool[i].active != 0) {
                creature_pool[i].lifecycle_stage -= frame_dt;
            }
        }
        bonus_spawn_guard = 0;
    } else {
        if (perk_id == perk_id_random_weapon) {
            i = 0;
            do {
                weapon_id = weapon_pick_random_available();
                ++i;
                if (weapon_id != 1
                    && weapon_id != player_state_table[0].weapon_id) {
                    break;
                }
            } while (i < 100);
            weapon_assign_player(0, weapon_id);
        }

    }

    player_count = config_player_count;

    if (perk_id == perk_id_infernal_contract) {
        player_state_table[0].level += 3;
        perk_pending_count += 3;
        if (player_state_table[0].health > 0.0f) {
            player_state_table[0].health = 0.1f;
        }
        if (player_state_table[1].health > 0.0f) {
            player_state_table[1].health = 0.1f;
        }
    }

    if (perk_id == perk_id_grim_deal) {
        experience = (int)(player_experience * 0.18f);
        player_experience = player_experience + experience;
        player_health = -1.0f;
    }

    if (perk_id == perk_id_ammo_maniac) {
        for (i = 0; i < player_count; ++i) {
            weapon_assign_player(i, player_state_table[i].weapon_id);
            player_count = config_player_count;
        }
    }

    if (perk_id == perk_id_death_clock) {
        player_state_table[0].perk_counts[perk_id_greater_regeneration] = 0;
        player_state_table[0].perk_counts[perk_id_regeneration] = 0;
        for (i = 0; i < config_player_count; ++i) {
            if (player_state_table[i].health > 0.0f) {
                player_state_table[i].health = 100.0f;
            }
        }
    }

    if (perk_id == perk_id_bandage) {
        for (i = 0; i < player_count; ++i) {
            player_state_table[i].health *= (float)(crt_rand() % 50) + 1.0f;
            if (player_state_table[i].health > 100.0f) {
                player_state_table[i].health = 100.0f;
            }
            effect_spawn_burst(&player_state_table[i].position, 8);
            player_count = config_player_count;
        }
    }

    if (perk_id == perk_id_my_favourite_weapon) {
        for (i = 0; i < config_player_count; ++i) {
            player_state_table[i].clip_size += 2.0f;
        }
    }

    if (perk_id == perk_id_plaguebearer) {
        player_plaguebearer_active[0] = 1;
    }
}
