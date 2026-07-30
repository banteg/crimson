#include "crimsonland_gameplay.h"
#include <stddef.h>

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
    float value;
    int i;
    int player_count;
    int count;
    int weapon_id;
    int experience;
    int *weapon_cursor;
    float *cursor;
    creature_t *creature;

    sfx_play(sfx_ui_bonus, 1.0f);
    player_state_table[0].perk_counts[perk_id] += 1;

    if (perk_id == perk_id_instant_winner) {
        player_state_table[0].experience += 2500;
        player_count = config_player_count;
    } else if (perk_id == perk_id_fatal_lottery) {
        if ((crt_rand() & 1) == 0) {
            player_state_table[0].experience += 10000;
        } else {
            player_state_table[0].health = -1.0f;
        }
        player_count = config_player_count;
    } else if (perk_id == perk_id_lifeline_50_50) {
        i = 0;
        creature = creature_pool;
        do {
            if ((i & 1) != 0
                && creature->active != 0
                && creature->health <= 500.0f
                && (creature->flags & CREATURE_FLAG_ANIM_PING_PONG) == 0) {
                creature->active = 0;
                effect_spawn_burst(
                    &creature->position,
                    4);
            }
            ++creature;
            ++i;
        } while ((int)creature < (int)&creature_pool[384]);
        player_count = config_player_count;
    } else if (perk_id == perk_id_thick_skinned) {
        player_count = config_player_count;
        if (player_count > 0) {
            cursor = &player_state_table[0].health;
            count = player_count;
            do {
                if (*cursor > 0.0f) {
                    *cursor -= *cursor * 0.33333334f;
                    if (*cursor <= 0.0f) {
                        *cursor = 1.0f;
                    }
                }
                cursor += sizeof(player_state_t) / sizeof(*cursor);
                --count;
            } while (count != 0);
        }
    } else if (perk_id == perk_id_breathing_room) {
        player_count = config_player_count;
        if (player_count > 0) {
            cursor = &player_state_table[0].health;
            count = player_count;
            do {
                *cursor -= *cursor * 0.6666667f;
                cursor += sizeof(player_state_t) / sizeof(*cursor);
                --count;
            } while (count != 0);
        }

        cursor = &creature_pool[0].lifecycle_stage;
        do {
            creature_t *cursor_creature = (creature_t *)(
                (char *)cursor
                - offsetof(creature_t, lifecycle_stage));
            if (cursor_creature->active != 0) {
                *cursor -= frame_dt;
            }
            cursor += sizeof(creature_t) / sizeof(*cursor);
        } while ((int)cursor < (int)&creature_pool[384].lifecycle_stage);
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
        player_count = config_player_count;
    }

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

    if (perk_id == perk_id_ammo_maniac && player_count > 0) {
        weapon_cursor = &player_state_table[0].weapon_id;
        i = 0;
        do {
            weapon_assign_player(i, *weapon_cursor);
            player_count = config_player_count;
            ++i;
            weapon_cursor += sizeof(player_state_t) / sizeof(*weapon_cursor);
        } while (i < player_count);
    }

    if (perk_id == perk_id_death_clock) {
        player_state_table[0].perk_counts[perk_id_greater_regeneration] = 0;
        player_state_table[0].perk_counts[perk_id_regeneration] = 0;
        if (player_count > 0) {
            cursor = &player_state_table[0].health;
            count = player_count;
            do {
                if (*cursor > 0.0f) {
                    *cursor = 100.0f;
                }
                cursor += sizeof(player_state_t) / sizeof(*cursor);
                --count;
            } while (count != 0);
        }
    }

    if (perk_id == perk_id_bandage && player_count > 0) {
        cursor = &player_state_table[0].health;
        i = 0;
        do {
            value = (float)(crt_rand() % 50) + 1.0f;
            value *= *cursor;
            *cursor = value;
            if (value > 100.0f) {
                *cursor = 100.0f;
            }
            player_state_t *player = (player_state_t *)(
                (char *)cursor - offsetof(player_state_t, health));
            effect_spawn_burst(
                &player->position,
                8);
            player_count = config_player_count;
            ++i;
            cursor += sizeof(player_state_t) / sizeof(*cursor);
        } while (i < player_count);
    }

    if (perk_id == perk_id_my_favourite_weapon && player_count > 0) {
        cursor = &player_state_table[0].clip_size;
        do {
            *cursor += 2.0f;
            cursor += sizeof(player_state_t) / sizeof(*cursor);
            --player_count;
        } while (player_count != 0);
    }

    if (perk_id == perk_id_plaguebearer) {
        player_plaguebearer_active[0] = 1;
    }
}
