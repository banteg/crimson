#include <math.h>
#include "crimsonland_gameplay.h"

typedef union player_damage_impulse_t {
    int i[2];
    float f[2];
} player_damage_impulse_t;

extern "C" void player_take_damage(int player_index, float damage)
{
    float abs_delta;

    if (perk_count_get(perk_id_death_clock) != 0) {
        return;
    }

    if (perk_count_get(perk_id_tough_reloader) != 0 && player_state_table[player_index].reload_active != 0) {
        damage = damage * 0.5f;
    }

    survival_reward_damage_seen = 1;
    float damage_scale = 1.0f;

    if (player_state_table[player_index].shield_timer > 0.0f) {
        return;
    }

    unsigned char was_dead = player_state_table[0].health <= 0.0f;
    if (perk_count_get(perk_id_thick_skinned) != 0) {
        damage_scale = 0.666f;
    }

    unsigned char dodged = 0;
    if (perk_count_get(perk_id_ninja) != 0) {
        if (crt_rand() % 3 == 0) {
            dodged = 1;
            goto post_damage;
        }
    } else {
        if (perk_count_get(perk_id_dodger) != 0 && crt_rand() % 5 == 0) {
            dodged = 1;
            goto post_damage;
        }
    }

    if (perk_count_get(perk_id_highlander) != 0) {
        if (crt_rand() % 10 == 0) {
            player_state_table[player_index].health = 0.0f;
        }
    } else {
        player_state_table[player_index].health = player_state_table[player_index].health - damage_scale * damage;
    }

post_damage:
    if (player_state_table[player_index].health < 0.0f) {
        player_state_table[player_index].death_timer =
            player_state_table[player_index].death_timer - frame_dt * 28.0f;
        if (was_dead) {
            return;
        }

        if (perk_count_get(perk_id_final_revenge) == 0) {
            unsigned int death_sfx = (unsigned int)crt_rand() & 0x80000001;
            if ((int)death_sfx < 0) {
                death_sfx = ((death_sfx - 1) | 0xfffffffe) + 1;
            }
            sfx_play_panned((int)death_sfx + sfx_trooper_die_01,
                            &player_state_table[player_index].pos_x,
                            1.0f);
        } else {
            float *player_pos = &player_state_table[player_index].pos_x;
            effect_spawn_explosion_burst(player_pos, 1.8f);
            bonus_spawn_guard = 1;

            int creature_index = 0;
            unsigned char *creature_cursor = (unsigned char *)creature_pool;
            do {
                creature_t *creature = (creature_t *)creature_cursor;
                if (creature->active) {
                    abs_delta = creature->pos_x - player_pos[0];
                    *(int *)&abs_delta &= 0x7fffffff;
                    if (abs_delta < 512.0f) {
                        abs_delta = creature->pos_y - player_state_table[player_index].pos_y;
                        *(int *)&abs_delta &= 0x7fffffff;
                        if (abs_delta < 512.0f) {
                            float dx = creature->pos_x - player_pos[0];
                            float dy = creature->pos_y - player_pos[1];
                            float blast = 512.0f - (float)sqrt(dx * dx + dy * dy);
                            if (blast > 0.0f) {
                                player_damage_impulse_t impulse;
                                impulse.i[0] = 0;
                                impulse.i[1] = 0;
                                creature_apply_damage(creature_index, blast * 5.0f, 3, impulse.f);
                            }
                        }
                    }
                }
                creature_cursor += sizeof(creature_t);
                ++creature_index;
            } while ((int)creature_cursor < (int)&creature_pool[0x180]);

            bonus_spawn_guard = 0;
            sfx_play_panned(sfx_explosion_large, player_pos, 1.0f);
            sfx_play_panned(sfx_shockwave, player_pos, 1.0f);
        }
    } else {
        sfx_play_panned(crt_rand() % 3 + sfx_trooper_inpain_01,
                        &player_state_table[player_index].pos_x,
                        1.0f);
        if (was_dead) {
            return;
        }
    }

    if (!dodged) {
        if (perk_count_get(perk_id_unstoppable) == 0) {
            player_state_table[player_index].heading =
                (float)(crt_rand() % 100 - 50) * 0.04f + player_state_table[player_index].heading;
            float spread_heat = damage * 0.01f + player_state_table[player_index].spread_heat;
            player_state_table[player_index].spread_heat = spread_heat;
            if (spread_heat > 0.48f) {
                player_state_table[player_index].spread_heat = 0.48f;
            }
        }

        if (player_state_table[player_index].health <= 20.0f && (crt_rand() & 7) == 3) {
            player_state_table[player_index].low_health_timer = 0.0f;
        }
    }
}
