#include <math.h>
#include "crimsonland_gameplay.h"

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    return (float)sqrt(dx * dx + dy * dy);
}

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

        if (perk_count_get(perk_id_final_revenge) != 0) {
            const vec2f_t *player_pos =
                (const vec2f_t *)&player_state_table[player_index].pos_x;
            effect_spawn_explosion_burst(player_pos, 1.8f);
            bonus_spawn_guard = 1;

            int creature_index = 0;
            do {
                if (creature_pool[creature_index].active) {
                    abs_delta = abs_bits(
                        creature_pool[creature_index].pos_x - player_pos->x);
                    if (abs_delta <= 512.0f) {
                        abs_delta = abs_bits(
                            creature_pool[creature_index].pos_y - player_state_table[player_index].pos_y
                        );
                        if (abs_delta <= 512.0f) {
                            float blast = 512.0f - vec2_distance(
                                (vec2f_t *)&creature_pool[creature_index].pos_x,
                                player_pos
                            );
                            if (blast > 0.0f) {
                                vec2f_t impulse;
                                impulse.x = 0.0f;
                                impulse.y = 0.0f;
                                creature_apply_damage(
                                    creature_index,
                                    blast * 5.0f,
                                    3,
                                    (float *)&impulse);
                            }
                        }
                    }
                }
                ++creature_index;
            } while (creature_index < 0x180);

            bonus_spawn_guard = 0;
            sfx_play_panned(
                sfx_explosion_large,
                (float *)player_pos,
                1.0f);
            sfx_play_panned(
                sfx_shockwave,
                (float *)player_pos,
                1.0f);
        } else {
            sfx_play_panned(crt_rand() % 2 + sfx_trooper_die_01,
                            &player_state_table[player_index].pos_x,
                            1.0f);
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
