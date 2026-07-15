#include "crimsonland_gameplay.h"

struct perk_effect_vec2_t {
    float x;
    float y;

    perk_effect_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }
};

extern "C" {
extern int config_player_count;
extern int perk_id_regeneration;
extern int perk_id_lean_mean_exp_machine;
extern int perk_id_doctor;
extern int perk_id_pyrokinetic;
extern int perk_id_evil_eyes;
extern int perk_id_jinxed;
extern float perk_lean_mean_exp_tick_timer_s;
extern int perk_doctor_target_creature_id;
extern float perk_jinxed_proc_timer_s;
extern int sfx_trooper_inpain_01_alias_1;

int creature_find_in_radius(float *pos, float radius, int start_index);
int fx_spawn_particle(
    float *pos,
    float angle,
    const perk_effect_vec2_t &velocity,
    float intensity);
void fx_queue_add_random(vec2f_t *pos);
}

extern "C" void perks_update_effects(void)
{
    if (perk_count_get(perk_id_regeneration) != 0) {
        if ((crt_rand() & 1) != 0) {
            int player_count = config_player_count;
            if (player_count > 0) {
                float health = player_state_table[0].health;
                int count = player_count;
                do {
                    if (health < 100.0f && health > 0.0f) {
                        health += frame_dt;
                        if (health > 100.0f) {
                            health = 100.0f;
                        }
                    }
                    --count;
                } while (count != 0);
                player_state_table[0].health = health;
            }
        }
    }

    perk_lean_mean_exp_tick_timer_s -= frame_dt;
    if (perk_lean_mean_exp_tick_timer_s < 0.0f) {
        perk_lean_mean_exp_tick_timer_s = 0.25f;
        int perk_count =
            player_state_table[0].perk_counts[perk_id_lean_mean_exp_machine];
        if (perk_count > 0) {
            player_state_table[0].experience += perk_count * 10;
        }
    }

    for (render_overlay_player_index = 0;
         render_overlay_player_index < config_player_count;
         ++render_overlay_player_index) {
        if (perk_count_get(perk_id_death_clock) != 0) {
            if (player_state_table[render_overlay_player_index].health > 0.0f) {
                player_state_table[render_overlay_player_index].health -=
                    frame_dt * 3.33333325f;
            } else {
                player_state_table[render_overlay_player_index].health = 0.0f;
            }
        }

        if (player_state_table[render_overlay_player_index].shield_timer > 0.0f) {
            player_state_table[render_overlay_player_index].shield_timer -=
                frame_dt;
        } else {
            player_state_table[render_overlay_player_index].shield_timer = 0.0f;
        }

        if (player_state_table[render_overlay_player_index].fire_bullets_timer
            > 0.0f) {
            player_state_table[render_overlay_player_index].fire_bullets_timer -=
                frame_dt;
        } else {
            player_state_table[render_overlay_player_index].fire_bullets_timer =
                0.0f;
        }

        if (player_state_table[render_overlay_player_index].speed_bonus_timer
            > 0.0f) {
            player_state_table[render_overlay_player_index].speed_bonus_timer -=
                frame_dt;
        } else {
            player_state_table[render_overlay_player_index].speed_bonus_timer =
                0.0f;
        }

    }

    perk_doctor_target_creature_id = -1;
    if (player_state_table[0].perk_counts[perk_id_doctor] > 0
        || player_state_table[0].perk_counts[perk_id_pyrokinetic] > 0
        || player_state_table[0].perk_counts[perk_id_evil_eyes] > 0) {
        player_state_table[0].evil_eyes_target_creature = -1;
        int creature_id = creature_find_in_radius(
            &player_state_table[0].aim_x,
            12.0f,
            0);
        if (creature_id != -1) {
            if (perk_count_get(perk_id_doctor) != 0) {
                perk_doctor_target_creature_id = creature_id;
            }

            if (perk_count_get(perk_id_pyrokinetic) != 0) {
                creature_pool[creature_id].collision_timer -= frame_dt;
                if (creature_pool[creature_id].collision_timer < 0.0f) {
                    creature_pool[creature_id].collision_timer = 0.5f;
                    float *pos = &creature_pool[creature_id].pos_x;
                    fx_spawn_particle(
                        pos,
                        (float)(crt_rand() % 0x274) * 0.01f,
                        perk_effect_vec2_t(0.0f, 0.0f),
                        0.8f);
                    fx_spawn_particle(
                        pos,
                        (float)(crt_rand() % 0x274) * 0.01f,
                        perk_effect_vec2_t(0.0f, 0.0f),
                        0.6f);
                    fx_spawn_particle(
                        pos,
                        (float)(crt_rand() % 0x274) * 0.01f,
                        perk_effect_vec2_t(0.0f, 0.0f),
                        0.4f);
                    fx_spawn_particle(
                        pos,
                        (float)(crt_rand() % 0x274) * 0.01f,
                        perk_effect_vec2_t(0.0f, 0.0f),
                        0.3f);
                    fx_spawn_particle(
                        pos,
                        (float)(crt_rand() % 0x274) * 0.01f,
                        perk_effect_vec2_t(0.0f, 0.0f),
                        0.2f);
                    fx_queue_add_random((vec2f_t *)pos);
                }
            }

            if (perk_count_get(perk_id_evil_eyes) != 0) {
                player_state_table[0].evil_eyes_target_creature = creature_id;
            }
        }
    }

    if (perk_count_get(perk_id_evil_eyes) == 0) {
        player_state_table[0].evil_eyes_target_creature = -1;
    }

    if (perk_jinxed_proc_timer_s >= 0.0f) {
        perk_jinxed_proc_timer_s -= frame_dt;
    }
    if (perk_jinxed_proc_timer_s >= 0.0f
        || player_state_table[0].perk_counts[perk_id_jinxed] <= 0) {
        return;
    }

    if (crt_rand() % 10 == 3) {
        player_state_table[0].health -= 5.0f;
        fx_queue_add_random((vec2f_t *)&player_state_table[0].pos_x);
        fx_queue_add_random((vec2f_t *)&player_state_table[0].pos_x);
    }

    perk_jinxed_proc_timer_s =
        (float)(crt_rand() % 20) * 0.1f
        + perk_jinxed_proc_timer_s
        + 2.0f;

    if (bonus_freeze_timer > 0.0f) {
        return;
    }

    int creature_id = crt_rand() % 0x17f;
    for (render_overlay_player_index = 0;
         render_overlay_player_index < 10
            && creature_pool[creature_id].active == 0;
         ++render_overlay_player_index) {
        creature_id = crt_rand() % 0x17f;
    }
    render_overlay_player_index = 0;

    if (creature_pool[creature_id].active == 0) {
        return;
    }

    creature_pool[creature_id].health = -1.0f;
    creature_pool[creature_id].lifecycle_stage -= frame_dt * 20.0f;
    player_state_table[0].experience =
        (int)((float)player_state_table[0].experience
            + creature_pool[creature_id].reward_value);
    sfx_play_panned(
        sfx_trooper_inpain_01_alias_1,
        &creature_pool[creature_id].pos_x,
        1.0f);
}
