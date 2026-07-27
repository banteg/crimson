#include <math.h>

#define creature_apply_damage creature_apply_damage_pointer_abi
#define fx_queue_add_rotated fx_queue_add_rotated_pointer_abi
#include "crimsonland_gameplay.h"
#undef creature_apply_damage
#undef fx_queue_add_rotated

struct creature_vec2_t {
    float x;
    float y;

    creature_vec2_t()
        : x(0.0f), y(0.0f)
    {
    }

    creature_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }
};

extern "C" {
extern int creature_update_tick;
extern int plaguebearer_infection_count;
extern int creature_kill_count;
extern int config_player_count;
extern int frame_dt_ms;
extern int perk_id_radioactive;
extern int perk_id_mr_melee;
extern int perk_id_toxic_avenger;
extern int sfx_shock_fire;
extern int sfx_plasmaminigun_fire;
extern creature_type_table_t creature_type_table;
extern cvar_float_t *cv_bodiesFade;

float angle_approach(float *angle, float target, float rate);
int creature_apply_damage(
    int creature_index,
    float damage,
    int damage_type,
    const creature_vec2_t &impulse);
unsigned char fx_queue_add_rotated(
    const creature_vec2_t &pos,
    effect_color_t *color,
    float rotation,
    float scale,
    int effect_id);
void creature_handle_death(int creature_id, unsigned char keep_corpse);
void fx_queue_add_random(vec2f_t *pos);
int vec2_add_inplace(
    int entity_index,
    vec2f_t *pos,
    const vec2f_t *delta);
int plaguebearer_spread_infection(int creature_id);
void player_take_damage(int player_index, float damage);
void effect_spawn_blood_splatter(
    const vec2f_t *pos,
    float angle,
    float age);
vec2f_t *__stdcall vec2_normalize_dispatch(vec2f_t *dst, const vec2f_t *src);
}

extern "C" void creature_update_all(void)
{
    int creature_index;
    float *lifecycle_stage;
    unsigned char *collision_flag;
    float *attack_cooldown;
    int spawn_limit;
    float target_delta_y;
    int slot_index;
    unsigned int flags;
    int linked_index;
    float *health;
    float distance;
    float move_scale;
    float alternate_distance;
    float random_cooldown;

    ++creature_update_tick;
    creature_active_count = 0;
    for (creature_index = 0; creature_index < 384; ++creature_index) {
        if (creature_pool[creature_index].active) {
            ++creature_active_count;
            if (creature_pool[creature_index].hit_flash_timer > 0.0f) {
                creature_pool[creature_index].hit_flash_timer -= frame_dt;
            }

            if (bonus_freeze_timer <= 0.0f) {
                health = &creature_pool[creature_index].health;
                if (*health <= 0.0f
                    && creature_pool[creature_index].lifecycle_stage == 16.0f) {
                    creature_pool[creature_index].lifecycle_stage -= frame_dt;
                }

                if ((creature_pool[creature_index].flags
                        & CREATURE_FLAG_SELF_DAMAGE_TICK_STRONG) != 0) {
                    creature_apply_damage(
                        creature_index,
                        frame_dt * 180.0f,
                        0,
                        creature_vec2_t());
                } else if ((creature_pool[creature_index].flags
                               & CREATURE_FLAG_SELF_DAMAGE_TICK) != 0) {
                    creature_apply_damage(
                        creature_index,
                        frame_dt * 60.0f,
                        0,
                        creature_vec2_t());
                }

                if ((creature_pool[creature_index].flags
                        & CREATURE_FLAG_AI7_LINK_TIMER) != 0) {
                    linked_index = creature_pool[creature_index].link_index;
                    if (linked_index < 0) {
                        linked_index += frame_dt_ms;
                        creature_pool[creature_index].link_index = linked_index;
                        if (linked_index >= 0) {
                            creature_pool[creature_index].ai_mode =
                                CREATURE_AI_HOLD_TIMER;
                            creature_pool[creature_index].link_index =
                                (crt_rand() & 0x1ff) + 500;
                        }
                    } else {
                        linked_index -= frame_dt_ms;
                        creature_pool[creature_index].link_index = linked_index;
                        if (linked_index <= 0) {
                            creature_pool[creature_index].link_index =
                                -700 - (crt_rand() & 0x3ff);
                        }
                    }
                }

                if (*health <= 0.0f
                    && creature_pool[creature_index].lifecycle_stage == 16.0f) {
                    creature_pool[creature_index].lifecycle_stage -= frame_dt;
                }

                {
                    signed char current_player =
                        creature_pool[creature_index].target_player;
                    int current_player_index = (int)current_player;
                    vec2f_t *position =
                        &creature_pool[creature_index].position;
                    float dx = player_state_table[current_player_index].position.x - position->x;
                    float dy = player_state_table[current_player_index].position.y - position->y;
                    distance = (float)sqrt(dx * dx + dy * dy);

                    if (creature_update_tick % 70 != 0) {
                        if (config_player_count == 2) {
                            if (player_state_table[1 - current_player].health > 0.0f) {
                                vec2f_t *alternate_pos =
                                    &player_state_table[1 - current_player].position;
                                dx = alternate_pos->x - position->x;
                                dy = alternate_pos->y - position->y;
                                alternate_distance = (float)sqrt(dx * dx + dy * dy);
                                if (alternate_distance < distance) {
                                    creature_pool[creature_index].target_player =
                                        1 - current_player;
                                    distance = alternate_distance;
                                }
                            }
                        } else {
                            dx = player_state_table[0].position.x - position->x;
                            dy = player_state_table[0].position.y - position->y;
                            alternate_distance = (float)sqrt(dx * dx + dy * dy);
                        }

                        current_player =
                            creature_pool[creature_index].target_player;
                        current_player_index = (int)current_player;
                        dx = player_state_table[0].position.x
                            - creature_pool[player_state_table[current_player_index].auto_target].pos_x;
                        dy = player_state_table[0].position.y
                            - creature_pool[player_state_table[current_player_index].auto_target].pos_y;
                        if (alternate_distance < (float)sqrt(dx * dx + dy * dy)) {
                            player_state_table[current_player_index].auto_target = creature_index;
                        }
                    }

                    if (player_state_table[current_player_index].health <= 0.0f) {
                        creature_pool[creature_index].target_player =
                            1 - current_player;
                    }

                    lifecycle_stage = &creature_pool[creature_index].lifecycle_stage;
                    if (*lifecycle_stage == 16.0f) {
                        collision_flag = &creature_pool[creature_index].collision_flag;
                        if (*collision_flag) {
                            float collision_timer =
                                creature_pool[creature_index].collision_timer - frame_dt;
                            creature_pool[creature_index].collision_timer = collision_timer;
                            if (collision_timer < 0.0f) {
                                creature_pool[creature_index].state_flag = 1;
                                creature_pool[creature_index].collision_timer =
                                    collision_timer + 0.5f;
                                *health -= 15.0f;
                                if (*health < 0.0f) {
                                    ++plaguebearer_infection_count;
                                    creature_handle_death(creature_index, 1);
                                    sfx_play_panned(
                                        creature_type_table[
                                            creature_pool[creature_index].type_id
                                        ].sfx_bank_b[crt_rand() % 2],
                                        position,
                                        1.0f);
                                }
                                fx_queue_add_random(position);
                            }
                        }

                        creature_pool[creature_index].force_target = 0;
                        move_scale = 1.0f;
                        float phase_angle =
                            (float)creature_pool[creature_index].phase_seed * 3.7f;
                        phase_angle = phase_angle * 3.1415927f;

                        if (creature_index
                            == player_state_table[0].evil_eyes_target_creature) {
                            goto next_creature;
                        }

                        int ai_mode = creature_pool[creature_index].ai_mode;
                        if (ai_mode == CREATURE_AI_ORBIT_PLAYER) {
                            current_player_index =
                                creature_pool[creature_index].target_player;
                            if (distance > 800.0f) {
                                creature_pool[creature_index].target_x =
                                    player_state_table[current_player_index].position.x;
                                creature_pool[creature_index].target_y =
                                    player_state_table[current_player_index].position.y;
                            } else {
                                creature_pool[creature_index].target_x =
                                    (float)cos(phase_angle) * distance * 0.85f
                                    + player_state_table[current_player_index].position.x;
                                creature_pool[creature_index].target_y =
                                    (float)sin(phase_angle) * distance * 0.85f
                                    + player_state_table[current_player_index].position.y;
                            }
                        } else if (ai_mode == CREATURE_AI_ORBIT_PLAYER_WIDE) {
                            current_player_index =
                                creature_pool[creature_index].target_player;
                            creature_pool[creature_index].target_x =
                                (float)cos(phase_angle) * distance * 0.9f
                                + player_state_table[current_player_index].position.x;
                            creature_pool[creature_index].target_y =
                                (float)sin(phase_angle) * distance * 0.9f
                                + player_state_table[current_player_index].position.y;
                        } else if (ai_mode == CREATURE_AI_ORBIT_PLAYER_TIGHT) {
                            current_player_index =
                                creature_pool[creature_index].target_player;
                            if (distance > 800.0f) {
                                creature_pool[creature_index].target_x =
                                    player_state_table[current_player_index].position.x;
                                creature_pool[creature_index].target_y =
                                    player_state_table[current_player_index].position.y;
                            } else {
                                creature_pool[creature_index].target_x =
                                    (float)cos(phase_angle) * distance * 0.55f
                                    + player_state_table[current_player_index].position.x;
                                creature_pool[creature_index].target_y =
                                    (float)sin(phase_angle) * distance * 0.55f
                                    + player_state_table[current_player_index].position.y;
                            }
                        } else if (ai_mode == CREATURE_AI_FOLLOW_LINK) {
                            linked_index = creature_pool[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                creature_pool[creature_index].target_x =
                                    creature_pool[linked_index].pos_x
                                    + creature_pool[creature_index].target_offset.x;
                                creature_pool[creature_index].target_y =
                                    creature_pool[linked_index].pos_y
                                    + creature_pool[creature_index].target_offset.y;
                            } else {
                                creature_pool[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                            }
                        } else if (ai_mode == CREATURE_AI_FOLLOW_LINK_TETHERED) {
                            linked_index = creature_pool[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                creature_pool[creature_index].target_x =
                                    creature_pool[linked_index].pos_x
                                    + creature_pool[creature_index].target_offset.x;
                                creature_pool[creature_index].target_y =
                                    creature_pool[linked_index].pos_y
                                    + creature_pool[creature_index].target_offset.y;
                                dx = creature_pool[creature_index].target_x - position->x;
                                target_delta_y =
                                    creature_pool[creature_index].target_y - position->y;
                                float target_distance =
                                    (float)sqrt(
                                        dx * dx + target_delta_y * target_delta_y);
                                if (target_distance <= 64.0f) {
                                    move_scale = target_distance * 0.015625f;
                                }
                            } else {
                                creature_pool[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                                creature_apply_damage(
                                    creature_index,
                                    1000.0f,
                                    1,
                                    creature_vec2_t());
                            }
                        }

                        ai_mode = creature_pool[creature_index].ai_mode;
                        if (ai_mode == CREATURE_AI_LINK_GUARD) {
                            linked_index = creature_pool[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                current_player_index =
                                    creature_pool[creature_index].target_player;
                                if (distance > 800.0f) {
                                    creature_pool[creature_index].target_x =
                                        player_state_table[current_player_index].position.x;
                                    creature_pool[creature_index].target_y =
                                        player_state_table[current_player_index].position.y;
                                } else {
                                    creature_pool[creature_index].target_x =
                                        (float)cos(phase_angle) * distance * 0.85f
                                        + player_state_table[current_player_index].position.x;
                                    creature_pool[creature_index].target_y =
                                        (float)sin(phase_angle) * distance * 0.85f
                                        + player_state_table[current_player_index].position.y;
                                }
                            } else {
                                creature_pool[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                                creature_apply_damage(
                                    creature_index,
                                    1000.0f,
                                    1,
                                    creature_vec2_t());
                            }
                        } else if (ai_mode == CREATURE_AI_HOLD_TIMER) {
                            flags = creature_pool[creature_index].flags
                                & CREATURE_FLAG_AI7_LINK_TIMER;
                            if (flags == 0
                                || creature_pool[creature_index].link_index <= 0) {
                                if (creature_pool[creature_index].orbit_radius.radius <= 0.0f
                                    || flags != 0) {
                                    creature_pool[creature_index].ai_mode =
                                        CREATURE_AI_ORBIT_PLAYER;
                                } else {
                                    creature_pool[creature_index].orbit_radius.radius -= frame_dt;
                                    creature_pool[creature_index].target_x = position->x;
                                    creature_pool[creature_index].target_y = position->y;
                                }
                            } else {
                                creature_pool[creature_index].target_x = position->x;
                                creature_pool[creature_index].target_y = position->y;
                            }
                        } else if (ai_mode == CREATURE_AI_ORBIT_LINK) {
                            linked_index = creature_pool[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                float orbit_heading =
                                    creature_pool[creature_index].orbit_angle
                                    + creature_pool[creature_index].heading;
                                creature_pool[creature_index].target_x =
                                    (float)cos(orbit_heading)
                                    * creature_pool[creature_index].orbit_radius.radius
                                    + creature_pool[linked_index].pos_x;
                                creature_pool[creature_index].target_y =
                                    (float)sin(orbit_heading)
                                    * creature_pool[creature_index].orbit_radius.radius
                                    + creature_pool[linked_index].pos_y;
                            } else {
                                creature_pool[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                            }
                        }

                        dx = creature_pool[creature_index].target_x - position->x;
                        dy = creature_pool[creature_index].target_y - position->y;
                        if ((float)sqrt(dx * dx + dy * dy) < 40.0f) {
                            creature_pool[creature_index].force_target = 1;
                        }
                        dx = creature_pool[creature_index].target_x - position->x;
                        dy = creature_pool[creature_index].target_y - position->y;
                        if ((float)sqrt(dx * dx + dy * dy) > 400.0f) {
                            creature_pool[creature_index].force_target = 1;
                        }
                        if (creature_pool[creature_index].force_target
                            || creature_pool[creature_index].ai_mode
                                == CREATURE_AI_CHASE_PLAYER) {
                            current_player_index =
                                creature_pool[creature_index].target_player;
                            creature_pool[creature_index].target_x =
                                player_state_table[current_player_index].position.x;
                            creature_pool[creature_index].target_y =
                                player_state_table[current_player_index].position.y;
                        }

                        float desired_heading = (float)atan2(
                            creature_pool[creature_index].target_y - position->y,
                            creature_pool[creature_index].target_x - position->x);
                        creature_pool[creature_index].target_heading =
                            (float)(desired_heading + 1.5707964f);
                        if ((bonus_energizer_timer > 0.0f
                                && creature_pool[creature_index].max_health < 500.0f)
                            || *collision_flag) {
                            creature_pool[creature_index].target_heading += 3.1415927f;
                        }

                        flags = creature_pool[creature_index].flags;
                        if ((flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
                            if (position->x < creature_pool[creature_index].size) {
                                position->x = creature_pool[creature_index].size;
                            }
                            if (position->y < creature_pool[creature_index].size) {
                                position->y = creature_pool[creature_index].size;
                            }
                            float max_pos = 1024.0f - creature_pool[creature_index].size;
                            if (position->x > max_pos) {
                                position->x = max_pos;
                            }
                            if (position->y > max_pos) {
                                position->y = max_pos;
                            }

                            if ((flags & CREATURE_FLAG_ANIM_LONG_STRIP) == 0) {
                                creature_pool[creature_index].vel_x = 0.0f;
                                creature_pool[creature_index].vel_y = 0.0f;
                            } else {
                                angle_approach(
                                    &creature_pool[creature_index].heading,
                                    creature_pool[creature_index].target_heading,
                                    4.0f * (creature_pool[creature_index].move_speed
                                        * 0.33333334f));
                                double movement_heading =
                                    creature_pool[creature_index].heading - 1.5707964f;
                                creature_pool[creature_index].vel_x =
                                    (float)cos(movement_heading) * frame_dt * move_scale
                                    * creature_pool[creature_index].move_speed * 30.0f;
                                creature_pool[creature_index].vel_y =
                                    (float)sin(movement_heading) * frame_dt * move_scale
                                    * creature_pool[creature_index].move_speed * 30.0f;
                                vec2_add_inplace(
                                    creature_index,
                                    position,
                                    &creature_pool[creature_index].velocity);
                            }

                            slot_index = creature_pool[creature_index].link_index;
                            creature_spawn_slot_table[slot_index].timer_s -= frame_dt;
                            if (creature_spawn_slot_table[slot_index].timer_s < 0.0f) {
                                int spawn_count =
                                    creature_spawn_slot_table[slot_index].count;
                                spawn_limit = creature_spawn_slot_table[slot_index].limit;
                                creature_spawn_slot_table[slot_index].timer_s +=
                                    creature_spawn_slot_table[slot_index].interval_s;
                                if (spawn_count < spawn_limit) {
                                    creature_spawn_slot_table[slot_index].count =
                                        spawn_count + 1;
                                    creature_spawn_template(
                                        creature_spawn_slot_table[slot_index].template_id,
                                        position,
                                        -100.0f);
                                }
                            }
                        } else if (creature_pool[creature_index].ai_mode
                            != CREATURE_AI_HOLD_TIMER) {
                            angle_approach(
                                &creature_pool[creature_index].heading,
                                creature_pool[creature_index].target_heading,
                                4.0f * (creature_pool[creature_index].move_speed
                                    * 0.33333334f));
                            double movement_heading =
                                creature_pool[creature_index].heading - 1.5707964f;
                            creature_pool[creature_index].vel_x =
                                (float)cos(movement_heading) * frame_dt * move_scale
                                * creature_pool[creature_index].move_speed * 30.0f;
                            creature_pool[creature_index].vel_y =
                                (float)sin(movement_heading) * frame_dt * move_scale
                                * creature_pool[creature_index].move_speed * 30.0f;
                            vec2_add_inplace(
                                creature_index,
                                position,
                                &creature_pool[creature_index].velocity);
                        }

                        if (perk_count_get(perk_id_plaguebearer) != 0
                            && plaguebearer_infection_count < 60) {
                            plaguebearer_spread_infection(creature_index);
                        }

                        float anim_scale = 30.0f / creature_pool[creature_index].size;
                        if ((creature_pool[creature_index].flags
                                & CREATURE_FLAG_ANIM_PING_PONG) == 0
                            || (creature_pool[creature_index].flags
                                & CREATURE_FLAG_ANIM_LONG_STRIP) != 0) {
                            if (creature_pool[creature_index].ai_mode
                                != CREATURE_AI_HOLD_TIMER) {
                                creature_pool[creature_index].anim_phase +=
                                    creature_type_table[
                                        creature_pool[creature_index].type_id
                                    ].anim_rate
                                    * creature_pool[creature_index].move_speed
                                    * frame_dt * anim_scale * move_scale * 25.0f;
                                while (creature_pool[creature_index].anim_phase > 31.0f) {
                                    creature_pool[creature_index].anim_phase -= 31.0f;
                                }
                            }
                        } else {
                            creature_pool[creature_index].anim_phase +=
                                creature_type_table[
                                    creature_pool[creature_index].type_id
                                ].anim_rate
                                * creature_pool[creature_index].move_speed
                                * frame_dt * anim_scale * move_scale * 22.0f;
                            if (creature_pool[creature_index].anim_phase > 15.0f) {
                                do {
                                    creature_pool[creature_index].anim_phase -= 15.0f;
                                } while (creature_pool[creature_index].anim_phase > 15.0f);
                            }
                        }

                        attack_cooldown =
                            &creature_pool[creature_index].attack_cooldown;
                        if (*attack_cooldown > 0.0f) {
                            *attack_cooldown -= frame_dt;
                        } else {
                            *attack_cooldown = 0.0f;
                        }

                        signed char *target_player =
                            &creature_pool[creature_index].target_player;
                        current_player_index = (int)*target_player;
                        dx = position->x - player_state_table[current_player_index].position.x;
                        dy = position->y - player_state_table[current_player_index].position.y;
                        distance = (float)sqrt(dx * dx + dy * dy);

                        if (distance < 100.0f
                            && perk_count_get(perk_id_radioactive) != 0) {
                            creature_pool[creature_index].collision_timer -=
                                frame_dt * 1.5f;
                            if (creature_pool[creature_index].collision_timer < 0.0f
                                && *health > 0.0f) {
                                creature_pool[creature_index].collision_timer = 0.5f;
                                creature_pool[creature_index].state_flag = 1;
                                *health -= (100.0f - distance) * 0.3f;
                                if (*health < 0.0f) {
                                    if (creature_pool[creature_index].type_id
                                        == CREATURE_TYPE_LIZARD) {
                                        *health = 1.0f;
                                    } else {
                                        player_state_table[0].experience = (int)(
                                            (float)player_state_table[0].experience
                                            + creature_pool[creature_index].reward_value);
                                        *lifecycle_stage -= frame_dt;
                                    }
                                }
                                fx_queue_add_random(position);
                            }
                        }

                        if (distance > 64.0f) {
                            if ((creature_pool[creature_index].flags
                                    & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0
                                && *attack_cooldown <= 0.0f) {
                                projectile_spawn(
                                    position,
                                    creature_pool[creature_index].heading,
                                    PROJECTILE_TYPE_PLASMA_RIFLE,
                                    creature_index);
                                *attack_cooldown += 1.0f;
                                sfx_play_panned(
                                    sfx_shock_fire,
                                    position,
                                    1.0f);
                            }
                            if ((creature_pool[creature_index].flags
                                    & CREATURE_FLAG_RANGED_ATTACK_VARIANT) != 0
                                && *attack_cooldown <= 0.0f) {
                                projectile_spawn(
                                    position,
                                    creature_pool[creature_index].heading,
                                    creature_pool[creature_index].orbit_radius.projectile_type,
                                    creature_index);
                                random_cooldown = (float)(crt_rand() & 3);
                                *attack_cooldown += random_cooldown * 0.1f
                                    + creature_pool[creature_index].orbit_angle;
                                sfx_play_panned(
                                    sfx_plasmaminigun_fire,
                                    position,
                                    0.8f);
                            }
                        }

                        if (distance < 20.0f) {
                            position->x -= creature_pool[creature_index].vel_x;
                            position->y -= creature_pool[creature_index].vel_y;
                            if (creature_pool[creature_index].max_health < 380.0f
                                && bonus_energizer_timer > 0.0f) {
                                player_state_table[0].experience = (int)(
                                    (float)player_state_table[0].experience
                                    + creature_pool[creature_index].reward_value);
                                effect_spawn_burst(
                                    position,
                                    6);
                                sfx_play_panned(
                                    sfx_ui_bonus,
                                    position,
                                    0.8f);
                                bonus_spawn_guard = 1;
                                creature_handle_death(creature_index, 0);
                                bonus_spawn_guard = 0;
                            }
                        }

                        if (creature_pool[creature_index].size > 16.0f) {
                            if (distance < 30.0f
                                && player_state_table[
                                    (int)*target_player
                                ].health > 0.0f
                                && bonus_energizer_timer <= 0.0f) {
                                if (*attack_cooldown <= 0.0f) {
                                    current_player_index = (int)*target_player;
                                    sfx_play_panned(
                                        creature_type_table[
                                            creature_pool[creature_index].type_id
                                        ].sfx_bank_b[crt_rand() % 2],
                                        position,
                                        1.0f);
                                    if (perk_count_get(perk_id_mr_melee) != 0) {
                                        creature_apply_damage(
                                            creature_index,
                                            25.0f,
                                            2,
                                            creature_vec2_t());
                                    }
                                    if (player_state_table[current_player_index].shield_timer
                                        <= 0.0f) {
                                        if (perk_count_get(perk_id_toxic_avenger) != 0) {
                                            creature_pool[creature_index].flags |= 3;
                                        } else if (perk_count_get(perk_id_veins_of_poison)
                                            != 0) {
                                            creature_pool[creature_index].flags |= 1;
                                        }
                                    }

                                    player_take_damage(
                                        current_player_index,
                                        creature_pool[creature_index].contact_damage);
                                    creature_vec2_t contact_delta(
                                        player_state_table[current_player_index].position.x - position->x,
                                        player_state_table[current_player_index].position.y - position->y);
                                    vec2_normalize_dispatch(
                                        (vec2f_t *)&contact_delta,
                                        (vec2f_t *)&contact_delta);
                                    creature_vec2_t impact(
                                        player_state_table[current_player_index].position.x
                                            + contact_delta.x * 3.0f,
                                        player_state_table[current_player_index].position.y
                                            + contact_delta.y * 3.0f);
                                    fx_queue_add_random((vec2f_t *)&impact);
                                    *attack_cooldown += 1.0f;
                                }

                                current_player_index = (int)*target_player;
                                if (player_state_table[current_player_index].plaguebearer_active
                                    && *health < 150.0f
                                    && plaguebearer_infection_count < 50) {
                                    *collision_flag = 1;
                                }
                            }
                        }

                        if (distance < 30.0f
                            && creature_pool[creature_index].size <= 30.0f) {
                            *health = 0.0f;
                            *lifecycle_stage -= frame_dt;
                        }
                    } else if (*lifecycle_stage > 0.0f) {
                        *lifecycle_stage -= frame_dt * 28.0f;
                        if (*lifecycle_stage <= 0.0f) {
                            if (!config_violence_disabled) {
                                unsigned char corpse_queued;
                                if ((creature_pool[creature_index].flags
                                        & CREATURE_FLAG_ANIM_PING_PONG) == 0
                                    || (creature_pool[creature_index].flags
                                        & CREATURE_FLAG_ANIM_LONG_STRIP) != 0) {
                                    float corpse_size =
                                        creature_pool[creature_index].size;
                                    float corpse_heading =
                                        creature_pool[creature_index].heading;
                                    corpse_queued = fx_queue_add_rotated(
                                        creature_vec2_t(
                                            position->x - corpse_size * 0.5f,
                                            position->y - corpse_size * 0.5f),
                                        &creature_pool[creature_index].color,
                                        corpse_heading,
                                        corpse_size,
                                        creature_pool[creature_index].type_id);
                                } else {
                                    float corpse_half_size =
                                        creature_pool[creature_index].size * 0.5f;
                                    corpse_queued = fx_queue_add_rotated(
                                        creature_vec2_t(
                                            position->x - corpse_half_size,
                                            position->y - corpse_half_size),
                                        &creature_pool[creature_index].color,
                                        creature_pool[creature_index].heading,
                                        creature_pool[creature_index].size,
                                        7);
                                }
                                if (!corpse_queued) {
                                    *lifecycle_stage = 0.001f;
                                    goto next_creature;
                                }
                            }

                            ++creature_kill_count;
                            if (!config_violence_disabled
                                && (creature_pool[creature_index].flags
                                    & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
                                int count = 8;
                                do {
                                    effect_spawn_blood_splatter(
                                        position,
                                        (float)(crt_rand() % 612) * 0.01f,
                                        0.0f);
                                } while (--count != 0);
                                count = 6;
                                do {
                                    effect_spawn_blood_splatter(
                                        position,
                                        (float)(crt_rand() % 612) * 0.01f,
                                        -0.07f);
                                } while (--count != 0);
                                count = 5;
                                do {
                                    effect_spawn_blood_splatter(
                                        position,
                                        (float)(crt_rand() % 612) * 0.01f,
                                        -0.12f);
                                } while (--count != 0);
                            }

                            if (cv_bodiesFade->value == 0.0f) {
                                creature_pool[creature_index].active = 0;
                            }
                        } else {
                            if ((creature_pool[creature_index].flags
                                    & CREATURE_FLAG_ANIM_PING_PONG) == 0
                                || (creature_pool[creature_index].flags
                                    & CREATURE_FLAG_ANIM_LONG_STRIP) != 0) {
                                double corpse_heading =
                                    creature_pool[creature_index].heading - 1.5707964f;
                                creature_pool[creature_index].vel_x =
                                    (float)cos(corpse_heading) * *lifecycle_stage
                                    * frame_dt * 9.0f;
                                creature_pool[creature_index].vel_y =
                                    (float)sin(corpse_heading) * *lifecycle_stage
                                    * frame_dt * 9.0f;
                                position->x -= creature_pool[creature_index].vel_x;
                                position->y -= creature_pool[creature_index].vel_y;
                            } else {
                                creature_pool[creature_index].vel_x = 0.0f;
                                creature_pool[creature_index].vel_y = 0.0f;
                            }
                        }
                    } else {
                        *lifecycle_stage -= frame_dt * 20.0f;
                    }
                }
            }
        }

next_creature:
        ;
    }
}
