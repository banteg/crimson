#include <math.h>

#define creature_apply_damage creature_apply_damage_pointer_abi
#define fx_queue_add_rotated fx_queue_add_rotated_pointer_abi
#include "crimsonland_gameplay.h"
#undef creature_apply_damage
#undef fx_queue_add_rotated

#define CRIMSONLAND_USE_ORIGINAL_CONFIG_OWNER
#include "crimsonland_config_owner.h"

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

    creature_vec2_t operator-(const creature_vec2_t &other)
    {
        return creature_vec2_t(x - other.x, y - other.y);
    }

    creature_vec2_t operator+(const creature_vec2_t &other)
    {
        return creature_vec2_t(x + other.x, y + other.y);
    }

    creature_vec2_t operator*(float scale)
    {
        return creature_vec2_t(x * scale, y * scale);
    }

    creature_vec2_t &operator-=(const creature_vec2_t &other)
    {
        x -= other.x;
        y -= other.y;
        return *this;
    }

};

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    float distance = (float)sqrt(distance_sq);
    return distance;
}

inline float creature_vec2_length(creature_vec2_t &value)
{
    float length = (float)sqrt(value.x * value.x + value.y * value.y);
    return length;
}

inline float creature_vec2_angle(const creature_vec2_t &value)
{
    return (float)atan2(value.y, value.x);
}

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
vec2f_t *__stdcall D3DXVec2Normalize(vec2f_t *dst, const vec2f_t *src);
}

extern "C" void creature_update_all(void)
{
    int creature_index;
    creature_t *creatures = creature_pool;
    float *lifecycle_stage;
    unsigned char *collision_flag;
    float *attack_cooldown;
    int spawn_limit;
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
        if (creatures[creature_index].active) {
            ++creature_active_count;
            if (creatures[creature_index].hit_flash_timer > 0.0f) {
                creatures[creature_index].hit_flash_timer -= frame_dt;
            }

            if (bonus_freeze_timer <= 0.0f) {
                health = &creatures[creature_index].health;
                if (creatures[creature_index].health <= 0.0f
                    && creatures[creature_index].lifecycle_stage == 16.0f) {
                    creatures[creature_index].lifecycle_stage -= frame_dt;
                }

                if ((creatures[creature_index].flags
                        & CREATURE_FLAG_SELF_DAMAGE_TICK_STRONG) != 0) {
                    creature_apply_damage(
                        creature_index,
                        frame_dt * 180.0f,
                        0,
                        creature_vec2_t());
                } else if ((creatures[creature_index].flags
                               & CREATURE_FLAG_SELF_DAMAGE_TICK) != 0) {
                    creature_apply_damage(
                        creature_index,
                        frame_dt * 60.0f,
                        0,
                        creature_vec2_t());
                }

                if ((creatures[creature_index].flags
                        & CREATURE_FLAG_AI7_LINK_TIMER) != 0) {
                    if (creatures[creature_index].link_index < 0) {
                        creatures[creature_index].link_index += frame_dt_ms;
                        if (creatures[creature_index].link_index >= 0) {
                            int hold_ms = crt_rand() & 0x1ff;
                            creatures[creature_index].ai_mode =
                                CREATURE_AI_HOLD_TIMER;
                            creatures[creature_index].link_index = hold_ms + 500;
                        }
                    } else {
                        creatures[creature_index].link_index -= frame_dt_ms;
                        if (creatures[creature_index].link_index <= 0) {
                            creatures[creature_index].link_index =
                                -700 - (crt_rand() & 0x3ff);
                        }
                    }
                }

                if (*health <= 0.0f
                    && creatures[creature_index].lifecycle_stage == 16.0f) {
                    creatures[creature_index].lifecycle_stage -= frame_dt;
                }

                {
                    signed char current_player =
                        creatures[creature_index].target_player;
                    int current_player_index = (int)current_player;
                    creature_t *creature = &creatures[creature_index];
                    vec2f_t *position = &creatures[creature_index].position;
                    distance = vec2_distance(
                        &player_state_table[current_player_index].position,
                        position);
                    float dx;
                    float dy;

                    if (creature_update_tick % 70 != 0) {
                        if (config_player_count == 2) {
                            if (player_state_table[1 - current_player_index].health > 0.0f) {
                                vec2f_t *alternate_pos =
                                    &player_state_table[1 - current_player_index].position;
                                alternate_distance = vec2_distance(alternate_pos, position);
                                if (alternate_distance < distance) {
                                    distance = alternate_distance;
                                    creatures[creature_index].target_player =
                                        1 - current_player;
                                }
                            }
                        } else {
                            alternate_distance = vec2_distance(
                                &player_state_table[0].position,
                                position);
                        }

                        current_player =
                            creatures[creature_index].target_player;
                        current_player_index = (int)current_player;
                        if (alternate_distance < vec2_distance(
                                &player_state_table[0].position,
                                &creature_pool[
                                    player_state_table[current_player_index].auto_target
                                ].position)) {
                            player_state_table[current_player_index].auto_target = creature_index;
                        }
                    }

                    if (player_state_table[current_player_index].health <= 0.0f) {
                        creatures[creature_index].target_player =
                            1 - current_player;
                    }

                    lifecycle_stage = &creatures[creature_index].lifecycle_stage;
                    if (creatures[creature_index].lifecycle_stage == 16.0f) {
                        collision_flag = &creatures[creature_index].collision_flag;
                        if (creatures[creature_index].collision_flag) {
                            float collision_timer =
                                creatures[creature_index].collision_timer - frame_dt;
                            creatures[creature_index].collision_timer = collision_timer;
                            if (collision_timer < 0.0f) {
                                creatures[creature_index].state_flag = 1;
                                creatures[creature_index].collision_timer =
                                    collision_timer + 0.5f;
                                *health -= 15.0f;
                                if (*health < 0.0f) {
                                    ++plaguebearer_infection_count;
                                    creature_handle_death(creature_index, 1);
                                    sfx_play_panned(
                                        creature_type_table[
                                            creatures[creature_index].type_id
                                        ].sfx_bank_b[crt_rand() % 2],
                                        position,
                                        1.0f);
                                }
                                fx_queue_add_random(position);
                            }
                        }

                        float phase_angle =
                            (float)creatures[creature_index].phase_seed * 3.7f;
                        phase_angle = phase_angle * 3.1415927f;
                        creatures[creature_index].force_target = 0;
                        move_scale = 1.0f;

                        if (creature_index
                            == player_state_table[0].evil_eyes_target_creature) {
                            goto next_creature;
                        }

                        int ai_mode = creatures[creature_index].ai_mode;
                        if (ai_mode == CREATURE_AI_ORBIT_PLAYER) {
                            if (distance > 800.0f) {
                                current_player_index = creatures[creature_index].target_player;
                                creatures[creature_index].target_x =
                                    player_state_table[current_player_index].position.x;
                                creatures[creature_index].target_y =
                                    player_state_table[current_player_index].position.y;
                            } else {
                                current_player_index = creatures[creature_index].target_player;
                                creatures[creature_index].target_x =
                                    (float)cos(phase_angle) * distance * 0.85f
                                    + player_state_table[current_player_index].position.x;
                                creatures[creature_index].target_y =
                                    (float)sin(phase_angle) * distance * 0.85f
                                    + player_state_table[current_player_index].position.y;
                            }
                        } else if (ai_mode == CREATURE_AI_ORBIT_PLAYER_WIDE) {
                            current_player_index =
                                creatures[creature_index].target_player;
                            creatures[creature_index].target_x =
                                (float)cos(phase_angle) * distance * 0.9f
                                + player_state_table[current_player_index].position.x;
                            creatures[creature_index].target_y =
                                (float)sin(phase_angle) * distance * 0.9f
                                + player_state_table[current_player_index].position.y;
                        } else if (ai_mode == CREATURE_AI_ORBIT_PLAYER_TIGHT) {
                            if (distance > 800.0f) {
                                current_player_index = creatures[creature_index].target_player;
                                creatures[creature_index].target_x =
                                    player_state_table[current_player_index].position.x;
                                creatures[creature_index].target_y =
                                    player_state_table[current_player_index].position.y;
                            } else {
                                current_player_index = creatures[creature_index].target_player;
                                creatures[creature_index].target_x =
                                    (float)cos(phase_angle) * distance * 0.55f
                                    + player_state_table[current_player_index].position.x;
                                creatures[creature_index].target_y =
                                    (float)sin(phase_angle) * distance * 0.55f
                                    + player_state_table[current_player_index].position.y;
                            }
                        } else if (ai_mode == CREATURE_AI_FOLLOW_LINK) {
                            linked_index = creatures[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                creatures[creature_index].target_x =
                                    creature_pool[linked_index].pos_x
                                    + creatures[creature_index].target_offset.x;
                                creatures[creature_index].target_y =
                                    creature_pool[linked_index].pos_y
                                    + creatures[creature_index].target_offset.y;
                            } else {
                                creatures[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                            }
                        } else if (ai_mode == CREATURE_AI_FOLLOW_LINK_TETHERED) {
                            linked_index = creatures[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                creatures[creature_index].target_x =
                                    creature_pool[linked_index].pos_x
                                    + creatures[creature_index].target_offset.x;
                                creatures[creature_index].target_y =
                                    creature_pool[linked_index].pos_y
                                    + creatures[creature_index].target_offset.y;
                                float target_distance = creature_vec2_length(
                                    *(creature_vec2_t *)&creatures[creature_index].target_x
                                    - *(creature_vec2_t *)position);
                                if (target_distance <= 64.0f) {
                                    move_scale = target_distance * 0.015625f;
                                }
                            } else {
                                creatures[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                                creature_apply_damage(
                                    creature_index,
                                    1000.0f,
                                    1,
                                    creature_vec2_t());
                            }
                        }

                        ai_mode = creatures[creature_index].ai_mode;
                        if (ai_mode == CREATURE_AI_LINK_GUARD) {
                            linked_index = creatures[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                if (distance > 800.0f) {
                                    current_player_index = creatures[creature_index].target_player;
                                    creatures[creature_index].target_x =
                                        player_state_table[current_player_index].position.x;
                                    creatures[creature_index].target_y =
                                        player_state_table[current_player_index].position.y;
                                } else {
                                    current_player_index = creatures[creature_index].target_player;
                                    creatures[creature_index].target_x =
                                        (float)cos(phase_angle) * distance * 0.85f
                                        + player_state_table[current_player_index].position.x;
                                    creatures[creature_index].target_y =
                                        (float)sin(phase_angle) * distance * 0.85f
                                        + player_state_table[current_player_index].position.y;
                                }
                            } else {
                                creatures[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                                creature_apply_damage(
                                    creature_index,
                                    1000.0f,
                                    1,
                                    creature_vec2_t());
                            }
                        } else if (ai_mode == CREATURE_AI_HOLD_TIMER) {
                            flags = creatures[creature_index].flags
                                & CREATURE_FLAG_AI7_LINK_TIMER;
                            if (flags == 0
                                || creatures[creature_index].link_index <= 0) {
                                if (creatures[creature_index].orbit_radius.radius <= 0.0f
                                    || flags != 0) {
                                    creatures[creature_index].ai_mode =
                                        CREATURE_AI_ORBIT_PLAYER;
                                } else {
                                    creature->orbit_radius.radius -= frame_dt;
                                    creature->target_position = creature->position;
                                }
                            } else {
                                creature->target_position = creature->position;
                            }
                        } else if (ai_mode == CREATURE_AI_ORBIT_LINK) {
                            linked_index = creatures[creature_index].link_index;
                            if (creature_pool[linked_index].health > 0.0f) {
                                float orbit_heading =
                                    creatures[creature_index].orbit_angle
                                    + creatures[creature_index].heading;
                                creatures[creature_index].target_x =
                                    (float)cos(orbit_heading)
                                    * creatures[creature_index].orbit_radius.radius
                                    + creature_pool[linked_index].pos_x;
                                creatures[creature_index].target_y =
                                    (float)sin(orbit_heading)
                                    * creatures[creature_index].orbit_radius.radius
                                    + creature_pool[linked_index].pos_y;
                            } else {
                                creatures[creature_index].ai_mode =
                                    CREATURE_AI_ORBIT_PLAYER;
                            }
                        }

                        dx = creatures[creature_index].target_x - position->x;
                        dy = creatures[creature_index].target_y - position->y;
                        if ((float)sqrt(dx * dx + dy * dy) < 40.0f) {
                            creatures[creature_index].force_target = 1;
                        }
                        dx = creatures[creature_index].target_x - position->x;
                        dy = creatures[creature_index].target_y - position->y;
                        if ((float)sqrt(dx * dx + dy * dy) > 400.0f) {
                            creatures[creature_index].force_target = 1;
                        }
                        if (creatures[creature_index].force_target
                            || creatures[creature_index].ai_mode
                                == CREATURE_AI_CHASE_PLAYER) {
                            current_player_index =
                                creatures[creature_index].target_player;
                            creatures[creature_index].target_position =
                                player_state_table[current_player_index].position;
                        }

                        creature_vec2_t &target_position =
                            *(creature_vec2_t *)&creatures[
                                creature_index
                            ].target_x;
                        float desired_heading = creature_vec2_angle(
                            target_position - *(creature_vec2_t *)position);
                        creatures[creature_index].target_heading =
                            (float)(desired_heading + 1.5707964f);
                        if ((bonus_energizer_timer > 0.0f
                                && creatures[creature_index].max_health < 500.0f)
                            || *collision_flag) {
                            creatures[creature_index].target_heading += 3.1415927f;
                        }

                        flags = creatures[creature_index].flags;
                        if ((flags & CREATURE_FLAG_ANIM_PING_PONG) != 0) {
                            if (position->x < creatures[creature_index].size) {
                                position->x = creatures[creature_index].size;
                            }
                            if (creatures[creature_index].pos_y < creatures[creature_index].size) {
                                creatures[creature_index].pos_y = creatures[creature_index].size;
                            }
                            float max_pos = 1024.0f - creatures[creature_index].size;
                            if (position->x > max_pos) {
                                position->x = max_pos;
                            }
                            if (creatures[creature_index].pos_y > max_pos) {
                                creatures[creature_index].pos_y = max_pos;
                            }

                            if ((flags & CREATURE_FLAG_ANIM_LONG_STRIP) == 0) {
                                creatures[creature_index].vel_x =
                                    creatures[creature_index].vel_y = 0.0f;
                            } else {
                                angle_approach(
                                    &creatures[creature_index].heading,
                                    creatures[creature_index].target_heading,
                                    4.0f * (creatures[creature_index].move_speed
                                        * 0.33333334f));
                                double movement_heading =
                                    creatures[creature_index].heading - 1.5707964f;
                                creatures[creature_index].vel_x =
                                    30.0f * creatures[creature_index].move_speed
                                    * (move_scale * (frame_dt * (float)cos(movement_heading)));
                                creatures[creature_index].vel_y =
                                    30.0f * creatures[creature_index].move_speed
                                    * (move_scale * (frame_dt * (float)sin(movement_heading)));
                                vec2_add_inplace(
                                    creature_index,
                                    position,
                                    &creatures[creature_index].velocity);
                            }

                            slot_index = creatures[creature_index].link_index;
                            creature_spawn_slot_t *spawn_slot =
                                &creature_spawn_slot_table[slot_index];
                            spawn_slot->timer_s -= frame_dt;
                            if (spawn_slot->timer_s < 0.0f) {
                                int spawn_count = spawn_slot->count;
                                spawn_limit = spawn_slot->limit;
                                spawn_slot->timer_s += spawn_slot->interval_s;
                                if (spawn_limit > spawn_count) {
                                    spawn_slot->count = spawn_count + 1;
                                    creature_spawn_template(
                                        spawn_slot->template_id,
                                        position,
                                        -100.0f);
                                }
                            }
                        } else if (creatures[creature_index].ai_mode
                            != CREATURE_AI_HOLD_TIMER) {
                            angle_approach(
                                &creatures[creature_index].heading,
                                creatures[creature_index].target_heading,
                                4.0f * (creatures[creature_index].move_speed
                                    * 0.33333334f));
                            double movement_heading =
                                creatures[creature_index].heading - 1.5707964f;
                            creatures[creature_index].vel_x =
                                30.0f * creatures[creature_index].move_speed
                                * (move_scale * (frame_dt * (float)cos(movement_heading)));
                            creatures[creature_index].vel_y =
                                30.0f * creatures[creature_index].move_speed
                                * (move_scale * (frame_dt * (float)sin(movement_heading)));
                            vec2_add_inplace(
                                creature_index,
                                position,
                                &creatures[creature_index].velocity);
                        }

                        if (perk_count_get(perk_id_plaguebearer) != 0
                            && plaguebearer_infection_count < 60) {
                            plaguebearer_spread_infection(creature_index);
                        }

                        float *size = &creatures[creature_index].size;
                        float anim_scale = 30.0f / creatures[creature_index].size;
                        if ((creatures[creature_index].flags
                                & CREATURE_FLAG_ANIM_PING_PONG) == 0
                            || (creatures[creature_index].flags
                                & CREATURE_FLAG_ANIM_LONG_STRIP) != 0) {
                            if (creatures[creature_index].ai_mode
                                != CREATURE_AI_HOLD_TIMER) {
                                creatures[creature_index].anim_phase +=
                                    anim_scale * (creature_type_table[
                                        creatures[creature_index].type_id
                                    ].anim_rate
                                    * creatures[creature_index].move_speed
                                    * frame_dt) * move_scale * 25.0f;
                                while (creatures[creature_index].anim_phase > 31.0f) {
                                    creatures[creature_index].anim_phase -= 31.0f;
                                }
                            }
                        } else {
                            creatures[creature_index].anim_phase +=
                                anim_scale * (creature_type_table[
                                    creatures[creature_index].type_id
                                ].anim_rate
                                * creatures[creature_index].move_speed
                                * frame_dt) * move_scale * 22.0f;
                            if (creatures[creature_index].anim_phase > 15.0f) {
                                do {
                                    creatures[creature_index].anim_phase -= 15.0f;
                                } while (creatures[creature_index].anim_phase > 15.0f);
                            }
                        }

                        attack_cooldown =
                            &creatures[creature_index].attack_cooldown;
                        if (creatures[creature_index].attack_cooldown > 0.0f) {
                            *attack_cooldown -= frame_dt;
                        } else {
                            *attack_cooldown = 0.0f;
                        }

                        signed char *target_player =
                            &creatures[creature_index].target_player;
                        float interaction_distance = creature_vec2_length(
                            *(creature_vec2_t *)position
                            - *(creature_vec2_t *)&player_state_table[*target_player].position);

                        if (interaction_distance < 100.0f
                            && perk_count_get(perk_id_radioactive) != 0) {
                            creatures[creature_index].collision_timer -=
                                frame_dt * 1.5f;
                            if (creatures[creature_index].collision_timer < 0.0f
                                && *health > 0.0f) {
                                creatures[creature_index].collision_timer = 0.5f;
                                creatures[creature_index].state_flag = 1;
                                *health -= (100.0f - interaction_distance) * 0.3f;
                                if (*health < 0.0f) {
                                    if (creatures[creature_index].type_id
                                        == CREATURE_TYPE_LIZARD) {
                                        *health = 1.0f;
                                    } else {
                                        player_state_table[0].experience = (int)(
                                            (float)player_state_table[0].experience
                                            + creatures[creature_index].reward_value);
                                        *lifecycle_stage -= frame_dt;
                                    }
                                }
                                fx_queue_add_random(position);
                            }
                        }

                        if (interaction_distance > 64.0f) {
                            if ((creatures[creature_index].flags
                                    & CREATURE_FLAG_RANGED_ATTACK_SHOCK) != 0
                                && *attack_cooldown <= 0.0f) {
                                projectile_spawn(
                                    position,
                                    creatures[creature_index].heading,
                                    PROJECTILE_TYPE_PLASMA_RIFLE,
                                    creature_index);
                                *attack_cooldown += 1.0f;
                                sfx_play_panned(
                                    sfx_shock_fire,
                                    position,
                                    1.0f);
                            }
                            if ((creatures[creature_index].flags
                                    & CREATURE_FLAG_RANGED_ATTACK_VARIANT) != 0
                                && *attack_cooldown <= 0.0f) {
                                projectile_spawn(
                                    position,
                                    creatures[creature_index].heading,
                                    creatures[creature_index].orbit_radius.projectile_type,
                                    creature_index);
                                random_cooldown = (float)(crt_rand() & 3);
                                *attack_cooldown += random_cooldown * 0.1f
                                    + creatures[creature_index].orbit_angle;
                                sfx_play_panned(
                                    sfx_plasmaminigun_fire,
                                    position,
                                    0.8f);
                            }
                        }

                        if (interaction_distance < 20.0f) {
                            position->x -= creatures[creature_index].vel_x;
                            position->y -= creatures[creature_index].vel_y;
                            if (creatures[creature_index].max_health < 380.0f
                                && bonus_energizer_timer > 0.0f) {
                                player_state_table[0].experience = (int)(
                                    (float)player_state_table[0].experience
                                    + creatures[creature_index].reward_value);
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

                        if (*size > 16.0f) {
                            if (interaction_distance < 30.0f
                                && player_state_table[*target_player].health > 0.0f
                                && bonus_energizer_timer <= 0.0f) {
                                if (*attack_cooldown <= 0.0f) {
                                    sfx_play_panned(
                                        creature_type_table[
                                            creatures[creature_index].type_id
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
                                    if (player_state_table[*target_player].shield_timer
                                        <= 0.0f) {
                                        if (perk_count_get(perk_id_toxic_avenger) != 0) {
                                            creatures[creature_index].flags |= 3;
                                        } else if (perk_count_get(perk_id_veins_of_poison)
                                            != 0) {
                                            creatures[creature_index].flags |= 1;
                                        }
                                    }

                                    player_take_damage(
                                        *target_player,
                                        creatures[creature_index].contact_damage);
                                    creature_vec2_t contact_delta =
                                        *(creature_vec2_t *)&player_state_table[*target_player].position
                                        - *(creature_vec2_t *)position;
                                    D3DXVec2Normalize(
                                        (vec2f_t *)&contact_delta,
                                        (vec2f_t *)&contact_delta);
                                    creature_vec2_t impact =
                                        *(creature_vec2_t *)&player_state_table[*target_player].position
                                        + contact_delta * 3.0f;
                                    fx_queue_add_random((vec2f_t *)&impact);
                                    *attack_cooldown += 1.0f;
                                }

                                if (player_state_table[*target_player].plaguebearer_active
                                    && *health < 150.0f
                                    && plaguebearer_infection_count < 50) {
                                    *collision_flag = 1;
                                }
                            }
                        }

                        if (interaction_distance < 30.0f
                            && *size <= 30.0f) {
                            *health = 0.0f;
                            *lifecycle_stage -= frame_dt;
                        }
                    } else if (*lifecycle_stage > 0.0f) {
                        float corpse_stage = *lifecycle_stage - frame_dt * 28.0f;
                        *lifecycle_stage = corpse_stage;
                        if (corpse_stage <= 0.0f) {
                            if (!config_violence_disabled) {
                                unsigned char corpse_queued;
                                if ((creatures[creature_index].flags
                                        & CREATURE_FLAG_ANIM_PING_PONG) == 0
                                    || (creatures[creature_index].flags
                                        & CREATURE_FLAG_ANIM_LONG_STRIP) != 0) {
                                    corpse_queued = fx_queue_add_rotated(
                                        *(creature_vec2_t *)position
                                            - creature_vec2_t(
                                                creatures[creature_index].size * 0.5f,
                                                creatures[creature_index].size * 0.5f),
                                        &creatures[creature_index].color,
                                        creatures[creature_index].heading,
                                        creatures[creature_index].size,
                                        creatures[creature_index].type_id);
                                } else {
                                    corpse_queued = fx_queue_add_rotated(
                                        *(creature_vec2_t *)position
                                            - creature_vec2_t(
                                                creatures[creature_index].size * 0.5f,
                                                creatures[creature_index].size * 0.5f),
                                        &creatures[creature_index].color,
                                        creatures[creature_index].heading,
                                        creatures[creature_index].size,
                                        7);
                                }
                                if (!corpse_queued) {
                                    *lifecycle_stage = 0.001f;
                                    goto next_creature;
                                }
                            }

                            ++creature_kill_count;
                            if (!config_violence_disabled
                                && (creatures[creature_index].flags
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
                                creatures[creature_index].active = 0;
                            }
                        } else {
                            if ((creatures[creature_index].flags
                                    & CREATURE_FLAG_ANIM_PING_PONG) == 0
                                || (creatures[creature_index].flags
                                    & CREATURE_FLAG_ANIM_LONG_STRIP) != 0) {
                                double corpse_heading =
                                    creatures[creature_index].heading - 1.5707964f;
                                creatures[creature_index].vel_x =
                                    (float)cos(corpse_heading) * corpse_stage
                                    * frame_dt * 9.0f;
                                creatures[creature_index].vel_y =
                                    (float)sin(corpse_heading) * corpse_stage
                                    * frame_dt * 9.0f;
                                *(creature_vec2_t *)position -=
                                    *(creature_vec2_t *)&creatures[creature_index].velocity;
                            } else {
                                creatures[creature_index].vel_x = 0.0f;
                                creatures[creature_index].vel_y = 0.0f;
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
