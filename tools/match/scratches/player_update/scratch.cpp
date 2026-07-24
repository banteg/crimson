#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

typedef vec2f_t player_update_vec2_t;

struct vec2_t {
    float x;
    float y;

    float *vec2_sub(float *dst, float *rhs);
};

extern "C" {
extern unsigned char console_open_flag;
extern unsigned char time_scale_active;
extern IGrim2D_cpp *grim_interface_ptr;
extern player_aim_screen_xy_t player_aim_screen_x;
extern float time_scale_factor;
extern float perk_man_bomb_trigger_interval_s;
extern float perk_fire_cough_trigger_interval_s;
extern float perk_hot_tempered_trigger_interval_s;
extern float player_spread_damping_gate;
extern float player_spread_damping_scalar;
extern int perk_id_sharpshooter;
extern int perk_id_anxious_loader;
extern int perk_id_stationary_reloader;
extern int perk_id_angry_reloader;
extern int perk_id_long_distance_runner;
extern int perk_id_hot_tempered;
extern int perk_id_fastshot;
extern int config_player_mode_flags[];
extern int config_aim_scheme[];
extern int config_player_count;
extern int config_key_reload;
extern int player_alt_move_key_forward;
extern int player_alt_move_key_backward;
extern int player_alt_turn_key_left;
extern int player_alt_turn_key_right;
extern float camera_offset_x;
extern float camera_offset_y;
extern cvar_float_t *cv_padAimDistMul;
extern int frame_dt_ms;
extern int player_alt_weapon_swap_cooldown_ms;
extern unsigned char survival_reward_fire_seen;
extern int weapon_ammo_class[];
extern int sfx_bloodspill_01;
extern int sfx_explosion_small;
extern int fire_bullets_primary_shot_sfx_id;
extern int fire_bullets_secondary_shot_sfx_id;
extern float fire_bullets_fallback_shot_cooldown;
extern float fire_bullets_fallback_spread_heat;

void effect_spawn_blood_splatter(
    const vec2f_t *pos,
    float angle,
    float age);
float vec2_length(const vec2f_t *v);
int fx_spawn_sprite(
    const vec2f_t *pos,
    const vec2f_t *vel,
    float scale);
bool input_primary_just_pressed(void);
bool input_aim_pov_left_active(void);
bool input_aim_pov_right_active(void);
float player_heading_approach_target(float target_heading);
vec2f_t *__stdcall vec2_normalize_dispatch(
    vec2f_t *dst,
    const vec2f_t *src);
void player_start_reload(void);
void player_take_damage(int player_index, float damage);
int fx_spawn_particle(
    const vec2f_t *pos,
    float angle,
    const vec2f_t *move,
    float intensity);
int fx_spawn_particle_slow(const vec2f_t *pos, float angle);
int fx_spawn_secondary_projectile(
    const vec2f_t *pos,
    float angle,
    secondary_projectile_type_id_t type_id);
}

static __inline void player_accelerate_move_speed(player_state_t *player)
{
    if (player_state_table[0].perk_counts[perk_id_long_distance_runner] > 0) {
        if (player->move_speed < 2.0f) {
            player->move_speed = player->move_speed + frame_dt * 4.0f;
        }
        player->move_speed = player->move_speed + frame_dt;
        if (player->move_speed > 2.8f) {
            player->move_speed = 2.8f;
        }
    } else {
        player->move_speed = player->move_speed + frame_dt * 5.0f;
        if (player->move_speed > 2.0f) {
            player->move_speed = 2.0f;
        }
    }
}

static __inline void player_decelerate_move_speed(player_state_t *player)
{
    player->move_speed = player->move_speed - frame_dt * 15.0f;
    if (player->move_speed < 0.0f) {
        player->move_speed = 0.0f;
    }
}

static __inline void player_apply_move_speed_cap(player_state_t *player)
{
    if (player->weapon_id == 7 && player->move_speed > 0.8f) {
        player->move_speed = 0.8f;
    }
}

extern "C" void player_update(void)
{
    float movement_heading;
    float angle_step;
    float scalar;
    player_update_vec2_t random_offset;
    player_update_vec2_t previous_pos;
    player_update_vec2_t movement_input;
    player_update_vec2_t scratch_pos;
    player_update_vec2_t move_delta;
    bool auto_fire;
    bool normal_fire_ready;
    bool perk_fire_ready;

    if (console_open_flag != 0) {
        return;
    }

    int player_index = render_overlay_player_index;
    *(player_update_vec2_t *)&player_aim_screen_x[player_index * 2] =
        *(player_update_vec2_t *)&ui_mouse_x;

    player_state_t *player = &player_state_table[player_index];
    vec2f_t *player_position = (vec2f_t *)&player->pos_x;
    float *muzzle_flash_alpha = &player->muzzle_flash_alpha;
    previous_pos.x = player_position->x;
    previous_pos.y = player_position->y;

    if (player->health <= 0.0f) {
        player->death_timer = player->death_timer - frame_dt * 20.0f;
        return;
    }

    if (player->speed_bonus_timer > 0.0f) {
        player->speed_multiplier = player->speed_multiplier + 1.0f;
    }

    if (player->low_health_timer != 100.0f && player->health < 20.0f) {
        player->low_health_timer = player->low_health_timer - frame_dt;
        if (player->low_health_timer < 0.0f) {
            scratch_pos.x =
                (float)cos(player->aim_heading + 1.5707964f - 0.5f) * -6.0f;
            scratch_pos.y =
                (float)sin(player->aim_heading + 1.5707964f - 0.5f) * -6.0f;
            scratch_pos.x += player_position->x;
            scratch_pos.y += player_position->y;
            float angle = player->aim_heading;
            effect_spawn_blood_splatter(&scratch_pos, angle, 0.0f);
            effect_spawn_blood_splatter(&scratch_pos, angle, 0.0f);
            effect_spawn_blood_splatter(&scratch_pos, angle, 0.0f);
            sfx_play_panned(
                (crt_rand() & 1) + sfx_bloodspill_01,
                player_position,
                1.0f);
            player->low_health_timer = 1.0f;
        }
    }

    *muzzle_flash_alpha = *muzzle_flash_alpha - (frame_dt + frame_dt);
    if (*muzzle_flash_alpha < 0.0f) {
        *muzzle_flash_alpha = 0.0f;
    }

    if (bonus_weapon_power_up_timer > 0.0f) {
        player->shot_cooldown = player->shot_cooldown - frame_dt * 1.5f;
    } else {
        player->shot_cooldown = player->shot_cooldown - frame_dt;
    }
    if (player->shot_cooldown < 0.0f) {
        player->shot_cooldown = 0.0f;
    }

    if (perk_count_get(perk_id_man_bomb) != 0) {
        player->man_bomb_timer = player->man_bomb_timer + frame_dt;
        if (player->man_bomb_timer > perk_man_bomb_trigger_interval_s) {
            int owner_id;
            if (cv_friendlyFire->value != 0.0f) {
                owner_id = -1 - render_overlay_player_index;
            } else {
                owner_id = -100;
            }

            int projectile_index = 0;
            do {
                if ((projectile_index & 1) != 0) {
                    projectile_spawn(
                        player_position,
                        (float)projectile_index * 0.7853982f
                            + (float)(crt_rand() % 0x32) * 0.01f
                            - 0.25f,
                        PROJECTILE_TYPE_ION_RIFLE,
                        owner_id);
                } else {
                    projectile_spawn(
                        player_position,
                        (float)projectile_index * 0.7853982f
                            + (float)(crt_rand() % 0x32) * 0.01f
                            - 0.25f,
                        PROJECTILE_TYPE_ION_MINIGUN,
                        owner_id);
                }
                ++projectile_index;
            } while (projectile_index < 8);

            sfx_play_panned(sfx_explosion_small, player_position, 1.0f);
            player->man_bomb_timer =
                player->man_bomb_timer - perk_man_bomb_trigger_interval_s;
            perk_man_bomb_trigger_interval_s = 4.0f;
        }
    } else {
        player->man_bomb_timer = 0.0f;
    }

    if (perk_count_get(perk_id_living_fortress) != 0) {
        player->living_fortress_timer =
            player->living_fortress_timer + frame_dt;
        if (player->living_fortress_timer > 30.0f) {
            player->living_fortress_timer = 30.0f;
        }
    } else {
        player->living_fortress_timer = 0.0f;
    }

    if (perk_count_get(perk_id_fire_caugh) != 0) {
        player->fire_cough_timer = player->fire_cough_timer + frame_dt;
        if (player->fire_cough_timer > perk_fire_cough_trigger_interval_s) {
            int owner_id;
            if (cv_friendlyFire->value != 0.0f) {
                owner_id = -1 - render_overlay_player_index;
            } else {
                owner_id = -100;
            }

            sfx_play_panned(
                fire_bullets_primary_shot_sfx_id,
                player_position,
                1.0f);
            sfx_play_panned(
                fire_bullets_secondary_shot_sfx_id,
                player_position,
                1.0f);

            float aim_heading = player->aim_heading;
            float muzzle_heading = aim_heading - 1.5707964f - 0.150915f;
            movement_input.x = (float)cos(muzzle_heading) * 16.0f;
            movement_input.y = (float)sin(muzzle_heading) * 16.0f;

            random_offset.x = player->aim_x;
            random_offset.y = player->aim_y;
            move_delta.x = random_offset.x - player_position->x;
            move_delta.y = random_offset.y - player_position->y;
            float spread_radius = vec2_length(&move_delta) * 0.5f;
            float spread_angle =
                (float)(crt_rand() & 0x1ff) * 0.012271847f;
            spread_radius = spread_radius * player->spread_heat
                * (float)(crt_rand() & 0x1ff) * 0.001953125f;
            random_offset.x = (float)cos(spread_angle) * spread_radius
                + random_offset.x;
            random_offset.y = (float)sin(spread_angle) * spread_radius
                + random_offset.y;

            ((vec2_t *)player_position)->vec2_sub(
                &scratch_pos.x,
                &random_offset.x);
            float shot_heading =
                (float)atan2(scratch_pos.y, scratch_pos.x) - 1.5707964f;
            movement_input.x = movement_input.x + player_position->x;
            movement_input.y = movement_input.y + player_position->y;
            projectile_spawn(
                &movement_input,
                shot_heading,
                PROJECTILE_TYPE_FIRE_BULLETS,
                owner_id);

            move_delta.x = (float)cos(aim_heading) * 25.0f;
            move_delta.y = (float)sin(aim_heading) * 25.0f;
            int effect_index = fx_spawn_sprite(&movement_input, &move_delta, 1.0f);
            sprite_effect_pool[effect_index].color_r = 0.5f;
            sprite_effect_pool[effect_index].color_g = 0.5f;
            sprite_effect_pool[effect_index].color_b = 0.5f;
            sprite_effect_pool[effect_index].color_a = 0.413f;

            player->fire_cough_timer =
                player->fire_cough_timer - perk_fire_cough_trigger_interval_s;
            perk_fire_cough_trigger_interval_s =
                (float)(crt_rand() % 4) + 2.0f;
        }
    } else {
        player->fire_cough_timer = 0.0f;
    }

    if (perk_count_get(perk_id_hot_tempered) != 0) {
        player->hot_tempered_timer = player->hot_tempered_timer + frame_dt;
        if (player->hot_tempered_timer > perk_hot_tempered_trigger_interval_s) {
            int owner_id;
            if (cv_friendlyFire->value != 0.0f) {
                owner_id = -1 - render_overlay_player_index;
            } else {
                owner_id = -100;
            }

            int projectile_index = 0;
            do {
                projectile_spawn(
                    player_position,
                    (float)projectile_index * 0.7853982f,
                    (projectile_index & 1) != 0
                        ? PROJECTILE_TYPE_PLASMA_RIFLE
                        : PROJECTILE_TYPE_PLASMA_MINIGUN,
                    owner_id);
                ++projectile_index;
            } while (projectile_index < 8);

            sfx_play_panned(sfx_explosion_small, player_position, 1.0f);
            player->hot_tempered_timer =
                player->hot_tempered_timer - perk_hot_tempered_trigger_interval_s;
            perk_hot_tempered_trigger_interval_s =
                (float)(crt_rand() % 8) + 2.0f;
        }
    } else {
        player->hot_tempered_timer = 0.0f;
    }

    if (player_spread_damping_gate > 0.0f) {
        player_spread_damping_scalar =
            player_spread_damping_scalar - frame_dt;
        if (player_spread_damping_scalar < 0.3f) {
            player_spread_damping_scalar = 0.3f;
        }
    } else {
        player_spread_damping_scalar =
            frame_dt * 0.8f + player_spread_damping_scalar;
        if (player_spread_damping_scalar > 1.0f) {
            player_spread_damping_scalar = 1.0f;
        }
    }

    scalar = player->speed_multiplier;
    scratch_pos.x = 0.0f;
    scratch_pos.y = 0.0f;
    player->move_dx = scratch_pos.x;
    player->move_dy = scratch_pos.y;
    if (time_scale_active != 0) {
        frame_dt = (0.6f / time_scale_factor) * frame_dt;
    }

    if (demo_mode_active != 0
        || config_player_mode_flags[render_overlay_player_index] == 5
        || config_aim_scheme[render_overlay_player_index] == 5) {
        if (player->auto_target < 0) {
            player->auto_target = 0;
        }

        int target_index = player->auto_target;
        float nearest_distance;
        if (!creature_pool[target_index].active
            || creature_pool[target_index].health <= 0.0f) {
            nearest_distance = 100000.0f;
        } else {
            nearest_distance = (float)sqrt(
                (player_position->y - creature_pool[target_index].pos_y)
                        * (player_position->y
                            - creature_pool[target_index].pos_y)
                    + (player_position->x - creature_pool[target_index].pos_x)
                        * (player_position->x
                            - creature_pool[target_index].pos_x));
        }

        int creature_index = 0;
        creature_t *candidate = creature_pool;
        do {
            if (candidate->active && candidate->health > 0.0f) {
                float distance = (float)sqrt(
                    (player_position->y - candidate->pos_y)
                            * (player_position->y - candidate->pos_y)
                        + (player_position->x - candidate->pos_x)
                            * (player_position->x - candidate->pos_x));
                if (distance < nearest_distance - 64.0f) {
                    player->auto_target = creature_index;
                    nearest_distance = distance;
                }
            }
            ++candidate;
            ++creature_index;
        } while ((int)candidate < (int)&creature_pool[384]);
    }

    if (demo_mode_active == 0
        && config_player_mode_flags[render_overlay_player_index] != 5) {
        int move_mode = config_player_mode_flags[render_overlay_player_index];
        if (move_mode == 4) {
            if (grim_interface_ptr->grim_is_key_active(config_key_reload)) {
                scratch_pos.y =
                    player_aim_screen_x[render_overlay_player_index * 2 + 1]
                    - camera_offset_y;
                scratch_pos.x =
                    player_aim_screen_x[render_overlay_player_index * 2]
                    - camera_offset_x;
                player->move_target_x = scratch_pos.x;
                player->move_target_y = scratch_pos.y;
            }

            bool moving_to_target = false;
            if (player->move_target_x != -1.0f) {
                scratch_pos.y = player_position->y - player->move_target_y;
                scratch_pos.x = player_position->x - player->move_target_x;
                if ((float)sqrt(
                        scratch_pos.y * scratch_pos.y
                        + scratch_pos.x * scratch_pos.x)
                    > 20.0f) {
                    movement_heading =
                        (float)atan2(scratch_pos.y, scratch_pos.x)
                        - 1.5707964f;
                    while (movement_heading < 0.0f) {
                        movement_heading = movement_heading + 6.2831855f;
                    }
                    if (movement_heading != -1.0f) {
                        angle_step = player_heading_approach_target(
                            movement_heading);
                        player_accelerate_move_speed(player);
                        player_apply_move_speed_cap(player);

                        movement_heading = 3.1415927f - angle_step;
                        player->move_dx =
                            (float)cos(player->heading - 1.5707964f)
                            * player->move_speed * movement_heading
                            * scalar * 7.957747f;
                        player->move_dy =
                            (float)sin(player->heading - 1.5707964f)
                            * player->move_speed * movement_heading
                            * scalar * 7.957747f;
                        movement_input.x = frame_dt * player->move_dx;
                        movement_input.y = frame_dt * player->move_dy;
                        moving_to_target = true;
                    }
                }
            }

            if (!moving_to_target) {
                player_decelerate_move_speed(player);
                player->move_dx =
                    (float)cos(player->heading - 1.5707964f)
                    * player->move_speed * scalar * 25.0f;
                player->move_dy =
                    (float)sin(player->heading - 1.5707964f)
                    * player->move_speed * scalar * 25.0f;
                movement_input.x = frame_dt * player->move_dx;
                movement_input.y = frame_dt * player->move_dy;
            }

            player_apply_move_with_spawn_avoidance(
                render_overlay_player_index,
                player_position,
                &movement_input);
            player->move_phase =
                frame_dt * player->move_speed * 19.0f + player->move_phase;
        } else if (move_mode == 3) {
            movement_input.y = -grim_interface_ptr->grim_get_config_float(
                player->input.axis_move_y);
            movement_input.x = -grim_interface_ptr->grim_get_config_float(
                player->input.axis_move_x);

            if ((float)sqrt(
                    movement_input.x * movement_input.x
                    + movement_input.y * movement_input.y)
                > 0.2f) {
                vec2_normalize_dispatch(&movement_input, &movement_input);
                movement_heading =
                    (float)atan2(movement_input.y, movement_input.x)
                    - 1.5707964f;
                while (movement_heading < 0.0f) {
                    movement_heading = movement_heading + 6.2831855f;
                }
                if (movement_heading != -1.0f) {
                    angle_step = player_heading_approach_target(
                        movement_heading);
                    player_accelerate_move_speed(player);
                    player_apply_move_speed_cap(player);

                    movement_heading = 3.1415927f - angle_step;
                    player->move_dx =
                        (float)cos(player->heading - 1.5707964f)
                        * player->move_speed * movement_heading * scalar
                        * 7.957747f;
                    player->move_dy =
                        (float)sin(player->heading - 1.5707964f)
                        * player->move_speed * movement_heading * scalar
                        * 7.957747f;
                    move_delta.x = frame_dt * player->move_dx;
                    move_delta.y = frame_dt * player->move_dy;
                } else {
                    player_decelerate_move_speed(player);
                    player->move_dx =
                        (float)cos(player->heading - 1.5707964f)
                        * player->move_speed * scalar * 25.0f;
                    player->move_dy =
                        (float)sin(player->heading - 1.5707964f)
                        * player->move_speed * scalar * 25.0f;
                    move_delta.x = frame_dt * player->move_dx;
                    move_delta.y = frame_dt * player->move_dy;
                }
            } else {
                player_decelerate_move_speed(player);
                player->move_dx =
                    (float)cos(player->heading - 1.5707964f)
                    * player->move_speed * scalar * 25.0f;
                player->move_dy =
                    (float)sin(player->heading - 1.5707964f)
                    * player->move_speed * scalar * 25.0f;
                move_delta.x = frame_dt * player->move_dx;
                move_delta.y = frame_dt * player->move_dy;
            }

            player_apply_move_with_spawn_avoidance(
                render_overlay_player_index,
                player_position,
                &move_delta);
            player->move_phase =
                frame_dt * player->move_speed * 19.0f + player->move_phase;
        } else if (move_mode == 1) {
            bool turned = false;
            movement_heading = 1.0f;
            if (player->turn_speed < 1.0f) {
                player->turn_speed = 1.0f;
            }
            if (player->turn_speed > 7.0f) {
                player->turn_speed = 7.0f;
            }

            int turn_left = grim_interface_ptr->grim_is_key_active(
                player->input.turn_key_left);
            if (!turn_left && config_player_count == 1) {
                turn_left = grim_interface_ptr->grim_is_key_down(
                    (unsigned char)player_alt_turn_key_left);
            }
            if (turn_left) {
                player->turn_speed = player->turn_speed + frame_dt * 10.0f;
                player->heading = player->heading
                    - player->turn_speed * frame_dt * 0.5f;
                player->aim_heading = player->aim_heading
                    - player->turn_speed * frame_dt * 0.5f;
                turned = true;
            } else {
                int turn_right = grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_right);
                if (!turn_right && config_player_count == 1) {
                    turn_right = grim_interface_ptr->grim_is_key_down(
                        (unsigned char)player_alt_turn_key_right);
                }
                if (turn_right) {
                    player->turn_speed =
                        player->turn_speed + frame_dt * 10.0f;
                    player->heading = player->heading
                        + player->turn_speed * frame_dt * 0.5f;
                    player->aim_heading = player->aim_heading
                        + player->turn_speed * frame_dt * 0.5f;
                    turned = true;
                }
            }

            int move_forward = grim_interface_ptr->grim_is_key_active(
                player->input.move_key_forward);
            if (!move_forward && config_player_count == 1) {
                move_forward = grim_interface_ptr->grim_is_key_down(
                    (unsigned char)player_alt_move_key_forward);
            }
            if (move_forward) {
                player_accelerate_move_speed(player);
                player_apply_move_speed_cap(player);
                player->move_dx =
                    (float)cos(player->heading - 1.5707964f)
                    * player->move_speed * 25.0f;
                player->move_dy =
                    (float)sin(player->heading - 1.5707964f)
                    * player->move_speed * 25.0f;
                move_delta.x = frame_dt * player->move_dx;
                move_delta.y = frame_dt * player->move_dy;
            } else {
                int move_backward = grim_interface_ptr->grim_is_key_active(
                    player->input.move_key_backward);
                if (!move_backward && config_player_count == 1) {
                    move_backward = grim_interface_ptr->grim_is_key_down(
                        (unsigned char)player_alt_move_key_backward);
                }
                if (move_backward) {
                    player_accelerate_move_speed(player);
                    movement_heading = -1.0f;
                    player->move_dx =
                        (float)cos(player->heading - 1.5707964f)
                        * player->move_speed * -25.0f;
                    player->move_dy =
                        (float)sin(player->heading - 1.5707964f)
                        * player->move_speed * -25.0f;
                    move_delta.x = frame_dt * player->move_dx;
                    move_delta.y = frame_dt * player->move_dy;
                } else {
                    if (!turned) {
                        player->turn_speed = 1.0f;
                    }
                    player_decelerate_move_speed(player);
                    player->move_dx =
                        (float)cos(player->heading - 1.5707964f)
                        * player->move_speed * 25.0f;
                    player->move_dy =
                        (float)sin(player->heading - 1.5707964f)
                        * player->move_speed * 25.0f;
                    move_delta.x = frame_dt * player->move_dx;
                    move_delta.y = frame_dt * player->move_dy;
                }
            }

            player_apply_move_with_spawn_avoidance(
                render_overlay_player_index,
                player_position,
                &move_delta);
            player->move_phase = movement_heading * player->move_speed * frame_dt
                * 19.0f + player->move_phase;
        } else if (move_mode == 2) {
            movement_heading = -1.0f;

            if (grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_left)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_active(
                        player_alt_turn_key_left))) {
                movement_heading = 4.712389f;
            }
            if (grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_right)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_active(
                        player_alt_turn_key_right))) {
                movement_heading = 1.5707964f;
            }

            if (grim_interface_ptr->grim_is_key_active(
                    player->input.move_key_forward)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_active(
                        player_alt_move_key_forward))) {
                if (grim_interface_ptr->grim_is_key_active(
                        player->input.turn_key_left)
                    || (config_player_count == 1
                        && grim_interface_ptr->grim_is_key_active(
                            player_alt_turn_key_left))) {
                    movement_heading = 5.497787f;
                } else if (grim_interface_ptr->grim_is_key_active(
                               player->input.turn_key_right)
                    || (config_player_count == 1
                        && grim_interface_ptr->grim_is_key_active(
                            player_alt_turn_key_right))) {
                    movement_heading = 0.7853982f;
                } else {
                    movement_heading = 0.0f;
                }
            }

            if (grim_interface_ptr->grim_is_key_active(
                    player->input.move_key_backward)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_active(
                        player_alt_move_key_backward))) {
                if (grim_interface_ptr->grim_is_key_active(
                        player->input.turn_key_left)
                    || (config_player_count == 1
                        && grim_interface_ptr->grim_is_key_active(
                            player_alt_turn_key_left))) {
                    movement_heading = 3.926991f;
                } else if (grim_interface_ptr->grim_is_key_active(
                               player->input.turn_key_right)
                    || (config_player_count == 1
                        && grim_interface_ptr->grim_is_key_active(
                            player_alt_turn_key_right))) {
                    movement_heading = 2.3561945f;
                } else {
                    movement_heading = 3.1415927f;
                }
            }

            if (movement_heading == -1.0f) {
                player_decelerate_move_speed(player);
                player->move_dx =
                    (float)cos(player->heading - 1.5707964f)
                    * player->move_speed * scalar * 25.0f;
                player->move_dy =
                    (float)sin(player->heading - 1.5707964f)
                    * player->move_speed * scalar * 25.0f;
            } else {
                angle_step = player_heading_approach_target(movement_heading);
                player->aim_heading =
                    player->aim_heading + player_heading_turn_delta;
                player_accelerate_move_speed(player);
                player_apply_move_speed_cap(player);

                movement_heading = 3.1415927f - angle_step;
                player->move_dx =
                    (float)cos(player->heading - 1.5707964f)
                    * player->move_speed * movement_heading * scalar
                    * 7.957747f;
                player->move_dy =
                    (float)sin(player->heading - 1.5707964f)
                    * player->move_speed * movement_heading * scalar
                    * 7.957747f;
            }
            move_delta.x = frame_dt * player->move_dx;
            move_delta.y = frame_dt * player->move_dy;
            player_apply_move_with_spawn_avoidance(
                render_overlay_player_index,
                player_position,
                &move_delta);
            player->move_phase = frame_dt * player->move_speed * 19.0f
                + player->move_phase;
        }
    } else {
        if (player->auto_target < 0
            || creature_pool[player->auto_target].health <= 0.0f) {
            movement_heading = (float)atan2(
                player_position->y - 512.0f,
                player_position->x - 512.0f) + 3.1415927f;
        } else {
            if ((float)sqrt(
                    (player_position->y - 512.0f)
                            * (player_position->y - 512.0f)
                        + (player_position->x - 512.0f)
                            * (player_position->x - 512.0f))
                <= 300.0f) {
                scratch_pos.y = player_position->y
                    - creature_pool[player->auto_target].pos_y;
                scratch_pos.x = player_position->x
                    - creature_pool[player->auto_target].pos_x;
            } else {
                scratch_pos.y = player_position->y - 512.0f;
                scratch_pos.x = player_position->x - 512.0f;
            }
            movement_input.x = scratch_pos.x;
            movement_input.y = scratch_pos.y;
            movement_heading = (float)atan2(
                movement_input.y,
                movement_input.x) - 1.5707964f;
        }

        if (movement_heading == -1.0f) {
            player_decelerate_move_speed(player);
            player->move_dx =
                (float)cos(player->heading - 1.5707964f)
                * player->move_speed * scalar * 25.0f;
            player->move_dy =
                (float)sin(player->heading - 1.5707964f)
                * player->move_speed * scalar * 25.0f;
        } else {
            angle_step = player_heading_approach_target(
                movement_heading);
            player_accelerate_move_speed(player);
            player_apply_move_speed_cap(player);

            movement_heading = 3.1415927f - angle_step;
            player->move_dx =
                (float)cos(player->heading - 1.5707964f)
                * player->move_speed * movement_heading * scalar
                * 7.957747f;
            player->move_dy =
                (float)sin(player->heading - 1.5707964f)
                * player->move_speed * movement_heading * scalar
                * 7.957747f;
        }
        move_delta.x = frame_dt * player->move_dx;
        move_delta.y = frame_dt * player->move_dy;
        player_apply_move_with_spawn_avoidance(
            render_overlay_player_index,
            player_position,
            &move_delta);
        player->move_phase =
            frame_dt * player->move_speed * 19.0f + player->move_phase;
    }

    if (time_scale_active != 0) {
        frame_dt = time_scale_factor * frame_dt * 1.6666666f;
    }

    if (perk_count_get(perk_id_sharpshooter) == 0) {
        player->spread_heat = player->spread_heat - frame_dt * 0.4f;
        if (player->spread_heat < 0.01f) {
            player->spread_heat = 0.01f;
        }
    } else {
        player->spread_heat = player->spread_heat - (frame_dt + frame_dt);
        if (player->spread_heat < 0.25f) {
            player->spread_heat = 0.25f;
        }
        player->spread_heat = 0.02f;
    }

    if (perk_count_get(perk_id_anxious_loader) != 0
        && input_primary_just_pressed()
        && player->reload_timer > 0.0f) {
        player->reload_timer = player->reload_timer - 0.05f;
        if (player->reload_timer <= 0.0f) {
            player->reload_timer = frame_dt * 0.8f;
        }
    }

    if (player->reload_timer - frame_dt < 0.0f
        && player->reload_timer > 0.0f) {
        player->ammo = player->clip_size;
    }

    scalar = 1.0f;
    if (player_position->x == previous_pos.x && player_position->y == previous_pos.y) {
        if (perk_count_get(perk_id_stationary_reloader) != 0) {
            scalar = 3.0f;
        }
    } else {
        player->man_bomb_timer = 0.0f;
        player->living_fortress_timer = 0.0f;
    }

    if (perk_count_get(perk_id_angry_reloader) == 0
        || player->reload_timer_max <= 0.5f
        || player->reload_timer <= player->reload_timer_max * 0.5f) {
        player->reload_timer = player->reload_timer - scalar * frame_dt;
    } else {
        player->reload_timer = player->reload_timer - scalar * frame_dt;
        if (player->reload_timer <= player->reload_timer_max * 0.5f) {
            int owner_id;
            bonus_spawn_guard = 1;
            if (cv_friendlyFire->value != 0.0f) {
                owner_id = -1 - render_overlay_player_index;
            } else {
                owner_id = -100;
            }

            int projectile_count =
                7 - (int)(player->reload_timer_max * -4.0f);
            int projectile_index = 0;
            if (projectile_count > 0) {
                angle_step = 6.2831855f / (float)projectile_count;
                do {
                    projectile_spawn(
                        player_position,
                        (float)projectile_index * angle_step + 0.1f,
                        PROJECTILE_TYPE_PLASMA_MINIGUN,
                        owner_id);
                    ++projectile_index;
                } while (projectile_index < projectile_count);
            }
            bonus_spawn_guard = 0;
            sfx_play_panned(sfx_explosion_small, player_position, 1.0f);
        }
    }

    if (player->reload_timer < 0.0f) {
        player->reload_timer = 0.0f;
    }

    if (demo_mode_active == 0
        && perk_count_get(perk_id_alternate_weapon) == 0
        && config_player_mode_flags[render_overlay_player_index] != 4
        && grim_interface_ptr->grim_is_key_active(config_key_reload)
        && player->reload_timer == 0.0f
        && config_player_count == 1) {
        player_start_reload();
    }

    auto_fire = false;
    if (demo_mode_active == 0
        && config_aim_scheme[render_overlay_player_index] != 5) {
        int aim_scheme = config_aim_scheme[render_overlay_player_index];
        if (aim_scheme == 0) {
            scratch_pos.y =
                player_aim_screen_x[render_overlay_player_index * 2 + 1]
                - camera_offset_y;
            scratch_pos.x =
                player_aim_screen_x[render_overlay_player_index * 2]
                - camera_offset_x;
            player->aim_x = scratch_pos.x;
            player->aim_y = scratch_pos.y;
        } else if (aim_scheme == 4) {
            movement_input.y = grim_interface_ptr->grim_get_config_float(
                player->input.axis_aim_y);
            movement_input.x = grim_interface_ptr->grim_get_config_float(
                player->input.axis_aim_x);
            scalar = (float)sqrt(
                movement_input.y * movement_input.y
                + movement_input.x * movement_input.x);
            if (scalar > 1.0f) {
                scalar = 1.0f;
            }
            vec2_normalize_dispatch(&movement_input, &movement_input);
            scalar = scalar * cv_padAimDistMul->value + 42.0f;
            move_delta.x = scalar * movement_input.x;
            scratch_pos.y =
                scalar * movement_input.y + player_position->y;
            scratch_pos.x = move_delta.x + player_position->x;
            player->aim_x = scratch_pos.x;
            player->aim_y = scratch_pos.y;
        } else if (aim_scheme == 3) {
            movement_input.y =
                player_aim_screen_x[render_overlay_player_index * 2 + 1]
                - 200.0f;
            movement_input.x =
                player_aim_screen_x[render_overlay_player_index * 2]
                - 200.0f;
            if (movement_input.x != 0.0f || movement_input.y != 0.0f) {
                player->aim_heading =
                    (float)atan2(movement_input.y, movement_input.x)
                    + 1.5707964f;
                random_offset.x = player->aim_heading - 1.5707964f;
                move_delta.y = (float)sin(random_offset.x);
                scratch_pos.y = move_delta.y * 60.0f + player_position->y;
                scratch_pos.x =
                    (float)cos(random_offset.x) * 60.0f + player_position->x;
                player->aim_x = scratch_pos.x;
                player->aim_y = scratch_pos.y;
            }
            if ((float)sqrt(
                    movement_input.x * movement_input.x
                    + movement_input.y * movement_input.y)
                > 30.0f) {
                vec2_normalize_dispatch(
                    &movement_input,
                    &movement_input);
                move_delta.y = movement_input.y * 30.0f;
                scratch_pos.x = movement_input.x * 30.0f + 200.0f;
                scratch_pos.y = move_delta.y + 200.0f;
                player_aim_screen_x[render_overlay_player_index * 2] =
                    scratch_pos.x;
                player_aim_screen_x[render_overlay_player_index * 2 + 1] =
                    scratch_pos.y;
            }
        } else if (aim_scheme == 1) {
            int move_mode =
                config_player_mode_flags[render_overlay_player_index];
            if (move_mode == 1 || move_mode == 2) {
                if (grim_interface_ptr->grim_is_key_active(
                        player->input.aim_key_right)) {
                    player->aim_heading =
                        player->aim_heading + frame_dt * 3.0f;
                }
                if (grim_interface_ptr->grim_is_key_active(
                        player->input.aim_key_left)) {
                    player->aim_heading =
                        player->aim_heading - frame_dt * 3.0f;
                }
                random_offset.x = player->aim_heading - 1.5707964f;
                move_delta.y = (float)sin(random_offset.x);
                scratch_pos.y = move_delta.y * 60.0f + player_position->y;
                scratch_pos.x =
                    (float)cos(random_offset.x) * 60.0f + player_position->x;
                player->aim_x = scratch_pos.x;
                player->aim_y = scratch_pos.y;
            }
        } else {
            if (input_aim_pov_left_active()) {
                player->aim_heading =
                    player->aim_heading - frame_dt * 4.0f;
            }
            if (input_aim_pov_right_active()) {
                player->aim_heading =
                    player->aim_heading + frame_dt * 4.0f;
            }
            random_offset.x = player->aim_heading - 1.5707964f;
            move_delta.y = (float)sin(random_offset.x);
            scratch_pos.y = move_delta.y * 60.0f + player_position->y;
            scratch_pos.x =
                (float)cos(random_offset.x) * 60.0f + player_position->x;
            player->aim_x = scratch_pos.x;
            player->aim_y = scratch_pos.y;
        }
    } else {
        int target_index = player->auto_target;
        movement_input.y =
            creature_pool[target_index].pos_y - player->aim_y;
        movement_input.x =
            creature_pool[target_index].pos_x - player->aim_x;
        scalar = (float)sqrt(
            movement_input.y * movement_input.y
            + movement_input.x * movement_input.x);
        if (scalar >= 4.0f) {
            vec2_normalize_dispatch(&movement_input, &movement_input);
            angle_step = (scalar * 6.0f) * frame_dt;
            move_delta.x = movement_input.x * angle_step;
            player->aim_x = player->aim_x + move_delta.x;
            player->aim_y = player->aim_y + movement_input.y * angle_step;
        } else {
            player->aim_x = creature_pool[target_index].pos_x;
            player->aim_y = creature_pool[target_index].pos_y;
        }
        if (scalar < 128.0f && creature_pool[target_index].health > 0.0f) {
            auto_fire = true;
        }
    }

    player->aim_heading =
        (float)atan2(
            player_position->y - player->aim_y,
            player_position->x - player->aim_x)
        - 1.5707964f;

    normal_fire_ready = false;
    perk_fire_ready = false;
    if (player->shot_cooldown <= 0.0f && player->reload_timer == 0.0f) {
        normal_fire_ready = true;
        player->reload_active = 0;
    }
    if (player->shot_cooldown <= 0.0f
        && player->experience > 0
        && (perk_count_get(perk_id_regression_bullets) != 0
            || perk_count_get(perk_id_ammunition_within) != 0)) {
        perk_fire_ready = true;
    }

    if (perk_count_get(perk_id_alternate_weapon) != 0) {
        if ((player_alt_weapon_swap_cooldown_ms < 1
                || (player_alt_weapon_swap_cooldown_ms =
                        player_alt_weapon_swap_cooldown_ms - frame_dt_ms,
                    player_alt_weapon_swap_cooldown_ms < 1))
            && grim_interface_ptr->grim_is_key_active(config_key_reload)) {
            int swap_weapon_id = player->alt_weapon_id;
            player->alt_weapon_id = player->weapon_id;
            player->weapon_id = swap_weapon_id;

            float swap_clip_size = player->alt_clip_size;
            player->alt_clip_size = player->clip_size;
            player->clip_size = swap_clip_size;

            unsigned char swap_reload_active = player->alt_reload_active;
            player->alt_reload_active = player->reload_active;
            player->reload_active = swap_reload_active;

            float swap_ammo = player->alt_ammo;
            player->alt_ammo = player->ammo;
            player->ammo = swap_ammo;

            float swap_reload_timer = player->alt_reload_timer;
            player->alt_reload_timer = player->reload_timer;
            player->reload_timer = swap_reload_timer;

            float swap_shot_cooldown = player->alt_shot_cooldown;
            player->alt_shot_cooldown = player->shot_cooldown;
            player->shot_cooldown = swap_shot_cooldown;

            float swap_reload_timer_max = player->alt_reload_timer_max;
            player->alt_reload_timer_max = player->reload_timer_max;
            player->reload_timer_max = swap_reload_timer_max;

            sfx_play_panned(
                weapon_table[player->weapon_id].reload_sfx_id,
                player_position,
                1.0f);
            player->shot_cooldown = player->shot_cooldown + 0.1f;
            player_alt_weapon_swap_cooldown_ms = 200;
        } else if (!grim_interface_ptr->grim_is_key_active(config_key_reload)) {
            player_alt_weapon_swap_cooldown_ms = 0;
        }
    }

    if ((normal_fire_ready || perk_fire_ready)
        && (grim_interface_ptr->grim_is_key_active(player->input.fire_key)
            || auto_fire)) {
        int owner_id;
        survival_reward_fire_seen = 1;

        if (!normal_fire_ready) {
            if (perk_count_get(perk_id_regression_bullets) != 0) {
                if (weapon_ammo_class[player->weapon_id * 31] == 1) {
                    player->experience = player->experience
                        - weapon_table[player->weapon_id].reload_time * 4.0f;
                } else {
                    player->experience = player->experience
                        - weapon_table[player->weapon_id].reload_time * 200.0f;
                }
            } else if (perk_count_get(perk_id_ammunition_within) != 0) {
                player_take_damage(
                    render_overlay_player_index,
                    weapon_ammo_class[player->weapon_id * 31] == 1
                        ? 0.15f
                        : 1.0f);
            }
            if (player->experience < 0) {
                player->experience = 0;
            }
        }

        movement_heading = player->aim_heading;
        angle_step = movement_heading - 1.5707964f;
        scalar = angle_step - 0.150915f;
        movement_input.x = (float)cos(scalar) * 16.0f;
        movement_input.y = (float)sin(scalar) * 16.0f;

        if ((weapon_table[player->weapon_id].flags & 1) != 0) {
            effect_color_t smoke_color;
            angle_step = (float)(crt_rand() & 0x3f) * 0.01f
                + movement_heading;
            scalar = (float)(crt_rand() & 0x3f) * 0.022727273f + 1.0f;
            smoke_color.r = 1.0f;
            smoke_color.g = 1.0f;
            smoke_color.b = 1.0f;
            smoke_color.a = 0.6f;
            effect_template.flags = 0x1c5;
            effect_template.color = smoke_color;
            effect_template.lifetime = 0.15f;
            effect_template.age = 0.0f;
            move_delta.x = (float)cos(angle_step) * scalar;
            move_delta.y = (float)sin(angle_step) * scalar;
            effect_template.half_width = 2.0f;
            effect_template.half_height = 2.0f;
            effect_template.rotation =
                (float)((crt_rand() & 0x3f) - 0x20) * 0.1f;
            effect_template.vel_x = move_delta.x * 100.0f;
            effect_template.vel_y = move_delta.y * 100.0f;
            effect_template.scale_step = 0.0f;
            effect_template.rotation_step =
                ((float)(crt_rand() % 20) * 0.1f - 1.0f) * 14.0f;
            scratch_pos.x = movement_input.x + player_position->x;
            scratch_pos.y = movement_input.y + player_position->y;
            effect_spawn(0x12, &scratch_pos);
        }

        if (player->spread_heat > 1.0f) {
            player->spread_heat = 1.0f;
        }

        scalar = 1.0f;
        if (cv_friendlyFire->value != 0.0f) {
            owner_id = -1 - render_overlay_player_index;
        } else {
            owner_id = -100;
        }

        random_offset.x = player->aim_x;
        random_offset.y = player->aim_y;
        move_delta.x = random_offset.x - player_position->x;
        move_delta.y = random_offset.y - player_position->y;
        angle_step = vec2_length(&move_delta) * 0.5f;
        scratch_pos.x = (float)(crt_rand() & 0x1ff) * 0.012271847f;
        angle_step = angle_step * player->spread_heat
            * (float)(crt_rand() & 0x1ff) * 0.001953125f;
        random_offset.x =
            (float)cos(scratch_pos.x) * angle_step + random_offset.x;
        random_offset.y =
            (float)sin(scratch_pos.x) * angle_step + random_offset.y;
        angle_step = (float)atan2(
            player_position->y - random_offset.y,
            player_position->x - random_offset.x) - 1.5707964f;

        if (grim_interface_ptr->grim_is_key_active(0x22)) {
            player->fire_bullets_timer = 10.0f;
        }
        if (player->fire_bullets_timer > 0.0f) {
            sfx_play_panned(
                fire_bullets_primary_shot_sfx_id,
                player_position,
                1.0f);
            sfx_play_panned(
                fire_bullets_secondary_shot_sfx_id,
                player_position,
                1.0f);

            if (weapon_table[player->weapon_id].pellet_count == 1) {
                player->shot_cooldown =
                    fire_bullets_fallback_shot_cooldown;
                *muzzle_flash_alpha = *muzzle_flash_alpha
                    + fire_bullets_fallback_spread_heat;
            } else {
                player->shot_cooldown =
                    weapon_table[player->weapon_id].shot_cooldown;
                *muzzle_flash_alpha = *muzzle_flash_alpha
                    + weapon_table[player->weapon_id].spread_heat;
            }

            for (int pellet_index = 0;
                 pellet_index < weapon_table[player->weapon_id].pellet_count;
                 ++pellet_index) {
                scalar = (float)(crt_rand() % 200 - 100) * 0.0015f
                    + angle_step;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &scratch_pos,
                    scalar,
                    PROJECTILE_TYPE_FIRE_BULLETS,
                    owner_id);
            }

            move_delta.x = (float)cos(movement_heading) * 25.0f;
            move_delta.y = (float)sin(movement_heading) * 25.0f;
            scratch_pos.x = movement_input.x + player_position->x;
            scratch_pos.y = movement_input.y + player_position->y;
            int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
            sprite_effect_pool[effect_index].color_r = 0.5f;
            sprite_effect_pool[effect_index].color_g = 0.5f;
            sprite_effect_pool[effect_index].color_b = 0.5f;
            sprite_effect_pool[effect_index].color_a = 0.413f;

            if (perk_count_get(perk_id_sharpshooter) == 0) {
                player->spread_heat = player->spread_heat
                    + fire_bullets_fallback_spread_heat * 1.3f;
            }
        } else {
            player->shot_cooldown =
                weapon_table[player->weapon_id].shot_cooldown;
            *muzzle_flash_alpha = *muzzle_flash_alpha
                + weapon_table[player->weapon_id].spread_heat;
            sfx_play_panned(
                crt_rand()
                        % weapon_table[player->weapon_id].shot_sfx_variant_count
                    + weapon_table[player->weapon_id].shot_sfx_base_id,
                player_position,
                1.0f);

            if (player->weapon_id == WEAPON_ID_SHRINKIFIER_5K) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_SHRINKIFIER,
                    owner_id);
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.23f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.213f;
            } else if (player->weapon_id == WEAPON_ID_PISTOL) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_PISTOL,
                    owner_id);
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.23f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.213f;
            } else if (player->weapon_id == WEAPON_ID_ASSAULT_RIFLE) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.23f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.213f;
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_ASSAULT_RIFLE,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_SHOTGUN) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.25f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.223f;

                int pellet_count = 12;
                do {
                    scratch_pos.x = movement_input.x + player_position->x;
                    scratch_pos.y = movement_input.y + player_position->y;
                    int projectile_index = projectile_spawn(
                        &scratch_pos,
                        (float)(crt_rand() % 200 - 100) * 0.0013f
                            + angle_step,
                        PROJECTILE_TYPE_SHOTGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .pos.tail.vy.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_JACKHAMMER) {
                move_delta.x = (float)cos(movement_heading) * 15.0f;
                move_delta.y = (float)sin(movement_heading) * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.223f;

                int pellet_count = 4;
                do {
                    scratch_pos.x = movement_input.x + player_position->x;
                    scratch_pos.y = movement_input.y + player_position->y;
                    int projectile_index = projectile_spawn(
                        &scratch_pos,
                        (float)(crt_rand() % 200 - 100) * 0.0013f
                            + angle_step,
                        PROJECTILE_TYPE_SHOTGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .pos.tail.vy.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_SAWED_OFF_SHOTGUN) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.26f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.233f;

                int pellet_count = 12;
                do {
                    scratch_pos.x = movement_input.x + player_position->x;
                    scratch_pos.y = movement_input.y + player_position->y;
                    int projectile_index = projectile_spawn(
                        &scratch_pos,
                        (float)(crt_rand() % 200 - 100) * 0.004f
                            + angle_step,
                        PROJECTILE_TYPE_SHOTGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .pos.tail.vy.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_FLAMETHROWER) {
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                fx_spawn_particle(
                    &scratch_pos,
                    movement_heading - 1.5707964f,
                    (const vec2f_t *)&player->move_dx,
                    1.0f);
                scalar = 0.1f;
            } else if (player->weapon_id == WEAPON_ID_HR_FLAMER) {
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                owner_id = fx_spawn_particle(
                    &scratch_pos,
                    movement_heading - 1.5707964f,
                    (const vec2f_t *)&player->move_dx,
                    1.0f);
                if (owner_id != -1) {
                    particle_pool[owner_id].style_id = 2;
                }
                scalar = 0.1f;
            } else if (player->weapon_id == WEAPON_ID_BLOW_TORCH) {
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                owner_id = fx_spawn_particle(
                    &scratch_pos,
                    movement_heading - 1.5707964f,
                    (const vec2f_t *)&player->move_dx,
                    1.0f);
                if (owner_id != -1) {
                    particle_pool[owner_id].style_id = 1;
                }
                scalar = 0.05f;
            } else if (player->weapon_id == WEAPON_ID_SUBMACHINE_GUN) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.23f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.213f;
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_SUBMACHINE_GUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_PLASMA_RIFLE) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_PLASMA_RIFLE,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_MULTI_PLASMA) {
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &scratch_pos,
                    angle_step - 0.31415927f,
                    PROJECTILE_TYPE_PLASMA_RIFLE,
                    owner_id);
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &scratch_pos,
                    angle_step - 0.5235988f,
                    PROJECTILE_TYPE_PLASMA_MINIGUN,
                    owner_id);
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &scratch_pos,
                    angle_step,
                    PROJECTILE_TYPE_PLASMA_RIFLE,
                    owner_id);
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &scratch_pos,
                    angle_step + 0.5235988f,
                    PROJECTILE_TYPE_PLASMA_MINIGUN,
                    owner_id);
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &scratch_pos,
                    angle_step + 0.31415927f,
                    PROJECTILE_TYPE_PLASMA_RIFLE,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_PULSE_GUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_PULSE_GUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_BLADE_GUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_BLADE_GUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_SPLITTER_GUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_SPLITTER_GUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_ION_RIFLE) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_ION_RIFLE,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_ION_MINIGUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_ION_MINIGUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_ION_CANNON) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_ION_CANNON,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_PLASMA_CANNON) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_PLASMA_CANNON,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_ION_SHOTGUN) {
                int pellet_count = 8;
                do {
                    scratch_pos.x = movement_input.x + player_position->x;
                    scratch_pos.y = movement_input.y + player_position->y;
                    int projectile_index = projectile_spawn(
                        &scratch_pos,
                        (float)(crt_rand() % 200 - 100) * 0.0026f
                            + angle_step,
                        PROJECTILE_TYPE_ION_MINIGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .pos.tail.vy.speed_scale =
                        (float)(crt_rand() % 80) * 0.01f + 1.4f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_PLASMA_MINIGUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_PLASMA_MINIGUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_GAUSS_SHOTGUN) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.33f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.263f;

                int pellet_count = 6;
                do {
                    scratch_pos.x = movement_input.x + player_position->x;
                    scratch_pos.y = movement_input.y + player_position->y;
                    int projectile_index = projectile_spawn(
                        &scratch_pos,
                        (float)(crt_rand() % 200 - 100) * 0.002f
                            + angle_step,
                        PROJECTILE_TYPE_GAUSS_GUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .pos.tail.vy.speed_scale =
                        (float)(crt_rand() % 80) * 0.01f + 1.4f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_GAUSS_GUN) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.33f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.263f;
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_GAUSS_GUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_ROCKET_LAUNCHER) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.34f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.283f;
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                fx_spawn_secondary_projectile(&spawn_pos, angle_step, SECONDARY_PROJECTILE_TYPE_ROCKET);
            } else if (player->weapon_id == WEAPON_ID_MINI_ROCKET_SWARMERS) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.34f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.283f;

                movement_heading = player->ammo * 1.0471976f;
                float rocket_heading = (angle_step - 3.1415927f)
                    - movement_heading * player->ammo * 0.5f;
                int rocket_count = 0;
                if (player->ammo > 0.0f) {
                    do {
                        scratch_pos.x = movement_input.x + player_position->x;
                        scratch_pos.y = movement_input.y + player_position->y;
                        fx_spawn_secondary_projectile(&scratch_pos, rocket_heading, SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET);
                        rocket_heading = rocket_heading + movement_heading;
                        ++rocket_count;
                    } while ((float)rocket_count < player->ammo);
                }
                scalar = player->ammo;
            } else if (player->weapon_id == WEAPON_ID_ROCKET_MINIGUN) {
                move_delta.x = (float)cos(movement_heading) * 25.0f;
                move_delta.y = (float)sin(movement_heading) * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.34f;
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                fx_spawn_secondary_projectile(&spawn_pos, angle_step, SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN);
            } else if (player->weapon_id == WEAPON_ID_SEEKER_ROCKETS) {
                random_offset.x = (float)cos(movement_heading);
                move_delta.x = random_offset.x * 25.0f;
                random_offset.y = (float)sin(movement_heading);
                move_delta.y = random_offset.y * 25.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                int effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.31f;
                move_delta.x = random_offset.x * 15.0f;
                move_delta.y = random_offset.y * 15.0f;
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                effect_index = fx_spawn_sprite(&scratch_pos, &move_delta, 2.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.243f;
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                fx_spawn_secondary_projectile(&spawn_pos, angle_step, SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET);
            } else if (player->weapon_id == WEAPON_ID_MEAN_MINIGUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_PISTOL,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_PLASMA_SHOTGUN) {
                int pellet_count = 14;
                do {
                    scratch_pos.x = movement_input.x + player_position->x;
                    scratch_pos.y = movement_input.y + player_position->y;
                    int projectile_index = projectile_spawn(
                        &scratch_pos,
                        (float)((crt_rand() & 0xff) - 0x80) * 0.002f
                            + angle_step,
                        PROJECTILE_TYPE_PLASMA_MINIGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .pos.tail.vy.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_PLAGUE_SPREADER_GUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_PLAGUE_SPREADER,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_RAINBOW_GUN) {
                player_update_vec2_t spawn_pos;
                spawn_pos.x = movement_input.x + player_position->x;
                spawn_pos.y = movement_input.y + player_position->y;
                projectile_spawn(
                    &spawn_pos,
                    angle_step,
                    PROJECTILE_TYPE_RAINBOW_GUN,
                    owner_id);
            } else if (player->weapon_id == WEAPON_ID_BUBBLEGUN) {
                scratch_pos.x = movement_input.x + player_position->x;
                scratch_pos.y = movement_input.y + player_position->y;
                fx_spawn_particle_slow(&scratch_pos, angle_step - 1.5707964f);
                scalar = 0.15f;
            }

            if (perk_count_get(perk_id_sharpshooter) == 0) {
                player->spread_heat = player->spread_heat
                    + weapon_table[player->weapon_id].spread_heat * 1.3f;
            }
            if (bonus_reflex_boost_timer <= 0.0f) {
                player->ammo = player->ammo - scalar;
            }
        }

        if (player->spread_heat > 0.48f) {
            player->spread_heat = 0.48f;
        }
        if (player_state_table[0].perk_counts[perk_id_fastshot] > 0) {
            player->shot_cooldown = player->shot_cooldown * 0.88f;
        }
        if (player_state_table[0].perk_counts[perk_id_sharpshooter] > 0) {
            player->shot_cooldown = player->shot_cooldown * 1.05f;
        }
        if (player->ammo <= 0.0f) {
            player_start_reload();
        }
    }

    while (player->move_phase > 14.0f) {
        player->move_phase = player->move_phase - 14.0f;
    }
    while (player->move_phase < 0.0f) {
        player->move_phase = player->move_phase + 14.0f;
    }

    if (player->speed_bonus_timer > 0.0f) {
        player->speed_multiplier = player->speed_multiplier - 1.0f;
    }

    scalar = player->size * 0.5f;
    if (player_position->x < scalar) {
        player_position->x = scalar;
    }
    if ((float)terrain_texture_width - scalar < player_position->x) {
        player_position->x = (float)terrain_texture_width - scalar;
    }
    if (player->pos_y < scalar) {
        player->pos_y = scalar;
    }
    if ((float)terrain_texture_height - scalar < player->pos_y) {
        player->pos_y = (float)terrain_texture_height - scalar;
    }
    if (*muzzle_flash_alpha > 0.8f) {
        *muzzle_flash_alpha = 0.8f;
    }
}
