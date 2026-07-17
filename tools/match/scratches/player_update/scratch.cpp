#include <math.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct player_update_vec2_t {
    float x;
    float y;
};

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
extern int sfx_bloodspill_01;
extern int sfx_explosion_small;
extern int fire_bullets_primary_shot_sfx_id;
extern int fire_bullets_secondary_shot_sfx_id;

void effect_spawn_blood_splatter(float *pos, float angle, float age);
float vec2_length(float *v);
int fx_spawn_sprite(float *pos, float *vel, float scale);
bool input_primary_just_pressed(void);
bool input_aim_pov_left_active(void);
bool input_aim_pov_right_active(void);
float player_heading_approach_target(float target_heading);
float *__stdcall vec2_normalize_dispatch(float *dst, float *src);
void player_start_reload(void);
}

static __inline void player_accelerate_move_speed(player_state_t *player)
{
    if (player_state_table[0].perk_counts[perk_id_long_distance_runner] < 1) {
        player->move_speed = player->move_speed + frame_dt * 5.0f;
        if (player->move_speed > 2.0f) {
            player->move_speed = 2.0f;
        }
    } else {
        if (player->move_speed < 2.0f) {
            player->move_speed = player->move_speed + frame_dt * 4.0f;
        }
        player->move_speed = player->move_speed + frame_dt;
        if (player->move_speed > 2.8f) {
            player->move_speed = 2.8f;
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
    int player_index;
    float movement_heading;
    float angle_step;
    float scalar;
    player_update_vec2_t random_offset;
    player_update_vec2_t previous_pos;
    player_update_vec2_t movement_input;
    player_update_vec2_t scratch_pos;
    player_update_vec2_t move_delta;

    if (console_open_flag != 0) {
        return;
    }

    player_index = render_overlay_player_index;
    player_aim_screen_x[player_index * 2] = ui_mouse_x;
    player_aim_screen_x[player_index * 2 + 1] = ui_mouse_y;

    player_state_t *player = &player_state_table[player_index];
    previous_pos.x = player->pos_x;
    previous_pos.y = player->pos_y;

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
            float angle = player->aim_heading;
            scratch_pos.x = (float)cos(angle + 1.5707964f - 0.5f) * -6.0f
                + player->pos_x;
            scratch_pos.y = (float)sin(angle + 1.5707964f - 0.5f) * -6.0f
                + player->pos_y;
            effect_spawn_blood_splatter(&scratch_pos.x, angle, 0.0f);
            effect_spawn_blood_splatter(&scratch_pos.x, angle, 0.0f);
            effect_spawn_blood_splatter(&scratch_pos.x, angle, 0.0f);
            sfx_play_panned(
                (crt_rand() & 1) + sfx_bloodspill_01,
                &player->pos_x,
                1.0f);
            player->low_health_timer = 1.0f;
        }
    }

    player->muzzle_flash_alpha =
        player->muzzle_flash_alpha - (frame_dt + frame_dt);
    if (player->muzzle_flash_alpha < 0.0f) {
        player->muzzle_flash_alpha = 0.0f;
    }

    if (bonus_weapon_power_up_timer <= 0.0f) {
        player->shot_cooldown = player->shot_cooldown - frame_dt;
    } else {
        player->shot_cooldown = player->shot_cooldown - frame_dt * 1.5f;
    }
    if (player->shot_cooldown < 0.0f) {
        player->shot_cooldown = 0.0f;
    }

    if (perk_count_get(perk_id_man_bomb) == 0) {
        player->man_bomb_timer = 0.0f;
    } else {
        player->man_bomb_timer = player->man_bomb_timer + frame_dt;
        if (player->man_bomb_timer > perk_man_bomb_trigger_interval_s) {
            int owner_id;
            if (cv_friendlyFire->value == 0.0f) {
                owner_id = -100;
            } else {
                owner_id = -1 - render_overlay_player_index;
            }

            int projectile_index = 0;
            do {
                int projectile_type;
                if ((projectile_index & 1) == 0) {
                    projectile_type = PROJECTILE_TYPE_ION_MINIGUN;
                } else {
                    projectile_type = PROJECTILE_TYPE_ION_RIFLE;
                }
                float projectile_angle =
                    (float)projectile_index * 0.7853982f
                    + (float)(crt_rand() % 0x32) * 0.01f
                    - 0.25f;
                projectile_spawn(
                    &player->pos_x,
                    projectile_angle,
                    projectile_type,
                    owner_id);
                ++projectile_index;
            } while (projectile_index < 8);

            sfx_play_panned(sfx_explosion_small, &player->pos_x, 1.0f);
            player->man_bomb_timer =
                player->man_bomb_timer - perk_man_bomb_trigger_interval_s;
            perk_man_bomb_trigger_interval_s = 4.0f;
        }
    }

    if (perk_count_get(perk_id_living_fortress) == 0) {
        player->living_fortress_timer = 0.0f;
    } else {
        player->living_fortress_timer =
            player->living_fortress_timer + frame_dt;
        if (player->living_fortress_timer > 30.0f) {
            player->living_fortress_timer = 30.0f;
        }
    }

    if (perk_count_get(perk_id_fire_caugh) == 0) {
        player->fire_cough_timer = 0.0f;
    } else {
        player->fire_cough_timer = player->fire_cough_timer + frame_dt;
        if (player->fire_cough_timer > perk_fire_cough_trigger_interval_s) {
            int owner_id;
            if (cv_friendlyFire->value == 0.0f) {
                owner_id = -100;
            } else {
                owner_id = -1 - render_overlay_player_index;
            }

            sfx_play_panned(
                fire_bullets_primary_shot_sfx_id,
                &player->pos_x,
                1.0f);
            sfx_play_panned(
                fire_bullets_secondary_shot_sfx_id,
                &player->pos_x,
                1.0f);

            float aim_heading = player->aim_heading;
            float muzzle_heading = aim_heading - 1.5707964f - 0.150915f;
            movement_input.x = (float)cos(muzzle_heading) * 16.0f;
            movement_input.y = (float)sin(muzzle_heading) * 16.0f;

            random_offset.x = player->aim_x;
            random_offset.y = player->aim_y;
            move_delta.x = random_offset.x - player->pos_x;
            move_delta.y = random_offset.y - player->pos_y;
            float spread_radius = vec2_length(&move_delta.x) * 0.5f;
            float spread_angle =
                (float)(crt_rand() & 0x1ff) * 0.012271847f;
            spread_radius = spread_radius * player->spread_heat
                * (float)(crt_rand() & 0x1ff) * 0.001953125f;
            random_offset.x = (float)cos(spread_angle) * spread_radius
                + random_offset.x;
            random_offset.y = (float)sin(spread_angle) * spread_radius
                + random_offset.y;

            ((vec2_t *)&player->pos_x)->vec2_sub(
                &scratch_pos.x,
                &random_offset.x);
            float shot_heading =
                (float)atan2(scratch_pos.y, scratch_pos.x) - 1.5707964f;
            movement_input.x = movement_input.x + player->pos_x;
            movement_input.y = movement_input.y + player->pos_y;
            projectile_spawn(
                &movement_input.x,
                shot_heading,
                PROJECTILE_TYPE_FIRE_BULLETS,
                owner_id);

            move_delta.x = (float)cos(aim_heading) * 25.0f;
            move_delta.y = (float)sin(aim_heading) * 25.0f;
            int effect_index = fx_spawn_sprite(
                &movement_input.x,
                &move_delta.x,
                1.0f);
            sprite_effect_pool[effect_index].color_r = 0.5f;
            sprite_effect_pool[effect_index].color_g = 0.5f;
            sprite_effect_pool[effect_index].color_b = 0.5f;
            sprite_effect_pool[effect_index].color_a = 0.413f;

            player->fire_cough_timer =
                player->fire_cough_timer - perk_fire_cough_trigger_interval_s;
            perk_fire_cough_trigger_interval_s =
                (float)(crt_rand() % 4) + 2.0f;
        }
    }

    if (perk_count_get(perk_id_hot_tempered) == 0) {
        player->hot_tempered_timer = 0.0f;
    } else {
        player->hot_tempered_timer = player->hot_tempered_timer + frame_dt;
        if (player->hot_tempered_timer > perk_hot_tempered_trigger_interval_s) {
            int owner_id;
            if (cv_friendlyFire->value == 0.0f) {
                owner_id = -100;
            } else {
                owner_id = -1 - render_overlay_player_index;
            }

            int projectile_index = 0;
            do {
                int projectile_type;
                if ((projectile_index & 1) == 0) {
                    projectile_type = PROJECTILE_TYPE_PLASMA_MINIGUN;
                } else {
                    projectile_type = PROJECTILE_TYPE_PLASMA_RIFLE;
                }
                projectile_spawn(
                    &player->pos_x,
                    (float)projectile_index * 0.7853982f,
                    projectile_type,
                    owner_id);
                ++projectile_index;
            } while (projectile_index < 8);

            sfx_play_panned(sfx_explosion_small, &player->pos_x, 1.0f);
            player->hot_tempered_timer =
                player->hot_tempered_timer - perk_hot_tempered_trigger_interval_s;
            perk_hot_tempered_trigger_interval_s =
                (float)(crt_rand() % 8) + 2.0f;
        }
    }

    if (player_spread_damping_gate <= 0.0f) {
        player_spread_damping_scalar =
            frame_dt * 0.8f + player_spread_damping_scalar;
        if (player_spread_damping_scalar > 1.0f) {
            player_spread_damping_scalar = 1.0f;
        }
    } else {
        player_spread_damping_scalar =
            player_spread_damping_scalar - frame_dt;
        if (player_spread_damping_scalar < 0.3f) {
            player_spread_damping_scalar = 0.3f;
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

    if (demo_mode_active == 0
        && config_player_mode_flags[player_index] != 5
        && config_aim_scheme[player_index] != 5) {
        int move_mode = config_player_mode_flags[player_index];
        if (move_mode == 4) {
            if (grim_interface_ptr->grim_is_key_active(config_key_reload)) {
                scratch_pos.y =
                    player_aim_screen_x[player_index * 2 + 1]
                    - camera_offset_y;
                scratch_pos.x =
                    player_aim_screen_x[player_index * 2]
                    - camera_offset_x;
                player->move_target_x = scratch_pos.x;
                player->move_target_y = scratch_pos.y;
            }

            bool moving_to_target = false;
            if (player->move_target_x != -1.0f) {
                scratch_pos.y = player->pos_y - player->move_target_y;
                scratch_pos.x = player->pos_x - player->move_target_x;
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
                        move_delta.x = frame_dt * player->move_dx;
                        move_delta.y = frame_dt * player->move_dy;
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
                move_delta.x = frame_dt * player->move_dx;
                move_delta.y = frame_dt * player->move_dy;
            }

            player_apply_move_with_spawn_avoidance(
                player_index,
                &player->pos_x,
                &move_delta.x);
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
                vec2_normalize_dispatch(&movement_input.x, &movement_input.x);
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
                player_index,
                &player->pos_x,
                &move_delta.x);
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
                player_index,
                &player->pos_x,
                &move_delta.x);
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
                player_index,
                &player->pos_x,
                &move_delta.x);
            player->move_phase = frame_dt * player->move_speed * 19.0f
                + player->move_phase;
        }
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
        && player->reload_timer >= 0.0f) {
        player->ammo = player->clip_size;
    }

    scalar = 1.0f;
    if (player->pos_x == previous_pos.x && player->pos_y == previous_pos.y) {
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
            if (cv_friendlyFire->value == 0.0f) {
                owner_id = -100;
            } else {
                owner_id = -1 - render_overlay_player_index;
            }

            int projectile_count =
                7 - (int)(player->reload_timer_max * -4.0f);
            int projectile_index = 0;
            if (projectile_count > 0) {
                angle_step = 6.2831855f / (float)projectile_count;
                do {
                    projectile_spawn(
                        &player->pos_x,
                        (float)projectile_index * angle_step + 0.1f,
                        PROJECTILE_TYPE_PLASMA_MINIGUN,
                        owner_id);
                    ++projectile_index;
                } while (projectile_index < projectile_count);
            }
            bonus_spawn_guard = 0;
            sfx_play_panned(sfx_explosion_small, &player->pos_x, 1.0f);
        }
    }

    if (player->reload_timer < 0.0f) {
        player->reload_timer = 0.0f;
    }

    if (demo_mode_active == 0
        && perk_count_get(perk_id_alternate_weapon) == 0
        && config_player_mode_flags[player_index] != 4
        && grim_interface_ptr->grim_is_key_active(config_key_reload)
        && player->reload_timer == 0.0f
        && config_player_count == 1) {
        player_start_reload();
    }

    if (demo_mode_active == 0 && config_aim_scheme[player_index] != 5) {
        int aim_scheme = config_aim_scheme[player_index];
        if (aim_scheme == 0) {
            scratch_pos.y =
                player_aim_screen_x[player_index * 2 + 1] - camera_offset_y;
            scratch_pos.x =
                player_aim_screen_x[player_index * 2] - camera_offset_x;
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
            vec2_normalize_dispatch(&movement_input.x, &movement_input.x);
            scalar = scalar * cv_padAimDistMul->value + 42.0f;
            move_delta.x = scalar * movement_input.x;
            scratch_pos.y =
                scalar * movement_input.y + player->pos_y;
            scratch_pos.x = move_delta.x + player->pos_x;
            player->aim_x = scratch_pos.x;
            player->aim_y = scratch_pos.y;
        } else if (aim_scheme == 3) {
            movement_input.y =
                player_aim_screen_x[player_index * 2 + 1] - 200.0f;
            movement_input.x =
                player_aim_screen_x[player_index * 2] - 200.0f;
            if (movement_input.x != 0.0f || movement_input.y != 0.0f) {
                player->aim_heading =
                    (float)atan2(movement_input.y, movement_input.x)
                    + 1.5707964f;
                random_offset.x = player->aim_heading - 1.5707964f;
                move_delta.y = (float)sin(random_offset.x);
                scratch_pos.y = move_delta.y * 60.0f + player->pos_y;
                scratch_pos.x =
                    (float)cos(random_offset.x) * 60.0f + player->pos_x;
                player->aim_x = scratch_pos.x;
                player->aim_y = scratch_pos.y;
            }
            if ((float)sqrt(
                    movement_input.x * movement_input.x
                    + movement_input.y * movement_input.y)
                > 30.0f) {
                vec2_normalize_dispatch(
                    &movement_input.x,
                    &movement_input.x);
                move_delta.y = movement_input.y * 30.0f;
                scratch_pos.x = movement_input.x * 30.0f + 200.0f;
                scratch_pos.y = move_delta.y + 200.0f;
                player_aim_screen_x[player_index * 2] = scratch_pos.x;
                player_aim_screen_x[player_index * 2 + 1] = scratch_pos.y;
            }
        } else if (aim_scheme == 1) {
            int move_mode = config_player_mode_flags[player_index];
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
                scratch_pos.y = move_delta.y * 60.0f + player->pos_y;
                scratch_pos.x =
                    (float)cos(random_offset.x) * 60.0f + player->pos_x;
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
            scratch_pos.y = move_delta.y * 60.0f + player->pos_y;
            scratch_pos.x =
                (float)cos(random_offset.x) * 60.0f + player->pos_x;
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
            vec2_normalize_dispatch(&movement_input.x, &movement_input.x);
            angle_step = scalar * 6.0f * frame_dt;
            move_delta.x = movement_input.x * angle_step;
            player->aim_x = player->aim_x + move_delta.x;
            player->aim_y = player->aim_y + movement_input.y * angle_step;
        } else {
            player->aim_x = creature_pool[target_index].pos_x;
            player->aim_y = creature_pool[target_index].pos_y;
        }
    }

    player->aim_heading =
        (float)atan2(
            player->pos_y - player->aim_y,
            player->pos_x - player->aim_x)
        - 1.5707964f;

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
    if (player->pos_x < scalar) {
        player->pos_x = scalar;
    }
    if ((float)terrain_texture_width - scalar < player->pos_x) {
        player->pos_x = (float)terrain_texture_width - scalar;
    }
    if (player->pos_y < scalar) {
        player->pos_y = scalar;
    }
    if ((float)terrain_texture_height - scalar < player->pos_y) {
        player->pos_y = (float)terrain_texture_height - scalar;
    }
    if (player->muzzle_flash_alpha > 0.8f) {
        player->muzzle_flash_alpha = 0.8f;
    }
}
