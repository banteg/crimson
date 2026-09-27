#include <math.h>

#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"
#include "grim2d_cpp.h"

struct vec2_t : vec2f_t {
    vec2_t() {}
    vec2_t(float _x, float _y) { x = _x; y = _y; }

    inline vec2_t operator - (const vec2_t &v)
    {
        return vec2_t (x - v.x, y - v.y);
    }

    inline vec2_t operator + (const vec2_t &v)
    {
        return vec2_t (x + v.x, y + v.y);
    }

    inline vec2_t& operator += (const vec2_t &v)
    {
        x += v.x;
        y += v.y;
        return *this;
    }

    vec2_t vec2_sub(const vec2_t &v);
};

typedef vec2_t player_update_vec2_t;

inline float VEC2_Length (const vec2_t &v)
{
	return sqrtf(v.x * v.x + v.y * v.y);
}

inline float VEC2_Angle (const vec2_t &v)
{
	return atan2f(v.y, v.x);
}

inline vec2_t operator * (const vec2_t &v, float s)
{	return vec2_t (s * v.x, s * v.y);	}

inline vec2_t operator * (float s, const vec2_t &v)
{	return vec2_t (s * v.x, s * v.y);	}

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
extern int config_movement_schemes[];
extern int config_aim_schemes[];
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
extern weapon_storage_entry_t weapon_ammo_class[];
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
vec2f_t *__stdcall D3DXVec2Normalize(
    vec2f_t *dst,
    const vec2f_t *src);
void player_start_reload(void);
void player_take_damage(int player_index, float damage);
int fx_spawn_particle(
    const vec2f_t *pos,
    float angle,
    const vec2f_t *move,
    float intensity);
int fx_spawn_particle_slow(
    const vec2f_t *pos,
    float angle,
    const vec2f_t *movement);
int fx_spawn_secondary_projectile(
    const vec2f_t *pos,
    float angle,
    secondary_projectile_type_id_t type_id);
}

template <class T> inline void pu_swap(T &a, T &b)
{
    T t = a;
    a = b;
    b = t;
}

static __inline int pu_perk_level(int perk_id)
{
    return player_state_table[0].perk_counts[perk_id];
}

static __inline void player_accelerate_move_speed(player_state_t *player)
{
    if (pu_perk_level(perk_id_long_distance_runner) > 0) {
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
    float turn_angle;
    float rocket_step;
    float fire_heading;
    float angle_step;
    float scalar;
    float speed_scale;
    float dir_x;
    float dir_y;
    bool auto_fire;
    bool normal_fire_ready;
    bool perk_fire_ready;

    if (console_open_flag != 0) {
        return;
    }

    int player_index = render_overlay_player_index;
    player_update_vec2_t *aim_screen =
        (player_update_vec2_t *)&player_aim_screen_x[player_index * 2];
    *aim_screen = *(player_update_vec2_t *)&ui_mouse_x;

    player_state_t *player = &player_state_table[player_index];
    vec2_t previous_pos = *(vec2_t *)&player->position;

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
            float heading = player->aim_heading;
            float dx = cosf(heading + 1.5707964f - 0.5f) * -6.0f;
            vec2_t blood_position;
            blood_position.y =
                sinf(player->aim_heading + 1.5707964f - 0.5f) * -6.0f;
            float angle = player->aim_heading;
            blood_position.x = dx;
            blood_position += *(vec2_t *)&player->position;
            effect_spawn_blood_splatter(&blood_position, angle, 0.0f);
            effect_spawn_blood_splatter(&blood_position, angle, 0.0f);
            effect_spawn_blood_splatter(&blood_position, angle, 0.0f);
            sfx_play_panned(
                (crt_rand() & 1) + sfx_bloodspill_01,
                &player->position,
                1.0f);
            player->low_health_timer = 1.0f;
        }
    }

    float *muzzle_flash_alpha = &player->muzzle_flash_alpha;
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
                        &player->position,
                        (float)projectile_index * 0.7853982f
                            + (float)(crt_rand() % 0x32) * 0.01f
                            - 0.25f,
                        PROJECTILE_TYPE_ION_RIFLE,
                        owner_id);
                } else {
                    projectile_spawn(
                        &player->position,
                        (float)projectile_index * 0.7853982f
                            + (float)(crt_rand() % 0x32) * 0.01f
                            - 0.25f,
                        PROJECTILE_TYPE_ION_MINIGUN,
                        owner_id);
                }
                ++projectile_index;
            } while (projectile_index < 8);

            sfx_play_panned(sfx_explosion_small, &player->position, 1.0f);
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
                &player->position,
                1.0f);
            sfx_play_panned(
                fire_bullets_secondary_shot_sfx_id,
                &player->position,
                1.0f);

            float aim_heading = player->aim_heading;
            float muzzle_heading = aim_heading - 1.5707964f - 0.150915f;
            vec2_t cough_offset(cosf(muzzle_heading) * 16.0f, sinf(muzzle_heading) * 16.0f);

            int fire_index = render_overlay_player_index;
            vec2_t cough_target = *(vec2_t *)&player_state_table[fire_index].aim;
            float shot_heading;
            {
                vec2_t target_delta = cough_target
                    - *(vec2_t *)&player_state_table[fire_index].position;
                float spread_radius = vec2_length(&target_delta) * 0.5f;
                float spread_angle =
                    (float)(crt_rand() & 0x1ff) * 0.012271847f;
                spread_radius = (float)(crt_rand() & 0x1ff)
                    * (spread_radius * player_state_table[fire_index].spread_heat)
                    * 0.001953125f;
                cough_target.x = cosf(spread_angle) * spread_radius
                    + cough_target.x;
                cough_target.y = sinf(spread_angle) * spread_radius
                    + cough_target.y;

                shot_heading = VEC2_Angle(
                    ((vec2_t *)&player_state_table[fire_index].position)->vec2_sub(cough_target))
                    - 1.5707964f;
            }
            {
                vec2_t spawn_position = cough_offset + *(vec2_t *)&player->position;
                projectile_spawn(
                    &spawn_position,
                    shot_heading,
                    PROJECTILE_TYPE_FIRE_BULLETS,
                    owner_id);
            }

            {
                vec2_t velocity;
                velocity.x = cosf(aim_heading) * 25.0f;
                velocity.y = sinf(aim_heading) * 25.0f;
                int effect_index =
                    fx_spawn_sprite(&(cough_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.413f;
            }

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
                if ((projectile_index & 1) != 0) {
                    projectile_spawn(&player->position,
                        (float)projectile_index * 0.7853982f,
                        PROJECTILE_TYPE_PLASMA_RIFLE, owner_id);
                } else {
                    projectile_spawn(&player->position,
                        (float)projectile_index * 0.7853982f,
                        PROJECTILE_TYPE_PLASMA_MINIGUN, owner_id);
                }
                ++projectile_index;
            } while (projectile_index < 8);

            sfx_play_panned(sfx_explosion_small, &player->position, 1.0f);
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

    speed_scale = player->speed_multiplier;
    vec2_t zero_movement(0.0f, 0.0f);
    player->movement = zero_movement;
    if (time_scale_active != 0) {
        frame_dt = (0.6f / time_scale_factor) * frame_dt;
    }

    if (demo_mode_active != 0
        || config_movement_schemes[render_overlay_player_index] == 5
        || config_aim_schemes[render_overlay_player_index] == 5) {
        if (player->auto_target < 0) {
            player->auto_target = 0;
        }

        int target_index = player->auto_target;
        float nearest_distance;
        if (!creature_pool[target_index].active
            || creature_pool[target_index].health <= 0.0f) {
            nearest_distance = 100000.0f;
        } else {
            nearest_distance = VEC2_Length(*(vec2_t *)&player->position
                - *(vec2_t *)&creature_pool[target_index].position);
        }

        int creature_index = 0;
        do {
            if (creature_pool[creature_index].active
                && creature_pool[creature_index].health > 0.0f) {
                float distance = VEC2_Length(*(vec2_t *)&player->position
                    - *(vec2_t *)&creature_pool[creature_index].position);
                if (distance < nearest_distance - 64.0f) {
                    player->auto_target = creature_index;
                    nearest_distance = distance;
                }
            }
            ++creature_index;
        } while (creature_index < 384);
    }

    if (demo_mode_active == 0
        && config_movement_schemes[render_overlay_player_index] != 5) {
        int move_mode = config_movement_schemes[render_overlay_player_index];
        if (move_mode == 4) {
            if (grim_interface_ptr->grim_is_key_active(config_key_reload)) {
                vec2_t target =
                    *(vec2_t *)&player_aim_screen_x[render_overlay_player_index * 2]
                    - *(vec2_t *)&camera_offset_x;
                *(vec2_t *)&player->move_target = target;
            }

            bool moving_to_target = false;
            if (player->move_target.x != -1.0f) {
                vec2_t delta = *(vec2_t *)&player->position - *(vec2_t *)&player->move_target;
                if (VEC2_Length(delta) > 20.0f) {
                    movement_heading = VEC2_Angle(delta) - 1.5707964f;
                    while (movement_heading < 0.0f) {
                        movement_heading = movement_heading + 6.2831855f;
                    }
                    if (movement_heading != -1.0f) {
                        angle_step = player_heading_approach_target(
                            movement_heading);
                        player_accelerate_move_speed(player);
                        player_apply_move_speed_cap(player);

                        player->move_dx = (cosf(player->heading - 1.5707964f) * player->move_speed)
                            * (3.1415927f - angle_step) * speed_scale * 7.957747f;
                        player->move_dy = (sinf(player->heading - 1.5707964f) * player->move_speed)
                            * (3.1415927f - angle_step) * speed_scale * 7.957747f;
                        vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                        player_apply_move_with_spawn_avoidance(
                            render_overlay_player_index,
                            &player->position,
                            &move);
                        moving_to_target = true;
                    }
                }
            }

            if (!moving_to_target) {
                player_decelerate_move_speed(player);
                player->move_dx =
                    cosf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                player->move_dy =
                    sinf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            }

            player->move_phase =
                frame_dt * player->move_speed * 19.0f + player->move_phase;
        } else if (move_mode == 3) {
            vec2_t pad(
                -grim_interface_ptr->grim_get_config_float(player->input.axis_move_x),
                -grim_interface_ptr->grim_get_config_float(player->input.axis_move_y));

            movement_heading = -1.0f;
            if (VEC2_Length(pad)
                > 0.2f) {
                D3DXVec2Normalize(&pad, &pad);
                movement_heading =
                    VEC2_Angle(pad)
                    - 1.5707964f;
                while (movement_heading < 0.0f) {
                    movement_heading = movement_heading + 6.2831855f;
                }
            }

            if (movement_heading != -1.0f) {
                angle_step = player_heading_approach_target(
                    movement_heading);
                player_accelerate_move_speed(player);
                player_apply_move_speed_cap(player);

                player->move_dx = (cosf(player->heading - 1.5707964f) * player->move_speed)
                    * (3.1415927f - angle_step) * speed_scale * 7.957747f;
                player->move_dy = (sinf(player->heading - 1.5707964f) * player->move_speed)
                    * (3.1415927f - angle_step) * speed_scale * 7.957747f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            } else {
                player_decelerate_move_speed(player);
                player->move_dx =
                    cosf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                player->move_dy =
                    sinf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            }

            player->move_phase =
                frame_dt * player->move_speed * 19.0f + player->move_phase;
        } else if (move_mode == 1) {
            bool turned = false;
            if (player->turn_speed < 1.0f) {
                player->turn_speed = 1.0f;
            }
            if (player->turn_speed > 7.0f) {
                player->turn_speed = 7.0f;
            }

            if (grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_left)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_down(player_alt_turn_key_left))) {
                float current_turn_speed = player->turn_speed + frame_dt * 10.0f;
                player->turn_speed = current_turn_speed;
                player->heading = player->heading
                    - current_turn_speed * frame_dt * 0.5f;
                player->aim_heading = player->aim_heading
                    - player->turn_speed * frame_dt * 0.5f;
                turned = true;
            } else if (grim_interface_ptr->grim_is_key_active(
                           player->input.turn_key_right)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_down(player_alt_turn_key_right))) {
                float current_turn_speed = player->turn_speed + frame_dt * 10.0f;
                player->turn_speed = current_turn_speed;
                player->heading = player->heading
                    + current_turn_speed * frame_dt * 0.5f;
                player->aim_heading = player->aim_heading
                    + player->turn_speed * frame_dt * 0.5f;
                turned = true;
            }

            movement_heading = 1.0f;
            if (grim_interface_ptr->grim_is_key_active(
                    player->input.move_key_forward)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_down(player_alt_move_key_forward))) {
                player_accelerate_move_speed(player);
                player_apply_move_speed_cap(player);
                player->move_dx =
                    cosf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                player->move_dy =
                    sinf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            } else if (grim_interface_ptr->grim_is_key_active(
                           player->input.move_key_backward)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_down(player_alt_move_key_backward))) {
                player_accelerate_move_speed(player);
                movement_heading = -1.0f;
                player->move_dx =
                    cosf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * -25.0f;
                player->move_dy =
                    sinf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * -25.0f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            } else {
                if (!turned) {
                    player->turn_speed = 1.0f;
                }
                player_decelerate_move_speed(player);
                player->move_dx =
                    cosf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                player->move_dy =
                    sinf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            }

            player->move_phase = movement_heading * player->move_speed * frame_dt
                * 19.0f + player->move_phase;
        } else if (move_mode == 2) {
            turn_angle = -1.0f;

            if (grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_left)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_active(
                        player_alt_turn_key_left))) {
                turn_angle = 4.712389f;
            }
            if (grim_interface_ptr->grim_is_key_active(
                    player->input.turn_key_right)
                || (config_player_count == 1
                    && grim_interface_ptr->grim_is_key_active(
                        player_alt_turn_key_right))) {
                turn_angle = 1.5707964f;
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
                    turn_angle = 5.4977875f;
                } else if (grim_interface_ptr->grim_is_key_active(
                               player->input.turn_key_right)
                    || (config_player_count == 1
                        && grim_interface_ptr->grim_is_key_active(
                            player_alt_turn_key_right))) {
                    turn_angle = 0.7853982f;
                } else {
                    turn_angle = 0.0f;
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
                    turn_angle = 3.926991f;
                } else if (grim_interface_ptr->grim_is_key_active(
                               player->input.turn_key_right)
                    || (config_player_count == 1
                        && grim_interface_ptr->grim_is_key_active(
                            player_alt_turn_key_right))) {
                    turn_angle = 2.3561945f;
                } else {
                    turn_angle = 3.1415927f;
                }
            }

            if (turn_angle != -1.0f) {
                angle_step = player_heading_approach_target(turn_angle);
                player->aim_heading =
                    player->aim_heading + player_heading_turn_delta;
                player_accelerate_move_speed(player);
                player_apply_move_speed_cap(player);

                player->move_dx = (cosf(player->heading - 1.5707964f) * player->move_speed)
                    * (3.1415927f - angle_step) * speed_scale * 7.957747f;
                player->move_dy = (sinf(player->heading - 1.5707964f) * player->move_speed)
                    * (3.1415927f - angle_step) * speed_scale * 7.957747f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            } else {
                player_decelerate_move_speed(player);
                player->move_dx =
                    cosf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                player->move_dy =
                    sinf(player->heading - 1.5707964f)
                    * player->move_speed * speed_scale * 25.0f;
                vec2_t move = frame_dt * *(vec2_t *)&player->movement;
                player_apply_move_with_spawn_avoidance(
                    render_overlay_player_index,
                    &player->position,
                    &move);
            }
            player->move_phase = frame_dt * player->move_speed * 19.0f
                + player->move_phase;
        }
    } else {
        vec2_t center(512.0f, 512.0f);
        if (player->auto_target < 0
            || creature_pool[player->auto_target].health <= 0.0f) {
            movement_heading =
                VEC2_Angle(*(vec2_t *)&player->position - center) + 3.1415927f;
        } else {
            vec2_t direction;
            if (VEC2_Length(*(vec2_t *)&player->position - center) > 300.0f) {
                direction = *(vec2_t *)&player->position - center;
            } else {
                direction = *(vec2_t *)&player->position
                    - *(vec2_t *)&creature_pool[player->auto_target].position;
            }
            movement_heading = VEC2_Angle(direction) - 1.5707964f;
        }

        if (movement_heading != -1.0f) {
            angle_step = player_heading_approach_target(
                movement_heading);
            player_accelerate_move_speed(player);
            player_apply_move_speed_cap(player);

            player->move_dx = (cosf(player->heading - 1.5707964f) * player->move_speed)
                * (3.1415927f - angle_step) * speed_scale * 7.957747f;
            player->move_dy = (sinf(player->heading - 1.5707964f) * player->move_speed)
                * (3.1415927f - angle_step) * speed_scale * 7.957747f;
            vec2_t move = frame_dt * *(vec2_t *)&player->movement;
            player_apply_move_with_spawn_avoidance(
                render_overlay_player_index,
                &player->position,
                &move);
        } else {
            player_decelerate_move_speed(player);
            player->move_dx =
                cosf(player->heading - 1.5707964f)
                * player->move_speed * speed_scale * 25.0f;
            player->move_dy =
                sinf(player->heading - 1.5707964f)
                * player->move_speed * speed_scale * 25.0f;
            vec2_t move = frame_dt * *(vec2_t *)&player->movement;
            player_apply_move_with_spawn_avoidance(
                render_overlay_player_index,
                &player->position,
                &move);
        }
        player->move_phase =
            frame_dt * player->move_speed * 19.0f + player->move_phase;
    }

    if (time_scale_active != 0) {
        frame_dt = time_scale_factor * frame_dt * 1.6666666f;
    }

    if (perk_count_get(perk_id_sharpshooter) != 0) {
        player->spread_heat = player->spread_heat - (frame_dt + frame_dt);
        if (player->spread_heat < 0.25f) {
            player->spread_heat = 0.25f;
        }
        player->spread_heat = 0.02f;
    } else {
        player->spread_heat = player->spread_heat - frame_dt * 0.4f;
        if (player->spread_heat < 0.01f) {
            player->spread_heat = 0.01f;
        }
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

    float reload_scale = 1.0f;
    if (((vec2_t *)&player->position)->x == previous_pos.x
        && player->position.y == previous_pos.y) {
        if (perk_count_get(perk_id_stationary_reloader) != 0) {
            reload_scale = 3.0f;
        }
    } else {
        player->man_bomb_timer = 0.0f;
        player->living_fortress_timer = 0.0f;
    }

    if (perk_count_get(perk_id_angry_reloader) != 0
        && player->reload_timer_max > 0.5f) {
        float half_reload = player->reload_timer_max * 0.5f;
        if (half_reload < player->reload_timer) {
            player->reload_timer = player->reload_timer - reload_scale * frame_dt;
            if (player->reload_timer <= half_reload) {
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
                        float ring_step = 6.2831855f / (float)projectile_count;
                        do {
                            projectile_spawn(
                                &player->position,
                                (float)projectile_index * ring_step + 0.1f,
                                PROJECTILE_TYPE_PLASMA_MINIGUN,
                                owner_id);
                            ++projectile_index;
                        } while (projectile_index < projectile_count);
                    }
                    bonus_spawn_guard = 0;
                    sfx_play_panned(sfx_explosion_small, &player->position, 1.0f);
            }
        } else {
            player->reload_timer = player->reload_timer - reload_scale * frame_dt;
        }
    } else {
        player->reload_timer = player->reload_timer - reload_scale * frame_dt;
    }

    if (player->reload_timer < 0.0f) {
        player->reload_timer = 0.0f;
    }

    if (demo_mode_active == 0
        && perk_count_get(perk_id_alternate_weapon) == 0
        && config_movement_schemes[render_overlay_player_index] != 4
        && grim_interface_ptr->grim_is_key_active(config_key_reload)
        && player->reload_timer == 0.0f
        && config_player_count == 1) {
        player_start_reload();
    }

    auto_fire = false;
    if (demo_mode_active == 0
        && config_aim_schemes[render_overlay_player_index] != 5) {
        int aim_scheme = config_aim_schemes[render_overlay_player_index];
        if (aim_scheme == 0) {
            player_update_vec2_t *mouse_screen =
                (player_update_vec2_t *)&player_aim_screen_x[
                    render_overlay_player_index * 2];
            *(vec2_t *)&player->aim = vec2_t(
                mouse_screen->x - camera_offset_x,
                mouse_screen->y - camera_offset_y);
            player->aim_heading =
                VEC2_Angle(
                    *(vec2_t *)&player->position - *(vec2_t *)&player->aim)
                - 1.5707964f;
        }
        if (aim_scheme == 4) {
            scalar = grim_interface_ptr->grim_get_config_float(
                player->input.axis_aim_y);
            vec2_t pad;
            pad.x = grim_interface_ptr->grim_get_config_float(
                player->input.axis_aim_x);
            pad.y = scalar;
            float length = sqrtf(
                pad.x * pad.x
                + scalar * scalar);
            if (1.0f < length) {
                scalar = 1.0f;
            } else {
                scalar = length;
            }
            D3DXVec2Normalize(&pad, &pad);
            float distance = scalar * cv_padAimDistMul->value + 42.0f;
            *(vec2_t *)&player->aim = pad * distance + *(vec2_t *)&player->position;
            player->aim_heading =
                VEC2_Angle(
                    *(vec2_t *)&player->position - *(vec2_t *)&player->aim)
                - 1.5707964f;
        }
        if (aim_scheme == 3) {
            player_update_vec2_t *stick_screen =
                (player_update_vec2_t *)&player_aim_screen_x[
                    render_overlay_player_index * 2];
            vec2_t stick(
                stick_screen->x - 200.0f,
                stick_screen->y - 200.0f);
            if (stick.x != 0.0f || stick.y != 0.0f) {
                player->aim_heading =
                    VEC2_Angle(stick)
                    + 1.5707964f;
                vec2_t direction(cosf(player->aim_heading - 1.5707964f), sinf(player->aim_heading - 1.5707964f));
                *(vec2_t *)&player->aim = direction * 60.0f + *(vec2_t *)&player->position;
            }
            if (VEC2_Length(stick)
                > 30.0f) {
                D3DXVec2Normalize(
                    &stick,
                    &stick);
                *(player_update_vec2_t *)&player_aim_screen_x[
                    render_overlay_player_index * 2] =
                    stick * 30.0f + vec2_t(200.0f, 200.0f);
            }
        }
        if (aim_scheme == 1) {
            int move_mode =
                config_movement_schemes[render_overlay_player_index];
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
                vec2_t direction(cosf(player->aim_heading - 1.5707964f), sinf(player->aim_heading - 1.5707964f));
                *(vec2_t *)&player->aim = direction * 60.0f + *(vec2_t *)&player->position;
            }
        }
        if (aim_scheme != 0 && aim_scheme != 4 && aim_scheme != 3 && aim_scheme != 1) {
            if (input_aim_pov_left_active()) {
                player->aim_heading =
                    player->aim_heading - frame_dt * 4.0f;
            }
            if (input_aim_pov_right_active()) {
                player->aim_heading =
                    player->aim_heading + frame_dt * 4.0f;
            }
            vec2_t direction(cosf(player->aim_heading - 1.5707964f), sinf(player->aim_heading - 1.5707964f));
            *(vec2_t *)&player->aim = direction * 60.0f + *(vec2_t *)&player->position;
        }
    } else {
        vec2_t aim_delta = *(vec2_t *)&creature_pool[player->auto_target].position
            - *(vec2_t *)&player->aim;
        scalar = VEC2_Length(aim_delta);
        if (!(scalar >= 4.0f)) {
            *(vec2_t *)&player->aim = *(vec2_t *)&creature_pool[player->auto_target].position;
        } else {
            D3DXVec2Normalize(&aim_delta, &aim_delta);
            angle_step = (scalar * 6.0f) * frame_dt;
            vec2_t aim_step;
            aim_step.x = aim_delta.x * angle_step;
            aim_step.y = aim_delta.y * angle_step;
            *(vec2_t *)&player->aim += aim_step;
        }
        if (scalar < 128.0f && creature_pool[player->auto_target].health > 0.0f) {
            auto_fire = true;
        }
    }

    player->aim_heading =
        VEC2_Angle(
            *(vec2_t *)&player->position - *(vec2_t *)&player->aim)
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
        if ((player_alt_weapon_swap_cooldown_ms <= 0
                || (player_alt_weapon_swap_cooldown_ms =
                        player_alt_weapon_swap_cooldown_ms - frame_dt_ms,
                    player_alt_weapon_swap_cooldown_ms <= 0))
            && grim_interface_ptr->grim_is_key_active(config_key_reload)) {
            pu_swap(player->alt_weapon_id, player->weapon_id);
            pu_swap(player->alt_clip_size, player->clip_size);
            pu_swap(player->alt_reload_active, player->reload_active);
            pu_swap(player->alt_ammo, player->ammo);
            pu_swap(player->alt_reload_timer, player->reload_timer);
            pu_swap(player->alt_shot_cooldown, player->shot_cooldown);
            pu_swap(player->alt_reload_timer_max, player->reload_timer_max);

            sfx_play_panned(
                weapon_table[player->weapon_id].reload_sfx_id,
                &player->position,
                1.0f);
            player->shot_cooldown = player->shot_cooldown + 0.1f;
            player_alt_weapon_swap_cooldown_ms = 200;
        } else if (!grim_interface_ptr->grim_is_key_active(config_key_reload)) {
            player_alt_weapon_swap_cooldown_ms = 0;
        }
    }

    if ((normal_fire_ready || perk_fire_ready)
        && (fire_heading = player->aim_heading,
            grim_interface_ptr->grim_is_key_active(player->input.fire_key)
                || auto_fire)) {
        int owner_id;
        survival_reward_fire_seen = 1;

        if (!normal_fire_ready) {
            if (perk_count_get(perk_id_regression_bullets) != 0) {
                if (weapon_ammo_class[player->weapon_id].ammo_class == 1) {
                    player->experience = player->experience
                        - weapon_table[player->weapon_id].reload_time * 4.0f;
                } else {
                    player->experience = player->experience
                        - weapon_table[player->weapon_id].reload_time * 200.0f;
                }
            } else if (perk_count_get(perk_id_ammunition_within) != 0) {
                if (weapon_ammo_class[player->weapon_id].ammo_class == 1) {
                    player_take_damage(render_overlay_player_index, 0.15f);
                } else {
                    player_take_damage(render_overlay_player_index, 1.0f);
                }
            }
            if (player->experience < 0) {
                player->experience = 0;
            }
        }

        turn_angle = fire_heading - 1.5707964f;
        float muzzle_angle = turn_angle - 0.150915f;
        vec2_t muzzle_offset(cosf(muzzle_angle) * 16.0f, sinf(muzzle_angle) * 16.0f);

        if ((weapon_table[player->weapon_id].flags & 1) != 0) {
            effect_color_t smoke_color;
            scalar = (float)(crt_rand() & 0x3f) * 0.01f
                + fire_heading;
            float smoke_speed = (float)(crt_rand() & 0x3f) * 0.022727273f + 1.0f;
            smoke_color.r = 1.0f;
            smoke_color.g = 1.0f;
            smoke_color.b = 1.0f;
            smoke_color.a = 0.6f;
            effect_template.flags = 0x1c5;
            effect_template.color = smoke_color;
            effect_template.lifetime = 0.15f;
            effect_template.age = 0.0f;
            vec2_t drift(cosf(scalar) * smoke_speed, sinf(scalar) * smoke_speed);
            effect_template.rotation =
                (float)((crt_rand() & 0x3f) - 0x20) * 0.1f;
            effect_template.half_extent.y = 2.0f;
            effect_template.half_extent.x = 2.0f;
            effect_template.velocity.x = drift.x * 100.0f;
            effect_template.velocity.y = drift.y * 100.0f;
            effect_template.rotation_step =
                ((float)(crt_rand() % 20) * 0.1f - 1.0f) * 14.0f;
            effect_template.scale_step = 0.0f;
            effect_spawn(0x12, &(muzzle_offset + *(vec2_t *)&player->position));
        }

        if (*muzzle_flash_alpha > 1.0f) {
            *muzzle_flash_alpha = 1.0f;
        }

        scalar = 1.0f;
        if (cv_friendlyFire->value != 0.0f) {
            owner_id = -1 - render_overlay_player_index;
        } else {
            owner_id = -100;
        }

        int spread_index = render_overlay_player_index;
        vec2_t spread_target = *(vec2_t *)&player_state_table[spread_index].aim;
        {
            vec2_t spread_delta = spread_target
                - *(vec2_t *)&player_state_table[spread_index].position;
            float spread_radius = vec2_length(&spread_delta) * 0.5f;
            float spread_angle =
                (float)(crt_rand() & 0x1ff) * 0.012271847f;
            float spread_distance = (float)(crt_rand() & 0x1ff)
                * (spread_radius * player_state_table[spread_index].spread_heat)
                * 0.001953125f;
            spread_target.x =
                cosf(spread_angle) * spread_distance + spread_target.x;
            spread_target.y =
                sinf(spread_angle) * spread_distance + spread_target.y;
        }
        angle_step = VEC2_Angle(
            *(vec2_t *)&player_state_table[spread_index].position - spread_target)
            - 1.5707964f;

        if (grim_interface_ptr->grim_is_key_active(0x22)) {
            player->fire_bullets_timer = 10.0f;
        }
        if (player->fire_bullets_timer > 0.0f) {
            sfx_play_panned(
                fire_bullets_primary_shot_sfx_id,
                &player->position,
                1.0f);
            sfx_play_panned(
                fire_bullets_secondary_shot_sfx_id,
                &player->position,
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
                float pellet_angle = (float)(crt_rand() % 200 - 100) * 0.0015f
                    + angle_step;
                projectile_spawn(
                    &(muzzle_offset + *(vec2_t *)&player->position),
                    pellet_angle,
                    PROJECTILE_TYPE_FIRE_BULLETS,
                    owner_id);
            }

            {
                vec2_t velocity(cosf(fire_heading) * 25.0f, sinf(fire_heading) * 25.0f);
                int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                sprite_effect_pool[effect_index].color_r = 0.5f;
                sprite_effect_pool[effect_index].color_g = 0.5f;
                sprite_effect_pool[effect_index].color_b = 0.5f;
                sprite_effect_pool[effect_index].color_a = 0.413f;
            }

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
                &player->position,
                1.0f);

            if (player->weapon_id == WEAPON_ID_SHRINKIFIER_5K) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_SHRINKIFIER,
                        owner_id);
                }
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.23f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.213f;
                }
            } else if (player->weapon_id == WEAPON_ID_PISTOL) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PISTOL,
                        owner_id);
                }
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.23f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.213f;
                }
            } else if (player->weapon_id == WEAPON_ID_ASSAULT_RIFLE) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.23f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.213f;
                }
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_ASSAULT_RIFLE,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_SHOTGUN) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.25f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.223f;
                }

                int pellet_count = 12;
                do {
                    int projectile_index = projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        (float)(crt_rand() % 200 - 100) * 0.0013f
                            + angle_step,
                        PROJECTILE_TYPE_SHOTGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .fields.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_JACKHAMMER) {
                {
                    vec2_t velocity(cosf(fire_heading) * 15.0f, sinf(fire_heading) * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.223f;
                }

                int pellet_count = 4;
                do {
                    int projectile_index = projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        (float)(crt_rand() % 200 - 100) * 0.0013f
                            + angle_step,
                        PROJECTILE_TYPE_SHOTGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .fields.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_SAWED_OFF_SHOTGUN) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.26f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.233f;
                }

                int pellet_count = 12;
                do {
                    int projectile_index = projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        (float)(crt_rand() % 200 - 100) * 0.004f
                            + angle_step,
                        PROJECTILE_TYPE_SHOTGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .fields.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_FLAMETHROWER) {
                {
                    fx_spawn_particle(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        turn_angle,
                        &player->movement,
                        1.0f);
                }
                scalar = 0.1f;
            } else if (player->weapon_id == WEAPON_ID_HR_FLAMER) {
                {
                    owner_id = fx_spawn_particle(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        turn_angle,
                        &player->movement,
                        1.0f);
                }
                if (owner_id != -1) {
                    particle_pool[owner_id].style_id = 2;
                }
                scalar = 0.1f;
            } else if (player->weapon_id == WEAPON_ID_BLOW_TORCH) {
                {
                    owner_id = fx_spawn_particle(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        turn_angle,
                        &player->movement,
                        1.0f);
                }
                if (owner_id != -1) {
                    particle_pool[owner_id].style_id = 1;
                }
                scalar = 0.05f;
            } else if (player->weapon_id == WEAPON_ID_SUBMACHINE_GUN) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.23f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.213f;
                }
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_SUBMACHINE_GUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_PLASMA_RIFLE) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PLASMA_RIFLE,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_MULTI_PLASMA) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step - 0.31415927f,
                        PROJECTILE_TYPE_PLASMA_RIFLE,
                        owner_id);
                }
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step - 0.5235988f,
                        PROJECTILE_TYPE_PLASMA_MINIGUN,
                        owner_id);
                }
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PLASMA_RIFLE,
                        owner_id);
                }
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step + 0.5235988f,
                        PROJECTILE_TYPE_PLASMA_MINIGUN,
                        owner_id);
                }
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step + 0.31415927f,
                        PROJECTILE_TYPE_PLASMA_RIFLE,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_PULSE_GUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PULSE_GUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_BLADE_GUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_BLADE_GUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_SPLITTER_GUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_SPLITTER_GUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_ION_RIFLE) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_ION_RIFLE,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_ION_MINIGUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_ION_MINIGUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_ION_CANNON) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_ION_CANNON,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_PLASMA_CANNON) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PLASMA_CANNON,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_ION_SHOTGUN) {
                int pellet_count = 8;
                do {
                    int projectile_index = projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        (float)(crt_rand() % 200 - 100) * 0.0026f
                            + angle_step,
                        PROJECTILE_TYPE_ION_MINIGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .fields.speed_scale =
                        (float)(crt_rand() % 80) * 0.01f + 1.4f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_PLASMA_MINIGUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PLASMA_MINIGUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_GAUSS_SHOTGUN) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.33f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.263f;
                }

                int pellet_count = 6;
                do {
                    int projectile_index = projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        (float)(crt_rand() % 200 - 100) * 0.002f
                            + angle_step,
                        PROJECTILE_TYPE_GAUSS_GUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .fields.speed_scale =
                        (float)(crt_rand() % 80) * 0.01f + 1.4f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_GAUSS_GUN) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.33f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.263f;
                }
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_GAUSS_GUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_ROCKET_LAUNCHER) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.34f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.283f;
                }
                {
                    fx_spawn_secondary_projectile(&(muzzle_offset + *(vec2_t *)&player->position), angle_step, SECONDARY_PROJECTILE_TYPE_ROCKET);
                }
            } else if (player->weapon_id == WEAPON_ID_MINI_ROCKET_SWARMERS) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.34f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.283f;
                }

                rocket_step = player->ammo * 1.0471976f;
                float rocket_heading = (angle_step - 3.1415927f)
                    - rocket_step * player->ammo * 0.5f;
                int rocket_count = 0;
                if (0.0f < player->ammo) {
                    do {
                        fx_spawn_secondary_projectile(&(muzzle_offset + *(vec2_t *)&player->position), rocket_heading, SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET);
                        rocket_heading = rocket_heading + rocket_step;
                        ++rocket_count;
                    } while ((float)rocket_count < player->ammo);
                }
                scalar = player->ammo;
            } else if (player->weapon_id == WEAPON_ID_ROCKET_MINIGUN) {
                {
                    vec2_t velocity(cosf(fire_heading) * 25.0f, sinf(fire_heading) * 25.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.34f;
                }
                {
                    fx_spawn_secondary_projectile(&(muzzle_offset + *(vec2_t *)&player->position), angle_step, SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN);
                }
            } else if (player->weapon_id == WEAPON_ID_SEEKER_ROCKETS) {
                {
                    vec2_t velocity;
                    dir_x = cosf(fire_heading);
                    velocity.x = dir_x * 25.0f;
                    dir_y = sinf(fire_heading);
                    velocity.y = dir_y * 25.0f;
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 1.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.31f;
                }
                {
                    vec2_t velocity;
                    velocity.x = dir_x * 15.0f;
                    velocity.y = (dir_y * 15.0f);
                    int effect_index = fx_spawn_sprite(&(muzzle_offset + *(vec2_t *)&player->position), &velocity, 2.0f);
                    sprite_effect_pool[effect_index].color_r = 0.5f;
                    sprite_effect_pool[effect_index].color_g = 0.5f;
                    sprite_effect_pool[effect_index].color_b = 0.5f;
                    sprite_effect_pool[effect_index].color_a = 0.243f;
                }
                {
                    fx_spawn_secondary_projectile(&(muzzle_offset + *(vec2_t *)&player->position), angle_step, SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET);
                }
            } else if (player->weapon_id == WEAPON_ID_MEAN_MINIGUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PISTOL,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_PLASMA_SHOTGUN) {
                int pellet_count = 14;
                do {
                    int projectile_index = projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        (float)((crt_rand() & 0xff) - 0x80) * 0.002f
                            + angle_step,
                        PROJECTILE_TYPE_PLASMA_MINIGUN,
                        owner_id);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .fields.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            } else if (player->weapon_id == WEAPON_ID_PLAGUE_SPREADER_GUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_PLAGUE_SPREADER,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_RAINBOW_GUN) {
                {
                    projectile_spawn(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step,
                        PROJECTILE_TYPE_RAINBOW_GUN,
                        owner_id);
                }
            } else if (player->weapon_id == WEAPON_ID_BUBBLEGUN) {
                {
                    fx_spawn_particle_slow(
                        &(muzzle_offset + *(vec2_t *)&player->position),
                        angle_step - 1.5707964f,
                        &player->movement);
                }
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
        if (pu_perk_level(perk_id_fastshot) > 0) {
            player->shot_cooldown = player->shot_cooldown * 0.88f;
        }
        if (pu_perk_level(perk_id_sharpshooter) > 0) {
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

    float half_size = player->size * 0.5f;
    if (((vec2_t *)&player->position)->x < half_size) {
        ((vec2_t *)&player->position)->x = half_size;
    }
    if ((float)terrain_texture_width - half_size < ((vec2_t *)&player->position)->x) {
        ((vec2_t *)&player->position)->x = (float)terrain_texture_width - half_size;
    }
    if (player->position.y < half_size) {
        player->position.y = half_size;
    }
    if ((float)terrain_texture_height - half_size < player->position.y) {
        player->position.y = (float)terrain_texture_height - half_size;
    }
    if (*muzzle_flash_alpha > 0.8f) {
        *muzzle_flash_alpha = 0.8f;
    }
}
