#include <math.h>

#include "crimsonland_gameplay.h"

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
extern player_aim_screen_xy_t player_aim_screen_x;
extern float perk_man_bomb_trigger_interval_s;
extern float perk_fire_cough_trigger_interval_s;
extern float perk_hot_tempered_trigger_interval_s;
extern float player_spread_damping_gate;
extern float player_spread_damping_scalar;
extern int perk_id_hot_tempered;
extern int sfx_bloodspill_01;
extern int sfx_explosion_small;
extern int fire_bullets_primary_shot_sfx_id;
extern int fire_bullets_secondary_shot_sfx_id;

void effect_spawn_blood_splatter(float *pos, float angle, float age);
float vec2_length(float *v);
int fx_spawn_sprite(float *pos, float *vel, float scale);
}

extern "C" void player_update(void)
{
    int player_index;
    if (console_open_flag != 0) {
        return;
    }

    player_index = render_overlay_player_index;
    player_aim_screen_x[player_index * 2] = ui_mouse_x;
    player_aim_screen_x[player_index * 2 + 1] = ui_mouse_y;

    player_state_t *player = &player_state_table[player_index];
    player_update_vec2_t previous_pos;
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
            player_update_vec2_t blood_pos;
            blood_pos.x = (float)cos(angle + 1.5707964f - 0.5f) * -6.0f
                + player->pos_x;
            blood_pos.y = (float)sin(angle + 1.5707964f - 0.5f) * -6.0f
                + player->pos_y;
            effect_spawn_blood_splatter(&blood_pos.x, angle, 0.0f);
            effect_spawn_blood_splatter(&blood_pos.x, angle, 0.0f);
            effect_spawn_blood_splatter(&blood_pos.x, angle, 0.0f);
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
            player_update_vec2_t muzzle_offset;
            muzzle_offset.x = (float)cos(muzzle_heading) * 16.0f;
            muzzle_offset.y = (float)sin(muzzle_heading) * 16.0f;

            player_update_vec2_t randomized_aim;
            randomized_aim.x = player->aim_x;
            randomized_aim.y = player->aim_y;
            player_update_vec2_t aim_delta;
            aim_delta.x = randomized_aim.x - player->pos_x;
            aim_delta.y = randomized_aim.y - player->pos_y;
            float spread_radius = vec2_length(&aim_delta.x) * 0.5f;
            float spread_angle =
                (float)(crt_rand() & 0x1ff) * 0.012271847f;
            spread_radius = spread_radius * player->spread_heat
                * (float)(crt_rand() & 0x1ff) * 0.001953125f;
            randomized_aim.x = (float)cos(spread_angle) * spread_radius
                + randomized_aim.x;
            randomized_aim.y = (float)sin(spread_angle) * spread_radius
                + randomized_aim.y;

            player_update_vec2_t shot_delta;
            ((vec2_t *)&player->pos_x)->vec2_sub(
                &shot_delta.x,
                &randomized_aim.x);
            float shot_heading =
                (float)atan2(shot_delta.y, shot_delta.x) - 1.5707964f;
            player_update_vec2_t muzzle_pos;
            muzzle_pos.x = muzzle_offset.x + player->pos_x;
            muzzle_pos.y = muzzle_offset.y + player->pos_y;
            projectile_spawn(
                &muzzle_pos.x,
                shot_heading,
                PROJECTILE_TYPE_FIRE_BULLETS,
                owner_id);

            player_update_vec2_t effect_velocity;
            effect_velocity.x = (float)cos(aim_heading) * 25.0f;
            effect_velocity.y = (float)sin(aim_heading) * 25.0f;
            int effect_index = fx_spawn_sprite(
                &muzzle_pos.x,
                &effect_velocity.x,
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
}
