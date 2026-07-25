#include "crimsonland_gameplay.h"

extern "C" double atan2(double y, double x);
extern "C" double cos(double angle);
extern "C" double sin(double angle);

struct typo_fire_vec2_t {
    float x;
    float y;

    typo_fire_vec2_t() {}

    typo_fire_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    typo_fire_vec2_t operator-(const typo_fire_vec2_t &other) const
    {
        return typo_fire_vec2_t(x - other.x, y - other.y);
    }

    float angle() const
    {
        return (float)atan2(y, x);
    }
};

extern "C" {
extern unsigned char console_open_flag;
extern float player_spread_damping_scalar;
extern int perk_id_sharpshooter;
extern int perk_id_fastshot;
extern int terrain_texture_width;
extern int terrain_texture_height;

__declspec(noreturn) void crt_exit(int code);
void player_start_reload(void);
int fx_spawn_sprite(
    const vec2f_t *pos,
    const vec2f_t *vel,
    float scale);
}

extern "C" void player_fire_weapon(
    const vec2f_t *aim,
    char fire_requested,
    char reload_requested)
{
    if (!game_is_full_version()) {
        crt_exit(0);
    }
    if (console_open_flag) {
        return;
    }

    if (player_state_table[render_overlay_player_index].health <= 0.0f) {
        player_state_table[render_overlay_player_index].death_timer -=
            frame_dt * 20.0f;
        return;
    }

    player_state_table[render_overlay_player_index].muzzle_flash_alpha -=
        frame_dt + frame_dt;
    if (player_state_table[render_overlay_player_index].muzzle_flash_alpha
        < 0.0f) {
        player_state_table[render_overlay_player_index].muzzle_flash_alpha =
            0.0f;
    }

    player_state_table[render_overlay_player_index].shot_cooldown = 0.0f;
    typo_fire_vec2_t local_offset(0.0f, 0.0f);
    *(typo_fire_vec2_t *)&player_state_table[render_overlay_player_index]
         .movement = local_offset;
    player_state_table[render_overlay_player_index].spread_heat = 0.0f;
    player_state_table[render_overlay_player_index].ammo =
        player_state_table[render_overlay_player_index].clip_size;
    player_state_table[render_overlay_player_index].reload_timer = 0.0f;

    if (reload_requested) {
        player_start_reload();
    }

    bool normal_fire_ready = false;
    player_state_table[render_overlay_player_index].aim = *aim;
    player_state_table[render_overlay_player_index].aim_heading =
        (*(typo_fire_vec2_t *)&player_state_table[render_overlay_player_index]
              .position
         - *(typo_fire_vec2_t *)&player_state_table
               [render_overlay_player_index]
                   .aim)
                .angle()
        - 1.57079637f;

    if (player_state_table[render_overlay_player_index].shot_cooldown <= 0.0f
        && player_state_table[render_overlay_player_index].reload_timer
            == 0.0f) {
        normal_fire_ready = true;
        player_state_table[render_overlay_player_index].reload_active = 0;
    }

    bool perk_fire_ready = false;
    if (player_state_table[render_overlay_player_index].shot_cooldown <= 0.0f
        && player_state_table[render_overlay_player_index].experience > 0
        && (perk_count_get(perk_id_regression_bullets) != 0
            || perk_count_get(perk_id_ammunition_within) != 0)) {
        perk_fire_ready = true;
    }

    if (normal_fire_ready || perk_fire_ready) {
        float shot_heading =
            player_state_table[render_overlay_player_index].aim_heading;
        if (fire_requested) {
            float muzzle_angle =
                shot_heading - 1.57079637f - 0.150914997f;
            local_offset.x = (float)cos(muzzle_angle) * 16.0f;
            local_offset.y = (float)sin(muzzle_angle) * 16.0f;

            if ((weapon_table[player_state_table[render_overlay_player_index]
                                  .weapon_id]
                     .flags
                 & 1)
                != 0) {
                crt_rand();
                crt_rand();
            }

            if (player_state_table[render_overlay_player_index]
                    .muzzle_flash_alpha
                > 1.0f) {
                player_state_table[render_overlay_player_index]
                    .muzzle_flash_alpha = 1.0f;
            }
            player_state_table[render_overlay_player_index]
                .muzzle_flash_alpha +=
                weapon_table[player_state_table[render_overlay_player_index]
                                 .weapon_id]
                    .spread_heat;
            sfx_play_panned(
                weapon_table[player_state_table[render_overlay_player_index]
                                 .weapon_id]
                    .shot_sfx_base_id,
                &player_state_table[render_overlay_player_index].position,
                1.0f);

            if (player_state_table[render_overlay_player_index].weapon_id
                == WEAPON_ID_SHOTGUN) {
                vec2f_t effect_velocity;
                vec2f_t effect_position;
                float heading_cos = (float)cos(shot_heading);
                effect_velocity.x = heading_cos * 25.0f;
                float heading_sin = (float)sin(shot_heading);
                effect_velocity.y = heading_sin * 25.0f;
                effect_position.x =
                    player_state_table[render_overlay_player_index].position.x
                    + local_offset.x;
                effect_position.y =
                    player_state_table[render_overlay_player_index].position.y
                    + local_offset.y;

                int effect_index = fx_spawn_sprite(
                    &effect_position,
                    &effect_velocity,
                    1.0f);
                sprite_effect_pool[effect_index].color.r = 0.5f;
                sprite_effect_pool[effect_index].color.g = 0.5f;
                sprite_effect_pool[effect_index].color.b = 0.5f;
                sprite_effect_pool[effect_index].color.a = 0.25f;

                effect_velocity.x = heading_cos * 15.0f;
                effect_velocity.y = heading_sin * 15.0f;
                vec2f_t *player_position =
                    &player_state_table[render_overlay_player_index].position;
                effect_position.x =
                    player_position->x + local_offset.x;
                effect_position.y =
                    player_position->y + local_offset.y;
                effect_index = fx_spawn_sprite(
                    &effect_position,
                    &effect_velocity,
                    2.0f);
                sprite_effect_pool[effect_index].color.r = 0.5f;
                sprite_effect_pool[effect_index].color.g = 0.5f;
                sprite_effect_pool[effect_index].color.b = 0.5f;
                sprite_effect_pool[effect_index].color.a = 0.223f;

                int pellet_count = 12;
                do {
                    player_position =
                        &player_state_table[render_overlay_player_index].position;
                    effect_position.x =
                        player_position->x + local_offset.x;
                    effect_position.y =
                        player_position->y + local_offset.y;
                    int projectile_index = projectile_spawn(
                        &effect_position,
                        (float)(crt_rand() % 200 - 100) * 0.0013f
                            + shot_heading,
                        PROJECTILE_TYPE_SHOTGUN,
                        -100);
                    --pellet_count;
                    projectile_pool[projectile_index]
                        .fields.speed_scale =
                        (float)(crt_rand() % 100) * 0.01f + 1.0f;
                } while (pellet_count != 0);
            }

            int sharpshooter_perk = perk_id_sharpshooter;
            if (player_state_table[0].perk_counts[sharpshooter_perk] <= 0) {
                player_state_table[render_overlay_player_index].spread_heat +=
                    player_spread_damping_scalar * frame_dt * 150.0f;
            }
            if (player_state_table[render_overlay_player_index].spread_heat
                > player_spread_damping_scalar
                    + player_spread_damping_scalar) {
                player_state_table[render_overlay_player_index].spread_heat =
                    player_spread_damping_scalar
                    + player_spread_damping_scalar;
            }
            player_state_table[render_overlay_player_index].spread_heat *=
                player_spread_damping_scalar;

            int fastshot_perk = perk_id_fastshot;
            if (player_state_table[0].perk_counts[fastshot_perk] > 0) {
                player_state_table[render_overlay_player_index].shot_cooldown *=
                    0.88f;
            }
            if (player_state_table[0].perk_counts[sharpshooter_perk] > 0) {
                player_state_table[render_overlay_player_index].shot_cooldown *=
                    1.05f;
            }
            if (player_state_table[render_overlay_player_index].ammo <= 0.0f) {
                player_start_reload();
            }
        }
    }

    while (player_state_table[render_overlay_player_index].move_phase > 14.0f) {
        player_state_table[render_overlay_player_index].move_phase -= 14.0f;
    }

    float half_size =
        player_state_table[render_overlay_player_index].size * 0.5f;
    if (player_state_table[render_overlay_player_index].pos_x < half_size) {
        player_state_table[render_overlay_player_index].pos_x = half_size;
    }
    if ((float)terrain_texture_width - half_size
        < player_state_table[render_overlay_player_index].pos_x) {
        player_state_table[render_overlay_player_index].pos_x =
            (float)terrain_texture_width - half_size;
    }
    if (player_state_table[render_overlay_player_index].pos_y < half_size) {
        player_state_table[render_overlay_player_index].pos_y = half_size;
    }
    if ((float)terrain_texture_height - half_size
        < player_state_table[render_overlay_player_index].pos_y) {
        player_state_table[render_overlay_player_index].pos_y =
            (float)terrain_texture_height - half_size;
    }
    if (player_state_table[render_overlay_player_index].muzzle_flash_alpha
        > 0.8f) {
        player_state_table[render_overlay_player_index].muzzle_flash_alpha =
            0.8f;
    }
}
