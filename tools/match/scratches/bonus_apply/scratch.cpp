#include "crimsonland_gameplay.h"

extern "C" double atan2(double y, double x);
extern "C" double sqrt(double x);

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
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    return (float)sqrt(distance_sq);
}

extern "C" void bonus_apply(int player_index, bonus_entry_t *bonus_entry)
{
    float abs_delta;
    float multiplier;

    sfx_play(sfx_ui_bonus, 1.0f);

    multiplier = 1.0f;
    if (perk_count_get(perk_id_bonus_economist)) {
        multiplier = 1.5f;
    }

    bonus_id_t bonus_id = bonus_entry->bonus_id;
    if (bonus_id == BONUS_ID_WEAPON) {
        weapon_assign_player(player_index, bonus_entry->time.amount);
    } else if (bonus_id == BONUS_ID_MEDIKIT) {
        if (player_state_table[player_index].health < 100.0f) {
            player_state_table[player_index].health += 10.0f;
            if (player_state_table[player_index].health > 100.0f) {
                player_state_table[player_index].health = 100.0f;
            }
        }
    } else if (bonus_id == BONUS_ID_REFLEX_BOOST) {
        if (bonus_reflex_boost_timer <= 0.0f) {
            bonus_hud_slot_activate(
                bonus_label_reflex_boost,
                bonus_icon_reflex_boost,
                &bonus_reflex_boost_timer,
                0);
        }
        bonus_reflex_boost_timer += (float)bonus_entry->time.amount * multiplier;
        for (int player_iter = 0; player_iter < config_blob.player_count; ++player_iter) {
            player_state_table[player_iter].ammo = player_state_table[player_iter].clip_size;
            player_state_table[player_iter].reload_timer = 0.0f;
        }
        effect_color_t color = {0.6f, 0.6f, 1.0f, 1.0f};
        effect_template.flags = 25;
        effect_template.color = color;
        effect_template_lifetime = 0.25f;
        effect_template_age = 0.0f;
        effect_template_half_width = 32.0f;
        effect_template_half_height = 32.0f;
        effect_template_rotation = 0.0f;
        effect_template_vel_x = 0.0f;
        effect_template_vel_y = 0.0f;
        effect_template_scale_step = 50.0f;
        effect_spawn(1, &bonus_entry->time.position);
        effect_template_rotation = 0.0f;
        effect_template_vel_x = 0.0f;
        effect_template_vel_y = 0.0f;
    } else if (bonus_id == BONUS_ID_WEAPON_POWER_UP) {
        if (bonus_weapon_power_up_timer <= 0.0f) {
            bonus_hud_slot_activate(
                bonus_label_weapon_power_up,
                bonus_icon_weapon_power_up,
                &bonus_weapon_power_up_timer,
                0);
        }
        bonus_weapon_power_up_timer += (float)bonus_entry->time.amount * multiplier;
        player_state_table[player_index].weapon_reset_latch = 0;
        player_state_table[player_index].shot_cooldown = 0.0f;
        player_state_table[player_index].reload_timer = 0.0f;
        player_state_table[player_index].ammo = player_state_table[player_index].clip_size;
    } else if (bonus_id == BONUS_ID_SPEED) {
        if (player_state_table[0].speed_bonus_timer <= 0.0f
            && player_state_table[1].speed_bonus_timer <= 0.0f) {
            bonus_hud_slot_activate(
                bonus_label_speed,
                bonus_icon_speed,
                &player_state_table[0].speed_bonus_timer,
                &player_state_table[1].speed_bonus_timer);
        }
        player_state_table[player_index].speed_bonus_timer += (float)bonus_entry->time.amount * multiplier;
    } else if (bonus_id == BONUS_ID_FREEZE) {
        if (bonus_freeze_timer <= 0.0f) {
            bonus_hud_slot_activate(bonus_label_freeze, bonus_icon_freeze, &bonus_freeze_timer, 0);
        }
        bonus_freeze_timer += (float)bonus_entry->time.amount * multiplier;

        for (int creature_iter = 0; creature_iter < 0x180; ++creature_iter) {
            if (creature_pool[creature_iter].active && creature_pool[creature_iter].health <= 0.0f) {
                for (int shard_iter = 0; shard_iter < 8; ++shard_iter) {
                    effect_spawn_freeze_shard(
                        &creature_pool[creature_iter].position,
                        (float)(crt_rand() % 612) * 0.01f);
                }
                effect_spawn_freeze_shatter(
                    &creature_pool[creature_iter].position,
                    (float)(crt_rand() % 612) * 0.01f);
                creature_pool[creature_iter].active = 0;
            }
        }

        effect_color_t color = {0.3f, 0.5f, 0.8f, 1.0f};
        effect_template.flags = 25;
        effect_template.color = color;
        effect_template_lifetime = 0.25f;
        effect_template_age = 0.0f;
        effect_template_half_width = 32.0f;
        effect_template_half_height = 32.0f;
        effect_template_rotation = 0.0f;
        effect_template_vel_x = 0.0f;
        effect_template_vel_y = 0.0f;
        effect_template_scale_step = 50.0f;
        effect_spawn(1, &bonus_entry->time.position);
        sfx_play_panned(
            sfx_shockwave,
            &bonus_entry->time.position,
            1.0f);
        effect_template_rotation = 0.0f;
        effect_template_vel_x = 0.0f;
        effect_template_vel_y = 0.0f;
    } else if (bonus_id == BONUS_ID_SHIELD) {
        if (player_state_table[0].shield_timer <= 0.0f && player_state_table[1].shield_timer <= 0.0f) {
            bonus_hud_slot_activate(
                bonus_label_shield,
                bonus_icon_shield,
                &player_state_table[0].shield_timer,
                &player_state_table[1].shield_timer);
        }
        player_state_table[player_index].shield_timer += (float)bonus_entry->time.amount * multiplier;
    } else if (bonus_id == BONUS_ID_SHOCK_CHAIN) {
        int owner;
        bonus_spawn_guard = 1;
        if (cv_friendlyFire->value != 0.0f) {
            owner = -1 - player_index;
        } else {
            owner = -100;
        }
        shock_chain_links_left = 32;

        const vec2f_t *bonus_pos =
            &bonus_entry->time.position;
        int creature_index = creature_find_nearest(
            bonus_pos,
            -1,
            0.0f);
        const vec2f_t *target_pos =
            &creature_pool[creature_index].position;
        float dx = target_pos->x - bonus_pos->x;
        float dy = target_pos->y - bonus_pos->y;
        shock_chain_projectile_id = projectile_spawn(
            bonus_pos,
            (float)atan2(dy, dx) - 1.5707964f - 3.1415927f,
            PROJECTILE_TYPE_ION_RIFLE,
            owner);

        bonus_spawn_guard = 0;
        sfx_play_panned(sfx_shock_hit_01, bonus_pos, 1.0f);
    } else if (bonus_id == BONUS_ID_FIREBLAST) {
        int owner;
        bonus_spawn_guard = 1;
        if (cv_friendlyFire->value != 0.0f) {
            owner = -1 - player_index;
        } else {
            owner = -100;
        }
        for (int ring_iter = 0; ring_iter < 16; ++ring_iter) {
            projectile_spawn(
                &bonus_entry->time.position,
                (float)ring_iter * 0.39269909f,
                PROJECTILE_TYPE_PLASMA_RIFLE,
                owner);
        }
        bonus_spawn_guard = 0;
        sfx_play_panned(
            sfx_explosion_medium,
            &bonus_entry->time.position,
            1.0f);
    } else if (bonus_id == BONUS_ID_FIRE_BULLETS) {
        if (player_state_table[0].fire_bullets_timer <= 0.0f
            && player_state_table[1].fire_bullets_timer <= 0.0f) {
            bonus_hud_slot_activate(
                bonus_label_fire_bullets,
                bonus_icon_fire_bullets,
                &player_state_table[0].fire_bullets_timer,
                &player_state_table[1].fire_bullets_timer);
        }
        player_state_table[player_index].fire_bullets_timer += 5.0f * multiplier;
        player_state_table[player_index].weapon_reset_latch = 0;
        player_state_table[player_index].shot_cooldown = 0.0f;
        player_state_table[player_index].reload_timer = 0.0f;
        player_state_table[player_index].ammo = player_state_table[player_index].clip_size;
    } else if (bonus_id == BONUS_ID_ENERGIZER) {
        if (bonus_energizer_timer <= 0.0f) {
            bonus_hud_slot_activate(bonus_label_energizer, bonus_icon_energizer, &bonus_energizer_timer, 0);
        }
        bonus_energizer_timer += 8.0f * multiplier;
    } else if (bonus_id == BONUS_ID_DOUBLE_EXPERIENCE) {
        if (bonus_double_xp_timer <= 0.0f) {
            bonus_hud_slot_activate(
                bonus_label_double_experience,
                bonus_icon_double_experience,
                &bonus_double_xp_timer,
                0);
        }
        bonus_double_xp_timer += 6.0f * multiplier;
    } else if (bonus_id == BONUS_ID_NUKE) {
        int bullet_count = (crt_rand() & 3) + 4;
        for (int bullet_iter = 0; bullet_iter < bullet_count; ++bullet_iter) {
            int projectile_index = projectile_spawn(
                &bonus_entry->time.position,
                (float)(crt_rand() % 628) * 0.01f,
                PROJECTILE_TYPE_PISTOL,
                -100);
            if (projectile_index != -1) {
                projectile_pool[projectile_index].pos.tail.vy.speed_scale *=
                    (float)(crt_rand() % 50) * 0.01f + 0.5f;
            }
        }

        const vec2f_t *bonus_pos =
            &bonus_entry->time.position;
        projectile_spawn(
            bonus_pos,
            (float)(crt_rand() % 628) * 0.01f,
            PROJECTILE_TYPE_GAUSS_GUN,
            -100);
        projectile_spawn(
            bonus_pos,
            (float)(crt_rand() % 628) * 0.01f,
            PROJECTILE_TYPE_GAUSS_GUN,
            -100);
        effect_spawn_explosion_burst(bonus_pos, 1.0f);
        camera_shake_pulses = 20;
        camera_shake_timer = 0.2f;

        bonus_spawn_guard = 1;
        int creature_iter = 0;
        do {
            if (creature_pool[creature_iter].active) {
                abs_delta = abs_bits(
                    creature_pool[creature_iter].pos_x - bonus_pos->x);
                if (abs_delta <= 256.0f) {
                    abs_delta = abs_bits(creature_pool[creature_iter].pos_y - bonus_entry->time.pos_y);
                    if (abs_delta <= 256.0f) {
                        float damage = 256.0f - vec2_distance(
                            &creature_pool[creature_iter].position,
                            bonus_pos);
                        if (damage > 0.0f) {
                            vec2f_t impulse;
                            impulse.x = 0.0f;
                            impulse.y = 0.0f;
                            creature_apply_damage(
                                creature_iter,
                                damage * 5.0f,
                                3,
                                &impulse);
                        }
                    }
                }
            }
            ++creature_iter;
        } while (creature_iter < 0x180);
        bonus_spawn_guard = 0;
        sfx_play_panned(sfx_explosion_large, bonus_pos, 1.0f);
        sfx_play_panned(sfx_shockwave, bonus_pos, 1.0f);
    } else if (bonus_id == BONUS_ID_POINTS) {
        player_state_table[0].experience += bonus_entry->time.amount;
    }

    effect_color_t color = {0.4f, 0.5f, 1.0f, 0.5f};
    effect_template.flags = 29;
    effect_template.color = color;
    effect_template_lifetime = 0.4f;
    effect_template_half_width = 32.0f;
    effect_template_half_height = 32.0f;

    if (bonus_entry->bonus_id != BONUS_ID_NUKE) {
        for (int fx_iter = 0; fx_iter < 12; ++fx_iter) {
            effect_template_rotation = (float)(crt_rand() & 0x7f) * 0.049087387f;
            effect_template_vel_x = (float)(crt_rand() % 128 - 64);
            effect_template_vel_y = (float)(crt_rand() % 128 - 64);
            effect_template_scale_step = 0.1f;
            effect_spawn(0, &bonus_entry->time.position);
        }
    }
}
