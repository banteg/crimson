#include "crimsonland_gameplay.h"

extern "C" double atan2(double y, double x);
extern "C" double sqrt(double x);

typedef union bonus_apply_locals_t {
    float f[4];
    int i[4];
} bonus_apply_locals_t;

#define multiplier locals.f[0]
#define angle locals.f[1]
#define impulse locals.f[2]
#define random_value locals.i[3]
#define color_bits_a locals.i[2]
#define color_bits_b locals.i[3]

extern "C" void bonus_apply(int player_index, bonus_entry_t *bonus_entry)
{
    bonus_apply_locals_t locals;

    sfx_play(sfx_ui_bonus, 1.0f);

    multiplier = 1.0f;
    if (perk_count_get(perk_id_bonus_economist)) {
        multiplier = 1.5f;
    }

    bonus_id_t bonus_id = bonus_entry->bonus_id;
    if (bonus_id == BONUS_ID_WEAPON) {
        weapon_assign_player(player_index, bonus_entry->time.amount);
    } else if (bonus_id == BONUS_ID_MEDIKIT) {
        player_state_t *player = &player_state_table[player_index];
        if (player->health < 100.0f) {
            player->health += 10.0f;
            if (player->health > 100.0f) {
                player->health = 100.0f;
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
            player_state_table[player_iter].reload_active = 0;
        }
        color_bits_a = 0x3f19999a;
        color_bits_b = 0x3f800000;
        effect_template_color_r = *(float *)&color_bits_a;
        effect_template_color_g = *(float *)&color_bits_a;
        effect_template_color_b = *(float *)&color_bits_b;
        effect_template_color_a = *(float *)&color_bits_b;
        effect_template_flags = 25;
        effect_template_lifetime = 0.25f;
        effect_template_age = 0.0f;
        effect_template_half_width = 32.0f;
        effect_template_half_height = 32.0f;
        effect_template_rotation = 0.0f;
        effect_template_vel_x = 0.0f;
        effect_template_vel_y = 0.0f;
        effect_template_scale_step = 50.0f;
        effect_spawn(1, &bonus_entry->time.pos_x);
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
        player_state_t *player = &player_state_table[player_index];
        player->weapon_reset_latch = 0;
        player->shot_cooldown = 0.0f;
        player->reload_timer = 0.0f;
        player->ammo = player->clip_size;
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

        for (creature_t *creature = creature_pool; creature < &creature_pool[0x180]; ++creature) {
            if (creature->active && creature->health <= 0.0f) {
                float *pos = &creature->pos_x;
                for (int shard_iter = 0; shard_iter < 8; ++shard_iter) {
                    random_value = crt_rand() % 612;
                    angle = (float)random_value * 0.01f;
                    effect_spawn_freeze_shard(pos, angle);
                }
                random_value = crt_rand() % 612;
                angle = (float)random_value * 0.01f;
                effect_spawn_freeze_shatter(pos, angle);
                creature->active = 0;
            }
        }

        color_bits_a = 0x3e99999a;
        color_bits_b = 0x3f000000;
        effect_template_color_r = *(float *)&color_bits_a;
        effect_template_color_g = *(float *)&color_bits_b;
        color_bits_a = 0x3f4ccccd;
        effect_template_color_b = *(float *)&color_bits_a;
        color_bits_b = 0x3f800000;
        effect_template_color_a = *(float *)&color_bits_b;
        effect_template_flags = 25;
        effect_template_lifetime = 0.25f;
        effect_template_age = 0.0f;
        effect_template_half_width = 32.0f;
        effect_template_half_height = 32.0f;
        effect_template_rotation = 0.0f;
        effect_template_vel_x = 0.0f;
        effect_template_vel_y = 0.0f;
        effect_template_scale_step = 50.0f;
        effect_spawn(1, &bonus_entry->time.pos_x);
        sfx_play_panned(sfx_shockwave, &bonus_entry->time.pos_x, 1.0f);
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
        if (cv_friendlyFire->value == 0.0f) {
            owner = -100;
        } else {
            owner = -1 - player_index;
        }
        shock_chain_links_left = 32;

        int creature_index = creature_find_nearest(&bonus_entry->time.pos_x, -1, 0.0f);
        creature_t *target = &creature_pool[creature_index];
        float dx = target->pos_x - bonus_entry->time.pos_x;
        float dy = target->pos_y - bonus_entry->time.pos_y;
        angle = (float)atan2(dy, dx) - 1.5707964f - 3.1415927f;
        shock_chain_projectile_id =
            projectile_spawn(&bonus_entry->time.pos_x, angle, PROJECTILE_TYPE_ION_RIFLE, owner);

        bonus_spawn_guard = 0;
        sfx_play_panned(sfx_shock_hit_01, &bonus_entry->time.pos_x, 1.0f);
    } else if (bonus_id == BONUS_ID_FIREBLAST) {
        int owner;
        bonus_spawn_guard = 1;
        if (cv_friendlyFire->value == 0.0f) {
            owner = -100;
        } else {
            owner = -1 - player_index;
        }
        for (int ring_iter = 0; ring_iter < 16; ++ring_iter) {
            angle = (float)ring_iter * 0.39269909f;
            projectile_spawn(&bonus_entry->time.pos_x, angle, PROJECTILE_TYPE_PLASMA_RIFLE, owner);
        }
        bonus_spawn_guard = 0;
        sfx_play_panned(sfx_explosion_medium, &bonus_entry->time.pos_x, 1.0f);
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
        player_state_t *player = &player_state_table[player_index];
        player->weapon_reset_latch = 0;
        player->shot_cooldown = 0.0f;
        player->reload_timer = 0.0f;
        player->ammo = player->clip_size;
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
            random_value = crt_rand() % 628;
            angle = (float)random_value * 0.01f;
            int projectile_index =
                projectile_spawn(&bonus_entry->time.pos_x, angle, PROJECTILE_TYPE_PISTOL, -100);
            if (projectile_index != -1) {
                projectile_pool[projectile_index].pos.tail.vy.speed_scale *=
                    (float)(crt_rand() % 50) * 0.01f + 0.5f;
            }
        }

        random_value = crt_rand() % 628;
        angle = (float)random_value * 0.01f;
        projectile_spawn(&bonus_entry->time.pos_x, angle, PROJECTILE_TYPE_GAUSS_GUN, -100);
        random_value = crt_rand() % 628;
        angle = (float)random_value * 0.01f;
        projectile_spawn(&bonus_entry->time.pos_x, angle, PROJECTILE_TYPE_GAUSS_GUN, -100);
        effect_spawn_explosion_burst(&bonus_entry->time.pos_x, 1.0f);
        camera_shake_pulses = 20;
        camera_shake_timer = 0.2f;

        bonus_spawn_guard = 1;
        for (int creature_iter = 0; creature_iter < 0x180; ++creature_iter) {
            creature_t *creature = &creature_pool[creature_iter];
            if (creature->active) {
                float dx = creature->pos_x - bonus_entry->time.pos_x;
                *(int *)&dx &= 0x7fffffff;
                if (dx < 256.0f) {
                    float dy = creature->pos_y - bonus_entry->time.pos_y;
                    *(int *)&dy &= 0x7fffffff;
                    if (dy < 256.0f) {
                        float raw_dx = creature->pos_x - bonus_entry->time.pos_x;
                        float raw_dy = creature->pos_y - bonus_entry->time.pos_y;
                        float distance = (float)sqrt(raw_dx * raw_dx + raw_dy * raw_dy);
                        float damage = 256.0f - distance;
                        if (damage > 0.0f) {
                            impulse = 0.0f;
                            creature_apply_damage(creature_iter, damage * 5.0f, 3, &impulse);
                        }
                    }
                }
            }
        }
        bonus_spawn_guard = 0;
        sfx_play_panned(sfx_explosion_large, &bonus_entry->time.pos_x, 1.0f);
        sfx_play_panned(sfx_shockwave, &bonus_entry->time.pos_x, 1.0f);
    } else if (bonus_id == BONUS_ID_POINTS) {
        player_state_table[0].experience += bonus_entry->time.amount;
    }

    color_bits_a = 0x3ecccccd;
    color_bits_b = 0x3f000000;
    effect_template_color_r = *(float *)&color_bits_a;
    effect_template_color_g = *(float *)&color_bits_b;
    color_bits_a = 0x3f800000;
    effect_template_color_b = *(float *)&color_bits_a;
    effect_template_color_a = *(float *)&color_bits_b;
    effect_template_flags = 29;
    effect_template_lifetime = 0.4f;
    effect_template_half_width = 32.0f;
    effect_template_half_height = 32.0f;

    if (bonus_entry->bonus_id != BONUS_ID_NUKE) {
        for (int fx_iter = 0; fx_iter < 12; ++fx_iter) {
            effect_template_rotation = (float)(crt_rand() & 0x7f) * 0.02f;
            effect_template_vel_x = (float)(crt_rand() % 128 - 64);
            effect_template_vel_y = (float)(crt_rand() % 128 - 64);
            effect_template_scale_step = 0.1f;
            effect_spawn(0, &bonus_entry->time.pos_x);
        }
    }
}

#undef multiplier
#undef angle
#undef impulse
#undef random_value
#undef color_bits_a
#undef color_bits_b
