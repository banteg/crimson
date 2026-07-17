#include <math.h>

#include "crimsonland_gameplay.h"

extern "C" {
extern int projectile_update_tick;
extern int perk_id_ion_gun_master;
extern int perk_id_barrel_greaser;
extern int perk_id_bloody_mess_quick_learner;
extern int highscore_record_shots_hit;
extern unsigned char music_playlist_randomized_latch;
extern int music_track_extra_0;
extern int sfx_bullet_hit_01;
extern int weapon_ammo_class[];

void creatures_apply_radius_damage(
    float *pos,
    float radius,
    float damage,
    int damage_type);
int creature_find_in_radius(float *pos, float radius, int start_index);
int player_find_in_radius(int owner_id, float *pos, float radius);
int vec2_add(float *dst, float *delta);
int vec2_add_inplace(int entity_index, float *pos, float *delta);
void effect_spawn_blood_splatter(float *pos, float angle, float age);
void effect_spawn_splitter_hit_burst(float *pos, float radius, int count);
void effect_spawn_ion_hit_sparks(float *pos, float scale);
void effect_spawn_shrinkifier_hit(float *pos);
void fx_queue_add_random(vec2f_t *pos);
void creature_handle_death(int creature_id, unsigned char keep_corpse);
void sfx_play_exclusive(int sfx_id);
}

extern "C" void projectile_update(void)
{
    float ion_damage_scale = 1.0f;

    ++projectile_update_tick;
    if (perk_count_get(perk_id_ion_gun_master) != 0) {
        ion_damage_scale = 1.2f;
    }

    int projectile_index = 0;
    do {
        projectile_t *projectile = &projectile_pool[projectile_index];
        if (projectile->active) {
            if (projectile->pos.tail.vy.life_timer <= 0.0f) {
                projectile->active = 0;
            }

            if (projectile->pos.tail.vy.life_timer < 0.4f) {
                projectile_type_id_t type_id =
                    projectile->pos.tail.vy.type_id;

                if (type_id == PROJECTILE_TYPE_ION_RIFLE
                    || type_id == PROJECTILE_TYPE_ION_MINIGUN) {
                    if (projectile_index == shock_chain_projectile_id) {
                        shock_chain_projectile_id = -1;
                        shock_chain_links_left = 0;
                    }

                    projectile->pos.tail.vy.life_timer -= frame_dt;
                    float radius;
                    float damage;
                    if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
                        damage = frame_dt * 100.0f;
                        radius = ion_damage_scale * 88.0f;
                    } else {
                        damage = frame_dt * 40.0f;
                        radius = ion_damage_scale * 60.0f;
                    }
                    creatures_apply_radius_damage(
                        &projectile->pos_x,
                        radius,
                        damage,
                        7);
                } else if (type_id == PROJECTILE_TYPE_ION_CANNON) {
                    projectile->pos.tail.vy.life_timer -= frame_dt * 0.7f;
                    creatures_apply_radius_damage(
                        &projectile->pos_x,
                        ion_damage_scale * 128.0f,
                        frame_dt * 300.0f,
                        7);
                } else if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
                    projectile->pos.tail.vy.life_timer -= frame_dt * 0.1f;
                } else {
                    projectile->pos.tail.vy.life_timer -= frame_dt;
                }
            } else {
                float *pos = &projectile->pos_x;
                if (projectile->pos_x < -64.0f
                    || projectile->pos.pos_y < -64.0f
                    || (float)(terrain_texture_width + 64)
                        < projectile->pos_x
                    || (float)(terrain_texture_height + 64)
                        < projectile->pos.pos_y) {
                    projectile->pos.tail.vy.life_timer -= frame_dt;
                } else {
                    int step_count =
                        (int)projectile->pos.tail.vy.travel_budget;
                    float heading = projectile->angle - 1.5707964f;
                    float step_x =
                        (float)(cos(heading) * frame_dt * 20.0f);
                    float step_y =
                        (float)(sin(heading) * frame_dt * 20.0f);

                    if (perk_count_get(perk_id_barrel_greaser) != 0
                        && projectile->pos.tail.vy.owner_id < 0) {
                        step_count *= 2.0f;
                    }

                    float delta[2] = {0.0f, 0.0f};
                    int step = 0;
                    if (step_count > 0) {
                        do {
                            delta[0] += step_x
                                * projectile->pos.tail.vy.speed_scale * 3.0f;
                            delta[1] += step_y
                                * projectile->pos.tail.vy.speed_scale * 3.0f;

                            float distance = (float)sqrt(
                                delta[0] * delta[0]
                                + delta[1] * delta[1]);
                            if (distance >= 4.0f
                                || step + 3 >= step_count) {
                                vec2_add(pos, delta);
                                int hit_id = creature_find_in_radius(
                                    pos,
                                    projectile->pos.tail.vy.hit_radius,
                                    0);

                                if (hit_id == -1
                                    || hit_id
                                        == projectile->pos.tail.vy.owner_id) {
                                    if (projectile_index
                                        != shock_chain_projectile_id) {
                                        int owner_id =
                                            projectile->pos.tail.vy.owner_id;
                                        if (owner_id != -100) {
                                            hit_id = player_find_in_radius(
                                                owner_id,
                                                pos,
                                                projectile->pos.tail.vy.hit_radius);
                                        }
                                        if (hit_id != -1) {
                                            projectile->pos.tail.vy.life_timer =
                                                0.25f;
                                            if (player_state_table[hit_id]
                                                    .shield_timer
                                                <= 0.0f) {
                                                player_state_table[hit_id]
                                                    .health -= 10.0f;
                                            }
                                        }
                                    }
                                } else {
                                    if (perk_count_get(
                                            perk_id_poison_bullets)
                                            != 0
                                        && (crt_rand() & 7) == 1) {
                                        creature_pool[hit_id].flags |=
                                            CREATURE_FLAG_SELF_DAMAGE_TICK;
                                    }

                                    projectile_type_id_t type_id =
                                        projectile->pos.tail.vy.type_id;
                                    if (type_id
                                        == PROJECTILE_TYPE_BLADE_GUN) {
                                        int count = 8;
                                        do {
                                            effect_spawn_blood_splatter(
                                                pos,
                                                (float)(crt_rand() & 0xff)
                                                    * 0.024543693f,
                                                0.0f);
                                            --count;
                                        } while (count != 0);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_SPLITTER_GUN) {
                                        effect_spawn_splitter_hit_burst(
                                            pos,
                                            26.0f,
                                            3);
                                        projectile_spawn(
                                            pos,
                                            projectile->angle - 1.0471976f,
                                            PROJECTILE_TYPE_SPLITTER_GUN,
                                            hit_id);
                                        projectile_spawn(
                                            pos,
                                            projectile->angle + 1.0471976f,
                                            PROJECTILE_TYPE_SPLITTER_GUN,
                                            hit_id);
                                    }

                                    effect_color_t effect_color = {
                                        1.0f,
                                        1.0f,
                                        1.0f,
                                        1.0f,
                                    };
                                    effect_template.color = effect_color;
                                    effect_template.flags = 0x59;
                                    effect_template.lifetime = 0.35f;
                                    effect_template.age = 0.0f;
                                    effect_template.half_width = 4.0f;
                                    effect_template.half_height = 4.0f;

                                    if (!config_violence_disabled) {
                                        if (perk_count_get(
                                                perk_id_bloody_mess_quick_learner)
                                            == 0) {
                                            if (bonus_freeze_timer <= 0.0f) {
                                                int count = 2;
                                                do {
                                                    effect_spawn_blood_splatter(
                                                        pos,
                                                        projectile->angle
                                                            - 1.5707964f,
                                                        0.0f);
                                                    if ((crt_rand() & 7)
                                                        == 2) {
                                                        effect_spawn_blood_splatter(
                                                            pos,
                                                            projectile->angle
                                                                - 1.5707964f
                                                                + 3.1415927f,
                                                            0.0f);
                                                    }
                                                    --count;
                                                } while (count != 0);
                                            }
                                        } else {
                                            int count = 8;
                                            do {
                                                effect_spawn_blood_splatter(
                                                    pos,
                                                    projectile->angle
                                                        - 1.5707964f
                                                        + (float)(
                                                            (crt_rand() & 0x1f)
                                                            - 0x10)
                                                            * 0.0625f,
                                                    0.0f);
                                                --count;
                                            } while (count != 0);
                                            effect_spawn_blood_splatter(
                                                pos,
                                                projectile->angle
                                                    - 1.5707964f
                                                    + 3.1415927f,
                                                0.0f);
                                        }
                                    }

                                    if (creature_pool[hit_id]
                                            .lifecycle_stage
                                        == 16.0f) {
                                        ++highscore_record_shots_hit;
                                    }

                                    if (perk_count_get(
                                            perk_id_bloody_mess_quick_learner)
                                        != 0) {
                                        int upper = 30;
                                        int lower = -30;
                                        do {
                                            int range = upper - lower;
                                            vec2f_t impact;
                                            impact.x =
                                                (float)(crt_rand() % range
                                                    + lower)
                                                + creature_pool[hit_id].pos_x;
                                            impact.y =
                                                (float)(crt_rand() % range
                                                    + lower)
                                                + creature_pool[hit_id].pos_y;
                                            fx_queue_add_random(&impact);

                                            impact.x =
                                                (float)(crt_rand() % range
                                                    + lower)
                                                + creature_pool[hit_id].pos_x;
                                            impact.y =
                                                (float)(crt_rand() % range
                                                    + lower)
                                                + creature_pool[hit_id].pos_y;
                                            fx_queue_add_random(&impact);

                                            lower -= 10;
                                            upper += 10;
                                        } while (lower > -60);
                                    }

                                    type_id =
                                        projectile->pos.tail.vy.type_id;
                                    if (type_id
                                            != PROJECTILE_TYPE_FIRE_BULLETS
                                        && type_id
                                            != PROJECTILE_TYPE_GAUSS_GUN
                                        && type_id
                                            != PROJECTILE_TYPE_BLADE_GUN) {
                                        projectile->pos.tail.vy.life_timer =
                                            0.25f;
                                        int jitter = crt_rand() & 3;
                                        float heading =
                                            projectile->angle - 1.5707964f;
                                        projectile->pos_x +=
                                            (float)(cos(heading) * jitter);
                                        projectile->pos.pos_y +=
                                            (float)(sin(heading) * jitter);
                                    }

                                    float damage_dx =
                                        projectile->pos.origin_x
                                        - projectile->pos_x;
                                    float damage_dy =
                                        projectile->pos.tail.origin_y
                                        - projectile->pos.pos_y;
                                    float damage_distance = (float)sqrt(
                                        damage_dx * damage_dx
                                        + damage_dy * damage_dy);
                                    if (damage_distance < 50.0f) {
                                        damage_distance = 50.0f;
                                    }

                                    type_id =
                                        projectile->pos.tail.vy.type_id;
                                    float damage_scale =
                                        weapon_table[type_id].damage_scale;

                                    if (type_id
                                        == PROJECTILE_TYPE_ION_MINIGUN) {
                                        effect_spawn_ion_hit_core(
                                            pos,
                                            1.5f,
                                            0.1f);
                                        effect_spawn_ion_hit_sparks(pos, 0.8f);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_ION_RIFLE) {
                                        if (shock_chain_links_left > 0
                                            && projectile_index
                                                == shock_chain_projectile_id) {
                                            --shock_chain_links_left;
                                            int next_id = creature_find_nearest(
                                                pos,
                                                hit_id,
                                                100.0f);
                                            bonus_spawn_guard = 1;
                                            float chain_angle = (float)atan2(
                                                creature_pool[next_id].pos_y
                                                    - creature_pool[hit_id]
                                                        .pos_y,
                                                creature_pool[next_id].pos_x
                                                    - creature_pool[hit_id]
                                                        .pos_x);
                                            shock_chain_projectile_id =
                                                projectile_spawn(
                                                    pos,
                                                    chain_angle
                                                        - 1.5707964f
                                                        - 3.1415927f,
                                                    PROJECTILE_TYPE_ION_RIFLE,
                                                    hit_id);
                                            bonus_spawn_guard = 0;
                                        }
                                        effect_spawn_ion_hit_core(
                                            pos,
                                            1.2f,
                                            0.4f);
                                        effect_spawn_ion_hit_sparks(pos, 1.2f);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_ION_CANNON) {
                                        effect_spawn_ion_hit_core(
                                            pos,
                                            1.0f,
                                            1.0f);
                                        effect_spawn_ion_hit_sparks(pos, 2.2f);
                                        sfx_play_panned(
                                            sfx_shockwave,
                                            pos,
                                            1.0f);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_PLASMA_CANNON) {
                                        bonus_spawn_guard = 1;
                                        int child_index = 0;
                                        float child_radius =
                                            creature_pool[hit_id].size * 0.5f
                                            + 1.0f;
                                        do {
                                            float child_angle =
                                                (float)child_index
                                                * 0.5235988f;
                                            vec2f_t child_pos;
                                            child_pos.x =
                                                (float)(cos(child_angle)
                                                    * child_radius)
                                                + projectile->pos_x;
                                            child_pos.y =
                                                (float)(sin(child_angle)
                                                    * child_radius)
                                                + projectile->pos.pos_y;
                                            projectile_spawn(
                                                &child_pos.x,
                                                child_angle,
                                                PROJECTILE_TYPE_PLASMA_RIFLE,
                                                -100);
                                            ++child_index;
                                        } while (child_index < 12);
                                        bonus_spawn_guard = 0;
                                        sfx_play_panned(
                                            sfx_explosion_medium,
                                            pos,
                                            1.0f);
                                        sfx_play_panned(
                                            sfx_shockwave,
                                            pos,
                                            1.0f);
                                        effect_spawn_plasma_hit_core(
                                            pos,
                                            1.5f,
                                            1.0f);
                                        effect_spawn_plasma_hit_core(
                                            pos,
                                            1.0f,
                                            1.0f);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_SHRINKIFIER) {
                                        effect_spawn_shrinkifier_hit(pos);
                                        float size =
                                            creature_pool[hit_id].size * 0.65f;
                                        projectile->pos.tail.vy.life_timer =
                                            0.25f;
                                        creature_pool[hit_id].size = size;
                                        if (size < 16.0f) {
                                            creature_handle_death(hit_id, 1);
                                        }
                                    } else if (type_id
                                        == PROJECTILE_TYPE_PULSE_GUN) {
                                        creature_pool[hit_id].pos_x +=
                                            delta[0] * 3.0f;
                                        creature_pool[hit_id].pos_y +=
                                            delta[1] * 3.0f;
                                    } else if (type_id
                                        == PROJECTILE_TYPE_PLAGUE_SPREADER) {
                                        creature_pool[hit_id].collision_flag =
                                            1;
                                    }

                                    float damage =
                                        ((100.0f / damage_distance)
                                                * damage_scale * 30.0f
                                            + 10.0f)
                                        * 0.95f;
                                    if (damage > 0.0f
                                        && creature_pool[hit_id].health
                                            > 0.0f) {
                                        projectile->pos.tail.vy.damage_pool -=
                                            1.0f;
                                        float impulse_axis = (float)(
                                            cos(projectile->angle - 1.5707964f)
                                            * projectile->pos.tail.vy
                                                .speed_scale);
                                        float impulse[2] = {
                                            impulse_axis,
                                            impulse_axis,
                                        };

                                        if (projectile->pos.tail.vy.damage_pool
                                            <= 0.0f) {
                                            creature_apply_damage(
                                                hit_id,
                                                damage,
                                                1,
                                                impulse);
                                            if (projectile->pos.tail.vy
                                                    .life_timer
                                                != 0.25f) {
                                                projectile->pos.tail.vy
                                                    .life_timer = 0.25f;
                                            }
                                        } else {
                                            creature_apply_damage(
                                                hit_id,
                                                projectile->pos.tail.vy
                                                    .damage_pool,
                                                1,
                                                impulse);
                                            projectile->pos.tail.vy.damage_pool -=
                                                creature_pool[hit_id].health;
                                        }
                                    }

                                    if (projectile->pos.tail.vy.damage_pool
                                        == 1.0f) {
                                        float life_timer =
                                            projectile->pos.tail.vy.life_timer;
                                        projectile->pos.tail.vy.damage_pool =
                                            0.0f;
                                        if (life_timer != 0.25f) {
                                            projectile->pos.tail.vy.life_timer =
                                                0.25f;
                                        }
                                    }
                                    creature_pool[hit_id].state_flag = 1;
                                    crt_rand();

                                    type_id =
                                        projectile->pos.tail.vy.type_id;
                                    if (type_id
                                            == PROJECTILE_TYPE_GAUSS_GUN
                                        || type_id
                                            == PROJECTILE_TYPE_FIRE_BULLETS) {
                                        perk_count_get(
                                            perk_id_bloody_mess_quick_learner);
                                        int count = 6;
                                        do {
                                            float speed =
                                                (float)(crt_rand() % 100)
                                                * 0.1f;
                                            if (speed > 4.0f) {
                                                speed =
                                                    (float)(crt_rand() % 90
                                                        + 10)
                                                    * 0.1f;
                                            }
                                            if (speed > 7.0f) {
                                                speed =
                                                    (float)(crt_rand() % 80
                                                        + 20)
                                                    * 0.1f;
                                            }

                                            float impact_heading =
                                                projectile->angle
                                                - 1.5707964f;
                                            float offset_x =
                                                (float)(cos(impact_heading)
                                                    * speed * 20.0f);
                                            float offset_y =
                                                (float)(sin(impact_heading)
                                                    * speed * 20.0f);
                                            vec2f_t impulse_pos = {
                                                creature_pool[hit_id].pos_x
                                                    + offset_x,
                                                creature_pool[hit_id].pos_y
                                                    + offset_y,
                                            };
                                            vec2f_t zero = {0.0f, 0.0f};
                                            vec2_add_inplace(
                                                hit_id,
                                                &impulse_pos.x,
                                                &zero.x);
                                            crt_rand();

                                            if (bonus_freeze_timer > 0.0f) {
                                                vec2f_t shard_pos = {
                                                    projectile->pos_x
                                                        + offset_x,
                                                    projectile->pos.pos_y
                                                        + offset_y,
                                                };
                                                effect_spawn_freeze_shard(
                                                    &shard_pos.x,
                                                    impact_heading
                                                        + (float)(
                                                            crt_rand() % 100)
                                                            * 0.01f);
                                            }

                                            vec2f_t decal_pos = {
                                                creature_pool[hit_id].pos_x
                                                    + offset_x,
                                                creature_pool[hit_id].pos_y
                                                    + offset_y,
                                            };
                                            fx_queue_add_random(&decal_pos);
                                            --count;
                                        } while (count != 0);
                                    } else if (bonus_freeze_timer <= 0.0f) {
                                        int count = 3;
                                        do {
                                            float impact_heading =
                                                projectile->angle
                                                - 1.5707964f
                                                + (float)(
                                                    crt_rand() % 20 - 10)
                                                    * 0.1f;
                                            float offset_x =
                                                (float)(cos(impact_heading)
                                                    * 20.0f);
                                            float offset_y =
                                                (float)(sin(impact_heading)
                                                    * 20.0f);

                                            vec2f_t *creature_pos =
                                                (vec2f_t *)&creature_pool[hit_id]
                                                    .pos_x;
                                            fx_queue_add_random(creature_pos);

                                            vec2f_t decal_pos = {
                                                creature_pos->x
                                                    + offset_x * 1.5f,
                                                creature_pos->y
                                                    + offset_y * 1.5f,
                                            };
                                            fx_queue_add_random(&decal_pos);

                                            decal_pos.x =
                                                creature_pos->x
                                                + offset_x * 2.0f;
                                            decal_pos.y =
                                                creature_pos->y
                                                + offset_y * 2.0f;
                                            fx_queue_add_random(&decal_pos);

                                            decal_pos.x =
                                                creature_pos->x
                                                + offset_x * 2.5f;
                                            decal_pos.y =
                                                creature_pos->y
                                                + offset_y * 2.5f;
                                            fx_queue_add_random(&decal_pos);
                                            --count;
                                        } while (count != 0);
                                    } else {
                                        effect_spawn_freeze_shard(
                                            pos,
                                            projectile->angle
                                                - 1.5707964f
                                                + (float)(crt_rand() % 100)
                                                    * 0.01f);
                                    }

                                    if (!demo_mode_active
                                        && !music_playlist_randomized_latch
                                        && config_game_mode
                                            != GAME_MODE_RUSH) {
                                        sfx_play_exclusive(
                                            music_track_extra_0);
                                    } else {
                                        int hit_sfx = sfx_shock_hit_01;
                                        if (weapon_ammo_class[type_id * 31]
                                            != 4) {
                                            hit_sfx = crt_rand() % 6
                                                + sfx_bullet_hit_01;
                                        }
                                        sfx_play_panned(hit_sfx, pos, 1.0f);
                                    }

                                    if (projectile->pos.tail.vy.damage_pool
                                        <= 0.0f) {
                                        break;
                                    }
                                }

                                delta[0] = 0.0f;
                                delta[1] = 0.0f;
                            }
                            step += 3;
                        } while (step < step_count);
                    }
                }
            }
        }
        ++projectile_index;
    } while (projectile_index < 0x60);
}
