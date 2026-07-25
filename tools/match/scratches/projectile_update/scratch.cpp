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
extern weapon_storage_entry_t weapon_ammo_class[];
extern int config_detail_preset;
extern creature_type_table_t creature_type_table;

void creatures_apply_radius_damage(
    const vec2f_t *pos,
    float radius,
    float damage,
    int damage_type);
int creature_find_in_radius(
    const vec2f_t *pos,
    float radius,
    int start_index);
int player_find_in_radius(
    int owner_id,
    const vec2f_t *pos,
    float radius);
int vec2_add(vec2f_t *dst, const vec2f_t *delta);
int vec2_add_inplace(
    int entity_index,
    vec2f_t *pos,
    const vec2f_t *delta);
void effect_spawn_blood_splatter(
    const vec2f_t *pos,
    float angle,
    float age);
void effect_spawn_splitter_hit_burst(
    const vec2f_t *pos,
    float radius,
    int count);
void effect_spawn_ion_hit_sparks(const vec2f_t *pos, float scale);
void effect_spawn_shrinkifier_hit(const vec2f_t *pos);
void fx_queue_add_random(vec2f_t *pos);
void creature_handle_death(int creature_id, unsigned char keep_corpse);
void sfx_play_exclusive(int sfx_id);
int fx_spawn_sprite(
    const vec2f_t *pos,
    const vec2f_t *vel,
    float scale);
vec2f_t *__stdcall vec2_normalize_dispatch(
    vec2f_t *dst,
    const vec2f_t *src);
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
                    if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
                        creatures_apply_radius_damage(
                            &projectile->position,
                            ion_damage_scale * 88.0f,
                            frame_dt * 100.0f,
                            7);
                    } else {
                        creatures_apply_radius_damage(
                            &projectile->position,
                            ion_damage_scale * 60.0f,
                            frame_dt * 40.0f,
                            7);
                    }
                } else if (type_id == PROJECTILE_TYPE_ION_CANNON) {
                    projectile->pos.tail.vy.life_timer -= frame_dt * 0.7f;
                    creatures_apply_radius_damage(
                        &projectile->position,
                        ion_damage_scale * 128.0f,
                        frame_dt * 300.0f,
                        7);
                } else if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
                    projectile->pos.tail.vy.life_timer -= frame_dt * 0.1f;
                } else {
                    projectile->pos.tail.vy.life_timer -= frame_dt;
                }
            } else {
                vec2f_t *position = &projectile->position;
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
                        (float)cos(heading) * frame_dt * 20.0f;
                    float step_y =
                        (float)sin(heading) * frame_dt * 20.0f;

                    if (perk_count_get(perk_id_barrel_greaser) != 0
                        && projectile->pos.tail.vy.owner_id < 0) {
                        step_count *= 2.0f;
                    }

                    vec2f_t delta = {0.0f, 0.0f};
                    int step = 0;
                    if (step_count > 0) {
                        do {
                            delta.x += step_x
                                * projectile->pos.tail.vy.speed_scale * 3.0f;
                            delta.y += step_y
                                * projectile->pos.tail.vy.speed_scale * 3.0f;

                            float distance = (float)sqrt(
                                delta.x * delta.x
                                + delta.y * delta.y);
                            if (distance >= 4.0f
                                || step + 3 >= step_count) {
                                vec2_add(position, &delta);
                                int hit_id = creature_find_in_radius(
                                    position,
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
                                                position,
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
                                                position,
                                                (float)(crt_rand() & 0xff)
                                                    * 0.024543693f,
                                                0.0f);
                                            --count;
                                        } while (count != 0);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_SPLITTER_GUN) {
                                        effect_spawn_splitter_hit_burst(
                                            position,
                                            26.0f,
                                            3);
                                        projectile_spawn(
                                            position,
                                            projectile->angle - 1.0471976f,
                                            PROJECTILE_TYPE_SPLITTER_GUN,
                                            hit_id);
                                        projectile_spawn(
                                            position,
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
                                            != 0) {
                                            int count = 8;
                                            do {
                                                effect_spawn_blood_splatter(
                                                    position,
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
                                                position,
                                                projectile->angle
                                                    - 1.5707964f
                                                    + 3.1415927f,
                                                0.0f);
                                        } else if (bonus_freeze_timer <= 0.0f) {
                                            int count = 2;
                                            do {
                                                effect_spawn_blood_splatter(
                                                    position,
                                                    projectile->angle
                                                        - 1.5707964f,
                                                    0.0f);
                                                if ((crt_rand() & 7) == 2) {
                                                    effect_spawn_blood_splatter(
                                                        position,
                                                        projectile->angle
                                                            - 1.5707964f
                                                            + 3.1415927f,
                                                        0.0f);
                                                }
                                                --count;
                                            } while (count != 0);
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
                                    float damage =
                                        ((100.0f / damage_distance)
                                                * weapon_table[type_id]
                                                    .damage_scale
                                                * 30.0f
                                            + 10.0f);

                                    if (type_id
                                        == PROJECTILE_TYPE_ION_MINIGUN) {
                                        effect_spawn_ion_hit_core(
                                            position,
                                            1.5f,
                                            0.1f);
                                        effect_spawn_ion_hit_sparks(
                                            position,
                                            0.8f);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_ION_RIFLE) {
                                        if (shock_chain_links_left > 0
                                            && projectile_index
                                                == shock_chain_projectile_id) {
                                            --shock_chain_links_left;
                                            int next_id = creature_find_nearest(
                                                position,
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
                                                    position,
                                                    chain_angle
                                                        - 1.5707964f
                                                        - 3.1415927f,
                                                    PROJECTILE_TYPE_ION_RIFLE,
                                                    hit_id);
                                            bonus_spawn_guard = 0;
                                        }
                                        effect_spawn_ion_hit_core(
                                            position,
                                            1.2f,
                                            0.4f);
                                        effect_spawn_ion_hit_sparks(
                                            position,
                                            1.2f);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_ION_CANNON) {
                                        effect_spawn_ion_hit_core(
                                            position,
                                            1.0f,
                                            1.0f);
                                        effect_spawn_ion_hit_sparks(
                                            position,
                                            2.2f);
                                        sfx_play_panned(
                                            sfx_shockwave,
                                            position,
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
                                                &child_pos,
                                                child_angle,
                                                PROJECTILE_TYPE_PLASMA_RIFLE,
                                                -100);
                                            ++child_index;
                                        } while (child_index < 12);
                                        bonus_spawn_guard = 0;
                                        sfx_play_panned(
                                            sfx_explosion_medium,
                                            position,
                                            1.0f);
                                        sfx_play_panned(
                                            sfx_shockwave,
                                            position,
                                            1.0f);
                                        effect_spawn_plasma_hit_core(
                                            position,
                                            1.5f,
                                            1.0f);
                                        effect_spawn_plasma_hit_core(
                                            position,
                                            1.0f,
                                            1.0f);
                                    } else if (type_id
                                        == PROJECTILE_TYPE_SHRINKIFIER) {
                                        effect_spawn_shrinkifier_hit(position);
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
                                            delta.x * 3.0f;
                                        creature_pool[hit_id].pos_y +=
                                            delta.y * 3.0f;
                                    } else if (type_id
                                        == PROJECTILE_TYPE_PLAGUE_SPREADER) {
                                        creature_pool[hit_id].collision_flag =
                                            1;
                                    }

                                    damage *= 0.95f;
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
                                                (float)cos(impact_heading)
                                                * speed * 20.0f;
                                            float offset_y =
                                                (float)sin(impact_heading)
                                                * speed * 20.0f;
                                            vec2f_t impulse_pos = {
                                                creature_pool[hit_id].pos_x
                                                    + offset_x,
                                                creature_pool[hit_id].pos_y
                                                    + offset_y,
                                            };
                                            vec2f_t zero = {0.0f, 0.0f};
                                            vec2_add_inplace(
                                                hit_id,
                                                &impulse_pos,
                                                &zero);
                                            crt_rand();

                                            if (bonus_freeze_timer > 0.0f) {
                                                vec2f_t shard_pos = {
                                                    projectile->pos_x
                                                        + offset_x,
                                                    projectile->pos.pos_y
                                                        + offset_y,
                                                };
                                                effect_spawn_freeze_shard(
                                                    &shard_pos,
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
                                                (float)cos(impact_heading)
                                                * 20.0f;
                                            float offset_y =
                                                (float)sin(impact_heading)
                                                * 20.0f;

                                            vec2f_t *creature_pos =
                                                &creature_pool[hit_id].position;
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
                                            position,
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
                                        if (weapon_ammo_class[type_id]
                                                .ammo_class != 4) {
                                            hit_sfx = crt_rand() % 6
                                                + sfx_bullet_hit_01;
                                        }
                                        sfx_play_panned(
                                            hit_sfx,
                                            position,
                                            1.0f);
                                    }

                                    if (projectile->pos.tail.vy.damage_pool
                                        <= 0.0f) {
                                        break;
                                    }
                                }

                                delta.x = 0.0f;
                                delta.y = 0.0f;
                            }
                            step += 3;
                        } while (step < step_count);
                    }
                }
            }
        }
        ++projectile_index;
    } while (projectile_index < 0x60);

    secondary_projectile_t *secondary = secondary_projectile_pool;
    do {
        if (secondary->active) {
            if (secondary->pos.vx.vy.type_id
                == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
                camera_shake_pulses = 4;
                secondary->pos.vx.vel_x += frame_dt * 3.0f;

                if (secondary->pos.vx.vel_x > 1.0f) {
                    float extent = secondary->pos.vx.vy.vel_y * 256.0f;
                    effect_color_t color = {
                        0.0f,
                        0.0f,
                        0.0f,
                        0.25f,
                    };
                    fx_queue_add(
                        0x10,
                        &secondary->position,
                        extent,
                        extent,
                        0.0f,
                        &color);
                    secondary->active = 0;
                }

                float radius = secondary->pos.vx.vy.vel_y
                    * secondary->pos.vx.vel_x * 80.0f;
                int creature_id = 0;
                do {
                    creature_t *creature = &creature_pool[creature_id];
                    if (creature->active && creature->health > 0.0f) {
                        float dx = creature->pos_x - secondary->pos_x;
                        float dy = creature->pos_y - secondary->pos.pos_y;
                        float distance =
                            (float)sqrt(dx * dx + dy * dy);
                        if (distance < radius) {
                            vec2f_t impulse = {dx, dy};
                            vec2_normalize_dispatch(&impulse, &impulse);
                            impulse.x *= 0.1f;
                            impulse.y *= 0.1f;
                            creature_apply_damage(
                                creature_id,
                                frame_dt
                                    * secondary->pos.vx.vy.vel_y * 700.0f,
                                3,
                                &impulse.x);
                            if (creature->health <= 0.0f) {
                                fx_queue_add_random(
                                    &creature->position);
                                fx_queue_add_random(
                                    &creature->position);
                                creature_handle_death(creature_id, 1);
                            }
                        }
                    }
                    ++creature_id;
                } while (creature_id < 0x180);
            } else {
                vec2f_t movement = {
                    frame_dt * secondary->pos.vx.vel_x,
                    frame_dt * secondary->pos.vx.vy.vel_y,
                };
                vec2_add(
                    &secondary->position,
                    &movement);

                secondary_projectile_type_id_t type_id =
                    secondary->pos.vx.vy.type_id;
                if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
                    float speed = (float)sqrt(
                        secondary->pos.vx.vel_x
                                * secondary->pos.vx.vel_x
                            + secondary->pos.vx.vy.vel_y
                                * secondary->pos.vx.vy.vel_y);
                    if (speed < 500.0f) {
                        float scale = frame_dt * 3.0f + 1.0f;
                        secondary->pos.vx.vel_x *= scale;
                        secondary->pos.vx.vy.vel_y *= scale;
                    }
                    secondary->life_timer -= frame_dt;
                } else if (type_id
                    == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
                    float speed = (float)sqrt(
                        secondary->pos.vx.vel_x
                                * secondary->pos.vx.vel_x
                            + secondary->pos.vx.vy.vel_y
                                * secondary->pos.vx.vy.vel_y);
                    if (speed < 600.0f) {
                        float scale = frame_dt * 4.0f + 1.0f;
                        secondary->pos.vx.vel_x *= scale;
                        secondary->pos.vx.vy.vel_y *= scale;
                    }
                    secondary->life_timer -= frame_dt;
                } else if (type_id
                    == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
                    if (!creature_pool[secondary->pos.vx.vy.target_id]
                            .active) {
                        secondary->pos.vx.vy.target_id =
                            creature_find_nearest(
                                &secondary->position,
                                -1,
                                0.0f);
                    }

                    creature_t *target = &creature_pool[
                        secondary->pos.vx.vy.target_id];
                    float target_angle = (float)atan2(
                        secondary->pos.pos_y - target->pos_y,
                        secondary->pos_x - target->pos_x);
                    secondary->angle = target_angle - 1.5707964f;
                    secondary->pos.vx.vel_x +=
                        (float)cos(
                            (target_angle - 1.5707964f) - 1.5707964f)
                        * frame_dt * 800.0f;
                    secondary->pos.vx.vy.vel_y +=
                        (float)sin(secondary->angle - 1.5707964f)
                        * frame_dt * 800.0f;

                    float speed = (float)sqrt(
                        secondary->pos.vx.vel_x
                                * secondary->pos.vx.vel_x
                            + secondary->pos.vx.vy.vel_y
                                * secondary->pos.vx.vy.vel_y);
                    if (speed > 350.0f) {
                        secondary->pos.vx.vel_x -=
                            (float)cos(
                                secondary->angle - 1.5707964f)
                            * frame_dt * 800.0f;
                        secondary->pos.vx.vy.vel_y -=
                            (float)sin(
                                secondary->angle - 1.5707964f)
                            * frame_dt * 800.0f;
                    }
                    secondary->life_timer -= frame_dt * 0.5f;
                }

                secondary->pos.vx.vy.trail_timer -=
                    ((float)fabs(secondary->pos.vx.vel_x)
                        + (float)fabs(secondary->pos.vx.vy.vel_y))
                    * frame_dt * 0.01f;
                if (secondary->pos.vx.vy.trail_timer < 0.0f) {
                    float trail_cos =
                        (float)cos(secondary->angle + 1.5707964f);
                    vec2f_t trail_velocity = {
                        trail_cos * 90.0f,
                        trail_cos * 90.0f,
                    };
                    float trail_heading =
                        secondary->angle - 1.5707964f;
                    vec2f_t trail_pos = {
                        secondary->pos_x
                            - (float)cos(trail_heading) * 9.0f,
                        secondary->pos.pos_y
                            - (float)sin(trail_heading) * 9.0f,
                    };
                    int effect_id = fx_spawn_sprite(&trail_pos, &trail_velocity, 14.0f);
                    secondary->pos.vx.vy.trail_timer = 0.06f;
                    sprite_effect_pool[effect_id].color_a = 0.25f;
                }

                int hit_id = creature_find_in_radius(
                    &secondary->position,
                    8.0f,
                    0);
                if (hit_id != -1) {
                    if (creature_pool[hit_id].lifecycle_stage == 16.0f) {
                        ++highscore_record_shots_hit;
                    }

                    if (bonus_freeze_timer <= 0.0f) {
                        vec2f_t decal_offset_1 = {
                            (float)(crt_rand() % 20 - 10),
                            (float)(crt_rand() % 20 - 10),
                        };
                        vec2f_t decal_pos_1 = {
                            decal_offset_1.x
                                + creature_pool[hit_id].pos_x,
                            decal_offset_1.y
                                + creature_pool[hit_id].pos_y,
                        };
                        fx_queue_add_random(&decal_pos_1);

                        vec2f_t decal_offset_2 = {
                            (float)(crt_rand() % 20 - 10),
                            (float)(crt_rand() % 20 - 10),
                        };
                        vec2f_t decal_pos_2 = {
                            decal_offset_2.x
                                + creature_pool[hit_id].pos_x,
                            decal_offset_2.y
                                + creature_pool[hit_id].pos_y,
                        };
                        fx_queue_add_random(&decal_pos_2);

                        vec2f_t decal_offset_3 = {
                            (float)(crt_rand() % 20 - 10),
                            (float)(crt_rand() % 20 - 10),
                        };
                        vec2f_t decal_pos_3 = {
                            decal_offset_3.x
                                + creature_pool[hit_id].pos_x,
                            decal_offset_3.y
                                + creature_pool[hit_id].pos_y,
                        };
                        fx_queue_add_random(&decal_pos_3);
                    } else {
                        int count = 4;
                        do {
                            effect_spawn_freeze_shard(
                                &secondary->position,
                                (float)(crt_rand() % 612) * 0.01f);
                            --count;
                        } while (count != 0);
                    }

                    float damage = 150.0f;
                    if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
                        damage = secondary->life_timer * 50.0f + 500.0f;
                        if (config_detail_preset > 2) {
                            effect_spawn_explosion_burst(
                                &secondary->position,
                                0.4f);
                        }
                    } else if (type_id
                        == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
                        damage = secondary->life_timer * 20.0f + 80.0f;
                    } else if (type_id
                        == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
                        damage = secondary->life_timer * 20.0f + 40.0f;
                    }

                    if (!demo_mode_active
                        && !music_playlist_randomized_latch
                        && config_game_mode != GAME_MODE_RUSH) {
                        sfx_play_exclusive(music_track_extra_0);
                    } else {
                        sfx_play_panned(
                            sfx_explosion_medium,
                            &secondary->position,
                            1.0f);
                    }

                    float inverse_dt = 1.0f / frame_dt;
                    creature_pool[hit_id].state_flag = 1;
                    vec2f_t impulse = {
                        inverse_dt * secondary->pos.vx.vel_x,
                        inverse_dt * secondary->pos.vx.vy.vel_y,
                    };
                    creature_apply_damage(
                        hit_id,
                        damage,
                        3,
                        &impulse.x);

                    float freeze_timer = bonus_freeze_timer;
                    if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
                        secondary->pos.vx.vy.type_id =
                            SECONDARY_PROJECTILE_TYPE_EXPLODING;
                        secondary->pos.vx.vel_x = 0.0f;
                        secondary->pos.vx.vy.vel_y = 1.0f;
                        if (freeze_timer <= 0.0f) {
                            int count = 20;
                            do {
                                float angle =
                                    (float)(crt_rand() % 628) * 0.01f;
                                int radius = crt_rand() % 90;
                                vec2f_t decal_pos = {
                                    (float)(cos(angle) * radius)
                                        + creature_pool[hit_id].pos_x,
                                    (float)(sin(angle) * radius)
                                        + creature_pool[hit_id].pos_y,
                                };
                                fx_queue_add_random(&decal_pos);
                                --count;
                            } while (count != 0);
                        } else {
                            int count = 8;
                            do {
                                effect_spawn_freeze_shard(
                                    &secondary->position,
                                    (float)(crt_rand() % 612) * 0.01f);
                                --count;
                            } while (count != 0);
                        }
                    } else if (type_id
                        == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
                        secondary->pos.vx.vy.type_id =
                            SECONDARY_PROJECTILE_TYPE_EXPLODING;
                        secondary->pos.vx.vel_x = 0.0f;
                        secondary->pos.vx.vy.vel_y = 0.35f;
                        if (freeze_timer <= 0.0f) {
                            int count = 10;
                            do {
                                float angle =
                                    (float)(crt_rand() % 628) * 0.01f;
                                int radius = crt_rand() % 64;
                                vec2f_t decal_pos = {
                                    (float)(cos(angle) * radius)
                                        + creature_pool[hit_id].pos_x,
                                    (float)(sin(angle) * radius)
                                        + creature_pool[hit_id].pos_y,
                                };
                                fx_queue_add_random(&decal_pos);
                                --count;
                            } while (count != 0);
                        } else {
                            int count = 8;
                            do {
                                effect_spawn_freeze_shard(
                                    &secondary->position,
                                    (float)(crt_rand() % 612) * 0.01f);
                                --count;
                            } while (count != 0);
                        }
                    } else if (type_id
                        == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
                        secondary->pos.vx.vy.type_id =
                            SECONDARY_PROJECTILE_TYPE_EXPLODING;
                        secondary->pos.vx.vel_x = 0.0f;
                        secondary->pos.vx.vy.vel_y = 0.25f;
                        if (freeze_timer <= 0.0f) {
                            int count = 3;
                            do {
                                float angle =
                                    (float)(crt_rand() % 628) * 0.01f;
                                int radius = crt_rand() % 44;
                                vec2f_t decal_pos = {
                                    (float)(cos(angle) * radius)
                                        + creature_pool[hit_id].pos_x,
                                    (float)(sin(angle) * radius)
                                        + creature_pool[hit_id].pos_y,
                                };
                                fx_queue_add_random(&decal_pos);
                                --count;
                            } while (count != 0);
                        } else {
                            int count = 8;
                            do {
                                effect_spawn_freeze_shard(
                                    (const vec2f_t *)
                                        &creature_pool[hit_id].pos_x,
                                    (float)(crt_rand() % 612) * 0.01f);
                                --count;
                            } while (count != 0);
                        }
                    }

                    int burst_index = 0;
                    do {
                        float magnitude =
                            (float)(crt_rand() % 800) * 0.1f;
                        float angle =
                            (float)burst_index * 0.62831855f;
                        vec2f_t velocity = {
                            (float)(cos(angle) * magnitude),
                            (float)(sin(angle) * magnitude),
                        };
                        int effect_id = fx_spawn_sprite(
                            &secondary->position,
                            &velocity,
                            14.0f);
                        sprite_effect_pool[effect_id].color_a = 0.37f;
                        ++burst_index;
                    } while (burst_index < 10);
                }

                if (secondary->life_timer <= 0.0f) {
                    secondary->pos.vx.vy.type_id =
                        SECONDARY_PROJECTILE_TYPE_EXPLODING;
                    secondary->pos.vx.vel_x = 0.0f;
                    secondary->pos.vx.vy.vel_y = 0.5f;
                }
            }
        }
        ++secondary;
    } while ((int)secondary < (int)&secondary_projectile_pool[0x40]);

    sprite_effect_t *sprite = sprite_effect_pool;
    do {
        if (sprite->active) {
            float move_x = frame_dt * sprite->vel_x;
            float move_y = frame_dt * sprite->vel_y;
            sprite->pos_x += move_x;
            sprite->pos_y += move_y;
            sprite->rotation += frame_dt * 3.0f;
            sprite->color_a -= frame_dt;
            if (sprite->color_a <= 0.0f) {
                sprite->active = 0;
            }
            sprite->scale += frame_dt * 60.0f;
        }
        ++sprite;
    } while ((int)sprite < (int)&sprite_effect_pool[0x180]);

    int particle_index = 0;
    particle_t *particle = particle_pool;
    do {
        if (particle->active) {
            unsigned char style_id = particle->style_id;
            if (style_id == 8) {
                particle->intensity -= frame_dt * 0.11f;
                particle->spin += frame_dt * 5.0f;
                if (particle->render_flag) {
                    float move_x = frame_dt * particle->vel_x;
                    if (particle->intensity <= 0.15f) {
                        particle->pos_x +=
                            move_x * 0.55f * particle->intensity;
                        particle->pos_y += frame_dt * particle->vel_y
                            * 0.55f * particle->intensity;
                    } else {
                        vec2f_t movement = {
                            move_x * particle->intensity,
                            frame_dt * particle->vel_y
                                * particle->intensity,
                        };
                        vec2_add(
                            &particle->position,
                            &movement);
                    }
                }
            } else {
                particle->intensity -= frame_dt * 0.9f;
                particle->spin += frame_dt;
                float move_x = frame_dt * particle->vel_x;
                if (particle->intensity <= 0.15f) {
                    particle->pos_x += move_x * 2.5f * 0.15f;
                    particle->pos_y += frame_dt * particle->vel_y
                        * 2.5f * 0.15f;
                } else {
                    vec2f_t movement = {
                        move_x * 2.5f * particle->intensity,
                        frame_dt * particle->vel_y * 2.5f
                            * particle->intensity,
                    };
                    vec2_add(
                        &particle->position,
                        &movement);
                }
            }

            if ((style_id == 0 && particle->intensity <= 0.0f)
                || (style_id != 0 && particle->intensity <= 0.8f)) {
                particle->active = 0;
                if (style_id == 8 && particle->target_id != -1) {
                    int target_id = particle->target_id;
                    if (creature_pool[target_id].active) {
                        int sfx_id = creature_type_table[
                            creature_pool[target_id].type_id]
                            .sfx_bank_a[crt_rand() % 3];
                        sfx_play_panned(
                            sfx_id,
                            (const vec2f_t *)
                                &creature_pool[target_id].pos_x,
                            1.0f);
                    }
                    creature_handle_death(target_id, 0);
                }
            } else {
                if (particle->render_flag == 1) {
                    if (style_id == 0) {
                        int turn = crt_rand() % 100 - 50;
                        particle->angle -= (float)turn * 0.06f
                            * particle->intensity * frame_dt * 1.96f;
                        particle->vel_x =
                            (float)cos(particle->angle) * 82.0f;
                        particle->vel_y =
                            (float)sin(particle->angle) * 82.0f;
                    } else if (style_id == 8) {
                        int turn = crt_rand() % 100 - 50;
                        particle->angle -= (float)turn * 0.06f
                            * particle->intensity * frame_dt * 1.1f;
                        particle->vel_x =
                            (float)cos(particle->angle) * 62.0f;
                        particle->vel_y =
                            (float)sin(particle->angle) * 62.0f;
                    } else {
                        int turn = crt_rand() % 100 - 50;
                        particle->angle -= (float)turn * 0.06f
                            * particle->intensity * frame_dt * 1.1f;
                        particle->vel_x =
                            (float)cos(particle->angle) * 82.0f;
                        particle->vel_y =
                            (float)sin(particle->angle) * 82.0f;
                    }
                }
                if (particle->intensity <= 1.0f) {
                    particle->age = particle->intensity;
                } else {
                    particle->age = 1.0f;
                }
                particle->scale_x = 1.0f - particle->intensity * 0.95f;
                particle->scale_y = particle->scale_x;

                if (particle->render_flag) {
                    int hit_id = creature_find_in_radius(
                        &particle->position,
                        particle->intensity * 8.0f,
                        0);
                    if (hit_id != -1) {
                        particle->render_flag = 0;
                        if (style_id == 8) {
                            particle->pos_x = creature_pool[hit_id].pos_x;
                            particle->pos_y = creature_pool[hit_id].pos_y;
                            particle->vel_x = 0.0f;
                            particle->vel_y = 0.0f;
                            creature_pool[hit_id].state_flag = 0;
                            particle->target_id = hit_id;
                        } else {
                            while (6.2831855f < particle->angle) {
                                particle->angle -= 6.2831855f;
                            }
                            while (particle->angle < 0.0f) {
                                particle->angle += 6.2831855f;
                            }

                            float hit_angle = (float)atan2(
                                particle->pos_y
                                    - frame_dt * particle->vel_y
                                    - creature_pool[hit_id].pos_y,
                                particle->pos_x
                                    - frame_dt * particle->vel_x
                                    - creature_pool[hit_id].pos_x);
                            while (6.2831855f < hit_angle) {
                                hit_angle -= 6.2831855f;
                            }
                            while (hit_angle < 0.0f) {
                                hit_angle += 6.2831855f;
                            }

                            if (particle->angle <= hit_angle) {
                                particle->angle += 1.2566371f;
                            } else {
                                particle->angle -= 1.2566371f;
                            }
                            particle->vel_x =
                                (float)cos(particle->angle) * 82.0f;
                            particle->vel_y =
                                (float)sin(particle->angle) * 82.0f;
                            int speed_scale = crt_rand() % 10;
                            particle->vel_x *= (float)speed_scale * 0.1f;
                            particle->vel_y *= (float)speed_scale * 0.1f;
                            creature_pool[hit_id].state_flag = 1;
                            vec2f_t impulse = {0.0f, 0.0f};
                            creature_apply_damage(
                                hit_id,
                                particle->intensity * 10.0f,
                                4,
                                &impulse.x);

                            creature_t *hit_creature =
                                &creature_pool[hit_id];
                            if (hit_creature->tint_r
                                    + hit_creature->tint_g
                                    + hit_creature->tint_b
                                > 1.6f) {
                                float tint_scale =
                                    1.0f - particle->intensity * 0.01f;
                                hit_creature->tint_r *= tint_scale;
                                hit_creature->tint_g *= tint_scale;
                                hit_creature->tint_b *= tint_scale;

                                if (hit_creature->tint_r < 0.0f) {
                                    hit_creature->tint_r = 0.0f;
                                } else if (hit_creature->tint_r > 1.0f) {
                                    hit_creature->tint_r = 1.0f;
                                }
                                if (hit_creature->tint_g < 0.0f) {
                                    hit_creature->tint_g = 0.0f;
                                } else if (hit_creature->tint_g > 1.0f) {
                                    hit_creature->tint_g = 1.0f;
                                }
                                if (hit_creature->tint_b < 0.0f) {
                                    hit_creature->tint_b = 0.0f;
                                } else if (hit_creature->tint_b > 1.0f) {
                                    hit_creature->tint_b = 1.0f;
                                }
                                if (hit_creature->tint_a < 0.0f) {
                                    hit_creature->tint_a = 0.0f;
                                } else if (hit_creature->tint_a > 1.0f) {
                                    hit_creature->tint_a = 1.0f;
                                }
                            }

                            if (particle_index % 3 == 0) {
                                vec2f_t velocity = {
                                    (float)(crt_rand() % 60 - 30),
                                    (float)(crt_rand() % 60 - 30),
                                };
                                int effect_id = fx_spawn_sprite(
                                    &hit_creature->position,
                                    &velocity,
                                    13.0f);
                                sprite_effect_pool[effect_id].color_a = 0.7f;
                            }
                            fx_queue_add_random(
                                &hit_creature->position);
                            hit_creature->pos_x +=
                                frame_dt * particle->vel_x;
                            hit_creature->pos_y +=
                                frame_dt * particle->vel_y;
                        }
                    }
                }
            }
        }
        ++particle;
        ++particle_index;
    } while ((int)particle < (int)&particle_pool[0x80]);
}
