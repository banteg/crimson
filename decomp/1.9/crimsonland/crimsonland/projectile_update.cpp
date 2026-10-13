#include <math.h>

#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_CONFIG_OWNER
#include "crimsonland_config_owner.h"
#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"

inline float m_fabs(float value)
{
    int bits = (*(int*)&value) & 0x7fffffff;
    return *(float*)&bits;
}

struct projectile_vec2_t {
    union {
        struct {
            float x;
            float y;
        };
        float values[2];
    };

    projectile_vec2_t() { }

    projectile_vec2_t(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }

    inline projectile_vec2_t operator-(const projectile_vec2_t& other)
    {
        return projectile_vec2_t(x - other.x, y - other.y);
    }

    inline projectile_vec2_t& operator+=(const projectile_vec2_t& other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

inline projectile_vec2_t operator*(const projectile_vec2_t& value, float scalar)
{
    return projectile_vec2_t(scalar * value.x, scalar * value.y);
}

inline projectile_vec2_t operator*(float scalar, const projectile_vec2_t& value)
{
    return projectile_vec2_t(scalar * value.x, scalar * value.y);
}

inline float projectile_vec2_angle(const projectile_vec2_t& value)
{
    return atan2f(value.y, value.x);
}

inline float projectile_vec2_dot(const vec2f_t& value)
{
    return value.x * value.x + value.y * value.y;
}

inline float projectile_vec2_length(vec2f_t& value)
{
#if CL_BUILD == 10908
    // 1.9.8 squares x first.
    float squared = value.x * value.x;
    squared += value.y * value.y;
    return (float)sqrt(squared);
#else
    float squared = value.y * value.y;
    squared += value.x * value.x;
    return (float)(sqrt(squared));
#endif
}

inline float projectile_vec2_length_of(const projectile_vec2_t& value)
{
    return (float)sqrt(value.x * value.x + value.y * value.y);
}

extern "C" {
extern int projectile_update_tick;
extern int perk_id_ion_gun_master;
extern int perk_id_barrel_greaser;
extern int perk_id_bloody_mess_quick_learner;
extern int highscore_record_shots_hit;
extern unsigned char music_playlist_randomized_latch;
extern int music_track_game_playlist;
extern int sfx_bullet_hit_01;
extern weapon_storage_entry_t weapon_ammo_class[];
extern int config_detail_preset;
extern creature_type_table_t creature_type_table;

void creatures_apply_radius_damage(const vec2f_t* pos, float radius, float damage, int damage_type);
int creature_find_in_radius(const vec2f_t* pos, float radius, int start_index);
int player_find_in_radius(int owner_id, const vec2f_t* pos, float radius);
int vec2_add(vec2f_t* dst, const vec2f_t* delta, float mode);
int vec2_add_inplace(int entity_index, vec2f_t* pos, const vec2f_t* delta);
void effect_spawn_blood_splatter(const vec2f_t* pos, float angle, float age);
void effect_spawn_splitter_hit_burst(const vec2f_t* pos, float radius, int count);
void effect_spawn_ion_hit_sparks(const vec2f_t* pos, float scale);
void effect_spawn_shrinkifier_hit(const vec2f_t* pos);
void fx_queue_add_random(vec2f_t* pos);
void creature_handle_death(int creature_id, unsigned char keep_corpse);
void music_play_exclusive(int sfx_id);
int fx_spawn_sprite(const vec2f_t* pos, const vec2f_t* vel, float scale);
vec2f_t* __stdcall D3DXVec2Normalize(vec2f_t* dst, const vec2f_t* src);
}

#if CL_BUILD == 10908
/*
 * Translation-unit context for 1.9.8. Its C2 (9044) reuses what it learned compiling earlier
 * functions of the same unit: a call to one of them keeps the registers and globals that the
 * callee leaves alone. vec2_add and creature_find_in_radius precede projectile_update in the
 * original unit (see vec2_add.cpp and creature_find_in_radius.c). Without them, the miss block
 * reloads shock_chain_projectile_id, and its compare loads projectile_index first. 1.9.93's C2
 * (8966) ignores this, so the canonical object keeps one function per file.
 */
extern "C" int vec2_add(
    vec2f_t *dst,
    const vec2f_t *delta,
    float)
{
    dst->x = dst->x + delta->x;
    dst->y = delta->y + dst->y;
    return 0;
}

static __inline float vec2_distance(const vec2f_t *lhs, const vec2f_t *rhs)
{
    float dx = lhs->x - rhs->x;
    float dy = lhs->y - rhs->y;
    float distance_sq = dx * dx;
    distance_sq += dy * dy;
    return (float)sqrt(distance_sq);
}

extern "C" int creature_find_in_radius(
    const vec2f_t *pos,
    float radius,
    int start_index)
{
    int index = start_index;

    while (index < 0x180) {
        if (creature_pool[index].active
            && vec2_distance(
                   &creature_pool[index].position,
                   pos)
                    - radius
                < creature_pool[index].size * 0.14285715f + 3.0f
            && creature_pool[index].death_timer > 5.0f) {
            goto found;
        }
        ++index;
    }
    return -1;

found:
    return index;
}
#endif

static __inline void projectile_clamp_tint(float* value)
{
    if (*value < 0.0f) {
        *value = 0.0f;
    } else if (*value > 1.0f) {
        *value = 1.0f;
    }
}

extern "C" void projectile_update(void)
{
    float offset_y;
    float offset_x;
    int step_count;
    float step_x;
    float step_y;
#if CL_BUILD != 10908
    // 1.9.8 scopes delta to the stepping block (frame packing); no shared spelling keeps both frames.
    vec2f_t delta;
#endif
    int step;
    ++projectile_update_tick;
    float ion_damage_scale = 1.0f;
    if (perk_count_get(perk_id_ion_gun_master) != 0) {
        ion_damage_scale = 1.2f;
    }

    int projectile_index = 0;
    do {
        if (projectile_pool[projectile_index].active) {
            projectile_t* projectile = &projectile_pool[projectile_index];
            if (projectile->pos.tail.vy.life_timer <= 0.0f) {
                projectile->active = 0;
            }

            if (projectile->pos.tail.vy.life_timer < 0.4f) {
                projectile_type_id_t type_id = projectile->pos.tail.vy.type_id;

                if (type_id == PROJECTILE_TYPE_ION_RIFLE
                    || type_id == PROJECTILE_TYPE_ION_MINIGUN) {
                    if (projectile_index == shock_chain_projectile_id) {
                        shock_chain_projectile_id = -1;
                        shock_chain_links_left = 0;
                    }

                    projectile->pos.tail.vy.life_timer -= frame_dt;
                    if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
                        creatures_apply_radius_damage(
                            &projectile->position, ion_damage_scale * 88.0f, frame_dt * 100.0f, 7);
                    } else {
                        creatures_apply_radius_damage(
                            &projectile->position, ion_damage_scale * 60.0f, frame_dt * 40.0f, 7);
                    }
                } else if (type_id == PROJECTILE_TYPE_ION_CANNON) {
                    projectile->pos.tail.vy.life_timer -= frame_dt * 0.7f;
                    creatures_apply_radius_damage(
                        &projectile->position, ion_damage_scale * 128.0f, frame_dt * 300.0f, 7);
                } else if (type_id == PROJECTILE_TYPE_GAUSS_GUN) {
                    projectile->pos.tail.vy.life_timer -= frame_dt * 0.1f;
                } else {
                    projectile->pos.tail.vy.life_timer -= frame_dt;
                }
            } else {
                vec2f_t* position = &projectile->position;
                if (projectile->position.x < -64.0f || projectile->position.y < -64.0f
                    || (float)(terrain_texture_width + 64) < projectile->position.x
                    || (float)(terrain_texture_height + 64) < projectile->position.y) {
                    projectile->pos.tail.vy.life_timer -= frame_dt;
                } else {
                    step_count = (int)projectile->pos.tail.vy.projectile_speed;
                    float heading = projectile->angle - 1.5707964f;
                    step_x = (float)cos(heading) * frame_dt * 20.0f;
                    step_y = (float)sin(heading) * frame_dt * 20.0f;

                    if (perk_count_get(perk_id_barrel_greaser) != 0
                        && projectile->pos.tail.vy.owner_id < 0) {
                        step_count *= 2.0f;
                    }

#if CL_BUILD == 10908
                    vec2f_t delta;
#endif
                    delta.x = delta.y = 0.0f;
                    {
                        for (step = 0; step < step_count; step += 3) {
                            delta.x += step_x * projectile->pos.tail.vy.speed_scale * 3.0f;
                            delta.y += step_y * projectile->pos.tail.vy.speed_scale * 3.0f;

                            float distance_sq = delta.x * delta.x;
                            distance_sq += delta.y * delta.y;
                            float distance = (float)sqrt(distance_sq);
                            bool microstep_ready = !(distance < 4.0f);
                            if (microstep_ready || step + 3 >= step_count) {
                                vec2_add(position, &delta, 0.0f);
                                int hit_id = creature_find_in_radius(
                                    position, projectile->pos.tail.vy.hit_radius, 0);

                                if (hit_id == -1 || hit_id == projectile->pos.tail.vy.owner_id) {
                                    if (projectile_index != shock_chain_projectile_id) {
                                        int owner_id = projectile->pos.tail.vy.owner_id;
                                        if (owner_id != -100) {
                                            hit_id = player_find_in_radius(owner_id, position,
                                                projectile->pos.tail.vy.hit_radius);
                                        }
                                        if (hit_id != -1) {
                                            projectile->pos.tail.vy.life_timer = 0.25f;
                                            if (player_state_table[hit_id].shield_timer <= 0.0f) {
                                                player_state_table[hit_id].health -= 10.0f;
                                            }
                                        }
                                    }
                                } else {
                                    if (perk_count_get(perk_id_poison_bullets) != 0
                                        && (crt_rand() & 7) == 1) {
                                        creature_pool[hit_id].flags
                                            |= CREATURE_FLAG_POISONED;
                                    }

                                    projectile_type_id_t type_id = projectile->pos.tail.vy.type_id;
                                    if (type_id == PROJECTILE_TYPE_BLADE_GUN) {
                                        for (int count = 0; count < 8; ++count) {
                                            effect_spawn_blood_splatter(position,
                                                (float)(crt_rand() & 0xff) * 0.024543693f, 0.0f);
                                        }
                                    } else if (type_id == PROJECTILE_TYPE_SPLITTER_GUN) {
                                        effect_spawn_splitter_hit_burst(position, 26.0f, 3);
                                        projectile_spawn(position, projectile->angle - 1.0471976f,
                                            PROJECTILE_TYPE_SPLITTER_GUN, hit_id);
                                        projectile_spawn(position, projectile->angle + 1.0471976f,
                                            PROJECTILE_TYPE_SPLITTER_GUN, hit_id);
                                    }

                                    effect_color_t effect_color = {
                                        1.0f,
                                        1.0f,
                                        1.0f,
                                        1.0f,
                                    };
                                    effect_template.flags = 0x59;
                                    effect_template.color = effect_color;
                                    effect_template.lifetime = 0.35f;
                                    effect_template.age = 0.0f;
                                    effect_template.half_extent.x = 4.0f;
                                    effect_template.half_extent.y = 4.0f;

                                    if (!config_violence_disabled) {
                                        if (perk_count_get(perk_id_bloody_mess_quick_learner)
                                            != 0) {
                                            for (int count = 0; count < 8; ++count) {
                                                effect_spawn_blood_splatter(position,
                                                    projectile->angle - 1.5707964f
                                                        + (float)((crt_rand() & 0x1f) - 0x10)
                                                            * 0.0625f,
                                                    0.0f);
                                            }
                                            effect_spawn_blood_splatter(position,
                                                projectile->angle - 1.5707964f + 3.1415927f, 0.0f);
                                        } else if (bonus_freeze_timer <= 0.0f) {
                                            for (int count = 0; count < 2; ++count) {
                                                effect_spawn_blood_splatter(
                                                    position, projectile->angle - 1.5707964f, 0.0f);
                                                if ((crt_rand() & 7) == 2) {
                                                    effect_spawn_blood_splatter(position,
                                                        projectile->angle - 1.5707964f + 3.1415927f,
                                                        0.0f);
                                                }
                                            }
                                        }
                                    }

                                    if (creature_pool[hit_id].death_timer == 16.0f) {
                                        ++highscore_record_shots_hit;
                                    }

                                    if (perk_count_get(perk_id_bloody_mess_quick_learner) != 0) {
                                        int upper = 30;
                                        int lower = -30;
                                        do {
                                            vec2f_t impact_offset_1 = {
                                                (float)(crt_rand() % (upper - lower) + lower),
                                                (float)(crt_rand() % (upper - lower) + lower),
                                            };
                                            vec2f_t impact_1 = {
                                                impact_offset_1.x
                                                    + creature_pool[hit_id].position.x,
                                                impact_offset_1.y
                                                    + creature_pool[hit_id].position.y,
                                            };
                                            fx_queue_add_random(&impact_1);

                                            vec2f_t impact_offset_2 = {
                                                (float)(crt_rand() % (upper - lower) + lower),
                                                (float)(crt_rand() % (upper - lower) + lower),
                                            };
                                            vec2f_t impact_2 = {
                                                impact_offset_2.x
                                                    + creature_pool[hit_id].position.x,
                                                impact_offset_2.y
                                                    + creature_pool[hit_id].position.y,
                                            };
                                            fx_queue_add_random(&impact_2);

                                            lower -= 10;
                                            upper += 10;
                                        } while (lower > -60);
                                    }

                                    type_id = projectile->pos.tail.vy.type_id;
                                    if (type_id != PROJECTILE_TYPE_FIRE_BULLETS
                                        && type_id != PROJECTILE_TYPE_GAUSS_GUN
                                        && type_id != PROJECTILE_TYPE_BLADE_GUN) {
                                        projectile->pos.tail.vy.life_timer = 0.25f;
                                        float jitter = (float)(crt_rand() & 3);
                                        float heading = projectile->angle - 1.5707964f;
                                        projectile->position.x += (float)cos(heading) * jitter;
                                        projectile->position.y += (float)sin(heading) * jitter;
                                    }

                                    float damage_dx = projectile->pos.origin_x - position->x;
                                    float damage_dy = projectile->pos.tail.origin_y - position->y;
                                    float damage_distance = (float)sqrt(
                                        damage_dx * damage_dx + damage_dy * damage_dy);
                                    if (damage_distance < 50.0f) {
                                        damage_distance = 50.0f;
                                    }

                                    type_id = projectile->pos.tail.vy.type_id;
                                    float damage = ((100.0f / damage_distance)
                                            * weapon_table[type_id].damage_scale * 30.0f
                                        + 10.0f);

                                    if (type_id == PROJECTILE_TYPE_ION_MINIGUN) {
                                        effect_spawn_ion_hit_core(position, 1.5f, 0.1f);
                                        effect_spawn_ion_hit_sparks(position, 0.8f);
                                    } else if (type_id == PROJECTILE_TYPE_ION_RIFLE) {
                                        if (shock_chain_links_left > 0
                                            && projectile_index == shock_chain_projectile_id) {
                                            --shock_chain_links_left;
                                            int next_id
                                                = creature_find_nearest(position, hit_id, 100.0f);
                                            scripted_burst_active = 1;
                                            vec2f_t* next_position
                                                = &creature_pool[next_id].position;
                                            vec2f_t* hit_position = &creature_pool[hit_id].position;
                                            float chain_angle
                                                = (float)atan2f(next_position->y - hit_position->y,
                                                    next_position->x - hit_position->x);
                                            shock_chain_projectile_id = projectile_spawn(position,
                                                chain_angle - 1.5707964f - 3.1415927f,
                                                PROJECTILE_TYPE_ION_RIFLE, hit_id);
                                            scripted_burst_active = 0;
                                        }
                                        effect_spawn_ion_hit_core(position, 1.2f, 0.4f);
                                        effect_spawn_ion_hit_sparks(position, 1.2f);
                                    } else if (type_id == PROJECTILE_TYPE_ION_CANNON) {
                                        effect_spawn_ion_hit_core(position, 1.0f, 1.0f);
                                        effect_spawn_ion_hit_sparks(position, 2.2f);
                                        sfx_play_panned(sfx_shockwave, position, 1.0f);
                                    } else if (type_id == PROJECTILE_TYPE_PLASMA_CANNON) {
                                        scripted_burst_active = 1;
                                        int child_index = 0;
                                        float child_radius
                                            = creature_pool[hit_id].size * 0.5f + 1.0f;
                                        do {
                                            float child_angle = (float)child_index * 0.5235988f;
                                            vec2f_t child_offset = {
                                                (float)(cos(child_angle) * child_radius),
                                                (float)(sin(child_angle) * child_radius),
                                            };
                                            vec2f_t child_pos = {
                                                child_offset.x + position->x,
                                                child_offset.y + position->y,
                                            };
                                            projectile_spawn(&child_pos, child_angle,
                                                PROJECTILE_TYPE_PLASMA_RIFLE, -100);
                                            ++child_index;
                                        } while (child_index < 12);
                                        scripted_burst_active = 0;
                                        sfx_play_panned(sfx_explosion_medium, position, 1.0f);
                                        sfx_play_panned(sfx_shockwave, position, 1.0f);
                                        effect_spawn_plasma_hit_core(position, 1.5f, 1.0f);
                                        effect_spawn_plasma_hit_core(position, 1.0f, 1.0f);
                                    } else if (type_id == PROJECTILE_TYPE_SHRINKIFIER) {
                                        effect_spawn_shrinkifier_hit(position);
                                        float size = creature_pool[hit_id].size * 0.65f;
                                        projectile->pos.tail.vy.life_timer = 0.25f;
                                        creature_pool[hit_id].size = size;
                                        if (size < 16.0f) {
                                            creature_handle_death(hit_id, 1);
                                        }
                                    } else if (type_id == PROJECTILE_TYPE_PULSE_GUN) {
                                        vec2f_t pulse_offset = {
                                            delta.x * 3.0f,
                                            delta.y * 3.0f,
                                        };
                                        creature_pool[hit_id].position.x += pulse_offset.x;
                                        creature_pool[hit_id].position.y += pulse_offset.y;
                                    } else if (type_id == PROJECTILE_TYPE_PLAGUE_SPREADER) {
                                        creature_pool[hit_id].plague_infected = 1;
                                    }

                                    damage *= 0.95f;
                                    if (damage > 0.0f && creature_pool[hit_id].health > 0.0f) {
                                        projectile->pos.tail.vy.damage_pool -= 1.0f;
                                        if (projectile->pos.tail.vy.damage_pool > 0.0f) {
                                            float& impulse_speed
                                                = projectile->pos.tail.vy.speed_scale;
                                            float impulse_cosine
                                                = (float)cos(projectile->angle - 1.5707964f);
                                            float impulse_x = impulse_cosine
                                                * projectile->pos.tail.vy.speed_scale;

                                            vec2f_t impulse = {
                                                impulse_x,
                                                impulse_cosine * impulse_speed,
                                            };
                                            creature_apply_damage(hit_id,
                                                projectile->pos.tail.vy.damage_pool, 1, &impulse);
                                            projectile->pos.tail.vy.damage_pool
                                                -= creature_pool[hit_id].health;
                                        } else {
                                            float& impulse_speed
                                                = projectile->pos.tail.vy.speed_scale;
                                            float impulse_cosine
                                                = (float)cos(projectile->angle - 1.5707964f);
                                            float impulse_x = impulse_cosine
                                                * projectile->pos.tail.vy.speed_scale;

                                            vec2f_t impulse = {
                                                impulse_x,
                                                impulse_cosine * impulse_speed,
                                            };
                                            creature_apply_damage(hit_id, damage, 1, &impulse);
                                            if (projectile->pos.tail.vy.life_timer != 0.25f) {
                                                projectile->pos.tail.vy.life_timer = 0.25f;
                                            }
                                        }
                                    }

                                    if (projectile->pos.tail.vy.damage_pool == 1.0f) {
                                        if (projectile->pos.tail.vy.life_timer == 0.25f) {
                                            projectile->pos.tail.vy.damage_pool = 0.0f;
                                        } else {
                                            projectile->pos.tail.vy.damage_pool = 0.0f;
                                            projectile->pos.tail.vy.life_timer = 0.25f;
                                        }
                                    }
                                    creature_pool[hit_id].state_flag = 1;
                                    crt_rand();

                                    type_id = projectile->pos.tail.vy.type_id;
                                    if (type_id == PROJECTILE_TYPE_GAUSS_GUN
                                        || type_id == PROJECTILE_TYPE_FIRE_BULLETS) {
                                        perk_count_get(perk_id_bloody_mess_quick_learner);
#if CL_BUILD == 10908
                                        // 1.9.8 hoists the zero vector out of the six-shard loop (frame packing).
                                        vec2f_t zero = { 0.0f, 0.0f };
#endif
                                        for (int count = 0; count < 6; ++count) {
                                            float speed = (float)(crt_rand() % 100) * 0.1f;
                                            if (speed > 4.0f) {
                                                speed = (float)(crt_rand() % 90 + 10) * 0.1f;
                                            }
                                            if (speed > 7.0f) {
                                                speed = (float)(crt_rand() % 80 + 20) * 0.1f;
                                            }

                                            float impact_heading = projectile->angle - 1.5707964f;
                                            offset_x = (float)cos(impact_heading) * speed * 20.0f;
                                            offset_y = (float)sin(impact_heading) * speed * 20.0f;
                                            vec2f_t impulse_pos = {
                                                creature_pool[hit_id].position.x + offset_x,
                                                creature_pool[hit_id].position.y + offset_y,
                                            };
#if CL_BUILD != 10908
                                            vec2f_t zero = { 0.0f, 0.0f };
#endif
                                            vec2_add_inplace(hit_id, &impulse_pos, &zero);
                                            crt_rand();

                                            if (bonus_freeze_timer > 0.0f) {
                                                vec2f_t shard_pos = {
                                                    position->x + offset_x,
                                                    position->y + offset_y,
                                                };
                                                effect_spawn_freeze_shard(&shard_pos,
                                                    projectile->angle - 1.5707964f
                                                        + (float)(crt_rand() % 100) * 0.01f);
                                            }

                                            vec2f_t decal_pos = {
                                                creature_pool[hit_id].position.x + offset_x,
                                                creature_pool[hit_id].position.y + offset_y,
                                            };
                                            fx_queue_add_random(&decal_pos);
                                        }
                                    } else if (bonus_freeze_timer > 0.0f) {
                                        effect_spawn_freeze_shard(position,
                                            projectile->angle - 1.5707964f
                                                + (float)(crt_rand() % 100) * 0.01f);
                                    } else {
                                        for (int count = 0; count < 3; ++count) {
                                            float impact_heading = projectile->angle - 1.5707964f
                                                + (float)(crt_rand() % 20 - 10) * 0.1f;
                                            offset_x = (float)cos(impact_heading) * 20.0f;
                                            offset_y = (float)sin(impact_heading) * 20.0f;

                                            vec2f_t* creature_pos = &creature_pool[hit_id].position;
                                            fx_queue_add_random(creature_pos);

                                            vec2f_t decal_offset_1 = {
                                                offset_x * 1.5f,
                                                offset_y * 1.5f,
                                            };
                                            vec2f_t decal_pos_1 = {
                                                creature_pos->x + decal_offset_1.x,
                                                creature_pos->y + decal_offset_1.y,
                                            };
                                            fx_queue_add_random(&decal_pos_1);

                                            vec2f_t decal_offset_2 = {
                                                offset_x * 2.0f,
                                                offset_y * 2.0f,
                                            };
                                            vec2f_t decal_pos_2 = {
                                                creature_pos->x + decal_offset_2.x,
                                                creature_pos->y + decal_offset_2.y,
                                            };
                                            fx_queue_add_random(&decal_pos_2);

                                            vec2f_t decal_offset_3 = {
                                                offset_x * 2.5f,
                                                offset_y * 2.5f,
                                            };
                                            vec2f_t decal_pos_3 = {
                                                creature_pos->x + decal_offset_3.x,
                                                creature_pos->y + decal_offset_3.y,
                                            };
                                            fx_queue_add_random(&decal_pos_3);
                                        }
                                    }

                                    if (!demo_mode_active && !music_playlist_randomized_latch
                                        && config_game_mode != GAME_MODE_RUSH) {
                                        music_play_exclusive(music_track_game_playlist);
                                    } else {
                                        if (weapon_ammo_class[projectile->pos.tail.vy.type_id]
                                                .ammo_class
                                            == 4) {
                                            sfx_play_panned(sfx_shock_hit_01, position, 1.0f);
                                        } else {
                                            sfx_play_panned(
                                                crt_rand() % 6 + sfx_bullet_hit_01, position, 1.0f);
                                        }
                                    }

                                    if (projectile->pos.tail.vy.damage_pool <= 0.0f) {
                                        break;
                                    }
                                }

                                delta.x = delta.y = 0.0f;
                            }
                        }
                    }
                }
            }
        }
        ++projectile_index;
    } while (projectile_index < PROJECTILE_POOL_CAPACITY);

    for (int secondary_index = 0; secondary_index < 0x40; ++secondary_index) {
        if (secondary_projectile_pool[secondary_index].active) {
            if (secondary_projectile_pool[secondary_index].pos.vx.vy.type_id == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
                camera_shake_pulses = 4;
                float scale = secondary_projectile_pool[secondary_index].pos.vx.vel_x + frame_dt * 3.0f;
                secondary_projectile_pool[secondary_index].pos.vx.vel_x += frame_dt * 3.0f;

#if CL_BUILD == 10908
                // 1.9.8 compares the local; 1.9.93 re-reads the field.
                if (scale > 1.0f) {
                    float extent = secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y * 256.0f;
                    effect_color_t color = {
                        0.0f,
                        0.0f,
                        0.0f,
                        0.25f,
                    };
                    fx_queue_add(0x10, &secondary_projectile_pool[secondary_index].position, extent, extent, 0.0f, &color);
                    secondary_projectile_pool[secondary_index].active = 0;
                }

#else
                if (secondary_projectile_pool[secondary_index].pos.vx.vel_x > 1.0f) {
                    float extent = secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y * 256.0f;
                    effect_color_t color = {
                        0.0f,
                        0.0f,
                        0.0f,
                        0.25f,
                    };
                    fx_queue_add(0x10, &secondary_projectile_pool[secondary_index].position, extent, extent, 0.0f, &color);
                    secondary_projectile_pool[secondary_index].active = 0;
                }

#endif

#if CL_BUILD == 10908
                // 1.9.8 reuses the local for the radius.
                float radius = scale * secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y * 80.0f;
#else
                float explosion_size = secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y;
                float radius = explosion_size * secondary_projectile_pool[secondary_index].pos.vx.vel_x * 80.0f;
#endif
                int creature_id = 0;
                do {
                    creature_t* creature = &creature_pool[creature_id];
                    if (creature->active && creature_pool[creature_id].health > 0.0f) {
                        vec2f_t& explosion_position = secondary_projectile_pool[secondary_index].position;
                        vec2f_t& explosion_target = creature_pool[creature_id].position;
                        float distance = projectile_vec2_length_of(*(projectile_vec2_t*)&creature_pool[creature_id].position - *(projectile_vec2_t*)&secondary_projectile_pool[secondary_index].position);
                        if (distance < radius) {
                            float dx = explosion_target.x - explosion_position.x;
                            float dy = creature->position.y - explosion_position.y;
                            vec2f_t direction = { dx, dy };
                            D3DXVec2Normalize(&direction, &direction);
                            projectile_vec2_t impulse = *(projectile_vec2_t*)&direction * 0.1f;
                            creature_apply_damage(creature_id,
                                frame_dt * secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y * 700.0f, 3,
                                (vec2f_t*)&impulse);
                            if (creature_pool[creature_id].health <= 0.0f) {
                                fx_queue_add_random(&creature_pool[creature_id].position);
                                fx_queue_add_random(&creature_pool[creature_id].position);
                                creature_handle_death(creature_id, 1);
                            }
                        }
                    }
                    ++creature_id;
                } while (creature_id < 0x180);
            } else {
                projectile_vec2_t& secondary_position = *(projectile_vec2_t*)&secondary_projectile_pool[secondary_index].position;
                projectile_vec2_t movement
                    = frame_dt * *(projectile_vec2_t*)&secondary_projectile_pool[secondary_index].pos.vx.velocity;
                vec2_add((vec2f_t*)&secondary_position, (vec2f_t*)&movement, 4.0f);

                secondary_projectile_type_id_t type_id = secondary_projectile_pool[secondary_index].pos.vx.vy.type_id;
                if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
                    float speed = projectile_vec2_length(secondary_projectile_pool[secondary_index].pos.vx.velocity);
                    if (speed < 500.0f) {
                        float scale = frame_dt * 3.0f + 1.0f;
                        secondary_projectile_pool[secondary_index].pos.vx.vel_x *= scale;
                        secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y *= scale;
                    }
                    secondary_projectile_pool[secondary_index].life_timer -= frame_dt;
                } else if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
                    float speed = projectile_vec2_length(secondary_projectile_pool[secondary_index].pos.vx.velocity);
                    if (speed < 600.0f) {
                        float scale = frame_dt * 4.0f + 1.0f;
                        secondary_projectile_pool[secondary_index].pos.vx.vel_x *= scale;
                        secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y *= scale;
                    }
                    secondary_projectile_pool[secondary_index].life_timer -= frame_dt;
                } else if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
                    if (!creature_pool[secondary_projectile_pool[secondary_index].pos.vx.vy.target_id].active) {
                        secondary_projectile_pool[secondary_index].pos.vx.vy.target_id
                            = creature_find_nearest((vec2f_t*)&secondary_position, -1, 0.0f);
                    }

                    creature_t* target = &creature_pool[secondary_projectile_pool[secondary_index].pos.vx.vy.target_id];
                    projectile_vec2_t& target_position = *(projectile_vec2_t*)&target->position;
                    projectile_vec2_t& secondary_velocity
                        = *(projectile_vec2_t*)&secondary_projectile_pool[secondary_index].pos.vx.velocity;
#if CL_BUILD == 10908
                    // 1.9.8 keeps the seeker steps for the speed clamp instead of recomputing them.
                    float seeker_heading = (secondary_projectile_pool[secondary_index].angle
                        = projectile_vec2_angle(secondary_position - target_position) - 1.5707964f);
                    float seeker_step_x = (float)cos(seeker_heading - 1.5707964f) * frame_dt * 800.0f;
                    float seeker_x = (secondary_velocity.x += seeker_step_x);
                    float seeker_step_y = (float)sin(seeker_heading - 1.5707964f) * frame_dt * 800.0f;
                    float seeker_y = (secondary_velocity.y += seeker_step_y);
                    float speed = projectile_vec2_length(secondary_projectile_pool[secondary_index].pos.vx.velocity);
                    if (speed > 350.0f) {
                        secondary_velocity.x = seeker_x - seeker_step_x;
                        secondary_velocity.y = seeker_y - seeker_step_y;
                    }
#else
                    secondary_projectile_pool[secondary_index].angle
                        = projectile_vec2_angle(secondary_position - target_position) - 1.5707964f;
                    secondary_velocity.x
                        += (float)cos(secondary_projectile_pool[secondary_index].angle - 1.5707964f) * frame_dt * 800.0f;
                    secondary_velocity.y
                        += (float)sin(secondary_projectile_pool[secondary_index].angle - 1.5707964f) * frame_dt * 800.0f;

                    float speed = projectile_vec2_length(secondary_projectile_pool[secondary_index].pos.vx.velocity);
                    if (speed > 350.0f) {
                        float& velocity_x = secondary_projectile_pool[secondary_index].pos.vx.vel_x;
                        velocity_x -= (float)cos(secondary_projectile_pool[secondary_index].angle - 1.5707964f) * frame_dt * 800.0f;
                        secondary_velocity.y
                            -= (float)sin(secondary_projectile_pool[secondary_index].angle - 1.5707964f) * frame_dt * 800.0f;
                    }
#endif
                    secondary_projectile_pool[secondary_index].life_timer -= frame_dt * 0.5f;
                }

                secondary_projectile_pool[secondary_index].pos.vx.vy.trail_distance
                    -= (m_fabs(secondary_projectile_pool[secondary_index].pos.vx.vel_x) + m_fabs(secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y))
                    * frame_dt * 0.01f;
                if (secondary_projectile_pool[secondary_index].pos.vx.vy.trail_distance < 0.0f) {
                    projectile_vec2_t trail_velocity
                        = projectile_vec2_t((float)cos(secondary_projectile_pool[secondary_index].angle + 1.5707964f),
                              (float)cos(secondary_projectile_pool[secondary_index].angle + 1.5707964f))
                        * 90.0f;
                    float trail_heading = secondary_projectile_pool[secondary_index].angle - 1.5707964f;
                    projectile_vec2_t& trail_origin = secondary_position;
                    projectile_vec2_t trail_pos = trail_origin
                        - projectile_vec2_t((float)cos(trail_heading), (float)sin(trail_heading))
                            * 9.0f;
                    int effect_id = fx_spawn_sprite(
                        (const vec2f_t*)&trail_pos, (const vec2f_t*)&trail_velocity, 14.0f);
                    secondary_projectile_pool[secondary_index].pos.vx.vy.trail_distance = 0.06f;
                    sprite_effect_pool[effect_id].color_a = 0.25f;
                }

                int hit_id = creature_find_in_radius((vec2f_t*)&secondary_position, 8.0f, 0);
                if (hit_id != -1) {
                    float angle;
                    if (creature_pool[hit_id].death_timer == 16.0f) {
                        ++highscore_record_shots_hit;
                    }

                    if (bonus_freeze_timer > 0.0f) {
                        for (int count = 0; count < 4; ++count) {
                            effect_spawn_freeze_shard(
                                (vec2f_t*)&secondary_position, (float)(crt_rand() % 612) * 0.01f);
                        }
                    } else {
                        vec2f_t decal_offset_1 = {
                            (float)(crt_rand() % 20 - 10),
                            (float)(crt_rand() % 20 - 10),
                        };
                        vec2f_t decal_pos_1 = {
                            decal_offset_1.x + creature_pool[hit_id].position.x,
                            decal_offset_1.y + creature_pool[hit_id].position.y,
                        };
                        fx_queue_add_random(&decal_pos_1);

                        vec2f_t decal_offset_2 = {
                            (float)(crt_rand() % 20 - 10),
                            (float)(crt_rand() % 20 - 10),
                        };
                        vec2f_t decal_pos_2 = {
                            decal_offset_2.x + creature_pool[hit_id].position.x,
                            decal_offset_2.y + creature_pool[hit_id].position.y,
                        };
                        fx_queue_add_random(&decal_pos_2);

                        vec2f_t decal_offset_3 = {
                            (float)(crt_rand() % 20 - 10),
                            (float)(crt_rand() % 20 - 10),
                        };
                        vec2f_t decal_pos_3 = {
                            decal_offset_3.x + creature_pool[hit_id].position.x,
                            decal_offset_3.y + creature_pool[hit_id].position.y,
                        };
                        fx_queue_add_random(&decal_pos_3);
                    }

                    type_id = secondary_projectile_pool[secondary_index].pos.vx.vy.type_id;
                    float damage = 150.0f;
                    if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
                        damage = secondary_projectile_pool[secondary_index].life_timer * 50.0f + 500.0f;
                        if (config_detail_preset >= 3) {
                            effect_spawn_explosion_burst((vec2f_t*)&secondary_position, 0.4f);
                        }
                    } else if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
                        damage = secondary_projectile_pool[secondary_index].life_timer * 20.0f + 80.0f;
                    } else if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
                        damage = secondary_projectile_pool[secondary_index].life_timer * 20.0f + 40.0f;
                    }

                    if (!demo_mode_active && !music_playlist_randomized_latch
                        && config_game_mode != GAME_MODE_RUSH) {
                        music_play_exclusive(music_track_game_playlist);
                    } else {
                        sfx_play_panned(sfx_explosion_medium, (vec2f_t*)&secondary_position, 1.0f);
                    }

                    float inverse_dt = frame_dt;
                    inverse_dt = 1.0f / inverse_dt;
                    creature_pool[hit_id].state_flag = 1;
                    vec2f_t impulse = {
                        inverse_dt * secondary_projectile_pool[secondary_index].pos.vx.vel_x,
                        inverse_dt * secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y,
                    };
                    creature_apply_damage(hit_id, damage, 3, &impulse);

                    type_id = secondary_projectile_pool[secondary_index].pos.vx.vy.type_id;
                    if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
                        secondary_projectile_pool[secondary_index].pos.vx.vy.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
                        secondary_projectile_pool[secondary_index].pos.vx.vel_x = 0.0f;
                        secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y = 1.0f;
                        if (bonus_freeze_timer > 0.0f) {
                            for (int count = 0; count < 8; ++count) {
                                effect_spawn_freeze_shard((vec2f_t*)&secondary_position,
                                    (float)(crt_rand() % 612) * 0.01f);
                            }
                        } else {
                            for (int count = 0; count < 20; ++count) {
                                angle = (float)(crt_rand() % 628) * 0.01f;
                                int radius = crt_rand() % 90;
                                vec2f_t decal_offset = {
                                    (float)(cos(angle) * radius),
                                    (float)(sin(angle) * radius),
                                };
                                vec2f_t decal_pos = {
                                    decal_offset.x + creature_pool[hit_id].position.x,
                                    decal_offset.y + creature_pool[hit_id].position.y,
                                };
                                fx_queue_add_random(&decal_pos);
                            }
                        }
                    } else if (type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
                        secondary_projectile_pool[secondary_index].pos.vx.vy.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
                        secondary_projectile_pool[secondary_index].pos.vx.vel_x = 0.0f;
                        secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y = 0.35f;
                        if (bonus_freeze_timer > 0.0f) {
                            for (int count = 0; count < 8; ++count) {
                                effect_spawn_freeze_shard((vec2f_t*)&secondary_position,
                                    (float)(crt_rand() % 612) * 0.01f);
                            }
                        } else {
                            for (int count = 0; count < 10; ++count) {
                                angle = (float)(crt_rand() % 628) * 0.01f;
                                int radius = crt_rand() % 64;
                                vec2f_t decal_offset = {
                                    (float)(cos(angle) * radius),
                                    (float)(sin(angle) * radius),
                                };
                                vec2f_t decal_pos = {
                                    decal_offset.x + creature_pool[hit_id].position.x,
                                    decal_offset.y + creature_pool[hit_id].position.y,
                                };
                                fx_queue_add_random(&decal_pos);
                            }
                        }
                    } else if (type_id == SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN) {
                        secondary_projectile_pool[secondary_index].pos.vx.vy.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
                        secondary_projectile_pool[secondary_index].pos.vx.vel_x = 0.0f;
                        secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y = 0.25f;
                        if (bonus_freeze_timer > 0.0f) {
                            for (int count = 0; count < 8; ++count) {
                                effect_spawn_freeze_shard(&creature_pool[hit_id].position,
                                    (float)(crt_rand() % 612) * 0.01f);
                            }
                        } else {
                            for (int count = 0; count < 3; ++count) {
                                angle = (float)(crt_rand() % 628) * 0.01f;
                                int radius = crt_rand() % 44;
                                vec2f_t decal_offset = {
                                    (float)(cos(angle) * radius),
                                    (float)(sin(angle) * radius),
                                };
                                vec2f_t decal_pos = {
                                    decal_offset.x + creature_pool[hit_id].position.x,
                                    decal_offset.y + creature_pool[hit_id].position.y,
                                };
                                fx_queue_add_random(&decal_pos);
                            }
                        }
                    }

                    int burst_index = 0;
                    do {
                        float magnitude = (float)(crt_rand() % 800) * 0.1f;
                        angle = (float)burst_index * 0.62831855f;
                        float burst_cos = (float)cos(angle);
                        float burst_sin = (float)sin(angle);
                        projectile_vec2_t burst_direction(burst_cos, burst_sin);
                        float velocity_x = magnitude;
                        velocity_x *= burst_direction.x;
                        vec2f_t velocity = {
                            velocity_x,
                            magnitude * burst_direction.y,
                        };
                        int effect_id = fx_spawn_sprite(
                            (vec2f_t*)&secondary_position, (vec2f_t*)&velocity, 14.0f);
                        sprite_effect_pool[effect_id].color_a = 0.37f;
                        ++burst_index;
                    } while (burst_index < 10);
                }

                if (secondary_projectile_pool[secondary_index].life_timer <= 0.0f) {
                    secondary_projectile_pool[secondary_index].pos.vx.vy.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
                    secondary_projectile_pool[secondary_index].pos.vx.vel_x = 0.0f;
                    secondary_projectile_pool[secondary_index].pos.vx.vy.vel_y = 0.5f;
                }
            }
        }
    }

    for (int sprite_index = 0; sprite_index < 0x180; ++sprite_index) {
        sprite_effect_t* sprite = &sprite_effect_pool[sprite_index];
        if (sprite->active) {
            *(projectile_vec2_t*)&sprite->position
                += frame_dt * *(projectile_vec2_t*)&sprite->velocity;
            sprite->rotation += frame_dt * 3.0f;
            sprite->color_a -= frame_dt;
            if (sprite->color_a <= 0.0f) {
                sprite->active = 0;
            }
            sprite->scale += frame_dt * 60.0f;
        }
    }

    for (projectile_index = 0; projectile_index < 0x80; ++projectile_index) {
        particle_t* particle = &particle_pool[projectile_index];
        if (particle->active) {
            projectile_vec2_t& particle_velocity = *(projectile_vec2_t*)&particle->velocity;
#if CL_BUILD != 10908
            // 1.9.8 steers through particle->angle directly.
            float& angle = particle->angle;
#endif
            float& rotation = particle->rotation;
            unsigned char& active = particle->active;
            unsigned char style_id = particle->style_id;
            if (style_id == 8) {
                particle->intensity -= frame_dt * 0.11f;
#if CL_BUILD == 10908
                // 1.9.8 updates the rotation field directly.
                particle->rotation += frame_dt * 5.0f;
#else
                rotation += frame_dt * 5.0f;
#endif
                if (particle->in_flight) {
                    if (particle->intensity > 0.15f) {
                        projectile_vec2_t movement
                            = frame_dt * particle_velocity * particle->intensity;
                        vec2_add(&particle->position, (vec2f_t*)&movement, 3.0f);
                    } else {
                        (*(projectile_vec2_t*)&particle->position)
                            += frame_dt * particle_velocity * 0.55f * particle->intensity;
                    }
                }
            } else {
                particle->intensity -= frame_dt * 0.9f;
#if CL_BUILD == 10908
                particle->rotation += frame_dt;
#else
                rotation += frame_dt;
#endif
                if (particle->intensity > 0.15f) {
                    projectile_vec2_t movement
                        = frame_dt * particle_velocity * 2.5f * particle->intensity;
                    vec2_add(&particle->position, (vec2f_t*)&movement, 3.0f);
                } else {
                    (*(projectile_vec2_t*)&particle->position)
                        += frame_dt * particle_velocity * 2.5f * 0.15f;
                }
            }

            style_id = particle->style_id;
            if (style_id == 0 && particle->intensity <= 0.0f) {
                active = 0;
            } else if (style_id != 0 && particle->intensity <= 0.8f) {
#if CL_BUILD == 10908
                // 1.9.8 tests the cached style byte; 1.9.93 re-reads it through a reference.
                active = 0;
                if (style_id == 8 && particle->target_id != -1) {
#else
                active = 0;
                const unsigned char& style = particle->style_id;
                if (style == 8 && particle->target_id != -1) {
#endif
                    if (creature_pool[particle->target_id].active) {
                        sfx_play_panned(
                            creature_type_table[creature_pool[particle->target_id].type_id]
                                .death_sfx[crt_rand() % 3],
                            &creature_pool[particle->target_id].position, 1.0f);
                    }
                    creature_handle_death(particle->target_id, 0);
                }
            } else {
                if (particle->in_flight == 1) {
                    if (style_id == 0) {
                        int turn = crt_rand() % 100 - 50;
                        float turn_delta = (float)turn * 0.06f;
                        turn_delta *= particle->intensity;
                        turn_delta *= frame_dt;
                        turn_delta *= 1.96f;
#if CL_BUILD == 10908
                        // 1.9.8 steers through the field, not the angle reference.
                        particle->angle -= turn_delta;
                        particle->velocity.x = (float)cos(particle->angle) * 82.0f;
                        particle->velocity.y = (float)sin(particle->angle) * 82.0f;
#else
                        angle -= turn_delta;
                        particle->velocity.x = (float)cos(angle) * 82.0f;
                        particle->velocity.y = (float)sin(angle) * 82.0f;
#endif
                    } else if (style_id == 8) {
                        int turn = crt_rand() % 100 - 50;
                        float turn_delta = (float)turn * 0.06f;
                        turn_delta *= particle->intensity;
                        turn_delta *= frame_dt;
                        turn_delta *= 1.1f;
#if CL_BUILD == 10908
                        particle->angle -= turn_delta;
                        particle->velocity.x = (float)cos(particle->angle) * 62.0f;
                        particle->velocity.y = (float)sin(particle->angle) * 62.0f;
#else
                        angle -= turn_delta;
                        particle->velocity.x = (float)cos(angle) * 62.0f;
                        particle->velocity.y = (float)sin(angle) * 62.0f;
#endif
                    } else {
                        int turn = crt_rand() % 100 - 50;
                        float turn_delta = (float)turn * 0.06f;
                        turn_delta *= particle->intensity;
                        turn_delta *= frame_dt;
                        turn_delta *= 1.1f;
#if CL_BUILD == 10908
                        particle->angle -= turn_delta;
                        particle->velocity.x = (float)cos(particle->angle) * 82.0f;
                        particle->velocity.y = (float)sin(particle->angle) * 82.0f;
#else
                        angle -= turn_delta;
                        particle->velocity.x = (float)cos(angle) * 82.0f;
                        particle->velocity.y = (float)sin(angle) * 82.0f;
#endif
                    }
                }
                particle->color_a = particle->intensity > 1.0f ? 1.0f : particle->intensity;
#if CL_BUILD == 10908
                // 1.9.8 writes the color fields directly.
                particle->color_r = 1.0f - particle->intensity * 0.95f;
                particle->color_g = particle->color_r;
#else
                float& color_r = particle->color_r;
                float& color_g = particle->color_g;
                color_r = 1.0f - particle->intensity * 0.95f;
                color_g = color_r;
#endif

                if (particle->in_flight) {
                    projectile_vec2_t& particle_position = *(projectile_vec2_t*)&particle->position;
                    int hit_id = creature_find_in_radius(
                        &particle->position, particle->intensity * 8.0f, 0);
                    if (hit_id != -1) {
#if CL_BUILD == 10908
                        // 1.9.8 writes the field directly.
                        particle->in_flight = 0;
#else
                        unsigned char& in_flight = particle->in_flight;
                        in_flight = 0;
#endif
#if CL_BUILD == 10908
                        // 1.9.8 stops the particle and records the target before it snaps to the creature.
                        if (particle->style_id == 8) {
                            particle_velocity.x = 0.0f;
                            particle_velocity.y = 0.0f;
                            particle->target_id = hit_id;
                            particle_position
                                = *(projectile_vec2_t*)&creature_pool[hit_id].position;
                            creature_pool[hit_id].state_flag = 0;
#else
                        if (particle->style_id == 8) {
                            particle_position
                                = *(projectile_vec2_t*)&creature_pool[hit_id].position;
                            particle_velocity.x = 0.0f;
                            particle_velocity.y = 0.0f;
                            creature_pool[hit_id].state_flag = 0;
                            particle->target_id = hit_id;
#endif
                        } else {
                            while (particle->angle > 6.2831855f) {
                                particle->angle -= 6.2831855f;
                            }
                            while (particle->angle < 0.0f) {
                                particle->angle += 6.2831855f;
                            }

                            projectile_vec2_t displacement = frame_dt * particle_velocity;
                            projectile_vec2_t previous_position(
                                particle_position.x - displacement.x,
                                particle->position.y - displacement.y);
                            projectile_vec2_t& hit_position
                                = *(projectile_vec2_t*)&creature_pool[hit_id].position;
                            projectile_vec2_t hit_direction = previous_position - hit_position;
                            float hit_angle = projectile_vec2_angle(hit_direction);
                            while (hit_angle > 6.2831855f) {
                                hit_angle -= 6.2831855f;
                            }
                            while (hit_angle < 0.0f) {
                                hit_angle += 6.2831855f;
                            }

                            if (hit_angle < particle->angle) {
                                particle->angle -= 1.2566371f;
                            } else {
                                particle->angle += 1.2566371f;
                            }
                            particle->velocity.x = (float)cos(particle->angle) * 82.0f;
                            particle->velocity.y = (float)sin(particle->angle) * 82.0f;
                            float speed_scale = (float)(crt_rand() % 10) * 0.1f;
                            particle->velocity.x *= speed_scale;
                            particle->velocity.y *= speed_scale;
                            creature_pool[hit_id].state_flag = 1;
                            vec2f_t impulse = { 0.0f, 0.0f };
                            creature_apply_damage(hit_id, particle->intensity * 10.0f, 4, &impulse);

                            creature_t* hit_creature = &creature_pool[hit_id];
                            float tint_green = hit_creature->tint_g;
                            if (tint_green + hit_creature->tint_r + hit_creature->tint_b
                                > 1.6f) {
                                float tint_scale = 1.0f - particle->intensity * 0.01f;
                                hit_creature->tint_r *= tint_scale;
                                hit_creature->tint_g *= tint_scale;
                                hit_creature->tint_b *= tint_scale;

                                projectile_clamp_tint(&hit_creature->tint_r);
                                projectile_clamp_tint(&hit_creature->tint_g);
                                projectile_clamp_tint(&hit_creature->tint_b);
                                projectile_clamp_tint(&hit_creature->tint_a);
                            }

                            if (projectile_index % 3 == 0) {
#if CL_BUILD == 10908
                                // 1.9.8 fills the jitter fields one by one instead of constructing it.
                                projectile_vec2_t velocity;
                                velocity.x = (float)(crt_rand() % 60 - 30);
                                velocity.y = (float)(crt_rand() % 60 - 30);
#else
                                int velocity_x = crt_rand() % 60 - 30;
                                projectile_vec2_t velocity(
                                    (float)velocity_x, (float)(crt_rand() % 60 - 30));
#endif
                                int effect_id = fx_spawn_sprite(
                                    (vec2f_t*)&hit_position, (vec2f_t*)&velocity, 13.0f);
                                sprite_effect_pool[effect_id].color_a = 0.7f;
                            }
                            fx_queue_add_random((vec2f_t*)&hit_position);
                            projectile_vec2_t reflected_velocity(
                                particle->velocity.x, particle->velocity.y);
                            float displacement_dt = frame_dt;
                            projectile_vec2_t creature_displacement
                                = reflected_velocity * displacement_dt;
                            hit_position += creature_displacement;
                        }
                    }
                }
            }
        }
    }
}
