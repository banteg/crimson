#include "freeware_edition.h"
#if FREEWARE_EDITION == 10002
#include "projectile_update_102.inc"
#else
// crimson.exe 1.3.0 at 0x406260 and 1.4.0 at 0x4094e0. All four passes share the CRT random stream.
#include "../effects/freeware_ice_mark.h"
#include "../ui/freeware_ui.h"
#include "crimsonland_types.h"
#include "freeware_level.h"
#include <math.h>
extern "C" {
extern projectile_pool_t projectile_pool;
extern secondary_projectile_pool_t secondary_projectile_pool;
extern particle_t particle_pool[128];
extern sprite_effect_t sprite_effect_pool[384];
extern creature_t creature_pool[512];
extern int freeware_arena_width, freeware_arena_height, perk_id_bloody_mess;
int projectile_spawn(const vec2f_t *, float, int);
extern float frame_dt, freeware_simulation_clock, bonus_fire_bullets_timer, bonus_freeze_timer;
extern float freeware_hit_sound_timer;
extern int highscore_record_hits, creature_spawned_count, current_player_index;
extern game_mode_id_t config_game_mode;
int crt_rand();
int creature_find_in_radius(const vec2f_t *, float);
int creature_find_nearest(const vec2f_t *);
int fx_spawn_sprite(const vec2f_t *, const vec2f_t *, float);
int fx_spawn_particle(const vec2f_t *, float, const vec2f_t *, float);
#if CL_BUILD == 10300
void creature_handle_death(int slot, int player);
#else
void creature_handle_death(int slot, int player, unsigned char leave_corpse);
#endif
#ifndef CRIMSON_FREEWARE_CLIENT
int sfx_play_panned(int, float, float);
#if CL_BUILD == 10300
extern int freeware_music_channel_b;
void freeware_game_track_start(int);
#else
void freeware_music_start(int);
#endif
#endif
void fx_queue_add_random(const vec2f_t *);
void freeware_combat_sound(int sample, float volume);
}

// VC6 emitted all four pool walks and their arithmetic inside this one native body.
#ifndef _MSC_VER
#define __forceinline inline
#endif
namespace {
__forceinline void impact_death(int id, int owner, unsigned char leave_corpse) {
#if CL_BUILD == 10300
    creature_handle_death(id, owner);
#else
    creature_handle_death(id, owner, leave_corpse);
#endif
}
__forceinline bool combat_music_active() {
#if CL_BUILD == 10300 && !defined(CRIMSON_FREEWARE_CLIENT)
    return freeware_music_channel_b != -1;
#else
    return freeware_hit_sound_timer > 0;
#endif
}
__forceinline void start_combat_music() {
#ifdef CRIMSON_FREEWARE_CLIENT
    freeware_combat_sound(31, 1);
#elif CL_BUILD == 10300
    freeware_game_track_start(31);
#else
    freeware_music_start(31);
#endif
}
__forceinline void impact_sound(int sample, float volume) {
#ifdef CRIMSON_FREEWARE_CLIENT
    freeware_combat_sound(sample, volume);
#else
    sfx_play_panned(sample, volume, .5f);
#endif
}
const float half_pi = 1.57079637f;

struct SprayPoint : vec2f_t {
    __forceinline SprayPoint(const float &px, const float &py) {
        x = px;
        y = py;
    }
    __forceinline float length() const { return (float)sqrt(x * x + y * y); }
};
__forceinline SprayPoint spray_position(const vec2f_t &offset, const vec2f_t &center) {
    return SprayPoint(offset.x + center.x, offset.y + center.y);
}
__forceinline void spray_blood(const vec2f_t &position) { fx_queue_add_random(&position); }
__forceinline void spray_ice(const vec2f_t &position, float size) { freeware_shard(&position, size); }
__forceinline void primary_hit_sound(bool lethal) {
#ifdef CRIMSON_FREEWARE_CLIENT
    freeware_combat_sound(lethal ? crt_rand() % 4 + 3 : crt_rand() % 2, .45f);
#else
    if (lethal)
        sfx_play_panned(crt_rand() % 4 + 3, .45f, .5f);
    else
        sfx_play_panned(crt_rand() % 2, .45f, .5f);
#endif
}
__forceinline void impact_marks(projectile_t &shot, int id) {
    float jitter = (float)(crt_rand() % 20 - 10) * .1f;
    float angle = (shot.angle - half_pi) + jitter;
    float x = (float)cos(angle) * 20.f, y = (float)sin(angle) * 20.f;
    if (shot.fields.type_id != 7 && shot.fields.type_id != 10) {
        if (bonus_freeze_timer > 0.f) {
            float size = (float)(crt_rand() % 10 + 5);
            spray_ice(creature_pool[id].position, size);
            size = (float)(crt_rand() % 10 + 5);
            spray_ice(spray_position(SprayPoint(x * 1.5f, y * 1.5f), creature_pool[id].position), size);
            size = (float)(crt_rand() % 10 + 5);
            spray_ice(spray_position(SprayPoint(x * 2.f, y * 2.f), creature_pool[id].position), size);
        } else {
            spray_blood(creature_pool[id].position);
            spray_blood(spray_position(SprayPoint(x * 1.5f, y * 1.5f), creature_pool[id].position));
            spray_blood(spray_position(SprayPoint(x * 2.f, y * 2.f), creature_pool[id].position));
            spray_blood(spray_position(SprayPoint(x * 2.5f, y * 2.5f), creature_pool[id].position));
        }
    }
    if (shot.fields.type_id == 10) {
        float factor = (float)(crt_rand() % 100) * .1f;
        if (factor > 4.f)
            factor = (float)(crt_rand() % 90 + 10) * .1f;
        if (factor > 7.f)
            factor = (float)(crt_rand() % 80 + 20) * .1f;
        float direction = shot.angle - half_pi;
        x = (float)cos(direction) * factor * 20.f;
        y = (float)sin(direction) * factor * 20.f;
        SprayPoint delta(x, y);
        SprayPoint probe = spray_position(delta, creature_pool[id].position), still(0.f, 0.f);
        if (freeware_current_map->move_with_collision(&probe, &still, 2.f) == 0) {
            float size = (float)(crt_rand() % 10 + 5);
            if (bonus_freeze_timer > 0.f)
                spray_ice(spray_position(delta, creature_pool[id].position), size);
            spray_blood(spray_position(delta, creature_pool[id].position));
        }
    }
}
__forceinline void hit(projectile_t &shot, int id, const vec2f_t *position, float &shard_radius) {
    if (creature_pool[id].death_timer == 16)
        ++highscore_record_hits;
    if (UI_PLAYER(current_player_index).perks[perk_id_bloody_mess] > 0) {
        for (int upper = 30, lower = -30; lower > -60; lower -= 10, upper += 10) {
            vec2f_t scatter;
            scatter.x = (float)(crt_rand() % (upper - lower) + lower);
            scatter.y = (float)(crt_rand() % (upper - lower) + lower);
            spray_blood(spray_position(scatter, creature_pool[id].position));
        }
    }
    if (bonus_fire_bullets_timer <= 0 && shot.fields.type_id != 10)
        shot.fields.life_timer = .25f;
    SprayPoint span(shot.fields.origin.x - position->x, shot.fields.origin.y - position->y);
    float range = span.length();
    if (range < 50)
        range = 50;
    float damage = 100.f / range * 30.f + 10.f;
    int type = shot.fields.type_id;
    if (type == 2)
        damage *= 1.2f;
    else if (type == 4)
        damage *= 4.1f;
    else if (type == 7)
        damage *= 5;
    else if (type == 9)
        damage *= 2;
    else if (type == 17) {
        creature_pool[id].plague_infected = 1;
        damage = 0;
    }
    float &pool = shot.fields.damage_pool;
    if (creature_pool[id].health > 0) {
        float power = pool - 1.f;
        pool = power;
        if (power > 0.f) {
            creature_pool[id].health -= power;
            // The remaining damage uses the creature's health after the hit.
            pool = power - creature_pool[id].health;
        } else {
            creature_pool[id].health -= damage * .95f;
            if (shot.fields.life_timer != .25f)
                shot.fields.life_timer = .25f;
        }
    }
    if (pool == 1) {
        pool = 0;
        if (shot.fields.life_timer != .25f)
            shot.fields.life_timer = .25f;
    }
    creature_pool[id].ai_mode = 1;
    impact_marks(shot, id);
    if (combat_music_active() || config_game_mode == 2)
        primary_hit_sound(false);
    else
        start_combat_music();
    if (creature_pool[id].health <= 0) {
        if (creature_pool[id].death_timer == 16) {
            if (bonus_freeze_timer > 0) {
                for (int remaining = 6; remaining > 0; --remaining) {
                    float size = (float)(crt_rand() % 10 + 5);
                    float angle = (float)(crt_rand() % 628) * .01f;
                    shard_radius = (float)(crt_rand() % 35);
                    SprayPoint spread((float)cos(angle) * shard_radius, (float)sin(angle) * shard_radius);
                    spray_ice(spray_position(spread, creature_pool[id].position), size);
                }
            }
            primary_hit_sound(true);
            impact_death(id, current_player_index, 1);
        }
        --creature_spawned_count;
        creature_pool[id].death_timer -= frame_dt * 20;
    }
}
__forceinline void spawn_ricochet(const vec2f_t &position, const projectile_t &shot, float dx, float dy) {
    vec2f_t offset = {dx * shot.fields.speed_scale, dy * shot.fields.speed_scale};
    SprayPoint start(position.x - offset.x, position.y - offset.y);
    projectile_spawn(&start, shot.angle - half_pi, 1);
}
__forceinline void bullets(float &shard_radius) {
    for (int i = 0; i < 64; ++i) {
        if (!projectile_pool[i].active)
            continue;
        if (projectile_pool[i].fields.life_timer <= 0)
            projectile_pool[i].active = 0;
        if (projectile_pool[i].fields.life_timer < .4f) {
            if (projectile_pool[i].fields.type_id == 10)
                projectile_pool[i].fields.life_timer -= frame_dt * .1f;
            else
                projectile_pool[i].fields.life_timer -= frame_dt;
            continue;
        }
        vec2f_t *position = &projectile_pool[i].position;
        if (position->x < -10 || projectile_pool[i].position.y < -10 || position->x > freeware_arena_width + 10 ||
            projectile_pool[i].position.y > freeware_arena_height + 10) {
            projectile_pool[i].fields.life_timer -= frame_dt;
            continue;
        }
        float dx, dy;
#if FREEWARE_EDITION != 10400
        dx = (float)cos(projectile_pool[i].angle - half_pi) * frame_dt * 20.f;
        dy = (float)sin(projectile_pool[i].angle - half_pi) * frame_dt * 20.f;
#endif
        int steps = 50;
        if (projectile_pool[i].fields.type_id == 2)
            steps = 60;
        if (projectile_pool[i].fields.type_id == 4)
            steps = 55;
        if (projectile_pool[i].fields.type_id == freeware_rules::plasma_round)
            steps = 30;
        if (projectile_pool[i].fields.type_id == freeware_rules::plasma_minigun_round)
            steps = 35;
        if (projectile_pool[i].fields.type_id == 10)
            steps = 215;
#if FREEWARE_EDITION == 10400
        if (projectile_pool[i].fields.type_id == 17)
            steps = 15;
        if (projectile_pool[i].fields.type_id == 18) {
            float angle = projectile_pool[i].angle - half_pi + (float)sin(freeware_simulation_clock * 4.f + i);
            dx = (float)cos(angle) * frame_dt * 10.f;
            dy = (float)sin(angle) * frame_dt * 10.f;
            steps = 10;
        } else {
            float angle = projectile_pool[i].angle - half_pi;
            dx = (float)cos(angle) * frame_dt * 20.f;
            dy = (float)sin(angle) * frame_dt * 20.f;
        }
#endif
        if (projectile_pool[i].fields.type_id != 3) {
            for (int step = 0; step < steps; ++step) {
                vec2f_t delta = {dx * projectile_pool[i].fields.speed_scale,
                                 dy * projectile_pool[i].fields.speed_scale};
                int wall = freeware_current_map->move_with_collision(position, &delta, 0.f);
                if (!wall) {
                    int id;
                    if (FREEWARE_EDITION == 10400 && projectile_pool[i].fields.type_id == 18)
                        id = creature_find_in_radius(position, 16.f);
                    else
                        id = creature_find_in_radius(position, 0.f);
                    if (id != -1) {
                        hit(projectile_pool[i], id, position, shard_radius);
                        if (projectile_pool[i].fields.damage_pool <= 0)
                            break;
                    }
                } else {
                    if (crt_rand() % 15 == 2) {
                        // Both executables construct a separate spawn position for each wall side.
                        if (wall == 1) {
                            spawn_ricochet(*position, projectile_pool[i], dx, dy);
                        } else if (wall == 2) {
                            spawn_ricochet(*position, projectile_pool[i], dx, dy);
                        } else {
                            spawn_ricochet(*position, projectile_pool[i], dx, dy);
                        }
                    }
                    projectile_pool[i].fields.life_timer = .25f;
                    break;
                }
            }
        } else {
            projectile_pool[i].pos_x += dx * 10;
            projectile_pool[i].position.y += dy * 10;
            projectile_pool[i].fields.reserved -= frame_dt;
            if (projectile_pool[i].fields.reserved < 0) {
                projectile_pool[i].fields.type_id = (projectile_type_id_t)0;
                for (int j = 0; j < 40; ++j) {
                    vec2f_t zero = {0, 0};
                    fx_spawn_particle(&projectile_pool[i].position, (crt_rand() % 628) * .01f, &zero, .8f);
                }
            }
        }
    }
}

#ifdef CRIMSON_FREEWARE_CLIENT
#define ROCKET_GLOW_TEXTURE ui140::texture("glow")
#else
#define ROCKET_GLOW_TEXTURE grim_interface_ptr->grim_get_texture_handle((char *)"glow")
#endif
__forceinline SprayPoint operator+(const vec2f_t &a, const vec2f_t &b) { return SprayPoint(a.x + b.x, a.y + b.y); }
__forceinline SprayPoint operator-(const vec2f_t &a, const vec2f_t &b) { return SprayPoint(a.x - b.x, a.y - b.y); }
__forceinline SprayPoint operator*(const vec2f_t &a, const float &scale) {
    return SprayPoint(a.x * scale, a.y * scale);
}
__forceinline float rocket_length(const vec2f_t &v) {
#if FREEWARE_EDITION == 10300
    return (float)sqrt(v.x * v.x + v.y * v.y);
#else
    float squared_y = v.y * v.y;
    float length = (float)sqrt(squared_y + v.x * v.x);
    return length;
#endif
}
__forceinline float rocket_distance(const vec2f_t &a, const vec2f_t &b) {
    float dx = a.x - b.x, dy = a.y - b.y;
    float squared_x = dx * dx;
    float distance = (float)sqrt(squared_x + dy * dy);
    return distance;
}
__forceinline float rocket_abs(float value) {
#if FREEWARE_EDITION == 10300 || defined(CRIMSON_FREEWARE_CLIENT)
    return (float)fabs(value);
#else
    int bits = (*(int *)&value) & 0x7fffffff;
    return *(float *)&bits;
#endif
}
__forceinline SprayPoint scaled_rocket(float amount, const SprayPoint &v) {
    float x = amount;
    x *= v.x;
    return SprayPoint(x, v.y * amount);
}
__forceinline void rocket_sparks(const vec2f_t *position) {
    for (int i = 0; i < 10; ++i) {
        float speed = (crt_rand() % 800) * .1f;
        float angle = i * .62831855f;
        SprayPoint velocity = scaled_rocket(speed, SprayPoint((float)cos(angle), (float)sin(angle)));
        int effect = fx_spawn_sprite(position, &velocity, 14.f);
        sprite_effect_pool[effect].color_a = .37f;
    }
}
// On a frozen impact the blast reuses the final polar offset from the three initial
// ice marks. The original still advances the random stream twice before choosing
// the size and rotation of each of the ten later marks.
__forceinline void rocket_burst_marks(int hit, const float &shard_angle, const float &shard_radius, int mark_count,
                                      int mark_radius) {
    if (bonus_freeze_timer > 0.f) {
        for (int k = 0; k < 10; ++k) {
            crt_rand();
            crt_rand();
            float size = (float)(crt_rand() % 10 + 5);
            SprayPoint frozen_offset((float)cos(shard_angle) * shard_radius,
                                     (float)sin(shard_angle) * shard_radius);
            SprayPoint p = creature_pool[hit].position + frozen_offset;
            freeware_shard(&p, size);
        }
    } else {
        for (int k = 0; k < mark_count; ++k) {
            float shard_angle = (float)(crt_rand() % 628) * .01f;
            float shard_radius = (float)(crt_rand() % mark_radius);
            SprayPoint offset((float)cos(shard_angle) * shard_radius, (float)sin(shard_angle) * shard_radius);
            SprayPoint p = offset + creature_pool[hit].position;
            fx_queue_add_random(&p);
        }
    }
}
__forceinline void rockets(float &shard_radius) {
    for (int i = 0; i < 64; ++i) {
        float &heading = secondary_projectile_pool[i].angle;
        if (!secondary_projectile_pool[i].active)
            continue;
        if (secondary_projectile_pool[i].fields.type_id == SECONDARY_PROJECTILE_TYPE_EXPLODING) {
            secondary_projectile_pool[i].fields.vel_x += frame_dt * 3.f;
            if (secondary_projectile_pool[i].fields.vel_x > 1.f) {
                float size = secondary_projectile_pool[i].fields.vel_y * 256.f;
                effect_color_t black = {0, 0, 0, .25f};
                fx_queue_add(ROCKET_GLOW_TEXTURE, &secondary_projectile_pool[i].position, size, size, 0.f, black);
                secondary_projectile_pool[i].active = 0;
            }
            float radius =
                secondary_projectile_pool[i].fields.vel_y * secondary_projectile_pool[i].fields.vel_x * 80.f;
            for (int j = 0; j < 512; ++j) {
                creature_t &c = creature_pool[j];
                if (c.active && c.health > 0.f) {
                    float distance = rocket_distance(c.position, secondary_projectile_pool[i].position);
                    if (distance < radius) {
                        c.health -= frame_dt * secondary_projectile_pool[i].fields.vel_y * 700.f;
                        if (c.health <= 0.f) {
                            fx_queue_add_random(&c.position);
                            impact_death(j, current_player_index, 1);
                        }
                    }
                }
            }
            continue;
        }
        vec2f_t &position = secondary_projectile_pool[i].position;
        float speed = frame_dt;
        SprayPoint delta(secondary_projectile_pool[i].fields.velocity.x * speed,
                         secondary_projectile_pool[i].fields.velocity.y * speed);
        if (freeware_current_map->move_with_collision(&position, &delta, 4.f)) {
            int type = secondary_projectile_pool[i].fields.type_id;
            secondary_projectile_pool[i].fields.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
            secondary_projectile_pool[i].fields.vel_x = 0.f;
            if (type == SECONDARY_PROJECTILE_TYPE_ROCKET)
                secondary_projectile_pool[i].fields.vel_y = 1.f;
            else
                secondary_projectile_pool[i].fields.vel_y = .5f;
        }
        if (secondary_projectile_pool[i].fields.type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
            float scale = frame_dt * 3.f + 1.f;
            secondary_projectile_pool[i].fields.vel_x *= scale;
            secondary_projectile_pool[i].fields.vel_y *= scale;
            secondary_projectile_pool[i].life_timer -= frame_dt;
        } else if (secondary_projectile_pool[i].fields.type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
            if (!creature_pool[secondary_projectile_pool[i].fields.target_id].active)
                secondary_projectile_pool[i].fields.target_id = creature_find_nearest(&position);
            const vec2f_t &target = creature_pool[secondary_projectile_pool[i].fields.target_id].position;
            SprayPoint dir = position - target;
            heading = (float)atan2(dir.y, dir.x) - half_pi;
            secondary_projectile_pool[i].fields.vel_x += (float)cos(heading - half_pi) * frame_dt * 800.f;
            secondary_projectile_pool[i].fields.vel_y += (float)sin(heading - half_pi) * frame_dt * 800.f;
            if (rocket_length(secondary_projectile_pool[i].fields.velocity) > 350.f) {
                secondary_projectile_pool[i].fields.vel_x -= (float)cos(heading - half_pi) * frame_dt * 800.f;
                secondary_projectile_pool[i].fields.vel_y -= (float)sin(heading - half_pi) * frame_dt * 800.f;
            }
            secondary_projectile_pool[i].life_timer -= frame_dt * .5f;
        }
        secondary_projectile_pool[i].fields.trail_distance -=
            (rocket_abs(secondary_projectile_pool[i].fields.vel_x) +
             rocket_abs(secondary_projectile_pool[i].fields.vel_y)) *
            frame_dt * .01f;
        if (secondary_projectile_pool[i].fields.trail_distance < 0.f) {
            SprayPoint vel =
                SprayPoint((float)cos(heading + 1.57079637f), (float)cos(heading + 1.57079637f)) * 90.f;
            float angle = heading - half_pi;
            SprayPoint pos = position - SprayPoint((float)cos(angle), (float)sin(angle)) * 9.f;
            int id = fx_spawn_sprite(&pos, &vel, 14.f);
            secondary_projectile_pool[i].fields.trail_distance = .05f;
            sprite_effect_pool[id].color_a = .3f;
        }
        int hit = creature_find_in_radius(&secondary_projectile_pool[i].position, 8.f);
        if (hit != -1) {
            if (creature_pool[hit].death_timer == 16.f)
                ++highscore_record_hits;
            float shard_angle;
            if (bonus_freeze_timer > 0.f) {
                for (int j = 0; j < 3; ++j) {
                    float size = (float)(crt_rand() % 10 + 5);
                    shard_angle = (float)(crt_rand() % 628) * .01f;
                    shard_radius = (float)(crt_rand() % 35);
                    SprayPoint offset((float)cos(shard_angle) * shard_radius,
                                      (float)sin(shard_angle) * shard_radius);
                    SprayPoint pos = offset + creature_pool[hit].position;
                    freeware_shard(&pos, size);
                }
            } else {
                vec2f_t spread;
                spread.x = (float)(crt_rand() % 20 - 10);
                spread.y = (float)(crt_rand() % 20 - 10);
                SprayPoint pos = spread + creature_pool[hit].position;
                fx_queue_add_random(&pos);
            }
            float damage = 150.f;
            if (secondary_projectile_pool[i].fields.type_id == SECONDARY_PROJECTILE_TYPE_ROCKET)
                damage = secondary_projectile_pool[i].life_timer * 50.f + 500.f;
            else if (secondary_projectile_pool[i].fields.type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET)
                damage = secondary_projectile_pool[i].life_timer * 50.f + 100.f;
            if (!combat_music_active())
                start_combat_music();
            else
                impact_sound(21, .45f);
            creature_pool[hit].health -= damage;
            creature_pool[hit].ai_mode = 1;
            if (creature_pool[hit].health <= 0.f) {
                if (creature_pool[hit].death_timer == 16.f)
                    impact_death(hit, current_player_index, 1);
                creature_pool[hit].death_timer -= frame_dt * 10.f;
            }
            if (secondary_projectile_pool[i].fields.type_id == SECONDARY_PROJECTILE_TYPE_ROCKET) {
                secondary_projectile_pool[i].fields.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
                secondary_projectile_pool[i].fields.vel_x = 0.f;
                secondary_projectile_pool[i].fields.vel_y = 1.f;
                rocket_burst_marks(hit, shard_angle, shard_radius, 20, 90);

            } else if (secondary_projectile_pool[i].fields.type_id == SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET) {
                secondary_projectile_pool[i].fields.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
                secondary_projectile_pool[i].fields.vel_x = 0.f;
                secondary_projectile_pool[i].fields.vel_y = .5f;
                rocket_burst_marks(hit, shard_angle, shard_radius, 10, 64);
            }
            rocket_sparks(&secondary_projectile_pool[i].position);
        }
        if (secondary_projectile_pool[i].life_timer <= 0.f) {
            rocket_sparks(&secondary_projectile_pool[i].position);
            secondary_projectile_pool[i].active = 0;
        }
    }
}

#undef ROCKET_GLOW_TEXTURE
#ifdef CRIMSON_FREEWARE_CLIENT
#define PARTICLE_SOUND(sample, volume) freeware_combat_sound(sample, volume)
#else
#define PARTICLE_SOUND(sample, volume) sfx_play_panned(sample, volume, .5f)
#endif
struct ParticlePoint : vec2f_t {
    __forceinline ParticlePoint(float px, float py) {
        x = px;
        y = py;
    }
};
__forceinline ParticlePoint scale_particle_vector(const vec2f_t &v, float amount) {
    return ParticlePoint(amount * v.x, amount * v.y);
}
__forceinline void add_particle_vector(vec2f_t &dst, const vec2f_t &delta) {
    dst.x += delta.x;
    dst.y += delta.y;
}
__forceinline void clamp_color(float &value) {
    if (value < 0.f)
        value = 0.f;
    else if (value > 1.f)
        value = 1.f;
}
__forceinline void turn_particle(int i, float factor) {
    int turn = crt_rand() % 100 - 50;
    float deviation = (float)turn * .06f;
    deviation *= frame_dt;
    deviation *= particle_pool[i].intensity;
    deviation *= factor;
    particle_pool[i].angle -= deviation;
}
__forceinline void particle_heading_velocity(int i, float speed) {
    particle_pool[i].vel_x = (float)cos(particle_pool[i].angle) * speed;
    particle_pool[i].vel_y = (float)sin(particle_pool[i].angle) * speed;
}
__forceinline void particles() {
    const float tau = 6.28318548f;
    for (int i = 0; i < 128; ++i) {
        if (!particle_pool[i].active)
            continue;
#if FREEWARE_EDITION != 10300
        if (particle_pool[i].style_id == 8) {
            particle_pool[i].intensity -= frame_dt * .11f;
            particle_pool[i].rotation += frame_dt * 5.f;
            if (particle_pool[i].in_flight) {
                if (particle_pool[i].intensity > .15f) {
                    ParticlePoint delta = scale_particle_vector(
                        scale_particle_vector(particle_pool[i].velocity, frame_dt), particle_pool[i].intensity);
                    freeware_current_map->move_with_collision(&particle_pool[i].position, &delta, 3.f);
                } else {
                    add_particle_vector(particle_pool[i].position, scale_particle_vector(
                        scale_particle_vector(scale_particle_vector(particle_pool[i].velocity, frame_dt), .55f),
                        particle_pool[i].intensity));
                }
            }
        } else
#endif
        {
            particle_pool[i].intensity -= frame_dt * .9f;
#if FREEWARE_EDITION == 10300
            if (particle_pool[i].style_id == 0) {
                if (particle_pool[i].intensity <= 0.f) {
                    particle_pool[i].active = 0;
                    continue;
                }
            } else if (particle_pool[i].intensity <= .8f) {
                particle_pool[i].active = 0;
                continue;
            }
#else
            particle_pool[i].rotation += frame_dt;
#endif
            if (particle_pool[i].intensity > .15f) {
                ParticlePoint delta = scale_particle_vector(
                    scale_particle_vector(scale_particle_vector(particle_pool[i].velocity, frame_dt), 2.5f),
                    particle_pool[i].intensity);
                freeware_current_map->move_with_collision(&particle_pool[i].position, &delta, 3.f);
            } else {
                add_particle_vector(particle_pool[i].position, scale_particle_vector(
                    scale_particle_vector(scale_particle_vector(particle_pool[i].velocity, frame_dt), 2.5f), .15f));
            }
        }
#if FREEWARE_EDITION != 10300
        if (particle_pool[i].style_id == 0) {
            if (particle_pool[i].intensity <= 0.f) {
                particle_pool[i].active = 0;
                continue;
            }
        } else if (particle_pool[i].intensity <= .8f) {
            particle_pool[i].active = 0;
            if (particle_pool[i].style_id == 8) {
                if (particle_pool[i].target_id != -1) {
                    if (creature_pool[particle_pool[i].target_id].active)
                        PARTICLE_SOUND(crt_rand() % 4 + 3, .45f);
                    impact_death(particle_pool[i].target_id, 0, 0);
                }
                PARTICLE_SOUND(27, (crt_rand() % 70) * .1f + .3f);
            }
            continue;
        }
#endif
        if (particle_pool[i].in_flight == 1) {
            if (particle_pool[i].style_id == 0) {
                turn_particle(i, 1.96f);
                if (FREEWARE_EDITION != 10300)
                    particle_heading_velocity(i, 82.f);
            } else if (FREEWARE_EDITION != 10300 && particle_pool[i].style_id == 8) {
                turn_particle(i, 1.1f);
                particle_heading_velocity(i, 62.f);
            } else {
                turn_particle(i, 1.1f);
                if (FREEWARE_EDITION != 10300)
                    particle_heading_velocity(i, 82.f);
            }
            if (FREEWARE_EDITION == 10300)
                particle_heading_velocity(i, 82.f);
        }
        particle_pool[i].color_a = particle_pool[i].intensity > 1.f ? 1.f : particle_pool[i].intensity;
        particle_pool[i].color_g = particle_pool[i].color_r = 1.f - particle_pool[i].intensity * .95f;
#if FREEWARE_EDITION == 10300
        particle_pool[i].rotation += frame_dt;
#endif
        if (!particle_pool[i].in_flight)
            continue;
        const vec2f_t &contact = particle_pool[i].position;
        int id = creature_find_in_radius(&contact, particle_pool[i].intensity * 8.f);
        if (id == -1)
            continue;
        particle_pool[i].in_flight = 0;

#if FREEWARE_EDITION != 10300
        if (particle_pool[i].style_id == 8) {
            particle_pool[i].position = creature_pool[id].position;
            creature_pool[id].ai_mode = 0;
            particle_pool[i].vel_x = 0.f;
            particle_pool[i].vel_y = 0.f;
            creature_pool[id].activation_radius = 0.f;
            particle_pool[i].target_id = id;
            continue;
        }
#endif
        while (particle_pool[i].angle > tau)
            particle_pool[i].angle -= tau;
        while (particle_pool[i].angle < 0)
            particle_pool[i].angle += tau;
        vec2f_t displacement = scale_particle_vector(particle_pool[i].velocity, frame_dt);
        ParticlePoint previous(contact.x - displacement.x, particle_pool[i].position.y - displacement.y);
        const vec2f_t &hit_position = creature_pool[id].position;
        ParticlePoint direction(previous.x - hit_position.x, previous.y - hit_position.y);
        float bearing = (float)atan2(direction.y, direction.x);
        while (bearing > tau)
            bearing -= tau;
        while (bearing < 0)
            bearing += tau;
        if (bearing < particle_pool[i].angle)
            particle_pool[i].angle -= 1.2566371f;
        else
            particle_pool[i].angle += 1.2566371f;
        particle_heading_velocity(i, 82.f);
        float speed = (crt_rand() % 10) * .1f;
        particle_pool[i].vel_x *= speed;
        particle_pool[i].vel_y *= speed;
        creature_pool[id].health -= particle_pool[i].intensity * 10.f;
        creature_pool[id].ai_mode = 1;

        float brightness = creature_pool[id].freeware.color.b;
        brightness += creature_pool[id].freeware.color.r;
        brightness += creature_pool[id].freeware.color.g;
        if (brightness > .6f) {
            float scale = 1.f - particle_pool[i].intensity * .18f;
            creature_pool[id].freeware.color.r *= scale;
            creature_pool[id].freeware.color.g *= scale;
            creature_pool[id].freeware.color.b *= scale;
            clamp_color(creature_pool[id].freeware.color.r);
            clamp_color(creature_pool[id].freeware.color.g);
            clamp_color(creature_pool[id].freeware.color.b);
            clamp_color(creature_pool[id].freeware.color.a);
        }
        if (i % 3 == 0) {
            int x = crt_rand() % 60 - 30;
            int y = crt_rand() % 60 - 30;
            SprayPoint velocity((float)x, (float)y);
            sprite_effect_pool[fx_spawn_sprite(&creature_pool[id].position, &velocity, 13.f)].color_a = .7f;
        }
        fx_queue_add_random(&creature_pool[id].position);
        ParticlePoint recoil(particle_pool[i].vel_x, particle_pool[i].vel_y);
        float delta_time = frame_dt;
        ParticlePoint delta = scale_particle_vector(recoil, delta_time);
        add_particle_vector(creature_pool[id].position, delta);
        if (creature_pool[id].health <= 0.f) {
            if (creature_pool[id].death_timer == 16.f) {
                impact_death(id, current_player_index, 1);
                PARTICLE_SOUND(crt_rand() % 4 + 3, .45f);
            }
            --creature_spawned_count;
            creature_pool[id].death_timer -= frame_dt * 20.f;
        }
    }
}
#undef PARTICLE_SOUND
} // namespace
extern "C" void projectile_update() {
    float shard_radius;
    bullets(shard_radius);
    rockets(shard_radius);
    for (int i = 0; i < (FREEWARE_EDITION == 10300 ? 256 : 384); ++i) {
        sprite_effect_t &s = sprite_effect_pool[i];
        if (!s.active)
            continue;
        add_particle_vector(s.position, scale_particle_vector(s.velocity, frame_dt));
        s.rotation += frame_dt * 3.f;
        s.color_a -= frame_dt;
        if (s.color_a <= 0.f)
            s.active = 0;
        s.scale += frame_dt * 60.f;
    }
    particles();
}
#endif
