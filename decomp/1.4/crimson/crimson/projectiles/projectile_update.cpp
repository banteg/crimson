// crimson.exe 1.4.0, 0x4094e0. The four passes share both the pools and the CRT random stream.
#include "../effects/freeware_ice_mark.h"
#include "../ui/freeware_ui.h"
#include "crimsonland_types.h"
#include "freeware_edition.h"
#include <math.h>
extern "C" {
extern projectile_pool_t projectile_pool;
extern secondary_projectile_pool_t secondary_projectile_pool;
extern particle_t particle_pool[128];
extern sprite_effect_t sprite_effect_pool[384];
extern creature_t creature_pool[512];
extern player_state_t player_state_table[2];
extern float frame_dt, freeware_simulation_clock, bonus_fire_bullets_timer, bonus_freeze_timer;
extern float freeware_hit_sound_timer;
extern int highscore_record_hits, creature_spawned_count, current_player_index;
extern game_mode_id_t config_game_mode;
int crt_rand();
int creature_find_in_radius(const vec2f_t *, float);
int creature_find_nearest(const vec2f_t *);
int fx_spawn_sprite(const vec2f_t *, const vec2f_t *, float);
int fx_spawn_particle(const vec2f_t *, float, const vec2f_t *, float);
void creature_handle_death(int slot, int player, unsigned char leave_corpse);
void fx_queue_add_random(const vec2f_t *);
void freeware_combat_sound(int sample, float volume);
}

// VC6 emitted all four pool walks and their arithmetic inside this one native body.
#ifndef _MSC_VER
#define __forceinline inline
#endif
namespace {
const float half_pi = 1.57079637f, tau = 6.28318548f;
__forceinline vec2f_t offset(const vec2f_t &p, float x, float y) {
    vec2f_t v = {p.x + x, p.y + y};
    return v;
}
__forceinline float distance(const vec2f_t &a, const vec2f_t &b) {
    double x = a.x - b.x, y = a.y - b.y;
    return (float)sqrt(x * x + y * y);
}
__forceinline void blood(vec2f_t p) { fx_queue_add_random(&p); }
__forceinline void shard(vec2f_t p, float size) { freeware_shard(&p, size); }
__forceinline vec2f_t scatter_shards(vec2f_t p, int count) {
    vec2f_t mark = p;
    for (int i = 0; i < count; ++i) {
        float size = (float)(crt_rand() % 10 + 5);
        float angle = (crt_rand() % 628) * .01f;
        int radius = crt_rand() % 35;
        mark = offset(p, (float)cos(angle) * radius, (float)sin(angle) * radius);
        shard(mark, size);
    }
    return mark;
}
__forceinline void sprite(vec2f_t pos, float vx, float vy, float scale, float alpha) {
    vec2f_t velocity = {vx, vy};
    sprite_effect_pool[fx_spawn_sprite(&pos, &velocity, scale)].color_a = alpha;
}
__forceinline void sparks(vec2f_t pos) {
    for (int i = 0; i < 10; ++i) {
        float speed = (crt_rand() % 800) * .1f;
        sprite(pos, (float)cos(i * .62831855f) * speed, (float)sin(i * .62831855f) * speed, 14, .37f);
    }
}
__forceinline void impact_marks(projectile_t &shot, creature_t &c) {
    float angle = shot.angle - half_pi + (crt_rand() % 20 - 10) * .1f;
    float x = (float)cos(angle) * 20, y = (float)sin(angle) * 20;
    int type = shot.fields.type_id;
    if (type != 7 && type != 10) {
        if (bonus_freeze_timer <= 0) {
            blood(c.position);
            for (int i = 3; i <= 5; ++i)
                blood(offset(c.position, x * i * .5f, y * i * .5f));
        } else {
            shard(c.position, (float)(crt_rand() % 10 + 5));
            shard(offset(c.position, x * 1.5f, y * 1.5f), (float)(crt_rand() % 10 + 5));
            shard(offset(c.position, x + x, y + y), (float)(crt_rand() % 10 + 5));
        }
    }
    if (type == 10) {
        double length = (crt_rand() % 100) * .1f;
        if (length > 4)
            length = (crt_rand() % 90 + 10) * .1f;
        if (length > 7)
            length = (crt_rand() % 80 + 20) * .1f;
        vec2f_t mark = offset(c.position, (float)(cos(shot.angle - half_pi) * length * 20),
                              (float)(sin(shot.angle - half_pi) * length * 20));
        float size = (float)(crt_rand() % 10 + 5);
        if (bonus_freeze_timer > 0)
            shard(mark, size);
        blood(mark);
    }
}
__forceinline void hit(projectile_t &shot, int id) {
    creature_t &c = creature_pool[id];
    int type = shot.fields.type_id;
    if (c.death_timer == 16)
        ++highscore_record_hits;
    if (player_state_table[current_player_index].freeware.perks[freeware_rules::bloody_mess] > 0) {
        for (int radius = 30; radius < 60; radius += 10) {
            int x = crt_rand() % (2 * radius) - radius;
            int y = crt_rand() % (2 * radius) - radius;
            blood(offset(c.position, (float)x, (float)y));
        }
    }
    if (bonus_fire_bullets_timer <= 0 && type != 10)
        shot.fields.life_timer = .25f;
    float range = distance(shot.fields.origin, shot.position);
    if (range < 50)
        range = 50;
    float damage = 100 / range * 30 + 10;
#if FREEWARE_EDITION == 10002
    // 0x402f3d..0x402f76 subtracts range-scaled damage directly.
    if (type == 2) damage *= .6f;
    else if (type == 4) damage *= 4.6f;
    else if (type == 6) damage *= 9.6f;
    c.health -= damage;
    float angle = shot.angle - half_pi + (crt_rand() % 20 - 10) * .1f;
    float dx = (float)cos(angle) * 20, dy = (float)sin(angle) * 20;
    if (type != 6) {
        blood(c.position);
        blood(offset(c.position, dx * 1.5f, dy * 1.5f));
        blood(offset(c.position, dx * 2.5f, dy * 2.5f));
    }
#else
    switch (type) {
    case 2:
        damage *= 1.2f;
        break;
    case 4:
        damage *= 4.1f;
        break;
    case 7:
        damage *= 5;
        break;
    case 9:
        damage *= 2;
        break;
    case 17:
        c.plague_infected = 1;
        damage = 0;
        break;
    }
    float &pool = shot.fields.damage_pool;
    if (c.health > 0) {
        pool -= 1;
        if (pool > 0) {
            c.health -= pool;
            pool -= c.health; // Uses the health AFTER subtraction, including a negative overkill balance.
        } else {
            c.health -= damage * .95f;
            shot.fields.life_timer = .25f;
        }
    }
    if (pool == 1) {
        pool = 0;
        shot.fields.life_timer = .25f;
    }
    c.ai_mode = 1;
    impact_marks(shot, c);
#endif
    if (FREEWARE_EDITION == 10002) {
        if (freeware_hit_sound_timer <= 0 && config_game_mode != 2)
            freeware_combat_sound(31, 1);
        else if (bonus_fire_bullets_timer == 0)
            freeware_combat_sound(crt_rand() % 2, .45f);
    } else if (freeware_hit_sound_timer > 0 || config_game_mode == 2)
        freeware_combat_sound(crt_rand() % 2, .45f);
    else
        freeware_combat_sound(31, 1);
    if (c.health <= 0) {
        if (c.death_timer == 16) {
            if (FREEWARE_EDITION != 10002 && bonus_freeze_timer > 0)
                scatter_shards(c.position, 6);
            freeware_combat_sound(crt_rand() % 4 + 3, .45f);
            creature_handle_death(id, current_player_index, 1);
        }
#if FREEWARE_EDITION == 10002
        float angle = shot.angle - half_pi + (crt_rand() % 20 - 10) * .1f;
        float x = (float)cos(angle) * 20, y = (float)sin(angle) * 20;
        blood(offset(c.position, x, y));
        blood(offset(c.position, x * 2, y * 2));
#else
        --creature_spawned_count;
#endif
        c.death_timer -= frame_dt * 20;
    }
}
__forceinline void bullets() {
    for (int i = 0; i < 64; ++i) {
        projectile_t &s = projectile_pool[i];
        if (!s.active)
            continue;
        if (s.fields.life_timer <= 0)
            s.active = 0;
        int type = s.fields.type_id;
        if (s.fields.life_timer < .4f) {
            s.fields.life_timer -= frame_dt * (type == 10 ? .1f : 1.f);
            continue;
        }
        if (s.pos_x < -10 || s.position.y < -10 || s.pos_x > 1034 || s.position.y > 1034) {
            s.fields.life_timer -= frame_dt;
            continue;
        }
        double angle = (double)s.angle - half_pi;
        int steps = 50;
        switch (type) {
        case 2:
            steps = 60;
            break;
        case 4:
            steps = 55;
            break;
        case freeware_rules::plasma_round:
            steps = 30;
            break;
        case freeware_rules::plasma_minigun_round:
            steps = 35;
            break;
        case 10:
            steps = 215;
            break;
        case 17:
            steps = FREEWARE_EDITION == 10300 ? 50 : 15;
            break;
        case 18:
            steps = 10;
            angle += sin((double)freeware_simulation_clock * 4 + i);
            break;
        }
        float dx = (float)(cos(angle) * frame_dt * (type == 18 ? 10 : 20));
        float dy = (float)(sin(angle) * frame_dt * (type == 18 ? 10 : 20));
        if (type == 3) {
            s.pos_x += dx * 10;
            s.position.y += dy * 10;
            s.fields.reserved -= frame_dt;
            if (s.fields.reserved < 0) {
                s.fields.type_id = (projectile_type_id_t)0;
                vec2f_t zero = {0, 0};
                for (int j = 0; j < 40; ++j)
                    fx_spawn_particle(&s.position, (crt_rand() % 628) * .01f, &zero, .8f);
            }
            continue;
        }
        // Career and Survival have an empty wall list. The 1.3.0 numbered maps use it.
        for (int step = 0; step < steps; ++step) {
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10300
            vec2f_t delta = {dx * s.fields.speed_scale, dy * s.fields.speed_scale};
            if (freeware_current_map->move_with_collision(&s.position, &delta, 0)) {
                if (crt_rand() % 15 == 2) {
                    vec2f_t start = {s.position.x - delta.x, s.position.y - delta.y};
                    projectile_spawn(&start, s.angle - half_pi, 1);
                }
                s.fields.life_timer = .25f;
                break;
            }
#else
            s.position.x += dx * s.fields.speed_scale;
            s.position.y += dy * s.fields.speed_scale;
#endif
            int id = creature_find_in_radius(&s.position, type == 18 ? 16.f : 0.f);
            if (id >= 0) {
                hit(s, id);
                if (FREEWARE_EDITION == 10002 || s.fields.damage_pool <= 0)
                    break;
            }
        }
    }
}
__forceinline void rockets() {
    for (int i = 0; i < 64; ++i) {
        secondary_projectile_t &r = secondary_projectile_pool[i];
        if (!r.active)
            continue;
        vec2f_t &v = r.fields.velocity;
        int type = r.fields.type_id;
        if (type == 3) {
            v.x += frame_dt * 3;
            if (v.x > 1) {
                float size = v.y * 256;
                effect_color_t black = {0, 0, 0, .25f};
                fx_queue_add(ui140::texture("glow"), &r.position, size, size, 0, black);
                r.active = 0;
            }
            for (int j = 0; j < 512; ++j) {
                creature_t &c = creature_pool[j];
                if (c.active && c.health > 0 && distance(c.position, r.position) < v.x * v.y * 80) {
                    c.health -= frame_dt * v.y * 700;
                    if (c.health <= 0) {
                        blood(c.position);
                        creature_handle_death(j, current_player_index, 1);
                    }
                }
            }
            continue;
        }
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10300
        vec2f_t delta = {v.x * frame_dt, v.y * frame_dt};
        if (freeware_current_map->move_with_collision(&r.position, &delta, 4)) {
            r.fields.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
            v.x = 0;
            v.y = type == 1 ? 1.f : .5f;
            type = 3;
        }
#else
        r.position.x += v.x * frame_dt;
        r.position.y += v.y * frame_dt;
#endif
        if (type == 1) {
            float scale = 1 + frame_dt * 3;
            v.x *= scale;
            v.y *= scale;
            r.life_timer -= frame_dt;
        } else if (type == 2) {
            int &id = r.fields.target_id;
            if (!creature_pool[id].active)
                id = creature_find_nearest(&r.position);
            vec2f_t target = creature_pool[id].position;
            double heading = atan2((double)r.position.y - target.y, (double)r.pos_x - target.x) - half_pi;
            r.angle = (float)heading;
            v.x = (float)(v.x + cos(heading - half_pi) * frame_dt * 800);
            v.y = (float)(v.y + sin((double)r.angle - half_pi) * frame_dt * 800);
            if (sqrt((double)v.x * v.x + (double)v.y * v.y) > 350) {
                v.x = (float)(v.x - cos((double)r.angle - half_pi) * frame_dt * 800);
                v.y = (float)(v.y - sin((double)r.angle - half_pi) * frame_dt * 800);
            }
            r.life_timer -= frame_dt * .5f;
        }
        r.fields.trail_distance -= (float)(fabs(v.x) + fabs(v.y)) * frame_dt * .01f;
        if (r.fields.trail_distance < 0) {
            float smoke = (float)cos(r.angle + half_pi) * 90;
            sprite(offset(r.position, (float)-cos(r.angle - half_pi) * 9, (float)-sin(r.angle - half_pi) * 9),
                   smoke, smoke, 14, .3f);
            r.fields.trail_distance = .05f;
        }
        int id = creature_find_in_radius(&r.position, 8);
        if (id >= 0) {
            creature_t &c = creature_pool[id];
            if (c.death_timer == 16)
                ++highscore_record_hits;
            vec2f_t frozen_mark = c.position;
            if (bonus_freeze_timer <= 0) {
                int x = crt_rand() % 20 - 10, y = crt_rand() % 20 - 10;
                blood(offset(c.position, (float)x, (float)y));
            } else
                frozen_mark = scatter_shards(c.position, 3);
            freeware_combat_sound(freeware_hit_sound_timer > 0 ? 21 : 31, .45f);
            c.health -= r.life_timer * 50 + (type == 1 ? 500.f : 100.f);
            c.ai_mode = 1;
            if (c.health <= 0) {
                if (c.death_timer == 16)
                    creature_handle_death(id, current_player_index, 1);
                c.death_timer -= frame_dt * 10;
            }
            r.fields.type_id = SECONDARY_PROJECTILE_TYPE_EXPLODING;
            v.x = 0;
            v.y = type == 1 ? 1.f : .5f;
            if (bonus_freeze_timer <= 0) {
                int count = type == 1 ? 20 : 10;
                for (int k = 0; k < count; ++k) {
                    float a = (crt_rand() % 628) * .01f;
                    int radius = crt_rand() % (type == 1 ? 90 : 64);
                    blood(offset(c.position, (float)cos(a) * radius, (float)sin(a) * radius));
                }
            } else {
                // The frozen blast reuses the last impact offset for all ten marks.
                // Size/position choices still consume four random values per mark.
                for (int k = 0; k < 10; ++k) {
                    crt_rand();
                    crt_rand();
                    shard(frozen_mark, (float)(crt_rand() % 10 + 5));
                }
            }
            sparks(r.position);
        }
        if (r.life_timer <= 0) {
            sparks(r.position);
            r.active = 0;
        }
    }
}
__forceinline float clamp_color(float value) { return value < 0 ? 0 : value > 1 ? 1 : value; }
__forceinline void particles() {
    for (int i = 0; i < 128; ++i) {
        particle_t &p = particle_pool[i];
        if (!p.active)
            continue;
        bool bubble = p.style_id == 8;
        p.intensity -= frame_dt * (FREEWARE_EDITION == 10002 ? 1.1f : bubble ? .11f : .9f);
        p.rotation += frame_dt * (bubble ? 5.f : 1.f);
        if (!bubble || p.in_flight) {
            float scale = bubble ? (p.intensity <= .15f ? .55f : 1.f) * p.intensity
                                 : 2.5f * (p.intensity > .15f ? p.intensity : .15f);
#if FREEWARE_EDITION == 10300
            vec2f_t delta = {frame_dt * p.vel_x * scale, frame_dt * p.vel_y * scale};
            if (p.intensity > .15f)
                freeware_current_map->move_with_collision(&p.position, &delta, 3);
            else {
                p.pos_x += delta.x;
                p.pos_y += delta.y;
            }
#else
            p.pos_x += frame_dt * p.vel_x * scale;
            p.pos_y += frame_dt * p.vel_y * scale;
#endif
        }
        if (p.intensity <= (p.style_id == 0 ? 0.f : .8f)) {
            p.active = 0;
            if (bubble) {
                if (p.target_id != -1) {
                    if (creature_pool[p.target_id].active)
                        freeware_combat_sound(crt_rand() % 4 + 3, .45f);
                    creature_handle_death(p.target_id, 0, 0);
                }
                freeware_combat_sound(27, (crt_rand() % 70) * .1f + .3f);
            }
            continue;
        }
        if (p.in_flight == 1) {
            double a = p.angle - (crt_rand() % 100 - 50) * (double)(FREEWARE_EDITION == 10002 ? .1f : .06f) * frame_dt * p.intensity *
                                     (p.style_id == 0 ? 1.96f : 1.1f);
            p.angle = (float)a;
            p.vel_x = (float)(cos(a) * (bubble ? 62 : 82));
            p.vel_y = (float)(sin(p.angle) * (bubble ? 62 : 82));
        }
        p.color_a = p.intensity < 1 ? p.intensity : 1;
        p.color_r = p.color_g = 1 - p.intensity * .95f;
        if (!p.in_flight)
            continue;
        int id = creature_find_in_radius(&p.position, p.intensity * 8);
        if (id < 0)
            continue;
        creature_t &c = creature_pool[id];
        p.in_flight = 0;
        if (bubble) {
            p.position = c.position;
            p.vel_x = p.vel_y = 0;
            p.target_id = id;
            c.ai_mode = 0;
            c.activation_radius = 0;
            continue;
        }
        while (p.angle > tau)
            p.angle -= tau;
        while (p.angle < 0)
            p.angle += tau;
        double bearing =
            atan2(p.pos_y - (double)frame_dt * p.vel_y - c.pos_y, (float)(p.pos_x - frame_dt * p.vel_x) - c.pos_x);
        if (bearing < 0)
            bearing += tau;
        p.angle += p.angle <= bearing ? 1.2566371f : -1.2566371f;
        float speed = (crt_rand() % 10) * .1f;
        p.vel_x = (float)(cos(p.angle) * 82) * speed;
        p.vel_y = (float)(sin(p.angle) * 82) * speed;
        c.health -= p.intensity * (FREEWARE_EDITION == 10002 ? 15 : 10);
#if FREEWARE_EDITION != 10002
        c.ai_mode = 1;
        effect_color_t &color = c.freeware.color;
        if (color.r + color.g + color.b > .6f) {
            float scale = 1 - p.intensity * .18f;
            color.r *= scale;
            color.g *= scale;
            color.b *= scale;
            color.r = clamp_color(color.r);
            color.g = clamp_color(color.g);
            color.b = clamp_color(color.b);
            color.a = clamp_color(color.a);
        }
        if (i % 3 == 0) {
            int x = crt_rand() % 60 - 30, y = crt_rand() % 60 - 30;
            sprite(c.position, (float)x, (float)y, 13, .7f);
        }
#endif
        blood(c.position);
        c.pos_x += p.vel_x * frame_dt;
        c.pos_y += p.vel_y * frame_dt;
        if (c.health <= 0) {
#if FREEWARE_EDITION == 10002
            // The 0x4036df flame kill awards XP directly without rolling a weapon pickup.
            if (c.death_timer == 16) {
                freeware_combat_sound(crt_rand() % 4 + 3, .45f);
                freeware_player_t &owner = player_state_table[current_player_index].freeware;
                owner.experience += (int)(c.freeware.reward * (owner.perks[freeware_rules::bloody_mess] ? 1.5 : 1));
#ifdef CRIMSON_FREEWARE_CLIENT
                UI_GAME.run.experience = owner.experience;
#endif
            }
#else
            if (c.death_timer == 16) {
                creature_handle_death(id, current_player_index, 1);
                freeware_combat_sound(crt_rand() % 4 + 3, .45f);
            }
#endif
            --creature_spawned_count;
            c.death_timer -= frame_dt * 20;
        }
    }
}
} // namespace
extern "C" void projectile_update() {
#if FREEWARE_EDITION == 10002
    // 0x402ca0 decays the muzzle flash before projectiles, including during the dying phase.
    float &flash = player_state_table[current_player_index].freeware.muzzle_flash;
    flash -= frame_dt * 2;
    if (flash < 0)
        flash = 0;
#endif
    bullets();
    rockets();
    for (int i = 0; i < 384; ++i) {
        sprite_effect_t &s = sprite_effect_pool[i];
        if (!s.active)
            continue;
        s.pos_x += frame_dt * s.vel_x;
        s.pos_y += frame_dt * s.vel_y;
        s.rotation += frame_dt * 3;
        s.color_a -= frame_dt;
        if (s.color_a <= 0)
            s.active = 0;
        s.scale += frame_dt * 60;
    }
    particles();
}
