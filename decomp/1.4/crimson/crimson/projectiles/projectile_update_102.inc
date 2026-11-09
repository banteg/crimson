// 1.0.2, 0x402ca0. Update primary shots and the flame-particle pool.
#include <math.h>
#include "crimsonland_types.h"
#include "freeware_edition.h"

extern "C" {
extern freeware_player_t player_state_table[2];
extern projectile_pool_t projectile_pool;
extern particle_t particle_pool[128];
extern creature_t creature_pool[128];
extern game_mode_id_t config_game_mode;
extern int current_player_index, perk_id_bloody_mess, creature_spawned_count;
extern int freeware_arena_width, freeware_arena_height, freeware_music_channel_b;
extern int freeware_pickup_id, freeware_no_pickup;
extern int freeware_bonus_fire, freeware_bonus_freeze, freeware_bonus_weapon, freeware_bonus_nuke;
extern vec2f_t freeware_pickup_position;
extern float frame_dt, bonus_fire_bullets_timer, freeware_pickup_time;
int creature_find_in_radius(const vec2f_t *, float);
int fx_spawn_particle(const vec2f_t *, float, const vec2f_t *, float);
int crt_rand();
int sfx_play_panned(int, float, float);
void freeware_game_track_start(int);
void fx_queue_add_random(const vec2f_t *);
}

namespace {
// The primary pool uses different projectile ids from the later builds.
enum { pellet_round = 2, burst_round = 3, pistol_round = 4 };
const float half_pi = 1.57079637f;

struct ImpactPoint : vec2f_t {
    __forceinline ImpactPoint(const float &px, const float &py) {
        x = px;
        y = py;
    }
};
__forceinline ImpactPoint offset_point(const vec2f_t &a, const vec2f_t &b) {
    return ImpactPoint(a.x + b.x, a.y + b.y);
}
__forceinline void leave_mark(const vec2f_t &point) {
    fx_queue_add_random(&point);
}
__forceinline void spray_direction(const float &heading, float &x, float &y) {
    float angle = (heading - half_pi) + (crt_rand() % 20 - 10) * .1f;
    x = (float)cos(angle) * 20.f;
    y = (float)sin(angle) * 20.f;
}
__forceinline void hit_creature(int slot, int id, const float &heading) {
    float dx, dy;
    if (player_state_table[current_player_index].perks[perk_id_bloody_mess] > 0 &&
        projectile_pool[slot].fields.type_id != freeware_rules::plasma_round) {
        for (int upper = 30, lower = -30; lower > -60; lower -= 10, upper += 10) {
            vec2f_t offset;
            offset.x = (float)(crt_rand() % (upper - lower) + lower);
            offset.y = (float)(crt_rand() % (upper - lower) + lower);
            leave_mark(offset_point(offset, creature_pool[id].position));
        }
    }
    if (bonus_fire_bullets_timer <= 0)
        projectile_pool[slot].fields.life_timer = .25f;
    float x = projectile_pool[slot].fields.origin.x - projectile_pool[slot].position.x;
    float y = projectile_pool[slot].fields.origin.y - projectile_pool[slot].position.y;
    float squared = x * x;
    squared += y * y;
    float range = (float)sqrt(squared);
    if (range < 50)
        range = 50;
    float damage = (100.f / range) * 30.f + 10.f;
    int type = projectile_pool[slot].fields.type_id;
    if (type == pellet_round)
        damage *= .6f;
    else if (type == pistol_round)
        damage *= 4.6f;
    else if (type == freeware_rules::plasma_round)
        damage *= 9.6f;
    creature_pool[id].health -= damage;

    spray_direction(heading, dx, dy);
    if (projectile_pool[slot].fields.type_id != freeware_rules::plasma_round) {
        const vec2f_t &pos = creature_pool[id].position;
        leave_mark(pos);
        leave_mark(offset_point(ImpactPoint(dx * 1.5f, dy * 1.5f), pos));
        leave_mark(offset_point(ImpactPoint(dx * 2.5f, dy * 2.5f), pos));
    }
    // A hit starts the game track whenever its channel is idle.
    if (freeware_music_channel_b == -1)
        freeware_game_track_start(31);
    else if (bonus_fire_bullets_timer == 0)
        sfx_play_panned(crt_rand() % 2, .45f, .5f);

    if (creature_pool[id].health <= 0) {
        if (creature_pool[id].death_timer == 16) {
            sfx_play_panned(crt_rand() % 4 + 3, .45f, .5f);
            if (player_state_table[current_player_index].perks[perk_id_bloody_mess] > 0)
                player_state_table[current_player_index].experience +=
                    (int)(creature_pool[id].freeware.reward * 1.5f);
            else
                player_state_table[current_player_index].experience += creature_pool[id].freeware.reward;
            if (freeware_pickup_id == freeware_no_pickup && config_game_mode != GAME_MODE_RUSH &&
                (crt_rand() % 15 == 1 ||
                 (player_state_table[current_player_index].weapon == 1 && crt_rand() % 3 == 1))) {
                freeware_pickup_position = creature_pool[id].position;
                int kind = crt_rand() % 4;
                if (config_game_mode == GAME_MODE_RUSH) {
                    while (kind == 2)
                        kind = crt_rand() % 4;
                }
                if (player_state_table[current_player_index].weapon == 1)
                    kind = 2;
                if (kind == 0)
                    freeware_pickup_id = freeware_bonus_fire;
                else if (kind == 1)
                    freeware_pickup_id = freeware_bonus_freeze;
                else if (kind == 2)
                    freeware_pickup_id = freeware_bonus_weapon;
                else if (kind == 3)
                    freeware_pickup_id = freeware_bonus_nuke;
                freeware_pickup_time = 10;
            }
        }
        creature_pool[id].death_timer -= frame_dt * 20;
        spray_direction(heading, dx, dy);
        leave_mark(offset_point(ImpactPoint(dx, dy), creature_pool[id].position));
        leave_mark(offset_point(ImpactPoint(dx + dx, dy + dy), creature_pool[id].position));
        --creature_spawned_count;
    }
}

// 1.0.2 has only the flame particle walk after the primary projectile pool.
struct ParticlePoint : vec2f_t {
    __forceinline ParticlePoint(float a, float b) { x = a; y = b; }
};
__forceinline ParticlePoint scale_particle_vector(const vec2f_t &v, float factor) {
    return ParticlePoint(factor * v.x, factor * v.y);
}
__forceinline ParticlePoint subtract_particle_vectors(const vec2f_t &a, const vec2f_t &b) {
    return ParticlePoint(a.x - b.x, a.y - b.y);
}
__forceinline void add_particle_vector(vec2f_t &a, const vec2f_t &b) {
    a.x += b.x;
    a.y += b.y;
}
__forceinline void update_flame_particles() {
    const float tau = 6.28318548f;
    for (int i = 0; i < 128; ++i) {
        particle_t &p = particle_pool[i];
        if (!p.active)
            continue;

        p.intensity -= frame_dt * 1.1f;
        if (p.intensity <= 0) {
            p.active = 0;
            continue;
        }
        if (p.intensity > .15f) {
            ParticlePoint delta = scale_particle_vector(
                scale_particle_vector(scale_particle_vector(particle_pool[i].velocity, frame_dt), 2.5f), p.intensity);
            particle_pool[i].position.x += delta.x;
            particle_pool[i].position.y += delta.y;
        } else {
            ParticlePoint delta = scale_particle_vector(
                scale_particle_vector(scale_particle_vector(particle_pool[i].velocity, frame_dt), 2.5f), .15f);
            particle_pool[i].position.x += delta.x;
            particle_pool[i].position.y += delta.y;
        }
        float &angle = p.angle;
        if (p.in_flight == 1) {
            int turn = crt_rand() % 100 - 50;
            float deviation = (float)turn * .1f;
            deviation *= p.intensity;
            deviation *= frame_dt;
            deviation *= 1.96f;
            angle -= deviation;
            p.vel_x = (float)cos(angle) * 82.f;
            p.vel_y = (float)sin(angle) * 82.f;
        }
        p.color_a = p.intensity > 1 ? 1 : p.intensity;
        float &red = p.color_r, &green = p.color_g;
        red = 1.f - p.intensity * .95f;
        green = red;
        float &rotation = p.rotation;
        rotation += frame_dt;
        if (!p.in_flight)
            continue;
        const vec2f_t &contact = p.position;
        int id = creature_find_in_radius(&contact, p.intensity * 8);
        if (id == -1)
            continue;

        unsigned char &in_flight = p.in_flight;
        in_flight = 0;
        while (p.angle > tau)
            p.angle -= tau;
        while (p.angle < 0)
            p.angle += tau;
        ParticlePoint displacement = scale_particle_vector(p.velocity, frame_dt);
        ParticlePoint previous_position(contact.x - displacement.x, p.position.y - displacement.y);
        const vec2f_t &hit_position = creature_pool[id].position;
        ParticlePoint from = subtract_particle_vectors(previous_position, hit_position);
        float bearing = (float)atan2(from.y, from.x);
        while (bearing > tau)
            bearing -= tau;
        while (bearing < 0)
            bearing += tau;
        if (bearing < p.angle)
            p.angle -= 1.2566371f;
        else
            p.angle += 1.2566371f;
        p.vel_x = (float)cos(p.angle) * 82.f;
        p.vel_y = (float)sin(p.angle) * 82.f;
        float speed = (crt_rand() % 10) * .1f;
        p.vel_x *= speed;
        p.vel_y *= speed;
        creature_pool[id].health -= p.intensity * 15;
        fx_queue_add_random(&creature_pool[id].position);
        ParticlePoint recoil(p.vel_x, p.vel_y);
        float delta_time = frame_dt;
        ParticlePoint delta = scale_particle_vector(recoil, delta_time);
        add_particle_vector(creature_pool[id].position, delta);
        if (creature_pool[id].health <= 0) {
            if (creature_pool[id].death_timer == 16) {
                sfx_play_panned(crt_rand() % 4 + 3, .45f, .5f);
                if (player_state_table[current_player_index].perks[perk_id_bloody_mess] > 0)
                    player_state_table[current_player_index].experience += (int)(creature_pool[id].freeware.reward * 1.5f);
                else
                    player_state_table[current_player_index].experience += creature_pool[id].freeware.reward;
            }
            --creature_spawned_count;
            creature_pool[id].death_timer -= frame_dt * 20;
        }
    }
}
} // namespace
extern "C" void projectile_update() {
    player_state_table[current_player_index].muzzle_flash -= frame_dt * 2.0f;
    if (player_state_table[current_player_index].muzzle_flash < 0)
        player_state_table[current_player_index].muzzle_flash = 0;
    for (int i = 0; i < PROJECTILE_POOL_CAPACITY; ++i) {
        if (!projectile_pool[i].active)
            continue;
        if (projectile_pool[i].fields.life_timer <= 0)
            projectile_pool[i].active = 0;
        if (projectile_pool[i].fields.life_timer < .4f || projectile_pool[i].pos_x < -10 ||
            projectile_pool[i].position.y < -10 || projectile_pool[i].pos_x > freeware_arena_width + 10 ||
            projectile_pool[i].position.y > freeware_arena_height + 10) {
            projectile_pool[i].fields.life_timer -= frame_dt;
            continue;
        }

        float dx = (float)cos(projectile_pool[i].angle - half_pi) * frame_dt * 20.f;
        float dy = (float)sin(projectile_pool[i].angle - half_pi) * frame_dt * 20.f;
        int steps = 50;
        if (projectile_pool[i].fields.type_id == pellet_round)
            steps = 60;
        if (projectile_pool[i].fields.type_id == pistol_round)
            steps = 55;
        if (projectile_pool[i].fields.type_id == freeware_rules::plasma_round)
            steps = 30;
        if (projectile_pool[i].fields.type_id == freeware_rules::plasma_minigun_round)
            steps = 35;
        if (projectile_pool[i].fields.type_id != burst_round) {
            for (int j = 0; j < steps; ++j) {
                projectile_pool[i].position.x += dx * projectile_pool[i].fields.speed_scale;
                projectile_pool[i].position.y += dy * projectile_pool[i].fields.speed_scale;
                int id = creature_find_in_radius(&projectile_pool[i].position, 0);
                if (id != -1) {
                    hit_creature(i, id, projectile_pool[i].angle);
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
    update_flame_particles();
}
