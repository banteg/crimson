// Player update at 0x408040 (1.0.2), 0x40e430 (1.3.0) and 0x4126e0 (1.4.0).
#include "freeware_level.h"
#include "freeware_edition.h"
#include <math.h>
#ifndef _MSC_VER
#define __forceinline inline
#endif
#ifndef CRIMSON_FREEWARE_CLIENT
#include "grim2d_cpp.h"
extern "C" IGrim2D_cpp *grim_interface_ptr;
#define KEY(k) grim_interface_ptr->grim_is_key_down(k)
#define EDGE(k) grim_interface_ptr->grim_was_key_pressed(k)
#define MOUSE(b) grim_interface_ptr->grim_is_mouse_button_down(b)
#define CLICK(b) grim_interface_ptr->grim_was_mouse_button_pressed(b)
#define PAD_FIRE() grim_interface_ptr->grim_is_joystick_button_down(0)
#else
extern "C" unsigned char freeware_key_down[256], freeware_key_edge[256], freeware_mouse_down[3],
    freeware_mouse_click, freeware_pad_fire;
#define KEY(k) freeware_key_down[k]
#define EDGE(k) freeware_key_edge[k]
#define MOUSE(b) freeware_mouse_down[b]
#define CLICK(b) freeware_mouse_click
#define PAD_FIRE() freeware_pad_fire
#endif

extern "C" {
#if CL_BUILD == 10400
extern player_state_t player_state_table[2];
#define PLAYER(i) player_state_table[i].freeware
#else
extern freeware_player_t player_state_table[2];
#define PLAYER(i) player_state_table[i]
#endif
extern creature_t creature_pool[CL_BUILD == 10002 ? 128 : 512];
extern projectile_pool_t projectile_pool;
extern particle_t particle_pool[128];
extern sprite_effect_t sprite_effect_pool[384];
extern game_mode_id_t config_game_mode;
extern int current_player_index, config_player_count, config_aim_schemes[2];
extern int config_movement_schemes[CL_BUILD == 10002 ? 1 : 2];
extern int freeware_arena_width, freeware_arena_height, highscore_record_shots_fired, freeware_first_kill_xp;
extern unsigned char console_open_flag, freeware_player_moved, freeware_secret_weapon_unlocked,
    freeware_rainbow_enabled, freeware_rainbow_armed, time_scale_active;
extern float frame_dt, freeware_simulation_clock, freeware_elapsed_seconds, freeware_berserk_timer, bonus_reflex_boost_timer,
    time_scale_factor, freeware_fade_time;
extern vec2f_t freeware_first_kill_position, freeware_aim_screen, freeware_camera;
extern int perk_id_long_distance_runner, perk_id_sharpshooter, perk_id_ammo_maniac, perk_id_fastshot,
    perk_id_anxious_loader;
extern int perk_id_timebender, perk_id_fastloader;
int crt_rand();
void weapon_assign_player(int, int);
int projectile_spawn(const vec2f_t *, float, int);
int fx_spawn_sprite(const vec2f_t *, const vec2f_t *, float);
int fx_spawn_particle(const vec2f_t *, float, const vec2f_t *, float);
int fx_spawn_particle_slow(const vec2f_t *, float, const vec2f_t *);
int fx_spawn_secondary_projectile(const vec2f_t *, float, secondary_projectile_type_id_t);
void fx_queue_add_shell(const vec2f_t *);
int sfx_play_panned(int, float, float);
void player_start_reload();
float player_heading_approach_target(float);
bool input_move_up_active(), input_move_down_active(), input_move_left_active(), input_move_right_active();
bool input_aim_pov_left_active(), input_aim_pov_right_active();
}

namespace {
const float pi = 3.14159274f, half_pi = 1.57079637f;
#define P PLAYER(current_player_index)
struct player_vec2_t : vec2f_t {
    player_vec2_t(float x_value, float y_value) {
        x = x_value;
        y = y_value;
    }
};
__forceinline player_vec2_t operator+(const vec2f_t &a, const vec2f_t &b) {
    return player_vec2_t(a.x + b.x, a.y + b.y);
}
__forceinline vec2f_t &operator+=(vec2f_t &a, const vec2f_t &b) {
    a.x += b.x;
    a.y += b.y;
    return a;
}
__forceinline vec2f_t operator-(const vec2f_t &a, const vec2f_t &b) {
    float x = a.x - b.x, y = a.y - b.y;
    vec2f_t difference = {x, y};
    return difference;
}
// The summed position lives through the call that consumes its address.
__forceinline const vec2f_t *position_ptr(const vec2f_t &position) { return &position; }

__forceinline float distance(const vec2f_t &a, const vec2f_t &b) {
    vec2f_t delta = a - b;
#if FREEWARE_EDITION == 10300
    return (float)sqrt((double)delta.y * delta.y + delta.x * delta.x);
#else
    return (float)sqrt(delta.y * delta.y + delta.x * delta.x);
#endif
}
__forceinline bool direction_key(int key) {
#if CL_BUILD == 10002
    if (key == 0) return KEY(0xc8) || KEY(0x11);
    if (key == 1) return KEY(0xd0) || KEY(0x1f);
    if (key == 2) return KEY(0xcb) || KEY(0x1e);
    return KEY(0xcd) || KEY(0x20);
#else
    return KEY(P.keys[key]) || (config_player_count == 1 && KEY(PLAYER(1).keys[key]));
#endif
}
__forceinline void accelerate() {
    if (P.perks[perk_id_long_distance_runner] > 0) {
        if (P.move_speed < 2)
            P.move_speed += frame_dt * (FREEWARE_EDITION == 10002 ? 5 : 4);
        P.move_speed += frame_dt;
        const float limit = FREEWARE_EDITION == 10002 ? 4.f : 2.8f;
        if (P.move_speed > limit)
            P.move_speed = limit;
    } else {
        P.move_speed += frame_dt * 5;
        if (P.move_speed > 2)
            P.move_speed = 2;
    }
    if (FREEWARE_EDITION != 10002 && P.weapon == 13 && P.move_speed > .8f)
        P.move_speed = .8f;
}
__forceinline void decelerate() {
    P.move_speed -= frame_dt * 15;
    if (P.move_speed < 0)
        P.move_speed = 0;
}
__forceinline void set_movement_delta(vec2f_t &delta, float x, float y) {
    delta.x = x;
    delta.y = y;
}
__forceinline void scale_movement(vec2f_t &delta, float dt, const vec2f_t &v) {
    set_movement_delta(delta, dt * v.x, dt * v.y);
}
__forceinline void apply_movement() {
    vec2f_t delta;
    scale_movement(delta, frame_dt, P.movement);
    freeware_current_map->move_with_collision(&P.position, &delta, 8.f);
}
__forceinline float movement_component(float wave, float speed, float turn, float units) {
#if FREEWARE_EDITION == 10300
    return (float)((wave * P.move_speed) * turn * speed * units);
#else
    return (float)(wave * turn * speed * P.move_speed * units);
#endif
}
__forceinline void move_forward(float speed, float turn = 1.f, float units = 25.f) {
    P.movement.x = movement_component((float)cos(P.heading - half_pi), speed, turn, units);
    P.movement.y = movement_component((float)sin(P.heading - half_pi), speed, turn, units);
    apply_movement();
}
__forceinline void move_back(float speed) {
    P.movement.x = (float)cos(P.heading - half_pi) * speed * -15.f;
    P.movement.y = (float)sin(P.heading - half_pi) * speed * -15.f;
    apply_movement();
}
__forceinline float aim_length(float x, float y) {
    float y_squared = (float)((double)y * y);
    return sqrtf(x * x + y_squared);
}
__forceinline void muzzle_smoke(const vec2f_t &muzzle, float velocity_x, float velocity_y, float scale,
                                float alpha) {
    vec2f_t velocity = {velocity_x, velocity_y};
    int slot = fx_spawn_sprite(position_ptr(muzzle + P.position), &velocity, scale);
    sprite_effect_pool[slot].color.r = .5f;
    sprite_effect_pool[slot].color.g = .5f;
    sprite_effect_pool[slot].color.b = .5f;
    sprite_effect_pool[slot].color.a = alpha;
}
__forceinline void muzzle_smoke_pair(const vec2f_t &muzzle, player_vec2_t direction, float first_alpha,
                                     float second_alpha) {
    muzzle_smoke(muzzle, direction.x * 25.f, (float)(direction.y * 25.f), 1.f, first_alpha);
    muzzle_smoke(muzzle, direction.x * 15.f, (float)(direction.y * 15.f), 2.f, second_alpha);
}
__forceinline float aim_angle() {
    vec2f_t delta = P.position - P.aim;
    return (float)(atan2(delta.y, delta.x) - half_pi);
}
__forceinline player_vec2_t operator*(const vec2f_t &vec, float value) {
    return player_vec2_t(value * vec.x, value * vec.y);
}
__forceinline void aim_along(float angle) {
    player_vec2_t unit(cosf(angle), sinf(angle));
    P.aim = unit * 60.f + P.position;
}
__forceinline void shot_sound(int id) { sfx_play_panned(id, .45f, .5f); }
__forceinline void start_reload() {
#if CL_BUILD == 10002
    shot_sound(16);
    if (P.perks[perk_id_fastloader] > 0)
        P.reload = .95f;
    else
        P.reload = 1.5f;
#else
    player_start_reload();
#endif
}
#if FREEWARE_EDITION == 10002
__forceinline void fire_early_shell(const vec2f_t &shell, int sound, float cooldown) {
    shot_sound(sound);
    fx_queue_add_shell(&shell);
    P.cooldown = cooldown;
}
__forceinline bool fire(float heading) {
    P.spread += time_scale_factor * frame_dt * 150;
    float max_spread = time_scale_factor * 2;
    if (P.spread > max_spread)
        P.spread = max_spread;
    P.spread *= time_scale_factor;
    float forward = heading - half_pi;
    float angle = forward - .150915f;
    vec2f_t barrel = {(float)cos(angle) * 15.f, (float)sin(angle) * 15.f};
    vec2f_t shell = {(crt_rand() % 10) * (float)cos(heading) * .5f,
                     (crt_rand() % 10) * (float)sin(heading) * .5f};
    shell += P.position;
    if (P.muzzle_flash > 1)
        P.muzzle_flash = 1;
    if (P.weapon == 1) {
        projectile_spawn(
            position_ptr(barrel + P.position), ((crt_rand() % 200 - 100) * P.spread * .001f + heading), 4);
        fire_early_shell(shell, 2, .7117f);
        P.ammo -= 1;
        P.muzzle_flash += .12f;
    } else if (P.weapon == 2) {
        projectile_spawn(
            position_ptr(barrel + P.position), ((crt_rand() % 200 - 100) * P.spread * .001f + heading), 1);
        fire_early_shell(shell, 7, .117f);
        P.ammo -= 1;
        P.muzzle_flash += .07f;
    } else if (P.weapon == 3) {
        int pellets_left = 10;
        do {
            int slot = projectile_spawn(position_ptr(barrel + P.position), (crt_rand() % 200 - 100) * .001f + heading, 2);
            projectile_pool[slot].fields.speed_scale = (crt_rand() % 100) * .01f + 1;
        } while (--pellets_left);
        fire_early_shell(shell, 15, .688117f);
        P.muzzle_flash += .12f;
        P.ammo -= 1;
    } else if (P.weapon == 4) {
        fx_spawn_particle(position_ptr(barrel + P.position), forward, &P.movement, 1);
        shot_sound(14);
        P.cooldown = .008113f;
        P.ammo -= .2f;
    } else if (P.weapon == 5) {
        projectile_spawn(
            position_ptr(barrel + P.position), ((crt_rand() % 20 - 10) * P.spread * .003f + heading), 2);
        fire_early_shell(shell, 26, .088117f);
        P.ammo -= 1;
        P.muzzle_flash += .022f;
    } else if (P.weapon == 6) {
        projectile_spawn(
            position_ptr(barrel + P.position), ((crt_rand() % 20 - 10) * P.spread * .003f + heading), 6);
        fire_early_shell(shell, 8, .2908117f);
        P.ammo -= 1;
    } else if (P.weapon == 7) {
        projectile_spawn(
            position_ptr(barrel + P.position), ((crt_rand() % 20 - 10) * P.spread * .003f + heading) - .31415927f, 6);
        projectile_spawn(
            position_ptr(barrel + P.position), ((crt_rand() % 20 - 10) * P.spread * .003f + heading) + .31415927f, 6);
        fire_early_shell(shell, 8, .3408117f);
        P.ammo -= 2;
    } else if (P.weapon == 8) {
        projectile_spawn(
            position_ptr(barrel + P.position), ((crt_rand() % 20 - 10) * P.spread * .003f + heading), 8);
        fire_early_shell(shell, 8, .10908117f);
        P.ammo -= 1;
    } else if (P.weapon == 17) {
        projectile_spawn(position_ptr(barrel + P.position), heading, 3);
        fire_early_shell(shell, 7, .688117f);
        P.ammo -= 1;
    }
    if (P.perks[perk_id_fastshot] > 0)
        P.cooldown *= .88f;
    if (P.ammo <= 0)
        start_reload();
    return true;
}
#endif
} // namespace

extern "C" void player_update() {
#if FREEWARE_EDITION >= 10400
    if (console_open_flag)
        return;
    if (KEY(P.keys[0]) || KEY(P.keys[1]) || KEY(P.keys[2]) || KEY(P.keys[3]))
        freeware_player_moved = 1;
    if (config_player_count == 1 && config_game_mode == 1) {
        if (P.health < 100 && distance(P.position, freeware_first_kill_position) >= 48)
            freeware_first_kill_xp = -10;
        if (distance(P.position, freeware_first_kill_position) < 48 && P.health < 5 &&
            P.experience == freeware_first_kill_xp) {
            freeware_secret_weapon_unlocked = 1;
            freeware_rainbow_armed = 1;
            freeware_rainbow_enabled = 1;
            if (P.weapon != 18)
                weapon_assign_player(0, 18);
        }
        if (P.experience == 0 && freeware_elapsed_seconds >= 120 && !highscore_record_shots_fired &&
            PLAYER(0).health == 100) {
            P.experience = 1;
            freeware_secret_weapon_unlocked = 1;
            freeware_rainbow_armed = 1;
            freeware_rainbow_enabled = 1;
            weapon_assign_player(0, 19);
        }
    }
#endif
    if (FREEWARE_EDITION != 10002 && P.health <= 0)
        return;
    if (FREEWARE_EDITION != 10002) {
        P.muzzle_flash -= frame_dt * 2;
        if (P.muzzle_flash < 0)
            P.muzzle_flash = 0;
    }
    P.cooldown -= frame_dt;
    if (P.cooldown < 0)
        P.cooldown = 0;
    if (freeware_berserk_timer > 10) {
#if FREEWARE_EDITION == 10002
        // 0x408095..0x40833a steers the player and fires along the body heading.
        float berserk_speed = P.speed_multiplier;
        P.heading += (float)sin(freeware_simulation_clock * 2) * frame_dt * 1.25f;
        P.move_speed += frame_dt * 5;
        if (P.move_speed > 3) P.move_speed = 3;
        P.position.x += (float)(cos(P.heading - half_pi) * P.move_speed) * frame_dt * berserk_speed * 25;
        P.position.y += (float)(sin(P.heading - half_pi) * P.move_speed) * frame_dt * berserk_speed * 25;
        float radius = P.size * .5f;
        if (P.position.x < radius) P.position.x = radius;
        if (P.position.x > freeware_arena_width - radius) P.position.x = freeware_arena_width - radius;
        if (P.position.y < radius) P.position.y = radius;
        if (P.position.y > freeware_arena_height - radius) P.position.y = freeware_arena_height - radius;
        P.aim = P.position;
        P.aim.x += (float)cos((double)P.heading - half_pi) * 25;
        P.aim.y += (float)sin((double)P.heading - half_pi) * 25;
#ifdef CRIMSON_FREEWARE_CLIENT
        P.aim_heading = P.heading;
#endif
        if (P.cooldown == 0) {
            float heading = P.heading;
            P.spread += time_scale_factor * frame_dt * 150;
            float maximum = time_scale_factor * 2;
            if (P.spread > maximum) P.spread = maximum;
            P.spread *= time_scale_factor;
            float angle = heading - half_pi - .25f;
            vec2f_t barrel = {(float)cos(angle) * 12.f, (float)sin(angle) * 12.f};
            player_vec2_t muzzle = barrel + P.position;
            projectile_spawn(&muzzle, (crt_rand() % 200 - 100) * P.spread * .001f + heading, 1);
            shot_sound(7);
            P.cooldown = .1f;
        }
        return;
#else
        if (P.cooldown != 0)
            return;
        for (int i = 0; i < 50; ++i) {
            int index = crt_rand() % 512;
            if (creature_pool[index].active && distance(P.position, creature_pool[index].position) < 500) {
                P.aim = creature_pool[index].position;
                break;
            }
        }
        float heading = aim_angle();
        P.aim_heading = heading;
        float angle = heading - half_pi - .25f;
        vec2f_t barrel = {(float)cos(angle) * 12.f, (float)sin(angle) * 12.f};
        projectile_spawn(position_ptr(barrel + P.position), heading, 1);
        shot_sound(7);
        P.cooldown = .1f;
        return;
#endif
    }
#if FREEWARE_EDITION == 10002
#ifdef CRIMSON_FREEWARE_CLIENT
    const int timebender = freeware_rules::timebender;
#else
    const int timebender = perk_id_timebender;
#endif
    if ((P.perks[timebender] > 0 && P.experience > 0) || config_game_mode == 2) {
        if (KEY(0x39) || MOUSE(1)) {
            P.experience += (int)(frame_dt * -1000);
            time_scale_factor -= frame_dt;
            if (time_scale_factor < .29f) time_scale_factor = .29f;
        } else if (KEY(0x2d)) {
            time_scale_factor += frame_dt;
            if (time_scale_factor > 1.4f) time_scale_factor = 1.4f;
        }
    }
    if (!KEY(0x39) && !MOUSE(1)) {
        time_scale_factor += frame_dt;
        if (time_scale_factor > 1) time_scale_factor = 1;
    }
#else
    if (bonus_reflex_boost_timer > 0) {
        time_scale_factor -= frame_dt * (FREEWARE_EDITION == 10300 ? 1.5f : 1.f);
        const float minimum = FREEWARE_EDITION == 10300 ? .35f : .3f;
        if (time_scale_factor < minimum)
            time_scale_factor = minimum;
    } else {
        time_scale_factor += frame_dt * (FREEWARE_EDITION == 10300 ? 1.5f : .8f);
        if (time_scale_factor > 1)
            time_scale_factor = 1;
    }
#if FREEWARE_EDITION >= 10400
    if (time_scale_active) {
        freeware_fade_time += frame_dt * .8;
        if (freeware_fade_time > 1.5f)
            time_scale_active = 0;
    }
#endif
#endif
    float speed = P.speed_multiplier;
#if FREEWARE_EDITION == 10002
    if (config_movement_schemes[0] == 1) {
        if (direction_key(2)) P.heading -= frame_dt * 2;
        if (direction_key(3)) P.heading += frame_dt * 2;
        if (!direction_key(0)) decelerate();
        else accelerate();
        P.movement.x = (float)(cos(P.heading - half_pi) * P.move_speed) * speed * 25;
        P.movement.y = (float)(sin(P.heading - half_pi) * P.move_speed) * speed * 25;
        P.position.x += frame_dt * P.movement.x;
        P.position.y += frame_dt * P.movement.y;
        P.walk_phase += frame_dt * P.move_speed * 19;
        if (direction_key(1)) {
            P.walk_phase += frame_dt * 26;
            P.movement.x = (float)cos(P.heading - half_pi) * speed * 15;
            P.movement.y = (float)sin(P.heading - half_pi) * speed * 15;
            P.position.x -= frame_dt * P.movement.x;
            P.position.y -= frame_dt * P.movement.y;
        }
    } else {
        float target = -1;
        if (direction_key(2)) target = 4.712389f;
        if (direction_key(3)) target = 1.57079637f;
        if (direction_key(0)) {
            if (!direction_key(2))
                target = !direction_key(3) ? 0.f : .785398185f;
            else
                target = 5.4977875f;
        }
        if (direction_key(1)) {
            if (!direction_key(2))
                target = !direction_key(3) ? 3.14159274f : 2.3561945f;
            else
                target = 3.926991f;
        }
        if (target != -1) {
            float turn = player_heading_approach_target(target);
            accelerate();
            turn = pi - turn;
            P.movement.x = (float)(cos(P.heading - half_pi) * P.move_speed) * turn * speed * 7.957747f;
            P.movement.y = (float)(sin(P.heading - half_pi) * P.move_speed) * turn * speed * 7.957747f;
        } else {
            decelerate();
            P.movement.x = (float)(cos(P.heading - half_pi) * P.move_speed) * speed * 25;
            P.movement.y = (float)(sin(P.heading - half_pi) * P.move_speed) * speed * 25;
        }
        P.position.x += frame_dt * P.movement.x;
        P.position.y += frame_dt * P.movement.y;
        P.walk_phase += frame_dt * P.move_speed * 19;
    }
#else
#if FREEWARE_EDITION >= 10400
    vec2f_t still = {0, 0};
    P.movement = still;
#endif
    const int scheme = config_movement_schemes[current_player_index];
    if (scheme == 1) {
        bool turning = false;
        if (P.turn_speed < 1) P.turn_speed = 1;
        if (P.turn_speed > 7) P.turn_speed = 7;
        if (!direction_key(2)) {
            if (direction_key(3)) {
#if FREEWARE_EDITION == 10300
                float turn_speed = P.turn_speed + frame_dt * 10.f;
                P.turn_speed = turn_speed;
                P.heading = P.heading + turn_speed * frame_dt * .5f;
#else
                P.turn_speed += frame_dt * 10.f;
                P.heading += P.turn_speed * frame_dt * .5f;
#endif
                turning = true;
            }
        } else {
#if FREEWARE_EDITION == 10300
            float turn_speed = P.turn_speed + frame_dt * 10.f;
            P.turn_speed = turn_speed;
            P.heading = P.heading - turn_speed * frame_dt * .5f;
#else
            P.turn_speed += frame_dt * 10.f;
            P.heading -= P.turn_speed * frame_dt * .5f;
#endif
            turning = true;
        }
        if (!direction_key(0)) {
            if (!turning) P.turn_speed = 1;
            decelerate();
            move_forward(speed);
        } else {
            accelerate();
            move_forward(speed);
        }
        P.walk_phase += frame_dt * P.move_speed * 19;
        if (direction_key(1)) {
            P.walk_phase += frame_dt * 26;
            move_back(speed);
        }
    } else if (scheme == 2 || scheme == 3) {
        float target = -1;
        if (scheme == 2) {
            if (direction_key(2)) target = 4.712389f;
            if (direction_key(3)) target = 1.57079637f;
            if (direction_key(0)) {
                if (!direction_key(2))
                    target = !direction_key(3) ? 0.f : .785398185f;
                else
                    target = 5.4977875f;
            }
            if (direction_key(1)) {
                if (!direction_key(2))
                    target = !direction_key(3) ? 3.14159274f : 2.3561945f;
                else
                    target = 3.926991f;
            }
        } else {
            if (input_move_left_active()) target = 4.712389f;
            if (input_move_right_active()) target = 1.57079637f;
            if (input_move_up_active()) {
                if (input_move_left_active())
                    target = 5.4977875f;
                else
                    target = input_move_right_active() ? .785398185f : 0.f;
            }
            if (input_move_down_active()) {
                if (input_move_left_active())
                    target = 3.926991f;
                else
                    target = input_move_right_active() ? 2.3561945f : 3.14159274f;
            }
        }
        if (target != -1) {
            float turn = player_heading_approach_target(target);
            accelerate();
            move_forward(speed, pi - turn, 7.957747f);
        } else {
            decelerate();
            move_forward(speed);
            P.spread -= frame_dt;
            if (P.spread < .25f) P.spread = .25f;
        }
        P.walk_phase += frame_dt * P.move_speed * 19;
    }
#endif
    if (P.perks[perk_id_sharpshooter] > 0) {
        P.spread -= frame_dt * 2;
        if (P.spread < .25f) P.spread = .25f;
#if FREEWARE_EDITION != 10002
        P.spread = 0;
#endif
    } else {
        P.spread -= frame_dt;
        if (P.spread < .5f) P.spread = .5f;
    }
    if (FREEWARE_EDITION != 10002 && P.perks[perk_id_anxious_loader] && CLICK(0) && P.reload > 0) {
        P.reload -= .05f;
        if (P.reload <= 0) P.reload = frame_dt * .8f;
    }
    if (P.reload - frame_dt < 0 && P.reload > 0) P.ammo = P.clip_size;
    P.reload -= frame_dt;
    if (P.reload < 0) P.reload = 0;
    if ((KEY(0x13) || MOUSE(2)) && P.reload == 0) start_reload();
#if FREEWARE_EDITION == 10002
    // 0x408cc8 writes both the world reticle and the unadjusted screen cursor while left Ctrl is held.
    if (KEY(0x1d)) {
        float angle = P.heading - half_pi;
        vec2f_t offset = {(float)cos(angle), (float)sin(angle)};
        offset.x *= 60;
        offset.y *= 60;
        offset.x += P.position.x;
        offset.y += P.position.y;
        P.aim = offset;
        freeware_aim_screen = offset;
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    // The portable renderer also needs a heading between shots.
    P.aim_heading = (float)(atan2((double)P.position.y - freeware_aim_screen.y + freeware_camera.y,
                                  (double)P.position.x - freeware_aim_screen.x + freeware_camera.x) -
                            half_pi);
#endif
    if (P.cooldown <= 0 && P.reload == 0) {
        vec2f_t offset = P.position - freeware_aim_screen;
        offset = offset + freeware_camera;
        float shot_heading = (float)(atan2(offset.y, offset.x) - half_pi);
        if (KEY(0x1d) || KEY(0x9d) || KEY(0x1c) || MOUSE(0)) fire(shot_heading);
    }
#else
    const int keyboard_aim = FREEWARE_EDITION == 10300 ? 1 : 2;
    const int pad_aim = FREEWARE_EDITION == 10300 ? 2 : 3;
    if (config_aim_schemes[current_player_index] == 0) {
        P.aim = freeware_aim_screen - freeware_camera;
        P.aim_heading = aim_angle();
#if FREEWARE_EDITION >= 10400
    } else if (config_aim_schemes[current_player_index] == 1) {
        vec2f_t direction = {freeware_aim_screen.x - 200.f, freeware_aim_screen.y - 200.f};
        if (direction.x != 0.f || direction.y != 0.f) {
            P.aim_heading = (float)atan2(direction.y, direction.x) + half_pi;
            aim_along(P.aim_heading - half_pi);
        }
        float length = aim_length(direction.x, direction.y);
        if (length > 30.f) {
            freeware_aim_screen = (direction * (1.f / length)) * 30.f + player_vec2_t(200.f, 200.f);
        }
#endif
    } else if (config_aim_schemes[current_player_index] == keyboard_aim) {
        if (config_movement_schemes[current_player_index] == 1) {
            P.aim_heading = aim_angle();
            P.aim_heading = P.heading + .5235988f;
            aim_along(P.aim_heading - half_pi);
        } else {
            aim_along(P.aim_heading - half_pi);
        }
    } else {
        if (input_aim_pov_left_active()) P.aim_heading -= frame_dt * 4.f;
        if (input_aim_pov_right_active()) P.aim_heading += frame_dt * 4.f;
        aim_along(P.aim_heading - half_pi);
    }
    P.aim_heading = aim_angle();
    if (config_movement_schemes[current_player_index] == 2 &&
        (EDGE(P.keys[4]) || (config_player_count == 1 && EDGE(PLAYER(1).keys[4]))) &&
        (FREEWARE_EDITION != 10300 || config_aim_schemes[current_player_index] != 0)) {
        aim_along(P.heading - half_pi);
        P.aim_heading = aim_angle();
    }
    if (P.cooldown <= 0 && P.reload == 0) {
        // Input polling can update the active player. The shot retains the pre-poll heading.
        float heading = P.aim_heading;
        if (KEY(P.keys[4]) ||
            (FREEWARE_EDITION != 10300 && config_aim_schemes[current_player_index] == 1 && MOUSE(0)) ||
            (config_aim_schemes[current_player_index] == 0 && MOUSE(0)) ||
            (config_aim_schemes[current_player_index] == pad_aim && PAD_FIRE())) {
#include "freeware_player_fire.inc"
        }
    }
#endif
    while (P.walk_phase > 14)
        P.walk_phase -= 14;
    float radius = P.size * .5f;
    if (P.position.x < radius)
        P.position.x = radius;
    if (P.position.x > freeware_arena_width - radius)
        P.position.x = freeware_arena_width - radius;
    if (P.position.y < radius)
        P.position.y = radius;
    if (P.position.y > freeware_arena_height - radius)
        P.position.y = freeware_arena_height - radius;
    if (FREEWARE_EDITION != 10002 && P.muzzle_flash > .8f)
        P.muzzle_flash = .8f;
}
