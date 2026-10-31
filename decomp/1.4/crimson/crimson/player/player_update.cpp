// crimson.exe 1.4.0, 0x4126e0..0x41568a.
#include "crimsonland_types.h"
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
extern player_state_t player_state_table[2];
extern creature_t creature_pool[512];
extern projectile_pool_t projectile_pool;
extern particle_t particle_pool[128];
extern sprite_effect_t sprite_effect_pool[384];
extern game_mode_id_t config_game_mode;
extern int current_player_index, config_player_count, config_movement_schemes[2], config_aim_schemes[2];
extern int freeware_arena_width, freeware_arena_height, highscore_record_shots_fired, freeware_first_kill_xp;
extern unsigned char console_open_flag, freeware_player_moved, freeware_secret_weapon_unlocked,
    freeware_rainbow_enabled, freeware_rainbow_armed, time_scale_active;
extern float frame_dt, freeware_elapsed_seconds, freeware_berserk_timer, bonus_reflex_boost_timer,
    time_scale_factor, freeware_fade_time;
extern vec2f_t freeware_first_kill_position, freeware_aim_screen, freeware_camera;
extern int perk_id_long_distance_runner, perk_id_sharpshooter, perk_id_ammo_maniac, perk_id_fastshot,
    perk_id_anxious_loader;
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
const float pi = 3.14159274f, quarter = .785398185f, half = 1.57079637f;
#define P player_state_table[current_player_index].freeware
__forceinline float distance(vec2f_t a, vec2f_t b) {
    double dx = (double)a.x - b.x, dy = (double)a.y - b.y;
    return (float)sqrt(dx * dx + dy * dy);
}
__forceinline bool direction_key(int key) {
    return KEY(P.keys[key]) || (config_player_count == 1 && KEY(player_state_table[1].freeware.keys[key]));
}
__forceinline void accelerate() {
    if (P.perks[perk_id_long_distance_runner] > 0) {
        if (P.move_speed < 2)
            P.move_speed += frame_dt * 4;
        P.move_speed += frame_dt;
        if (P.move_speed > 2.8f)
            P.move_speed = 2.8f;
    } else {
        P.move_speed += frame_dt * 5;
        if (P.move_speed > 2)
            P.move_speed = 2;
    }
    if (P.weapon == 13 && P.move_speed > .8f)
        P.move_speed = .8f;
}
__forceinline void decelerate() {
    P.move_speed -= frame_dt * 15;
    if (P.move_speed < 0)
        P.move_speed = 0;
}
struct level_map_t {
    int move_with_collision(vec2f_t *pos, const vec2f_t *delta, float radius);
};
extern "C" level_map_t *freeware_level_map;
__forceinline void move(double speed) {
    P.movement.x = (float)(cos((double)P.heading - half) * speed);
    P.movement.y = (float)(sin((double)P.heading - half) * speed);
    vec2f_t delta = {frame_dt * P.movement.x, frame_dt * P.movement.y};
#ifdef CRIMSON_FREEWARE_CLIENT
    // Career and Survival both initialize the level with an empty wall list (0x408440).
    P.position.x += delta.x;
    P.position.y += delta.y;
#else
    freeware_level_map->move_with_collision(&P.position, &delta, 8.f);
#endif
}
__forceinline float aim_angle() {
    return (float)(atan2((double)P.position.y - P.aim.y, (double)P.position.x - P.aim.x) - half);
}
__forceinline void aim_along(double angle) {
    P.aim.x = P.position.x + (float)cos(angle) * 60.f;
    P.aim.y = (float)(P.position.y + sin(angle) * 60.f);
}
__forceinline void smoke(vec2f_t muzzle, vec2f_t dir, float speed, float scale, float alpha) {
    vec2f_t vel = {dir.x * speed, dir.y * speed};
    sprite_effect_t &s = sprite_effect_pool[fx_spawn_sprite(&muzzle, &vel, scale)];
    s.color.r = s.color.g = s.color.b = .5f;
    s.color.a = alpha;
}
__forceinline void smoke_pair(vec2f_t muzzle, vec2f_t dir, float a, float b) {
    smoke(muzzle, dir, 25, 1, a);
    smoke(muzzle, dir, 15, 2, b);
}
__forceinline float jitter(int range, float factor) {
    return (float)((crt_rand() % range - range / 2) * (double)P.spread * factor + P.aim_heading);
}
__forceinline void pellets(vec2f_t muzzle, int count, int type, float factor) {
    do {
        int slot =
            projectile_spawn(&muzzle, (float)((crt_rand() % 200 - 100) * (double)factor + P.aim_heading), type);
        projectile_pool[slot].fields.speed_scale = (crt_rand() % 100) * .01f + 1;
    } while (--count);
}
__forceinline void shot_sound(int id) { sfx_play_panned(id, .45f, .5f); }
__forceinline void eject(vec2f_t shell, int sound, float cooldown, float flash) {
    shot_sound(sound);
    fx_queue_add_shell(&shell);
    P.cooldown = cooldown;
    P.muzzle_flash += flash;
}
__forceinline bool fire() {
    const float heading = P.aim_heading;
    const double angle = (double)heading - half - .150915f;
    vec2f_t muzzle = {P.position.x + (float)(cos(angle) * 16), P.position.y + (float)(sin(angle) * 16)};
    vec2f_t dir = {(float)cos(heading), (float)sin(heading)};
    vec2f_t shell;
    shell.x = P.position.x + (crt_rand() % 10) * dir.x * .5f;
    shell.y = P.position.y + (crt_rand() % 10) * dir.y * .5f;
    if (P.muzzle_flash > 1)
        P.muzzle_flash = 1;
    float ammo = 1;
    if (P.weapon == 1) {
        projectile_spawn(&muzzle, jitter(200, .001f), 4);
        smoke_pair(muzzle, dir, .23f, .213f);
        eject(shell, 2, .7117f, .22f);
    } else if (P.weapon == 2) {
        smoke_pair(muzzle, dir, .23f, .213f);
        projectile_spawn(&muzzle, jitter(200, .001f), 1);
        eject(shell, 7, .117f, .07f);
    } else if (P.weapon == 3) {
        smoke_pair(muzzle, dir, .25f, .223f);
        pellets(muzzle, 12, 2, .0013f);
        eject(shell, 15, .688117f, .12f);
    } else if (P.weapon == 4) {
        smoke_pair(muzzle, dir, .26f, .233f);
        pellets(muzzle, 12, 2, .0033f);
        eject(shell, 15, .788117f, .12f);
    } else if (P.weapon == 5) {
        fx_spawn_particle(&muzzle, heading - half, &P.movement, 1);
        shot_sound(14);
        ammo = .1f;
        P.cooldown = .008113f;
    } else if (P.weapon == 15) {
        int slot = fx_spawn_particle(&muzzle, heading - half, &P.movement, 1);
        if (slot != -1)
            particle_pool[slot].style_id = 1;
        shot_sound(14);
        ammo = .05f;
        P.cooldown = .006113f;
    } else if (P.weapon == 6) {
        smoke_pair(muzzle, dir, .23f, .213f);
        projectile_spawn(&muzzle, jitter(20, .003f), 2);
        eject(shell, 26, .088117f, .082f);
    } else if (P.weapon == 7) {
        projectile_spawn(&muzzle, jitter(20, .003f), 7);
        eject(shell, 8, .290812f, .182f);
    } else if (P.weapon == 8) {
        projectile_spawn(&muzzle, jitter(20, .003f) - .31415927f, 7);
        projectile_spawn(&muzzle, jitter(20, .003f), 7);
        projectile_spawn(&muzzle, jitter(20, .003f) + .31415927f, 7);
        eject(shell, 8, .640812f, .32f);
    } else if (P.weapon == 9) {
        projectile_spawn(&muzzle, jitter(20, .003f), 9);
        eject(shell, 12, .109081f, .097f);
    } else if (P.weapon == 10) {
        smoke_pair(muzzle, dir, .33f, .263f);
        projectile_spawn(&muzzle, jitter(20, .003f), 10);
        eject(shell, 8, .950812f, .42f);
    } else if (P.weapon == 11) {
        smoke_pair(muzzle, dir, .34f, .283f);
        fx_spawn_secondary_projectile(&muzzle, jitter(20, .003f), (secondary_projectile_type_id_t)1);
        shot_sound(20);
        P.cooldown = .740812f;
        P.muzzle_flash += .42f;
    } else if (P.weapon == 12) {
        smoke_pair(muzzle, dir, .31f, .243f);
        fx_spawn_secondary_projectile(&muzzle, jitter(20, .003f), (secondary_projectile_type_id_t)2);
        shot_sound(20);
        P.cooldown = .310812f;
        P.muzzle_flash += .42f;
    } else if (P.weapon == 13) {
        projectile_spawn(&muzzle, jitter(20, .012f), 4);
        eject(shell, 26, .07f, .062f);
    } else if (P.weapon == 14) {
        pellets(muzzle, 14, 9, .0013f);
        eject(shell, 15, .288117f, .1f);
    } else if (P.weapon == 17 && freeware_secret_weapon_unlocked) {
        projectile_spawn(&muzzle, jitter(20, .012f), 17);
        eject(shell, 8, .2f, .04f);
    } else if (P.weapon == 18 && freeware_secret_weapon_unlocked) {
        if (!freeware_rainbow_enabled || !freeware_rainbow_armed || P.health >= 5)
            return false;
        shot_sound(8);
        if (P.health >= 5)
            return false;
        fx_queue_add_shell(&shell);
        P.cooldown = .2f;
        P.muzzle_flash += .09f;
        if (P.health >= 5)
            return false;
        projectile_spawn(&muzzle, jitter(20, .012f), 18);
    } else if (P.weapon == 19) {
        fx_spawn_particle_slow(&muzzle, heading - half, 0);
        ammo = .15f;
        P.cooldown = .1613f;
    }
    if (P.perks[perk_id_sharpshooter] < 1)
        P.spread += time_scale_factor * frame_dt * 150;
    if (P.spread > time_scale_factor * 2)
        P.spread = time_scale_factor * 2;
    P.spread *= time_scale_factor;
    if (P.perks[perk_id_ammo_maniac] > 0)
        ammo *= .8f;
    P.ammo -= ammo;
    if (P.perks[perk_id_fastshot] > 0)
        P.cooldown *= .88f;
    if (P.perks[perk_id_sharpshooter] > 0)
        P.cooldown *= 1.05f;
    if (P.ammo <= 0)
        player_start_reload();
    return true;
}
} // namespace

extern "C" void player_update() {
    if (console_open_flag)
        return;
    if (KEY(P.keys[0]) || KEY(P.keys[1]) || KEY(P.keys[2]) || KEY(P.keys[3]))
        freeware_player_moved = 1;
    if (config_player_count == 1 && config_game_mode == 1) {
        if (P.health < 100 && distance(P.position, freeware_first_kill_position) >= 48)
            freeware_first_kill_xp = -10;
        if (distance(P.position, freeware_first_kill_position) < 48 && P.health < 5 &&
            P.experience == freeware_first_kill_xp) {
            freeware_secret_weapon_unlocked = freeware_rainbow_armed = freeware_rainbow_enabled = 1;
            if (P.weapon != 18)
                weapon_assign_player(0, 18);
        }
        if (P.experience == 0 && freeware_elapsed_seconds >= 120 && !highscore_record_shots_fired &&
            player_state_table[0].freeware.health == 100) {
            P.experience = 1;
            freeware_secret_weapon_unlocked = freeware_rainbow_armed = freeware_rainbow_enabled = 1;
            weapon_assign_player(0, 19);
        }
    }
    if (P.health <= 0)
        return;
    P.muzzle_flash -= frame_dt * 2;
    if (P.muzzle_flash < 0)
        P.muzzle_flash = 0;
    P.cooldown -= frame_dt;
    if (P.cooldown < 0)
        P.cooldown = 0;
    if (freeware_berserk_timer > 10) {
        if (P.cooldown != 0)
            return;
        for (int i = 0; i < 50; ++i) {
            creature_t &c = creature_pool[crt_rand() % 512];
            if (c.active && distance(P.position, c.position) < 500) {
                P.aim = c.position;
                break;
            }
        }
        P.aim_heading = aim_angle();
        double angle = (double)P.aim_heading - half - .25f;
        vec2f_t muzzle = {P.position.x + (float)(12 * cos(angle)), (float)(P.position.y + 12 * sin(angle))};
        projectile_spawn(&muzzle, P.aim_heading, 1);
        shot_sound(7);
        P.cooldown = .1f;
        return;
    }
    if (bonus_reflex_boost_timer > 0) {
        time_scale_factor -= frame_dt;
        if (time_scale_factor < .3f)
            time_scale_factor = .3f;
    } else {
        time_scale_factor += frame_dt * .8f;
        if (time_scale_factor > 1)
            time_scale_factor = 1;
    }
    if (time_scale_active) {
        freeware_fade_time += frame_dt * .8f;
        if (freeware_fade_time > 1.5f)
            time_scale_active = 0;
    }
    float speed = P.speed_multiplier;
    P.movement.x = P.movement.y = 0;
    int scheme = config_movement_schemes[current_player_index];
    if (scheme == 1) {
        bool turning = false;
        if (P.turn_speed < 1)
            P.turn_speed = 1;
        if (P.turn_speed > 7)
            P.turn_speed = 7;
        if (direction_key(2)) {
            P.turn_speed += frame_dt * 10;
            P.heading -= P.turn_speed * frame_dt * .5f;
            turning = true;
        } else if (direction_key(3)) {
            P.turn_speed += frame_dt * 10;
            P.heading += P.turn_speed * frame_dt * .5f;
            turning = true;
        }
        if (direction_key(0))
            accelerate();
        else {
            if (!turning)
                P.turn_speed = 1;
            decelerate();
        }
        move((double)speed * P.move_speed * 25);
        P.walk_phase += frame_dt * P.move_speed * 19;
        if (direction_key(1)) {
            P.walk_phase += frame_dt * 26;
            move(speed * -15.f);
        }
    } else if (scheme == 2 || scheme == 3) {
        float target = -1;
        bool left = scheme == 2 ? direction_key(2) : input_move_left_active();
        bool right = scheme == 2 ? direction_key(3) : input_move_right_active();
        bool up = scheme == 2 ? direction_key(0) : input_move_up_active();
        bool down = scheme == 2 ? direction_key(1) : input_move_down_active();
        if (left)
            target = 4.712389f;
        if (right)
            target = half;
        if (up)
            target = left ? 5.4977875f : right ? quarter : 0.f;
        if (down)
            target = left ? 3.926991f : right ? 2.3561945f : pi;
        if (target != -1) {
            float turn = player_heading_approach_target(target);
            accelerate();
            move(((double)pi - turn) * speed * P.move_speed * 7.957747f);
        } else {
            decelerate();
            move((double)speed * P.move_speed * 25);
            P.spread -= frame_dt;
            if (P.spread < .25f)
                P.spread = .25f;
        }
        P.walk_phase += frame_dt * P.move_speed * 19;
    }
    if (P.perks[perk_id_sharpshooter] < 1) {
        P.spread -= frame_dt;
        if (P.spread < .5f)
            P.spread = .5f;
    } else
        P.spread = 0;
    if (P.perks[perk_id_anxious_loader] && CLICK(0) && P.reload > 0) {
        P.reload -= .05f;
        if (P.reload <= 0)
            P.reload = frame_dt * .8f;
    }
    if (P.reload - frame_dt < 0 && P.reload > 0)
        P.ammo = P.clip_size;
    P.reload -= frame_dt;
    if (P.reload < 0)
        P.reload = 0;
    if ((KEY(0x13) || MOUSE(2)) && P.reload == 0)
        player_start_reload();
    int aim = config_aim_schemes[current_player_index];
    if (aim == 0) {
        P.aim.x = freeware_aim_screen.x - freeware_camera.x;
        P.aim.y = freeware_aim_screen.y - freeware_camera.y;
    } else if (aim == 1) {
        double x = (double)freeware_aim_screen.x - 200, y = (double)freeware_aim_screen.y - 200;
        if (x != 0 || y != 0)
            aim_along(atan2(y, x));
        double length = sqrt(x * x + y * y);
        if (length > 30) {
            freeware_aim_screen.x = 200 + (float)(x / length) * 30.f;
            freeware_aim_screen.y = (float)(200 + y / length * 30);
        }
    } else if (aim == 2) {
        if (scheme == 1)
            aim_along((double)P.heading + .5235988f - half);
        else
            aim_along((double)P.aim_heading - half);
    } else {
        if (input_aim_pov_left_active())
            P.aim_heading -= frame_dt * 4;
        if (input_aim_pov_right_active())
            P.aim_heading += frame_dt * 4;
        aim_along((double)P.aim_heading - half);
    }
    P.aim_heading = aim_angle();
    if (scheme == 2 &&
        (EDGE(P.keys[4]) || (config_player_count == 1 && EDGE(player_state_table[1].freeware.keys[4])))) {
        aim_along((double)P.heading - half);
        P.aim_heading = aim_angle();
    }
    if (P.cooldown <= 0 && P.reload == 0 &&
        (KEY(P.keys[4]) || (aim == 1 && MOUSE(0)) || (aim == 0 && MOUSE(0)) || (aim == 3 && PAD_FIRE())))
        if (!fire())
            return;
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
    if (P.muzzle_flash > .8f)
        P.muzzle_flash = .8f;
}
