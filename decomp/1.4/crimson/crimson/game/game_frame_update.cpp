// crimson.exe 1.4.0, 0x418190. The camera and the secret flags consume the
// gameplay CRT stream between the early combat pass and the state dispatch.
#include "freeware_level.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#ifndef _MSC_VER
#define __forceinline inline
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
#include "game.h"
extern freeware::Game *freeware_frame_game;
extern const freeware::Input *freeware_frame_input;
extern float freeware_frame_delta;
#define G (*freeware_frame_game)
#define INPUT (*freeware_frame_input)
#define FIELD(native, client) (G.client)
#else
#include "crimsonland_console.h"
#include "grim2d_cpp.h"
extern "C" IGrim2D_cpp *grim_interface_ptr;
#define FIELD(native, client) (native)
#endif

extern "C" {
extern player_state_t player_state_table[2];
extern creature_t creature_pool[512];
extern int current_player_index, config_player_count, config_aim_schemes[2], freeware_arena_width,
    freeware_arena_height;
extern int perk_id_reflex_boosted, perk_id_lean_mean_exp_machine, perk_id_final_revenge, perk_id_jinxed,
    perk_id_spontaneously_combusteous, perk_id_evil_eyes, perk_id_berserk_attack;
extern int perk_id_see_health;
extern game_mode_id_t config_game_mode;
extern unsigned char console_open_flag, time_scale_active, freeware_spawn_enabled, freeware_game_active,
    freeware_rainbow_armed, freeware_rainbow_enabled, freeware_secret_weapon_unlocked;
extern float frame_dt, freeware_simulation_clock, freeware_elapsed_seconds, time_scale_factor, freeware_fade_time,
    bonus_reflex_boost_timer, bonus_fire_bullets_timer, bonus_freeze_timer, freeware_berserk_timer;
extern vec2f_t freeware_aim_screen, freeware_camera;
int crt_rand();
void player_update(), player_check_level(), creature_update_all(), creature_reset_all(), projectile_update(),
    perks_generate_choices();
void weapon_assign_player(int, int);
int creature_spawn(const vec2f_t *, const effect_color_t *, int);
unsigned char creature_spawn_random(const vec2f_t *);
int creature_find_in_radius(const vec2f_t *, float);
int fx_spawn_particle(const vec2f_t *, float, const vec2f_t *, float);
int sfx_play_panned(int, float, float);
void fx_queue_add_random(const vec2f_t *);
void fx_queue_render(), terrain_render(), projectile_render(), effect_render_all(), player_render(),
    gameplay_render_hud(), game_show_message(), perk_selection_screen_update(), creature_render_all();
unsigned char freeware_overlay_begin(), game_highscores_update(), game_credits_update();

#ifndef CRIMSON_FREEWARE_CLIENT
extern console_queue_t freeware_console;
extern IGrim2D_cpp *freeware_console_grim;
extern float freeware_mouse_dx, freeware_mouse_dy, frame_dt_copy, freeware_real_clock;
extern char freeware_ui_buffer[256];
extern int game_state_id, freeware_pending_perks, freeware_pickup_id, freeware_no_pickup, screen_width,
    screen_height, screenshot_file_index, freeware_fps_count;
extern float freeware_xp_timer, freeware_pickup_time, freeware_next_spawn, freeware_jinx_timer,
    freeware_revive_timer, freeware_camera_timer, freeware_bomb_age, freeware_state_since, freeware_fps_min,
    freeware_fps_max, freeware_fps[50];
extern vec2f_t freeware_camera_shake, freeware_bomb_position;
extern unsigned char freeware_random_flags[8], quit_requested;
void player_render(), gameplay_render_hud(), terrain_render(), fx_queue_render(), projectile_render(),
    effect_render_all(), creature_render_all(), gameplay_reset_state(), sfx_update();
#endif
}

extern "C" {
#ifndef CRIMSON_FREEWARE_CLIENT
extern unsigned char freeware_transition_pending, freeware_safe_mode;
extern float freeware_transition_alpha;

#endif
}
namespace frame_update140 {
#define P(i) player_state_table[i].freeware
#define XP FIELD(P(0).experience, run.experience)
#define PERK(i) FIELD(P(0).perks[i], run.perks[i])
#define HP(i) FIELD(P(i).health, actor(i).health)
#define POS(i) FIELD(P(i).position, actor(i).player)
#define SHIELD(i) FIELD(P(i).shield, actor(i).shield)
#define CLOCK freeware_simulation_clock
#define SCALE FIELD(time_scale_factor, run.speed_scale)
#define XP_TIMER FIELD(freeware_xp_timer, run.exp_clock)
#define SLOW FIELD(bonus_reflex_boost_timer, run.slow)
#define FREEZE FIELD(bonus_freeze_timer, run.freeze)
#define BERSERK FIELD(freeware_berserk_timer, run.berserk)
#define PICKUP_TIME FIELD(freeware_pickup_time, run.pickup.time)
#define SECONDS FIELD(freeware_elapsed_seconds, run.seconds)
#define SPAWN_TIMER FIELD(freeware_next_spawn, run.next_spawn)
#define JINX FIELD(freeware_jinx_timer, run.jinx)
#define REVIVE FIELD(freeware_revive_timer, run.plague_time)
#define BOMB FIELD(freeware_bomb_age, run.bomb_age)
#define BOMB_POS FIELD(freeware_bomb_position, run.bomb_pos)
#define CAM FIELD(freeware_camera, camera)
#define SHAKE FIELD(freeware_camera_shake, camera_shake)
#define SHAKE_TIME FIELD(freeware_camera_timer, camera_timer)
#define STATE_SINCE FIELD(freeware_state_since, state_since)
#define ACTIVE FIELD(freeware_game_active, active_run)
#define PENDING FIELD(freeware_pending_perks, run.pending)
#ifdef CRIMSON_FREEWARE_CLIENT
const int screen_width = freeware::width, screen_height = freeware::height;
__forceinline int state() { return G.frame_state(); }
__forceinline void enter(int id) { G.enter_state(id); }
__forceinline void creatures() { G.update_creatures(frame_dt); }
__forceinline void shots() { G.update_projectiles(frame_dt); }
__forceinline void player() {
    vec2f_t world = {G.cursor_x - CAM.x, G.cursor_y - CAM.y};
    G.step_player(current_player_index, frame_dt, INPUT, world);
}
__forceinline bool open_perk() {
    return INPUT.level_up || INPUT.perk_button || (G.aiming[0] == 3 && INPUT.pad_perk[0]) ||
           (INPUT.click && G.cursor_x > screen_width - 240 && G.cursor_x < screen_width + 17 &&
            G.cursor_y > screen_height - 50 && G.cursor_y < screen_height + 1);
}
__forceinline void level_check() { G.check_level(); }
__forceinline void open_choices() { G.open_perks(); }
__forceinline void hud() { gameplay_render_hud(); }
#else
__forceinline int state() { return game_state_id; }
__forceinline void enter(int id) { game_state_id = id; }
__forceinline void creatures() { creature_update_all(); }
__forceinline void shots() { projectile_update(); }
__forceinline void player() { player_update(); }
__forceinline bool open_perk() {
    return grim_interface_ptr->grim_is_key_down(0x4e) || grim_interface_ptr->grim_is_key_down(0x39) ||
           grim_interface_ptr->grim_was_mouse_button_pressed(1) ||
           (config_aim_schemes[current_player_index] == 3 &&
            grim_interface_ptr->grim_is_joystick_button_down(1)) ||
           (freeware_aim_screen.x > screen_width - 240 && freeware_aim_screen.x < screen_width + 17 &&
            freeware_aim_screen.y > screen_height - 50 && freeware_aim_screen.y < screen_height + 1 &&
            grim_interface_ptr->grim_was_mouse_button_pressed(0));
}
__forceinline void level_check() { player_check_level(); }
__forceinline void open_choices() { perks_generate_choices(); }
__forceinline void hud() { gameplay_render_hud(); }
#endif

__forceinline void request_transition() {
    FIELD(freeware_transition_pending, transition_pending) = 1;
    FIELD(freeware_transition_alpha, transition_alpha) = 1;
}
__forceinline void begin_overlay() { freeware_overlay_begin(); }
__forceinline void simulate_players() {
    XP_TIMER -= frame_dt;
    if (XP_TIMER < 0) {
        XP_TIMER = .25f;
        if (PERK(perk_id_lean_mean_exp_machine) > 0)
            XP += PERK(perk_id_lean_mean_exp_machine) * 10;
    }
    creatures();
    shots();
    if (PENDING > 0 && config_game_mode != 2 && open_perk()) {
        enter(4);
        open_choices();
        request_transition();
        STATE_SINCE = CLOCK;
    } else {
        for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index)
            if (HP(current_player_index) > 0)
                player();
    }
    current_player_index = 0;
    level_check();
}
__forceinline float shake(float value) { return (float)(value * .125 * (crt_rand() % 200 - 100) * .15f); }
__forceinline void position_camera() {
    if (config_game_mode == 4 && state() == 3) {
        CAM.x = screen_width / 2 -
                FIELD(freeware_aim_screen.x, cursor_x) / (screen_width * .8f) * freeware_arena_width;
        CAM.y = screen_height / 2 -
                FIELD(freeware_aim_screen.y, cursor_y) / (screen_height * .8f) * freeware_arena_height;
    } else {
        vec2f_t target = POS(0);
        if (config_player_count != 1) {
            if (HP(0) <= 0)
                target = POS(1);
            else if (HP(1) > 0) {
                target.x -= (target.x - POS(1).x) * .5f;
                target.y -= (target.y - POS(1).y) * .5f;
            }
        }
        CAM.x = screen_width / 2 - target.x;
        CAM.y = screen_height / 2 - target.y;
    }
    SHAKE_TIME -= frame_dt;
    if (SHAKE_TIME <= 0) {
        SHAKE_TIME = .061f;
        SHAKE.x = shake(SHAKE.x);
        SHAKE.y = shake(SHAKE.y);
        if (sqrt((double)SHAKE.x * SHAKE.x + (double)SHAKE.y * SHAKE.y) < 5) {
            SHAKE.x = shake(SHAKE.x);
            SHAKE.y = shake(SHAKE.y);
        }
    }
    CAM.x += SHAKE.x;
    CAM.y += SHAKE.y;
    if (CAM.x > -1)
        CAM.x = -1;
    if (CAM.y > -1)
        CAM.y = -1;
    if (CAM.x < screen_width - freeware_arena_width)
        CAM.x = (float)(screen_width - freeware_arena_width);
    if (CAM.y < screen_height - freeware_arena_height)
        CAM.y = (float)(screen_height - freeware_arena_height);
}
__forceinline void render_world() {
    terrain_render();
#ifdef CRIMSON_FREEWARE_CLIENT
    G.terrain_sprites.swap(G.frame_sprites);
    G.presented_terrain_revision = G.terrain_revision;
#endif
    fx_queue_render();
    creature_render_all();
    if (ACTIVE) {
        if (SLOW <= 0)
            SLOW = 0;
        else {
            SLOW -= frame_dt;
            if (SLOW <= 0) {
                time_scale_active = 1;
                freeware_fade_time = 0;
                SLOW = -.01f;
            }
        }
        for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
            if (HP(current_player_index) <= 0)
                continue;
            if (state() == 3) {
                if (SHIELD(current_player_index) <= 0)
                    SHIELD(current_player_index) = 0;
                else
                    SHIELD(current_player_index) -= frame_dt;
            }
            player_render();
        }
    }
    current_player_index = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
    G.actor_sprites.swap(G.frame_sprites);
#endif
    projectile_render();
    freeware_current_map->render_layer(1, 0);
    freeware_current_map->render_triggers(1);
    effect_render_all();
    freeware_current_map->render_layer(2, 0);
#ifdef CRIMSON_FREEWARE_CLIENT
    G.effect_sprites.swap(G.frame_sprites);
    G.effect_labels.swap(G.frame_labels);
#endif
}
__forceinline void spawn_edge() {
    for (int attempt = 0; attempt < 100; ++attempt) {
        vec2f_t p;
        switch (crt_rand() % 4) {
        case 0:
            p.x = (float)(crt_rand() % freeware_arena_width);
            p.y = -40;
            break;
        case 1:
            p.x = (float)(crt_rand() % freeware_arena_width);
            p.y = (float)(freeware_arena_height + 40);
            break;
        case 2:
            p.x = -40;
            p.y = (float)(crt_rand() % freeware_arena_height);
            break;
        default:
            p.x = (float)(freeware_arena_width + 40);
            p.y = (float)(crt_rand() % freeware_arena_height);
            break;
        }
        if (creature_spawn_random(&p))
            break;
    }
}
__forceinline float saturate(float x) {
    if (x < 0)
        return 0;
    if (x > 1)
        return 1;
    return x;
}
__forceinline void spawn_wave() {
#if defined(FREEWARE_EDITION) && FREEWARE_EDITION == 10002
    if (config_game_mode == 2)
        P(0).weapon = 2;
    SPAWN_TIMER -= frame_dt;
    if (SPAWN_TIMER < 0) {
        if (config_game_mode == 2) {
            // 0x40d861..0x40d967 attempts one spawn even on a long frame.
            SPAWN_TIMER = .01f;
            effect_color_t tint = {saturate(SECONDS / 120.f), saturate(10.f / SECONDS),
                                   saturate((float)sin(SECONDS * .1f)), 1};
            vec2f_t east = {(float)freeware_arena_width, freeware_arena_height * .5f};
            creature_spawn(&east, &tint, 1);
        } else if (freeware_spawn_enabled) {
            SPAWN_TIMER = 1.f - XP * .00001f;
            if (SPAWN_TIMER < .2f)
                SPAWN_TIMER = .2f;
            spawn_edge();
        }
    }
#else
    if (config_game_mode == 2) {
        P(0).weapon = P(1).weapon = 2;
        P(0).ammo = P(1).ammo = 30;
    }
    SPAWN_TIMER -= frame_dt * config_player_count;
    if (config_game_mode == 3)
        return;
    while (SPAWN_TIMER < 0) {
        if (config_game_mode == 2) {
            SPAWN_TIMER += .25f;
            effect_color_t tint = {saturate(SECONDS * .0083333338f + .3f), saturate(10.f / SECONDS + .3f),
                                   saturate((float)sin(SECONDS * .1f) + .3f), 1};
            vec2f_t right = {(float)(freeware_arena_width + 64),
                             (float)(freeware_arena_height * .5 + cos(SECONDS) * 256)};
            vec2f_t left = {-64, (float)(freeware_arena_height * .5 + sin(SECONDS) * 256)};
            creature_spawn(&right, &tint, 1);
            creature_spawn(&left, &tint, 1);
        } else if (freeware_spawn_enabled) {
            SPAWN_TIMER += 1.f - XP * .000016666667f;
            if (SPAWN_TIMER < .01f)
                SPAWN_TIMER = .01f;
            spawn_edge();
        } else
            break;
    }
#endif
}
__forceinline void die() {
    enter(6);
    STATE_SINCE = CLOCK;
#ifdef CRIMSON_FREEWARE_CLIENT
    G.death_clock = 0;
    std::printf(FREEWARE_VERSION " death %d kills %.2f seconds\n", G.run.kills, SECONDS);
#endif
}
__forceinline void deaths() {
    if (config_player_count == 1) {
        if (HP(0) <= 0) {
            if (REVIVE < 1 && (XP == 6 || XP == 66 || XP == 666 || XP == 6666)) {
                freeware_secret_weapon_unlocked = 1;
                HP(0) = 1;
                REVIVE += frame_dt * 10;
                weapon_assign_player(0, 17);
            } else {
                if (PERK(perk_id_final_revenge) > 0) {
                    BOMB_POS = POS(0);
                    BOMB = 0;
                    SHAKE.x = SHAKE.y = 10;
                    sfx_play_panned(21, .45f, .5f);
                }
                HP(0) = 0;
                die();
            }
        }
    } else if (HP(0) <= 0 && HP(1) <= 0) {
        HP(0) = HP(1) = 0;
        die();
    }
}
__forceinline void update_wave() {
    if (BOMB >= 0)
        BOMB += (BOMB + 1) * frame_dt * 1.8f;
}
__forceinline void label(const char *, float, float, float, float, float, float, float);
__forceinline void target_perks() {
    for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
        if (HP(current_player_index) <= 0 ||
            (P(current_player_index).perks[perk_id_spontaneously_combusteous] <= 0 &&
             P(current_player_index).perks[perk_id_evil_eyes] <= 0 &&
             P(current_player_index).perks[perk_id_see_health] <= 0))
            continue;
        int id = creature_find_in_radius(&P(current_player_index).aim, 10);
        if (id < 0)
            continue;
        creature_t &c = creature_pool[id];
        if (P(current_player_index).perks[perk_id_see_health] > 0) {
            char buf[40];
            sprintf(buf, "health %d", (int)c.health);
            label(buf, FIELD(freeware_aim_screen.x, cursor_x), FIELD(freeware_aim_screen.y, cursor_y) + 32, .5f, 1,
                  1, 1, .64f);
        }
        if (P(current_player_index).perks[perk_id_spontaneously_combusteous] > 0) {
            c.anim_phase -= frame_dt;
            if (c.anim_phase < 0) {
                c.anim_phase = .5f;
                vec2f_t zero = {0, 0};
                fx_spawn_particle(&c.position, (crt_rand() % 628) * .01f, &zero, .8f);
                fx_spawn_particle(&c.position, (crt_rand() % 628) * .01f, &zero, .6f);
                fx_spawn_particle(&c.position, (crt_rand() % 628) * .01f, &zero, .4f);
                fx_spawn_particle(&c.position, (crt_rand() % 628) * .01f, &zero, .3f);
                fx_spawn_particle(&c.position, (crt_rand() % 628) * .01f, &zero, .2f);
                fx_queue_add_random(&c.position);
            }
        }
        if (P(current_player_index).perks[perk_id_evil_eyes] > 0 && FREEZE <= 0) {
            c.pos_x -= c.vel_x;
            c.pos_y -= c.vel_y;
        }
    }
    current_player_index = 0;
}
__forceinline void timed_perks() {
    if (JINX >= 0)
        JINX -= frame_dt;
    if (JINX < 0 && PERK(perk_id_jinxed) > 0) {
        if (crt_rand() % 10 == 3) {
            HP(0) -= 5;
            fx_queue_add_random(&POS(0));
            fx_queue_add_random(&POS(0));
        }
        JINX += (crt_rand() % 20) * .1f + 2;
        int id = crt_rand() % 511;
        for (int n = 0; n < 10 && !creature_pool[id].active; ++n)
            id = crt_rand() % 511;
        creature_t &c = creature_pool[id];
        if (c.active) {
            c.health = -1;
            c.death_timer -= frame_dt * 20;
            XP = (int)(XP + c.freeware.reward);
            sfx_play_panned(3, .45f, .5f);
        }
    }
    if (PERK(perk_id_berserk_attack) > 0) {
        BERSERK -= frame_dt;
        if (BERSERK < 0) {
            if (crt_rand() % 15 == 2) {
                BERSERK = 12;
                sfx_play_panned(19, .45f, .5f);
            } else
                BERSERK = 2;
        }
    }
}
__forceinline void label(const char *text, float x, float y, float scale, float r, float g, float b, float alpha) {
#ifdef CRIMSON_FREEWARE_CLIENT
    G.ui.scale = scale;
    G.frame_labels.push_back({text, x, y, scale, {r, g, b, alpha}, G.frame_sprites.size()});
#else
    grim_interface_ptr->grim_set_config_var(0x18, scale);
    grim_interface_ptr->grim_set_color(r, g, b, alpha);
    grim_interface_ptr->grim_draw_text_mono(x, y, (char *)text);
#endif
}
__forceinline void sprite(const char *name, float x, float y, float w, float h, float angle, float r, float g,
                          float b, float a) {
#ifdef CRIMSON_FREEWARE_CLIENT
    G.frame_sprites.push_back({name, x, y, w, h, angle, {r, g, b, a}, {}, G.ui.filter, G.ui.destination_blend});
#else
    grim_interface_ptr->grim_bind_texture(grim_interface_ptr->grim_get_texture_handle((char *)name), 0);
    grim_interface_ptr->grim_set_rotation(angle);
    grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
    grim_interface_ptr->grim_set_color(r, g, b, a);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(x, y, w, h);
    grim_interface_ptr->grim_end_batch();
#endif
}
#define MOUSE_X FIELD(freeware_aim_screen.x, cursor_x)
#define MOUSE_Y FIELD(freeware_aim_screen.y, cursor_y)

#include "frame_level.inc"
#include "frame_menu.inc"
#include "frame_overlays.inc"
} // namespace frame_update140
using namespace frame_update140;

extern "C" unsigned char game_frame_update() {
#ifdef CRIMSON_FREEWARE_CLIENT
    if (INPUT.screenshot)
        G.screenshot_requested = true;
    if (!G.console_open && !INPUT.ctrl) {
        if (INPUT.relative) {
            MOUSE_X += G.mouse_dx;
            MOUSE_Y += G.mouse_dy;
        } else {
            MOUSE_X = INPUT.x;
            MOUSE_Y = INPUT.y;
        }
    }
    float dt = freeware_frame_delta;
#else
    if (grim_interface_ptr->grim_was_key_pressed(0x58)) {
        sprintf(freeware_ui_buffer, "screenshot_%i.bmp", screenshot_file_index);
        if (grim_interface_ptr->grim_save_screenshot(freeware_ui_buffer))
            ++screenshot_file_index;
    }
    if (freeware_console_grim->grim_was_key_pressed(0x29))
        freeware_console.console_set_open(!console_open_flag);
    if (!console_open_flag && !grim_interface_ptr->grim_is_key_down(0x1d)) {
        freeware_mouse_dx = grim_interface_ptr->grim_get_mouse_dx();
        freeware_mouse_dy = grim_interface_ptr->grim_get_mouse_dy();
        MOUSE_X += freeware_mouse_dx;
        MOUSE_Y += freeware_mouse_dy;
    }
    float dt = grim_interface_ptr->grim_get_frame_dt();
    frame_dt_copy = dt;
    freeware_real_clock += dt;
#endif
    float margin = P(current_player_index).size * .5f;
    if (state() == 3)
        margin = 0;
    if (MOUSE_X < margin)
        MOUSE_X = margin;
    if (MOUSE_X > screen_width - margin)
        MOUSE_X = screen_width - margin;
    if (MOUSE_Y < margin)
        MOUSE_Y = margin;
    if (MOUSE_Y > screen_height - margin)
        MOUSE_Y = screen_height - margin;
    if (FIELD(console_open_flag, console_open))
        dt = 0;
    if (PERK(perk_id_reflex_boosted) > 0 && SCALE > .85f)
        SCALE = .85f;
    current_player_index = 0;
    frame_dt = SCALE * dt;
    CLOCK += frame_dt;
    if (state() == 3 && config_game_mode != 4)
        simulate_players();
    position_camera();
    if (config_game_mode == 3 && state() == 3) {
        freeware_current_map->update_triggers();
        if (level_cleared()) {
            enter(8);
            STATE_SINCE = CLOCK;
        }
    }
    if (config_game_mode == 4 && state() == 3)
        editor();
    else
        render_world();
    if (!freeware_rainbow_armed) {
        for (int i = 0; i < 8; ++i) {
            unsigned char bit = crt_rand() % 2 == 0;
#ifdef CRIMSON_FREEWARE_CLIENT
            G.random_flags[i] = bit;
            if (i == 4)
                freeware_rainbow_enabled = bit;
#else
            freeware_random_flags[i] = bit;
#endif
        }
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    G.presented_screen = G.screen;
#endif
    switch (state()) {
    case 1:
        if (!ACTIVE) {
            creatures();
            shots();
        }
        if (!main_menu())
            return 0;
        break;
    case 3:
        if (config_game_mode != 4) {
            deaths();
            if (PICKUP_TIME <= 0) {
                PICKUP_TIME = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
                G.run.pickup.kind = freeware::Bonus::None;
#else
                freeware_pickup_id = freeware_no_pickup;
#endif
            } else
                PICKUP_TIME -= frame_dt;
            if (bonus_fire_bullets_timer <= 0)
                bonus_fire_bullets_timer = 0;
            else
                bonus_fire_bullets_timer -= frame_dt;
            if (FREEZE <= 0)
                FREEZE = 0;
            else
                FREEZE -= frame_dt;
            update_wave();
            aim_overlays();
            target_perks();
            timed_perks();
            spawn_wave();
            hud();
            if (!FIELD(freeware_music_started, wind_started) && CLOCK > 1.1f) {
                sfx_play_panned(13, .45f, .5f);
                FIELD(freeware_music_started, wind_started) = 1;
            }
        }
        break;
    case 4:
        hud();
        perk_selection_screen_update();
        break;
    case 6:
        update_wave();
        creatures();
        shots();
        hud();
        CLOCK += frame_dt * .5f;
#ifdef CRIMSON_FREEWARE_CLIENT
        G.death_clock = CLOCK - STATE_SINCE;
#endif
        if (CLOCK - STATE_SINCE < 3) {
            float elapsed = CLOCK - STATE_SINCE;
            sprite("reaper", screen_width / 2 - 64.f, screen_height / 2 - 64.f, 128, 128, 0, 1, 1, 1,
                   elapsed < 1   ? elapsed
                   : elapsed < 2 ? 1.f
                                 : 3.f - elapsed);
        }
        if (CLOCK - STATE_SINCE >= 3) {
            enter(9);
            request_transition();
            STATE_SINCE = CLOCK;
        }
        break;
    case 7:
        hud();
        game_show_message();
        break;
    case 8:
        hud();
        if (CLOCK - STATE_SINCE < 3) {
            float elapsed = CLOCK - STATE_SINCE;
            label("Level Cleared!", screen_width / 2.f - 112, screen_height / 2.f - 32, 1, 1, 1, 1,
                  elapsed < 1   ? elapsed
                  : elapsed < 2 ? 1.f
                                : 3.f - elapsed);
        }
        if (CLOCK - STATE_SINCE >= 3) {
#ifndef CRIMSON_FREEWARE_CLIENT
            level_load_next();
#else
            G.load_next_level();
#endif
            enter(3);
        }
        break;
    case 9:
        name_screen();
        break;
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    if (INPUT.escape && state() != 6 && state() != 1) {
        G.paused_perks = G.screen == freeware::Screen::Perks;
        G.paused = ACTIVE;
        G.selected = 0;
        enter(1);
    }
    if (G.show_fps) {
        char buf[64];
        sprintf(buf, "fps: %.2f", G.fps);
        label(buf, 5, screen_height - 25.f, .7f, 1, 1, 1, 1);
    }
    if (G.safe_mode)
        label("(Safemode)", 150, screen_height - 25.f, .695f, 1, 1, 1, 1);
    update_fps(G.fps);
    return !G.quit;
#else
    sfx_update();
    if (grim_interface_ptr->grim_is_key_down(1) && state() != 6)
        enter(1);
    if (grim_interface_ptr->grim_is_key_down(0x38) && grim_interface_ptr->grim_is_key_down(0x10))
        return 0;
    if (quit_requested)
        return 0;
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_set_config_var(0x18, .7f);
    update_fps(grim_interface_ptr->grim_get_fps());
    if (freeware_show_fps) {
        sprintf(freeware_ui_buffer, "fps: %.2f", (double)grim_interface_ptr->grim_get_fps());
        grim_interface_ptr->grim_draw_text_mono(5, screen_height - 25.f, freeware_ui_buffer);
    }
    if (freeware_safe_mode)
        label("(Safemode)", 150, screen_height - 25.f, .695f, 1, 1, 1, 1);
    freeware_console.render();
    return 1;
#endif
}

#ifdef CRIMSON_FREEWARE_CLIENT
// These narrow probes also exercise the inlined stages used by the real callback.
extern "C" void freeware_playing_stage() { simulate_players(); }
extern "C" void freeware_spawn_edge() { spawn_edge(); }
extern "C" void freeware_bomb_advance() { update_wave(); }
#endif
