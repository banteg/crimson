#include "freeware_edition.h"
// crimson.exe 1.0.2 0x40c110, 1.3.0 0x412fd0, 1.4.0 0x418190.
#include "freeware_level.h"
#if FREEWARE_EDITION == 10002
#include "../ui/gameplay_hud_102.h"
#endif
#if FREEWARE_EDITION < 10400
#ifndef CRIMSON_FREEWARE_CLIENT
#include "../highscore/freeware_score.h"
#endif
#endif
#if CL_BUILD == 10002
extern "C" void freeware_post_player_render_noop();
extern "C" void freeware_career_menu_update();
#endif
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
#include "../level/freeware_editor_brush.h"
extern "C" IGrim2D_cpp *grim_interface_ptr;
#define FIELD(native, client) (native)
#endif

extern "C" {
#if CL_BUILD < 10400
extern freeware_player_t player_state_table[2];
#define P(i) player_state_table[i]
#else
extern player_state_t player_state_table[2];
#define P(i) player_state_table[i].freeware
#endif
extern creature_t creature_pool[CL_BUILD == 10002 ? 128 : 512];
#if CL_BUILD != 10002
extern int config_player_count;
#endif
extern int current_player_index, config_aim_schemes[2], freeware_arena_width, freeware_arena_height;
extern int perk_id_reflex_boosted, perk_id_lean_mean_exp_machine, perk_id_final_revenge, perk_id_jinxed,
    perk_id_spontaneously_combusteous, perk_id_evil_eyes, perk_id_berserk_attack;
extern int perk_id_see_health;
#if CL_BUILD == 10300
extern int perk_id_reserved_22;
#endif
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
extern int game_state_id, freeware_pending_perks, freeware_pickup_id, freeware_no_pickup, screenshot_file_index,
    freeware_fps_count;
#if CL_BUILD != 10002
extern int screen_width, screen_height;
#endif
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
#if FREEWARE_EDITION >= 10300
#include "../render/world_render.h"
extern "C" int world_arrow_marker_texture;
#else
#define PICKUP_TIME FIELD(freeware_pickup_time, run.pickup.time)
#define BOMB_POS FIELD(freeware_bomb_position, run.bomb_pos)
#endif
namespace frame_update140 {
struct FramePoint : vec2f_t {
    FramePoint(float px, float py) {
        x = px;
        y = py;
    }
    FramePoint operator+(const FramePoint &other) const { return FramePoint(x + other.x, y + other.y); }
    const vec2f_t *address() const { return this; }
};
#if FREEWARE_EDITION == 10002
typedef FramePoint FramePoint102;
#endif
#if CL_BUILD == 10002
enum { config_player_count = 1, screen_width = 640, screen_height = 480 };
#endif
#ifndef CRIMSON_FREEWARE_CLIENT
enum { frame_font_scale = CL_BUILD == 10002 ? 0x11 : 0x18, frame_src_blend = CL_BUILD == 10002 ? 0x0d : 0x13,
       frame_dst_blend = CL_BUILD == 10002 ? 0x0e : 0x14 };
// Keep the virtual receiver and texture lookup in the same call expression.
#if CL_BUILD < 10400
#define frame_bind_texture(handle) grim_interface_ptr->grim_bind_texture(handle)
#else
#define frame_bind_texture(handle) grim_interface_ptr->grim_bind_texture(handle, 0)
#endif
#endif
#define XP FIELD(P(0).experience, run.experience)
#define PLAYER_PERK(player, perk) FIELD(P(player).perks[perk], run.perks[perk])
#define PERK(i) PLAYER_PERK(0, i)
#define HP(i) FIELD(P(i).health, actor(i).health)
#define POS(i) FIELD(P(i).position, actor(i).player)
#define SHIELD(i) FIELD(P(i).shield, actor(i).shield)
#define CLOCK freeware_simulation_clock
#define SCALE FIELD(time_scale_factor, run.speed_scale)
#define XP_TIMER FIELD(freeware_xp_timer, run.exp_clock)
#define SLOW FIELD(bonus_reflex_boost_timer, run.slow)
#define FREEZE FIELD(bonus_freeze_timer, run.freeze)
#define BERSERK FIELD(freeware_berserk_timer, run.berserk)
#define SECONDS FIELD(freeware_elapsed_seconds, run.seconds)
#define SPAWN_TIMER FIELD(freeware_next_spawn, run.next_spawn)
#define JINX FIELD(freeware_jinx_timer, run.jinx)
#define REVIVE FIELD(freeware_revive_timer, run.plague_time)
#define BOMB FIELD(freeware_bomb_age, run.bomb_age)
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
#if FREEWARE_EDITION == 10002
    bool pressed = INPUT.keypad_plus_down && G.perk_key_released;
    G.perk_key_released = !INPUT.keypad_plus_down;
    return INPUT.level_up || pressed || (INPUT.click && G.cursor_x > 400.f && G.cursor_x < 656.f &&
                              G.cursor_y > 430.f && G.cursor_y < 480.f);
#else
    return INPUT.level_up || (FREEWARE_EDITION != 10300 && INPUT.perk_button) ||
           (G.aiming[0] == 3 && INPUT.pad_perk[0]) ||
           (INPUT.click && G.cursor_x > screen_width - 240 && G.cursor_x < screen_width + 17 &&
            G.cursor_y > screen_height - 50 && G.cursor_y < screen_height + 1);
#endif
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
extern "C" int freeware_point_in_rect(const vec2f_t *, const vec2f_t *, const vec2f_t *);
#if CL_BUILD != 10002
__forceinline bool perk_shortcut() {
    return grim_interface_ptr->grim_is_key_down(0x4e) || grim_interface_ptr->grim_is_key_down(0x39) ||
           (FREEWARE_EDITION != 10300 && grim_interface_ptr->grim_was_mouse_button_pressed(1)) ||
           (config_aim_schemes[current_player_index] == (FREEWARE_EDITION == 10300 ? 2 : 3) &&
            grim_interface_ptr->grim_is_joystick_button_down(1));
}
#endif
#if FREEWARE_EDITION != 10400
__forceinline bool click_perk() {
#if CL_BUILD == 10002
    vec2f_t hi = {656.f, 480.f};
    vec2f_t lo = {400.f, 430.f};
#else
    const float x = screen_width - 240.f, y = screen_height - 50.f;
    vec2f_t hi = {x + 257.f, y + 51.f};
    vec2f_t lo = {x, y};
#endif
    return (unsigned char)freeware_point_in_rect(&freeware_aim_screen, &lo, &hi) && grim_interface_ptr->grim_was_mouse_button_pressed(0);
}
__forceinline bool open_perk() {
#if CL_BUILD == 10002
    return grim_interface_ptr->grim_was_key_pressed(0x4e) || click_perk();
#else
    return perk_shortcut() || click_perk();
#endif
}
#endif
__forceinline void level_check() { player_check_level(); }
__forceinline void open_choices() { perks_generate_choices(); }
__forceinline void hud() {
#if CL_BUILD == 10002
    hud102::render();
#else
    gameplay_render_hud();
#endif
}
#endif

__forceinline void request_transition() {
    FIELD(freeware_transition_pending, transition_pending) = 1;
    FIELD(freeware_transition_alpha, transition_alpha) = 1;
}
__forceinline void begin_overlay() { freeware_overlay_begin(); }
__forceinline void simulate_players() {
#if FREEWARE_EDITION == 10002
    creatures();
    shots();
    player();
#else
    XP_TIMER -= frame_dt;
    if (XP_TIMER < 0) {
        XP_TIMER = .25f;
        if (PERK(perk_id_lean_mean_exp_machine) > 0)
            XP += PERK(perk_id_lean_mean_exp_machine) * 10;
    }
    creatures();
    shots();
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10400
    bool perk_requested = false;
    if (PENDING >= 1 && config_game_mode != 2) {
        if (perk_shortcut())
            perk_requested = true;
        else {
            const float x = screen_width - 240.f, y = screen_height - 50.f;
            const FramePoint origin(x, y);
            FramePoint hi = origin + FramePoint(257.f, 51.f);
            FramePoint lo = origin;
            perk_requested = (unsigned char)freeware_point_in_rect(&freeware_aim_screen, &lo, &hi) &&
                             grim_interface_ptr->grim_was_mouse_button_pressed(0);
        }
    }
    if (perk_requested) {
#else
    if (FREEWARE_EDITION != 10002 && PENDING >= 1 && config_game_mode != 2 && open_perk()) {
#endif
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
#endif
    level_check();
}
__forceinline void shake(float &value) {
    const int random = crt_rand() % 200 - 100;
    value *= .125f;
    value = value * random * .15f;
}
__forceinline void center_camera_on(int i) {
    CAM.x = screen_width / 2 - POS(i).x;
    CAM.y = screen_height / 2 - POS(i).y;
}
__forceinline void position_camera() {
    if (CL_BUILD != 10002 && config_game_mode == 4 && state() == 3) {
        CAM.x = screen_width / 2 -
                FIELD(freeware_aim_screen.x, cursor_x) / (screen_width * .8f) * freeware_arena_width;
        CAM.y = screen_height / 2 -
                FIELD(freeware_aim_screen.y, cursor_y) / (screen_height * .8f) * freeware_arena_height;
    } else if ((FREEWARE_EDITION == 10002 ? 1 : config_player_count) == 1)
        center_camera_on(current_player_index);
    else if (HP(0) <= 0)
        center_camera_on(1);
    else if (HP(1) <= 0)
        center_camera_on(0);
    else {
        CAM.x = screen_width / 2 - (POS(0).x - (POS(0).x - POS(1).x) * .5f);
        CAM.y = screen_height / 2 - (POS(0).y - (POS(0).y - POS(1).y) * .5f);
    }
#if FREEWARE_EDITION != 10002
    SHAKE_TIME -= frame_dt;
    if (SHAKE_TIME <= 0) {
        SHAKE_TIME = .061f;
        shake(SHAKE.x);
        shake(SHAKE.y);
        const double squared_y = (double)SHAKE.y * SHAKE.y;
        if ((float)sqrt(SHAKE.x * SHAKE.x + squared_y) < 5.f) {
            shake(SHAKE.x);
            shake(SHAKE.y);
        }
    }
    CAM.x += SHAKE.x;
    CAM.y += SHAKE.y;
#endif
    const int edge = FREEWARE_EDITION < 10400 ? 0 : -1;
    if (CAM.x > edge)
        CAM.x = (float)edge;
    if (CAM.y > edge)
        CAM.y = (float)edge;
#if FREEWARE_EDITION == 10002
    if (CAM.x < screen_width - freeware_arena_width)
        CAM.x = -(freeware_arena_width - (float)screen_width);
    if (CAM.y < screen_height - freeware_arena_height)
        CAM.y = -(freeware_arena_height - (float)screen_height);
#else
    if (CAM.x < screen_width - freeware_arena_width)
        CAM.x = (float)(screen_width - freeware_arena_width);
    if (CAM.y < screen_height - freeware_arena_height)
        CAM.y = (float)(screen_height - freeware_arena_height);
#endif
}
__forceinline void render_ground() {
    terrain_render();
#ifdef CRIMSON_FREEWARE_CLIENT
    G.terrain_sprites.swap(G.frame_sprites);
    G.presented_terrain_revision = G.terrain_revision;
#endif
}
__forceinline void draw_projectiles() {
#ifdef CRIMSON_FREEWARE_CLIENT
    G.actor_sprites.swap(G.frame_sprites);
#endif
    projectile_render();
}
__forceinline void render_world() {
#if FREEWARE_EDITION < 10400
    // Retired creatures contribute marks to this frame's queue in both early releases.
    creature_render_all();
    fx_queue_render();
#else
    fx_queue_render();
    creature_render_all();
#endif
#if FREEWARE_EDITION == 10002
    draw_projectiles();
#endif
#if FREEWARE_EDITION == 10002
    if (ACTIVE)
        player_render();
#if CL_BUILD == 10002
    freeware_post_player_render_noop();
#endif
#else
    if (ACTIVE) {
        if (SLOW > 0) {
            SLOW -= frame_dt;
            if (FREEWARE_EDITION != 10300 && SLOW <= 0) {
                time_scale_active = 1;
                freeware_fade_time = 0;
                SLOW = -.01f;
            }
        } else
            SLOW = 0;
        for (current_player_index = 0; current_player_index < config_player_count; ++current_player_index) {
            if (HP(current_player_index) <= 0)
                continue;
#if CL_BUILD != 10002
            if (state() == 3) {
                if (SHIELD(current_player_index) > 0)
                    SHIELD(current_player_index) -= frame_dt;
                else
                    SHIELD(current_player_index) = 0;
#if FREEWARE_EDITION == 10300
                // The reserved perk trades contact immunity for increasing damage every half second.
#ifdef CRIMSON_FREEWARE_CLIENT
                const int reserved = 22;
#else
                const int reserved = perk_id_reserved_22;
#endif
                if (PLAYER_PERK(current_player_index, reserved)) {
                    freeware_player_t &p = P(current_player_index);
                    p.move_phase -= frame_dt;
                    if (p.move_phase <= 0) {
                        float &damage = p.control_reserved;
                        damage += .2f;
                        p.move_phase += .5f;
                        FIELD(p.health, actor(current_player_index).health) -= damage;
                    }
                }
#endif
            }
#endif
            player_render();
        }
    }
    draw_projectiles();
    current_player_index = 0;
#endif
#if CL_BUILD != 10002
    freeware_current_map->render_layer(1, 0);
    freeware_current_map->render_triggers(1);
#endif
    effect_render_all();
#if FREEWARE_EDITION != 10002
    world_tint(1, 1, 1, 1);
#endif
#if CL_BUILD != 10002
    freeware_current_map->render_layer(2, 0);
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
    G.effect_sprites.swap(G.frame_sprites);
    G.effect_labels.swap(G.frame_labels);
#endif
}
__forceinline float spawn_random_coord(int extent) {
    return (float)(crt_rand() % extent);
}
__forceinline void clamp_spawn_color(float &value) {
    if (value < 0)
        value = 0;
    else if (value > 1)
        value = 1;
}
__forceinline float saturate(float x) {
    if (x < 0)
        return 0;
    if (x > 1)
        return 1;
    return x;
}
#ifndef CRIMSON_FREEWARE_CLIENT
extern "C" void freeware_music_stop(int);
#if FREEWARE_EDITION == 10300
extern "C" void freeware_title_track_fade(), freeware_game_track_fade();
#endif
#endif

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
        if (HP(current_player_index) <= 0) {
            if (FREEWARE_EDITION >= 10301 && REVIVE < 1 && (XP == 6 || XP == 66 || XP == 666 || XP == 6666)) {
                freeware_secret_weapon_unlocked = 1;
                HP(0) = 1;
                REVIVE += frame_dt * 10;
                weapon_assign_player(0, 17);
            } else {
                if (CL_BUILD != 10002 && PERK(perk_id_final_revenge) > 0) {
                    BOMB_POS = POS(current_player_index);
                    BOMB = 0;
                    vec2f_t shake = {10, 10};
                    SHAKE = shake;
                    sfx_play_panned(21, .45f, .5f);
                }
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
                enter(6);
                HP(current_player_index) = 0;
#if FREEWARE_EDITION == 10300
                freeware_title_track_fade();
                freeware_game_track_fade();
#else
                freeware_music_stop(31);
                freeware_music_stop(30);
                freeware_music_stop(29);
#endif
                STATE_SINCE = CLOCK;
#else
                HP(current_player_index) = 0;
                die();
#endif
            }
        }
    } else if (HP(0) <= 0 && HP(1) <= 0) {
        HP(0) = 0;
        HP(1) = 0;
        die();
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
        freeware_title_track_fade();
        freeware_game_track_fade();
#elif !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10400
        freeware_music_stop(30);
        freeware_music_stop(29);
        freeware_music_stop(31);
#endif
    }
}
__forceinline void update_wave() {
    if (BOMB >= 0)
        BOMB += (BOMB + 1) * frame_dt * 1.8f;
}
__forceinline void label(const char *, float, float, float, float, float, float, float);
#if FREEWARE_EDITION != 10002
__forceinline void timed_perks() {
    if (JINX >= 0)
        JINX -= frame_dt;
    if (JINX < 0 && PERK(perk_id_jinxed) > 0) {
        if (crt_rand() % 10 == 3) {
            HP(current_player_index) -= 5;
            fx_queue_add_random(&POS(current_player_index));
            fx_queue_add_random(&POS(current_player_index));
        }
        JINX = (crt_rand() % 20) * .1f + JINX + 2;
        int id = crt_rand() % 511;
        for (current_player_index = 0; current_player_index < 10 && !creature_pool[id].active; ++current_player_index)
            id = crt_rand() % 511;
        current_player_index = 0;
        if (creature_pool[id].active) {
            creature_pool[id].health = -1;
            creature_pool[id].death_timer -= frame_dt * 20;
            XP = (int)(XP + creature_pool[id].freeware.reward);
            sfx_play_panned(3, .45f, .5f);
        }
    }
    if (PLAYER_PERK(current_player_index, perk_id_berserk_attack) > 0) {
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
#endif
__forceinline void label(const char *text, float x, float y, float scale, float r, float g, float b, float alpha) {
#ifdef CRIMSON_FREEWARE_CLIENT
    G.ui.scale = scale;
    G.frame_labels.push_back({text, x, y, scale, {r, g, b, alpha}, G.frame_sprites.size()});
#else
    grim_interface_ptr->grim_set_config_var(frame_font_scale, scale);
    grim_interface_ptr->grim_set_color(r, g, b, alpha);
    grim_interface_ptr->grim_draw_text_mono(x, y, (char *)text);
#endif
}
__forceinline void sprite(const char *name, float x, float y, float w, float h, float angle, float r, float g,
                          float b, float a) {
#ifdef CRIMSON_FREEWARE_CLIENT
    G.frame_sprites.push_back({name, x, y, w, h, angle, {r, g, b, a}, {}, G.ui.filter, G.ui.destination_blend});
#else
    frame_bind_texture(grim_interface_ptr->grim_get_texture_handle((char *)name));
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
#if CL_BUILD == 10002 && !defined(CRIMSON_FREEWARE_CLIENT)
#include "frame_menu_102.inc"
#endif
#include "frame_overlays.inc"

#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
enum transition_phase { transition_fade_in, transition_solid, transition_fade_out };
__forceinline void draw_transition(bool dying, transition_phase phase) {
    grim_interface_ptr->grim_begin_batch();
    if (dying)
        frame_bind_texture(grim_interface_ptr->grim_get_texture_handle("reaper"));
    if (phase == transition_fade_in)
        grim_interface_ptr->grim_set_color(1, 1, 1, CLOCK - STATE_SINCE);
    else if (phase == transition_fade_out)
        grim_interface_ptr->grim_set_color(1, 1, 1, 3.f - (CLOCK - STATE_SINCE));
    else
        grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    if (dying)
        grim_interface_ptr->grim_draw_quad(screen_width / 2 - 64, screen_height / 2 - 64, 128, 128);
    else
        grim_interface_ptr->grim_draw_text_mono(screen_width / 2 - strlen("Level cleared!") * 8,
                                               screen_height / 2 - 32, "Level Cleared!");
    grim_interface_ptr->grim_end_batch();
}
__forceinline void draw_timed_transition(bool dying) {
    if (CLOCK - STATE_SINCE < 1.f)
        draw_transition(dying, transition_fade_in);
    else if (CLOCK - STATE_SINCE < 2.f)
        draw_transition(dying, transition_solid);
    else if (CLOCK - STATE_SINCE < 3.f)
        draw_transition(dying, transition_fade_out);
}
#endif
#if FREEWARE_EDITION == 10002
#include "frame_gameplay_102.inc"
#endif

// VC6 emits the editor allocation's exception cleanup for the two later callbacks.
#if defined(CRIMSON_FREEWARE_CLIENT) || CL_BUILD == 10002
extern "C"
#endif
unsigned char game_frame_update() {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10400
    vec2f_t lo;
#endif
#if FREEWARE_EDITION == 10002
    // Both overlays retain their cursor clocks and particle opacity across the draw calls.
    float cursor_phase, cursor_orbit, cursor_alpha;
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
    if (INPUT.screenshot)
        G.screenshot_requested = true;
    if (!G.console_open && (FREEWARE_EDITION == 10002 || !INPUT.ctrl)) {
        if (INPUT.relative) {
            MOUSE_X += G.mouse_dx;
            MOUSE_Y += G.mouse_dy;
        } else {
            MOUSE_X = INPUT.x;
            MOUSE_Y = INPUT.y;
        }
    }
    float dt = freeware_frame_delta;
#elif CL_BUILD == 10002
    MOUSE_X += grim_interface_ptr->grim_get_mouse_dx();
    MOUSE_Y += grim_interface_ptr->grim_get_mouse_dy();
#else
    if (grim_interface_ptr->grim_was_key_pressed(0x58)) {
        sprintf(freeware_ui_buffer, "screenshot_%i.bmp", screenshot_file_index);
        if (grim_interface_ptr->grim_save_screenshot(freeware_ui_buffer))
            ++screenshot_file_index;
    }
#if CL_BUILD >= 10400
    if (freeware_console_grim->grim_was_key_pressed(0x29))
        freeware_console.console_set_open(!console_open_flag);
    if (!console_open_flag && !grim_interface_ptr->grim_is_key_down(0x1d)) {
#else
    if (!grim_interface_ptr->grim_is_key_down(0x1d)) {
#endif
        freeware_mouse_dx = grim_interface_ptr->grim_get_mouse_dx();
        freeware_mouse_dy = grim_interface_ptr->grim_get_mouse_dy();
        MOUSE_X += freeware_mouse_dx;
        MOUSE_Y += freeware_mouse_dy;
    }
#endif
    float margin = P(current_player_index).size * .5f;
    if (FREEWARE_EDITION != 10002 && state() == 3)
        margin = 0;
    if (MOUSE_X < margin)
        MOUSE_X = margin;
    if (MOUSE_X > screen_width - margin)
        MOUSE_X = screen_width - margin;
    if (MOUSE_Y < margin)
        MOUSE_Y = margin;
    if (MOUSE_Y > screen_height - margin)
        MOUSE_Y = screen_height - margin;
#ifndef CRIMSON_FREEWARE_CLIENT
    float dt = grim_interface_ptr->grim_get_frame_dt();
#if CL_BUILD >= 10400
    frame_dt_copy = dt;
    freeware_real_clock += dt;
#endif
#endif
#if CL_BUILD >= 10400
    if (FIELD(console_open_flag, console_open))
        dt = 0;
#endif
    if (PLAYER_PERK(current_player_index, perk_id_reflex_boosted) > 0 &&
        (FREEWARE_EDITION == 10002 || SCALE > .85f))
        SCALE = .85f;
    if (FREEWARE_EDITION != 10002)
        current_player_index = 0;
    frame_dt = SCALE * dt;
    CLOCK += frame_dt;
    if (state() == 3 && (CL_BUILD == 10002 || config_game_mode != 4))
        simulate_players();
#if FREEWARE_EDITION == 10002
    render_ground(); // 0x40c243 draws the ground with the preceding frame's camera.
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
    if (INPUT.filter_override)
        G.ui.filter = 3;
#else
    if (grim_interface_ptr->grim_is_key_down(0x18))
        grim_interface_ptr->grim_set_config_var(CL_BUILD == 10002 ? 0x0f : 0x15, 3U);
#endif
    position_camera();
#if FREEWARE_EDITION >= 10300
    render_ground();
#endif
#if CL_BUILD != 10002
    if (config_game_mode == 3 && state() == 3) {
        freeware_current_map->update_triggers();
        if (level_cleared()) {
            enter(freeware_rules::level_clear_state);
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
            menu_tracks(false);
#endif
            STATE_SINCE = CLOCK;
        }
    }
    if (config_game_mode == 4 && state() == 3) {
#include "frame_editor.inc"
    } else
#endif
        render_world();
    if (FREEWARE_EDITION >= 10400 && !freeware_rainbow_armed) {
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
#if CL_BUILD == 10002 && !defined(CRIMSON_FREEWARE_CLIENT)
        {
            if (MENU_MUSIC && !ACTIVE) {
                freeware_title_track_start(30);
                MENU_MUSIC = 0;
                STATE_SINCE = CLOCK;
                freeware_logo_angle = 0;
            }
            crt_free(freeware_main_labels[0]);
            if (ACTIVE)
                freeware_main_labels[0] = strdup_malloc("Resume game.");
            else
                freeware_main_labels[0] = strdup_malloc("Begin game.");
            cursor_phase = CLOCK - STATE_SINCE;
            cursor_orbit = CLOCK;
            menu102_title(cursor_orbit, cursor_phase);
            grim_interface_ptr->grim_set_config_var(frame_font_scale, .75435f);
            freeware_perk_hover = -1;
            int row_index;
            if (freeware_options_open) {
                menu102_option_labels();
                for (row_index = 0; row_index < 9; ++row_index) {
                    const FramePoint102 &row = FramePoint102(180.f, 180.f + row_index * 32.f);
                    menu102_draw_row(row_index, false, row, FramePoint102(180.f + strlen(freeware_option_labels[row_index]) * 16.f,
                                                                  row.y + 30.f));
                }
            } else {
                for (row_index = 0; row_index < 6; ++row_index) {
                    const FramePoint102 &row = FramePoint102(220.f, 220.f + row_index * 32.f);
                    menu102_draw_row(row_index, true, row, FramePoint102(220.f + strlen(freeware_main_labels[row_index]) * 16.f,
                                                                 row.y + 30.f));
                }
            }
            menu_footer_102(cursor_phase, cursor_orbit, cursor_alpha);
            menu102_option_input();
            if (!freeware_credits_open && !freeware_scores_open && !freeware_options_open) {
                if (grim_interface_ptr->grim_was_mouse_button_pressed(0)) {
                    int row = freeware_perk_hover;
                    if (row == 0) {
                        if (ACTIVE)
                            enter(3);
                        else {
                            freeware_logo_visible = 0;
                            MENU_MUSIC = 1;
                            enter(3);
                            freeware_music_started = 1;
                            gameplay_reset_state();
                            freeware_title_track_fade();
                            freeware_spawn_enabled = 1;
                            ACTIVE = 1;
                        }
                    } else if (row == 1) {
                        if (!ACTIVE) {
                            config_game_mode = (game_mode_id_t)(config_game_mode + 1);
                            if (config_game_mode > 2)
                                config_game_mode = (game_mode_id_t)1;
                            crt_free(freeware_main_labels[1]);
                            if (config_game_mode == 1)
                                freeware_main_labels[1] = strdup_malloc("Game mode: career");
                            else
                                freeware_main_labels[1] = strdup_malloc("Game mode: survival");
                        }
                    } else if (row == 2) {
                        highscore_load_table();
                        freeware_transition_pending = 1;
                        freeware_scores_open = 1;
                        freeware_transition_alpha = 1.f;
                    } else if (row == 3) {
                        freeware_transition_pending = 1;
                        freeware_credits_open = 1;
                        freeware_transition_alpha = 1.f;
                    } else if (row == 4)
                        freeware_options_open = 1;
                    else if (row == 5)
                        return 0;
                }
            }
            if (freeware_credits_open)
                game_credits_update();
            if (freeware_scores_open)
                game_highscores_update();
        }
        break;
#else
        if (FREEWARE_EDITION >= 10400 && !ACTIVE) {
            creatures();
            shots();
        }
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
        {
#include "frame_main_menu.inc"
        }
#else
        if (!main_menu())
            return 0;
#endif
        break;
#endif
#if CL_BUILD == 10002
    case 2:
        freeware_career_menu_update();
        break;
#endif
    case 3:
        if (CL_BUILD == 10002 || config_game_mode != 4) {
            if (FREEWARE_EDITION != 10002)
                deaths();
#if FREEWARE_EDITION == 10002
#include "frame_gameplay_state_102.inc"
#else
            if (PICKUP_TIME > 0)
                PICKUP_TIME -= frame_dt;
            else {
                PICKUP_TIME = 0;
#ifdef CRIMSON_FREEWARE_CLIENT
                G.run.pickup.kind = freeware::Bonus::None;
#else
                freeware_pickup_id = freeware_no_pickup;
#endif
            }
            if (bonus_fire_bullets_timer > 0)
                bonus_fire_bullets_timer -= frame_dt;
            else
                bonus_fire_bullets_timer = 0;
            if (FREEZE > 0)
                FREEZE -= frame_dt;
            else
                FREEZE = 0;
            update_wave();
#include "frame_gameplay_state.inc"
#endif
#if FREEWARE_EDITION == 10002
            // The prompt's draw and its input check share the same pending-perk gate.
#ifdef CRIMSON_FREEWARE_CLIENT
            if (hud102::render() && open_perk()) {
#else
            if (hud102::render() &&
                (grim_interface_ptr->grim_was_key_pressed(0x4e) ||
                 ((unsigned char)freeware_point_in_rect(&freeware_aim_screen, FramePoint102(400.f, 430.f).address(),
                                                       FramePoint102(656.f, 480.f).address()) &&
                  grim_interface_ptr->grim_was_mouse_button_pressed(0)))) {
#endif
                enter(4);
                open_choices();
                request_transition();
                STATE_SINCE = CLOCK;
            }
#else
            hud();
#endif
            if (!FIELD(freeware_music_started, wind_started) && CLOCK > 1.1f) {
                sfx_play_panned(13, .45f, .5f);
                FIELD(freeware_music_started, wind_started) = 1;
            }
        }
        break;
    case 4:
        if (FREEWARE_EDITION != 10002)
            hud();
        perk_selection_screen_update();
        break;
#if CL_BUILD != 10002 && FREEWARE_EDITION != 10300
    case 7:
        hud();
        game_show_message();
        break;
#endif
#if FREEWARE_EDITION != 10002
    case 6:
        update_wave();
#if FREEWARE_EDITION != 10300
        creatures();
        shots();
#endif
        hud();
        CLOCK += frame_dt * (FREEWARE_EDITION == 10300 ? 1.f : .5f);
#ifdef CRIMSON_FREEWARE_CLIENT
        G.death_clock = CLOCK - STATE_SINCE;
#endif
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
        grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
        draw_timed_transition(true);
#else
        if (CLOCK - STATE_SINCE < 3) {
            float elapsed = CLOCK - STATE_SINCE;
            sprite("reaper", screen_width / 2 - 64.f, screen_height / 2 - 64.f, 128, 128, 0, 1, 1, 1,
                   elapsed < 1   ? elapsed
                   : elapsed < 2 ? 1.f
                                 : 3.f - elapsed);
        }
#endif
        if (CLOCK - STATE_SINCE >= 3) {
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10300
            freeware_game_track_start(29);
#elif !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION == 10400
            freeware_music_start(29);
#endif
            enter(freeware_rules::name_entry_state);
            request_transition();
            STATE_SINCE = CLOCK;
        }
        break;
#endif
#if CL_BUILD != 10002
    case freeware_rules::level_clear_state:
        hud();
#if !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
        grim_interface_ptr->grim_set_uv(0, 0, 1, 1);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, 1.f);
        draw_timed_transition(false);
#else
        if (CLOCK - STATE_SINCE < 3) {
            float elapsed = CLOCK - STATE_SINCE;
            label("Level Cleared!", screen_width / 2.f - 112, screen_height / 2.f - 32, 1, 1, 1, 1,
                  elapsed < 1   ? elapsed
                  : elapsed < 2 ? 1.f
                                : 3.f - elapsed);
        }
#endif
        if (CLOCK - STATE_SINCE >= 3) {
#ifndef CRIMSON_FREEWARE_CLIENT
            level_load_next();
#else
            G.load_next_level();
#endif
            enter(3);
        }
        break;
#endif
    case freeware_rules::name_entry_state:
#if FREEWARE_EDITION == 10002
        name_screen(cursor_phase, cursor_orbit, cursor_alpha);
#elif !defined(CRIMSON_FREEWARE_CLIENT) && FREEWARE_EDITION >= 10300
#include "frame_name_state.inc"
#else
        name_screen();
#endif
        break;
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    if (INPUT.escape && (FREEWARE_EDITION < 10400 || state() != 6) && state() != 1) {
        G.paused_perks = G.screen == freeware::Screen::Perks;
        G.paused = ACTIVE;
        G.selected = 0;
        enter(1);
    }
    if ((FREEWARE_EDITION != 10002 && INPUT.quit_chord) || (FREEWARE_EDITION >= 10400 && G.quit))
        return 0;
    if (G.show_fps) {
        char buf[64];
        sprintf(buf, "fps: %.2f", G.fps);
        label(buf, 5, screen_height - 25.f, .7f, 1, 1, 1, 1);
    }
    if (G.safe_mode)
        label("(Safemode)", 150, screen_height - 25.f, .695f, 1, 1, 1, 1);
    if (FREEWARE_EDITION != 10002)
        update_fps(G.fps);
    return !G.quit;
#else
    sfx_update();
    if (grim_interface_ptr->grim_is_key_down(1) && (CL_BUILD < 10400 || state() != 6))
        enter(1);
    if (CL_BUILD != 10002 && grim_interface_ptr->grim_is_key_down(0x38) && grim_interface_ptr->grim_is_key_down(0x10))
        return 0;
    if (CL_BUILD >= 10400 && quit_requested)
        return 0;
    grim_interface_ptr->grim_set_color(1, 1, 1, 1);
    grim_interface_ptr->grim_set_config_var(frame_font_scale, .7f);
    if (CL_BUILD != 10002)
        update_fps(grim_interface_ptr->grim_get_fps());
    if (freeware_show_fps) {
        sprintf(freeware_ui_buffer, "fps: %.2f", (double)grim_interface_ptr->grim_get_fps());
        grim_interface_ptr->grim_draw_text_mono(5, screen_height - 25.f, freeware_ui_buffer);
    }
    if (freeware_safe_mode) {
        grim_interface_ptr->grim_set_color(1, 1, 1, 1);
        grim_interface_ptr->grim_set_config_var(frame_font_scale, .695f);
        grim_interface_ptr->grim_draw_text_mono(150, screen_height - 25.f, "(Safemode)");
    }
    if (CL_BUILD >= 10400)
        freeware_console.render();
    return 1;
#endif
}

#ifdef CRIMSON_FREEWARE_CLIENT
// These narrow probes also exercise the inlined stages used by the real callback.
extern "C" void freeware_playing_stage() { simulate_players(); }
extern "C" void freeware_spawn_edge() {
#include "frame_spawn_edge.inc"
}
extern "C" void freeware_bomb_advance() { update_wave(); }
#endif
} // namespace frame_update140
