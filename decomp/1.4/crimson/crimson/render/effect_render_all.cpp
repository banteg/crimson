// The later freeware builds apply bomb damage during the effects draw pass.
#include "../effects/freeware_fx_queues.h"
#include "world_render.h"
#include <math.h>
#include <string.h>

enum { smoke_capacity = CL_BUILD < 10400 ? 256 : 384 };

extern "C" {
extern int freeware_particle_texture;
extern unsigned char freeware_glow, freeware_smoke;
extern float freeware_berserk_timer;
extern vec2f_t freeware_aim_screen;
extern creature_t creature_pool[512];
extern particle_t particle_pool[128];
extern secondary_projectile_pool_t secondary_projectile_pool;
extern sprite_effect_t sprite_effect_pool[smoke_capacity];
#if CL_BUILD < 10400
void creature_handle_death(int, int);
#else
void creature_handle_death(int, int, unsigned char);
#endif
void fx_queue_add_random(const vec2f_t *);
}
using namespace world140;

namespace {
#define CLOCK freeware_simulation_clock
#define GLOW UI_FIELD(freeware_glow, effects)
#if CL_BUILD != 10002
__forceinline void blinking_tint(float r, float g, float b, float strong, float weak) {
    if (PICKUP_TIME > 2)
        world_tint(r, g, b, strong * 2);
    else if ((float)sin(PICKUP_TIME * 18.849556f) > 0)
        world_tint(r, g, b, PICKUP_TIME * weak);
    else
        world_tint(r, g, b, PICKUP_TIME * strong);
}
#endif

// The original x87 draws read the world and camera coordinates in opposite orders.
__forceinline float pickup_coord(float world, float camera, float radius) {
#if CL_BUILD == 10002
    return camera + world - radius;
#else
    return world + camera - radius;
#endif
}

__forceinline void pickup() {
    if (!(PICKUP_TIME > 0 && PICKUP_ID != freeware_no_pickup))
        return;
    angle(0);
    source(5);
    destination(2);
    bind("part");
    uv(0, 0, 1, 1);
#if CL_BUILD == 10002
    if (PICKUP_TIME > 1)
        world_tint(1, 1, 1, 1);
    else
        world_tint(1, 1, 1, PICKUP_TIME);
#else
    blinking_tint(1, 1, 1, .5f, .25f);
#endif
    begin();
    float sine = (float)sin(CLOCK);
    float radius = (float)pow(sine, 2) * 16.0f + 24.0f;
    world_quad(pickup_coord(PICKUP_POS.x, CAMERA.x, radius), pickup_coord(PICKUP_POS.y, CAMERA.y, radius),
               radius + radius, radius + radius);
    end();
#if CL_BUILD == 10002
    destination(6);
#endif
    angle((float)sin(CLOCK + CLOCK) * .2f);
    if (PICKUP_ID == freeware_bonus_fire)
        bind("b_fire");
    else if (PICKUP_ID == freeware_bonus_freeze)
        bind("b_freeze");
    else if (PICKUP_ID == freeware_bonus_weapon)
        bind("b_weapon");
    else if (PICKUP_ID == freeware_bonus_nuke)
        bind("b_bomb");
#if CL_BUILD != 10002
    else if (PICKUP_ID == freeware_bonus_shield)
        bind("shockwave");
    else if (PICKUP_ID == freeware_bonus_time)
        bind("b_timebend");
#endif
    else
        bind("b_bomb");
#if CL_BUILD != 10002
    if (PICKUP_ID == freeware_bonus_shield) {
        blinking_tint(91.f / 255, 180.f / 255, 1, .2f, .1f);
        begin();
        world_quad(PICKUP_POS.x + CAMERA.x - 12 + (float)cos(CLOCK + CLOCK) * 3,
                   PICKUP_POS.y + CAMERA.y - 12 + (float)sin(CLOCK + CLOCK) * 3, 24, 24);
        end();
        destination(6);
        return;
    }
    destination(6);
#endif
    begin();
    world_quad(pickup_coord(PICKUP_POS.x, CAMERA.x, 20), pickup_coord(PICKUP_POS.y, CAMERA.y, 20), 40, 40);
    end();
}

__forceinline void particles() {
    int i;
    const float glow_scale = CL_BUILD == 10002 ? 50.0f : 55.0f;
    if (GLOW) {
        source(5);
        destination(2);
#ifdef CRIMSON_FREEWARE_CLIENT
        bind("part");
#else
        bind(freeware_particle_texture);
#endif
        world_angle(0);
        uv(0, 0, 1, 1);
        world_tint(1, 1, 1, CL_BUILD == 10002 ? .055f : .065f);
        begin();
        for (i = 0; i < 128; ++i)
            if (particle_pool[i].active && (CL_BUILD == 10002 || !(i % 2)) &&
                (CL_BUILD < 10400 || particle_pool[i].style_id != 8)) {
                float r =
                    ((float)sin((1.0f - particle_pool[i].intensity) * 1.57079637f) + .1f) * glow_scale + 4.0f;
                if (r < 16)
                    r = 16;
                world_quad(CAMERA.x + particle_pool[i].pos_x - r, CAMERA.y + particle_pool[i].pos_y - r,
                           r + r, r + r);
            }
        end();
        destination(6);
    }
    source(5);
    destination(2);
    bind("flame");
    world_angle(0);
    uv(0, 0, 1, 1);
    begin();
    for (i = 0; i < 128; ++i)
        if (particle_pool[i].active && (CL_BUILD < 10400 || particle_pool[i].style_id != 8)) {
            world_angle(particle_pool[i].rotation);
            world_tint(particle_pool[i].color_r, particle_pool[i].color_g, particle_pool[i].color_b,
                       particle_pool[i].color_a);
            float r = (float)sin((1.0f - particle_pool[i].intensity) * 1.57079637f) * 24.0f;
            if (CL_BUILD != 10002 && particle_pool[i].style_id == 1)
                r *= .8f;
            if (r < 2)
                r = 2;
            world_quad(CAMERA.x + particle_pool[i].pos_x - r, CAMERA.y + particle_pool[i].pos_y - r, r + r,
                       r + r);
        }
    end();
#if CL_BUILD >= 10400
    bind("bubble");
    world_angle(0);
    uv(0, 0, 1, 1);
    begin();
    for (i = 0; i < 128; ++i)
        if (particle_pool[i].active && particle_pool[i].style_id == 8) {
            world_tint(1, 1, 1, particle_pool[i].color_a);
            float wave = (float)sin(particle_pool[i].rotation) * 3.0f;
            vec2f_t radii = {15.0f - wave, 15.0f + wave};
            radii.y = radii.y * particle_pool[i].color_r * 7.0f;
            radii.x = radii.x * particle_pool[i].color_r * 7.0f;
            world_quad(CAMERA.x + particle_pool[i].pos_x - radii.x,
                       CAMERA.y + particle_pool[i].pos_y - radii.y, radii.x + radii.x, radii.y + radii.y);
        }
    end();
#endif
    destination(6);
}
#if CL_BUILD != 10002
#ifdef CRIMSON_FREEWARE_CLIENT
#define pickup_text ui140::text
#else
#define pickup_text grim_interface_ptr->grim_draw_text_mono
#endif
// The original converts the range-test result to float before testing it.
__forceinline float aim_near_pickup(const vec2f_t &aim) {
    const float dx = aim.x - PICKUP_POS.x;
    const float dy = aim.y - PICKUP_POS.y;
    const vec2f_t delta = {dx, dy};
    return (float)sqrt(delta.x * delta.x + delta.y * delta.y) < 24.0f;
}
#if CL_BUILD >= 10400
__forceinline float m_fabs(float value) {
    unsigned int bits;
    memcpy(&bits, &value, sizeof(bits));
    bits &= 0x7fffffffu;
    float magnitude;
    memcpy(&magnitude, &bits, sizeof(magnitude));
    return magnitude;
}
#endif
__forceinline void labels() {
    for (int i = 0; i < config_player_count; ++i) {
        const freeware_player_t &p = UI_PLAYER(i);
        if (UI_FIELD(p.health, actor(i).health) > 0 && aim_near_pickup(p.aim)) {
            scale(CL_BUILD < 10400 ? .45f : .5f);
            world_tint(1, 1, 1, .6f);
            if (PICKUP_ID == freeware_bonus_fire)
                pickup_text(CAMERA.x + p.aim.x + 8, CAMERA.y + p.aim.y - 7, "Piercing fire bullets");
            else if (PICKUP_ID == freeware_bonus_freeze)
                pickup_text(UI_FIELD(freeware_aim_screen.x, cursor_x) + 8,
                            UI_FIELD(freeware_aim_screen.y, cursor_y) - 7, "Freeze");
            else if (PICKUP_ID == freeware_bonus_weapon)
                pickup_text(CAMERA.x + p.aim.x + 8, CAMERA.y + p.aim.y - 7, weapon_name_get(PICKUP_WEAPON));
            else if (PICKUP_ID == freeware_bonus_nuke)
                pickup_text(UI_FIELD(freeware_aim_screen.x, cursor_x) + 8,
                            UI_FIELD(freeware_aim_screen.y, cursor_y) - 7, "Bomb!");
            else if (PICKUP_ID == freeware_bonus_shield)
                pickup_text(UI_FIELD(freeware_aim_screen.x, cursor_x) + 8,
                            UI_FIELD(freeware_aim_screen.y, cursor_y) - 7, "Force field");
            else if (PICKUP_ID == freeware_bonus_time)
                pickup_text(UI_FIELD(freeware_aim_screen.x, cursor_x) + 8,
                            UI_FIELD(freeware_aim_screen.y, cursor_y) - 7, "Time bender");
        }
    }
    if (UI_FIELD(freeware_berserk_timer, run.berserk) > 10) {
        scale(.9f);
#if CL_BUILD < 10400
        float pulse = (float)fabs(sin(CLOCK * 4.0f));
#else
        float pulse = m_fabs((float)sin(CLOCK * 4.0f));
#endif
        world_tint(1, 1, 1, (pulse + 1.0f) * .5f);
        pickup_text(10, 150, "Berserk!");
    }
}

#undef pickup_text

__forceinline void scorch(float dx, float dy) {
    float x = BOMB_POS.x - dx;
    float y = BOMB_POS.y - dy;
    vec2f_t pos = {x, y};
    effect_color_t black = {0, 0, 0, .3f};
#ifdef CRIMSON_FREEWARE_CLIENT
    fx_queue_add(texture("glow"), &pos, 600, 600, 0, black);
#else
    fx_queue_add(grim_interface_ptr->grim_get_texture_handle("glow"), &pos, 600, 600, 0, black);
#endif
}

__forceinline void blast() {
    if (BOMB_AGE < 0)
        return;
    if (BOMB_AGE > 1) {
        scorch(50, 50);
        scorch(-50, -50);
        scorch(50, -50);
        scorch(-50, 50);
        BOMB_AGE = -1;
        return;
    }
    uv(0, 0, 1, 1);
    begin();
    angle(0);
    float size = BOMB_AGE * 870.4f;
    world_tint(.1f, .46f, .9f, (1 - BOMB_AGE) * (1.f / 3));
    world_quad(BOMB_POS.x + CAMERA.x - size * .5f, BOMB_POS.y + CAMERA.y - size * .5f, size, size);
    size = BOMB_AGE * 512;
    world_tint(.1f, .46f, .9f, 1 - BOMB_AGE);
    world_quad(BOMB_POS.x + CAMERA.x - size * .5f, BOMB_POS.y + CAMERA.y - size * .5f, size, size);
    size *= .5f;
    world_tint(.1f, .46f, .9f, (1 - BOMB_AGE) * .5f);
    world_quad(CAMERA.x - 40 + BOMB_POS.x - size * .5f, CAMERA.y - 40 + BOMB_POS.y - size * .5f, size, size);
    world_quad(BOMB_POS.x + CAMERA.x - size * .5f, BOMB_POS.y + CAMERA.y + 40 - size * .5f, size, size);
    world_quad(BOMB_POS.x + CAMERA.x + 40 - size * .5f, CAMERA.y - 40 + BOMB_POS.y - size * .5f, size, size);
    size *= .5f;
    world_quad(BOMB_POS.x + CAMERA.x - size * .5f, BOMB_POS.y + CAMERA.y - size * .5f, size, size);
    end();
    if (GLOW) {
        bind("glow");
        world_tint(.1f, .46f, .9f, BOMB_AGE);
        begin();
        angle(0);
        world_quad(BOMB_POS.x + CAMERA.x - 512, BOMB_POS.y + CAMERA.y - 512, 1024, 1024);
        end();
    }
    if (UI_FIELD(freeware_game_active, active_run)) {
        for (int i = 0; i < 512; ++i) {

            vec2f_t *pos = &creature_pool[i].position;
            if (!creature_pool[i].active || creature_pool[i].health <= 0)
                continue;
            double x = pos->x - BOMB_POS.x, y = pos->y - BOMB_POS.y;
            float dist = (float)sqrt(x * x + y * y);
            if (dist < BOMB_AGE * 256) {
                creature_pool[i].health -= frame_dt * 2000;
                fx_queue_add_random(pos);
#ifdef CRIMSON_FREEWARE_CLIENT
                if (creature_pool[i].health <= 0)
                    UI_GAME.kill(i, 0);
#else
                if (creature_pool[i].health <= 0)
#if CL_BUILD < 10400
                    creature_handle_death(i, 0);
#else
                    creature_handle_death(i, 0, 1);
#endif
#endif
            }
        }
    }
}
#endif
} // namespace

extern "C" void effect_render_all() {
    pickup();
    particles();
#if CL_BUILD != 10002
    labels();
    bind("shockwave");
    source(5);
    destination(2);
    blast();
    source(5);
    destination(2);
    uv(0, 0, 1, 1);
    world_angle(0);
    begin();
    for (int k = 0; k < 64; ++k) {
        secondary_projectile_t *p = &secondary_projectile_pool[k];
        if (p->active && p->fields.type_id == 3) {
            world_tint(1, .6f, .1f, 1 - p->fields.vel_x);
            float size = p->fields.vel_y * p->fields.vel_x * 64;
            world_quad(CAMERA.x + p->pos_x - size * 0.5f, CAMERA.y + p->fields.pos_y - size * 0.5f, size,
                       size);
            world_tint(1, .6f, .1f, (1 - p->fields.vel_x) * .3f);
            size = p->fields.vel_y * p->fields.vel_x * 200;
            world_quad(CAMERA.x + p->pos_x - size * 0.5f, CAMERA.y + p->fields.pos_y - size * 0.5f, size,
                       size);
        }
    }
    end();
    destination(6);
    if (UI_FIELD(freeware_smoke, smoke)) {
        source(5);
        destination(6);
        bind("smoke");
        uv(0, 0, 1, 1);
        begin();
        for (int i = 0; i < smoke_capacity; ++i)
            if (sprite_effect_pool[i].active) {
                float size = sprite_effect_pool[i].scale;
                world_angle(sprite_effect_pool[i].rotation);
                world_tint(sprite_effect_pool[i].color_r, sprite_effect_pool[i].color_g,
                           sprite_effect_pool[i].color_b, sprite_effect_pool[i].color_a);
                world_quad(CAMERA.x + sprite_effect_pool[i].pos_x - size * 0.5f,
                           CAMERA.y + sprite_effect_pool[i].pos_y - size * 0.5f, size, size);
            }
        end();
    }
#endif
}
