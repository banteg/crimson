// crimson.exe 1.4.0, 0x4110a0. The bomb damages creatures during this draw pass.
#include "../effects/freeware_fx_queues.h"
#include "world_render.h"
#include <math.h>
extern "C" {
extern int freeware_particle_texture;
extern unsigned char freeware_glow, freeware_smoke;
extern float freeware_berserk_timer;
extern vec2f_t freeware_aim_screen;
extern creature_t creature_pool[512];
extern particle_t particle_pool[128];
extern secondary_projectile_pool_t secondary_projectile_pool;
extern sprite_effect_t sprite_effect_pool[384];
void creature_handle_death(int, int, unsigned char);
void fx_queue_add_random(const vec2f_t *);
}
using namespace world140;
namespace {
#define CLOCK freeware_simulation_clock
#define GLOW UI_FIELD(freeware_glow, effects)
__forceinline void square(const vec2f_t &p, float size, float dx = 0, float dy = 0) {
    quad(CAMERA.x + p.x + dx - size * .5f, CAMERA.y + p.y + dy - size * .5f, size, size);
}
__forceinline float blink(float strong, float weak) {
    if (PICKUP_TIME > 2)
        return strong * 2;
    return PICKUP_TIME * (sin(PICKUP_TIME * 18.849556f) > 0 ? weak : strong);
}
__forceinline void pickup() {
    if (PICKUP_TIME <= 0 || PICKUP_ID == freeware_no_pickup)
        return;
    angle(0);
    source(5);
    destination(2);
    bind(texture("part"));
    uv(0, 0, 1, 1);
    tint(1, 1, 1, blink(.5f, .25f));
    begin();
    double radius = pow(sin(CLOCK), 2) * 16 + 24;
    quad((float)(PICKUP_POS.x + CAMERA.x - radius), (float)(PICKUP_POS.y + CAMERA.y - radius),
         (float)(radius + radius), (float)(radius + radius));
    end();
    angle((float)(sin(CLOCK + CLOCK) * .2f));
    const char *icon;
    if (PICKUP_ID == freeware_bonus_fire)
        icon = "b_fire";
    else if (PICKUP_ID == freeware_bonus_freeze)
        icon = "b_freeze";
    else if (PICKUP_ID == freeware_bonus_weapon)
        icon = "b_weapon";
    else if (PICKUP_ID == freeware_bonus_nuke)
        icon = "b_bomb";
    else if (PICKUP_ID == freeware_bonus_shield)
        icon = "shockwave";
    else if (PICKUP_ID == freeware_bonus_time)
        icon = "b_timebend";
    else
        icon = "b_bomb";
    bind(texture(icon));
    if (PICKUP_ID == freeware_bonus_shield) {
        tint(91.f / 255, 180.f / 255, 1, blink(.2f, .1f));
        begin();
        square(PICKUP_POS, 24, (float)(cos(CLOCK + CLOCK) * 3), (float)(sin(CLOCK + CLOCK) * 3));
        end();
        destination(6);
    } else {
        destination(6);
        begin();
        square(PICKUP_POS, 40);
        end();
    }
}
__forceinline void particles() {
    particle_t *p;
    if (GLOW) {
        source(5);
        destination(2);
#ifdef CRIMSON_FREEWARE_CLIENT
        bind("part");
#else
        bind(freeware_particle_texture);
#endif
        angle(0);
        uv(0, 0, 1, 1);
        tint(1, 1, 1, .065f);
        begin();
        int i = 0;
        for (p = particle_pool; i < 128; ++p, ++i)
            if (p->active && !(i % 2) && p->style_id != 8) {
                float r = (float)((sin((1. - p->intensity) * 1.57079637f) + .1f) * 55 + 4);
                if (r < 16)
                    r = 16;
                square(p->position, (float)(r + r));
            }
        end();
        destination(6);
    }
    source(5);
    destination(2);
    bind(texture("flame"));
    angle(0);
    uv(0, 0, 1, 1);
    begin();
    for (p = particle_pool; p < particle_pool + 128; ++p)
        if (p->active && p->style_id != 8) {
            angle(p->rotation);
            tint(p->color_r, p->color_g, p->color_b, p->color_a);
            float r = (float)(sin((1. - p->intensity) * 1.57079637f) * 24);
            if (p->style_id == 1)
                r *= .8f;
            if (r < 2)
                r = 2;
            square(p->position, (float)(r + r));
        }
    end();
    bind(texture("bubble"));
    angle(0);
    uv(0, 0, 1, 1);
    begin();
    for (p = particle_pool; p < particle_pool + 128; ++p)
        if (p->active && p->style_id == 8) {
            tint(1, 1, 1, p->color_a);
            double wave = sin(p->rotation) * 3;
            float rx = (float)(15 - wave) * p->color_r * 7;
            double ry = (15 + wave) * p->color_r * 7;
            quad(CAMERA.x + p->pos_x - rx, (float)(CAMERA.y + p->pos_y - ry), rx + rx, (float)(ry + ry));
        }
    end();
    destination(6);
}
__forceinline void labels() {
    for (int i = 0; i < config_player_count; ++i) {
        const freeware_player_t &p = player_state_table[i].freeware;
        double x = p.aim.x - PICKUP_POS.x, y = p.aim.y - PICKUP_POS.y;
        if (UI_FIELD(p.health, actor(i).health) > 0 && sqrt(x * x + y * y) < 24) {
            scale(.5f);
            tint(1, 1, 1, .6f);
            if (PICKUP_ID == freeware_bonus_fire)
                text(CAMERA.x + p.aim.x + 8, CAMERA.y + p.aim.y - 7, "Piercing fire bullets");
            else if (PICKUP_ID == freeware_bonus_weapon)
                text(CAMERA.x + p.aim.x + 8, CAMERA.y + p.aim.y - 7, weapon_name_get(PICKUP_WEAPON));
            else {
                const char *s = 0;
                if (PICKUP_ID == freeware_bonus_freeze)
                    s = "Freeze";
                else if (PICKUP_ID == freeware_bonus_nuke)
                    s = "Bomb!";
                else if (PICKUP_ID == freeware_bonus_shield)
                    s = "Force field";
                else if (PICKUP_ID == freeware_bonus_time)
                    s = "Time bender";
                if (s)
                    text(UI_FIELD(freeware_aim_screen.x, cursor_x) + 8,
                         UI_FIELD(freeware_aim_screen.y, cursor_y) - 7, s);
            }
        }
    }
    if (UI_FIELD(freeware_berserk_timer, run.berserk) > 10) {
        scale(.9f);
        tint(1, 1, 1, (float)((fabs(sin(CLOCK * 4)) + 1) * .5));
        text(10, 150, "Berserk!");
    }
}
__forceinline void scorch(float dx, float dy) {
    vec2f_t pos = {BOMB_POS.x + dx, BOMB_POS.y + dy};
    effect_color_t black = {0, 0, 0, .3f};
    fx_queue_add(texture("glow"), &pos, 600, 600, 0, black);
}
__forceinline void blast() {
    if (BOMB_AGE < 0)
        return;
    if (BOMB_AGE > 1) {
        scorch(-50, -50);
        scorch(50, 50);
        scorch(-50, 50);
        scorch(50, -50);
        BOMB_AGE = -1;
        return;
    }
    uv(0, 0, 1, 1);
    begin();
    angle(0);
    tint(.1f, .46f, .9f, (1 - BOMB_AGE) * (1.f / 3));
    square(BOMB_POS, BOMB_AGE * 870.4f);
    float size = BOMB_AGE * 512;
    tint(.1f, .46f, .9f, 1 - BOMB_AGE);
    square(BOMB_POS, size);
    size *= .5f;
    tint(.1f, .46f, .9f, (1 - BOMB_AGE) * .5f);
    square(BOMB_POS, size, -40, -40);
    square(BOMB_POS, size, 0, 40);
    square(BOMB_POS, size, 40, -40);
    square(BOMB_POS, size * .5f);
    end();
    if (GLOW) {
        bind(texture("glow"));
        tint(.1f, .46f, .9f, BOMB_AGE);
        begin();
        angle(0);
        square(BOMB_POS, 1024);
        end();
    }
    if (UI_FIELD(freeware_game_active, active_run)) {
        for (int i = 0; i < 512; ++i) {
            creature_t &c = creature_pool[i];
            if (!c.active || c.health <= 0)
                continue;
            double x = c.pos_x - BOMB_POS.x, y = c.pos_y - BOMB_POS.y;
            if (sqrt(x * x + y * y) < BOMB_AGE * 256) {
                c.health -= frame_dt * 2000;
                fx_queue_add_random(&c.position);
#ifdef CRIMSON_FREEWARE_CLIENT
                if (c.health <= 0)
                    UI_GAME.kill(i, 0);
#else
                if (c.health <= 0)
                    creature_handle_death(i, 0, 1);
#endif
            }
        }
    }
}
} // namespace
extern "C" void effect_render_all() {
    pickup();
    particles();
    labels();
    bind(texture("shockwave"));
    source(5);
    destination(2);
    blast();
    source(5);
    destination(2);
    uv(0, 0, 1, 1);
    angle(0);
    begin();
    for (secondary_projectile_t *p = secondary_projectile_pool; p < secondary_projectile_pool + 64; ++p)
        if (p->active && p->fields.type_id == 3) {
            float age = p->fields.vel_x;
            tint(1, .6f, .1f, 1 - age);
            square(p->position, p->fields.vel_y * age * 64);
            tint(1, .6f, .1f, (1 - age) * .3f);
            square(p->position, p->fields.vel_y * age * 200);
        }
    end();
    destination(6);
    if (UI_FIELD(freeware_smoke, smoke)) {
        source(5);
        destination(6);
        bind(texture("smoke"));
        uv(0, 0, 1, 1);
        begin();
        for (int i = 0; i < 384; ++i)
            if (sprite_effect_pool[i].active) {
                sprite_effect_t *s = &sprite_effect_pool[i];
                angle(s->rotation);
                tint(s->color_r, s->color_g, s->color_b, s->color_a);
                square(s->position, s->scale);
            }
        end();
    }
}
