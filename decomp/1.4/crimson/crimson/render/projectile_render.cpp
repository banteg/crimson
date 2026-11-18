#include "cl_build.h"

#ifndef CRIMSON_FREEWARE_CLIENT
#include "projectile_render_early.inc"
#else
// crimson.exe 1.4.0, 0x40b570.
#include "world_render.h"
#include "freeware_edition.h"
#include <math.h>
extern "C" {
extern projectile_pool_t projectile_pool;
extern secondary_projectile_pool_t secondary_projectile_pool;
extern int freeware_particle_texture, perk_id_sharpshooter;
extern float bonus_fire_bullets_timer;
extern unsigned char freeware_glow;
}
using namespace world140;
namespace {
const float half_pi = 1.57079637f, muzzle_offset = .150915f;
#define GLOW UI_FIELD(freeware_glow, effects)
#define SECONDS UI_FIELD(freeware_elapsed_seconds, run.seconds)
__forceinline float clamp_alpha(float a) {
    if (a > 1)
        a = 1;
    else if (a < 0)
        a = 0;
    return a;
}
__forceinline void corner(int slot, float r, float g, float b, float a) {
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.trail_colors[slot] = {r, g, b, a};
#else
    grim_interface_ptr->grim_set_color_slot(slot, r, g, b, a);
#endif
}
__forceinline void ribbon(float x0, float y0, float x1, float y1, float x2, float y2, float x3, float y3) {
#ifdef CRIMSON_FREEWARE_CLIENT
    const freeware::UiState &s = UI_GAME.ui;
    UI_GAME.frame_trails.push_back({s.texture,
                                    {{x0, y0}, {x1, y1}, {x2, y2}, {x3, y3}},
                                    UI_GAME.trail_colors,
                                    s.filter,
                                    s.source_blend,
                                    s.destination_blend});
#else
    grim_interface_ptr->grim_draw_quad_points(x0, y0, x1, y1, x2, y2, x3, y3);
#endif
}
__forceinline void sights() {
    for (int i = 0; i < config_player_count; ++i) {
        const freeware_player_t &p = player_state_table[i].freeware;
        if (UI_FIELD(p.health, actor(i).health) <= 0)
            continue;
        const vec2f_t &pos = UI_FIELD(p.position, actor(i).player);
        double angle = p.aim_heading - half_pi;
        float ox = pos.x + (float)(cos(angle - muzzle_offset) * 15) + CAMERA.x;
        float oy = pos.y + (float)(sin(angle - muzzle_offset) * 15) + CAMERA.y;
        float ex = pos.x + (float)(cos(angle) * 512) + CAMERA.x;
        float ey = pos.y + (float)(sin(angle) * 512) + CAMERA.y;
        vec2f_t half = {(float)(cos(p.aim_heading) * 1.1f), (float)(sin(p.aim_heading) * 1.1f)};
        if (player_state_table[0].freeware.perks[perk_id_sharpshooter] > 0) {
            destination(2);
            begin();
            ribbon(ox - half.x, oy - half.y, ox + half.x, oy + half.y, ex + half.x, ey + half.y, ex - half.x,
                   ey - half.y);
            end();
            destination(6);
        }
    }
}
__forceinline vec2f_t operator+(const vec2f_t &a, const vec2f_t &b) {
    vec2f_t v = {a.x + b.x, a.y + b.y};
    return v;
}
__forceinline vec2f_t operator-(const vec2f_t &a, const vec2f_t &b) {
    vec2f_t v = {a.x - b.x, a.y - b.y};
    return v;
}
__forceinline vec2f_t operator*(const vec2f_t &v, const float &scale) {
    vec2f_t r = {v.x * scale, v.y * scale};
    return r;
}
__forceinline void trail(const projectile_t &p, float width, vec2f_t (&point)[4]) {
    // Calculate the width at each corner, as in the original inlined vector expressions.
    point[0] = (CAMERA + p.fields.origin) - p.fields.velocity * width;
    point[1] = (CAMERA + p.fields.origin) + p.fields.velocity * width;
    point[2] = (CAMERA + p.position) + p.fields.velocity * width;
    point[3] = (CAMERA + p.position) - p.fields.velocity * width;
}
__forceinline void trails(bool fire) {
    for (projectile_t *p = projectile_pool; p < projectile_pool + 64; ++p) {
        const projectile_type_id_t &type = p->fields.type_id;
        if (!p->active || type == freeware_rules::plasma_round || type == freeware_rules::plasma_minigun_round || (!fire && (type == 18 || type == 17)))
            continue;
        if (type == 0)
            p->active = 0;
        float alpha = clamp_alpha(p->fields.life_timer);
        corner(2, .8f, .6f, .6f, alpha);
        corner(3, .8f, .6f, .6f, alpha);
        vec2f_t point[4];
        if (type == 1)
            trail(*p, fire ? 3.f : 1.f, point);
        else if (type == 4)
            trail(*p, fire ? 3.f : 1.3f, point);
        else if (!fire && type == 10) {
            corner(2, .2f, .5f, 1, alpha);
            corner(3, .2f, .5f, 1, alpha);
            trail(*p, 1.2f, point);
        } else
            trail(*p, fire ? 1.f : .7f, point);
        ribbon(point[0].x, point[0].y, point[1].x, point[1].y, point[2].x, point[2].y, point[3].x, point[3].y);
    }
}
__forceinline void centered(const vec2f_t &p, float size) {
    quad(CAMERA.x + p.x - size * .5f, CAMERA.y + p.y - size * .5f, size, size);
}
__forceinline void plasma(const projectile_t &p, float gap, int cap, float bead, float head, float head_alpha,
                          float glow, float glow_alpha) {
    float dx = p.position.x - p.fields.origin.x, dy = p.position.y - p.fields.origin.y;
    float spacing = p.fields.speed_scale * gap;
    int divisor = (int)spacing;
#ifdef CRIMSON_FREEWARE_CLIENT
    // A stock shot always has a nonzero divisor. Custom shots can have zero speed.
    if (!divisor)
        divisor = 1;
#endif
    int beads = (int)sqrt((double)dx * dx + (double)dy * dy) / divisor;
    if (beads > cap)
        beads = cap;
    float sx = (float)(cos((double)p.angle + half_pi) * p.fields.speed_scale * gap);
    float sy = (float)(sin((double)p.angle + half_pi) * p.fields.speed_scale * gap);
    tint(1, 1, 1, .4f);
    for (int i = 0; i < beads; ++i)
        quad(i * sx + p.position.x + CAMERA.x - bead * .5f, i * sy + CAMERA.y + p.position.y - bead * .5f, bead,
             bead);
    tint(1, 1, 1, head_alpha);
    centered(p.position, head);
    tint(1, 1, 1, glow_alpha);
    if (GLOW)
        centered(p.position, glow);
}
__forceinline void orbit(const projectile_t &p, float phase, float radius, float offset, float size) {
    quad((float)(CAMERA.x + p.pos_x - offset + cos(phase) * radius),
         (float)(CAMERA.y + p.position.y - offset + sin(phase) * radius), size, size);
}
__forceinline void energy(int type) {
    for (int i = 0; i < 64; ++i) {
        const projectile_t &p = projectile_pool[i];
        if (!p.active || p.fields.type_id != type)
            continue;
        if (p.fields.life_timer != .4f) {
            float a = clamp_alpha(p.fields.life_timer * 2.5f);
            tint(1, 1, 1, a);
            centered(p.position, type == 18 ? a * 80 + 76 : a * 40 + 32);
            continue;
        }
        tint(1, 1, 1, 1);
        centered(p.position, 60);
        // The game's x87 precision control rounds each phase addition to a float.
        float phase = SECONDS * 9 + i;
        if (type == 18) {
            tint(1, .2f, .2f, .9f);
            orbit(p, phase, 13, 21, 42);
            tint(.2f, 1, .2f, .9f);
            orbit(p, phase + 2.0943952f, 13, 21, 42);
            tint(.2f, .2f, 1, .9f);
            orbit(p, phase + 4.1887903f, 13, 21, 42);
        } else {
            orbit(p, (double)p.angle + half_pi, 15, 30, 60);
            tint(1, 1, 1, 1);
            float c = (float)cos(phase);
            quad(CAMERA.x + p.pos_x - 31 + c * c, (float)(CAMERA.y + p.position.y - 31 + sin(phase) * 11), 52, 52);
            tint(1, 1, 1, 1);
            orbit(p, phase + 2.0943952f, 10, 31, 62);
            tint(1, 1, 1, 1);
            float last = (float)(phase + 4.1887903f);
            quad((float)(CAMERA.x + p.pos_x - 31 + cos(last) * 10),
                 (float)(CAMERA.y + p.position.y - 31 + sin(last) * sin(phase + 2.0943952f)), 62, 62);
        }
    }
}
__forceinline void rocket_glow(float reach, float size, float alpha) {
    source(5);
    destination(2);
    world_sheet(freeware_particle_texture, "part");
    begin();
    for (secondary_projectile_t *r = secondary_projectile_pool; r < secondary_projectile_pool + 64; ++r)
        if (r->active) {
            tint(1, 1, 1, alpha);
            double a = (double)r->angle - half_pi;
            quad((CAMERA.x + r->pos_x) - (float)cos(a) * reach - size * .5f,
                 (float)((CAMERA.y + r->position.y) - sin(a) * reach - size * .5f), size, size);
        }
    end();
    destination(6);
}
} // namespace
extern "C" void projectile_render() {
    uv(0, 0, 1, 1);
    world_sheet(freeware_bullet_texture, "bullet");
    tint(1, 0, 0, .5f);
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.trail_colors.fill(UI_GAME.ui.color);
#endif
    corner(2, 0, 0, 0, .2f);
    corner(3, 0, 0, 0, .2f);
    sights();
    corner(0, .6f, .6f, .6f, 0);
    corner(1, .6f, .6f, .6f, 0);
    begin();
    if (bonus_fire_bullets_timer <= 0) {
        world_sheet(freeware_bullet_texture, "bullet");
        trails(false);
    } else {
        world_sheet(freeware_particle_texture, "part");
        source(5);
        destination(2);
        trails(true);
    }
    end();
    source(5);
    destination(2);
    world_sheet(freeware_particle_texture, "part");
    uv(0, 0, 1, 1);
    angle(0);
    const freeware_player_t &player = player_state_table[current_player_index].freeware;
    if (player.muzzle_flash > 0) {
        double a = (double)player.aim_heading - half_pi - muzzle_offset;
        const vec2f_t &pos = UI_FIELD(player.position, actor(current_player_index).player);
        float x = (float)(cos(a) * 15), y = (float)(sin(a) * 15);
        tint(1, 1, 1, player.muzzle_flash);
        begin();
        quad(x + pos.x + CAMERA.x - 80, y + pos.y + CAMERA.y - 80, 160, 160);
        end();
    }
    begin();
    for (projectile_t *p = projectile_pool; p < projectile_pool + 64; ++p)
        if (p->active && (p->fields.type_id == freeware_rules::plasma_round || p->fields.type_id == freeware_rules::plasma_minigun_round)) {
            if (p->fields.life_timer == .4f) {
                if (p->fields.type_id == freeware_rules::plasma_round)
                    plasma(*p, 2.5f, 8, 22, 56, .45f, 256, .3f);
                else
                    plasma(*p, 2.1f, 3, 12, 16, .5f, 120, .15f);
            } else {
                tint(1, 1, 1, clamp_alpha(p->fields.life_timer * 2.5f));
                centered(p->position, 56);
            }
        }
    end();
    bind(texture("glow"));
    begin();
    energy(18);
    end();
    source(1);
    destination(6);
    begin();
    energy(17);
    end();
    if (bonus_fire_bullets_timer > 0) {
        source(5);
        destination(2);
        world_sheet(freeware_particle_texture, "part");
        float a = bonus_fire_bullets_timer * .25f;
        if (a >= 1)
            a = 1;
        tint(1, 1, 1, a);
        begin();
        for (projectile_t *f = projectile_pool; f < projectile_pool + 64; ++f)
            if (f->active && f->fields.life_timer == .4f) {
                world_angle(f->angle);
                centered(f->position, 64);
            }
        end();
    }
    source(5);
    destination(6);
    tint(.8f, .8f, .8f, .9f);
    world_sheet(freeware_bullet_icon, "bullet_i");
    begin();
    for (projectile_t *b = projectile_pool; b < projectile_pool + 64; ++b)
        if (b->active && b->fields.life_timer == .4f && b->fields.type_id != freeware_rules::plasma_round && b->fields.type_id != freeware_rules::plasma_minigun_round) {
            world_angle(b->angle);
            if (b->fields.type_id == 1)
                centered(b->position, 6);
            else if (b->fields.type_id == 4)
                centered(b->position, 8);
            else
                centered(b->position, 4);
        }
    end();
    if (GLOW)
        rocket_glow(5, 140, .48f);
    source(5);
    destination(6);
    tint(.8f, .8f, .8f, .9f);
    bind(texture("rocket"));
    begin();
    for (secondary_projectile_t *r = secondary_projectile_pool; r < secondary_projectile_pool + 64; ++r)
        if (r->active && r->fields.type_id != 3) {
            world_angle(r->angle);
            centered(r->position, 10);
        }
    end();
    if (GLOW)
        rocket_glow(9, 60, .68f);
}
#endif
