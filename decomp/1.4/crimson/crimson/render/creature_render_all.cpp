#include "freeware_edition.h"
#include "world_render.h"

extern "C" {
extern creature_t creature_pool[CL_BUILD == 10002 ? 128 : 512];
extern int freeware_kills;
void fx_queue_add_rotated(const vec2f_t *, const effect_color_t *, float, float, int);
void fx_queue_add_random(const vec2f_t *);
}

using namespace world140;
namespace {
enum { creature_count = FREEWARE_EDITION == 10002 ? 128 : 512 };

struct DrawPoint : vec2f_t {
    __forceinline DrawPoint(const float &px, const float &py) {
        x = px;
        y = py;
    }
};

__forceinline DrawPoint operator+(const vec2f_t &a, const vec2f_t &b) {
    return DrawPoint(a.x + b.x, a.y + b.y);
}

__forceinline DrawPoint operator-(const vec2f_t &a, const vec2f_t &b) {
    return DrawPoint(a.x - b.x, a.y - b.y);
}

__forceinline void set_cell(int cell) {
#ifdef CRIMSON_FREEWARE_CLIENT
    atlas_origin(cell);
#else
    const vec2f_t &origin = freeware_atlas_uv[cell];
    const vec2f_t first = freeware_atlas_uv[cell];
    freeware_draw_point[0] = first;
    freeware_draw_point[1] = origin + DrawPoint(.125f, .125f);
#endif
}

__forceinline void set_pose(int index, bool shadow) {
    int cell = (int)(creature_pool[index].freeware.animation + .5f);
    if (shadow && creature_pool[index].freeware.type == 1) {
        if (cell > 15)
            cell = 0;
    } else if (cell > 15) {
        cell = 31 - cell;
    }
    if (creature_pool[index].death_timer != 16)
        cell = (int)(31.f - creature_pool[index].death_timer);

    if (creature_pool[index].freeware.type == 1) {
        world_angle(creature_pool[index].freeware.heading - 1.57079637f);
        set_cell(32 + cell);
    } else {
        world_angle(creature_pool[index].freeware.heading);
        set_cell(cell);
    }
    world_uv(freeware_draw_point[0].x, freeware_draw_point[0].y, freeware_draw_point[1].x, freeware_draw_point[1].y);
}
} // namespace

extern "C" void creature_render_all() {
    world_sheet(freeware_creature_texture, "goblin");
    world_uv(0, 0, 1, 1);
    if (UI_FIELD(freeware_shadows, shadows)) {
        source(1);
        destination(6);
        begin();
        for (int i = 0; i < creature_count; ++i) {
            if (!creature_pool[i].active)
                continue;
            set_pose(i, true);
            effect_color_t color = creature_pool[i].freeware.color;
            color.a *= .5f;
            world_tint(color.r, color.g, color.b, color.a);
            freeware_draw_point[0] = CAMERA + creature_pool[i].position -
                DrawPoint(creature_pool[i].freeware.size * .5f - 2, creature_pool[i].freeware.size * .5f - 2);
            float size = creature_pool[i].freeware.size * 1.04f;
            world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size, size);
        }
        end();
    }

    source(5);
    destination(6);
    bind("glow");
    world_tint(.3f, .6f, .3f, 1);
    world_tint(0, 0, 0, 1);
    world_uv(0, 0, 1, 1);
    world_angle(0);
    begin();
    for (int i = 0; i < creature_count; ++i) {
        if (creature_pool[i].active && creature_pool[i].plague_infected)
            world_quad(CAMERA.x + creature_pool[i].position.x - 40, CAMERA.y + creature_pool[i].position.y - 40, 80, 80);
    }
    end();

    destination(6);
    world_sheet(freeware_creature_texture, "goblin");
    begin();
    for (int j = 0; j < creature_count; ++j) {
        creature_t &body = creature_pool[j];
        if (!body.active)
            continue;
        set_pose(j, false);
        const effect_color_t &color = body.freeware.color;
        if (UI_FIELD(bonus_freeze_timer, run.freeze) > 0)
            world_tint(44.f / 255, 195.f / 255, 1, .4f);
        else
            world_tint(color.r, color.g, color.b, color.a);
        freeware_draw_point[0] = CAMERA + body.position - DrawPoint(body.freeware.size * .5f, body.freeware.size * .5f);
        world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, body.freeware.size, body.freeware.size);

        if (body.death_timer < 0) {
            if (body.freeware.type == 1) {
                const vec2f_t &position = body.position - DrawPoint(body.freeware.size * .5f, body.freeware.size * .5f);
                fx_queue_add_rotated(&position, &color, body.freeware.heading - 1.57079637f, body.freeware.size, 1);
            } else {
                const vec2f_t &position = body.position - DrawPoint(body.freeware.size * .5f, body.freeware.size * .5f);
                fx_queue_add_rotated(&position, &color, body.freeware.heading, body.freeware.size, 0);
            }
            fx_queue_add_random(&body.position);
#ifdef CRIMSON_FREEWARE_CLIENT
            if (++UI_GAME.run.kills == 1)
                std::puts(FREEWARE_VERSION " first kill");
#elif CL_BUILD != 10002
            ++freeware_kills;
#endif
            body.active = 0;
        }
    }
    end();
}
