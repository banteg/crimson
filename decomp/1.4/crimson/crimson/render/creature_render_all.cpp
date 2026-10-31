// crimson.exe 1.4.0, 0x40fd10.
#include "world_render.h"
extern "C" {
extern creature_t creature_pool[512];
extern int freeware_kills;
void fx_queue_add_rotated(const vec2f_t *, const effect_color_t *, float, float, int);
void freeware_blood(const vec2f_t *);
}
using namespace world140;
namespace {
__forceinline void creature_sheet() {
#ifdef CRIMSON_FREEWARE_CLIENT
    bind("goblin");
#else
    bind(freeware_creature_texture);
#endif
}
__forceinline void pose(const creature_t &c, bool shadow) {
    int cell = (int)(c.freeware.animation + .5f);
    const int bank = c.freeware.type;
    if (shadow && bank == 1) {
        if (cell > 15)
            cell = 0;
    } else if (cell > 15)
        cell = 31 - cell;
    if (c.death_timer != 16)
        cell = (int)(31.f - c.death_timer);
    if (bank == 1) {
        angle(c.freeware.heading - 1.57079637f);
        atlas_origin(32 + cell);
    } else {
        angle(c.freeware.heading);
        atlas_origin(cell);
    }
    uv(freeware_draw_point[0].x, freeware_draw_point[0].y, freeware_draw_point[1].x, freeware_draw_point[1].y);
}
__forceinline void draw_body(const creature_t &c, float inset, float size) {
    vec2f_t center = {CAMERA.x + c.position.x, CAMERA.y + c.position.y};
    vec2f_t pos = {center.x - inset, center.y - inset};
    freeware_draw_point[0] = pos;
    quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size, size);
}
} // namespace
extern "C" void creature_render_all() {
    creature_sheet();
    uv(0, 0, 1, 1);
    if (UI_FIELD(freeware_shadows, shadows)) {
        source(1);
        destination(6);
        begin();
        for (creature_t *c = creature_pool; c != creature_pool + 512; ++c)
            if (c->active) {
                pose(*c, true);
                const effect_color_t color = c->freeware.color;
                tint(color.r, color.g, color.b, color.a * .5f);
                draw_body(*c, c->freeware.size * .5f - 2.f, c->freeware.size * 1.04f);
            }
        end();
    }
    source(5);
    destination(6);
    bind(texture("glow"));
    tint(.3f, .6f, .3f, 1);
    tint(0, 0, 0, 1);
    uv(0, 0, 1, 1);
    angle(0);
    begin();
    for (creature_t *infected = creature_pool; infected != creature_pool + 512; ++infected)
        if (infected->active && infected->plague_infected)
            quad(CAMERA.x + infected->position.x - 40, CAMERA.y + infected->position.y - 40, 80, 80);
    end();
    destination(6);
    creature_sheet();
    begin();
    for (creature_t *body = creature_pool; body != creature_pool + 512; ++body)
        if (body->active) {
            pose(*body, false);
            const effect_color_t &color = body->freeware.color;
            if (UI_FIELD(bonus_freeze_timer, run.freeze) > 0)
                tint(44.f / 255, 195.f / 255, 1, .4f);
            else
                tint(color.r, color.g, color.b, color.a);
            draw_body(*body, body->freeware.size * .5f, body->freeware.size);
            if (body->death_timer < 0) {
                float half = body->freeware.size * .5f;
                vec2f_t pos = {body->position.x - half, body->position.y - half};
                bool alien = body->freeware.type == 1;
                float rot = alien ? body->freeware.heading - 1.57079637f : body->freeware.heading;
                fx_queue_add_rotated(&pos, &color, rot, body->freeware.size, (int)alien);
#ifdef CRIMSON_FREEWARE_CLIENT
                UI_GAME.queue_blood(body->position);
                if (++UI_GAME.run.kills == 1)
                    std::puts("1.4.0 first kill");
#else
                freeware_blood(&body->position);
                ++freeware_kills;
#endif
                body->active = 0;
            }
        }
    end();
}
