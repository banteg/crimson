// Freeware ground decals and corpse passes. Safe mode leaves the queues intact.
#include "../effects/freeware_fx_queues.h"
#include "world_render.h"
#include "freeware_edition.h"
extern "C" {
extern unsigned char freeware_safe_mode;
extern int terrain_render_target, freeware_blood_texture;
int crt_rand();
}
using namespace world140;

namespace {
struct MarkPoint : vec2f_t {
    __forceinline MarkPoint(float x_value, float y_value) {
        x = x_value;
        y = y_value;
    }
};
#define IMPACT(i) FX_STORE(fx_queue, impacts)[i]
#define CORPSE_COLOR(i) FX_STORE(freeware_corpse_colors, corpse_colors)[i]
#define IMPACTS FX_STORE(fx_queue_count, impact_count)
#define BLOOD FX_STORE(freeware_blood_count, blood_count)
#define CORPSES FX_STORE(freeware_corpse_count, corpse_count)
#define SHELLS FX_STORE(freeware_shell_count, shell_count)
#define CORPSE_POS(i) FX_STORE(freeware_corpse_positions, corpse_positions)[i]
#define CORPSE_SIZE(i) FX_STORE(freeware_corpse_sizes, corpse_sizes)[i]
__forceinline void ground_target(bool enable) {
#ifdef CRIMSON_FREEWARE_CLIENT
    // Swap at both target changes so draws already on the backbuffer stay in order.
    UI_GAME.frame_sprites.swap(UI_GAME.terrain_marks);
#else
    grim_interface_ptr->grim_set_render_target(enable ? terrain_render_target : -1);
#endif
}
__forceinline void mark_uv(int index) {
#ifdef CRIMSON_FREEWARE_CLIENT
    atlas_origin(index);
#else
    const vec2f_t &origin = freeware_atlas_uv[index];
    freeware_draw_point[0] = origin;
    freeware_draw_point[1] = MarkPoint(origin.x + .125f, origin.y + .125f);
#endif
    world_uv(freeware_draw_point[0].x, freeware_draw_point[0].y, freeware_draw_point[1].x,
             freeware_draw_point[1].y);
}
__forceinline void corpse_uv(int i) {
    if (!FX_STORE(freeware_corpse_species, corpse_species)[i])
        mark_uv(31);
    else
        mark_uv(62);
}
__forceinline void corpses(bool screen) {
    world_sheet(freeware_creature_texture, "goblin");
    source(1);
    destination(6);
    begin();
    for (int i = 0; i < CORPSES; ++i) {
        effect_color_t &c = CORPSE_COLOR(i);
        if (FREEWARE_EDITION < 10400)
            c.a = .5f;
        corpse_uv(i);
        world_tint(c.r, c.g, c.b, FREEWARE_EDITION < 10400 ? c.a : .5f);
        world_angle(FX_STORE(freeware_corpse_angles, corpse_angles)[i]);
        const vec2f_t &pos = CORPSE_POS(i);
        freeware_draw_point[0] = MarkPoint(pos.x + 2, pos.y + 2);
        float size = CORPSE_SIZE(i) * 1.04f;
        if (screen)
            world_quad(freeware_draw_point[0].x + CAMERA.x, freeware_draw_point[0].y + CAMERA.y, size, size);
        else
            world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size, size);
    }
    end();
    source(5);
    destination(6);
    begin();
    for (int j = 0; j < CORPSES; ++j) {
        corpse_uv(j);
        if (FREEWARE_EDITION < 10400)
            CORPSE_COLOR(j).a = .99f;
        world_tint(CORPSE_COLOR(j).r, CORPSE_COLOR(j).g, CORPSE_COLOR(j).b, CORPSE_COLOR(j).a);
        world_angle(FX_STORE(freeware_corpse_angles, corpse_angles)[j]);
        float size = CORPSE_SIZE(j);
        if (screen)
            world_quad(CAMERA.x + CORPSE_POS(j).x, CAMERA.y + CORPSE_POS(j).y, size, size);
        else
            world_quad(CORPSE_POS(j).x, CORPSE_POS(j).y, size, size);
    }
    end();
}
} // namespace
extern "C" void fx_queue_render() {
    if (UI_FIELD(freeware_safe_mode, safe_mode)) {
        if (FREEWARE_EDITION >= 10400 && CORPSES > 0)
            corpses(true);
        return;
    }
    if (!BLOOD && !CORPSES && !SHELLS && (FREEWARE_EDITION == 10002 || !IMPACTS))
        return;
    ground_target(true);
    if (FREEWARE_EDITION != 10002 && IMPACTS > 0) {
        begin();
        uv(0, 0, 1, 1);
        for (int i = 0; i < IMPACTS; ++i) {
            bind(IMPACT(i).effect_id);
            world_tint(IMPACT(i).color.r, IMPACT(i).color.g, IMPACT(i).color.b, IMPACT(i).color.a);
            world_angle(IMPACT(i).rotation);
            world_quad(IMPACT(i).position.x - IMPACT(i).width * .5f, IMPACT(i).position.y - IMPACT(i).height * .5f,
                       IMPACT(i).width, IMPACT(i).height);
        }
        end();
    }
    if (BLOOD > 0) {
        world_sheet(freeware_blood_texture, "blood");
        begin();
        world_tint(1, 1, 1, FREEWARE_EDITION < 10400 ? .8f : .78f);
        uv(0, 0, 1, 1);
        for (int blood = 0; blood < BLOOD; ++blood) {
            world_angle((crt_rand() % 628) * .01f);
            float size = (float)(crt_rand() % 20 - 10) + 32.f;
            const vec2f_t &p = FX_STORE(freeware_blood_positions, blood)[blood];
            vec2f_t half = {size * .5f, size * .5f};
            vec2f_t top = {p.x - half.x, p.y - half.y};
            freeware_draw_point[0] = top;
            world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size, size);
        }
        end();
    }
    if (FREEWARE_EDITION >= 10400 && CORPSES > 0)
        corpses(false);
    if (SHELLS > 0) {
        world_sheet(freeware_bullet_icon, "bullet_i");
        begin();
        world_tint(1, 1, 1, .8f);
        uv(0, 0, 1, 1);
        for (int shell = 0; shell < SHELLS; ++shell) {
            world_angle((crt_rand() % 628) * .01f);
            const vec2f_t &p = FX_STORE(freeware_shell_positions, shells)[shell];
            vec2f_t top = {p.x - 2, p.y - 2};
            freeware_draw_point[0] = top;
            world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, 4, 4);
        }
        end();
    }
    if (FREEWARE_EDITION < 10400 && CORPSES > 0)
        corpses(false);
    if (FREEWARE_EDITION != 10002)
        IMPACTS = 0;
    SHELLS = 0;
    CORPSES = 0;
    BLOOD = 0;
    ground_target(false);
}
