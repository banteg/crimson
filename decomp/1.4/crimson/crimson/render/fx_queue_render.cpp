// crimson.exe 1.4.0, 0x40e830. Safe mode keeps the corpse queue for the next frame.
#include "../effects/freeware_fx_queues.h"
#include "world_render.h"
extern "C" {
extern unsigned char freeware_safe_mode;
extern int terrain_render_target, freeware_blood_texture;
int crt_rand();
}
using namespace world140;

namespace {
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
    atlas_origin(index);
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
        corpse_uv(i);
        const effect_color_t &c = FX_STORE(freeware_corpse_colors, corpse_colors)[i];
        world_tint(c.r, c.g, c.b, .5f);
        world_angle(FX_STORE(freeware_corpse_angles, corpse_angles)[i]);
        const vec2f_t &pos = CORPSE_POS(i);
        vec2f_t top = {pos.x + 2, pos.y + 2};
        freeware_draw_point[0] = top;
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
        const effect_color_t &c = FX_STORE(freeware_corpse_colors, corpse_colors)[j];
        world_tint(c.r, c.g, c.b, c.a);
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
        if (CORPSES > 0)
            corpses(true);
        return;
    }
    if (!BLOOD && !CORPSES && !SHELLS && !IMPACTS)
        return;
    ground_target(true);
    if (IMPACTS > 0) {
        begin();
        uv(0, 0, 1, 1);
        for (int i = 0; i < IMPACTS; ++i) {
#ifdef CRIMSON_FREEWARE_CLIENT
            const freeware::QueuedImpact &e = FX_STORE(fx_queue, impacts)[i];
#else
            const fx_queue_entry_t &e = fx_queue[i];
#endif
            bind(e.effect_id);
            world_tint(e.color.r, e.color.g, e.color.b, e.color.a);
            world_angle(e.rotation);
            world_quad(e.position.x - e.width * .5f, e.position.y - e.height * .5f, e.width, e.height);
        }
        end();
    }
    if (BLOOD > 0) {
        world_sheet(freeware_blood_texture, "blood");
        begin();
        world_tint(1, 1, 1, .78f);
        uv(0, 0, 1, 1);
        for (int blood = 0; blood < BLOOD; ++blood) {
            world_angle((crt_rand() % 628) * .01f);
            float size = (float)(crt_rand() % 20 - 10) + 32.f;
            const vec2f_t &p = FX_STORE(freeware_blood_positions, blood)[blood];
            vec2f_t top = {p.x - size * .5f, p.y - size * .5f};
            freeware_draw_point[0] = top;
            world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, size, size);
        }
        end();
    }
    if (CORPSES > 0)
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
    IMPACTS = 0;
    SHELLS = 0;
    CORPSES = 0;
    BLOOD = 0;
    ground_target(false);
}
