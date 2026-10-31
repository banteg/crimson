// crimson.exe 1.4.0, 0x40e830. Safe mode keeps the corpse queue for the next frame.
#include "world_render.h"
extern "C" {
extern unsigned char freeware_safe_mode;
extern int terrain_render_target, freeware_blood_texture;
extern int fx_queue_count, freeware_blood_count, freeware_shell_count, freeware_corpse_count;
extern fx_queue_entry_t fx_queue[];
extern vec2f_t freeware_blood_positions[], freeware_shell_positions[], freeware_corpse_positions[];
extern float freeware_corpse_angles[], freeware_corpse_sizes[];
extern int freeware_corpse_species[];
extern effect_color_t freeware_corpse_colors[];
int crt_rand();
}
using namespace world140;

namespace {
#ifdef CRIMSON_FREEWARE_CLIENT
#define COUNT(native, member) ((int)UI_GAME.member.size())
#define IMPACT(i) UI_GAME.pending_impacts[i]
typedef freeware::QueuedImpact Impact;
#else
#define COUNT(native, member) (native)
#define IMPACT(i) fx_queue[i]
typedef fx_queue_entry_t Impact;
#endif
#define IMPACTS COUNT(fx_queue_count, pending_impacts)
#define BLOOD COUNT(freeware_blood_count, pending_blood)
#define CORPSES COUNT(freeware_corpse_count, pending_decals)
#define SHELLS COUNT(freeware_shell_count, pending_shells)
#define CORPSE_POS(i) UI_FIELD(freeware_corpse_positions[i], pending_decals[i].position)
#define CORPSE_SIZE(i) UI_FIELD(freeware_corpse_sizes[i], pending_decals[i].size)
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
    if (!UI_FIELD(freeware_corpse_species[i], pending_decals[i].cell == 62))
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
        const effect_color_t &c = UI_FIELD(freeware_corpse_colors[i], pending_decals[i].color);
        world_tint(c.r, c.g, c.b, .5f);
        world_angle(UI_FIELD(freeware_corpse_angles[i], pending_decals[i].heading));
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
        const effect_color_t &c = UI_FIELD(freeware_corpse_colors[j], pending_decals[j].color);
        world_tint(c.r, c.g, c.b, c.a);
        world_angle(UI_FIELD(freeware_corpse_angles[j], pending_decals[j].heading));
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
            const Impact &e = IMPACT(i);
            bind(UI_FIELD(e.effect_id, pending_impacts[i].texture));
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
            const vec2f_t &p = UI_FIELD(freeware_blood_positions[blood], pending_blood[blood]);
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
            const vec2f_t &p = UI_FIELD(freeware_shell_positions[shell], pending_shells[shell]);
            vec2f_t top = {p.x - 2, p.y - 2};
            freeware_draw_point[0] = top;
            world_quad(freeware_draw_point[0].x, freeware_draw_point[0].y, 4, 4);
        }
        end();
    }
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.pending_impacts.clear();
    UI_GAME.pending_shells.clear();
    UI_GAME.pending_decals.clear();
    UI_GAME.pending_blood.clear();
#else
    fx_queue_count = 0;
    freeware_shell_count = 0;
    freeware_corpse_count = 0;
    freeware_blood_count = 0;
#endif
    ground_target(false);
}
