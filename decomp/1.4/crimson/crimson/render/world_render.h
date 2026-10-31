// Shared Grim state at the creature, player and effect passes of the 1.4.0 frame.
#ifndef FREEWARE_WORLD_RENDER_H
#define FREEWARE_WORLD_RENDER_H
#include "../ui/freeware_ui.h"
extern "C" {
extern vec2f_t freeware_camera, freeware_draw_point[2];
extern vec2f_t freeware_atlas_uv[64];
extern int freeware_creature_texture, freeware_player_texture;
extern unsigned char freeware_shadows;
extern float bonus_freeze_timer;
}
namespace world140 {
using namespace ui140;
#define CAMERA UI_FIELD(freeware_camera, camera)
__forceinline void source(unsigned factor) {
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.ui.source_blend = factor;
#else
    grim_interface_ptr->grim_set_config_var(0x13, factor);
#endif
}
__forceinline void destination(unsigned factor) {
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.ui.destination_blend = factor;
#else
    grim_interface_ptr->grim_set_config_var(0x14, factor);
#endif
}
__forceinline void atlas(int cell) {
#ifdef CRIMSON_FREEWARE_CLIENT
    // A corpse can overshoot the last animation cell on a long frame. The next
    // pair in the original BSS holds the map pointer and padding, both effectively zero as UVs.
    vec2f_t origin = {0, 0};
    if (cell >= 0 && cell < 64) {
        origin.x = (cell % 8) * .125f;
        origin.y = (cell / 8) * .125f;
    }
#else
    const vec2f_t &origin = freeware_atlas_uv[cell];
#endif
    freeware_draw_point[0] = origin;
    freeware_draw_point[1].x = origin.x + .125f;
    freeware_draw_point[1].y = origin.y + .125f;
    uv(freeware_draw_point[0].x, freeware_draw_point[0].y, freeware_draw_point[1].x, freeware_draw_point[1].y);
}
} // namespace world140
#endif
