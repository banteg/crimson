// crimson.exe 1.4.0, 0x40f340.
#include "world_render.h"
extern "C" {
extern unsigned char freeware_filter_sharp, freeware_safe_mode;
extern int freeware_arena_width, freeware_arena_height, terrain_render_target;
}
using namespace world140;
#ifdef CRIMSON_FREEWARE_CLIENT
#define world_quad ui140::quad
#else
#define world_quad grim_interface_ptr->grim_draw_quad
#endif
namespace {
__forceinline void ground() {
#ifdef CRIMSON_FREEWARE_CLIENT
    bind("ground");
#else
    bind(terrain_render_target);
#endif
    begin();
    tint(1, 1, 1, 1);
    uv(0, 0, 1, 1);
    angle(0);
}
} // namespace
extern "C" void terrain_render() {
#ifdef CRIMSON_FREEWARE_CLIENT
    if (!UI_GAME.smooth)
#else
    if (freeware_filter_sharp)
#endif
        filter(1);
    if (UI_FIELD(freeware_safe_mode, safe_mode)) {
        ground();
        uv(0, 0, 1, 1);
        for (int y = 0; y < freeware_arena_height / 256 + 1; ++y)
            for (int x = 0; x < freeware_arena_width / 256 + 1; ++x)
                world_quad(CAMERA.x + x * 256, CAMERA.y + y * 256, 256, 256);
        end();
        filter(2);
        return;
    }
    ground();
    world_quad(CAMERA.x, CAMERA.y, (float)freeware_arena_width, (float)freeware_arena_height);
    uv(0, 0, 1, 1);
    end();
    filter(2);
}
