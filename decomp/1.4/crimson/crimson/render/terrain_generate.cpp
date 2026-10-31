// crimson.exe 1.4.0, 0x40e060.
#include "freeware_level.h"
#include "world_render.h"

extern "C" {
extern unsigned char freeware_safe_mode;
extern int freeware_arena_width, freeware_arena_height, terrain_render_target;
int crt_rand();
}

using namespace world140;
namespace {
#ifdef CRIMSON_FREEWARE_CLIENT
#define bind_ground(name) bind(name)
#else
#define bind_ground(name)                                                                                         \
    grim_interface_ptr->grim_bind_texture(grim_interface_ptr->grim_get_texture_handle((char *)name), 0)
#endif
__forceinline void clear_ground(float r, float g, float b) {
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.terrain_clear = {r, g, b, 1};
#else
    grim_interface_ptr->grim_clear_color(r, g, b, 1);
#endif
}
__forceinline void scatter(int density) {
    begin();
    for (int i = 0; i < freeware_arena_height * freeware_arena_width * density / 524288; ++i) {
        world_angle((crt_rand() % 314) * .01f);
        int h = freeware_arena_height + 64, w = freeware_arena_width + 64;
        vec2f_t p = {(float)(crt_rand() % (w + 64) - 64), (float)(crt_rand() % (h + 64) - 64)};
        world_quad(p.x, p.y, 128, 128);
    }
    end();
}
__forceinline void shadow(float x, float y, float alpha) {
    vec2f_t offset = {x, y};
    CAMERA = offset;
    world_tint(1, 1, 1, alpha);
    freeware_current_map->render_layer(1, 1);
}
} // namespace
extern "C" void terrain_generate(unsigned char textured) {
    if (UI_FIELD(freeware_safe_mode, safe_mode))
        return;
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_set_config_var(0x12, true);
#endif
    source(5);
    destination(6);
    filter(1);
    world_uv(0, 0, 1, 1);
#ifdef CRIMSON_FREEWARE_CLIENT
    ++UI_GAME.terrain_revision;
    UI_GAME.terrain.clear();
    UI_GAME.terrain.swap(UI_GAME.frame_sprites);
#else
    grim_interface_ptr->grim_set_render_target(terrain_render_target);
#endif
    if (!textured)
        clear_ground(0, 0, 0);
    else {
        clear_ground(63.f / 255, 56.f / 255, 25.f / 255);
        bind_ground("grass1.tga");
        world_tint(.7f, .7f, .7f, .9f);
        scatter(700);
        bind_ground("mud1.tga");
        scatter(35);
    }
    vec2f_t zero = {0, 0};
    CAMERA = zero;
    source(5);
    destination(6);
    world_tint(1, 1, 1, 1);
    freeware_current_map->render_layer(0, 0);
    source(1);
    for (int d = 3; d < 10; d += 3) {
        shadow((float)-d, (float)-d, .08f);
        shadow((float)-d, (float)d, .08f);
        shadow((float)d, (float)-d, .08f);
        shadow((float)d, (float)d, .08f);
    }
    for (int i = 0; i < 8; ++i)
        shadow(i * 1.1f, i * 1.1f, .1f);
    source(5);
    destination(6);
    filter(2);
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.terrain.swap(UI_GAME.frame_sprites);
#else
    grim_interface_ptr->grim_set_render_target(-1);
#endif
}
