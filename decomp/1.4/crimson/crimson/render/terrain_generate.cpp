// Freeware ground render target, including authored map shadows from 1.3.0.
#include "freeware_level.h"
#include "world_render.h"
#include "freeware_edition.h"

extern "C" {
extern unsigned char freeware_safe_mode;
extern int freeware_arena_width, freeware_arena_height, terrain_render_target;
int crt_rand();
}

using namespace world140;
namespace {
__forceinline void clear_ground(float r, float g, float b) {
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.terrain_clear = {r, g, b, 1};
#else
    grim_interface_ptr->grim_clear_color(r, g, b, 1);
#endif
}
__forceinline void scatter(int density) {
    begin();
    for (int i = 0; i < (int)((unsigned)freeware_arena_width * freeware_arena_height * density) / 524288; ++i) {
        world_angle((crt_rand() % 314) * .01f);
        int h = freeware_arena_height + 64, w = freeware_arena_width + 64;
        vec2f_t p = {(float)(crt_rand() % (w + 64) - 64), (float)(crt_rand() % (h + 64) - 64)};
        world_quad(p.x, p.y, 128, 128);
    }
    end();
}
#if CL_BUILD < 10400 && !defined(CRIMSON_FREEWARE_CLIENT)
// The older builds register the base terrain textures as "grass" and "mud".
#define GROUND_GRASS "grass"
#define GROUND_MUD "mud"
#else
#define GROUND_GRASS "grass1.tga"
#define GROUND_MUD "mud1.tga"
#endif
__forceinline void ground_layers(const char *base, const char *detail, int density) {
    world_sheet(grim_interface_ptr->grim_get_texture_handle((char *)base), base);
    world_tint(.7f, .7f, .7f, .9f);
    scatter(density);
    world_sheet(grim_interface_ptr->grim_get_texture_handle((char *)detail), detail);
    scatter(35);
}
__forceinline void shadow(float x, float y, float alpha) {
    vec2f_t offset = {x, y};
    CAMERA = offset;
    world_tint(1, 1, 1, alpha);
    freeware_current_map->render_layer(1, 1);
}
} // namespace
#if CL_BUILD == 10002 && !defined(CRIMSON_FREEWARE_CLIENT)
extern "C" void terrain_generate(int ground) {
#else
extern "C" void terrain_generate(unsigned char textured) {
#endif
#if FREEWARE_EDITION == 10002
    // 0x405090 rolls the alternate ground before checking safe mode.
#ifdef CRIMSON_FREEWARE_CLIENT
    int ground = textured;
#endif
    if (crt_rand() % 256 == 1)
        ground = crt_rand() % 3 + 1;
#endif
    if (UI_FIELD(freeware_safe_mode, safe_mode))
        return;
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_set_config_var(CL_BUILD == 10002 ? 0xc : 0x12, true);
#endif
    source(5);
    destination(6);
#if CL_BUILD != 10002
    filter(1);
#endif
    world_uv(0, 0, 1, 1);
#ifdef CRIMSON_FREEWARE_CLIENT
    ++UI_GAME.terrain_revision;
    UI_GAME.terrain.clear();
    UI_GAME.terrain.swap(UI_GAME.frame_sprites);
#else
    grim_interface_ptr->grim_set_render_target(terrain_render_target);
#endif
#if FREEWARE_EDITION == 10002
    clear_ground(63.f / 255, 56.f / 255, 25.f / 255);
    if (ground == 1)
        ground_layers(GROUND_GRASS, GROUND_MUD, 600);
    else if (ground == 2)
        ground_layers("gnd_bdirt", "gnd_bdirt", 600);
    else if (ground == 3)
        ground_layers("gnd_smallrocks", "gnd_smallrocks", 600);
#else
    if (textured)
        clear_ground(63.f / 255, 56.f / 255, 25.f / 255);
    else
        clear_ground(0, 0, 0);
    if (textured)
        ground_layers(GROUND_GRASS, GROUND_MUD, 700);
    vec2f_t zero = {0, 0};
    CAMERA = zero;
    source(5);
    destination(6);
    world_tint(1, 1, 1, 1);
    freeware_current_map->render_layer(0, 0);
    source(1);
    int i;
    for (i = 3; i < 10; i += 3) {
        shadow((float)-i, (float)-i, .08f);
        shadow((float)-i, (float)i, .08f);
        shadow((float)i, (float)-i, .08f);
        shadow((float)i, (float)i, .08f);
    }
    for (i = 0; i < 8; ++i)
        shadow(i * 1.1f, i * 1.1f, .1f);
    source(5);
    destination(6);
    filter(2);
#endif
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.terrain.swap(UI_GAME.frame_sprites);
#else
    grim_interface_ptr->grim_set_render_target(-1);
#endif
}
