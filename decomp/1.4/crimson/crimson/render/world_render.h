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
extern "C" {
extern int freeware_no_pickup, freeware_pickup_id, freeware_pickup_weapon;
extern int freeware_bonus_fire, freeware_bonus_freeze, freeware_bonus_weapon, freeware_bonus_nuke,
    freeware_bonus_shield, freeware_bonus_time;
extern vec2f_t freeware_pickup_position, freeware_bomb_position;
extern float freeware_pickup_time, freeware_bomb_age;
}
#define PICKUP_ID ((int)UI_FIELD(freeware_pickup_id, run.pickup.kind))
#define PICKUP_TIME UI_FIELD(freeware_pickup_time, run.pickup.time)
#define PICKUP_WEAPON UI_FIELD(freeware_pickup_weapon, run.pickup.weapon)
#define PICKUP_POS UI_FIELD(freeware_pickup_position, run.pickup.pos)
#define BOMB_AGE UI_FIELD(freeware_bomb_age, run.bomb_age)
#define BOMB_POS UI_FIELD(freeware_bomb_position, run.bomb_pos)
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
__forceinline void atlas_origin(int cell) {
#ifdef CRIMSON_FREEWARE_CLIENT
    // On its final frame a corpse can read past the atlas. Cell 64 aliases the
    // map pointer (a subnormal UV) and padding. Cell 65 aliases the camera.
    vec2f_t origin = {0, 0};
    if (cell >= 0 && cell < 64) {
        origin.x = (cell % 8) * .125f;
        origin.y = (cell / 8) * .125f;
    } else if (cell == 65)
        origin = CAMERA;
#else
    const vec2f_t &origin = freeware_atlas_uv[cell];
#endif
    freeware_draw_point[0] = origin;
    vec2f_t last = {origin.x + .125f, origin.y + .125f};
    freeware_draw_point[1] = last;
}
__forceinline void atlas(int cell) {
    atlas_origin(cell);
    uv(freeware_draw_point[0].x, freeware_draw_point[0].y, freeware_draw_point[1].x, freeware_draw_point[1].y);
}
} // namespace world140
#endif
