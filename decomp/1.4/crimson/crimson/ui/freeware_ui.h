// Grim calls shared by the 1.4.0 HUD and menu screens.
#ifndef FREEWARE_UI_H
#define FREEWARE_UI_H
#include "crimsonland_types.h"
#ifdef CRIMSON_FREEWARE_CLIENT
#include "game.h"
extern freeware::Game *freeware_frame_game;
extern const freeware::Input *freeware_frame_input;
extern float freeware_frame_delta;
#define UI_GAME (*freeware_frame_game)
#define UI_FIELD(native, member) (UI_GAME.member)
#ifndef __forceinline
#define __forceinline inline
#endif
#else
#include "grim2d_cpp.h"
extern "C" IGrim2D_cpp *grim_interface_ptr;
#define UI_FIELD(native, member) (native)
#endif
extern "C" {
extern player_state_t player_state_table[2];
extern int current_player_index, config_player_count, screen_width, screen_height, game_state_id;
extern game_mode_id_t config_game_mode;
extern float frame_dt, freeware_elapsed_seconds, freeware_simulation_clock, freeware_state_since,
    freeware_transition_alpha;
extern unsigned char freeware_game_active, freeware_transition_pending;
extern int freeware_pending_perks, freeware_bullet_icon, freeware_bullet_texture;
extern char freeware_ui_buffer[];
char *weapon_name_get(int);
}
namespace ui140 {
#ifdef CRIMSON_FREEWARE_CLIENT
typedef const char *Texture;
__forceinline int viewport_width() { return freeware::width; }
__forceinline int viewport_height() { return freeware::height; }
__forceinline Texture texture(const char *name) { return name; }
__forceinline void bind(Texture value) { UI_GAME.ui.texture = value; }
__forceinline void filter(unsigned value) { UI_GAME.ui.filter = value; }
__forceinline void scale(float value) { UI_GAME.ui.scale = value; }
__forceinline void angle(float value) { UI_GAME.ui.angle = value; }
__forceinline void uv(float u, float v, float s, float t) { UI_GAME.ui.uv = {u, v, s, t}; }
__forceinline void tint(float r, float g, float b, float a) { UI_GAME.ui.color = {r, g, b, a}; }
__forceinline void begin() {}
__forceinline void end() {}
__forceinline void quad(float x, float y, float w, float h) {
    const freeware::UiState &state = UI_GAME.ui;
    UI_GAME.frame_sprites.push_back({state.texture, x, y, w, h, state.angle, state.color, state.uv, state.filter,
                                     state.destination_blend, state.source_blend});
}
__forceinline void text(float x, float y, const char *s) {
    UI_GAME.frame_labels.push_back({s, x, y, UI_GAME.ui.scale, UI_GAME.ui.color, UI_GAME.frame_sprites.size()});
}
#else
typedef int Texture;
__forceinline int viewport_width() { return CL_BUILD == 10002 ? 640 : screen_width; }
__forceinline int viewport_height() { return CL_BUILD == 10002 ? 480 : screen_height; }
__forceinline Texture texture(const char *name) {
    return grim_interface_ptr->grim_get_texture_handle((char *)name);
}
__forceinline void bind(Texture value) {
#if CL_BUILD < 10400
    grim_interface_ptr->grim_bind_texture(value);
#else
    grim_interface_ptr->grim_bind_texture(value, 0);
#endif
}
__forceinline void bind(const char *name) {
#if CL_BUILD < 10400
    grim_interface_ptr->grim_bind_texture(grim_interface_ptr->grim_get_texture_handle((char *)name));
#else
    grim_interface_ptr->grim_bind_texture(grim_interface_ptr->grim_get_texture_handle((char *)name), 0);
#endif
}
__forceinline void filter(unsigned value) { grim_interface_ptr->grim_set_config_var(CL_BUILD == 10002 ? 0xf : 0x15, value); }
__forceinline void scale(float value) { grim_interface_ptr->grim_set_config_var(CL_BUILD == 10002 ? 0x11 : 0x18, value); }
__forceinline void angle(float value) { grim_interface_ptr->grim_set_rotation(value); }
__forceinline void uv(float u, float v, float s, float t) { grim_interface_ptr->grim_set_uv(u, v, s, t); }
__forceinline void tint(float r, float g, float b, float a) { grim_interface_ptr->grim_set_color(r, g, b, a); }
__forceinline void begin() { grim_interface_ptr->grim_begin_batch(); }
__forceinline void end() { grim_interface_ptr->grim_end_batch(); }
__forceinline void quad(float x, float y, float w, float h) { grim_interface_ptr->grim_draw_quad(x, y, w, h); }
__forceinline void text(float x, float y, const char *s) {
    grim_interface_ptr->grim_draw_text_mono(x, y, (char *)s);
}
#endif
} // namespace ui140
#endif
