// State shared by the original modal screens, including their fade on dismissal.
#ifndef FREEWARE_OVERLAY_H
#define FREEWARE_OVERLAY_H
#include "freeware_ui.h"
extern "C" {
extern vec2f_t freeware_aim_screen;
extern unsigned char freeware_see_through, freeware_scores_open, freeware_credits_open;
extern float freeware_name_alpha;
unsigned char freeware_overlay_begin();
}
namespace ui140 {
#define UI_ALPHA UI_FIELD(freeware_transition_alpha, transition_alpha)
#define UI_PENDING UI_FIELD(freeware_transition_pending, transition_pending)
#define UI_SINCE UI_FIELD(freeware_state_since, state_since)
#define UI_SEE_THROUGH UI_FIELD(freeware_see_through, perk_transparent)
#define UI_MOUSE_X UI_FIELD(freeware_aim_screen.x, cursor_x)
#define UI_MOUSE_Y UI_FIELD(freeware_aim_screen.y, cursor_y)
__forceinline float raw_delta() {
#ifdef CRIMSON_FREEWARE_CLIENT
    return freeware_frame_delta;
#else
    return grim_interface_ptr->grim_get_frame_dt();
#endif
}
__forceinline bool key_pressed(int key) {
#ifdef CRIMSON_FREEWARE_CLIENT
    const freeware::Input &in = *freeware_frame_input;
    return key == 1 ? in.escape : key == 0x1c ? in.accept : key == 0x20 ? in.delete_scores : in.space_pressed;
#else
    return grim_interface_ptr->grim_was_key_pressed(key);
#endif
}
__forceinline bool left_click() {
#ifdef CRIMSON_FREEWARE_CLIENT
    return freeware_frame_input->click;
#else
    return grim_interface_ptr->grim_was_mouse_button_pressed(0);
#endif
}
__forceinline void set_state(int id) {
#ifdef CRIMSON_FREEWARE_CLIENT
    UI_GAME.enter_state(id);
#else
    game_state_id = id;
#endif
}
__forceinline void backdrop(float age, bool see_through) {
    angle(0);
    uv(0, 0, 1, 1);
    tint(0, 0, 0, age >= 1 ? 1 : age);
    if (see_through)
        tint(0, 0, 0, .3f);
    if (UI_ALPHA < 1)
        tint(0, 0, 0, UI_ALPHA);
}
__forceinline void draw_backdrop() {
#ifdef CRIMSON_FREEWARE_CLIENT
    bind("bullet");
#else
    bind(freeware_bullet_texture);
#endif
    begin();
    quad(-300, -300, (float)(viewport_width() + 300), (float)(viewport_height() + 600));
    end();
    tint(1, 1, 1, .68f);
    scale(.76f);
#ifndef CRIMSON_FREEWARE_CLIENT
    grim_interface_ptr->grim_set_config_var(0x12, 1u);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
#else
    UI_GAME.ui.destination_blend = 6;
#endif
    tint(1, 1, 1, .88f);
    if (UI_ALPHA < 1)
        tint(1, 1, 1, UI_ALPHA * .88f);
}
__forceinline void reset_overlay_time() {
    UI_PENDING = 0;
    UI_SINCE = freeware_simulation_clock;
}
__forceinline void aim_cursor() {
    bind(texture("aim32"));
    uv(0, 0, 1, 1);
    tint(1, 1, 1, .64f);
    begin();
    quad(UI_MOUSE_X - 16, UI_MOUSE_Y - 16, 32, 32);
    end();
}
__forceinline bool dismiss_scroll(bool past_end) {
    if (UI_ALPHA < 1)
        UI_ALPHA -= frame_dt * 2.4f;
    if (key_pressed(1) || key_pressed(0x1c) || left_click() || past_end)
        UI_ALPHA -= frame_dt;
    if (UI_ALPHA > 0)
        return false;
    set_state(1);
    UI_SINCE = freeware_simulation_clock;
    UI_PENDING = 1;
    return true;
}
} // namespace ui140
#endif
