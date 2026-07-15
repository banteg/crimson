#include "crimsonland_gameplay.h"

class ui_vec2_cpp_t {
public:
    void construct(void);

    float x;
    float y;
};

class ui_vec2_value_t {
public:
    ui_vec2_value_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    float x;
    float y;
};

static __forceinline ui_vec2_value_t make_ui_vec2(float x, float y)
{
    return ui_vec2_value_t(x, y);
}

typedef void (ui_vec2_cpp_t::*ui_vec2_callback_t)(void);

extern "C" void __stdcall invoke_callback_n(
    ui_vec2_cpp_t *cursor,
    int stride,
    int count,
    ui_vec2_callback_t callback);
extern "C" ui_menu_item_subtemplate_block_t *__fastcall
ui_template_block_set_mode4(ui_menu_item_subtemplate_block_t *block);
extern "C" ui_menu_template_triplet_t *__fastcall
ui_template_triplet_reset_and_seed_modes(ui_menu_template_triplet_t *element);

extern "C" ui_element_t ui_sign_crimson;
extern "C" ui_element_t ui_element_slot_01_main_menu_aux;
extern "C" ui_element_t ui_element_slot_03_main_menu_play_game;
extern "C" ui_element_t ui_element_slot_04_main_menu_options;
extern "C" ui_element_t ui_element_slot_05_main_menu_statistics;
extern "C" ui_element_t ui_element_slot_02_main_menu_primary;
extern "C" ui_element_t ui_element_slot_footer_variant_a;
extern "C" ui_element_t ui_element_slot_footer_variant_b;
extern "C" ui_element_t ui_element_slot_31;
extern "C" ui_element_t ui_element_slot_32_layout_c;
extern "C" ui_element_t ui_element_slot_10;
extern "C" ui_element_t ui_element_slot_11;
extern "C" ui_element_t ui_element_slot_12_layout_a;
extern "C" ui_element_t ui_element_slot_08;
extern "C" ui_element_t ui_element_slot_09;
extern "C" ui_element_t ui_element_slot_33;
extern "C" ui_element_t ui_element_slot_15;
extern "C" ui_element_t ui_element_slot_16;
extern "C" ui_element_t ui_element_slot_17;
extern "C" ui_element_t ui_element_slot_19;
extern "C" ui_element_t ui_element_slot_20;
extern "C" ui_element_t ui_element_slot_21;
extern "C" ui_element_t ui_element_slot_22;
extern "C" ui_element_t ui_element_slot_23;
extern "C" ui_element_t ui_element_slot_24;
extern "C" ui_element_t ui_element_slot_25;
extern "C" ui_element_t ui_element_slot_26;
extern "C" ui_element_t ui_element_slot_27;
extern "C" ui_element_t ui_element_slot_29;
extern "C" ui_element_t ui_element_slot_30;
extern "C" ui_element_t ui_element_slot_13;
extern "C" ui_element_t ui_element_slot_14;
extern "C" ui_element_t ui_element_slot_18_layout_b;
extern "C" ui_element_t ui_element_slot_34;
extern "C" ui_element_t ui_element_slot_35;
extern "C" ui_element_t ui_element_slot_36;
extern "C" ui_element_t ui_element_slot_37;
extern "C" ui_element_t ui_element_slot_38;
extern "C" ui_element_t ui_element_slot_39;
extern "C" ui_element_t ui_element_slot_28;
extern "C" ui_element_t ui_element_slot_40;
extern "C" ui_element_t ui_perk_prompt_element;

extern "C" unsigned char highscore_return_latch;
extern "C" unsigned char player_overlay_suppressed_latch;
extern "C" int pause_keybind_help_alpha_ms;
extern "C" int player_name_length;
extern "C" float camera_shake_timer;
extern "C" unsigned char gameplay_transition_latch;
extern "C" unsigned char highscore_save_skip_record_init;
extern "C" unsigned char ui_focus_input_locked;
extern "C" unsigned char input_mouse_delta_nonzero;
extern "C" unsigned char ui_mouse_blocked;
extern "C" float ui_transition_alpha;
extern "C" ui_vec2_value_t camera_shake_offset;

static __forceinline void construct_ui_element_inline(ui_element_t *element)
{
    invoke_callback_n(
        (ui_vec2_cpp_t *)&element->hover_min_x,
        sizeof(ui_vec2_cpp_t),
        2,
        &ui_vec2_cpp_t::construct);
    ui_template_block_set_mode4(
        (ui_menu_item_subtemplate_block_t *)((char *)element + 0x3c));
    ui_template_block_set_mode4(
        (ui_menu_item_subtemplate_block_t *)((char *)element + 0x124));
    ui_template_block_set_mode4(
        (ui_menu_item_subtemplate_block_t *)((char *)element + 0x20c));

    ui_menu_template_triplet_t *triplet =
        (ui_menu_template_triplet_t *)element;
    triplet->tail_state_2f8 = 0;
    triplet->tail_active_314 = 0;
    element->on_update = 0;
    element->on_activate = 0;
    element->active = 0;
}

extern "C" void ui_element_globals_init(void)
{
    construct_ui_element_inline(&ui_sign_crimson);
    construct_ui_element_inline(&ui_element_slot_01_main_menu_aux);

    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_03_main_menu_play_game);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_04_main_menu_options);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_05_main_menu_statistics);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_02_main_menu_primary);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_footer_variant_a);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_footer_variant_b);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_31);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_32_layout_c);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_10);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_11);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_12_layout_a);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_08);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_09);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_33);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_15);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_16);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_17);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_19);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_20);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_21);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_22);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_23);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_24);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_25);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_26);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_27);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_29);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_30);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_13);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_14);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_18_layout_b);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_34);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_35);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_36);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_37);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_38);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_39);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_28);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_element_slot_40);
    ui_template_triplet_reset_and_seed_modes((ui_menu_template_triplet_t *)&ui_perk_prompt_element);

    highscore_return_latch = 0;
    player_overlay_suppressed_latch = 0;
    pause_keybind_help_alpha_ms = 0;
    player_name_length = 0;
    ui_vec2_value_t shake_offset = make_ui_vec2(0.0f, 0.0f);
    camera_shake_timer = 0.0f;
    gameplay_transition_latch = 0;
    highscore_save_skip_record_init = 0;
    ui_focus_input_locked = 0;
    input_mouse_delta_nonzero = 0;
    ui_mouse_blocked = 0;
    ui_transition_alpha = 1.0f;
    camera_shake_offset = shake_offset;
}
