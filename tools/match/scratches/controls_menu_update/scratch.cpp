#define CONTROLS_INLINE_KEY_NAME
#include "input_key_name_impl.h"

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

struct controls_vec2_t {
    float x;
    float y;

    controls_vec2_t()
    {
    }

    controls_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    float *vec2_add_out(float *dst, float *rhs);
};

struct controls_color_t {
    float r;
    float g;
    float b;
    float a;
};

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;

extern unsigned char controls_menu_init_flags;
extern ui_button_t controls_redefine_button;
extern ui_button_t controls_back_button;
extern ui_list_widget_t controls_player_profile_list;
extern ui_list_widget_t controls_aim_method_list;
extern ui_list_widget_t controls_move_method_list;
extern ui_checkbox_t controls_direction_arrow_checkbox;
extern controls_rebind_item_table_t controls_rebind_items;

extern unsigned char controls_menu_selection_refresh_latch;
extern int controls_rebind_slot_index;
extern int controls_rebind_player_index;
extern unsigned char controls_rebind_capture_armed;
extern float controls_rebind_axis_peak_abs_13f;
extern float controls_rebind_axis_peak_abs_140;
extern float controls_rebind_axis_peak_abs_141;
extern float controls_rebind_axis_peak_abs_153;
extern float controls_rebind_axis_peak_abs_154;
extern float controls_rebind_axis_peak_abs_155;
extern unsigned char ui_focus_input_locked;

extern int config_aim_scheme[4];
extern int config_player_mode_flags[4];
extern unsigned char config_direction_arrow_flags[4];
extern int config_p1_move_forward[64];
extern int config_key_pick_perk;
extern int config_key_reload;
extern cvar_float_t *cv_enableMousePointAndClickMovement;

extern ui_element_t ui_element_slot_14;
extern ui_element_t ui_element_slot_40;
extern int ui_text_controls_texture;
extern float render_tint_color_r;
extern float render_tint_color_g;
extern float render_tint_color_b;
extern float render_tint_color_a;

void nullsub_89(void);
void nullsub_90(void);
void nullsub_91(void);
void nullsub_92(void);
void nullsub_93(void);
void nullsub_94(void);
void nullsub_95(void);
int crt_atexit(void (*function)(void));
void crt_free(void *ptr);
char *strdup_malloc(char *text);

char *input_configure_for_label(int config_id);
char *input_scheme_label(int scheme);
unsigned char input_any_key_pressed(void);
int input_detect_active_analog_axis(void);
unsigned char input_primary_just_pressed(void);
bool ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);
bool ui_menu_item_update(float *xy, ui_menu_item_t *item);
int ui_list_widget_update(float *xy, ui_list_widget_t *list);
void ui_draw_textured_quad(
    int x, int y, int width, int height, int texture_id);
}

static __forceinline void init_button(
    ui_button_t &button,
    void (*destroy)(void))
{
    button.enabled = 1;
    button.force_wide = 0;
    button.force_small = 0;
    button.alpha = 1.0f;
    button.click_anim = 0;
    button.label = 0;
    button.hovered = 0;
    button.activated = 0;
    button.hover_anim = 0;
    crt_atexit(destroy);
}

static __forceinline void init_list(
    ui_list_widget_t &list,
    void (*destroy)(void))
{
    list.enabled = 1;
    list.active_index = 0;
    list.hovered = 0;
    list.selected_index = 0;
    list.open = 0;
    list.item_count = 0;
    list.items = 0;
    crt_atexit(destroy);
}

static __forceinline int activate_list(
    controls_vec2_t &base,
    controls_vec2_t offset,
    ui_list_widget_t &list)
{
    controls_vec2_t position;
    int selected = ui_list_widget_update(
        base.vec2_add_out((float *)&position, (float *)&offset),
        &list);
    if (selected <= -2) {
        return -1;
    }
    if (!input_primary_just_pressed()
        && !grim_interface_ptr->grim_was_key_pressed(0x1c)) {
        return -1;
    }
    list.open = 1 - list.open;
    return selected;
}

static __forceinline float abs_float(float value)
{
    *(unsigned int *)&value &= 0x7fffffff;
    return value;
}

static __forceinline void update_axis_peak(float &peak, int axis)
{
    float value = abs_float(grim_interface_ptr->grim_get_config_float(axis));
    if (peak > value) {
        value = peak;
    }
    peak = value;
}

static __forceinline void draw_rebind_heading(
    controls_vec2_t &position,
    char *label,
    controls_color_t &tint)
{
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x, position.y, label);
    grim_interface_ptr->grim_set_color_ptr((float *)&tint);

    controls_vec2_t line_offset(0.0f, 13.0f);
    controls_vec2_t line_position;
    grim_interface_ptr->grim_draw_rect_outline(
        position.vec2_add_out(
            (float *)&line_position,
            (float *)&line_offset),
        228.0f,
        1.0f);

    position.x += 8.0f;
    position.y += 18.0f;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
}

static __forceinline void draw_rebind_row(
    controls_vec2_t &position,
    char *label,
    int item_index)
{
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x, position.y, label);

    controls_vec2_t item_offset(128.0f, 0.0f);
    controls_vec2_t item_position;
    ui_menu_item_update(
        position.vec2_add_out(
            (float *)&item_position,
            (float *)&item_offset),
        &controls_rebind_items[item_index]);

    position.y += 16.0f;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
}

extern "C" void controls_menu_update(void)
{
    if (!(controls_menu_init_flags & 1)) {
        controls_menu_init_flags |= 1;
        init_button(controls_redefine_button, nullsub_95);
    }
    controls_redefine_button.label = "Redefine";

    if (!(controls_menu_init_flags & 2)) {
        controls_menu_init_flags |= 2;
        init_button(controls_back_button, nullsub_94);
    }
    controls_back_button.label = "Back";

    if (!(controls_menu_init_flags & 4)) {
        controls_menu_init_flags |= 4;
        init_list(controls_player_profile_list, nullsub_93);
    }
    if (!(controls_menu_init_flags & 8)) {
        controls_menu_init_flags |= 8;
        init_list(controls_aim_method_list, nullsub_92);
    }
    if (!(controls_menu_init_flags & 0x10)) {
        controls_menu_init_flags |= 0x10;
        init_list(controls_move_method_list, nullsub_91);
    }

    if (controls_menu_selection_refresh_latch) {
        controls_menu_selection_refresh_latch = 0;
        controls_aim_method_list.selected_index =
            config_aim_scheme[controls_rebind_player_index];
        controls_move_method_list.selected_index =
            config_player_mode_flags[controls_rebind_player_index] - 1;
    }

    char *aim_items[7];
    aim_items[0] = input_configure_for_label(0);
    aim_items[1] = input_configure_for_label(1);
    aim_items[2] = input_configure_for_label(2);
    aim_items[3] = input_configure_for_label(3);
    aim_items[4] = input_configure_for_label(4);
    aim_items[5] = input_configure_for_label(5);
    aim_items[6] = input_configure_for_label(6);
    controls_aim_method_list.items = aim_items;
    controls_aim_method_list.item_count = 5;

    char *move_items[6];
    move_items[0] = input_scheme_label(1);
    move_items[1] = input_scheme_label(2);
    move_items[2] = input_scheme_label(3);
    move_items[3] = input_scheme_label(4);
    move_items[4] = input_scheme_label(5);
    move_items[5] = input_scheme_label(6);
    controls_move_method_list.items = move_items;
    controls_move_method_list.item_count = 3;
    if (cv_enableMousePointAndClickMovement->value != 0.0f) {
        controls_move_method_list.item_count = 4;
    }

    char *player_items[4] = {
        "Player 1",
        "Player 2",
        "Player 3",
        "Player 4",
    };
    controls_player_profile_list.items = player_items;
    controls_player_profile_list.item_count = 2;

    controls_vec2_t left_base(
        ui_element_slot_14.vertices[0].x
            + ui_element_slot_14.pos_x
            + ui_element_slot_14.render_offset_x
            - 32.0f
            - 64.0f
            + 300.0f,
        ui_element_slot_14.vertices[0].y
            + ui_element_slot_14.pos_y
            + 40.0f);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    ui_draw_textured_quad(
        (int)(left_base.x + 2.0f),
        (int)(left_base.y + 4.0f),
        128,
        32,
        ui_text_controls_texture);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.8f);

    controls_vec2_t draw_position(
        left_base.x + 9.0f,
        left_base.y + 3.0f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        draw_position.x + 126.0f,
        draw_position.y - 2.0f,
        "Configure for:");
    draw_position.y += 43.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        draw_position.x, draw_position.y, "Aiming method:");
    draw_position.y += 42.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        draw_position.x, draw_position.y, "Moving method:");
    draw_position.y += 42.0f;

    if (!(controls_menu_init_flags & 0x20)) {
        controls_menu_init_flags |= 0x20;
        controls_direction_arrow_checkbox.checked = 0;
        controls_direction_arrow_checkbox.disabled = 0;
        controls_direction_arrow_checkbox.hovered = 0;
        controls_direction_arrow_checkbox.label = 0;
        crt_atexit(nullsub_90);
    }
    controls_direction_arrow_checkbox.label = "Show direction arrow";
    draw_position.y += 4.0f;
    controls_direction_arrow_checkbox.checked =
        config_direction_arrow_flags[controls_rebind_player_index];
    ui_checkbox_update(
        (float *)&draw_position,
        &controls_direction_arrow_checkbox);
    config_direction_arrow_flags[controls_rebind_player_index] =
        controls_direction_arrow_checkbox.checked;

    controls_vec2_t right_base(
        ui_element_slot_40.vertices[0].x
            + ui_element_slot_40.pos_x
            + ui_element_slot_40.render_offset_x
            - 64.0f
            + 50.0f
            + 64.0f
            + 16.0f,
        ui_element_slot_40.vertices[0].y
            + ui_element_slot_40.pos_y
            + 40.0f
            + 32.0f
            + 4.0f
            - 38.0f);

    player_input_config_t *binding =
        (player_input_config_t *)config_p1_move_forward;
    player_state_t *player = player_state_table;
    do {
        player_input_t &input = player->input;
        input.move_key_forward = binding->move_key_forward;
        input.move_key_backward = binding->move_key_backward;
        input.turn_key_left = binding->turn_key_left;
        input.turn_key_right = binding->turn_key_right;
        input.fire_key = binding->fire_key;
        input.key_reserved_0 = binding->key_reserved_0;
        input.key_reserved_1 = binding->key_reserved_1;
        input.aim_key_left = binding->aim_key_left;
        input.aim_key_right = binding->aim_key_right;
        input.axis_aim_y = binding->axis_aim_y;
        input.axis_aim_x = binding->axis_aim_x;
        input.axis_move_y = binding->axis_move_y;
        input.axis_move_x = binding->axis_move_x;
        ++binding;
        ++player;
    } while (binding < (player_input_config_t *)config_p1_move_forward + 2);

    grim_interface_ptr->grim_set_color(
        1.0f,
        1.0f,
        1.0f,
        controls_redefine_button.hover_anim * 0.000900000043f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.9f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        right_base.x + 54.0f,
        right_base.y,
        "Configured controls");
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.8f);

    draw_position.x = right_base.x + 54.0f;
    draw_position.y = right_base.y + 13.0f;
    grim_interface_ptr->grim_draw_rect_outline(
        (float *)&draw_position,
        (float)grim_interface_ptr->grim_measure_text_width(
            "Configured controls"),
        1.0f);

    if (!(controls_menu_init_flags & 0x40)) {
        controls_menu_init_flags |= 0x40;
        int item_count = 15;
        ui_menu_item_t *item = controls_rebind_items;
        do {
            item->enabled = 1;
            item->alpha = 1.0f;
            item->label = 0;
            item->activated = 0;
            item->hovered = 0;
            item->hover_phase = 0.0f;
            ++item;
        } while (--item_count);
        crt_atexit(nullsub_89);
    }

    {
        ui_menu_item_t *item = controls_rebind_items;
        do {
            item->enabled = 1;
            item->activated = 0;
            ++item;
        } while (item < controls_rebind_items + 15);
    }

    {
        int i = 0;
        int binding_base = controls_rebind_player_index * 16;
        do {
            if (controls_rebind_items[i].label) {
                crt_free(controls_rebind_items[i].label);
            }
            controls_rebind_items[i].label =
                strdup_malloc(controls_key_name(
                    config_p1_move_forward[binding_base]));
            ++binding_base;
            ++i;
        } while (i < 13);
        if (controls_rebind_items[i].label) {
            crt_free(controls_rebind_items[i].label);
        }
        controls_rebind_items[i].label =
            strdup_malloc(controls_key_name(
                config_p1_move_forward[binding_base]));
        if (controls_rebind_items[i].label) {
            crt_free(controls_rebind_items[i].label);
        }
        controls_rebind_items[i].label =
            strdup_malloc(controls_key_name(config_key_pick_perk));
        if (controls_rebind_items[14].label) {
            crt_free(controls_rebind_items[14].label);
        }
        controls_rebind_items[14].label =
            strdup_malloc(controls_key_name(config_key_reload));
    }

    if (controls_rebind_slot_index != -1) {
        ui_menu_item_t &active =
            controls_rebind_items[controls_rebind_slot_index];
        if (active.label) {
            crt_free(active.label);
        }
        active.label = strdup_malloc("???");
        active.enabled = 0;
    }

    render_tint_color_a = 0.7f;
    controls_color_t section_tint = {
        render_tint_color_r,
        render_tint_color_g,
        render_tint_color_b,
        render_tint_color_a,
    };
    draw_position.x = right_base.x - 22.0f;
    draw_position.y = right_base.y + 26.0f;

    draw_rebind_heading(draw_position, "Aiming", section_tint);
    if (config_aim_scheme[controls_rebind_player_index] == 1) {
        draw_rebind_row(draw_position, "Torso left:", 7);
        draw_rebind_row(draw_position, "Torso right:", 8);
    }
    if (config_aim_scheme[controls_rebind_player_index] == 4) {
        draw_rebind_row(draw_position, "Aim Up/Down Axis:", 9);
        draw_rebind_row(draw_position, "Aim Left/Right Axis:", 10);
    }
    draw_rebind_row(draw_position, "Fire:", 4);
    draw_position.y += 8.0f;

    draw_position.x -= 8.0f;
    draw_rebind_heading(draw_position, "Moving", section_tint);
    if (config_player_mode_flags[controls_rebind_player_index] == 2) {
        draw_rebind_row(draw_position, "Move Up:", 0);
        draw_rebind_row(draw_position, "Move Down:", 1);
        draw_rebind_row(draw_position, "Move Left:", 2);
        draw_rebind_row(draw_position, "Move Right:", 3);
    }
    if (config_player_mode_flags[controls_rebind_player_index] == 1) {
        draw_rebind_row(draw_position, "Forward:", 0);
        draw_rebind_row(draw_position, "Backwards:", 1);
        draw_rebind_row(draw_position, "Turn left:", 2);
        draw_rebind_row(draw_position, "Turn right:", 3);
    }
    if (config_player_mode_flags[controls_rebind_player_index] == 4) {
        draw_rebind_row(draw_position, "Move to cursor:", 14);
    }
    if (config_player_mode_flags[controls_rebind_player_index] == 3) {
        draw_rebind_row(draw_position, "Up/Down Axis:", 11);
        draw_rebind_row(draw_position, "Left/Right Axis:", 12);
    }
    draw_position.y += 8.0f;
    draw_position.x -= 8.0f;

    if (controls_rebind_player_index == 0) {
        draw_rebind_heading(draw_position, "Misc", section_tint);
        draw_rebind_row(draw_position, "Level Up:", 13);
        if (config_player_mode_flags[controls_rebind_player_index] != 4) {
            draw_rebind_row(draw_position, "Reload:", 14);
        }
        draw_position.y += 8.0f;
        draw_position.x -= 8.0f;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.9f);
    draw_position.x -= 27.0f;
    if (controls_rebind_slot_index != -1) {
        float prompt_y = draw_position.y + 12.0f;
        if (controls_rebind_slot_index < 9
            || controls_rebind_slot_index >= 13) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                draw_position.x + 54.0f,
                prompt_y,
                "Assign control (eg. press a key).");
            grim_interface_ptr->grim_draw_text_small_fmt(
                draw_position.x + 54.0f,
                prompt_y + 13.0f,
                "     (press ESCAPE to cancel)");
        } else {
            grim_interface_ptr->grim_draw_text_small_fmt(
                draw_position.x + 54.0f,
                prompt_y,
                " Move joystick/pad analog controller");
            grim_interface_ptr->grim_draw_text_small_fmt(
                draw_position.x + 54.0f,
                prompt_y + 13.0f,
                "axis you want to assign the control to");
            grim_interface_ptr->grim_draw_text_small_fmt(
                draw_position.x + 54.0f,
                prompt_y + 26.0f,
                "     (press ESCAPE to cancel)");
        }
    }

    for (int i = 0; i < 15; ++i) {
        if (controls_rebind_items[i].activated) {
            controls_rebind_capture_armed = 0;
            bool was_idle = controls_rebind_slot_index == -1;
            controls_rebind_slot_index = -1;
            if (was_idle) {
                controls_rebind_slot_index = i;
            }
        }
    }

    if (controls_rebind_slot_index != -1) {
        if (controls_rebind_slot_index < 9
            || controls_rebind_slot_index >= 13) {
            if (!input_any_key_pressed()) {
                controls_rebind_capture_armed = 1;
            }
            if (grim_interface_ptr->grim_was_key_pressed(1)) {
                ui_focus_input_locked = 0;
                controls_rebind_slot_index = -1;
                controls_rebind_capture_armed = 0;
            } else if (controls_rebind_capture_armed) {
                int key = 2;
                if (controls_rebind_slot_index >= 13) {
                    do {
                        if (grim_interface_ptr->grim_is_key_active(key)) {
                            grim_interface_ptr->grim_flush_input();
                            if (controls_rebind_slot_index == 13) {
                                config_key_pick_perk = key;
                            } else {
                                config_key_reload = key;
                            }
                            controls_rebind_slot_index = -1;
                            controls_rebind_capture_armed = 0;
                        }
                        ++key;
                    } while (key < 0x17f);
                    int axis = input_detect_active_analog_axis();
                    if (axis) {
                        if (controls_rebind_slot_index == 13) {
                            config_key_pick_perk = axis;
                        } else {
                            config_key_reload = axis;
                        }
                    }
                } else {
                    do {
                        if (grim_interface_ptr->grim_is_key_active(key)) {
                            grim_interface_ptr->grim_flush_input();
                            config_p1_move_forward[
                                controls_rebind_player_index * 16
                                + controls_rebind_slot_index] = key;
                            controls_rebind_slot_index = -1;
                            controls_rebind_capture_armed = 0;
                        }
                        ++key;
                    } while (key < 0x17f);
                    int axis = input_detect_active_analog_axis();
                    if (axis) {
                        config_p1_move_forward[
                            controls_rebind_player_index * 16
                            + controls_rebind_slot_index] = axis;
                        controls_rebind_slot_index = -1;
                        controls_rebind_capture_armed = 0;
                    }
                }
            }
        } else {
            if (!controls_rebind_capture_armed
                && !input_any_key_pressed()) {
                controls_rebind_capture_armed = 1;
                float *peak = &controls_rebind_axis_peak_abs_13f;
                for (int i = 0; i < 16; ++i) {
                    peak[i] = 0.0f;
                }
            }
            if (grim_interface_ptr->grim_was_key_pressed(1)) {
                ui_focus_input_locked = 0;
                controls_rebind_slot_index = -1;
                controls_rebind_capture_armed = 0;
            } else if (controls_rebind_capture_armed) {
                update_axis_peak(controls_rebind_axis_peak_abs_13f, 0x13f);
                update_axis_peak(controls_rebind_axis_peak_abs_140, 0x140);
                update_axis_peak(controls_rebind_axis_peak_abs_141, 0x141);
                update_axis_peak(controls_rebind_axis_peak_abs_153, 0x153);
                update_axis_peak(controls_rebind_axis_peak_abs_154, 0x154);
                update_axis_peak(controls_rebind_axis_peak_abs_155, 0x155);
                float *peaks = &controls_rebind_axis_peak_abs_13f;
                int axis_index = 0;
                do {
                    if (*peaks > 0.5f) {
                        int binding =
                            controls_rebind_player_index * 16
                            + controls_rebind_slot_index;
                        switch (axis_index) {
                        case 0:
                            config_p1_move_forward[binding] = 0x13f;
                            grim_interface_ptr->grim_flush_input();
                            break;
                        case 1:
                            config_p1_move_forward[binding] = 0x140;
                            grim_interface_ptr->grim_flush_input();
                            break;
                        case 2:
                            config_p1_move_forward[binding] = 0x141;
                            grim_interface_ptr->grim_flush_input();
                            break;
                        case 3:
                            config_p1_move_forward[binding] = 0x153;
                            grim_interface_ptr->grim_flush_input();
                            break;
                        case 4:
                            config_p1_move_forward[binding] = 0x154;
                            grim_interface_ptr->grim_flush_input();
                            break;
                        case 5:
                            config_p1_move_forward[binding] = 0x155;
                        default:
                            grim_interface_ptr->grim_flush_input();
                        }
                        controls_rebind_slot_index = -1;
                        controls_rebind_capture_armed = 0;
                        break;
                    }
                    ++peaks;
                    ++axis_index;
                } while (
                    peaks < &controls_rebind_axis_peak_abs_13f + 6);
            }
        }
    }
    controls_move_method_list.enabled = 1;
    controls_aim_method_list.enabled = 1;
    controls_player_profile_list.enabled = 1;
    controls_direction_arrow_checkbox.disabled = 0;
    if (controls_move_method_list.open) {
        controls_aim_method_list.enabled = 0;
        controls_player_profile_list.enabled = 0;
    }
    if (controls_player_profile_list.open) {
        controls_aim_method_list.enabled = 0;
        controls_move_method_list.enabled = 0;
    }
    if (controls_aim_method_list.open) {
        controls_move_method_list.enabled = 0;
        controls_player_profile_list.enabled = 0;
    }
    if (controls_move_method_list.open || controls_aim_method_list.open) {
        controls_direction_arrow_checkbox.disabled = 1;
    }

    int selected = activate_list(
        left_base,
        controls_vec2_t(10.0f, 104.0f),
        controls_move_method_list);
    if (selected >= 0) {
        controls_move_method_list.selected_index = selected;
        config_player_mode_flags[controls_rebind_player_index] = selected + 1;
    }
    selected = activate_list(
        left_base,
        controls_vec2_t(10.0f, 62.0f),
        controls_aim_method_list);
    if (selected >= 0) {
        controls_aim_method_list.selected_index = selected;
        config_aim_scheme[controls_rebind_player_index] = selected;
    }
    selected = activate_list(
        left_base,
        controls_vec2_t(136.0f, 16.0f),
        controls_player_profile_list);
    if (selected >= 0) {
        controls_aim_method_list.selected_index =
            config_aim_scheme[selected];
        controls_move_method_list.selected_index =
            config_player_mode_flags[selected] - 1;
        controls_player_profile_list.selected_index = selected;
        controls_rebind_player_index = selected;
    }
}
