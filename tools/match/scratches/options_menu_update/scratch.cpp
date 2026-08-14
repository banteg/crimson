#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct options_vec2_t {
    float x;
    float y;

    options_vec2_t() {}

    options_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    options_vec2_t operator+(const options_vec2_t &other) const
    {
        options_vec2_t result(x + other.x, other.y + y);
        return result;
    }
};

struct options_checkbox_t {
    unsigned char checked;
    unsigned char disabled;
    unsigned char hovered;
    unsigned char padding;
    char *label;

    options_checkbox_t()
    {
        disabled = checked = false;
        hovered = false;
        label = 0;
    }

    ~options_checkbox_t() {}
};

struct options_slider_t {
    int value;
    int max;
    int min;
    bool enabled;
    bool hovered;
    unsigned char padding[2];

    options_slider_t()
    {
        enabled = true;
        hovered = false;
        value = 0;
        max = 10;
        min = 0;
    }

    ~options_slider_t() {}
};

struct options_button_t {
    char *label;
    unsigned char hovered;
    unsigned char activated;
    unsigned char enabled;
    unsigned char padding;
    int hover_anim;
    int click_anim;
    float alpha;
    unsigned char force_small;
    unsigned char force_wide;
    unsigned char padding_tail[2];

    options_button_t()
    {
        enabled = true;
        force_wide = false;
        force_small = false;
        alpha = 1.0f;
        click_anim = 0;
        label = 0;
        hovered = false;
        activated = false;
        hover_anim = 0;
    }

    ~options_button_t() {}
};

extern "C" {
extern ui_element_t ui_element_slot_31;
extern int ui_item_texts_texture;
extern char *perk_slot_1_name_wrapped_primary;
extern char *perk_slot_1_name_wrapped_alternate;
extern char *perk_slot_1_desc_wrapped_primary;
extern char *perk_slot_1_desc_wrapped_alternate;
extern int perk_id_bloody_mess_quick_learner;

void ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);
void ui_segmented_slider_update(
    float *xy,
    ui_segmented_slider_t *slider);
bool ui_button_update(float *xy, ui_button_t *button);
void config_apply_detail_preset(void);
void ui_menu_main_click_controls(void);
void ui_menu_click_back_contextual(void);
}

#define CRIMSONLAND_USE_ORIGINAL_TEXTURES_OWNER
#include "crimsonland_textures_owner.h"

extern "C" void options_menu_update(void)
{
    options_vec2_t panel_position =
        *(options_vec2_t *)&ui_element_slot_31.pos_x
        + *(options_vec2_t *)&ui_element_slot_31.vertices[0].x
        + options_vec2_t(300.0f, 40.0f);
    options_vec2_t xy = panel_position;
    xy.x =
        ui_element_slot_31.render_offset_x - 24.0f - 64.0f + xy.x;
    panel_position = xy;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_bind_texture(ui_item_texts_texture, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.25f, 1.0f, 0.375f);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_draw_quad(
        panel_position.x, panel_position.y, 128.0f, 32.0f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);

    panel_position.x = xy.x + 8.0f;
    panel_position.y += 2.0f;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.8f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        panel_position.x,
        panel_position.y + 45.0f,
        "Sound volume:");
    grim_interface_ptr->grim_draw_text_small_fmt(
        panel_position.x,
        panel_position.y + 65.0f,
        "Music volume:");
    grim_interface_ptr->grim_draw_text_small_fmt(
        panel_position.x,
        panel_position.y + 85.0f,
        "Graphics detail:");
    grim_interface_ptr->grim_draw_text_small_fmt(
        panel_position.x,
        panel_position.y + 105.0f,
        "Mouse sensitivity:");

    static options_checkbox_t info_checkbox;
    unsigned char ui_info_texts = config_blob.ui_info_texts;
    xy.x = panel_position.x;
    info_checkbox.label = "UI Info texts";
    info_checkbox.checked = ui_info_texts;
    xy.y = panel_position.y + 133.0f;
    ui_checkbox_update((float *)&xy, (ui_checkbox_t *)&info_checkbox);
    config_blob.ui_info_texts = info_checkbox.checked;

    panel_position.x -= 18.0f;
    panel_position.y -= 2.0f;

    static options_slider_t sfx_volume_slider;
    sfx_volume_slider.value = (int)(config_blob.sfx_volume * 10.0f);
    xy.x = panel_position.x + 148.0f;
    options_vec2_t slider_position;
    slider_position.x = xy.x;
    slider_position.y = panel_position.y + 47.0f;
    ui_segmented_slider_update(
        (float *)&slider_position,
        (ui_segmented_slider_t *)&sfx_volume_slider);
    config_blob.sfx_volume = (float)sfx_volume_slider.value * 0.1f;

    static options_slider_t music_volume_slider;
    music_volume_slider.value = (int)(config_blob.music_volume * 10.0f);
    slider_position.x = xy.x;
    slider_position.y = panel_position.y + 67.0f;
    ui_segmented_slider_update(
        (float *)&slider_position,
        (ui_segmented_slider_t *)&music_volume_slider);
    config_blob.music_volume =
        (float)music_volume_slider.value * 0.1f;

    static options_slider_t graphics_detail_slider;
    int detail_max = 5;
    graphics_detail_slider.max = detail_max;
    graphics_detail_slider.min = 1;
    graphics_detail_slider.value = config_blob.detail_preset;
    slider_position.x = xy.x;
    slider_position.y = panel_position.y + 87.0f;
    ui_segmented_slider_update(
        (float *)&slider_position,
        (ui_segmented_slider_t *)&graphics_detail_slider);
    config_blob.detail_preset = graphics_detail_slider.value;
    if (graphics_detail_slider.value < 1) {
        config_blob.detail_preset = 1;
    } else if (graphics_detail_slider.value > detail_max) {
        config_blob.detail_preset = detail_max;
    }
    config_apply_detail_preset();

    static options_slider_t mouse_sensitivity_slider;
    mouse_sensitivity_slider.max = 10;
    mouse_sensitivity_slider.min = 1;
    mouse_sensitivity_slider.value =
        (int)(config_blob.mouse_sensitivity * 10.0f + 0.5f);
    slider_position.x = xy.x;
    slider_position.y = panel_position.y + 107.0f;
    ui_segmented_slider_update(
        (float *)&slider_position,
        (ui_segmented_slider_t *)&mouse_sensitivity_slider);
    config_blob.mouse_sensitivity =
        (float)mouse_sensitivity_slider.value * 0.1f;
    if (config_blob.mouse_sensitivity < 0.1f) {
        config_blob.mouse_sensitivity = 0.1f;
    } else if (config_blob.mouse_sensitivity > 1.0f) {
        config_blob.mouse_sensitivity = 1.0f;
    }

    static options_button_t controls_button;
    controls_button.label = "Controls";
    slider_position.x = panel_position.x + 10.0f;
    slider_position.y = panel_position.y + 155.0f;
    ui_button_update(
        (float *)&slider_position,
        (ui_button_t *)&controls_button);

    if (config_blob.violence_disabled) {
        perk_meta_table[perk_id_bloody_mess_quick_learner].name =
            perk_slot_1_name_wrapped_alternate;
        perk_meta_table[perk_id_bloody_mess_quick_learner].description =
            perk_slot_1_desc_wrapped_alternate;
    } else {
        perk_meta_table[perk_id_bloody_mess_quick_learner].name =
            perk_slot_1_name_wrapped_primary;
        perk_meta_table[perk_id_bloody_mess_quick_learner].description =
            perk_slot_1_desc_wrapped_primary;
    }

    if (controls_button.activated) {
        ui_menu_main_click_controls();
    }
    if (grim_interface_ptr->grim_was_key_pressed(1)) {
        ui_menu_click_back_contextual();
    }
}
