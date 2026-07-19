#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct quest_select_vec2_t {
    float x;
    float y;

    quest_select_vec2_t() {}

    quest_select_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    quest_select_vec2_t operator+(const quest_select_vec2_t &other) const
    {
        return quest_select_vec2_t(x + other.x, y + other.y);
    }

    quest_select_vec2_t &operator+=(const quest_select_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct quest_select_color_t {
    float r;
    float g;
    float b;
    float a;

    quest_select_color_t(
        float red,
        float green,
        float blue,
        float alpha)
        : r(red), g(green), b(blue), a(alpha) {}

    ~quest_select_color_t() {}
};

struct quest_select_checkbox_t {
    unsigned char checked;
    unsigned char disabled;
    unsigned char hovered;
    unsigned char padding;
    char *label;

    quest_select_checkbox_t()
    {
        checked = false;
        disabled = false;
        hovered = false;
        label = 0;
    }

    ~quest_select_checkbox_t() {}
};

struct quest_select_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    unsigned char padding;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;
    unsigned char padding_tail[2];

    quest_select_button_t()
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

    ~quest_select_button_t() {}
};

extern "C" {
extern ui_element_t ui_element_slot_37;
extern ui_element_t ui_sign_crimson;
extern int ui_text_quest_texture;
extern int ui_digit_1_texture;
extern int ui_digit_2_texture;
extern int ui_digit_3_texture;
extern int ui_digit_4_texture;
extern int ui_digit_5_texture;
extern int ui_hud_arrow_texture;
extern int quest_select_stage_major;
extern int quest_select_stage_minor_index;
extern game_status_t game_status_blob;
extern unsigned char ui_transition_direction;
extern unsigned char screen_fade_ramp_flag;
extern game_state_id_t game_state_pending;
extern int music_track_crimson_theme_id;
extern int music_track_shortie_monk_id;
extern int music_track_extra_0;
extern int sfx_ui_buttonclick;
extern char menu_label_back[];
extern char highscore_month_label_default[];

bool input_primary_just_pressed(void);
bool ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);
bool ui_button_update(float *xy, ui_button_t *button);
void sfx_play(int sfx_id, float gain);
void sfx_mute_all(int sfx_id);
}

extern "C" void quest_select_menu_update(void)
{
    quest_select_vec2_t panel_position;
    panel_position.x =
        ui_element_slot_37.vertices[0].x + ui_element_slot_37.pos_x;
    panel_position.y =
        ui_element_slot_37.pos_y + ui_element_slot_37.vertices[0].y;
    panel_position.x += 300.0f;

    bool row_hovered = false;
    quest_select_vec2_t position = panel_position;
    position.y += 40.0f;
    position.x += ui_element_slot_37.render_offset_x;
    position.x += 64.0f;
    position.x -= 145.0f;
    position.y += 4.0f;

    static quest_select_color_t row_idle_color(
        0.274509817f, 0.70588237f, 0.941176474f, 0.600000024f);
    static quest_select_color_t row_hover_color(
        0.274509817f, 0.70588237f, 0.941176474f, 1.0f);
    static quest_select_color_t unused_blue_color(
        0.0f, 0.494117647f, 0.776470602f, 1.0f);
    static quest_select_color_t unused_blue_dim_color(
        0.0f, 0.494117647f, 0.776470602f, 0.5f);
    static quest_select_color_t title_color(
        0.699999988f, 0.699999988f, 0.699999988f, 0.699999988f);
    static quest_select_color_t selected_stage_color(
        1.0f, 1.0f, 1.0f, 1.0f);
    static quest_select_color_t hovered_stage_color(
        1.0f, 1.0f, 1.0f, 0.800000012f);
    static quest_select_color_t unused_orange_color(
        0.776470602f, 0.494117647f, 0.0f, 1.0f);

    if (config_hardcore) {
        row_idle_color = quest_select_color_t(
            0.980392158f,
            0.274509817f,
            0.235294119f,
            0.600000024f);
        row_hover_color = quest_select_color_t(
            0.980392158f,
            0.274509817f,
            0.235294119f,
            1.0f);
    } else {
        row_idle_color = quest_select_color_t(
            0.274509817f,
            0.70588237f,
            0.941176474f,
            0.600000024f);
        row_hover_color = quest_select_color_t(
            0.274509817f,
            0.70588237f,
            0.941176474f,
            1.0f);
    }

    grim_interface_ptr->grim_set_color_ptr((float *)&title_color);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_bind_texture(ui_text_quest_texture, 0);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        position.x, position.y, 64.0f, 32.0f);
    grim_interface_ptr->grim_end_batch();

    int hovered_stage = -1;
    int stage = 1;
    int *digit_texture = &ui_digit_1_texture;
    position.x += 80.0f;
    float icon_y = position.y + 3.0f;
    do {
        if (ui_mouse_x <= position.x
            || ui_mouse_y <= position.y
            || position.x + 32.0f <= ui_mouse_x
            || position.y + 32.0f <= ui_mouse_y
            || ui_mouse_blocked) {
            grim_interface_ptr->grim_set_color_ptr((float *)&title_color);
        } else {
            grim_interface_ptr->grim_set_color_ptr(
                (float *)&hovered_stage_color);
            hovered_stage = stage;
        }

        float icon_scale = 1.0f;
        if (quest_select_stage_major == stage) {
            grim_interface_ptr->grim_set_color_ptr(
                (float *)&selected_stage_color);
        } else {
            icon_scale = 0.800000012f;
        }

        if ((int)digit_texture < (int)&ui_hud_arrow_texture) {
            grim_interface_ptr->grim_bind_texture(*digit_texture, 0);
        } else {
            grim_interface_ptr->grim_bind_texture(ui_digit_4_texture, 0);
        }
        grim_interface_ptr->grim_begin_batch();
        float icon_size = icon_scale * 32.0f;
        grim_interface_ptr->grim_draw_quad(
            position.x,
            icon_y,
            icon_size,
            icon_size);
        position.x += 36.0f;
        grim_interface_ptr->grim_end_batch();
        ++digit_texture;
        ++stage;
    } while ((int)digit_texture < (int)&ui_hud_arrow_texture);

    position.x -= 36.0f;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    position.y += 50.0f;
    position.x -= 208.0f;
    position.x += 16.0f;

    static quest_select_checkbox_t hardcore_checkbox;
    hardcore_checkbox.label = "Hardcore";
    if (quest_unlock_index >= 40) {
        quest_select_vec2_t checkbox_position(
            position.x + 132.0f,
            position.y - 12.0f);
        hardcore_checkbox.checked = config_hardcore;
        ui_checkbox_update(
            (float *)&checkbox_position,
            (ui_checkbox_t *)&hardcore_checkbox);
        config_hardcore = hardcore_checkbox.checked;
        position.y += 10.0f;
    }
    if (!game_is_full_version()) {
        config_hardcore = 0;
    }

    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    bool show_counts = false;
    if (grim_interface_ptr->grim_is_key_down(0x3b)) {
        show_counts = true;
    }

    int row = 0;
    int next_row;
    float hover_left = position.x - 10.0f;
    do {
        if (ui_mouse_x <= hover_left
            || position.y - 2.0f >= ui_mouse_y
            || position.x + 210.0f <= ui_mouse_x
            || position.y + 18.0f <= ui_mouse_y
            || ui_mouse_blocked) {
            grim_interface_ptr->grim_set_color_ptr(
                (float *)&row_idle_color);
        } else {
            quest_select_stage_minor_index = row;
            row_hovered = true;
            grim_interface_ptr->grim_set_color_ptr(
                (float *)&row_hover_color);
        }

        int quest_index = row + quest_select_stage_major * 10 - 10;
        if (config_hardcore) {
            if (quest_unlock_index_full >= quest_index) {
                goto unlocked_row;
            }
        } else if (quest_unlock_index >= quest_index) {
            goto unlocked_row;
        }

        next_row = row + 1;
        {
            float row_y = position.y;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x,
                position.y,
                "%d.%d",
                quest_select_stage_major,
                next_row);
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 32.0f,
                row_y,
                highscore_month_label_default);
        }
        goto row_done;

unlocked_row:
        next_row = row + 1;
        {
            float row_y = position.y;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x,
                position.y,
                "%d.%d",
                quest_select_stage_major,
                next_row);
            char *quest_name = quest_selected_meta[quest_index].name;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 32.0f,
                row_y,
                "%s",
                quest_name);
            float title_width =
                (float)(grim_interface_ptr->grim_measure_text_width(
                    quest_name) + 32);
            quest_select_vec2_t line_position(
                position.x, position.y + 13.0f);
            grim_interface_ptr->grim_draw_rect_outline(
                (float *)&line_position, title_width, 1.0f);

            if (show_counts) {
                grim_interface_ptr->grim_draw_text_small_fmt(
                    title_width + position.x + 12.0f,
                    row_y,
                    "(%d/%d)",
                    game_status_blob.quest_play_counts[
                        quest_select_stage_major * 10 + 41 + row],
                    game_status_blob.quest_play_counts[
                        quest_select_stage_major * 10 + 1 + row]);
            }
        }

row_done:
        row = next_row;
        position.y += 20.0f;
    } while (next_row < 10);

    if (show_counts) {
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 96.0f,
            position.y - 2.0f,
            "(completed/games)");
    }

    position.x = hover_left;
    position.y += 12.0f;
    if (grim_interface_ptr->grim_was_key_pressed(203)) {
        --quest_select_stage_major;
        if (quest_select_stage_major < 1) {
            quest_select_stage_major = 1;
        }
    }
    if (grim_interface_ptr->grim_was_key_pressed(205)) {
        ++quest_select_stage_major;
        if (quest_select_stage_major > 5) {
            quest_select_stage_major = 5;
        }
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.9f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    static quest_select_button_t back_button;
    back_button.label = menu_label_back;
    quest_select_vec2_t back_position(position.x + 148.0f, position.y);
    ui_button_update(
        (float *)&back_position,
        (ui_button_t *)&back_button);
    if (back_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_PLAY_GAME_MENU;
        sfx_play(sfx_ui_buttonclick, 1.0f);
    }

    if (hovered_stage != -1 && input_primary_just_pressed()) {
        quest_select_stage_major = hovered_stage;
    }

    int old_minor_index = quest_select_stage_minor_index;
    int selected_minor;
    int selected_index;
    quest_select_stage_minor_index = -10;
    if (grim_interface_ptr->grim_was_key_pressed(2)) {
        quest_select_stage_minor_index = 0;
    }
    if (grim_interface_ptr->grim_was_key_pressed(3)) {
        quest_select_stage_minor_index = 1;
    }
    if (grim_interface_ptr->grim_was_key_pressed(4)) {
        quest_select_stage_minor_index = 2;
    }
    if (grim_interface_ptr->grim_was_key_pressed(5)) {
        quest_select_stage_minor_index = 3;
    }
    if (grim_interface_ptr->grim_was_key_pressed(6)) {
        quest_select_stage_minor_index = 4;
    }
    if (grim_interface_ptr->grim_was_key_pressed(7)) {
        quest_select_stage_minor_index = 5;
    }
    if (grim_interface_ptr->grim_was_key_pressed(8)) {
        quest_select_stage_minor_index = 6;
    }
    if (grim_interface_ptr->grim_was_key_pressed(9)) {
        quest_select_stage_minor_index = 7;
    }
    if (grim_interface_ptr->grim_was_key_pressed(10)) {
        quest_select_stage_minor_index = 8;
    }
    if (grim_interface_ptr->grim_was_key_pressed(11)) {
        selected_minor = 9;
        quest_select_stage_minor_index = 9;
        goto validate_selected;
    }

    selected_minor = quest_select_stage_minor_index;
    if (quest_select_stage_minor_index != -10) {
start_selected:
        if (selected_minor == 10) {
            return;
        }
validate_selected:
        selected_index = selected_minor + quest_select_stage_major * 10 - 10;
        if (config_hardcore) {
            if (quest_unlock_index_full < selected_index) {
                return;
            }
        } else if (quest_unlock_index < selected_index) {
            return;
        }

        ui_sign_crimson.focus_disabled = 0;
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        config_game_mode = GAME_MODE_QUEST;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
        quest_stage_major = quest_select_stage_major;
        quest_stage_minor = selected_minor + 1;
        screen_fade_ramp_flag = 1;
        sfx_play(sfx_ui_buttonclick, 1.0f);
        return;
    }

    quest_select_stage_minor_index = old_minor_index;
    if (input_primary_just_pressed()
        && (row_hovered
            || grim_interface_ptr->grim_is_key_down(28))) {
        selected_minor = quest_select_stage_minor_index;
        goto start_selected;
    }
}
