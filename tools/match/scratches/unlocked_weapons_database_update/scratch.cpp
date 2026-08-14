#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

#include <string.h>

extern IGrim2D_cpp *grim_interface_ptr;

#ifndef CRIMSON_DATABASE_UI_TYPES
#define CRIMSON_DATABASE_UI_TYPES

struct database_vec2_t {
    float x;
    float y;

    database_vec2_t() {}
    database_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}

    database_vec2_t operator+(const database_vec2_t &other) const
    {
        return database_vec2_t(x + other.x, y + other.y);
    }

    database_vec2_t &operator+=(const database_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct database_scrollbar_t {
    float scroll_offset;
    int hovered_index;
    int selected_index;
    int visible_rows;
    int column_offsets[8];
    char **items;
    int item_count;

    database_scrollbar_t()
    {
        memset(column_offsets, 0, 8);
    }

    ~database_scrollbar_t() {}
};

struct database_button_t {
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

    database_button_t()
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

    ~database_button_t() {}
};

#endif

struct weapon_ammo_view_t {
    int ammo_class;
    unsigned char payload[120];
};

extern "C" {
extern ui_element_t ui_element_slot_09;
extern ui_element_t ui_element_slot_33;
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern unsigned char ui_mouse_blocked;
extern int unlocked_weapons_nav_focus_index;
extern int config_screen_width;
extern int ui_weapon_icons_texture;
extern weapon_ammo_view_t weapon_ammo_class[];

void ui_scrollbar_update(float *xy, float *state);
bool ui_button_update(float *xy, ui_button_t *button);
}

#include "crimsonland_textures_owner.h"

extern "C" void unlocked_weapons_database_update(void)
{
    int weapon_id = -1;
    database_vec2_t position;
    position =
        *(database_vec2_t *)&ui_element_slot_09.pos_x
        + *(database_vec2_t *)&ui_element_slot_09.vertices[0].x
        + database_vec2_t(300.0f, 40.0f);
    position.x += ui_element_slot_09.render_offset_x;
    position.x += 44.0f;
    position.x -= 110.0f;
    position.y += 10.0f;
    position.x -= 32.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    int title_width = grim_interface_ptr->grim_measure_text_width(
        "Unlocked Weapons Database");
    grim_interface_ptr->grim_draw_text_small(
        position.x + 132.0f - (float)(title_width / 2),
        position.y,
        "Unlocked Weapons Database");

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
    {
        database_vec2_t separator_position(
            position.x + (float)(132 - title_width / 2),
            position.y + 13.0f);
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&separator_position, (float)title_width, 1.0f);
    }

    position.y += 20.0f;
    int database_count = 0;
    int index = 1;
    do {
        if (weapon_table[index].unlocked != 0) {
            ++database_count;
        }
        ++index;
    } while (index < 64);

    position.y += 10.0f;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x + 8.0f,
        position.y,
        "%d weapons in database",
        database_count);
    position.y += 20.0f;
    position.y += 8.0f;

    if (grim_interface_ptr->grim_was_key_pressed(0xc8)) {
        ui_mouse_blocked = 1;
        --unlocked_weapons_nav_focus_index;
    }
    if (grim_interface_ptr->grim_was_key_pressed(0xd0)) {
        ui_mouse_blocked = 1;
        ++unlocked_weapons_nav_focus_index;
    }
    if (unlocked_weapons_nav_focus_index < 0) {
        unlocked_weapons_nav_focus_index = 0;
    } else if (unlocked_weapons_nav_focus_index > 1) {
        unlocked_weapons_nav_focus_index = 1;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    position.x += 10.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x - 2.0f, position.y, "Weapon");
    position.y += 16.0f;
    position.y += 4.0f;

    char *weapon_names[64];
    int weapon_count = 0;
    char **name_cursor = weapon_names;
    index = 1;
    do {
        if (weapon_table[index].unlocked != 0) {
            *name_cursor = weapon_table[index].name;
            ++weapon_count;
            ++name_cursor;
        }
        ++index;
    } while (index < 64);

    static database_scrollbar_t scrollbar;
    scrollbar.items = weapon_names;
    scrollbar.item_count = weapon_count;
    scrollbar.visible_rows = 10;
    ui_scrollbar_update((float *)&position, (float *)&scrollbar);

    if (scrollbar.hovered_index != -1) {
        int available_index = 0;
        index = 1;
        while (index < 64) {
            if (weapon_table[index].unlocked != 0) {
                if (available_index++ == scrollbar.hovered_index) {
                    weapon_id = index;
                    break;
                }
            }
            ++index;
        }
    }

    position =
        *(database_vec2_t *)&ui_element_slot_09.pos_x
        + *(database_vec2_t *)&ui_element_slot_09.vertices[0].x
        + database_vec2_t(300.0f, 40.0f);
    position.x += ui_element_slot_09.render_offset_x;
    position.x += 44.0f;
    position.x -= 110.0f;
    position.y += 265.0f;
    position.x -= 10.0f;

    static database_button_t back_button;
    back_button.label = "Back";
    {
        database_vec2_t button_position;
        button_position.x = position.x + 144.0f;
        button_position.y = position.y + 8.0f;
        if (ui_button_update(
                (float *)&button_position, (ui_button_t *)&back_button)) {
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_STATISTICS_MENU;
        }
    }

    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    {
        database_vec2_t panel_position =
            *(database_vec2_t *)&ui_element_slot_33.pos_x
            + *(database_vec2_t *)&ui_element_slot_33.vertices[0].x
            + database_vec2_t(300.0f, 40.0f);
        position = panel_position;
        position.x = ui_element_slot_33.render_offset_x - 16.0f;
        position.x += panel_position.x;
        position.x -= 240.0f;
        position.y += 10.0f;
        position.x -= 10.0f;
    }
    if (config_screen_width <= 640) {
        position.x += 20.0f;
    }

    if (weapon_id != -1) {
        position.x += 16.0f;
        grim_interface_ptr->grim_set_config_var(0x18, 0.43f);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.4f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 190.0f,
            position.y - 18.0f,
            "wepno #%d",
            weapon_id);
        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "%s", weapon_table[weapon_id].name);

        position.y += 22.0f;
        position.x += 32.0f;
        position.y += 26.0f;
        grim_interface_ptr->grim_bind_texture(
            texture_handles.ui_weapon_icons_texture, 0);
        grim_interface_ptr->grim_set_sub_rect(
            8, 2, 1, weapon_table[weapon_id].hud_icon_id << 1);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            position.x, position.y - 16.0f, 64.0f, 32.0f);
        grim_interface_ptr->grim_end_batch();

        position.y += 30.0f;
        position.x -= 16.0f;
        if (weapon_ammo_class[weapon_id].ammo_class != 1) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x,
                position.y,
                "Firerate:    %d rpm",
                (int)(60.0f / weapon_table[weapon_id].shot_cooldown));
        } else {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y, "Firerate:    n/a");
        }
        position.y += 18.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x,
            position.y,
            "Reload time: %.1f secs",
            weapon_table[weapon_id].reload_time);
        position.y += 18.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x,
            position.y,
            "Clip size: %d",
            weapon_table[weapon_id].clip_size);
        position.y += 18.0f;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    if (grim_interface_ptr->grim_was_key_pressed(1)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
    }
}
