#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

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
    float column_offsets[8];
    char **items;
    int item_count;

    database_scrollbar_t()
    {
        column_offsets[0] = 0.0f;
        column_offsets[1] = 0.0f;
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

extern "C" {
extern ui_element_t ui_element_slot_09;
extern ui_element_t ui_element_slot_33;
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern unsigned char ui_mouse_blocked;
extern int unlocked_perks_nav_focus_index;
extern int config_screen_width;

void ui_scrollbar_update(float *xy, float *state);
bool ui_button_update(float *xy, ui_button_t *button);
}

extern "C" void unlocked_perks_database_update(void)
{
    int perk_id = -1;
    database_vec2_t panel_position =
        *(database_vec2_t *)&ui_element_slot_09.pos_x
        + *(database_vec2_t *)&ui_element_slot_09.vertices[0].x;
    panel_position += database_vec2_t(300.0f, 40.0f);

    database_vec2_t position = panel_position;
    position.y += 10.0f;
    position.x +=
        ui_element_slot_09.render_offset_x + 44.0f - 110.0f - 32.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    int title_width = grim_interface_ptr->grim_measure_text_width(
        "Unlocked Perks Database");
    int title_half_width = title_width / 2;
    grim_interface_ptr->grim_draw_text_small(
        position.x + 132.0f - (float)title_half_width,
        position.y,
        "Unlocked Perks Database");

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
    database_vec2_t separator_position(
        position.x + (float)(132 - title_half_width),
        position.y + 13.0f);
    grim_interface_ptr->grim_draw_rect_outline(
        (float *)&separator_position, (float)title_width, 1.0f);

    int database_count = 0;
    int index = 1;
    do {
        if ((char)perk_meta_table[index].available != 0) {
            ++database_count;
        }
        ++index;
    } while (index < 128);

    position.y += 28.0f;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x + 8.0f,
        position.y,
        "%d perks in database",
        database_count);
    position.y += 28.0f;

    if (grim_interface_ptr->grim_was_key_pressed(0xc8)) {
        ui_mouse_blocked = 1;
        --unlocked_perks_nav_focus_index;
    }
    if (grim_interface_ptr->grim_was_key_pressed(0xd0)) {
        ui_mouse_blocked = 1;
        ++unlocked_perks_nav_focus_index;
    }
    if (unlocked_perks_nav_focus_index < 0) {
        unlocked_perks_nav_focus_index = 0;
    } else if (unlocked_perks_nav_focus_index > 1) {
        unlocked_perks_nav_focus_index = 1;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    position.x += 10.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x - 2.0f, position.y, "Perks");
    position.y += 20.0f;

    char *perk_names[128];
    int perk_count = 0;
    char **name_cursor = perk_names;
    index = 0;
    do {
        if ((char)perk_meta_table[index].available != 0) {
            *name_cursor = perk_meta_table[index].name;
            ++perk_count;
            ++name_cursor;
        }
        ++index;
    } while (index < 128);

    static database_scrollbar_t scrollbar;
    scrollbar.items = perk_names;
    scrollbar.item_count = perk_count;
    scrollbar.visible_rows = 10;
    ui_scrollbar_update((float *)&position, (float *)&scrollbar);

    if (scrollbar.hovered_index != -1) {
        int available_index = 0;
        index = 0;
        do {
            if ((char)perk_meta_table[index].available != 0) {
                if (available_index == scrollbar.hovered_index) {
                    perk_id = index;
                    break;
                }
                ++available_index;
            }
            ++index;
        } while (index < 128);
    }

    panel_position =
        *(database_vec2_t *)&ui_element_slot_09.pos_x
        + *(database_vec2_t *)&ui_element_slot_09.vertices[0].x;
    panel_position += database_vec2_t(300.0f, 40.0f);
    position = panel_position;
    position.y += 275.0f;
    position.x +=
        ui_element_slot_09.render_offset_x + 44.0f - 110.0f - 10.0f;

    static database_button_t back_button;
    back_button.label = "Back";
    position.x += 132.0f;
    if (ui_button_update((float *)&position, (ui_button_t *)&back_button)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
    }

    panel_position =
        *(database_vec2_t *)&ui_element_slot_33.pos_x
        + *(database_vec2_t *)&ui_element_slot_33.vertices[0].x;
    panel_position += database_vec2_t(300.0f, 40.0f);
    position = panel_position;
    position.y += 10.0f;
    position.x +=
        ui_element_slot_33.render_offset_x - 16.0f - 240.0f - 10.0f;
    if (config_screen_width <= 640) {
        position.x -= 10.0f;
    }

    if (perk_id != -1) {
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_set_config_var(0x18, 0.43f);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.4f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 190.0f,
            position.y - 18.0f,
            "perkno #%d",
            perk_id);
        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

        char *name = perk_meta_table[perk_id].name;
        int name_width = grim_interface_ptr->grim_measure_text_width(name);
        int name_half_width = name_width / 2;
        grim_interface_ptr->grim_draw_text_small(
            position.x + 128.0f - (float)name_half_width,
            position.y,
            name);

        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
        separator_position.x =
            position.x + (float)(128 - name_half_width);
        separator_position.y = position.y + 13.0f;
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&separator_position, (float)name_width, 1.0f);
        position.y += 22.0f;

        int prerequisite = perk_meta_table[perk_id].prerequisite;
        if (prerequisite != -1) {
            grim_interface_ptr->grim_set_color(1.0f, 0.8f, 0.8f, 0.8f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 16.0f,
                position.y,
                "Requires: %s",
                perk_meta_table[prerequisite].name);
            position.y += 18.0f;
        }

        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
        grim_interface_ptr->grim_draw_text_small(
            position.x + 16.0f,
            position.y,
            perk_meta_table[perk_id].description);
        position.y += 22.0f;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    if (grim_interface_ptr->grim_was_key_pressed(0x1c)
        && unlocked_perks_nav_focus_index == 0) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
    }
    if (grim_interface_ptr->grim_was_key_pressed(1)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
    }
}
