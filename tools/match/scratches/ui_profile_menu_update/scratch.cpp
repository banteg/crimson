#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct profile_vec2_t {
    float x;
    float y;

    profile_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct profile_text_input_t {
    char *text;
    int cursor;
    int max_chars;
    int width_px;
    float alpha;

    profile_text_input_t(char *buffer, int max, int width)
    {
        alpha = 1.0f;
        text = buffer;
        cursor = 0;
        max_chars = max;
        width_px = width;
    }

    ~profile_text_input_t() {}
};

struct profile_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;

    profile_button_t()
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

    ~profile_button_t() {}
};

struct profile_list_widget_t {
    unsigned char enabled;
    int open;
    int selected_index;
    char **items;
    int item_count;
    unsigned char hovered;
    int active_index;

    profile_list_widget_t()
    {
        enabled = true;
        active_index = 0;
        hovered = false;
        selected_index = 0;
        open = 0;
        item_count = 0;
        items = 0;
    }

    ~profile_list_widget_t() {}
};

extern "C" {
extern char profile_name_input_buffer[64];
extern char *profile_name_item_ptrs[9];
extern int profile_name_list_open;
extern unsigned char profile_name_add_mode;
extern unsigned char profile_name_selection_dirty;
extern unsigned char profile_name_filter_dirty;

char *strdup_malloc(char *src);
void crt_free(void *ptr);
bool ui_text_input_update(float *xy, ui_text_input_state_t *input_state);
bool ui_button_update(float *xy, ui_button_t *button);
int ui_list_widget_update(float *xy, ui_list_widget_t *list);
bool input_primary_just_pressed(void);
void j_highscore_load_table(void);
}

static __inline bool profile_add_button_update(
    float *xy,
    profile_vec2_t *button_xy,
    profile_button_t *button)
{
    button_xy->set(xy[0] + 180.0f, xy[1] + 22.0f);
    return ui_button_update(
        (float *)button_xy,
        (ui_button_t *)button);
}

extern "C" bool ui_profile_menu_update(float *xy, char enabled)
{
    static profile_text_input_t name_input(
        profile_name_input_buffer, 0x1b, 0x60);
    int list_count = 0;

    if (config_blob.saved_name_count > 0) {
        char **item = profile_name_item_ptrs;
        char *saved_name = config_blob.saved_names[0];
        int remaining = config_blob.saved_name_count;
        list_count = remaining;
        do {
            *item = saved_name;
            saved_name += sizeof(config_blob.saved_names[0]);
            ++item;
        } while (--remaining != 0);
    }
    char *add_item = strdup_malloc("<add new named list>");
    profile_name_item_ptrs[list_count] = add_item;

    static profile_button_t add_button;
    add_button.label = "Add";

    static profile_button_t delete_button;
    delete_button.label = "Delete";
    name_input.width_px = 0xae;

    if (profile_name_add_mode) {
        profile_vec2_t input_xy(xy[0], xy[1] + 29.0f);
        if (ui_text_input_update(
                (float *)&input_xy,
                (ui_text_input_state_t *)&name_input)
            || profile_add_button_update(
                xy, &input_xy, &add_button)) {
            strcpy(
                config_blob.saved_names[config_blob.saved_name_count],
                profile_name_input_buffer);
            config_blob.selected_saved_name_slot =
                config_blob.saved_name_count;
            ++config_blob.saved_name_count;
            if (config_blob.saved_name_count >= 8) {
                strcpy(
                    config_blob.saved_names[1],
                    profile_name_input_buffer);
                --config_blob.saved_name_count;
            }
            profile_name_input_buffer[0] = 0;
            name_input.cursor = 0;
            profile_name_add_mode = 0;
            j_highscore_load_table();
        }
    } else if (!profile_name_list_open
               && config_blob.selected_saved_name_slot != 0) {
        profile_vec2_t delete_xy(xy[0], xy[1] + 22.0f);
        if (ui_button_update(
                (float *)&delete_xy,
                (ui_button_t *)&delete_button)) {
            --config_blob.saved_name_count;
            strcpy(
                config_blob.saved_names[
                    config_blob.selected_saved_name_slot],
                config_blob.saved_names[config_blob.saved_name_count]);
            config_blob.selected_saved_name_slot = 0;
            j_highscore_load_table();
        }
    }

    static profile_list_widget_t name_list;
    int item_count = list_count + 1;
    name_list.items = profile_name_item_ptrs;
    name_list.item_count = item_count;
    name_list.enabled = enabled;
    name_list.selected_index = config_blob.selected_saved_name_slot;

    int selected = ui_list_widget_update(
        xy, (ui_list_widget_t *)&name_list);
    if (selected > -2
        && (input_primary_just_pressed()
            || grim_interface_ptr->grim_was_key_pressed(0x1c))) {
        profile_name_list_open = 1 - profile_name_list_open;
        if (selected >= 0) {
            name_list.selected_index = selected;
            config_blob.selected_saved_name_slot = selected;
            if (selected != item_count - 1) {
                j_highscore_load_table();
            }
            profile_name_selection_dirty = 1;
            profile_name_filter_dirty = 1;
        }
        profile_name_add_mode = selected == item_count - 1;
    }

    name_list.open = profile_name_list_open;
    crt_free(profile_name_item_ptrs[list_count]);
    return false;
}
