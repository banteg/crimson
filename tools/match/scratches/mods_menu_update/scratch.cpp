#include <io.h>
#include <string.h>

#include "crimsonland_gameplay.h"
#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct mods_vec2_t {
    float x;
    float y;

    mods_vec2_t() {}

    mods_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value)
    {
    }

    mods_vec2_t operator+(const mods_vec2_t &other) const
    {
        return mods_vec2_t(x + other.x, y + other.y);
    }

    mods_vec2_t &operator+=(const mods_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct mods_color_t {
    float r;
    float g;
    float b;
    float a;
};

struct mods_scrollbar_t {
    float scroll_offset;
    int hovered_index;
    int selected_index;
    int visible_rows;
    int column_offsets[8];
    char **items;
    int item_count;

    mods_scrollbar_t()
    {
        for (int index = 0; index < 2; ++index) {
            column_offsets[index] = 0;
        }
    }

    ~mods_scrollbar_t() {}
};

struct mods_button_t {
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

    mods_button_t()
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

    ~mods_button_t() {}
};

extern "C" {
extern ui_element_t ui_element_slot_09;
extern ui_element_t ui_element_slot_33;
extern unsigned char mods_menu_refresh_pending;
extern int mods_menu_previous_selected_index;
extern int mods_menu_entry_count;
extern mod_info_t *mods_menu_selected_info;
extern char mods_menu_filenames[32][64];
extern char mods_menu_display_names[32][64];
extern char *mods_menu_item_labels[32];
extern float render_tint_color_r;
extern float render_tint_color_g;
extern float render_tint_color_b;
extern float render_tint_color_a;
extern unsigned char ui_transition_direction;
extern game_state_id_t game_state_pending;
extern mod_interface_t *plugin_interface_ptr;
extern mod_api_t mod_api_context;

long crt_findfirst(char *pattern, _finddata_t *finddata);
int crt_findnext(long handle, _finddata_t *finddata);
int crt_findclose(long handle);
int crt_sprintf(char *dst, const char *format, ...);
mod_info_t *mod_load_info(char *filename);
mod_interface_cpp_t *mod_load_mod(char *filename);
void ui_scrollbar_update(float *xy, float *state);
bool ui_button_update(float *xy, ui_button_t *button);
}

extern "C" void mods_menu_update(void)
{
    mods_vec2_t position =
        *(mods_vec2_t *)&ui_element_slot_09.pos_x
        + *(mods_vec2_t *)&ui_element_slot_33.vertices[0].x;
    position = position + mods_vec2_t(300.0f, 40.0f);
    position.x =
        ui_element_slot_09.render_offset_x - 240.0f
        + position.x + 64.0f;
    position.y += 4.0f;
    mods_vec2_t button_origin = position;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 1.0f);
    grim_interface_ptr->grim_draw_text_mono_fmt(
        position.x - 16.0f + 144.0f,
        position.y - 8.0f,
        "mods");
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    position.y += 32.0f;

    if (mods_menu_refresh_pending) {
        mods_menu_entry_count = 0;

        _finddata_t finddata;
        long handle = crt_findfirst("mods\\*.dll", &finddata);
        if (handle != -1 && finddata.name != 0) {
            do {
                if (mods_menu_entry_count == 31) {
                    mods_menu_item_labels[31] =
                        mods_menu_display_names[31];
                    strcpy(mods_menu_filenames[31], "+ more");
                    strcpy(mods_menu_display_names[31], "+ more");
                } else {
                    strcpy(
                        mods_menu_filenames[mods_menu_entry_count],
                        finddata.name);
                    strcpy(
                        mods_menu_display_names[mods_menu_entry_count],
                        (char *)mod_load_info(finddata.name));
                    mods_menu_item_labels[mods_menu_entry_count] =
                        mods_menu_display_names[mods_menu_entry_count];
                    ++mods_menu_entry_count;
                }
            } while (crt_findnext(handle, &finddata) == 0);
        }
        crt_findclose(handle);
        mods_menu_refresh_pending = 0;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.8f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    static mods_scrollbar_t scrollbar;
    position.x += 4.0f;
    IGrim2D_cpp *renderer = grim_interface_ptr;
    scrollbar.items = mods_menu_item_labels;
    scrollbar.item_count = mods_menu_entry_count;
    scrollbar.visible_rows = 5;

    position.y += 6.0f;
    renderer->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x, position.y - 14.0f, "list of mods:");
    ui_scrollbar_update((float *)&position, (float *)&scrollbar);

    if (scrollbar.selected_index != mods_menu_previous_selected_index) {
        mods_menu_previous_selected_index = scrollbar.selected_index;
        mods_menu_selected_info =
            mod_load_info(
                mods_menu_filenames[scrollbar.selected_index]);
    }

    position.y += 104.0f;
    if (mods_menu_selected_info != 0) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.5f);

        position.y += 8.0f;
        mods_color_t separator_color =
            *(mods_color_t *)&render_tint_color_r;

        position.x += 12.0f;
        position.x += 16.0f;
        separator_color.a = 1.0f;

        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.99f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x,
            position.y,
            "%s",
            mods_menu_selected_info);

        char version_text[16];
        crt_sprintf(
            version_text,
            "v%.2f",
            (double)mods_menu_selected_info->version);
        IGrim2D_cpp *version_renderer = grim_interface_ptr;
        int text_width =
            version_renderer->grim_measure_text_width(version_text);
        version_renderer->grim_draw_text_small_fmt(
            position.x + 192.0f - (float)text_width,
            position.y,
            "%s",
            version_text);

        position.y += 14.0f;
        grim_interface_ptr->grim_set_color_ptr(
            (float *)&separator_color);
        mods_vec2_t separator_position(
            position.x - 4.0f, position.y);
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&separator_position, 200.0f, 1.0f);

        position.y -= 2.0f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.34f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "name");
        IGrim2D_cpp *version_label_renderer = grim_interface_ptr;
        text_width =
            version_label_renderer->grim_measure_text_width("version");
        version_label_renderer->grim_draw_text_small_fmt(
            position.x + 192.0f - (float)text_width,
            position.y,
            "version");

        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.7f);
        position.y += 22.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Author(s):");

        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.96f);
        text_width =
            grim_interface_ptr->grim_measure_text_width(
                mods_menu_selected_info->author);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 192.0f - (float)text_width,
            position.y,
            "%s",
            mods_menu_selected_info->author);

        position.y += 15.0f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.7f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x, position.y, "Filename:");

        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.96f);
        char *filename =
            mods_menu_filenames[scrollbar.selected_index];
        text_width =
            grim_interface_ptr->grim_measure_text_width(filename);
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 192.0f - (float)text_width,
            position.y,
            "%s",
            filename);

        position.y += 15.0f;
        if (mods_menu_selected_info->usesApiVersion != 3) {
            grim_interface_ptr->grim_set_color(
                1.0f, 0.0f, 0.0f, 1.0f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x,
                position.y,
                "(Unsupported API version)",
                mods_menu_selected_info->author);
        }

        position.y += 15.0f;
        position.y += 15.0f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.6f);
        position.x -= 16.0f;
        position.x -= 16.0f;
        position.y += 32.0f;
    }

    static mods_button_t main_menu_button;
    main_menu_button.label = "Main menu";

    static mods_button_t launch_button;
    launch_button.label = "Launch";

    mods_vec2_t button_position;
    if (mods_menu_selected_info != 0
        && mods_menu_selected_info->usesApiVersion == 3) {
        button_position.x = button_origin.x + 58.0f;
        button_position.y = button_origin.y + 232.0f;
        if (ui_button_update(
                (float *)&button_position,
                (ui_button_t *)&launch_button)) {
            if (scrollbar.selected_index >= 0) {
                plugin_interface_ptr =
                    (mod_interface_t *)mod_load_mod(
                        mods_menu_filenames[
                            scrollbar.selected_index]);
                if (plugin_interface_ptr != 0) {
                    game_state_pending = GAME_STATE_PLUGIN_RUNTIME;
                    ui_transition_direction = 0;

                    for (int i = 0; i < 2; ++i) {
                        mod_api_context.keyConfig.up[i] =
                            player_state_table[i]
                                .input.move_key_forward;
                        mod_api_context.keyConfig.down[i] =
                            player_state_table[i]
                                .input.move_key_backward;
                        mod_api_context.keyConfig.left[i] =
                            player_state_table[i]
                                .input.turn_key_left;
                        mod_api_context.keyConfig.right[i] =
                            player_state_table[i]
                                .input.turn_key_right;
                        mod_api_context.keyConfig.fire[i] =
                            player_state_table[i].input.fire_key;
                        mod_api_context.keyConfig.torsoLeft[i] =
                            player_state_table[i].input.aim_key_left;
                        mod_api_context.keyConfig.torsoRight[i] =
                            player_state_table[i].input.aim_key_right;
                        mod_api_context.keyConfig.joyAimAxisX[i] =
                            player_state_table[i].input.axis_aim_x;
                        mod_api_context.keyConfig.joyAimAxisY[i] =
                            player_state_table[i].input.axis_aim_y;
                        mod_api_context.keyConfig.joyMoveAxisX[i] =
                            player_state_table[i].input.axis_move_x;
                        mod_api_context.keyConfig.joyMoveAxisY[i] =
                            player_state_table[i].input.axis_move_y;
                    }
                    mod_api_context.keyConfig.levelUp =
                        config_blob.key_pick_perk;
                    mod_api_context.keyConfig.reload =
                        config_blob.key_reload;
                }
            }
        }
    }

    button_position.x = button_origin.x + 58.0f;
    button_position.y = button_origin.y + 266.0f;
    if (ui_button_update(
            (float *)&button_position,
            (ui_button_t *)&main_menu_button)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_MAIN_MENU;
        mods_menu_refresh_pending = 1;
    }
}
