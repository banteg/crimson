#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct perk_selection_vec2_t {
    float x;
    float y;

    perk_selection_vec2_t() {}

    perk_selection_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    perk_selection_vec2_t operator+(const perk_selection_vec2_t &other) const
    {
        return perk_selection_vec2_t(x + other.x, other.y + y);
    }

    perk_selection_vec2_t &operator+=(const perk_selection_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct perk_selection_color_t {
    float r;
    float g;
    float b;
    float a;

    perk_selection_color_t(
        float red,
        float green,
        float blue,
        float alpha)
        : r(red), g(green), b(blue), a(alpha) {}

    ~perk_selection_color_t() {}
};

struct perk_selection_item_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    unsigned char padding;
    float hover_phase;
    float alpha;

    perk_selection_item_t()
    {
        enabled = true;
        alpha = 1.0f;
        label = 0;
        hovered = false;
        activated = false;
        hover_phase = 0.0f;
    }

    ~perk_selection_item_t() {}
};

struct perk_selection_button_t {
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

    perk_selection_button_t()
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

    ~perk_selection_button_t() {}
};

extern "C" {
extern int perk_id_perk_expert;
extern int perk_id_perk_master;
extern int perk_choice_ids[7];
extern int ui_text_pick_perk_texture;
extern int perk_selection_index;
extern int perk_pending_count;
extern unsigned char perk_choices_dirty;
extern unsigned char ui_transition_direction;
extern game_state_id_t game_state_pending;
extern int sfx_ui_buttonclick;

void ui_draw_textured_quad(
    int x, int y, int width, int height, int texture_id);
bool ui_menu_item_update(float *xy, ui_menu_item_t *item);
bool ui_button_update(float *xy, ui_button_t *button);
void perk_apply(int perk_id);
}

#define CRIMSONLAND_USE_ORIGINAL_TEXTURES_OWNER
#include "crimsonland_textures_owner.h"

extern "C" void perk_selection_screen_update(void)
{
    gameplay_render_world();
    ui_elements_update_and_render();

    perk_selection_vec2_t panel_position =
        *(perk_selection_vec2_t *)&ui_element_slot_27.pos
        + *(perk_selection_vec2_t *)&ui_element_slot_27.vertices[0].position;

    float line_height = 19.0f;
    bool any_hovered = false;
    int choice_count = 5;

    panel_position += perk_selection_vec2_t(180.0f, 40.0f);
    perk_selection_vec2_t choice_position = panel_position;
    choice_position.x =
        ui_element_slot_27.render_offset_x + choice_position.x + 44.0f;
    perk_selection_vec2_t anchor_position = choice_position;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    ui_draw_textured_quad(
        (int)(choice_position.x + 54.0f),
        (int)(choice_position.y + 6.0f),
        128,
        32,
        ui_text_pick_perk_texture);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.5f);
    if (player_state_table[0].perk_counts[perk_id_perk_master] > 0) {
        grim_interface_ptr->grim_draw_text_small_fmt(
            choice_position.x - 28.0f,
            choice_position.y - 8.0f,
            "extra perks sponsored by the Perk Master");
        choice_count = 7;
    } else if (player_state_table[0].perk_counts[perk_id_perk_expert] > 0) {
        grim_interface_ptr->grim_draw_text_small_fmt(
            choice_position.x - 26.0f,
            choice_position.y - 8.0f,
            "extra perk sponsored by the Perk Expert");
        choice_count = 6;
    }

    if (player_state_table[0].perk_counts[perk_id_perk_expert] > 0) {
        float choice_y = choice_position.y + 40.0f;
        line_height = 18.0f;
        choice_position.y = choice_y;
    } else {
        float choice_y = choice_position.y + 50.0f;
        choice_position.y = choice_y;
    }

    static perk_selection_color_t idle_color(
        0.274509817f, 0.70588237f, 0.941176474f, 0.600000024f);
    static perk_selection_color_t hover_color(
        0.274509817f, 0.70588237f, 0.941176474f, 1.0f);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    static perk_selection_item_t choice_items[10];
    for (int i = 0; i < choice_count; ++i) {
        choice_items[i].label = perk_meta_table[perk_choice_ids[i]].name;
        ui_menu_item_update(
            (float *)&choice_position,
            (ui_menu_item_t *)&choice_items[i]);
        if (choice_items[i].hovered) {
            any_hovered = true;
            perk_selection_index = i;
        }
        choice_position.y += line_height;
    }

    choice_position.y += 32.0f;
    if (choice_count > 5) {
        choice_position.y -= 20.0f;
    }
    choice_position.x -= 28.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    grim_interface_ptr->grim_draw_text_small(
        choice_position.x + 16.0f,
        choice_position.y,
        perk_meta_table[perk_choice_ids[perk_selection_index]].description);

    static perk_selection_button_t cancel_button;
    cancel_button.label = "Cancel";

    static perk_selection_button_t select_button;
    select_button.label = "Select";

    perk_selection_vec2_t button_position(
        anchor_position.x + 162.0f,
        anchor_position.y + 276.0f);
    if (ui_button_update(
            (float *)&button_position,
            (ui_button_t *)&cancel_button)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
    }

    perk_prompt_update_and_render();
    ui_cursor_render();

    if (any_hovered
        && perk_selection_index >= 0
        && choice_items[perk_selection_index].activated) {
        sfx_play(sfx_ui_buttonclick, 1.0f);
        perk_apply(perk_choice_ids[perk_selection_index]);
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        --perk_pending_count;
        perk_choices_dirty = 1;
    }
}
