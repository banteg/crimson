#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct tutorial_color_t {
    float r;
    float g;
    float b;
    float a;

    tutorial_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

struct tutorial_vec2_t {
    float x;
    float y;

    tutorial_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }
};

struct tutorial_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;

    tutorial_button_t()
    {
        enabled = true;
        force_small = force_wide = false;
        alpha = 1.0f;
        click_anim = 0;
        label = 0;
        hovered = false;
        activated = false;
        hover_anim = 0;
    }

    ~tutorial_button_t() {}
};

extern "C" {
extern int config_screen_width;
extern int config_screen_height;
extern ui_element_t ui_sign_crimson;
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern int tutorial_stage_timer;
extern int tutorial_stage_transition_timer;
extern int perk_pending_count;

bool ui_button_update(float *xy, ui_button_t *button);
void console_input_poll(void);
}

extern "C" void tutorial_prompt_dialog(
    char *text,
    float alpha,
    char tutorial_complete)
{
    int text_width = grim_interface_ptr->grim_measure_text_width(text);
    int line_count = 1;
    if (strchr(text, '\n') != 0) {
        line_count = 2;
    }
    if (tutorial_complete) {
        line_count = 4;
    }

    int left = (int)(
        (float)(config_screen_width / 2)
        - (float)text_width * 0.5f
        - 20.0f);
    tutorial_color_t panel_color(0.0f, 0.0f, 0.0f, alpha * 0.8f);
    {
        tutorial_vec2_t panel_xy((float)left, 64.0f);
        float panel_height = (float)(line_count * 16 + 6);
        float panel_width = (float)(text_width + 40);
        grim_interface_ptr->grim_draw_rect_filled(
            (float *)&panel_xy,
            panel_width,
            panel_height,
            (float *)&panel_color);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
        panel_xy.set((float)left, 64.0f);
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&panel_xy,
            panel_width,
            panel_height);
    }

    panel_color = tutorial_color_t(1.0f, 1.0f, 1.0f, alpha * 0.9f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        (float)(left + 20),
        68.0f,
        text);

    static tutorial_button_t repeat_button;
    repeat_button.label = "Repeat tutorial";

    static tutorial_button_t primary_button;
    primary_button.label = "Play a game";

    if (tutorial_complete) {
        primary_button.alpha = alpha;
        repeat_button.alpha = alpha;

        tutorial_vec2_t button_xy((float)(left + 32), 90.0f);
        ui_button_update(
            (float *)&button_xy,
            (ui_button_t *)&primary_button);
        button_xy.x = (float)(left + 192);
        button_xy.y = 90.0f;
        ui_button_update(
            (float *)&button_xy,
            (ui_button_t *)&repeat_button);

        if (primary_button.activated) {
            ui_sign_crimson.focus_disabled = 0;
            game_state_pending = GAME_STATE_PLAY_GAME_MENU;
            render_pass_mode = 0;
            ui_transition_direction = 0;
            grim_interface_ptr->grim_flush_input();
            console_input_poll();
            tutorial_stage_transition_timer = -1000;
        }
        if (repeat_button.activated) {
            player_state_table[0].level = 1;
            memset(
                player_state_table[0].perk_counts,
                0,
                sizeof(player_state_table[0].perk_counts));
            tutorial_stage_transition_timer = -1000;
            perk_pending_count = 0;
            tutorial_stage_timer = 2000;
            return;
        }
    } else {
        primary_button.alpha =
            (float)(tutorial_stage_timer - 1000) * 0.001f;
        if (primary_button.alpha > 1.0f) {
            primary_button.alpha = 1.0f;
        } else if (primary_button.alpha < 0.0f) {
            primary_button.alpha = 0.0f;
        }

        primary_button.label = "Skip tutorial";
        tutorial_vec2_t button_xy(
            10.0f,
            (float)(config_screen_height - 50));
        ui_button_update(
            (float *)&button_xy,
            (ui_button_t *)&primary_button);
        if (primary_button.activated) {
            ui_sign_crimson.focus_disabled = 0;
            game_state_pending = GAME_STATE_PLAY_GAME_MENU;
            render_pass_mode = 0;
            ui_transition_direction = 0;
            grim_interface_ptr->grim_flush_input();
            console_input_poll();
            tutorial_stage_transition_timer = -1000;
        }
    }
}
