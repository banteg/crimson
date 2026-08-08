#include <windows.h>
#include <shellapi.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct demo_trial_vec2_t {
    float x;
    float y;

    demo_trial_vec2_t() {}

    demo_trial_vec2_t(float x_value, float y_value) : x(x_value), y(y_value) {}
};

struct demo_trial_color_t {
    float r;
    float g;
    float b;
    float a;

    demo_trial_color_t(float r_value, float g_value, float b_value, float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}
};

struct demo_trial_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;

    demo_trial_button_t() {
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

    ~demo_trial_button_t() {}
};

extern "C" {
extern int demo_trial_elapsed_ms;
extern unsigned char demo_trial_overlay_active;
extern unsigned char shareware_offer_seen_latch;
extern unsigned char quit_requested;
extern unsigned char ui_transition_direction;
extern game_state_id_t game_state_pending;
extern int music_track_intro_id;
extern int music_track_shortie_monk_id;
extern int music_track_crimson_theme_id;
extern int music_track_extra_0;

int demo_trial_time_limit_ms(void);
int play_time_get(void);
bool ui_button_update(float *xy, ui_button_t *button);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
}

extern "C" void demo_trial_overlay_render(float *xy, float alpha) {
    demo_trial_overlay_active = 1;

    demo_trial_color_t panel_color(0.0f, 0.0f, 0.0f, alpha * 0.8f);
    grim_interface_ptr->grim_draw_rect_filled(xy, 512.0f, 256.0f, (float *)&panel_color);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_draw_rect_outline(xy, 512.0f, 256.0f);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_bind_texture(grim_interface_ptr->grim_get_texture_handle("cl_logo"),
                                          0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_draw_quad(xy[0] + 72.0f, xy[1] + 22.0f, 371.2f, 46.4f);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_draw_text_small_fmt(xy[0] + 131.0f, xy[1] + 9.0f,
                                                 "You've been playing the Demo version of");
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    {
        demo_trial_vec2_t position = *(demo_trial_vec2_t *)xy;
        position.x += 26.0f;
        position.y += 80.0f;

        int remaining_ms = demo_trial_time_limit_ms() - (int)play_time_ms;
        if (demo_trial_elapsed_ms > 0) {
            remaining_ms = 300000 - demo_trial_elapsed_ms;
        }

        int total_seconds = remaining_ms / 1000;
        int minutes = total_seconds / 60;
        minutes -= (minutes / 60) * 60;
        int seconds = total_seconds - minutes * 60;
        int centiseconds = (remaining_ms - (minutes * 60 + seconds) * 1000) / 10;

        if (minutes < 0) {
            seconds = 0;
            centiseconds = 0;
            minutes = 0;
        }

        char seconds_text[128];
        char time_text[128];
        if (seconds < 10) {
            crt_sprintf(seconds_text, "0%d", seconds);
        } else {
            crt_sprintf(seconds_text, "%d", seconds);
        }
        if (centiseconds < 10) {
            crt_sprintf(time_text, "%d:%s.0%d", minutes, seconds_text, centiseconds);
        } else {
            crt_sprintf(time_text, "%d:%s.%d", minutes, seconds_text, centiseconds);
        }

        if (!game_is_full_version() && config_game_mode != GAME_MODE_TUTORIAL &&
            (int)(play_time_ms = play_time_get()) <= 2400000 &&
            ((demo_trial_elapsed_ms > 0 && config_game_mode == GAME_MODE_QUEST &&
              (float)(demo_trial_elapsed_ms / 1000) * 0.016666668f <= 5.0f) ||
             (demo_trial_elapsed_ms <= 0 && config_game_mode == GAME_MODE_QUEST)) &&
            game_state_id == GAME_STATE_GAMEPLAY &&
            (quest_stage_major > 1 || quest_stage_minor > 10)) {
            position.y -= 6.0f;
            if (demo_trial_elapsed_ms <= 0) {
                grim_interface_ptr->grim_draw_text_small_fmt(
                    position.x, position.y,
                    "You've completed all Quest mode levels available in the Demo version.");
                position.y += 18.0f;
                grim_interface_ptr->grim_draw_text_small_fmt(
                    position.x, position.y,
                    "However, you still have %s time left to play Survival and Rush game modes.",
                    time_text);
                position.y += 18.0f;
                grim_interface_ptr->grim_draw_text_small_fmt(position.x, position.y, "");
                position.y += 14.0f;
            } else {
                position.y += 6.0f;
                grim_interface_ptr->grim_draw_text_small_fmt(
                    position.x, position.y,
                    "You've completed all Quest mode levels available in the Demo version.");
                position.y += 18.0f;
            }

            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "If you would like to have unlimited play time and access to all features,");
            position.y += 18.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y, "please upgrade to the full version of Crimsonland.");
            position.y += 22.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y, "The full version features unrestricted access to all 3");
            position.y += 18.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "game modes and be able to post your scores on the Internet. Why not buy");
            position.y += 18.0f;
        } else if (minutes <= 0 && seconds <= 0) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "Trial time is up. If you would like to have unlimited play time and access to");
            position.y += 18.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "all features, please upgrade to the full version of Crimsonland.  The process");
            position.y += 18.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(position.x, position.y,
                                                         "is very easy and takes just minutes.");
            position.y += 24.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "Buy the full version to gain unrestricted access to all 3");
            position.y += 18.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "game modes and be able to post your scores on the Internet. Why not buy");
            position.y += 18.0f;
        } else {
            position.y -= 7.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "You have used up your play time in this game mode. However, you still", time_text);
            position.y += 16.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y, "have %s time left to play Quest mode levels only.",
                time_text);
            position.y += 22.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "If you would like to have unlimited play time and access to all features,");
            position.y += 16.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "please upgrade to the full version of Crimsonland.  The process is very easy");
            position.y += 16.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(position.x, position.y,
                                                         "and takes just minutes. ");
            position.y += 22.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "Buy the full version to gain unrestricted access to all 3");
            position.y += 16.0f;
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x, position.y,
                "game modes and be able to post your scores on the Internet. Why not buy");
            position.y += 16.0f;
        }

        grim_interface_ptr->grim_draw_text_small_fmt(position.x, position.y,
                                                     "it now? You'll have a great time!");
    }

    static demo_trial_button_t maybe_later_button;
    maybe_later_button.label = "Maybe later";

    static demo_trial_button_t purchase_button;
    purchase_button.label = "Purchase";

    static demo_trial_button_t already_paid_button;
    already_paid_button.label = "Already paid";

    {
        demo_trial_vec2_t button_position;
        button_position.x = xy[0] + 22.0f;
        float button_y = xy[1] + 212.0f;

        {
            demo_trial_vec2_t position;
            position.x = button_position.x + 6.0f;
            position.y = button_y + 6.0f;
            if (ui_button_update((float *)&position, (ui_button_t *)&purchase_button)) {
                shareware_offer_seen_latch = 1;
                quit_requested = 1;
                ShellExecuteA(0, "open", "http://buy.crimsonland.com", 0, 0, SW_SHOWNORMAL);
            }
        }

        button_position.x += 326.0f;
        button_position.y = button_y + 6.0f;
        if (ui_button_update((float *)&button_position, (ui_button_t *)&maybe_later_button)) {
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_MAIN_MENU;
            render_pass_mode = 0;
            sfx_mute_all(music_track_intro_id);
            sfx_mute_all(music_track_shortie_monk_id);
            sfx_mute_all(music_track_extra_0);
            sfx_play_exclusive(music_track_crimson_theme_id);
        }
    }
}
