#include <math.h>
#include <string.h>
#include <windows.h>
#include <shellapi.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct demo_purchase_vec2_t {
    float x;
    float y;
};

struct demo_purchase_color_t {
    float r;
    float g;
    float b;
    float a;
};

struct demo_purchase_button_t {
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

    demo_purchase_button_t()
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

    ~demo_purchase_button_t() {}
};

extern "C" {
extern int frame_dt_ms;
extern int quest_spawn_timeline;
extern int demo_time_limit_ms;
extern int demo_upsell_message_index;
extern int ui_pulse_timer_ms;
extern unsigned char demo_purchase_screen_active;
extern unsigned char shareware_offer_seen_latch;
extern unsigned char quit_requested;
extern unsigned char ui_transition_direction;
extern game_state_id_t game_state_pending;
extern int music_track_intro_id;
extern int music_track_shortie_monk_id;
extern int music_track_crimsonquest_id;
extern int music_track_crimson_theme_id;

unsigned char game_is_full_version(void);
bool input_primary_just_pressed(void);
bool config_load_presets(bool skip_grim_settings);
bool ui_button_update(float *xy, ui_button_t *button);
void ui_draw_textured_quad(
    int x, int y, int width, int height, int texture_id);
void demo_mode_start(void);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
}

static __forceinline void demo_purchase_render_message(
    char *message,
    float position_y,
    float alpha)
{
    demo_purchase_vec2_t position;
    demo_purchase_color_t color;
    float message_y;
    float message_width = (float)strlen(message) * 12.8f;
    float progress_width =
        (float)quest_spawn_timeline
        / (float)demo_time_limit_ms
        * message_width;

    position.x = 60.0f;
    color.r = 0.0f;
    color.g = 0.0f;
    color.b = 0.0f;
    color.a = alpha * 0.5f;
    position.y = (message_y = position_y + 50.0f) - 4.0f;
    grim_interface_ptr->grim_draw_rect_filled(
        (float *)&position,
        message_width + 12.0f,
        30.0f,
        (float *)&color);

    position.x = 64.0f;
    color.r = 0.5f;
    color.g = 0.1f;
    color.b = 0.1f;
    color.a = alpha * 0.8f;
    position.y = position_y + 72.0f;
    grim_interface_ptr->grim_draw_rect_filled(
        (float *)&position,
        progress_width,
        3.0f,
        (float *)&color);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_draw_text_mono(
        50.0f, message_y, message);
}

extern "C" void demo_purchase_screen_update(void)
{
    if (ui_transition_direction != 0 && game_is_full_version()) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_MAIN_MENU;
        demo_mode_active = 1;
        config_load_presets(false);
        sfx_mute_all(music_track_intro_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_play_exclusive(music_track_crimson_theme_id);
        ui_elements_update_and_render();
        ui_cursor_render();
        return;
    }

    if (demo_purchase_screen_active == 0
        && (input_primary_just_pressed()
            || grim_interface_ptr->grim_was_key_pressed(1)
            || grim_interface_ptr->grim_was_key_pressed(0x39))) {
        demo_purchase_screen_active = 1;
        demo_time_limit_ms = 16000;
    }

    static demo_purchase_button_t maybe_later_button;
    maybe_later_button.label = "Maybe later";

    static demo_purchase_button_t purchase_button;
    purchase_button.label = "Purchase";

    float alpha;
    float position_y;
    position_y = (float)quest_spawn_timeline * 0.016000001f;
    alpha = 1.0f;
    if (position_y < 20.0f) {
        alpha = position_y * 0.05f;
    }
    if (quest_spawn_timeline > demo_time_limit_ms - 500) {
        alpha =
            (float)(demo_time_limit_ms - quest_spawn_timeline) * 0.002f;
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, alpha);
    grim_interface_ptr->grim_set_config_var(0x18, 0.8f);

    char *message = "";

    if (demo_purchase_screen_active != 0) {
        ui_pulse_timer_ms += frame_dt_ms;
        float pulse =
            (float)sin((float)(ui_pulse_timer_ms % 1000) * 6.2831855f);
        float pulse_squared = pulse * pulse;

        grim_interface_ptr->grim_set_color_slot(
            0, 0.0f, 0.0f, 0.0f, 1.0f);
        grim_interface_ptr->grim_set_color_slot(
            1, 0.0f, 0.0f, 0.3f, 1.0f);
        grim_interface_ptr->grim_set_color_slot(
            2, 0.0f, 0.4f, pulse_squared * 0.55f, pulse_squared);
        grim_interface_ptr->grim_set_color_slot(
            3, 0.0f, 0.4f, 0.4f, 1.0f);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 0.5f, 0.5f);
        grim_interface_ptr->grim_bind_texture(
            grim_interface_ptr->grim_get_texture_handle("backplasma"), 0);
        grim_interface_ptr->grim_draw_quad(
            0.0f,
            0.0f,
            (float)config_blob.screen_width,
            (float)config_blob.screen_height);
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

        float layout_shift = 0.0f;
        if (config_blob.screen_width == 800) {
            layout_shift = 64.0f;
        } else if (config_blob.screen_width == 1024) {
            layout_shift = 128.0f;
        }

        ui_draw_textured_quad(
            (int)((float)(config_blob.screen_width / 2 - 128)
                  + layout_shift),
            config_blob.screen_height / 2 - 140,
            512,
            256,
            grim_interface_ptr->grim_get_texture_handle("mockup"));

        ui_draw_textured_quad(
            config_blob.screen_width / 2 - 256,
            (int)((float)(config_blob.screen_height / 2 - 200)
                  - layout_shift * 0.4f),
            512,
            64,
            grim_interface_ptr->grim_get_texture_handle("cl_logo"));

        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_set_config_var(0x18, 0.6f);

        position_y = (float)(config_blob.screen_height / 2 - 104);
        int text_x_int =
            (int)((float)(config_blob.screen_width / 2 - 296)
                  - layout_shift * 0.8f);
        float text_x = (float)text_x_int;

        grim_interface_ptr->grim_draw_text_small(
            text_x,
            position_y,
            "Upgrade to the full version of Crimsonland Today!");
        position_y += 28.0f;
        grim_interface_ptr->grim_draw_text_small(
            text_x, position_y, "Full version features:");

        demo_purchase_vec2_t position;
        position.x = text_x;
        position.y = position_y + 15.0f;
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&position,
            (float)grim_interface_ptr->grim_measure_text_width(
                "Full version features:"),
            1.0f);

        position_y += 22.0f;
        float feature_x = (float)(text_x_int + 8);
        grim_interface_ptr->grim_draw_text_small(
            feature_x,
            position_y,
            "-Unlimited Play Time in three thrilling Game Modes!");
        position_y += 22.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            feature_x,
            position_y,
            "-The varied weapon arsenal consisting of over 20 unique");
        position_y += 17.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            feature_x,
            position_y,
            " weapons that allow you to deal death with plasma, lead,");
        position_y += 17.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            feature_x, position_y, " fire and electricity!");
        position_y += 22.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            feature_x, position_y, "-Over 40 game altering Perks!");
        position_y += 22.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            feature_x, position_y, "-40 insane Levels that give you");
        position_y += 18.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            feature_x, position_y, " hours of intense and fun gameplay!");
        position_y += 22.0f;
        grim_interface_ptr->grim_draw_text_small(
            feature_x,
            position_y,
            "-The ability to post your high scores online!");
        position_y += 22.0f;
        position_y += 22.0f;
        grim_interface_ptr->grim_draw_text_small(
            text_x,
            position_y,
            "Purchasing the game is very easy and secure.");
        position_y += 17.0f;
        position_y += 17.0f;
        position_y += 22.0f;

        position.x =
            (float)(config_blob.screen_width / 2 + 128);
        position.y =
            (float)(config_blob.screen_height / 2 + 102)
            + layout_shift * 0.3f + 50.0f;
        if (ui_button_update(
                (float *)&position,
                (ui_button_t *)&purchase_button)) {
            shareware_offer_seen_latch = 1;
            quit_requested = 1;
            ShellExecuteA(
                0,
                "open",
                "http://buy.crimsonland.com",
                0,
                0,
                SW_SHOWNORMAL);
            return;
        }

        position.x =
            (float)(config_blob.screen_width / 2 + 128);
        position.y =
            (float)(config_blob.screen_height / 2 + 102)
            + layout_shift * 0.3f + 90.0f;
        if (ui_button_update(
                (float *)&position,
                (ui_button_t *)&maybe_later_button)) {
            unsigned char offer_seen = shareware_offer_seen_latch;
            if (offer_seen != 0) {
                quit_requested = 1;
            }
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_MAIN_MENU;
            demo_mode_active = 1;
            if (offer_seen == 0) {
                config_load_presets(false);
                sfx_mute_all(music_track_intro_id);
                sfx_mute_all(music_track_crimsonquest_id);
                sfx_play_exclusive(music_track_crimson_theme_id);
            }
            return;
        }

        quest_spawn_timeline += frame_dt_ms;
        if (quest_spawn_timeline > demo_time_limit_ms) {
            render_pass_mode = 0;
            demo_mode_start();
        }
        if (demo_purchase_screen_active != 0) {
            ui_elements_update_and_render();
            ui_cursor_render();
            return;
        }
    } else {
        int message_index = demo_upsell_message_index;
        if (quest_spawn_timeline == 0) {
            message_index = (message_index + 1) % 5;
            demo_upsell_message_index = message_index;
        }

        if (message_index == 0) {
            message = "Want more Levels?";
        } else if (message_index == 1) {
            message = "Want more Weapons?";
        } else if (message_index == 2) {
            message = "Want more Perks?";
        } else if (message_index == 3) {
            message = "Want unlimited Play time?";
        } else if (message_index == 4) {
            message = "Want to post your high scores?";
        }
    }

    demo_purchase_render_message(message, position_y, alpha);

    ui_elements_update_and_render();
    ui_cursor_render();
}
