#include <process.h>
#include <windows.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct statistics_vec2_t {
    float x;
    float y;

    statistics_vec2_t() {}

    statistics_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    statistics_vec2_t operator+(const statistics_vec2_t &other) const
    {
        return statistics_vec2_t(x + other.x, other.y + y);
    }

};

struct statistics_button_t {
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

    statistics_button_t()
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

    ~statistics_button_t() {}
};

extern "C" {
extern ui_element_t ui_element_slot_39;
extern ui_element_t ui_sign_crimson;
extern int ui_item_texts_texture;
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern unsigned char screen_fade_ramp_flag;
extern unsigned char render_pass_mode;
extern int online_sync_status;
extern char *update_notice_url;
extern unsigned char update_notice_pending;
extern int music_track_crimson_theme_id;
extern int music_track_shortie_monk_id;
extern int music_track_extra_0;
extern char menu_label_back[];

bool ui_button_update(float *xy, ui_button_t *button);
void highscore_load_table_thunk(void);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
void statistics_update_check_worker(void *arg);
void crt_beginthread(
    void (*function)(void *),
    unsigned int stack_size,
    void *arg);
}

extern "C" void statistics_menu_update(void)
{
    static statistics_button_t high_scores_button;
    high_scores_button.label = "High scores";

    static statistics_button_t weapons_button;
    weapons_button.label = "  Weapons  ";

    static statistics_button_t perks_button;
    perks_button.label = "  Perks  ";

    static statistics_button_t credits_button;
    credits_button.label = " Credits ";

    static statistics_button_t typo_button;
    typo_button.label = " (Typ'o'Shooter) ";

    static statistics_button_t mods_button;
    mods_button.label = "(Mods)";

    static statistics_button_t update_button;
    update_button.label = "Check for updates";

    static statistics_button_t back_button;
    back_button.label = menu_label_back;

    if (online_sync_status == 0 || online_sync_status == 6) {
        back_button.enabled = true;
        update_button.enabled = true;
        mods_button.enabled = true;
        credits_button.enabled = true;
        weapons_button.enabled = true;
        high_scores_button.enabled = true;
    } else {
        back_button.enabled = false;
        update_button.enabled = false;
        mods_button.enabled = false;
        credits_button.enabled = false;
        weapons_button.enabled = false;
        high_scores_button.enabled = false;
    }

    statistics_vec2_t panel_position =
        *(statistics_vec2_t *)&ui_element_slot_39.pos_x
        + *(statistics_vec2_t *)&ui_element_slot_39.vertices[0].x
        + statistics_vec2_t(300.0f, 40.0f);
    statistics_vec2_t xy = panel_position;
    xy.x =
        ui_element_slot_39.render_offset_x - 110.0f + xy.x + 52.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    xy.y += 16.0f;
    grim_interface_ptr->grim_bind_texture(ui_item_texts_texture, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.375f, 1.0f, 0.5f);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_draw_quad(
        xy.x + 64.0f - 16.0f,
        xy.y - 4.0f,
        128.0f,
        32.0f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);

    xy.y += 48.0f;
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.23f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.43f);

    int session_minutes = (int)play_time_ms / 1000 / 60;
    int session_hours = session_minutes / 60;
    int session_minute_part = session_minutes - session_hours * 60;
    grim_interface_ptr->grim_draw_text_small_fmt(
        xy.x - 38.0f,
        xy.y + 230.0f,
        "played for %d hours %d minutes",
        session_hours,
        session_minute_part,
        (int)play_time_ms / 1000 - session_minute_part * 60);

    if (online_sync_status != 0) {
        Sleep(10);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        char *status_text = "";
        if (online_sync_status == 1) {
            grim_interface_ptr->grim_set_color(
                0.2f, 1.0f, 0.2f, 0.8f);
            status_text = "Connecting server..";
        } else if (online_sync_status == 5) {
            grim_interface_ptr->grim_set_color(
                0.4f, 1.0f, 0.4f, 0.8f);
            status_text = "Done..";
        } else if (online_sync_status == 6) {
            grim_interface_ptr->grim_set_color(
                1.0f, 0.1f, 0.1f, 0.8f);
            status_text = "Failed..";
        }
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x - 38.0f, xy.y + 186.0f, status_text);
    } else {
        if (update_notice_pending && update_notice_url == 0) {
            grim_interface_ptr->grim_set_color(
                0.5f, 0.6f, 1.0f, 0.8f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x - 40.0f,
                xy.y + 186.0f,
                "You've got the newest version");
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x - 40.0f,
                xy.y + 200.0f,
                "of Crimsonland.");
        } else if (update_button.hover_anim > 0) {
            grim_interface_ptr->grim_set_color(
                1.0f,
                1.0f,
                1.0f,
                (float)update_button.hover_anim * 0.001f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x - 38.0f,
                xy.y + 186.0f,
                "Connect the Internet and check");
            grim_interface_ptr->grim_draw_text_small_fmt(
                xy.x - 38.0f,
                xy.y + 200.0f,
                "for new Crimsonland versions");
        }
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    int total_seconds = time_played_ms / 1000;
    int total_minutes = total_seconds / 60;
    int total_hours = total_minutes / 60;
    total_minutes -= total_hours * 60;
    if (total_hours != session_hours
        && grim_interface_ptr->grim_is_key_active(0x3b)) {
        IGrim2D_cpp *total_renderer = grim_interface_ptr;
        total_renderer->grim_draw_text_small_fmt(
            xy.x - 38.0f,
            xy.y + 230.0f - 15.0f,
            "(total %dh)",
            total_hours,
            total_minutes,
            total_seconds - total_minutes * 60);
    }

    xy.x += 28.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&high_scores_button);
    xy.y += 34.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&weapons_button);
    xy.y += 34.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&perks_button);
    xy.y += 34.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&credits_button);
    xy.y += 34.0f;
    xy.y += 34.0f;
    xy.x += 124.0f;
    xy.y += 16.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&back_button);
    xy.y += 34.0f;

    if (high_scores_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_HIGHSCORES;
        if (quest_stage_major < 1) {
            quest_stage_major = 1;
        } else if (quest_stage_major > 4) {
            quest_stage_major = 4;
        }
        if (quest_stage_minor < 1) {
            quest_stage_minor = 1;
            highscore_load_table_thunk();
        } else {
            if (quest_stage_minor > 10) {
                quest_stage_minor = 10;
            }
            highscore_load_table_thunk();
        }
    }

    if (weapons_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_WEAPON_DATABASE;
    }
    if (perks_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_PERK_DATABASE;
    }
    if (typo_button.activated) {
        render_pass_mode = 0;
        ui_sign_crimson.focus_disabled = 0;
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_TYPO_GAMEPLAY;
        config_game_mode = GAME_MODE_TYPO_SHOOTER;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
        screen_fade_ramp_flag = 1;
    }
    if (credits_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_CREDITS;
    }
    if (update_button.activated) {
        online_sync_status = 1;
        crt_beginthread(statistics_update_check_worker, 0, 0);
    }
    if (back_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_MAIN_MENU;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
        sfx_play_exclusive(music_track_crimson_theme_id);
    }
    if (grim_interface_ptr->grim_was_key_pressed(1)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_MAIN_MENU;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
        sfx_play_exclusive(music_track_crimson_theme_id);
    }
    if (ui_transition_direction == 0) {
        update_notice_pending = 0;
    }
}
