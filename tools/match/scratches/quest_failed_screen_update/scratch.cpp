#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct quest_failed_vec2_t {
    float x;
    float y;
};

struct quest_failed_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;

    quest_failed_button_t()
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

    ~quest_failed_button_t() {}
};

extern "C" {
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern int ui_screen_phase;
extern int quest_failed_highscore_rank_index;
extern ui_element_t ui_element_slot_35;
extern ui_element_t ui_sign_crimson;
extern int ui_text_reaper_texture;

void j_highscore_load_table(void);
int highscore_rank_index(void);
int console_input_poll(void);
unsigned char sfx_is_unmuted(int sfx_id);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
extern int music_track_shortie_monk_id;
extern int music_track_crimson_theme_id;
extern int music_track_extra_0;
void ui_draw_textured_quad(
    int x, int y, int width, int height, int texture_id);
void ui_text_input_render(
    float *xy,
    highscore_record_t *record,
    float alpha,
    int rank);
bool ui_button_update(float *xy, ui_button_t *button);
}

extern "C" void quest_failed_screen_update(void)
{
    bonus_reflex_boost_timer = 0.0f;
    if (game_state_id == GAME_STATE_QUEST_FAILED
        && game_state_pending == GAME_STATE_PENDING_IDLE_SENTINEL
        && ui_transition_direction != 0
        && !sfx_is_unmuted(music_track_shortie_monk_id)) {
        sfx_play_exclusive(music_track_shortie_monk_id);
    }

    gameplay_render_world();
    ui_elements_update_and_render();
    perk_prompt_update_and_render();

    do {
        quest_failed_vec2_t panel_xy;
        panel_xy.x =
            ui_element_slot_35.pos_x + ui_element_slot_35.vertices[0].x;
        panel_xy.y =
            ui_element_slot_35.vertices[0].y + ui_element_slot_35.pos_y;
        panel_xy.x += 180.0f;

        quest_failed_vec2_t xy;
        xy.x = panel_xy.x;
        xy.y = panel_xy.y + 40.0f;
        xy.x =
            ui_element_slot_35.render_offset_x + xy.x + 44.0f - 10.0f;

        {
            quest_failed_vec2_t banner_xy = xy;

            ui_draw_textured_quad(
                (int)(xy.x - 2.0f),
                (int)xy.y,
                256,
                64,
                ui_text_reaper_texture);

            if (ui_screen_phase == -1) {
                j_highscore_load_table();
                quest_failed_highscore_rank_index = highscore_rank_index();
                highscore_active_record.game_mode_id =
                    (unsigned char)config_game_mode;
                grim_interface_ptr->grim_flush_input();
                console_input_poll();
                grim_interface_ptr->grim_was_key_pressed(0x1c);
                ui_screen_phase = 0;
            } else if (ui_screen_phase != 0) {
                break;
            }

            xy = banner_xy;
        }

        xy.x += 30.0f;
        xy.y += 70.0f;
        xy.y += 16.0f;
        switch (quest_fail_retry_count) {
        case 0:
            grim_interface_ptr->grim_draw_text_small(
                xy.x, xy.y, "Quest failed, try again.");
            break;
        case 1:
            grim_interface_ptr->grim_draw_text_small(
                xy.x, xy.y, "You didn't make it, do try again.");
            break;
        case 2:
            grim_interface_ptr->grim_draw_text_small(
                xy.x, xy.y, "Third time no good.");
            break;
        case 3:
            grim_interface_ptr->grim_draw_text_small(
                xy.x, xy.y, "No luck this time, have another go?");
            break;
        case 4:
            grim_interface_ptr->grim_draw_text_small(
                xy.x, xy.y, "Persistence will be rewared.");
            break;
        case 5:
            grim_interface_ptr->grim_draw_text_small(
                xy.x, xy.y, "Try one more time?");
            break;
        default:
            grim_interface_ptr->grim_draw_text_small(
                xy.x, xy.y, "Quest failed, try again.");
            break;
        }

        xy.y += 16.0f;
        xy.x += 6.0f;

        quest_failed_vec2_t input_xy;
        input_xy.x = xy.x + 4.0f;
        input_xy.y = xy.y + 10.0f;
        ui_text_input_render(
            (float *)&input_xy,
            &highscore_active_record,
            1.0f,
            quest_failed_highscore_rank_index + 1);

        xy.y = panel_xy.y + 98.0f;
        xy.x += 16.0f;

        static quest_failed_button_t play_again_button;
        play_again_button.label = "Play Again";

        static quest_failed_button_t play_another_button;
        play_another_button.label = "Play Another";

        static quest_failed_button_t main_menu_button;
        main_menu_button.label = "Main Menu";

        ui_button_update((float *)&xy, (ui_button_t *)&play_again_button);
        xy.y += 32.0f;
        ui_button_update((float *)&xy, (ui_button_t *)&play_another_button);
        xy.y += 32.0f;
        ui_button_update((float *)&xy, (ui_button_t *)&main_menu_button);
        xy.y += 32.0f;

        if (play_again_button.activated) {
            ++quest_fail_retry_count;
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_GAMEPLAY;
            sfx_mute_all(music_track_crimson_theme_id);
            sfx_mute_all(music_track_shortie_monk_id);
            sfx_mute_all(music_track_extra_0);
            render_pass_mode = 0;
        }
        if (play_another_button.activated) {
            quest_fail_retry_count = 0;
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_QUEST_SELECT;
            ui_sign_crimson.focus_disabled = 0;
            sfx_mute_all(music_track_crimson_theme_id);
            sfx_mute_all(music_track_shortie_monk_id);
            sfx_mute_all(music_track_extra_0);
            sfx_play_exclusive(music_track_crimson_theme_id);
        }
        if (main_menu_button.activated) {
            quest_fail_retry_count = 0;
            sfx_mute_all(music_track_extra_0);
            sfx_mute_all(music_track_crimson_theme_id);
            sfx_mute_all(music_track_shortie_monk_id);
            sfx_play_exclusive(music_track_crimson_theme_id);
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_MAIN_MENU;
            ui_sign_crimson.focus_disabled = 0;
        }
    } while (false);

    ui_cursor_render();
}
