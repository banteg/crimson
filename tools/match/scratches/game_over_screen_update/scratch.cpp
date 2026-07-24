#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct game_over_vec2_t {
    float x;
    float y;

    game_over_vec2_t() {}

    game_over_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    void set(float x_value, float y_value)
    {
        x = x_value;
        y = y_value;
    }

    game_over_vec2_t operator+(const game_over_vec2_t &other) const
    {
        return game_over_vec2_t(x + other.x, other.y + y);
    }

    game_over_vec2_t &operator+=(const game_over_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct game_over_text_input_t {
    char *text;
    int cursor;
    int max_chars;
    int width_px;
    float alpha;

    game_over_text_input_t(char *buffer, int max, int width)
    {
        alpha = 1.0f;
        text = buffer;
        cursor = 0;
        max_chars = max;
        width_px = width;
    }

    ~game_over_text_input_t() {}
};

struct game_over_button_t {
    char *label;
    bool hovered;
    bool activated;
    bool enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    bool force_small;
    bool force_wide;

    game_over_button_t()
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

    ~game_over_button_t() {}
};

extern "C" {
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern int ui_screen_phase;
extern unsigned char highscore_return_latch;
extern int highscore_return_quest_stage_major;
extern int highscore_return_quest_stage_minor;
extern game_mode_id_t highscore_return_game_mode_id;
extern unsigned char highscore_return_hardcore_flag;
extern int game_over_highscore_rank_index;
extern char game_over_name_input_buffer[];
extern ui_element_t ui_element_slot_30;
extern ui_element_t ui_sign_crimson;
extern int ui_text_reaper_texture;
extern float render_tint_color_r;
extern float render_tint_color_a;
extern int player_name_length;
extern int sfx_ui_typeenter;

void j_highscore_load_table(void);
int highscore_rank_index(void);
void highscore_save_active(void);
int console_input_poll(void);
unsigned char sfx_is_unmuted(int sfx_id);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
extern int music_track_shortie_monk_id;
extern int music_track_crimson_theme_id;
extern int music_track_extra_0;
void ui_draw_textured_quad(
    int x, int y, int width, int height, int texture_id);
bool ui_text_input_update(float *xy, ui_text_input_state_t *input_state);
void ui_text_input_render(
    game_over_vec2_t &xy,
    highscore_record_t *record,
    float alpha,
    int rank);
bool ui_button_update(float *xy, ui_button_t *button);
}

static __inline unsigned char game_over_name_is_valid(char *name)
{
    int length = strlen(name);
    if (length < 1) {
        return false;
    }

    int first_non_space = 0;
    while (first_non_space < length && name[first_non_space] == ' ') {
        ++first_non_space;
    }
    return name[first_non_space];
}

extern "C" void game_over_screen_update(void)
{
    static game_over_button_t name_submit_button;
    char *name_buffer = game_over_name_input_buffer;
    static game_over_text_input_t name_input(
        name_buffer, 0x18, 0x60);

    bonus_reflex_boost_timer = 0.0f;
    if (ui_transition_direction != 0 && highscore_return_latch != 0) {
        highscore_return_latch = 0;
        ui_screen_phase = 1;
    }
    if (game_state_id == GAME_STATE_GAME_OVER
        && game_state_pending == GAME_STATE_PENDING_IDLE_SENTINEL
        && ui_transition_direction != 0
        && !sfx_is_unmuted(music_track_shortie_monk_id)) {
        sfx_play_exclusive(music_track_shortie_monk_id);
    }

    gameplay_render_world();
    ui_elements_update_and_render();
    perk_prompt_update_and_render();

    game_over_vec2_t panel_xy =
        *(game_over_vec2_t *)&ui_element_slot_30.pos
        + *(game_over_vec2_t *)&ui_element_slot_30.vertices[0].position
        + game_over_vec2_t(180.0f, 40.0f);

    game_over_vec2_t xy = panel_xy;
    xy.x =
        ui_element_slot_30.render_offset_x + xy.x + 44.0f - 10.0f;

    game_over_vec2_t banner_xy = xy;
    ui_draw_textured_quad(
        (int)(xy.x - 2.0f),
        (int)xy.y,
        256,
        64,
        ui_text_reaper_texture);

    if (ui_screen_phase == -1) {
        j_highscore_load_table();
        game_over_highscore_rank_index = highscore_rank_index();
        highscore_active_record.game_mode_id =
            (unsigned char)config_game_mode;
        grim_interface_ptr->grim_flush_input();
        console_input_poll();
        grim_interface_ptr->grim_was_key_pressed(0x1c);
        if (game_over_highscore_rank_index >= 100) {
            ui_screen_phase = 1;
        } else {
            ui_screen_phase = 0;
            name_input.max_chars = 0x14;
            name_input.text = name_buffer;
            strcpy(
                name_buffer,
                highscore_active_record.player_name);
            name_input.cursor = strlen(highscore_active_record.player_name);
        }
    }

    if (ui_screen_phase == 0) {
        xy.x += 8.0f;
        xy.y += 84.0f;
        render_tint_color_a = 1.0f;
        grim_interface_ptr->grim_set_color_ptr(&render_tint_color_r);
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x + 42.0f, xy.y, "State your name, trooper!");

        xy.y += 40.0f;
        render_tint_color_a = 0.7f;
        name_submit_button.label = "Ok";

        panel_xy.x = xy.x + 170.0f;
        panel_xy.y = xy.y - 8.0f;
        ui_button_update(
            (float *)&panel_xy,
            (ui_button_t *)&name_submit_button);

        name_input.width_px = 0xa6;
        if (ui_text_input_update(
                (float *)&xy,
                (ui_text_input_state_t *)&name_input)
            || name_submit_button.activated) {
            if (game_over_name_is_valid(name_buffer)) {
                ui_screen_phase = 1;
                sfx_play(sfx_ui_typeenter, 1.0f);
                memset(&highscore_active_record, 0, 0x1c);
                name_input.text = name_buffer;
                strcpy(
                    highscore_active_record.player_name,
                    name_buffer);
                player_name_length = name_input.cursor;
                highscore_active_record.player_name[name_input.cursor] = 0;
                highscore_save_active();
                j_highscore_load_table();
            } else {
                name_submit_button.activated = false;
                sfx_play(sfx_shock_hit_01, 1.0f);
            }
        }

        xy.y += 60.0f;
        grim_interface_ptr->grim_set_color_ptr(&render_tint_color_r);
        if (game_over_highscore_rank_index < 100) {
            panel_xy.set(xy.x + 16.0f, xy.y + 16.0f);
            ui_text_input_render(
                panel_xy,
                &highscore_active_record,
                1.0f,
                game_over_highscore_rank_index + 1);
        }
        ui_cursor_render();
        return;
    } else if (ui_screen_phase != 1) {
        ui_cursor_render();
        return;
    }

    xy = banner_xy;
    name_input.text = name_buffer;
    xy.x += 30.0f;
    if (game_over_highscore_rank_index >= 100) {
        xy.y += 62.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            xy.x + 8.0f,
            xy.y,
            "Score too low for top%d.",
            100);
        xy.y += 6.0f;
    } else {
        xy.y += 64.0f;
    }

    panel_xy.set(xy.x, xy.y + 16.0f);
    ui_text_input_render(
        panel_xy,
        &highscore_active_record,
        1.0f,
        game_over_highscore_rank_index + 1);

    xy.y += 146.0f;
    static game_over_button_t play_again_button;
    play_again_button.label = "Play Again";

    static game_over_button_t highscores_button;
    highscores_button.label = "High scores";

    static game_over_button_t main_menu_button;
    main_menu_button.label = "Main Menu";

    xy.x = xy.x - 4.0f + 26.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&play_again_button);
    xy.y += 32.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&highscores_button);
    xy.y += 32.0f;
    ui_button_update((float *)&xy, (ui_button_t *)&main_menu_button);
    xy.y += 32.0f;

    if (play_again_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        if (config_game_mode == GAME_MODE_TYPO_SHOOTER) {
            game_state_pending = GAME_STATE_TYPO_GAMEPLAY;
        }
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
    }
    if (highscores_button.activated) {
        highscore_return_game_mode_id = config_game_mode;
        highscore_return_latch = 1;
        highscore_return_quest_stage_major = quest_stage_major;
        highscore_return_quest_stage_minor = quest_stage_minor;
        highscore_return_hardcore_flag = config_hardcore;
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_HIGHSCORES;
    }
    if (main_menu_button.activated) {
        sfx_mute_all(music_track_extra_0);
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_play_exclusive(music_track_crimson_theme_id);
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_MAIN_MENU;
        ui_sign_crimson.focus_disabled = 0;
    }

    ui_cursor_render();
}
