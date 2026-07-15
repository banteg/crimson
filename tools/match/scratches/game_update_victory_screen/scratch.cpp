#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct victory_vec2_t {
    float x;
    float y;

    victory_vec2_t() {}

    victory_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    victory_vec2_t operator+(const victory_vec2_t &other) const
    {
        return victory_vec2_t(x + other.x, other.y + y);
    }

    victory_vec2_t &operator+=(const victory_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct victory_button_t {
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

    victory_button_t()
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

    ~victory_button_t() {}
};

extern "C" {
extern game_state_id_t game_state_pending;
extern unsigned char ui_transition_direction;
extern unsigned char screen_fade_ramp_flag;
extern int ui_screen_phase;
extern ui_element_t ui_element_slot_35;
extern ui_element_t ui_sign_crimson;
extern int music_track_shortie_monk_id;
extern int music_track_crimson_theme_id;
extern int music_track_extra_0;

bool ui_button_update(float *xy, ui_button_t *button);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
}

extern "C" void game_update_victory_screen(void)
{
    gameplay_render_world();
    ui_elements_update_and_render();

    victory_vec2_t panel_position =
        *(victory_vec2_t *)&ui_element_slot_35.pos_x
        + *(victory_vec2_t *)&ui_element_slot_35.vertices[0].x
        + victory_vec2_t(180.0f, 40.0f);

    victory_vec2_t text_position = panel_position;
    text_position.x =
        ui_element_slot_35.render_offset_x
        + text_position.x
        + 44.0f
        - 10.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    text_position.y += 6.0f;

    if (ui_screen_phase == -1) {
        ui_screen_phase = 0;
    }

    grim_interface_ptr->grim_set_config_var(0x18, 0.8f);
    if (!config_hardcore) {
        grim_interface_ptr->grim_draw_text_mono_fmt(
            text_position.x, text_position.y, "Congratulations!");
    } else {
        grim_interface_ptr->grim_draw_text_mono_fmt(
            text_position.x, text_position.y, "   Incredible!");
    }

    text_position.y += 32.0f;
    text_position.x -= 8.0f;
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    if (!config_hardcore) {
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "You've completed all the levels but the battle");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "isn't over yet! With all of the unlocked perks");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "and weapons your Survival is just a bit easier.");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "You can also replay the quests in Hardcore.");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "As an additional reward for your victorious");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "playing, a completely new and different game");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "mode is unlocked for you: Typ'o'Shooter.");
    } else {
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "You've done the thing we all thought was");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "virtually impossible. To reward your");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x,
            text_position.y,
            "efforts a new weapon has been unlocked ");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x, text_position.y, "for you: Splitter Gun.");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x, text_position.y, "");
        text_position.y += 14.0f;
        grim_interface_ptr->grim_draw_text_small_fmt(
            text_position.x, text_position.y, "");
    }

    text_position.y += 14.0f;
    text_position.y += 8.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        text_position.x,
        text_position.y,
        "Good luck with your battles, trooper!");

    victory_vec2_t button_panel_position =
        *(victory_vec2_t *)&ui_element_slot_35.pos_x
        + *(victory_vec2_t *)&ui_element_slot_35.vertices[0].x
        + victory_vec2_t(180.0f, 40.0f);
    text_position = button_panel_position;
    text_position.x += ui_element_slot_35.render_offset_x;
    text_position.x += 44.0f;
    text_position.x += 20.0f;
    text_position.y += 170.0f;

    static victory_button_t survival_button;
    survival_button.label = "Survival";

    static victory_button_t rush_button;
    rush_button.label = "  Rush  ";

    static victory_button_t typo_button;
    typo_button.label = "Typ'o'Shooter";

    static victory_button_t main_menu_button;
    main_menu_button.label = "Main Menu";

    text_position.x = text_position.x - 4.0f + 26.0f;
    ui_button_update((float *)&text_position, (ui_button_t *)&survival_button);
    text_position.y += 32.0f;
    ui_button_update((float *)&text_position, (ui_button_t *)&rush_button);
    text_position.y += 32.0f;
    ui_button_update((float *)&text_position, (ui_button_t *)&typo_button);
    text_position.y += 32.0f;
    ui_button_update((float *)&text_position, (ui_button_t *)&main_menu_button);
    text_position.y += 32.0f;

    if (rush_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
        config_game_mode = GAME_MODE_RUSH;
    }

    if (survival_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        config_game_mode = GAME_MODE_SURVIVAL;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
    }

    if (typo_button.activated) {
        render_pass_mode = 0;
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_TYPO_GAMEPLAY;
        config_game_mode = GAME_MODE_TYPO_SHOOTER;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
        screen_fade_ramp_flag = 1;
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
