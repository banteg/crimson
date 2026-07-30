#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct play_game_vec2_t {
    float x;
    float y;

    play_game_vec2_t() {}

    play_game_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    play_game_vec2_t operator+(const play_game_vec2_t &other) const
    {
        return play_game_vec2_t(x + other.x, y + other.y);
    }

    play_game_vec2_t &operator+=(const play_game_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct play_game_button_t {
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

    play_game_button_t()
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

    ~play_game_button_t() {}
};

struct play_game_checkbox_t {
    bool checked;
    bool disabled;
    bool hovered;
    unsigned char padding;
    char *label;

    play_game_checkbox_t()
    {
        checked = false;
        disabled = false;
        hovered = false;
        label = 0;
    }

    ~play_game_checkbox_t() {}
};

struct play_game_list_t {
    unsigned char enabled;
    unsigned char padding0[3];
    int open;
    int selected_index;
    char **items;
    int item_count;
    unsigned char hovered;
    unsigned char padding1[3];
    int active_index;

    play_game_list_t()
    {
        enabled = true;
        active_index = 0;
        hovered = false;
        selected_index = 0;
        open = 0;
        item_count = 0;
        items = 0;
    }

    ~play_game_list_t() {}
};

extern "C" {
extern ui_element_t ui_element_slot_11;
extern ui_element_t ui_sign_crimson;
extern int ui_item_texts_texture;
extern int config_player_count;
extern int quest_play_counts[91];
extern int mode_play_survival;
extern int mode_play_rush;
extern int mode_play_typo;
extern unsigned char ui_transition_direction;
extern unsigned char screen_fade_ramp_flag;
extern game_state_id_t game_state_pending;
extern int music_track_crimson_theme_id;
extern int music_track_shortie_monk_id;
extern int music_track_extra_0;

bool ui_button_update(float *xy, ui_button_t *button);
int ui_list_widget_update(float *xy, ui_list_widget_t *list);
bool input_primary_just_pressed(void);
void j_highscore_load_table(void);
void sfx_mute_all(int sfx_id);
void ui_menu_click_back_contextual(void);
}

static __inline int play_game_quest_count(void)
{
    int count = 0;
    int index = 11;
    do {
        count += quest_play_counts[index];
        ++index;
    } while (index < 51);
    return count;
}

extern "C" void play_game_menu_update(void)
{
    static play_game_button_t quests_button;
    quests_button.label = " Quests ";

    static play_game_button_t rush_button;
    rush_button.label = "  Rush  ";

    static play_game_button_t survival_button;
    survival_button.label = "Survival";

    static play_game_button_t typo_button;
    typo_button.label = "Typ'o'Shooter";

    static play_game_checkbox_t hardcore_checkbox;
    hardcore_checkbox.label = "Hardcore";

    static play_game_button_t tutorial_button;

    play_game_vec2_t position =
        *(play_game_vec2_t *)&ui_element_slot_11.pos_x
        + *(play_game_vec2_t *)&ui_element_slot_11.vertices[0].x;
    tutorial_button.label = "Tutorial";
    position = position + play_game_vec2_t(330.0f, 50.0f);
    position.x += ui_element_slot_11.render_offset_x - 64.0f;
    play_game_vec2_t base_position = position;

    grim_interface_ptr->grim_bind_texture(ui_item_texts_texture, 0);
    grim_interface_ptr->grim_set_uv(0.0f, 0.125f, 1.0f, 0.25f);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_draw_quad(
        position.x - 64.0f,
        position.y - 8.0f,
        128.0f,
        32.0f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    bool show_play_counts = false;
    if (grim_interface_ptr->grim_is_key_down(0x3b)) {
        show_play_counts = true;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 132.0f,
            position.y + 16.0f,
            "times played:");
    }

    if (quest_unlock_index < 0x28 || config_player_count > 1) {
        position.y += 32.0f;
        if (quest_play_counts[11] + mode_play_survival + mode_play_rush <= 0
            && config_player_count == 1) {
            ui_button_update(
                (float *)&position, (ui_button_t *)&tutorial_button);
            position.y += 32.0f;
        }

        ui_button_update((float *)&position, (ui_button_t *)&quests_button);
        if (show_play_counts) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 158.0f,
                position.y + 8.0f,
                "%d",
                play_game_quest_count());
        }
        position.y += 32.0f;

        ui_button_update((float *)&position, (ui_button_t *)&rush_button);
        if (show_play_counts) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 158.0f,
                position.y + 8.0f,
                "%d",
                mode_play_rush);
        }
        position.y += 32.0f;

        ui_button_update((float *)&position, (ui_button_t *)&survival_button);
        if (show_play_counts) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 158.0f,
                position.y + 8.0f,
                "%d",
                mode_play_survival);
        }
        position.y += 32.0f;

        if (quest_play_counts[11] + mode_play_survival + mode_play_rush > 0) {
            if (config_player_count == 1) {
                ui_button_update(
                    (float *)&position, (ui_button_t *)&tutorial_button);
            }
            position.y += 32.0f;
        }
    } else {
        position.y += 26.0f;
        if (quest_play_counts[11] + mode_play_survival + mode_play_rush <= 0
            && config_player_count == 1) {
            ui_button_update(
                (float *)&position, (ui_button_t *)&tutorial_button);
            position.y += 28.0f;
        }

        ui_button_update((float *)&position, (ui_button_t *)&quests_button);
        if (show_play_counts) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 158.0f,
                position.y + 8.0f,
                "%d",
                play_game_quest_count());
        }
        position.y += 28.0f;

        ui_button_update((float *)&position, (ui_button_t *)&rush_button);
        if (show_play_counts) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 158.0f,
                position.y + 8.0f,
                "%d",
                mode_play_rush);
        }
        position.y += 28.0f;

        ui_button_update((float *)&position, (ui_button_t *)&survival_button);
        if (show_play_counts) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                position.x + 158.0f,
                position.y + 8.0f,
                "%d",
                mode_play_survival);
        }
        position.y += 28.0f;

        if (game_is_full_version() && config_player_count == 1) {
            ui_button_update((float *)&position, (ui_button_t *)&typo_button);
            if (show_play_counts) {
                grim_interface_ptr->grim_draw_text_small_fmt(
                    position.x + 158.0f,
                    position.y + 8.0f,
                    "%d",
                    mode_play_typo);
            }
            position.y += 28.0f;
        }

        if (quest_play_counts[11] + mode_play_survival + mode_play_rush > 0) {
            ui_button_update(
                (float *)&position, (ui_button_t *)&tutorial_button);
            position.y += 28.0f;
        }
    }

    char *player_count_labels[4] = {
        "1 player", "2 players", "3 players", "4 players"
    };
    static play_game_list_t player_count_list;
    player_count_list.items = player_count_labels;
    player_count_list.selected_index = config_player_count - 1;
    player_count_list.item_count = 2;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.81f);
    play_game_vec2_t list_position =
        base_position + play_game_vec2_t(80.0f, 1.0f);
    int selected = ui_list_widget_update(
        (float *)&list_position, (ui_list_widget_t *)&player_count_list);
    if (selected > -2
        && (input_primary_just_pressed()
            || grim_interface_ptr->grim_was_key_pressed(0x1c))) {
        player_count_list.open = 1 - player_count_list.open;
        if (selected >= 0) {
            player_count_list.selected_index = selected;
            config_player_count = selected + 1;
            j_highscore_load_table();
        }
    }

    if (player_count_list.open) {
        survival_button.enabled = false;
        rush_button.enabled = false;
        quests_button.enabled = false;
    } else {
        survival_button.enabled = true;
        rush_button.enabled = true;
        quests_button.enabled = true;
    }

    position.x -= 55.0f;
    position.y += 16.0f;
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    if (quests_button.hover_anim > 0) {
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            (float)quests_button.hover_anim * 0.0009f);
        grim_interface_ptr->grim_draw_text_small(
            position.x - 8.0f,
            position.y,
            "Unlock new weapons and perks in Quest mode.");
    }
    if (rush_button.hover_anim > 0) {
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            (float)rush_button.hover_anim * 0.0009f);
        grim_interface_ptr->grim_draw_text_small(
            position.x + 32.0f,
            position.y,
            "Face a rush of aliens in Rush mode.");
    }
    if (survival_button.hover_anim > 0) {
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            (float)survival_button.hover_anim * 0.0009f);
        grim_interface_ptr->grim_draw_text_small(
            position.x + 20.0f,
            position.y,
            "Gain perks and weapons and fight back.");
    }
    if (typo_button.hover_anim > 0) {
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            (float)typo_button.hover_anim * 0.0009f);
        grim_interface_ptr->grim_draw_text_small(
            position.x,
            position.y - 12.0f,
            "Use your typing skills as the weapon to lay\nthem down.");
    }
    if (tutorial_button.hover_anim > 0) {
        grim_interface_ptr->grim_set_color(
            1.0f,
            1.0f,
            1.0f,
            (float)tutorial_button.hover_anim * 0.0009f);
        grim_interface_ptr->grim_draw_text_small(
            position.x + 38.0f,
            position.y,
            "Learn how to play Crimsonland.");
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
    if (quests_button.activated) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_QUEST_SELECT;
    }
    if (rush_button.activated) {
        ui_sign_crimson.focus_disabled = 0;
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        config_game_mode = GAME_MODE_RUSH;
        screen_fade_ramp_flag = 1;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
    }
    if (survival_button.activated) {
        ui_sign_crimson.focus_disabled = 0;
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        config_game_mode = GAME_MODE_SURVIVAL;
        screen_fade_ramp_flag = 1;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
    }
    if (tutorial_button.activated) {
        ui_sign_crimson.focus_disabled = 0;
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        config_game_mode = GAME_MODE_TUTORIAL;
        screen_fade_ramp_flag = 1;
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
    }

    if (grim_interface_ptr->grim_was_key_pressed(1)) {
        ui_menu_click_back_contextual();
    }
}
