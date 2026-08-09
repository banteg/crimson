#include <process.h>
#include <stddef.h>
#include <string.h>
#include <windows.h>

#include "crimsonland_gameplay.h"
#include "crimsonland_ui.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

#define HIGHSCORE_RECORD_FROM_FLAGS(record_flags) \
    ((highscore_record_t *)((record_flags) - offsetof(highscore_record_t, flags)))

struct highscore_vec2_t {
    float x;
    float y;

    highscore_vec2_t() {}
    highscore_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    highscore_vec2_t operator+(const highscore_vec2_t &other) const
    {
        return highscore_vec2_t(x + other.x, y + other.y);
    }

    highscore_vec2_t &operator+=(const highscore_vec2_t &other)
    {
        x += other.x;
        y += other.y;
        return *this;
    }
};

struct highscore_color_t {
    float r;
    float g;
    float b;
    float a;

    highscore_color_t() {}

    highscore_color_t(float red, float green, float blue, float alpha)
        : r(red), g(green), b(blue), a(alpha) {}
};

struct highscore_checkbox_t {
    unsigned char checked;
    unsigned char disabled;
    unsigned char hovered;
    char *label;

    highscore_checkbox_t()
    {
        checked = false;
        disabled = false;
        hovered = false;
        label = 0;
    }

    ~highscore_checkbox_t() {}
};

struct highscore_list_widget_t {
    unsigned char enabled;
    int open;
    int selected_index;
    char **items;
    int item_count;
    unsigned char hovered;
    int active_index;

    highscore_list_widget_t()
    {
        enabled = true;
        active_index = 0;
        hovered = false;
        selected_index = 0;
        open = 0;
        item_count = 0;
        items = 0;
    }

    ~highscore_list_widget_t() {}
};

struct highscore_scrollbar_t {
    float scroll_offset;
    int hovered_index;
    int selected_index;
    int visible_rows;
    int column_offsets[8];
    char **items;
    int item_count;

    highscore_scrollbar_t()
    {
        int *column = column_offsets;
        int *end = column_offsets + 2;
        while (column != end) {
            *column++ = 0;
        }
    }

    ~highscore_scrollbar_t() {}
};

struct highscore_button_t {
    char *label;
    unsigned char hovered;
    unsigned char activated;
    unsigned char enabled;
    int hover_anim;
    int click_anim;
    float alpha;
    unsigned char force_small;
    unsigned char force_wide;

    highscore_button_t()
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

    ~highscore_button_t() {}
};

extern "C" {
extern ui_element_t ui_element_slot_09;
extern ui_element_t ui_element_slot_33;
extern ui_element_t ui_sign_crimson;
extern int ui_hud_arrow_texture;
extern game_status_t game_status_blob;

extern unsigned char ui_transition_direction;
extern unsigned char screen_fade_ramp_flag;
extern unsigned char render_pass_mode;
extern game_state_id_t game_state_pending;
extern unsigned char player_overlay_suppressed_latch;

extern int music_track_crimson_theme_id;
extern int music_track_shortie_monk_id;
extern int music_track_extra_0;

extern int online_sync_status;
extern unsigned char highscore_batch_sync_mode;
extern int highscore_batch_sync_stage_index;
extern int highscore_screen_action_id;
extern unsigned char highscore_post_sync_update_check_latch;

extern unsigned char highscore_return_latch;
extern int highscore_return_quest_stage_major;
extern int highscore_return_quest_stage_minor;
extern game_mode_id_t highscore_return_game_mode_id;
extern unsigned char highscore_return_hardcore_flag;

extern char *update_notice_url;
extern unsigned char update_notice_pending;
extern unsigned char update_notice_open_requested;
extern unsigned char ui_profile_menu_enabled;
extern char menu_label_back[];

char *game_mode_label(void);
int crt_sprintf(char *dst, const char *format, ...);
void highscore_load_table_thunk(void);
unsigned char game_is_full_version(void);
bool input_primary_just_pressed(void);
bool ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);
void ui_scrollbar_update(float *xy, float *state);
bool ui_button_update(float *xy, ui_button_t *button);
bool ui_profile_menu_update(float *xy, char enabled);
int ui_list_widget_update(float *xy, ui_list_widget_t *list);
void ui_text_input_render(
    float *xy, highscore_record_t *record, float alpha, int rank);
void ui_update_notice_update(float *xy, float alpha);
void sfx_mute_all(int sfx_id);
void highscore_sync_worker(void *);
void statistics_update_check_worker(void *);
void crt_beginthread(void (*function)(void *), unsigned int stack_size, void *arg);
}

extern "C" void highscore_screen_update(void)
{
    highscore_color_t quest_color;
    if (config_blob.hardcore) {
        quest_color = highscore_color_t(
            0.980392158f,
            0.274509817f,
            0.235294119f,
            0.7f);
    } else {
        quest_color = highscore_color_t(
            0.274509817f,
            0.70588237f,
            0.941176474f,
            0.7f);
    }

    unsigned char arrow_hovered = 0;
    highscore_vec2_t left_panel =
        *(highscore_vec2_t *)&ui_element_slot_09.pos_x
        + *(highscore_vec2_t *)&ui_element_slot_09.vertices[0].x
        + highscore_vec2_t(300.0f, 40.0f);

    highscore_vec2_t position = left_panel;
    position.x =
        position.x + ui_element_slot_09.render_offset_x + 44.0f - 110.0f;
    position.y += 1.0f;
    position.x -= 32.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    static char title_buffer[128];
    crt_sprintf(title_buffer, "High scores - %s", game_mode_label());
    int title_width = grim_interface_ptr->grim_measure_text_width(title_buffer);
    int title_half_width = title_width / 2;
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x - (float)title_half_width + 128.0f,
        position.y,
        title_buffer);

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
    {
        highscore_vec2_t separator(
            position.x + (float)(128 - title_half_width),
            position.y + 14.0f);
        grim_interface_ptr->grim_draw_rect_outline(
            (float *)&separator, (float)title_width, 1.0f);
    }
    position.y += 15.0f;

    if (config_blob.game_mode == GAME_MODE_QUEST) {
        position.x -= 8.0f;
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.800000012f);
        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
        position.y += 6.0f;

        if (config_blob.hardcore) {
            int quest_index =
                quest_stage_minor + quest_stage_major * 10 - 11;
            if (quest_index > quest_unlock_index_full) {
                quest_stage_major = quest_unlock_index_full / 10 + 1;
                quest_stage_minor = quest_unlock_index_full % 10 + 1;
                highscore_load_table_thunk();
            }
        } else {
            int quest_index =
                quest_stage_minor + quest_stage_major * 10 - 11;
            if (quest_index > quest_unlock_index) {
                quest_stage_major = quest_unlock_index / 10 + 1;
                quest_stage_minor = quest_unlock_index % 10 + 1;
                highscore_load_table_thunk();
            }
        }

        grim_interface_ptr->grim_set_color_ptr((float *)&quest_color);
        int quest_index =
            quest_stage_minor + quest_stage_major * 10 - 11;
        grim_interface_ptr->grim_draw_text_small_fmt(
            position.x + 42.0f,
            position.y + 1.0f,
            "%d.%d: %s",
            quest_stage_major,
            quest_stage_minor,
            quest_selected_meta[quest_index].name);
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.800000012f);

        if (ui_mouse_x > position.x
            && ui_mouse_y > position.y - 2.0f
            && ui_mouse_x < position.x + 32.0f
            && ui_mouse_y < position.y + 18.0f
            && !ui_mouse_blocked) {
            highscore_screen_action_id = -3;
            arrow_hovered = true;
            grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        } else {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.560000002f);
        }

        grim_interface_ptr->grim_bind_texture(ui_hud_arrow_texture, 0);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        if (quest_stage_major != 1 || quest_stage_minor != 1) {
            grim_interface_ptr->grim_draw_quad(
                position.x, position.y, 32.0f, 16.0f);
        }

        position.x += 255.0f;
        if (ui_mouse_x > position.x
            && ui_mouse_y > position.y - 2.0f
            && ui_mouse_x < position.x + 32.0f
            && ui_mouse_y < position.y + 18.0f
            && !ui_mouse_blocked) {
            highscore_screen_action_id = -2;
            arrow_hovered = true;
            grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        } else {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.50999999f);
        }
        grim_interface_ptr->grim_set_uv(1.0f, 0.0f, 0.0f, 1.0f);
        if (quest_stage_major != 5 || quest_stage_minor != 10) {
            grim_interface_ptr->grim_draw_quad(
                position.x, position.y, 32.0f, 16.0f);
        }
        grim_interface_ptr->grim_end_batch();
        position.x -= 255.0f;
        position.y += 14.0f;
        position.x += 8.0f;
    } else {
        position.y += 20.0f;
    }
    position.y += 8.0f;

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x + 9.0f, position.y, "Rank");
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x + 44.0f, position.y, "Score");
    grim_interface_ptr->grim_draw_text_small_fmt(
        position.x + 100.0f, position.y, "Player");

    if (config_blob.game_mode == GAME_MODE_QUEST) {
        static highscore_checkbox_t hardcore_checkbox;
        hardcore_checkbox.label = "Hardcore";
        if (quest_unlock_index >= 40) {
            highscore_vec2_t checkbox_position(
                position.x + 162.0f, position.y - 2.0f);
            hardcore_checkbox.checked = config_blob.hardcore;
            ui_checkbox_update(
                (float *)&checkbox_position,
                (ui_checkbox_t *)&hardcore_checkbox);
            if (config_blob.hardcore != hardcore_checkbox.checked) {
                config_blob.hardcore = hardcore_checkbox.checked;
                highscore_load_table_thunk();
            }
        } else {
            config_blob.hardcore = 0;
        }
        if (!game_is_full_version()) {
            config_blob.hardcore = 0;
        }
    }

    static char score_line_buffers[100][164];
    static char *score_line_items[100];
    int score_number = 1;
    int selected_score = -1;
    int score_count = 0;
    char **score_line_item = score_line_items;
    position.y += 16.0f;
    position.y += 1.0f;
    unsigned char *record_flags = &highscore_table[0].flags;
    char (*score_line_buffer)[164] = score_line_buffers;
    do {
        *score_line_item = *score_line_buffer;
        memset(*score_line_item, 0, sizeof(*score_line_buffer));
        if (HIGHSCORE_RECORD_FROM_FLAGS(record_flags)->survival_elapsed_ms == 0) {
            break;
        }

        int prefix_length = 0;
        if ((*record_flags & 5) != 0
            && ((*record_flags & 2) == 0 || (*record_flags & 4) != 0)) {
            (*score_line_item)[0] = '\\';
            (*score_line_item)[1] = 'g';
            prefix_length = 2;
        }

        switch (config_blob.game_mode) {
        case GAME_MODE_RUSH:
            crt_sprintf(
                *score_line_item + prefix_length,
                "%d\t%d\t%s",
                score_number,
                (int)HIGHSCORE_RECORD_FROM_FLAGS(record_flags)
                    ->survival_elapsed_ms / 1000,
                HIGHSCORE_RECORD_FROM_FLAGS(record_flags)->player_name);
            break;
        case GAME_MODE_QUEST:
            crt_sprintf(
                *score_line_item + prefix_length,
                "%d\t%d\t%s",
                score_number,
                (int)HIGHSCORE_RECORD_FROM_FLAGS(record_flags)
                    ->survival_elapsed_ms / 1000,
                HIGHSCORE_RECORD_FROM_FLAGS(record_flags)->player_name);
            break;
        default:
            crt_sprintf(
                *score_line_item + prefix_length,
                "%d\t%d\t%s",
                score_number,
                HIGHSCORE_RECORD_FROM_FLAGS(record_flags)->score_xp,
                HIGHSCORE_RECORD_FROM_FLAGS(record_flags)->player_name);
            break;
        }
        ++score_count;
        ++score_line_buffer;
        record_flags += sizeof(highscore_record_t);
        ++score_number;
        ++score_line_item;
    } while (score_line_buffer < score_line_buffers + 100);

    position.x += 16.0f;
    static highscore_scrollbar_t score_scrollbar;
    score_scrollbar.item_count = score_count;
    {
        highscore_vec2_t scrollbar_position(position.x - 8.0f, position.y);
        score_scrollbar.items = score_line_items;
        score_scrollbar.visible_rows = 10;
        score_scrollbar.column_offsets[0] = 10;
        score_scrollbar.column_offsets[1] = 30;
        score_scrollbar.column_offsets[2] = 44;
        ui_scrollbar_update(
            (float *)&scrollbar_position, (float *)&score_scrollbar);
    }
    position.y += 168.0f;
    int hovered_score = score_scrollbar.hovered_index;
    if (hovered_score != -1) {
        selected_score = hovered_score;
    }

    position.x += 16.0f;
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
    position.y -= 1.0f;

    static highscore_button_t update_button;
    if (game_is_full_version()) {
        if (grim_interface_ptr->grim_is_key_down(42)
            || grim_interface_ptr->grim_is_key_down(54)) {
            update_button.label = "Update all";
        } else {
            update_button.label = "Update scores";
        }
    } else {
        if (grim_interface_ptr->grim_is_key_down(42)
            || grim_interface_ptr->grim_is_key_down(54)) {
            update_button.label = "Receive all";
        } else {
            update_button.label = "Receive scores";
        }
    }

    if (ui_button_update((float *)&position, (ui_button_t *)&update_button)
        && (online_sync_status == 0 || online_sync_status == 6)) {
        if (grim_interface_ptr->grim_is_key_down(42)
            || grim_interface_ptr->grim_is_key_down(54)) {
            highscore_batch_sync_stage_index = -4;
            highscore_batch_sync_mode = 1;
        } else {
            highscore_batch_sync_mode = 0;
        }
        online_sync_status = 1;
        crt_beginthread(highscore_sync_worker, 0, 0);
    }

    position.y += 33.0f;
    static highscore_button_t play_button;
    play_button.label = "Play a game";
    play_button.enabled =
        online_sync_status == 6 || online_sync_status == 0;
    if (ui_button_update((float *)&position, (ui_button_t *)&play_button)) {
        if (config_blob.game_mode == GAME_MODE_QUEST) {
            const int &quest_unlock_limit = config_blob.hardcore
                ? quest_unlock_index_full
                : quest_unlock_index;
            int quest_index =
                quest_stage_minor + quest_stage_major * 10 - 11;
            if (quest_unlock_limit < quest_index) {
                goto play_game_done;
            }
            render_pass_mode = 0;
            ui_sign_crimson.focus_disabled = 0;
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_GAMEPLAY;
        } else {
            render_pass_mode = 0;
            ui_sign_crimson.focus_disabled = 0;
            ui_transition_direction = 0;
            game_state_pending = config_blob.game_mode == GAME_MODE_TYPO_SHOOTER
                ? GAME_STATE_TYPO_GAMEPLAY
                : GAME_STATE_GAMEPLAY;
        }
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_mute_all(music_track_extra_0);
        screen_fade_ramp_flag = 1;
play_game_done:
        ;
    }

    left_panel.x = position.x - 32.0f;
    left_panel.y = position.y + 32.0f;
    static highscore_button_t back_button;
    back_button.label = menu_label_back;
    back_button.enabled =
        online_sync_status == 6 || online_sync_status == 0;
    {
        highscore_vec2_t back_position(position.x + 166.0f, position.y);
        if (ui_button_update(
                (float *)&back_position, (ui_button_t *)&back_button)) {
            if (highscore_return_latch) {
                bonus_entry_t *bonus = bonus_pool;
                do {
                    bonus->bonus_id = BONUS_ID_NONE;
                    ++bonus;
                } while (bonus < bonus_pool + 16);
                projectile_t *projectile = projectile_pool;
                do {
                    projectile->active = 0;
                    ++projectile;
                } while (projectile < projectile_pool + 0x60);
                sprite_effect_t *sprite = sprite_effect_pool;
                do {
                    sprite->active = 0;
                    ++sprite;
                } while (sprite < sprite_effect_pool + 0x180);
                secondary_projectile_t *secondary = secondary_projectile_pool;
                do {
                    secondary->active = 0;
                    ++secondary;
                } while (secondary < secondary_projectile_pool + 0x40);
                creature_t *creature = creature_pool;
                do {
                    creature->active = 0;
                    ++creature;
                } while (creature < creature_pool + 384);
                quest_stage_minor = highscore_return_quest_stage_minor;
                quest_stage_major = highscore_return_quest_stage_major;
                player_overlay_suppressed_latch = 1;
                config_blob.game_mode = highscore_return_game_mode_id;
                config_blob.hardcore = highscore_return_hardcore_flag;
                ui_transition_direction = 0;
                game_state_pending =
                    highscore_return_game_mode_id == GAME_MODE_QUEST
                    ? GAME_STATE_QUEST_RESULTS
                    : GAME_STATE_GAME_OVER;
            } else {
                ui_transition_direction = 0;
                game_state_pending = GAME_STATE_STATISTICS_MENU;
            }
        }
    }

    highscore_vec2_t right_panel =
        *(highscore_vec2_t *)&ui_element_slot_33.pos_x
        + *(highscore_vec2_t *)&ui_element_slot_33.vertices[0].x;
    right_panel += highscore_vec2_t(300.0f, 40.0f);
    position.x =
        ui_element_slot_33.render_offset_x - 16.0f + right_panel.x - 224.0f;
    position.y = right_panel.y + 10.0f;
    highscore_vec2_t notice_position(
        position.x + 32.0f, position.y + 364.0f);
    right_panel.x = position.x - 16.0f;
    right_panel.y = position.y - 8.0f;
    if (config_blob.screen_width <= 640) {
        right_panel.x += 10.0f;
        position.x -= 8.0f;
    }
    position.x -= 10.0f;

    if ((online_sync_status == 6 || online_sync_status == 0)
        && selected_score == -1) {
        right_panel.y += 2.0f;
        {
            static highscore_checkbox_t online_scores_checkbox;
            highscore_vec2_t widget_position(right_panel.x, right_panel.y);
            online_scores_checkbox.label = "Show internet scores";
            online_scores_checkbox.checked = config_blob.show_online_scores;
            if (ui_checkbox_update(
                    (float *)&widget_position,
                    (ui_checkbox_t *)&online_scores_checkbox)) {
                config_blob.show_online_scores = online_scores_checkbox.checked;
                highscore_load_table_thunk();
            }
        }

        char *date_items[5] = {
            "Best of all time",
            "Best of month",
            "Best of week",
            "Best of day",
            0,
        };
        right_panel.y += 6.0f;
        static highscore_list_widget_t date_filter_list;
        date_filter_list.item_count = 4;
        date_filter_list.items = date_items;

        if (game_is_full_version()) {
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.800000012f);
            grim_interface_ptr->grim_draw_text_small(
                right_panel.x,
                right_panel.y + 100.0f,
                "Selected score list:");
            highscore_vec2_t profile_position(
                right_panel.x, right_panel.y + 114.0f);
            ui_profile_menu_update(
                (float *)&profile_position, ui_profile_menu_enabled);
        }

        date_filter_list.selected_index = config_blob.highscore_date_mode;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.800000012f);
        float option_label_y = right_panel.y + 28.0f - 14.0f;
        grim_interface_ptr->grim_draw_text_small(
            right_panel.x + 2.0f,
            option_label_y,
            "Number of players");
        grim_interface_ptr->grim_draw_text_small(
            right_panel.x + 130.0f,
            option_label_y,
            "Game mode");
        grim_interface_ptr->grim_draw_text_small(
            right_panel.x,
            right_panel.y + 56.0f,
            "Show scores:");

        int selected;
        {
            highscore_vec2_t date_position(
                right_panel.x, right_panel.y + 70.0f);
            selected = ui_list_widget_update(
                (float *)&date_position,
                (ui_list_widget_t *)&date_filter_list);
            if ((online_sync_status == 6 || online_sync_status == 0)
                && selected > -2
                && (input_primary_just_pressed()
                    || grim_interface_ptr->grim_was_key_pressed(28))) {
                date_filter_list.open = 1 - date_filter_list.open;
                if (selected >= 0) {
                    date_filter_list.selected_index = selected;
                    if (selected == 0) {
                        config_blob.highscore_date_mode = 0;
                    } else if (selected == 1) {
                        config_blob.highscore_date_mode = 1;
                    } else if (selected == 2) {
                        config_blob.highscore_date_mode = 2;
                    } else if (selected == 3) {
                        config_blob.highscore_date_mode = 3;
                    }
                    highscore_load_table_thunk();
                }
            }
        }

        static highscore_list_widget_t player_count_list;
        {
            char *player_count_items[2] = {
                "1 player",
                "2 players",
            };
            player_count_list.items = player_count_items;
            player_count_list.item_count = 2;
            player_count_list.selected_index = config_blob.player_count - 1;
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, 0.810000002f);
            highscore_vec2_t player_count_position(
                right_panel.x + 2.0f, right_panel.y + 28.0f);
            selected = ui_list_widget_update(
                (float *)&player_count_position,
                (ui_list_widget_t *)&player_count_list);
            if ((online_sync_status == 6 || online_sync_status == 0)
                && selected > -2
                && (input_primary_just_pressed()
                    || grim_interface_ptr->grim_was_key_pressed(28))) {
                player_count_list.open = 1 - player_count_list.open;
                if (selected >= 0) {
                    player_count_list.selected_index = selected;
                    config_blob.player_count = selected + 1;
                    highscore_load_table_thunk();
                }
            }
        }

        char *game_mode_items[5] = {
            "Quests",
            "Rush",
            "Survival",
            "Typ'o'Shooter",
            0,
        };
        static highscore_list_widget_t game_mode_list;
        game_mode_list.items = game_mode_items;
        game_mode_list.item_count = 3;
        if (quest_unlock_index >= 40) {
            game_mode_list.item_count = 4;
        }
        game_mode_list.enabled = true;
        date_filter_list.enabled = true;
        ui_profile_menu_enabled = 1;
        if (game_mode_list.open) {
            ui_profile_menu_enabled = 0;
            date_filter_list.enabled = false;
        }
        if (player_count_list.open) {
            ui_profile_menu_enabled = 0;
            date_filter_list.enabled = false;
            game_mode_list.enabled = false;
        }
        if (date_filter_list.open) {
            ui_profile_menu_enabled = 0;
            game_mode_list.enabled = false;
        }
        player_count_list.enabled = true;
        if (config_blob.game_mode == GAME_MODE_SURVIVAL) {
            game_mode_list.selected_index = 2;
        } else if (config_blob.game_mode == GAME_MODE_RUSH) {
            game_mode_list.selected_index = 1;
        } else if (config_blob.game_mode == GAME_MODE_QUEST) {
            game_mode_list.selected_index = 0;
        } else if (config_blob.game_mode == GAME_MODE_TYPO_SHOOTER) {
            game_mode_list.selected_index = 3;
            player_count_list.enabled = false;
            player_count_list.selected_index = 0;
            config_blob.player_count = 1;
        }

        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.810000002f);
        highscore_vec2_t game_mode_position(
            right_panel.x + 130.0f, right_panel.y + 28.0f);
        selected = ui_list_widget_update(
            (float *)&game_mode_position,
            (ui_list_widget_t *)&game_mode_list);
        if ((online_sync_status == 6 || online_sync_status == 0)
            && selected > -2
            && (input_primary_just_pressed()
                || grim_interface_ptr->grim_was_key_pressed(28))) {
            game_mode_list.open = 1 - game_mode_list.open;
            if (selected >= 0) {
                game_mode_list.selected_index = selected;
                if (selected == 0) {
                    config_blob.game_mode = GAME_MODE_QUEST;
                } else if (selected == 1) {
                    config_blob.game_mode = GAME_MODE_RUSH;
                } else if (selected == 2) {
                    config_blob.game_mode = GAME_MODE_SURVIVAL;
                } else if (selected == 3) {
                    config_blob.game_mode = GAME_MODE_TYPO_SHOOTER;
                    config_blob.player_count = 1;
                }
                highscore_load_table_thunk();
            }
        }
    }

    position.y += 44.0f;
    if (config_blob.screen_width <= 640) {
        position.x += 20.0f;
    }
    float tooltip_x = left_panel.x;
    float tooltip_y = left_panel.y;

    if (online_sync_status != 0) {
        grim_interface_ptr->grim_set_color(
            0.5f, 1.0f, 0.600000024f, 1.0f);
        if (online_sync_status == 1) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                tooltip_x, tooltip_y, "Connecting...");
            Sleep(10);
        } else if (online_sync_status == 2) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                tooltip_x, tooltip_y, "Connected...");
            Sleep(10);
        } else if (online_sync_status == 3) {
            if (game_is_full_version()) {
                grim_interface_ptr->grim_draw_text_small_fmt(
                    tooltip_x, tooltip_y, "Sending local scores...");
            } else {
                grim_interface_ptr->grim_draw_text_small_fmt(
                    tooltip_x, tooltip_y, "Connected....");
            }
            Sleep(10);
        } else if (online_sync_status == 4) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                tooltip_x, tooltip_y, "Receiving internet scores...");
            Sleep(10);
        } else if (online_sync_status == 5) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                tooltip_x, tooltip_y, "Done...");
            if (!highscore_post_sync_update_check_latch) {
                online_sync_status = 1;
                crt_beginthread(statistics_update_check_worker, 0, 0);
                highscore_post_sync_update_check_latch = 1;
            }
            Sleep(10);
        } else if (online_sync_status == 6) {
            grim_interface_ptr->grim_set_color(1.0f, 0.5f, 0.5f, 1.0f);
            grim_interface_ptr->grim_draw_text_small_fmt(
                tooltip_x,
                tooltip_y,
                "Failed to update scores. Try again later.");
            highscore_batch_sync_mode = 0;
            Sleep(10);
        } else {
            Sleep(10);
        }
    } else {
        if (grim_interface_ptr->grim_is_key_down(1)) {
            highscore_batch_sync_mode = 0;
        } else if (highscore_batch_sync_mode) {
            unsigned char hardcore;
            if (config_blob.game_mode != GAME_MODE_QUEST) {
                hardcore = 0;
                config_blob.hardcore = 0;
            } else {
                hardcore = config_blob.hardcore;
            }
            static unsigned char batch_hardcore;
            batch_hardcore = hardcore;
            int stage = ++highscore_batch_sync_stage_index;
            if (hardcore && stage < 0) {
                stage = 0;
                highscore_batch_sync_stage_index = 0;
            } else {
                if (stage == -3) {
                    config_blob.game_mode = GAME_MODE_SURVIVAL;
                } else if (stage == -2) {
                    config_blob.game_mode = GAME_MODE_RUSH;
                } else if (stage == -1) {
                    if (config_blob.player_count > 1) {
                        stage = 0;
                        highscore_batch_sync_stage_index = 0;
                    }
                    config_blob.game_mode = GAME_MODE_TYPO_SHOOTER;
                }
            }

            if (stage >= 0) {
                if ((!hardcore
                        && game_status_blob.quest_unlock_index < stage)
                    || (hardcore
                        && game_status_blob.quest_unlock_index_full < stage)
                    || stage / 10 + 1 >= 5) {
                    highscore_batch_sync_mode = 0;
                } else {
                    quest_stage_major = stage / 10 + 1;
                    config_blob.game_mode = GAME_MODE_QUEST;
                    quest_stage_minor = stage % 10 + 1;
                }
            }
            if (highscore_batch_sync_mode) {
                Sleep(50);
                online_sync_status = 1;
                crt_beginthread(highscore_sync_worker, 0, 0);
            }
        }
    }

    if (selected_score == -1) {
        grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
        if (online_sync_status == 0) {
            if (update_button.hover_anim > 0) {
                grim_interface_ptr->grim_set_color(
                    1.0f,
                    1.0f,
                    1.0f,
                    (float)update_button.hover_anim * 0.000900000043f);
                if (game_is_full_version()) {
                    if (grim_interface_ptr->grim_is_key_down(42)
                        || grim_interface_ptr->grim_is_key_down(54)) {
                        grim_interface_ptr->grim_draw_text_small_fmt(
                            tooltip_x,
                            tooltip_y,
                            "Update scores from the Internet");
                    }
                } else {
                    grim_interface_ptr->grim_draw_text_small_fmt(
                        tooltip_x - 4.0f,
                        tooltip_y,
                        "Only receive scores from the Internet. (Demo)");
                }
            }
            if (play_button.hover_anim > 0) {
                grim_interface_ptr->grim_set_color(
                    1.0f,
                    1.0f,
                    1.0f,
                    (float)play_button.hover_anim * 0.000900000043f);
                grim_interface_ptr->grim_draw_text_small_fmt(
                    tooltip_x,
                    tooltip_y,
                    "Play a game of selected game mode");
            }
        }
    } else {
        highscore_vec2_t saved_position = position;
        grim_interface_ptr->grim_set_config_var(0x18, 0.430000007f);
        position.y -= 54.0f;
        highscore_vec2_t detail_position(
            position.x + 24.0f, position.y + 4.0f);
        ui_text_input_render(
            (float *)&detail_position,
            &highscore_table[selected_score],
            1.0f,
            selected_score + 1);
        position = saved_position;
    }

    if ((online_sync_status == 6 || online_sync_status == 0)
        && grim_interface_ptr->grim_was_key_pressed(203)) {
        --quest_stage_minor;
        if (quest_stage_minor <= 0) {
            if (quest_stage_major >= 2) {
                --quest_stage_major;
                quest_stage_minor = 10;
            } else {
                quest_stage_minor = 1;
            }
        }
        if (config_blob.hardcore) {
            if (quest_stage_minor + 10 * quest_stage_major - 11
                > quest_unlock_index_full) {
                quest_stage_major = quest_unlock_index_full / 10 + 1;
                quest_stage_minor = quest_unlock_index_full % 10 + 1;
                highscore_load_table_thunk();
            }
        } else if (quest_stage_minor + 10 * quest_stage_major - 11
                   > quest_unlock_index) {
            quest_stage_major = quest_unlock_index / 10 + 1;
            quest_stage_minor = quest_unlock_index % 10 + 1;
        }
        highscore_load_table_thunk();
    }

    if ((online_sync_status == 6 || online_sync_status == 0)
        && grim_interface_ptr->grim_was_key_pressed(205)) {
        if (quest_stage_minor + 10 * quest_stage_major - 11
            < quest_unlock_index) {
            ++quest_stage_minor;
        }
        if (quest_stage_minor > 10) {
            if (quest_stage_major < 5) {
                ++quest_stage_major;
                quest_stage_minor = 1;
            } else {
                quest_stage_minor = 10;
            }
        }
        if (config_blob.hardcore) {
            if (quest_stage_minor + 10 * quest_stage_major - 11
                > quest_unlock_index_full) {
                quest_stage_major = quest_unlock_index_full / 10 + 1;
                quest_stage_minor = quest_unlock_index_full % 10 + 1;
                highscore_load_table_thunk();
            }
        } else if (quest_stage_minor + 10 * quest_stage_major - 11
                   > quest_unlock_index) {
            quest_stage_major = quest_unlock_index / 10 + 1;
            quest_stage_minor = quest_unlock_index % 10 + 1;
        }
        highscore_load_table_thunk();
    }

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    if ((online_sync_status == 0 || online_sync_status == 6)
        && ((arrow_hovered && input_primary_just_pressed())
            || grim_interface_ptr->grim_was_key_pressed(28))) {
        int action = highscore_screen_action_id;
        if (action == -3) {
            --quest_stage_minor;
            if (quest_stage_minor <= 0) {
                if (quest_stage_major >= 2) {
                    --quest_stage_major;
                    quest_stage_minor = 10;
                } else {
                    quest_stage_minor = 1;
                }
            }
            if (config_blob.hardcore) {
                if (quest_stage_minor + 10 * quest_stage_major - 11
                    > quest_unlock_index_full) {
                    quest_stage_major = quest_unlock_index_full / 10 + 1;
                    quest_stage_minor = quest_unlock_index_full % 10 + 1;
                    highscore_load_table_thunk();
                }
            } else if (quest_stage_minor + 10 * quest_stage_major - 11
                       > quest_unlock_index) {
                quest_stage_major = quest_unlock_index / 10 + 1;
                quest_stage_minor = quest_unlock_index % 10 + 1;
            }
            highscore_load_table_thunk();
        } else if (action == -2) {
            if (quest_stage_minor + 10 * quest_stage_major - 11
                < quest_unlock_index) {
                ++quest_stage_minor;
            }
            if (quest_stage_minor > 10) {
                if (quest_stage_major < 5) {
                    ++quest_stage_major;
                    quest_stage_minor = 1;
                } else {
                    quest_stage_minor = 10;
                }
            }
            if (config_blob.hardcore) {
                if (quest_stage_minor + 10 * quest_stage_major - 11
                    > quest_unlock_index_full) {
                    quest_stage_major = quest_unlock_index_full / 10 + 1;
                    quest_stage_minor = quest_unlock_index_full % 10 + 1;
                    highscore_load_table_thunk();
                }
            } else if (quest_stage_minor + 10 * quest_stage_major - 11
                       > quest_unlock_index) {
                quest_stage_major = quest_unlock_index / 10 + 1;
                quest_stage_minor = quest_unlock_index % 10 + 1;
            }
            highscore_load_table_thunk();
        } else if (action == 1) {
            if (online_sync_status == 0 || online_sync_status == 6) {
                if (grim_interface_ptr->grim_is_key_down(42)
                    || grim_interface_ptr->grim_is_key_down(54)) {
                    highscore_batch_sync_stage_index = -4;
                    highscore_batch_sync_mode = 1;
                } else {
                    highscore_batch_sync_mode = 0;
                }
                online_sync_status = 1;
                crt_beginthread(highscore_sync_worker, 0, 0);
            }
        } else if (action == 2) {
            render_pass_mode = 0;
            ui_sign_crimson.focus_disabled = 0;
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_GAMEPLAY;
            sfx_mute_all(music_track_crimson_theme_id);
            sfx_mute_all(music_track_shortie_monk_id);
            sfx_mute_all(music_track_extra_0);
            screen_fade_ramp_flag = 1;
        } else if (action == 3) {
            ui_transition_direction = 0;
            game_state_pending = GAME_STATE_STATISTICS_MENU;
        }
    }

    if ((online_sync_status == 0 || online_sync_status == 6)
        && grim_interface_ptr->grim_was_key_pressed(1)) {
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_STATISTICS_MENU;
    }

    if (online_sync_status == 0
        && update_notice_pending
        && update_notice_url) {
        highscore_vec2_t update_position(
            notice_position.x - 48.0f,
            notice_position.y - 146.0f);
        ui_update_notice_update((float *)&update_position, 1.0f);
    } else {
        update_notice_open_requested = 0;
    }
    if (!ui_transition_direction) {
        update_notice_pending = 0;
        highscore_post_sync_update_check_latch = 0;
    }
}
