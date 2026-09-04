#include <math.h>
#include <string.h>

#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct typo_vec2_t {
    float x;
    float y;

    typo_vec2_t() {}

    typo_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}

    ~typo_vec2_t() {}
};

extern "C" {
extern int frame_dt_ms;
extern int config_player_count;
extern int config_screen_height;
extern int survival_spawn_cooldown;
extern int typo_submit_count;
extern int typo_match_count;
extern int typo_input_length;
extern int typo_spawn_counter;
extern unsigned char console_open_flag;
extern unsigned char time_scale_active;
extern unsigned char ui_transition_direction;
extern unsigned char typo_mode_reset_flag;
extern float time_scale_factor;
extern float game_time_s;
extern game_state_id_t game_state_pending;
extern char typo_input_buffer[];
extern char s_typo_command_reload[];
extern char console_prompt_format[];
extern char console_caret_string[];

extern int sfx_ui_typeenter;
extern int sfx_ui_typeclick_01;
extern int music_track_extra_0;
extern int music_track_crimson_theme_id;
extern int music_track_shortie_monk_id;
extern int ui_hud_panel_texture;

int console_input_poll(void);
int typo_target_find_by_name(char *name);
void typo_target_name_assign_random(int creature_id);
void typo_target_name_draw_labels(void);
void perks_update_effects(void);
void creature_update_all(void);
void projectile_update(void);
void player_fire_weapon(
    const vec2f_t *aim,
    char fire_requested,
    char reload_requested);
void camera_update(void);
void sfx_mute_all(int sfx_id);
void sfx_play_exclusive(int sfx_id);
void hud_update_and_render(void);
}

#define CRIMSONLAND_USE_ORIGINAL_TEXTURES_OWNER
#include "crimsonland_textures_owner.h"

static __inline void clamp01(float *value)
{
    if (*value < 0.0f) {
        *value = 0.0f;
    } else if (*value > 1.0f) {
        *value = 1.0f;
    }
}

extern "C" void typo_gameplay_update_and_render(void)
{
    bool fire_requested = false;
    bool reload_requested = false;
    static typo_vec2_t target_world(
        player_state_table[0].position.x + 128.0f,
        player_state_table[0].position.y);

    if (typo_mode_reset_flag) {
        typo_input_length = 0;
        typo_input_buffer[0] = '\0';
        typo_mode_reset_flag = 0;
    }

    typo_vec2_t panel_position;
    panel_position.y = (float)config_screen_height - 128.0f;
    typo_input_buffer[typo_input_length + 1] = '\0';

    if (grim_interface_ptr->grim_is_key_down(0x1c)
        && typo_input_length > 0) {
        sfx_play(sfx_ui_typeenter, 1.0f);
        int submit_count = typo_submit_count + 1;
        typo_input_buffer[typo_input_length] = '\0';
        typo_submit_count = submit_count;

        int creature_id = typo_target_find_by_name(typo_input_buffer);
        if (creature_id != -1) {
            fire_requested = true;
            *(vec2f_t *)&target_world =
                creature_pool[creature_id].position;
            ++typo_match_count;
        } else if (strcmp(s_typo_command_reload, typo_input_buffer) == 0) {
            reload_requested = true;
        }

        typo_input_length = 0;
        typo_input_buffer[0] = '\0';
    }

    int input_char = console_input_poll();
    if (input_char != 0 && input_char != '\r') {
        if (input_char == '\b') {
            sfx_play(sfx_ui_typeclick_01 + crt_rand() % 2, 1.0f);
            if (typo_input_length > 0) {
                --typo_input_length;
                typo_input_buffer[typo_input_length] = '\0';
            } else {
                typo_input_buffer[0] = '\0';
            }
        } else {
            if (typo_input_length < 17) {
                typo_input_buffer[typo_input_length] = (char)input_char;
                ++typo_input_length;
            }
            typo_input_buffer[typo_input_length] = '\0';
            sfx_play(sfx_ui_typeclick_01 + crt_rand() % 2, 1.0f);
        }
    }

    perks_update_effects();
    float unscaled_frame_dt = frame_dt;
    if (time_scale_active) {
        time_scale_factor = 0.3f;
        frame_dt *= 0.3f;
        frame_dt_ms = (int)(frame_dt * 1000.0f);
    }
    effects_update();

    if (game_state_id == GAME_STATE_TYPO_GAMEPLAY) {
        creature_update_all();
        projectile_update();
        if (game_state_id == GAME_STATE_TYPO_GAMEPLAY) {
            for (render_overlay_player_index = 0;
                 render_overlay_player_index < config_player_count;
                ++render_overlay_player_index) {
                player_fire_weapon(
                    (const vec2f_t *)&target_world,
                    fire_requested,
                    reload_requested);
            }
        }
    }

    render_overlay_player_index = 0;
    player_state_table[0].weapon_id = WEAPON_ID_SHOTGUN;
    player_state_table[0].ammo = 30.0f;

    if (!console_open_flag) {
        survival_spawn_cooldown -= config_player_count * frame_dt_ms;
    }
    while (survival_spawn_cooldown < 0) {
        survival_spawn_cooldown += 3500 - survival_elapsed_ms / 800;
        if (survival_spawn_cooldown < 100) {
            survival_spawn_cooldown = 100;
        }

        float elapsed = (float)(survival_elapsed_ms + 1);
        effect_color_t color;
        color.r = elapsed * 0.00000833333343f + 0.3f;
        color.g = elapsed * 10000.0f + 0.3f;
        color.b = (float)sin(elapsed * 0.000100000005f) + 0.3f;
        color.a = 1.0f;
        clamp01(&color.r);
        clamp01(&color.g);
        clamp01(&color.b);

        ++typo_spawn_counter;
        vec2f_t right_pos;
        right_pos.x = (float)terrain_texture_width + 64.0f;
        right_pos.y = (float)terrain_texture_height * 0.5f
            + (float)cos((float)survival_elapsed_ms * 0.001f) * 256.0f;
        typo_target_name_assign_random(
            creature_spawn_tinted(&right_pos, &color, 4));

        typo_vec2_t left_pos(
            -64.0f,
            (float)terrain_texture_height * 0.5f
                + (float)cos((float)survival_elapsed_ms * 0.001f) * 256.0f);
        typo_target_name_assign_random(
            creature_spawn_tinted((const vec2f_t *)&left_pos, &color, 2));
    }

    highscore_active_record.score_xp = player_state_table[0].experience;
    if (!console_open_flag) {
        bonus_weapon_power_up_timer = 0.0f;
        bonus_reflex_boost_timer = 0.0f;
        time_scale_active = 0;
        survival_elapsed_ms += frame_dt_ms;
        unsigned int *weapon_time =
            &weapon_usage_time[player_state_table[0].weapon_id];
        *weapon_time += frame_dt_ms;
    }

    camera_update();
    gameplay_render_world();
    typo_target_name_draw_labels();

    for (int bonus_index = 0; bonus_index < 16; ++bonus_index) {
        bonus_pool[bonus_index].bonus_id = BONUS_ID_NONE;
    }
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);

    if (!demo_mode_active
        && player_state_table[0].health <= 0.0f
        && player_state_table[0].death_timer < 0.0f
        && (config_player_count == 1
            || (player_state_table[1].health <= 0.0f
                && player_state_table[1].death_timer < 0.0f))) {
        render_pass_mode = 0;
        game_state_pending = GAME_STATE_GAME_OVER;
        ui_transition_direction = 0;
        grim_interface_ptr->grim_flush_input();
        console_input_poll();
        sfx_mute_all(music_track_extra_0);
        sfx_mute_all(music_track_crimson_theme_id);
        sfx_mute_all(music_track_shortie_monk_id);
        sfx_play_exclusive(music_track_shortie_monk_id);
    }

    frame_dt = unscaled_frame_dt;
    frame_dt_ms = (int)(unscaled_frame_dt * 1000.0f);
    perk_prompt_update_and_render();
    hud_update_and_render();

    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x15, (unsigned int)1);
    grim_interface_ptr->grim_bind_texture(ui_hud_panel_texture, 0);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.7f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        -1.0f, panel_position.y - 16.0f, 182.0f, 53.0f);
    grim_interface_ptr->grim_end_batch();
    grim_interface_ptr->grim_set_config_var(0x15, (unsigned int)2);
    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);

    typo_vec2_t text_position;
    text_position.x = 6.0f;
    text_position.y = panel_position.y + 1.0f;
    grim_interface_ptr->grim_draw_text_small_fmt(
        text_position.x,
        text_position.y,
        console_prompt_format,
        typo_input_buffer);

    float caret_alpha = 1.0f;
    if ((float)sin(game_time_s * 4.0f) > 0.0f) {
        caret_alpha = 0.4f;
    }
    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, caret_alpha);
    grim_interface_ptr->grim_draw_text_small_fmt(
        (float)grim_interface_ptr->grim_measure_text_width(typo_input_buffer)
            + 14.0f,
        text_position.y,
        console_caret_string);

    highscore_active_record.shots_hit = typo_match_count;
    highscore_active_record.shots_fired = typo_submit_count;
    ui_elements_update_and_render();
}
