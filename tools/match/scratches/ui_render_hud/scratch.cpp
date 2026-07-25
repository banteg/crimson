#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

struct hud_render_vec2_t {
    float x;
    float y;

    hud_render_vec2_t(float x_value, float y_value)
        : x(x_value), y(y_value) {}
};

struct hud_render_color_t {
    float r;
    float g;
    float b;
    float a;

    hud_render_color_t(
        float r_value,
        float g_value,
        float b_value,
        float a_value)
        : r(r_value), g(g_value), b(b_value), a(a_value) {}

    ~hud_render_color_t() {}
};

extern "C" {
extern cvar_float_t *cv_uiTransparency;
extern int config_player_count;
extern int config_screen_width;
extern int config_screen_height;
extern int frame_dt_ms;
extern float game_time_s;

extern unsigned char hud_show_health_panel;
extern unsigned char hud_show_weapon_panel;
extern unsigned char hud_show_xp_panel;
extern unsigned char hud_show_quest_panel;
extern unsigned char hud_show_timer_panel;

extern int ui_hud_panel_texture;
extern int ui_hud_life_indicator_texture;
extern int ui_weapon_icons_texture;
extern int ui_clock_table_texture;
extern int ui_clock_pointer_texture;
extern int ui_text_level_complete_texture;

extern weapon_storage_entry_t weapon_ammo_class[];
extern int quest_spawn_timeline;
extern int quest_stage_banner_timer_ms;
extern char quest_stage_label_buffer[];
extern float quest_kill_progress_ratio;
extern int quest_progress_reserved_zero;
extern int survival_xp_smoothed;

extern float render_tint_color_r;
extern float render_tint_color_a;

void ui_draw_progress_bar(
    float *xy,
    float width,
    float ratio,
    float *rgba);
void bonus_hud_slot_update_and_render(
    float *y,
    int slot_index,
    float alpha);
}

extern "C" void ui_render_hud(float transition_alpha)
{
    if (cv_uiTransparency->value >= 0.0f
        && cv_uiTransparency->value <= 1.0f) {
        transition_alpha *= cv_uiTransparency->value;
    }

    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    float panel_alpha = transition_alpha * 0.7f;
    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, panel_alpha);
    grim_interface_ptr->grim_bind_texture(
        grim_interface_ptr->grim_get_texture_handle("iGameUI"), 0);
    grim_interface_ptr->grim_set_rotation(0.0f);
    grim_interface_ptr->grim_set_uv(
        0.001953125f, 0.015625f, 0.998046875f, 0.984375f);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(0.0f, 0.0f, 512.0f, 64.0f);
    grim_interface_ptr->grim_end_batch();

    if (hud_show_health_panel) {
        grim_interface_ptr->grim_set_config_var(0x15, 2u);

        hud_render_vec2_t center(27.0f, 21.0f);
        if (config_player_count == 1) {
            center = hud_render_vec2_t(27.0f, 21.0f);
        } else {
            center = hud_render_vec2_t(27.0f, 12.0f);
        }

        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, transition_alpha * 0.8f);
        grim_interface_ptr->grim_bind_texture(
            grim_interface_ptr->grim_get_texture_handle("iHeart"), 0);
        grim_interface_ptr->grim_set_uv(
            0.03125f, 0.03125f, 0.96875f, 0.96875f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_begin_batch();

        float pulse_speed = 2.0f;
        float pulse;
        if (config_player_count == 1) {
            if (player_state_table[0].health < 30.0f) {
                pulse_speed = 5.0f;
            }
            float pulse_value =
                (float)sin(game_time_s * pulse_speed);
            pulse =
                (float)pow(pulse_value, 4.0) * 4.0f + 14.0f;
            grim_interface_ptr->grim_draw_quad(
                center.x - pulse,
                center.y - pulse,
                pulse + pulse,
                pulse + pulse);
        } else {
            if (player_state_table[0].health < 30.0f) {
                pulse_speed = 5.0f;
            }
            float pulse_value =
                (float)sin(game_time_s * pulse_speed);
            pulse =
                ((float)pow(pulse_value, 4.0) * 4.0f + 14.0f)
                * 0.5f;
            grim_interface_ptr->grim_draw_quad(
                center.x - pulse,
                center.y - pulse,
                pulse + pulse,
                pulse + pulse);

            float player_two_speed =
                player_state_table[1].health < 30.0f
                    ? 5.0f
                    : pulse_speed;
            pulse_value = (float)sin(
                game_time_s * player_two_speed + 1.57079637f);
            pulse =
                ((float)pow(pulse_value, 4.0) * 4.0f + 14.0f)
                * 0.5f;
            grim_interface_ptr->grim_draw_quad(
                center.x - pulse,
                center.y - pulse + 15.0f,
                pulse + pulse,
                pulse + pulse);
        }
        grim_interface_ptr->grim_end_batch();
    }

    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    if (hud_show_weapon_panel) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, transition_alpha * 0.8f);
        grim_interface_ptr->grim_bind_texture(
            ui_weapon_icons_texture, 0);
        grim_interface_ptr->grim_begin_batch();

        int weapon_id = player_state_table[0].weapon_id;
        if (config_player_count == 1) {
            grim_interface_ptr->grim_set_sub_rect(
                8,
                2,
                1,
                weapon_table[weapon_id].hud_icon_id * 2);
            grim_interface_ptr->grim_draw_quad(
                220.0f, 2.0f, 64.0f, 32.0f);
        } else {
            grim_interface_ptr->grim_set_sub_rect(
                8,
                2,
                1,
                weapon_table[weapon_id].hud_icon_id * 2);
            grim_interface_ptr->grim_draw_quad(
                220.0f, 4.0f, 32.0f, 16.0f);
            grim_interface_ptr->grim_set_sub_rect(
                8,
                2,
                1,
                weapon_table[player_state_table[1].weapon_id]
                    .hud_icon_id
                    * 2);
            grim_interface_ptr->grim_draw_quad(
                220.0f, 20.0f, 32.0f, 16.0f);
        }
        grim_interface_ptr->grim_end_batch();
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    }

    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    if (hud_show_health_panel) {
        grim_interface_ptr->grim_bind_texture(
            ui_hud_life_indicator_texture, 0);
        grim_interface_ptr->grim_begin_batch();

        hud_render_vec2_t bar_position(64.0f, 16.0f);
        if (config_player_count == 1) {
            bar_position = hud_render_vec2_t(64.0f, 16.0f);
        } else {
            bar_position = hud_render_vec2_t(64.0f, 6.0f);
        }
        render_overlay_player_index = 0;
        if (config_player_count > 0) {
            float background_alpha = transition_alpha * 0.5f;
            float fill_alpha = transition_alpha * 0.8f;
            do {
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, background_alpha);
                grim_interface_ptr->grim_set_uv(
                    0.0f, 0.0f, 1.0f, 1.0f);
                grim_interface_ptr->grim_draw_quad(
                    bar_position.x,
                    bar_position.y
                        + (float)(render_overlay_player_index * 16),
                    120.0f,
                    9.0f);

                float health_ratio =
                    player_state_table[render_overlay_player_index].health
                    * 0.01f;
                if (health_ratio > 1.0f) {
                    health_ratio = 1.0f;
                } else if (health_ratio < 0.0f) {
                    health_ratio = 0.0f;
                }

                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, fill_alpha);
                grim_interface_ptr->grim_set_uv(
                    0.0f, 0.0f, health_ratio, 1.0f);
                grim_interface_ptr->grim_draw_quad(
                    bar_position.x,
                    bar_position.y
                        + (float)(render_overlay_player_index * 16),
                    health_ratio * 120.0f,
                    9.0f);
                ++render_overlay_player_index;
            } while (render_overlay_player_index < config_player_count);
        }
        grim_interface_ptr->grim_end_batch();
    }

    if (hud_show_weapon_panel) {
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);

        hud_render_vec2_t ammo_position(300.0f, 10.0f);
        if (config_player_count == 1) {
            ammo_position = hud_render_vec2_t(300.0f, 10.0f);
        } else {
            ammo_position = hud_render_vec2_t(290.0f, 4.0f);
        }
        for (render_overlay_player_index = 0;
             render_overlay_player_index < config_player_count;
             ++render_overlay_player_index) {
            int weapon_id =
                player_state_table[render_overlay_player_index].weapon_id;
            int ammo_class = weapon_ammo_class[weapon_id].ammo_class;
            if (ammo_class == 1) {
                grim_interface_ptr->grim_bind_texture(
                    grim_interface_ptr->grim_get_texture_handle(
                        "ui\\ui_indFire.jaz"),
                    0);
            } else if (ammo_class == 0) {
                grim_interface_ptr->grim_bind_texture(
                    grim_interface_ptr->grim_get_texture_handle(
                        "ui\\ui_indBullet.jaz"),
                    0);
            } else if (ammo_class == 2) {
                grim_interface_ptr->grim_bind_texture(
                    grim_interface_ptr->grim_get_texture_handle(
                        "ui\\ui_indRocket.jaz"),
                    0);
            } else {
                grim_interface_ptr->grim_bind_texture(
                    grim_interface_ptr->grim_get_texture_handle(
                        "ui\\ui_indElectric.jaz"),
                    0);
            }
            grim_interface_ptr->grim_begin_batch();

            int bar_count = (int)player_state_table
                [render_overlay_player_index]
                    .clip_size;
            if (bar_count > 30) {
                bar_count = 20;
            }
            int ammo = (int)player_state_table
                [render_overlay_player_index]
                    .ammo;
            grim_interface_ptr->grim_set_uv(
                0.0f, 0.0f, 1.0f, 1.0f);

            int bar_index = 0;
            if (bar_count > 0) {
                int bar_x = 0;
                do {
                    float ammo_alpha =
                        bar_index < ammo
                            ? transition_alpha
                            : transition_alpha * 0.3f;
                    grim_interface_ptr->grim_set_color(
                        1.0f, 1.0f, 1.0f, ammo_alpha);
                    grim_interface_ptr->grim_draw_quad(
                        ammo_position.x + (float)bar_x,
                        ammo_position.y
                            + (float)(
                                render_overlay_player_index * 14),
                        6.0f,
                        16.0f);
                    ++bar_index;
                    bar_x += 6;
                } while (bar_index < bar_count);
            }
            grim_interface_ptr->grim_end_batch();

            if (ammo > bar_count) {
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, panel_alpha);
                grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
                grim_interface_ptr->grim_draw_text_small_fmt(
                    ammo_position.x + (float)(bar_index * 6) + 8.0f,
                    ammo_position.y
                        + (float)(render_overlay_player_index * 14)
                        + 1.0f,
                    "+ %d",
                    ammo - bar_count);
            }
        }
    }

    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, panel_alpha);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    grim_interface_ptr->grim_set_config_var(0x15, 2u);

    int hud_y = 78;
    if (hud_show_quest_panel) {
        grim_interface_ptr->grim_set_config_var(0x15, 1u);
        grim_interface_ptr->grim_bind_texture(ui_hud_panel_texture, 0);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        grim_interface_ptr->grim_begin_batch();

        float slide_x = 0.0f;
        if (quest_spawn_timeline < 1000) {
            slide_x =
                (float)(1000 - quest_spawn_timeline) * -0.128f;
        }
        grim_interface_ptr->grim_draw_quad(
            slide_x - 90.0f, 67.0f, 182.0f, 53.0f);
        grim_interface_ptr->grim_draw_quad(
            -80.0f, 107.0f, 182.0f, 53.0f);
        grim_interface_ptr->grim_end_batch();

        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        float clock_alpha = transition_alpha * 0.9f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, clock_alpha);
        grim_interface_ptr->grim_bind_texture(
            ui_clock_table_texture, 0);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_begin_batch();
        float clock_x = slide_x + 2.0f;
        grim_interface_ptr->grim_draw_quad(
            clock_x, 78.0f, 32.0f, 32.0f);
        grim_interface_ptr->grim_end_batch();

        grim_interface_ptr->grim_set_config_var(0x15, 2u);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, clock_alpha);
        grim_interface_ptr->grim_bind_texture(
            ui_clock_pointer_texture, 0);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_rotation(
            (float)(quest_spawn_timeline / 1000)
            * 0.10471976f);
        grim_interface_ptr->grim_draw_quad(
            clock_x, 78.0f, 32.0f, 32.0f);
        grim_interface_ptr->grim_end_batch();

        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
        int elapsed_seconds = quest_spawn_timeline / 1000;
        if (elapsed_seconds % 60 >= 10) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                slide_x + 32.0f,
                86.0f,
                "%d:%d",
                elapsed_seconds / 60,
                elapsed_seconds % 60);
        } else {
            grim_interface_ptr->grim_draw_text_small_fmt(
                slide_x + 32.0f,
                86.0f,
                "%d:0%d",
                elapsed_seconds / 60,
                elapsed_seconds % 60);
        }
        grim_interface_ptr->grim_set_config_var(0x18, 0.45f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            18.0f, 122.0f, "Progress");

        static hud_render_color_t progress_color(
            0.2f, 0.8f, 0.3f, 1.0f);
        progress_color.a = transition_alpha * 0.8f;

        int queued_creatures = 0;
        quest_progress_reserved_zero = 0;
        int spawn_count = quest_spawn_count;
        if (spawn_count > 0) {
            int *count = &quest_spawn_table[0].count;
            do {
                queued_creatures += *count;
                count += 6;
                --spawn_count;
            } while (spawn_count != 0);
        }

        int total_creatures =
            queued_creatures + creature_spawned_count;
        hud_render_vec2_t progress_position(10.0f, 139.0f);
        quest_kill_progress_ratio =
            (float)(int)highscore_active_record.creature_kill_count
            / (float)total_creatures;
        ui_draw_progress_bar(
            (float *)&progress_position,
            70.0f,
            quest_kill_progress_ratio,
            (float *)&progress_color);
        hud_y = 158;

        float banner_fade;
        if (quest_stage_banner_timer_ms < 500) {
            banner_fade =
                (float)(quest_stage_banner_timer_ms * 2) * 0.001f;
        } else if (quest_stage_banner_timer_ms < 1500) {
            banner_fade = 1.0f;
        } else if (quest_stage_banner_timer_ms < 2000) {
            banner_fade =
                1.0f
                - (float)(
                    quest_stage_banner_timer_ms * 2 - 3000)
                    * 0.001f;
        } else {
            banner_fade = 0.0f;
        }
        if (banner_fade > 1.0f) {
            banner_fade = 1.0f;
        }

        float banner_alpha = banner_fade * transition_alpha;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, banner_alpha);
        if (banner_fade >= 0.0f) {
            float name_scale = 0.8f;
            int quest_name_length = strlen(
                quest_selected_meta[
                    quest_stage_minor
                    + quest_stage_major * 10
                    - 11]
                    .name);
            if (config_screen_width <= 640) {
                name_scale = 0.75f;
            }
            grim_interface_ptr->grim_set_config_var(
                0x18, name_scale);

            float name_x =
                (float)(config_screen_width / 2)
                - (float)quest_name_length
                    * name_scale
                    * 8.0f;
            float name_y =
                (float)(config_screen_height / 2 - 32);
            grim_interface_ptr->grim_draw_text_mono(
                name_x,
                name_y,
                quest_selected_meta[
                    quest_stage_minor
                    + quest_stage_major * 10
                    - 11]
                    .name);

            float stage_scale = name_scale - 0.2f;
            grim_interface_ptr->grim_set_config_var(
                0x18, stage_scale);
            grim_interface_ptr->grim_set_color(
                1.0f, 1.0f, 1.0f, banner_alpha * 0.5f);

            int stage_minor = quest_stage_minor;
            if (stage_minor > 10) {
                stage_minor -= 10;
                ++quest_stage_major;
                quest_stage_minor = stage_minor;
            }
            crt_sprintf(
                quest_stage_label_buffer,
                "%d.%d",
                quest_stage_major,
                stage_minor);

            float stage_y =
                (float)(config_screen_height / 2 - 32)
                + stage_scale * 23.36f
                - stage_scale * 16.0f;
            float stage_x =
                name_x
                - (float)strlen(quest_stage_label_buffer)
                    * stage_scale
                    * 8.0f
                - stage_scale * 32.0f
                - 4.0f;
            grim_interface_ptr->grim_draw_text_mono_fmt(
                stage_x,
                stage_y,
                quest_stage_label_buffer);
        }

        if (quest_transition_timer_ms > 0) {
            float complete_fade;
            if (quest_transition_timer_ms < 500) {
                complete_fade =
                    (float)quest_transition_timer_ms * 0.002f;
            } else if (quest_transition_timer_ms < 1500) {
                complete_fade = 1.0f;
            } else if (quest_transition_timer_ms < 2500) {
                complete_fade =
                    (float)(
                        2000 - quest_transition_timer_ms)
                        * 0.002f
                    + 1.0f;
            } else {
                complete_fade = 0.0f;
            }
            if (complete_fade > 1.0f) {
                complete_fade = 1.0f;
            } else if (complete_fade < 0.0f) {
                complete_fade = 0.0f;
            }

            grim_interface_ptr->grim_set_config_var(0x18, 1.0f);
            float complete_scale =
                (float)quest_transition_timer_ms
                    * 0.0004f;
            complete_scale *= 0.13f;
            complete_scale += 0.95;
            grim_interface_ptr->grim_set_color(
                1.0f,
                1.0f,
                1.0f,
                complete_fade * transition_alpha);
            grim_interface_ptr->grim_bind_texture(
                ui_text_level_complete_texture, 0);
            grim_interface_ptr->grim_set_uv(
                0.0f, 0.0f, 1.0f, 1.0f);
            grim_interface_ptr->grim_draw_quad(
                (float)(config_screen_width / 2)
                    - complete_scale * 128.0f,
                (float)(config_screen_height / 2)
                    - complete_scale * 16.0f,
                complete_scale * 256.0f,
                complete_scale * 32.0f);
            grim_interface_ptr->grim_end_batch();
        }
    }

    if (hud_show_timer_panel) {
        grim_interface_ptr->grim_set_config_var(0x15, 1u);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        float clock_alpha = transition_alpha * 0.9f;
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, clock_alpha);
        grim_interface_ptr->grim_bind_texture(
            ui_clock_table_texture, 0);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            220.0f, 2.0f, 32.0f, 32.0f);
        grim_interface_ptr->grim_end_batch();

        grim_interface_ptr->grim_set_config_var(0x15, 2u);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, clock_alpha);
        grim_interface_ptr->grim_bind_texture(
            ui_clock_pointer_texture, 0);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_set_rotation(
            (float)(survival_elapsed_ms / 1000)
            * 0.10471976f);
        grim_interface_ptr->grim_draw_quad(
            220.0f, 2.0f, 32.0f, 32.0f);
        grim_interface_ptr->grim_end_batch();

        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            255.0f,
            10.0f,
            "%d seconds",
            survival_elapsed_ms / 1000);
    }

    if (hud_show_xp_panel) {
        grim_interface_ptr->grim_bind_texture(ui_hud_panel_texture, 0);
        grim_interface_ptr->grim_set_rotation(0.0f);
        grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, panel_alpha);
        grim_interface_ptr->grim_begin_batch();
        grim_interface_ptr->grim_draw_quad(
            -68.0f,
            (float)(hud_y - 18),
            182.0f,
            53.0f);
        grim_interface_ptr->grim_end_batch();

        if (player_state_table[0].experience == 0) {
            survival_xp_smoothed = 0;
        } else {
            if (survival_xp_smoothed
                < player_state_table[0].experience) {
                int step = frame_dt_ms / 2;
                if (step <= 0) {
                    step = 1;
                }
                int difference = abs(
                    survival_xp_smoothed
                    - player_state_table[0].experience);
                if (difference > 1000) {
                    step *= difference / 100;
                }
                survival_xp_smoothed += step;
                if (survival_xp_smoothed
                    > player_state_table[0].experience) {
                    survival_xp_smoothed =
                        player_state_table[0].experience;
                }
            } else if (survival_xp_smoothed
                       > player_state_table[0].experience) {
                int step = frame_dt_ms / 2;
                if (step <= 0) {
                    step = 1;
                }
                int difference = abs(
                    survival_xp_smoothed
                    - player_state_table[0].experience);
                if (difference > 1000) {
                    step *= difference / 100;
                }
                survival_xp_smoothed -= step;
                if (survival_xp_smoothed
                    < player_state_table[0].experience) {
                    survival_xp_smoothed =
                        player_state_table[0].experience;
                }
            }
        }

        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, transition_alpha * 0.9f);
        grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            4.0f, (float)hud_y, "Xp");
        grim_interface_ptr->grim_draw_text_small_fmt(
            26.0f,
            (float)(hud_y - 4),
            "%d",
            survival_xp_smoothed);

        render_tint_color_a = transition_alpha;
        grim_interface_ptr->grim_set_color_ptr(&render_tint_color_r);
        grim_interface_ptr->grim_draw_text_small_fmt(
            85.0f,
            (float)(hud_y + 1),
            "%d",
            player_state_table[0].level);

        int current_level = player_state_table[0].level;
        render_tint_color_a = 0.7f;
        int previous_threshold =
            1000
            - (int)(
                (float)pow(
                    (float)(player_state_table[0].level - 1),
                    1.8f)
                * -1000.0f);
        if (current_level == 1) {
            previous_threshold = 0;
        }
        hud_render_color_t progress_color(
            0.1f, 0.3f, 0.6f, panel_alpha);
        hud_render_vec2_t progress_position(
            26.0f, (float)(hud_y + 13));
        int next_threshold =
            1000
            - (int)(
                (float)pow(
                    (float)player_state_table[0].level,
                    1.8f)
                * -1000.0f);
        float progress_ratio =
            (float)(
                player_state_table[0].experience
                - previous_threshold)
            / (float)(next_threshold - previous_threshold);
        ui_draw_progress_bar(
            (float *)&progress_position,
            54.0f,
            progress_ratio,
            (float *)&progress_color);
        hud_y += 43;
    }

    grim_interface_ptr->grim_set_config_var(0x15, 1u);
    float bonus_y = (float)hud_y;
    int slot_index = 0;
    do {
        bonus_hud_slot_update_and_render(
            &bonus_y, slot_index, transition_alpha);
        ++slot_index;
    } while (slot_index < 16);

    int text_y = (int)bonus_y + 1;
    int icon_y = (int)bonus_y - 5;
    render_overlay_player_index = 0;
    if (config_player_count > 0) {
        do {
            if (player_aux_timer[render_overlay_player_index] > 0.0f) {
                float popup_fade =
                    player_aux_timer[render_overlay_player_index];
                if (popup_fade < 1.0f) {
                    player_aux_timer[render_overlay_player_index] -=
                        frame_dt * 0.5f;
                } else {
                    player_aux_timer[render_overlay_player_index] -=
                        frame_dt * 1.4f;
                }

                if (popup_fade > 1.0f) {
                    popup_fade = 2.0f - popup_fade;
                }
                if (popup_fade < 0.0f) {
                    popup_fade = 0.0f;
                }
                popup_fade *= transition_alpha;

                grim_interface_ptr->grim_set_color(
                    1.0f,
                    1.0f,
                    1.0f,
                    popup_fade * 0.8f);
                grim_interface_ptr->grim_bind_texture(
                    ui_hud_panel_texture, 0);
                grim_interface_ptr->grim_set_rotation(0.0f);
                grim_interface_ptr->grim_set_uv(
                    0.0f, 0.0f, 1.0f, 1.0f);
                grim_interface_ptr->grim_begin_batch();
                grim_interface_ptr->grim_draw_quad(
                    -12.0f,
                    (float)(icon_y - 12),
                    182.0f,
                    53.0f);
                grim_interface_ptr->grim_end_batch();

                grim_interface_ptr->grim_bind_texture(
                    ui_weapon_icons_texture, 0);
                grim_interface_ptr->grim_set_sub_rect(
                    8,
                    2,
                    1,
                    weapon_table[
                        player_state_table[render_overlay_player_index]
                            .weapon_id]
                        .hud_icon_id
                        * 2);
                grim_interface_ptr->grim_begin_batch();
                grim_interface_ptr->grim_draw_quad(
                    105.0f,
                    (float)icon_y,
                    60.0f,
                    30.0f);
                grim_interface_ptr->grim_end_batch();

                grim_interface_ptr->grim_set_config_var(0x18, 0.5f);
                grim_interface_ptr->grim_set_color(
                    1.0f, 1.0f, 1.0f, popup_fade);
                grim_interface_ptr->grim_draw_text_small(
                    8.0f,
                    (float)text_y,
                    weapon_table[
                        player_state_table[render_overlay_player_index]
                            .weapon_id]
                        .name);

                text_y += 32;
                icon_y += 32;
            }
            ++render_overlay_player_index;
        } while (render_overlay_player_index < config_player_count);
    }

    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    render_overlay_player_index = 0;
}
