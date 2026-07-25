#include <windows.h>

#include "crimsonland_audio.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern unsigned char startup_first_frame_latch;
extern unsigned char startup_intro_enabled;
extern unsigned char startup_bootstrap_pending;
extern unsigned char startup_async_load_ready;
extern unsigned char startup_skip_requested;
extern unsigned char startup_logo_sequence_active;
extern unsigned char startup_loading_fade_complete;
extern unsigned char startup_terrain_generation_active;
extern unsigned char quit_requested;

extern int startup_texture_load_stage;
extern int startup_texture_load_stage_count;
extern int startup_post_load_settle_ticks;

extern float startup_splash_timer;
extern float game_time_s;
extern float screen_width_f;
extern float screen_height_f;
extern float render_tint_color_r;
extern float render_tint_color_a;

extern cvar_float_t *cv_showFPS;

int texture_get_or_load(char *name, char *path);
int load_textures_step(void);
void game_startup_init_prelude(void);
void startup_audio_load_thread(void *arg);
void crt_beginthread(
    void (*function)(void *),
    unsigned int stack_size,
    void *arg);
bool input_primary_just_pressed(void);
void demo_mode_start(void);
unsigned char game_is_full_version(void);
unsigned char game_frame_update(void);
}

static __forceinline void startup_render_fps(void)
{
    if (cv_showFPS->value != 0.0f) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, 0.6f);
        if ((int)grim_interface_ptr->grim_get_fps() >= 400) {
            grim_interface_ptr->grim_draw_text_small_fmt(
                (float)(config_blob.screen_width - 51),
                (float)(config_blob.screen_height - 24),
                "400+",
                (int)grim_interface_ptr->grim_get_fps());
        } else {
            grim_interface_ptr->grim_draw_text_small_fmt(
                (float)(config_blob.screen_width - 45),
                (float)(config_blob.screen_height - 24),
                "%d",
                (int)grim_interface_ptr->grim_get_fps());
        }
    }
}

static __forceinline unsigned char startup_continue_requested(void)
{
    if (grim_interface_ptr->grim_is_key_down(0x10)
        && grim_interface_ptr->grim_is_key_down(0x38)) {
        return 0;
    }
    return !quit_requested;
}

extern "C" unsigned char game_startup_init(void)
{
    float outline_xy[2];

    frame_dt = grim_interface_ptr->grim_get_frame_dt();
    if (frame_dt > 0.1f) {
        frame_dt = 0.1f;
    }

    if (startup_first_frame_latch) {
        startup_first_frame_latch = 0;
    }

    char logo_sequence_active = startup_logo_sequence_active;
    if (!logo_sequence_active) {
        load_textures_step();
        logo_sequence_active = startup_logo_sequence_active;
    }

    if (startup_first_frame_latch || !startup_bootstrap_pending) {
        if (!logo_sequence_active) {
            goto render_loading_screen;
        }
    } else {
        texture_get_or_load(
            "splashReflexive", "load\\splashReflexive.jpg");
        texture_get_or_load(
            "splash10Tons", "load\\splash10tons.jaz");
        game_startup_init_prelude();
        crt_beginthread(startup_audio_load_thread, 0, 0);
        startup_bootstrap_pending = 0;
        logo_sequence_active = 1;
        startup_logo_sequence_active = logo_sequence_active;
        if (startup_splash_timer > 0.5f) {
            startup_splash_timer = 0.5f;
        }
    }

    if (startup_async_load_ready && startup_loading_fade_complete) {
        if (startup_post_load_settle_ticks < 5) {
            ++startup_post_load_settle_ticks;
            Sleep(5);
            grim_interface_ptr->grim_clear_color(
                0.0f, 0.0f, 0.0f, 1.0f);
            audio_update();
            console_log_queue.update();
            console_log_queue.render();
            startup_render_fps();
            return startup_continue_requested();
        }

        if (startup_splash_timer > 14.0f) {
            grim_interface_ptr->grim_set_config_var(
                0x2d, (char *)game_frame_update);

            grim_interface_ptr->grim_destroy_texture(
                grim_interface_ptr->grim_get_texture_handle(
                    "splashReflexive"));
            grim_interface_ptr->grim_destroy_texture(
                grim_interface_ptr->grim_get_texture_handle(
                    "splash10Tons"));
            sfx_mute_all(music_track_intro_id);
            if (!game_is_full_version()) {
                sfx_play_exclusive(music_track_crimsonquest_id);
                demo_mode_start();
            } else {
                sfx_play_exclusive(music_track_crimson_theme_id);
            }
            grim_interface_ptr->grim_clear_color(
                0.0f, 0.0f, 0.0f, 1.0f);
            return 1;
        }

        if (grim_interface_ptr->grim_is_key_down(1)
            || grim_interface_ptr->grim_is_key_down(0x39)
            || grim_interface_ptr->grim_is_key_down(0x1c)
            || input_primary_just_pressed()
            || grim_interface_ptr->grim_was_mouse_button_pressed(1)) {
            startup_skip_requested = 1;
        } else if (!startup_terrain_generation_active) {
            if (grim_interface_ptr->grim_was_key_pressed(0x29)) {
                console_log_queue.console_set_open(
                    !console_log_queue.open);
            }

            frame_dt_copy = frame_dt;
            game_time_s += frame_dt;
            grim_interface_ptr->grim_clear_color(
                0.0f, 0.0f, 0.0f, 1.0f);

            if (startup_intro_enabled) {
                if (!sfx_is_unmuted(music_track_intro_id)) {
                    sfx_play_exclusive(music_track_intro_id);
                }

                startup_splash_timer += frame_dt * 1.1f;
                grim_interface_ptr->grim_set_config_var(0x15, 1u);
                startup_splash_timer -= 2.0f;

                if (startup_skip_requested) {
                    if (startup_splash_timer < 1.0f) {
                        startup_splash_timer = 16.0f;
                    } else if (startup_splash_timer < 5.0f) {
                        startup_splash_timer += frame_dt * 4.0f;
                    } else if (startup_splash_timer < 7.0f) {
                        startup_splash_timer = 16.0f;
                    } else if (startup_splash_timer < 11.0f) {
                        startup_splash_timer += frame_dt * 4.0f;
                    } else {
                        startup_splash_timer = 16.0f;
                    }
                }

                int logo_height = 64;
                grim_interface_ptr->grim_set_uv(
                    0.0f, 0.0f, 1.0f, 1.0f);
                grim_interface_ptr->grim_set_rotation(0.0f);

                int texture_handle = -1;
                if (startup_splash_timer > 1.0f
                    && startup_splash_timer < 5.0f) {
                    logo_height = 128;
                    texture_handle =
                        grim_interface_ptr->grim_get_texture_handle(
                            "splash10Tons");
                } else if (startup_splash_timer > 6.0f) {
                    texture_handle =
                        grim_interface_ptr->grim_get_texture_handle(
                            "splashReflexive");
                    logo_height = 256;
                }
                if (texture_handle >= 0) {
                    grim_interface_ptr->grim_bind_texture(
                        texture_handle, 0);
                }

                grim_interface_ptr->grim_begin_batch();
                if (startup_splash_timer > 1.0f
                    && startup_splash_timer < 2.0f) {
                    grim_interface_ptr->grim_set_color(
                        1.0f,
                        1.0f,
                        1.0f,
                        startup_splash_timer - 1.0f);
                    grim_interface_ptr->grim_draw_quad(
                        (float)(config_blob.screen_width / 2 - 256),
                        (float)(config_blob.screen_height / 2
                            - logo_height / 2),
                        512.0f,
                        (float)logo_height);
                } else if (startup_splash_timer >= 2.0f
                    && startup_splash_timer < 4.0f) {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 1.0f, 1.0f, 1.0f);
                    grim_interface_ptr->grim_draw_quad(
                        (float)(config_blob.screen_width / 2 - 256),
                        (float)(config_blob.screen_height / 2
                            - logo_height / 2),
                        512.0f,
                        (float)logo_height);
                } else if (startup_splash_timer >= 4.0f
                    && startup_splash_timer < 5.0f) {
                    float alpha =
                        1.0f - (startup_splash_timer - 4.0f);
                    if (alpha < 0.0f) {
                        alpha = 0.0f;
                    } else if (alpha > 1.0f) {
                        alpha = 1.0f;
                    }
                    grim_interface_ptr->grim_set_color(
                        1.0f, 1.0f, 1.0f, alpha);
                    grim_interface_ptr->grim_draw_quad(
                        (float)(config_blob.screen_width / 2 - 256),
                        (float)(config_blob.screen_height / 2
                            - logo_height / 2),
                        512.0f,
                        (float)logo_height);
                } else if (startup_splash_timer > 7.0f
                    && startup_splash_timer < 8.0f) {
                    grim_interface_ptr->grim_set_color(
                        1.0f,
                        1.0f,
                        1.0f,
                        startup_splash_timer - 6.0f - 1.0f);
                    grim_interface_ptr->grim_draw_quad(
                        (float)(config_blob.screen_width / 2 - 256),
                        (float)(config_blob.screen_height / 2
                            - logo_height / 2),
                        512.0f,
                        (float)logo_height);
                } else if (startup_splash_timer >= 8.0f
                    && startup_splash_timer < 10.0f) {
                    grim_interface_ptr->grim_set_color(
                        1.0f, 1.0f, 1.0f, 1.0f);
                    grim_interface_ptr->grim_draw_quad(
                        (float)(config_blob.screen_width / 2 - 256),
                        (float)(config_blob.screen_height / 2
                            - logo_height / 2),
                        512.0f,
                        (float)logo_height);
                } else if (startup_splash_timer >= 10.0f
                    && startup_splash_timer < 11.0f) {
                    float alpha =
                        1.0f
                        - (startup_splash_timer - 6.0f - 4.0f);
                    if (alpha < 0.0f) {
                        alpha = 0.0f;
                    } else if (alpha > 1.0f) {
                        alpha = 1.0f;
                    }
                    grim_interface_ptr->grim_set_color(
                        1.0f, 1.0f, 1.0f, alpha);
                    grim_interface_ptr->grim_set_color(
                        1.0f, 1.0f, 1.0f, alpha);
                    grim_interface_ptr->grim_draw_quad(
                        (float)(config_blob.screen_width / 2 - 256),
                        (float)(config_blob.screen_height / 2
                            - logo_height / 2),
                        512.0f,
                        (float)logo_height);
                }

                startup_splash_timer += 2.0f;
                grim_interface_ptr->grim_set_config_var(0x15, 2u);
                grim_interface_ptr->grim_end_batch();
                audio_update();
            }

            console_log_queue.update();
            console_log_queue.render();
            if (grim_interface_ptr->grim_is_key_down(0x10)) {
                if (grim_interface_ptr->grim_is_key_down(0x38)) {
                    return 0;
                }
            }
            if (quit_requested) {
                return 0;
            }
        }

        startup_render_fps();
        return 1;
    }

render_loading_screen:
    if (logo_sequence_active && startup_async_load_ready) {
        startup_splash_timer -= frame_dt;
        if (startup_splash_timer < 0.0f) {
            startup_splash_timer = 0.0f;
            startup_loading_fade_complete = 1;
            grim_interface_ptr->grim_destroy_texture(
                grim_interface_ptr->grim_get_texture_handle("loading"));
            grim_interface_ptr->grim_destroy_texture(
                grim_interface_ptr->grim_get_texture_handle("logo_esrb"));
        }
    } else {
        startup_splash_timer += frame_dt;
    }

    grim_interface_ptr->grim_clear_color(
        0.0f, 0.0f, 0.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x15, 1u);

    float loading_alpha = startup_splash_timer * 2.0f;
    if (loading_alpha > 1.0f) {
        loading_alpha = 1.0f;
    } else if (loading_alpha < 0.0f) {
        loading_alpha = 0.0f;
    }

    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, loading_alpha);
    grim_interface_ptr->grim_set_uv(0.0f, 0.0f, 1.0f, 1.0f);
    grim_interface_ptr->grim_set_rotation(0.0f);

    grim_interface_ptr->grim_bind_texture(
        grim_interface_ptr->grim_get_texture_handle("logo_esrb"), 0);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        screen_width_f - 256.0f - 1.0f,
        screen_height_f - 128.0f - 1.0f,
        256.0f,
        128.0f);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_bind_texture(
        grim_interface_ptr->grim_get_texture_handle("loading"), 0);
    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_draw_quad(
        screen_width_f * 0.5f + 128.0f,
        screen_height_f * 0.5f + 16.0f,
        128.0f,
        32.0f);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_begin_batch();
    grim_interface_ptr->grim_bind_texture(
        grim_interface_ptr->grim_get_texture_handle("cl_logo"), 0);
    grim_interface_ptr->grim_draw_quad(
        screen_width_f * 0.5f - 256.0f,
        screen_height_f * 0.5f - 32.0f,
        512.0f,
        64.0f);
    grim_interface_ptr->grim_end_batch();

    grim_interface_ptr->grim_set_color(
        1.0f, 1.0f, 1.0f, loading_alpha);
    if (cv_silentloads->value == 0.0f) {
        grim_interface_ptr->grim_set_color(
            1.0f, 1.0f, 1.0f, loading_alpha * 0.7f);
        grim_interface_ptr->grim_draw_text_small_fmt(
            screen_width_f * 0.5f - 246.0f,
            screen_height_f * 0.5f + 32.0f,
            "Grim GFX %d/%d",
            startup_texture_load_stage,
            startup_texture_load_stage_count - 1);
        grim_interface_ptr->grim_draw_text_small_fmt(
            screen_width_f * 0.5f - 246.0f,
            screen_height_f * 0.5f + 45.0f,
            "Grim SFX: %d/%d",
            audio_assets_loaded_count,
            81);
    }

    grim_interface_ptr->grim_set_config_var(0x15, 2u);
    render_tint_color_a = loading_alpha * 0.7f;
    grim_interface_ptr->grim_set_color_ptr(&render_tint_color_r);

    outline_xy[0] = -4.0f;
    outline_xy[1] = screen_height_f * 0.5f - 68.0f;
    grim_interface_ptr->grim_draw_rect_outline(
        outline_xy, screen_width_f + 8.0f, 128.0f);

    console_log_queue.update();
    console_log_queue.render();
    startup_render_fps();
    Sleep(50);
    return 1;
}
