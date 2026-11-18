#include <direct.h>
#include <math.h>
#include <string.h>
#include <windows.h>

#include "grim2d_cpp.h"
#include "grim_texture.h"

#if CL_BUILD < 10900
extern grim_config_value_t grim_config_values[128];
extern unsigned int grim_backbuffer_width;
extern unsigned int grim_backbuffer_height;

enum {
    texture_filter_config = CL_BUILD < 10300 ? 15 : 21,
    skip_splash_config = 66,
};
#endif

extern char grim_working_dir[260];
extern bool grim_mouse_enabled;
extern bool grim_keyboard_enabled;
extern bool grim_joystick_enabled;
extern bool grim_input_cached;
extern HWND grim_main_window_hwnd;
extern HWND *grim_main_window_hwnd_ref;
extern unsigned char grim_font2_glyph_widths[256];

bool grim_d3d_init(void);
void grim_d3d_shutdown(void);
BOOL grim_window_destroy(void);
bool grim_mouse_init(HWND hwnd);
void grim_mouse_shutdown(void);
bool grim_keyboard_init(HWND hwnd);
void grim_keyboard_shutdown(void);
bool grim_joystick_init(HWND hwnd);
void grim_timing_init(void);
void grim_timing_update(void);
char *grim_lookup_blob_find(char *path);

bool IGrim2D_cpp::grim_init_system(void)
{
#if CL_BUILD >= 10900
    memset(grim_working_dir, 0, sizeof(grim_working_dir));
    _getcwd(grim_working_dir, sizeof(grim_working_dir));
#endif

    if (!grim_d3d_init()) {
        return false;
    }

    if (grim_mouse_enabled == true && !grim_input_cached) {
        if (!grim_mouse_init(grim_main_window_hwnd)) {
            grim_error_text = "DI8: Could not initialize mouse.";
            grim_mouse_shutdown();
            grim_d3d_shutdown();
            grim_window_destroy();
            return false;
        }
    }

    if (grim_keyboard_enabled == true) {
        if (!grim_keyboard_init(grim_main_window_hwnd)) {
            grim_error_text = "DI8: Could not initialize keyboard.";
            grim_mouse_shutdown();
            grim_keyboard_shutdown();
            grim_d3d_shutdown();
            grim_window_destroy();
            return false;
        }
    }

#if CL_BUILD >= 10300
    if (grim_joystick_enabled == true) {
        bool initialized = grim_joystick_init(grim_main_window_hwnd);
        if (!initialized) {
            grim_error_text = "DI8: Could not initialize joystic.";
            grim_joystick_enabled = false;
        }
    }
#endif

    grim_timing_init();
    grim_timing_update();

#if CL_BUILD < 10900
    if (!grim_config_values[skip_splash_config]) {
        grim_d3d_device->SetTexture(0, grim_splash_texture);
        grim_set_rotation(0.0f);
        grim_set_config_var(texture_filter_config, (unsigned int)1);
#if CL_BUILD < 10400
        float time_left = 3.0f;
        do {
            grim_clear_color(0.0f, 0.0f, 0.0f, 1.0f);
            float fade = (float)sin((1.0f - time_left * 0.5f) * 3.141f);
            fade *= fade;
            if (fade > 1.0f) {
                fade = 1.0f;
            } else if (fade < 0.0f) {
                fade = 0.0f;
            }
            grim_set_color(1.0f, 1.0f, 1.0f, fade);
            grim_begin_batch();
            if (time_left <= 2.0f) {
                grim_draw_quad(grim_backbuffer_width * 0.5f - 64.0f,
                               grim_backbuffer_height * 0.5f - 64.0f,
                               128.0f, 128.0f);
            }
            grim_end_batch();
            grim_d3d_device->Present(0, 0, 0, 0);
            grim_timing_update();
            time_left -= grim_get_frame_dt() * (CL_BUILD < 10300 ? 1.0f : 2.0f);
        } while (time_left > 0.0f);
#endif
        grim_set_config_var(texture_filter_config, (unsigned int)2);
#if CL_BUILD >= 10400
        grim_main_window_hwnd_ref = &grim_main_window_hwnd;
#endif
    }
#else
    grim_set_config_var(0x15, (unsigned int)2);
    grim_main_window_hwnd_ref = &grim_main_window_hwnd;

    grim_set_config_var(0x10, "crimson.paq");

    char *widths = grim_lookup_blob_find("load\\smallFnt.dat");
    if (widths != 0) {
        memcpy(grim_font2_glyph_widths, widths, 256);
    }
#endif

    return true;
}
