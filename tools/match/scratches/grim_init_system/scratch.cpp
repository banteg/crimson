#include <string.h>
#include <windows.h>

#include "grim2d_cpp.h"
#include "grim_texture.h"

extern "C" __declspec(dllimport) char *__cdecl _getcwd(
    char *buffer, int max_length);

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
    memset(grim_working_dir, 0, sizeof(grim_working_dir));
    _getcwd(grim_working_dir, sizeof(grim_working_dir));

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

    if (grim_joystick_enabled == true) {
        bool initialized = grim_joystick_init(grim_main_window_hwnd);
        if (!initialized) {
            grim_error_text = "DI8: Could not initialize joystic.";
            grim_joystick_enabled = initialized;
        }
    }

    grim_timing_init();
    grim_timing_update();

    grim_set_config_var(0x15, 2);
    grim_main_window_hwnd_ref = &grim_main_window_hwnd;

    grim_set_config_var(0x10, "crimson.paq");

    char *widths = grim_lookup_blob_find("load\\smallFnt.dat");
    if (widths != 0) {
        memcpy(grim_font2_glyph_widths, widths, 256);
    }

    return true;
}
