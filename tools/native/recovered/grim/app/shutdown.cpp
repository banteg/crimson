#include "grim2d_cpp.h"

extern char grim_empty_string;

extern bool grim_lookup_blob_load(char *path);
extern void grim_mouse_shutdown(void);
extern void grim_keyboard_shutdown(void);
extern void grim_joystick_shutdown(void);
extern void grim_d3d_shutdown(void);
extern int grim_window_destroy(void);

void IGrim2D_cpp::grim_shutdown(void)
{
    grim_lookup_blob_load(&grim_empty_string);
    grim_mouse_shutdown();
    grim_keyboard_shutdown();
    grim_joystick_shutdown();
    grim_d3d_shutdown();
    grim_window_destroy();
}
