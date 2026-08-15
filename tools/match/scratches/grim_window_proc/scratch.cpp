#include <windows.h>

#include "grim2d_cpp.h"
#include "grim_texture.h"

#ifndef WM_MOUSEWHEEL
#define WM_MOUSEWHEEL 0x020a
#endif

class GrimInputDevice {
public:
    virtual void unused_0(void) = 0;
    virtual void unused_1(void) = 0;
    virtual void unused_2(void) = 0;
    virtual void unused_3(void) = 0;
    virtual void unused_4(void) = 0;
    virtual void unused_5(void) = 0;
    virtual void unused_6(void) = 0;
    virtual void unused_7(void) = 0;
    virtual long __stdcall Unacquire(void) = 0;
};

extern bool grim_dc_mode_active;
extern unsigned char grim_window_proc_dc_flag;
extern unsigned char grim_window_proc_paint_flag;
extern HWND grim_main_window_hwnd;
extern HICON grim_window_icon_handle;
extern unsigned char grim_device_ready;
extern unsigned char grim_timing_frozen;
extern unsigned char grim_device_restore_callback_pending;
extern GrimInputDevice *grim_keyboard_device;
extern GrimInputDevice *grim_mouse_device;
extern void (*grim_on_device_lost)(void);
extern void (*grim_on_device_restore)(void);
extern grim_config_value_t grim_config_values[128];
extern int grim_key_char_queue[8];
extern int grim_key_char_queue_count;
extern unsigned char *grim_key_char_buffer;
extern int *grim_key_char_buffer_count;
extern int grim_key_char_buffer_size;
extern unsigned char grim_mouse_button_cache[16];
extern float grim_mouse_x_cached;
extern float grim_mouse_y_cached;
extern float grim_mouse_wheel_delta_cached;

extern "C" void grim_noop(char *message, ...);
bool grim_restore_device_after_activation(void);
bool grim_backup_textures(void);
bool grim_restore_textures(void);
void grim_apply_render_state(void);

LRESULT CALLBACK grim_window_proc(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    if (grim_dc_mode_active) {
        grim_noop("WM_MESSAGE (dc)", message);
    } else {
        grim_noop("WM_MESSAGE (d3d)", message);
    }

    if (grim_dc_mode_active) {
        switch (message) {
        case WM_CANCELMODE:
            grim_noop("dc WM_CANCELMODE", 0);
            grim_backup_textures();
            break;

        case WM_PAINT: {
            PAINTSTRUCT paint;
            BeginPaint(grim_main_window_hwnd, &paint);
            EndPaint(grim_main_window_hwnd, &paint);
            grim_window_proc_paint_flag = 1;
            *(bool *)grim_config_values[0x57].words = true;
            break;
        }

        case WM_ACTIVATEAPP:
            if (wparam == 0) {
                grim_noop("dc WM_ACTIVATEAPP inactive", 0);
                grim_keyboard_device->Unacquire();
                grim_mouse_device->Unacquire();
                grim_timing_frozen = 1;
                if (grim_device_ready) {
                    grim_on_device_lost();
                    grim_backup_textures();
                }
                grim_device_ready = 0;
                return 0;
            }

            grim_noop("dc WM_ACTIVATEAPP active", 0);
            grim_restore_device_after_activation();
            if (grim_device_ready) {
                grim_restore_textures();
                grim_apply_render_state();
                grim_device_restore_callback_pending = 0;
            } else {
                grim_device_restore_callback_pending = 1;
            }
            grim_timing_frozen = 0;
            return 0;

        case WM_ACTIVATE:
            if (LOWORD(wparam) != WA_INACTIVE &&
                HIWORD(wparam) == 0) {
                grim_noop("dc WM_ACTIVATE active", 0);
                grim_restore_device_after_activation();
                if (grim_d3d_device != 0) {
                    grim_restore_textures();
                    grim_apply_render_state();
                    grim_device_restore_callback_pending = 0;
                } else {
                    grim_device_restore_callback_pending = 1;
                }
                grim_timing_frozen = 0;
                return 0;
            }

            grim_noop("dc WM_ACTIVATE inactive", 0);
            grim_keyboard_device->Unacquire();
            grim_mouse_device->Unacquire();
            grim_timing_frozen = 1;
            grim_on_device_lost();
            grim_backup_textures();
            grim_device_ready = 0;
            return 0;

        case WM_DESTROY:
        case WM_CLOSE:
            PostQuitMessage(
                grim_window_proc_dc_flag = grim_dc_mode_active = false);
            return 0;

        case WM_ERASEBKGND:
            return 1;
        }

        return DefWindowProcA(
            hwnd, message, wparam, lparam);
    }

    switch (message) {
        case WM_CLOSE:
            PostQuitMessage(0);
            return 0;

        case WM_ENTERSIZEMOVE:
            grim_timing_frozen = 1;
            grim_device_ready = 0;
            return 0;

        case WM_EXITSIZEMOVE:
            grim_timing_frozen = 0;
            return 0;

        case WM_CREATE:
            SendMessageA(
                grim_main_window_hwnd,
                WM_SETICON,
                ICON_BIG,
                (LPARAM)grim_window_icon_handle);
            SendMessageA(
                grim_main_window_hwnd,
                WM_SETICON,
                ICON_SMALL,
                (LPARAM)grim_window_icon_handle);
            grim_main_window_hwnd = hwnd;
            SetFocus(hwnd);
            break;

        case WM_SIZE:
            if (wparam == SIZE_MAXHIDE || wparam == SIZE_MINIMIZED) {
                grim_timing_frozen = 1;
                grim_device_ready = 0;
            } else {
                grim_timing_frozen = 0;
            }
            break;

        case WM_ACTIVATEAPP:
            if (wparam == 0) {
                grim_noop("WM_ACTIVATEAPP inactive", 0);
                if (!grim_device_ready) {
                    grim_noop("d3d not ready!", 0);
                }
                if (grim_d3d_device != 0) {
                    grim_backup_textures();
                    grim_on_device_lost();
                }
                grim_keyboard_device->Unacquire();
                grim_mouse_device->Unacquire();
                grim_timing_frozen = 1;
                grim_device_ready = 0;
            } else {
                grim_noop("WM_ACTIVATEAPP active", 0);
                if (!grim_device_ready) {
                    grim_noop("d3d not ready!", 0);
                }
                if (grim_device_ready) {
                    grim_restore_textures();
                    grim_apply_render_state();
                    grim_on_device_restore();
                    grim_device_restore_callback_pending = 0;
                } else {
                    grim_device_restore_callback_pending = 1;
                }
                grim_timing_frozen = 0;
            }
            return 0;

        case WM_ACTIVATE:
            if (LOWORD(wparam) != WA_INACTIVE && HIWORD(wparam) == 0) {
                grim_noop("WM_ACTIVATE active", 0);
                if (!grim_device_ready) {
                    grim_noop("d3d not ready!", 0);
                }
                if (grim_device_ready) {
                    grim_restore_textures();
                    grim_apply_render_state();
                    grim_on_device_restore();
                    grim_device_restore_callback_pending = 0;
                } else {
                    grim_device_restore_callback_pending = 1;
                }
                grim_timing_frozen = 0;
            } else {
                grim_noop("WM_ACTIVATE inactive", 0);
                if (!grim_device_ready) {
                    grim_noop("d3d not ready!", 0);
                }
                if (grim_d3d_device != 0) {
                    grim_backup_textures();
                    grim_on_device_lost();
                }
                grim_keyboard_device->Unacquire();
                grim_mouse_device->Unacquire();
                grim_timing_frozen = 1;
                grim_device_ready = 0;
            }
            return 0;

        case WM_CHAR:
            if ((unsigned char)wparam != 0xa7 &&
                (unsigned char)wparam != 9) {
                if (grim_key_char_queue_count < 7) {
                    grim_key_char_queue[grim_key_char_queue_count] = wparam;
                    ++grim_key_char_queue_count;
                }

                if (wparam == 8) {
                    if (*grim_key_char_buffer_count > 0) {
                        --*grim_key_char_buffer_count;
                        grim_key_char_buffer[*grim_key_char_buffer_count] = 0;
                    } else {
                        grim_key_char_buffer[0] = 0;
                    }
                } else if (wparam != 13 &&
                           *grim_key_char_buffer_count <
                               grim_key_char_buffer_size - 1) {
                    grim_key_char_buffer[*grim_key_char_buffer_count] =
                        (unsigned char)wparam;
                    ++*grim_key_char_buffer_count;
                    grim_key_char_buffer[*grim_key_char_buffer_count] = 0;
                }
            }
            break;

        case WM_CANCELMODE:
            grim_noop("WM_CANCELMODE", 0);
            grim_backup_textures();
            break;

        case WM_SYSCOMMAND:
            switch (wparam) {
            case SC_SIZE:
            case SC_MOVE:
            case SC_MAXIMIZE:
            case SC_SCREENSAVE:
            case SC_MONITORPOWER:
                if (!grim_config_values[8]) {
                    return 1;
                }
                break;
            }
            break;

        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
            return 1;

        case WM_MOUSEMOVE:
            if (grim_config_values[13]) {
                grim_mouse_x_cached = (float)(short)LOWORD(lparam);
                grim_mouse_y_cached = (float)(short)HIWORD(lparam);
            }
            break;

        case WM_LBUTTONDOWN:
            if (grim_config_values[13]) {
                grim_mouse_button_cache[0] = 1;
            }
            break;

        case WM_MBUTTONDOWN:
            if (grim_config_values[13]) {
                grim_mouse_button_cache[2] = 1;
            }
            break;

        case WM_RBUTTONDOWN:
            if (grim_config_values[13]) {
                grim_mouse_button_cache[1] = 1;
            }
            break;

        case WM_LBUTTONUP:
            if (grim_config_values[13]) {
                grim_mouse_button_cache[0] = 0;
            }
            break;

        case WM_MBUTTONUP:
            if (grim_config_values[13]) {
                grim_mouse_button_cache[2] = 0;
            }
            break;

        case WM_RBUTTONUP:
            if (grim_config_values[13]) {
                grim_mouse_button_cache[1] = 0;
            }
            break;

        case WM_MOUSEWHEEL:
            if (grim_config_values[13]) {
                grim_mouse_wheel_delta_cached =
                    (float)(short)HIWORD(wparam);
            }
            break;

    }

    return DefWindowProcA(hwnd, message, wparam, lparam);
}
