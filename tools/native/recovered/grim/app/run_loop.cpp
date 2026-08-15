#include <string.h>
#include <windows.h>
#include <mmsystem.h>

#include "grim_d3d8.h"
#include "grim_joystick_state.h"
#include "grim_timing.h"

class MyApp {
public:
    bool init(void);
    void pump(void);
    void shutdown(void);
};

class GrimInputProvider {
public:
    virtual void unused_0(void) = 0;
    virtual void unused_1(void) = 0;
    virtual void unused_2(void) = 0;
    virtual void unused_3(void) = 0;
    virtual void unused_4(void) = 0;
    virtual void update(void) = 0;
};

extern MyApp grim_app;
extern HWND grim_main_window_hwnd;
extern IDirect3DDevice8 *grim_d3d_device;
extern unsigned char grim_dc_mode_active;
extern unsigned char grim_paused_flag;
extern unsigned char grim_device_ready;
extern unsigned char grim_keyboard_enabled;
extern unsigned char grim_input_cached;
extern unsigned char grim_device_restore_callback_pending;
extern unsigned char grim_render_disabled;
extern float grim_key_repeat_timers[256];
extern float grim_mouse_x;
extern float grim_mouse_y;
extern float grim_mouse_x_cached;
extern float grim_mouse_y_cached;
extern GrimJoystickState *grim_joystick_state_ptr;
extern GrimInputProvider *grim_input_provider;
extern void (*grim_on_device_restore)(void);
extern bool (*grim_frame_callback)(void);

void grim_timing_init(void);
void grim_timing_update(void);
bool grim_keyboard_poll(void);
bool grim_joystick_poll(void);
bool grim_mouse_poll(void);
HRESULT grim_try_reset_device(void);
BOOL grim_window_destroy(void);

extern "C" int grim_run_loop(void)
{
    MSG msg;
    memset(&msg, 0, sizeof(msg));
    PeekMessageA(&msg, 0, 0, 0, PM_NOREMOVE);

    grim_timing_init();
    grim_timing_update();
    grim_timing_init();
    grim_timing_update();
    grim_timing_update();
    grim_app.init();
    SetFocus(grim_main_window_hwnd);
    SetForegroundWindow(grim_main_window_hwnd);

    if (grim_main_window_hwnd != 0 && msg.message != WM_QUIT) {
        do {
            if (PeekMessageA(&msg, 0, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            } else {
                if (!grim_dc_mode_active) {
                    grim_timing_update();
                }

                if (!grim_paused_flag &&
                    !grim_dc_mode_active &&
                    grim_device_ready &&
                    !grim_timing_frozen) {
                    if (grim_keyboard_enabled) {
                        grim_keyboard_poll();
                        for (int i = 0; i < 256; ++i) {
                            float *timer = &grim_key_repeat_timers[i];
                            *timer -= grim_frame_dt;
                            if (*timer < 0.0f) {
                                *timer = 0.0f;
                            }
                        }
                    }

                    grim_joystick_poll();
                    grim_joystick_state_ptr = &grim_joystick_state;
                    if (!grim_input_cached) {
                        grim_mouse_x_cached = grim_mouse_x;
                        grim_mouse_y_cached = grim_mouse_y;
                        grim_mouse_poll();
                    }
                }

                grim_device_ready = false;
                if (grim_dc_mode_active) {
                    grim_timing_frozen = true;
                    grim_app.pump();
                }

                if (!grim_timing_frozen) {
                    if (!grim_dc_mode_active && grim_d3d_device != 0) {
                        grim_device_ready =
                            grim_d3d_device->TestCooperativeLevel() == D3D_OK;
                        if (!grim_device_ready) {
                            Sleep(500);
                            HRESULT status =
                                grim_d3d_device->TestCooperativeLevel();
                            grim_device_ready = status == D3D_OK;
                            if (status == D3DERR_DEVICENOTRESET &&
                                grim_try_reset_device() ==
                                    D3DERR_DEVICENOTRESET) {
                                break;
                            }
                        } else {
                            if (grim_device_restore_callback_pending) {
                                grim_on_device_restore();
                                grim_device_restore_callback_pending = false;
                            }
                            if (!grim_frame_callback()) {
                                break;
                            }
                            if (grim_input_provider != 0) {
                                grim_input_provider->update();
                            }
                            if (!grim_render_disabled) {
                                grim_d3d_device->Present(0, 0, 0, 0);
                            }
                        }
                    }
                } else if (!grim_dc_mode_active) {
                    Sleep(50);
                }
            }
        } while (msg.message != WM_QUIT);
    }

    timeEndPeriod(1);
    grim_app.shutdown();
    if (grim_input_cached) {
        ShowCursor(TRUE);
    }
    grim_window_destroy();
    return 0;
}
