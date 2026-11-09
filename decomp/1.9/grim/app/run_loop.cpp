#include <string.h>
#include <windows.h>
#include <mmsystem.h>

#include "grim_d3d8.h"
#include "grim_joystick_state.h"
#include "grim_timing.h"
#include "grim_texture.h"

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

#if CL_BUILD < 10900
void grim_apply_render_state(void);
bool grim_restore_textures(void);

static inline void grim_release_frame_targets(void)
{
    if (grim_render_target_surface && grim_render_target_surface->Release() <= 0) {
        grim_render_target_surface = 0;
    }
    if (grim_backbuffer_surface && grim_backbuffer_surface->Release() <= 0) {
        grim_backbuffer_surface = 0;
    }
    for (int i = 0; i <= grim_texture_slot_max_index; ++i) {
        if (grim_texture_slots[i] && grim_texture_slots[i]->owns_texture &&
            grim_texture_slots[i]->texture && grim_texture_slots[i]->texture->Release() <= 0) {
            grim_texture_slots[i]->texture = 0;
        }
    }
}

static inline void grim_recreate_frame_targets(void)
{
    for (int j = 0; j <= grim_texture_slot_max_index; ++j) {
        if (grim_texture_slots[j] && grim_texture_slots[j]->owns_texture &&
            grim_d3d_device->CreateTexture(
                grim_texture_slots[j]->width, grim_texture_slots[j]->height,
                1, D3DUSAGE_RENDERTARGET, grim_texture_format, D3DPOOL_DEFAULT,
                &grim_texture_slots[j]->texture) < 0) {
            grim_error_text = "D3D: Unable to recreate a texture.";
#if CL_BUILD < 10300
            while (MessageBoxA(0, grim_error_text, "Grim", MB_RETRYCANCEL) == IDRETRY) {
            }
            break;
#else
            grim_texture_slots[j]->texture = 0;
#endif
        }
    }
}
#endif

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
#if CL_BUILD >= 10900
    grim_app.init();
    SetFocus(grim_main_window_hwnd);
    SetForegroundWindow(grim_main_window_hwnd);
#endif

    if (grim_main_window_hwnd != 0) {
        while (msg.message != WM_QUIT) {
            if (PeekMessageA(&msg, 0, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            } else {
#if CL_BUILD >= 10900
                if (!grim_dc_mode_active) {
                    grim_timing_update();
                }

                if (!grim_paused_flag &&
                    !grim_dc_mode_active &&
                    grim_device_ready &&
                    !grim_timing_frozen) {
#else
                grim_timing_update();
                if (grim_device_ready && !grim_timing_frozen) {
#endif
#if CL_BUILD >= 10400
                    if (grim_keyboard_enabled) {
                        grim_keyboard_poll();
                        for (int i = 0; i < 256; ++i) {
                            grim_key_repeat_timers[i] -= grim_frame_dt;
                            if (grim_key_repeat_timers[i] < 0.0f) {
                                grim_key_repeat_timers[i] = 0.0f;
                            }
                        }
                    }
#else
                    grim_keyboard_poll();
#endif
#if CL_BUILD >= 10300
                    grim_joystick_poll();
                    grim_joystick_state_ptr = &grim_joystick_state;
#endif
                    if (!grim_input_cached) {
                        grim_mouse_x_cached = grim_mouse_x;
                        grim_mouse_y_cached = grim_mouse_y;
                        grim_mouse_poll();
                    }
                }

                grim_device_ready = false;
#if CL_BUILD >= 10900
                if (grim_dc_mode_active) {
                    grim_timing_frozen = true;
                    grim_app.pump();
                }
#endif

                if (!grim_timing_frozen) {
#if CL_BUILD >= 10900
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
#else
                    if (grim_d3d_device != 0) {
                        HRESULT status = grim_d3d_device->TestCooperativeLevel();
                        grim_device_ready = status == D3D_OK;
                        if (!grim_device_ready) {
                            if (status == D3DERR_DEVICENOTRESET) {
                                grim_release_frame_targets();
                                if (grim_d3d_device->Reset(&grim_present_parameters) == D3D_OK) {
                                    grim_apply_render_state();
                                    grim_recreate_frame_targets();
#if CL_BUILD < 10300
                                    if (!grim_restore_textures()) {
                                        while (MessageBoxA(0, grim_error_text, "Grim", MB_RETRYCANCEL) == IDRETRY) {
                                        }
                                        break;
                                    }
#else
                                    grim_restore_textures();
#endif
                                } else {
                                    grim_error_text = "D3D: Unable to restore device.";
#if CL_BUILD < 10300
                                    if (MessageBoxA(0, grim_error_text, "Grim", MB_RETRYCANCEL) == IDCANCEL) {
                                        break;
                                    }
#else
                                    if (MessageBoxA(grim_main_window_hwnd, grim_error_text, "Grim", MB_RETRYCANCEL) == IDCANCEL) {
                                        break;
                                    }
#endif
                                }
                            }
#endif
                        } else {
#if CL_BUILD >= 10300
                            if (grim_device_restore_callback_pending) {
                                grim_on_device_restore();
                                grim_device_restore_callback_pending = false;
                            }
#endif
                            if (!grim_frame_callback()) {
                                break;
                            }
#if CL_BUILD >= 10900
                            if (grim_input_provider != 0) {
                                grim_input_provider->update();
                            }
#endif
#if CL_BUILD >= 10400
                            if (!grim_render_disabled) {
                                grim_d3d_device->Present(0, 0, 0, 0);
                            }
#else
                            grim_d3d_device->Present(0, 0, 0, 0);
#endif
                        }
                    }
#if CL_BUILD >= 10900
                } else if (!grim_dc_mode_active) {
#else
                } else {
#endif
                    Sleep(50);
                }
            }
        }
    }

#if CL_BUILD >= 10900
    timeEndPeriod(1);
    grim_app.shutdown();
    if (grim_input_cached) {
        ShowCursor(TRUE);
    }
#endif
    grim_window_destroy();
    return 0;
}
