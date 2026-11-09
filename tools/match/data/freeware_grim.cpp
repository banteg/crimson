// Pre-startup Grim2D storage. The manifest identifies the matched functions
// that establish each object's width or pass its complete type to Windows.
#include <windows.h>

#include "grim2d_cpp.h"
#include "grim_joystick_input.h"
#include "grim_texture.h"
#include "grim_timing.h"
#include "grim_uv.h"

// grim_state_init initializes 128 records and a 16-by-16 atlas of UV pairs.
grim_config_value_t grim_config_default;
grim_config_value_t grim_config_values[128];
GrimUV grim_font2_uv_u[256];
GrimUV grim_uv_u0[4];
struct GrimDepth {
    float z, rhw;
};
GrimDepth grim_vertex_z;
unsigned int grim_color_slot0, grim_color_slot1, grim_color_slot2, grim_color_slot3;
unsigned int grim_mouse_button_latch[2];
char *grim_error_text;
char grim_empty_string;
void *grim_lookup_blob;
int grim_lookup_blob_size;
unsigned char grim_lookup_blob_loaded, grim_reserved_d3ac;
void (*grim_frame_callback)(void);

// grim_find_free_texture_slot visits 128 entries in 1.0.2 and 256 afterwards.
GrimTexture *grim_texture_slots[GRIM_TEXTURE_SLOT_CAPACITY];
int grim_texture_slot_max_index = -1;
int grim_bound_texture_handle = -1;
D3DFORMAT grim_texture_format, grim_preferred_texture_format;
IDirect3DTexture8 *grim_font_texture, *grim_splash_texture;
unsigned char grim_texture_backup_pending;

#pragma const_seg(".data")
extern const char grim_missing_frame_error_text[] = "System: No Frame Function defined.";
#pragma const_seg()

WNDCLASSEXA grim_window_class;
HINSTANCE grim_process_hinstance, grim_module_handle;
HICON grim_window_icon_handle;
HWND grim_main_window_hwnd;
char *grim_window_title;
bool grim_config_dialog_pure_software_selected, grim_config_dialog_windowed_selected;
bool grim_config_dialog_bpp16_selected, grim_config_dialog_canceled;

D3DCAPS8 grim_device_caps;
D3DPRESENT_PARAMETERS grim_present_parameters;
D3DDEVTYPE grim_d3d_device_type;
IDirect3D8 *grim_d3d8;
IDirect3DDevice8 *grim_d3d_device;
IDirect3DSurface8 *grim_backbuffer_surface, *grim_render_target_surface;
unsigned int grim_selected_adapter_index, grim_backbuffer_width, grim_backbuffer_height;
unsigned char grim_device_ready;

IDirect3DVertexBuffer8 *grim_vertex_buffer;
IDirect3DIndexBuffer8 *grim_index_buffer;
unsigned char *grim_vertex_write_ptr;
unsigned short *grim_index_write_ptr;
unsigned int grim_vertex_capacity;
unsigned short grim_vertex_count;
unsigned char grim_batch_active;
float grim_rotation_radians, grim_rotation_sin, grim_rotation_cos;

LARGE_INTEGER grim_tick_now, grim_tick_prev, grim_timing_epoch_ticks;
__int64 grim_time_ticks;
float grim_time_ms, grim_frame_dt, grim_fps, grim_ms_to_seconds_scale;
float grim_fps_sample_seconds;
DWORD grim_fps_sample_frames;
unsigned char grim_timing_frozen;

struct GrimKeyboardDevice;
struct GrimMouseDevice;
struct GrimMouseState {
    long lX, lY, lZ;
    unsigned char rgbButtons[8];
};
GrimDirectInput *grim_dinput_keyboard, *grim_dinput_mouse;
GrimKeyboardDevice *grim_keyboard_device;
GrimMouseDevice *grim_mouse_device;
unsigned char grim_keyboard_state[256], grim_key_repeat_first_press[256];
GrimMouseState grim_mouse_state;
float grim_mouse_x, grim_mouse_y, grim_mouse_wheel;
float grim_mouse_dx, grim_mouse_dy, grim_mouse_wheel_delta;
float grim_mouse_x_cached, grim_mouse_y_cached, grim_mouse_wheel_delta_cached;

#if CL_BUILD >= 10300
// GetAdapterIdentifier writes the SDK record including its Description member.
D3DADAPTER_IDENTIFIER8 grim_adapter_identifier;
IDirect3D8 *grim_d3d8_probe;
int grim_config_resolution_index;
void (*grim_on_device_restore)(void);
void (*grim_on_device_lost)(void);
unsigned char grim_device_restore_callback_pending;
GrimDirectInput *grim_dinput_joystick;
GrimJoystickDevice *grim_joystick_device;
GrimJoystickState grim_joystick_state;
bool grim_joystick_found;
#endif

#if CL_BUILD == 10400
struct GrimKeyboardEvent {
    DWORD dwOfs, dwData, dwTimeStamp, dwSequence;
    unsigned long uAppData;
};
GrimKeyboardEvent grim_keyboard_event_buffer[10];
float grim_key_repeat_timers[256];
float grim_key_repeat_delay = 0.5f;
unsigned char grim_caps_can_render_windowed = 1;
SYSTEMTIME grim_config_dialog_system_time;
HWND grim_device_window_override;
unsigned char grim_render_disabled;
#endif
