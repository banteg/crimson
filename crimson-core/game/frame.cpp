// The original's control flow, handed to a host that owns the main loop:
// crimsonland_main up to Grim's run loop (game_start, host/game.inc), then one
// pass of that loop per host frame (app/run_loop.cpp), then the code after the loop. The window messages
// Grim's window procedure handled arrive here as calls.
#include <string.h>
#include <windows.h>
#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"
#include "grim_d3d8.h"
#include "grim_joystick_state.h"
#include "grim_timing.h"

class GrimInputProvider {
public:
  virtual void unused_0(void) = 0;
  virtual void unused_1(void) = 0;
  virtual void unused_2(void) = 0;
  virtual void unused_3(void) = 0;
  virtual void unused_4(void) = 0;
  virtual void update(void) = 0;
};
extern IDirect3DDevice8 *grim_d3d_device;
extern unsigned char grim_dc_mode_active;
extern unsigned char grim_paused_flag;
extern unsigned char grim_device_ready;
extern unsigned char grim_keyboard_enabled;
extern unsigned char grim_input_cached;
extern unsigned char grim_device_restore_callback_pending;
extern unsigned char grim_render_disabled;
extern unsigned char grim_timing_frozen;
extern float grim_frame_dt;
extern float grim_key_repeat_timers[256];
extern float grim_mouse_x;
extern float grim_mouse_y;
extern float grim_mouse_x_cached;
extern float grim_mouse_y_cached;
extern GrimJoystickState grim_joystick_state;
extern GrimJoystickState *grim_joystick_state_ptr;
extern GrimInputProvider *grim_input_provider;
extern void (*grim_on_device_restore)(void);
extern bool (*grim_frame_callback)(void);
extern grim_config_value_t grim_config_values[128];
extern int grim_key_char_queue[8];
extern int grim_key_char_queue_count;
extern unsigned char *grim_key_char_buffer;
extern int *grim_key_char_buffer_count;
extern int grim_key_char_buffer_size;
void grim_timing_update(void);
bool grim_keyboard_poll(void);
bool grim_joystick_poll(void);
bool grim_mouse_poll(void);

extern "C" int crimsonland_main_exit(void);
extern "C" int game_live_frame(void);
extern "C" void game_live_quit(void);

static bool quit_posted;

#define GAME_EXPORT(name) extern "C" __attribute__((export_name(#name)))

// One pass of Grim's run loop; false once the game has quit.
GAME_EXPORT(game_frame) int game_frame() {
  if (quit_posted) {
    game_live_quit();
    return 0;
  }
  if (!grim_dc_mode_active)
    grim_timing_update();
  if (!grim_paused_flag && !grim_dc_mode_active && grim_device_ready && !grim_timing_frozen) {
    if (grim_keyboard_enabled) {
      grim_keyboard_poll();
      for (int i = 0; i < 256; ++i) {
        grim_key_repeat_timers[i] -= grim_frame_dt;
        if (grim_key_repeat_timers[i] < 0.0f)
          grim_key_repeat_timers[i] = 0.0f;
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
  if (grim_timing_frozen || grim_dc_mode_active || !grim_d3d_device)
    return 1;
  grim_device_ready = grim_d3d_device->TestCooperativeLevel() == D3D_OK;
  if (grim_device_restore_callback_pending) {
    ((bool (*)(void))grim_on_device_restore)();
    grim_device_restore_callback_pending = false;
  }
  // A run the client plays draws once per pass that ticks; the host shows the
  // last frame again for one that does not (host/session.inc).
  if (game_live_frame() == 0)
    return 1;
  if (!grim_frame_callback()) {
    quit_posted = true;
    game_live_quit();
    return 0;
  }
  if (grim_input_provider)
    grim_input_provider->update();
  if (!grim_render_disabled)
    grim_d3d_device->Present(nullptr, nullptr, nullptr, nullptr);
  return 1;
}

// What follows the run loop: saving, then shutdown.
GAME_EXPORT(game_exit) void game_exit() { crimsonland_main_exit(); }

// The screen the game shows (game_state_id_t).
GAME_EXPORT(game_state) int game_state() { return game_state_id; }

// WM_ACTIVATEAPP: losing the window freezes Grim's clock, so the loop stops
// running the game until it returns, and tells the game (it suspends audio).
// The device keeps its textures, so there is nothing to back up or restore.
// Grim stores the callbacks as void functions, but every one the game or Grim
// registers returns a flag, and wasm calls through a pointer by its exact type.
extern void (*grim_on_device_lost)(void);
GAME_EXPORT(game_activate) void game_activate(int active) {
  if (active) {
    if (grim_d3d_device)
      ((bool (*)(void))grim_on_device_restore)();
    grim_timing_frozen = false;
  } else {
    if (grim_d3d_device)
      ((bool (*)(void))grim_on_device_lost)();
    grim_timing_frozen = true;
    grim_device_ready = false;
  }
}

// WM_CLOSE.
GAME_EXPORT(game_close) void game_close() { quit_posted = true; }

// The game keeps its own cursor, moved by DirectInput motion scaled by the mouse
// sensitivity (game_frame_update). A host with an absolute pointer asks for the
// motion that brings it there.
extern "C" float ui_mouse_x, ui_mouse_y;
GAME_EXPORT(game_motion_x) float game_motion_x(float x) {
  float scale = config_blob.mouse_sensitivity * 2.0f;
  return scale > 0 ? (x - ui_mouse_x) / scale : 0;
}
GAME_EXPORT(game_motion_y) float game_motion_y(float y) {
  float scale = config_blob.mouse_sensitivity * 2.0f;
  return scale > 0 ? (y - ui_mouse_y) / scale : 0;
}

// WM_MOUSEMOVE: the window cursor, used while Grim reads the system cursor.
GAME_EXPORT(game_mouse_move) void game_mouse_move(float x, float y) {
  if (grim_config_values[13]) {
    grim_mouse_x_cached = x;
    grim_mouse_y_cached = y;
  }
}

// WM_CHAR: typed text for the key-character queue and the bound text buffer.
GAME_EXPORT(game_key_char) void game_key_char(int character) {
  if ((unsigned char)character == 0xa7 || (unsigned char)character == 9)
    return;
  if (grim_key_char_queue_count < 7)
    grim_key_char_queue[grim_key_char_queue_count++] = character;
  if (!grim_key_char_buffer || !grim_key_char_buffer_count)
    return;
  if (character == 8) {
    if (*grim_key_char_buffer_count > 0) {
      --*grim_key_char_buffer_count;
      grim_key_char_buffer[*grim_key_char_buffer_count] = 0;
    } else {
      grim_key_char_buffer[0] = 0;
    }
  } else if (character != 13 && *grim_key_char_buffer_count < grim_key_char_buffer_size - 1) {
    grim_key_char_buffer[*grim_key_char_buffer_count] = (unsigned char)character;
    ++*grim_key_char_buffer_count;
    grim_key_char_buffer[*grim_key_char_buffer_count] = 0;
  }
}
