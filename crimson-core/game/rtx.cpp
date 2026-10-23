// RTX, the client's rendering mode beyond the original's look, after the Python
// port's src/crimson/render/rtx. The mode lives here, where the console's
// commands change it (rendermode, togglertx, registered by game/rtx/rtx.patch);
// the host shows it and shades what the world's marks enclose. Nothing here
// reaches a run's state: only drawing reads the mode.
#include "crimsonland_console.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <string.h>

bool platform_outputs();
extern IGrim2D_cpp *grim_interface_ptr;
extern "C" {
extern unsigned char grim_render_disabled;
int console_cmd_argc_get(void);

int rtx_render_mode;

static const char *rtx_mode_name(int mode) { return mode ? "rtx" : "classic"; }

static void rtx_set_mode(int requested) {
  rtx_render_mode = platform_outputs() ? host_render_mode(requested) : 0;
}

// The mode the host's launch options ask for (--rtx, CRIMSON_RTX).
__attribute__((export_name("game_render_mode"))) void game_render_mode(int mode) { rtx_set_mode(mode); }

static void rtx_report(int requested) {
  if (rtx_render_mode != requested)
    console_printf(&console_log_queue, "Render mode '%s' is not available here.\n", rtx_mode_name(requested));
  console_printf(&console_log_queue, "Render mode set to '%s'.\n", rtx_mode_name(rtx_render_mode));
}

void console_cmd_render_mode(void) {
  int argc = console_cmd_argc_get();
  char *name = argc == 2 ? console_cmd_arg_get(1) : nullptr;
  if (argc == 1) {
    console_printf(&console_log_queue, "Render mode is '%s'.\n", rtx_mode_name(rtx_render_mode));
  } else if (name && (!strcmp(name, "classic") || !strcmp(name, "rtx"))) {
    int requested = !strcmp(name, "rtx");
    rtx_set_mode(requested);
    rtx_report(requested);
  } else {
    console_printf(&console_log_queue, "rendermode <classic|rtx>\n");
  }
}

void console_cmd_toggle_rtx(void) {
  int requested = !rtx_render_mode;
  rtx_set_mode(requested);
  rtx_report(requested);
}

// The world's bounds in the frame (game/rtx/rtx.patch): what Grim batched before
// a bound belongs to the side it was drawn on.
void rtx_world(int begin) {
  if (!rtx_render_mode || !platform_outputs() || grim_render_disabled)
    return;
  grim_interface_ptr->grim_flush_batch();
  host_render_pass(begin ? HOST_PASS_WORLD_BEGIN : HOST_PASS_WORLD_END);
}
}
