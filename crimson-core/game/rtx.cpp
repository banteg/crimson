// RTX, the client's rendering mode beyond the original's look, after the Python
// port's src/crimson/render/rtx. The mode lives here, where the console's
// commands change it (rendermode, togglertx, registered by game/rtx/rtx.patch);
// the host shows it, shades what the world's marks enclose and draws the beams
// sent in place of the original's stamped streaks. Nothing here reaches a run's
// state: only drawing reads the mode.
#include "crimsonland_console.h"
#include "crimsonland_types.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <math.h>
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

static bool rtx_drawing() { return rtx_render_mode && platform_outputs() && !grim_render_disabled; }

int rtx_collect_lights(float *out, int capacity);
extern vec2f_t camera_offset;

// The world's bounds in the frame (game/rtx/rtx.patch): what Grim batched before
// a bound belongs to the side it was drawn on. The world's lights go first.
void rtx_world(int begin) {
  if (!rtx_drawing())
    return;
  grim_interface_ptr->grim_flush_batch();
  if (begin) {
    static float lights[32 * 16];
    int count = rtx_collect_lights(lights, 32);
    const float camera[2] = {camera_offset.x, camera_offset.y};
    host_scene(camera, lights, count);
  }
  host_render_pass(begin ? HOST_PASS_WORLD_BEGIN : HOST_PASS_WORLD_END);
}

// The batches the host lights (HOST_PASS_CREATURES, _PLAYERS), and the return to
// the device's own shading (HOST_PASS_SPRITES).
void rtx_material(int pass) {
  if (!rtx_drawing())
    return;
  grim_interface_ptr->grim_flush_batch();
  host_render_pass(pass);
}

// Analytic beams, from src/crimson/render/rtx/beam.py: an ion or Fire Bullets
// streak's stamps summed along one quad, and its head as one stamp, in screen
// pixels at the original's scale. Grim's batch draws first, keeping the order.
static const float RTX_BEAM_RADIUS = 16.0f;
static const float RTX_HEAD_RADIUS = 1.05f, RTX_FIRE_HEAD_RADIUS = 1.35f;

static float rtx_clamp(float value, float low, float high) { return value < low ? low : value > high ? high : value; }

static unsigned rtx_color(float r, float g, float b, float a) {
  auto byte = [](float v) { return (unsigned)(rtx_clamp(v * 255.0f, 0.0f, 255.0f) + 0.5f); };
  return byte(a) << 24 | byte(r) << 16 | byte(g) << 8 | byte(b);
}

// A quad from `tail` to `head` along unit `direction`, `radius` wide on each side,
// its u running from -1 past the tail to `u_end` past the head.
static void rtx_beam_quad(float tail_x, float tail_y, float head_x, float head_y, float dx, float dy, float radius,
                          float u_end, float length, float step, unsigned color) {
  // The left perpendicular, as Vec2.perp_left.
  float sx = -dy * radius, sy = dx * radius;
  const float corners[16] = {tail_x - sx, tail_y - sy, -1, -1,    tail_x + sx, tail_y + sy, -1, 1,
                             head_x + sx, head_y + sy, u_end, 1, head_x - sx, head_y - sy, u_end, -1};
  grim_interface_ptr->grim_flush_batch();
  host_beam(corners, length, step, color);
}

// The streak's last `span` units of the path from `origin` to `head`, `start`
// units along it, with stamps every `step` units.
void rtx_beam_body(float origin_x, float origin_y, float head_x, float head_y, float start, float span, float step,
                   float effect_scale, float alpha, float r, float g, float b) {
  float ray_x = head_x - origin_x, ray_y = head_y - origin_y;
  if (!rtx_drawing() || span <= 1e-6f || sqrtf(ray_x * ray_x + ray_y * ray_y) <= 1e-6f)
    return;
  float start_t = rtx_clamp(start / fmaxf(1e-6f, start + span), 0, 1);
  float x0 = origin_x + ray_x * start_t, y0 = origin_y + ray_y * start_t;
  float length = sqrtf((head_x - x0) * (head_x - x0) + (head_y - y0) * (head_y - y0));
  unsigned color = rtx_color(r, g, b, alpha);
  if (length <= 1e-6f || !(color >> 24))
    return;
  float dx = (head_x - x0) / length, dy = (head_y - y0) / length;
  float radius = fmaxf(0.001f, RTX_BEAM_RADIUS * effect_scale);
  float step_uv = fmaxf(1e-4f, fmaxf(1e-6f, step * length / fmaxf(1e-6f, span)) / radius);
  float length_uv = length / radius;
  rtx_beam_quad(x0 - dx * radius, y0 - dy * radius, head_x + dx * radius, head_y + dy * radius, dx, dy, radius,
                length_uv + 1, length_uv, step_uv, color);
}

// The head at `center`, facing `rotation`, in the color Grim was last given
// (the streak's own head colors, original bug 41 included).
void rtx_beam_head(float center_x, float center_y, float rotation, float effect_scale, bool fire) {
  extern unsigned long grim_color_slot0[4];
  unsigned color = (unsigned)grim_color_slot0[0];
  if (!rtx_drawing() || !(color >> 24))
    return;
  float radius = fmaxf(0.001f, RTX_BEAM_RADIUS * effect_scale * (fire ? RTX_FIRE_HEAD_RADIUS : RTX_HEAD_RADIUS));
  float dx = cosf(rotation), dy = sinf(rotation);
  rtx_beam_quad(center_x - dx * radius, center_y - dy * radius, center_x + dx * radius, center_y + dy * radius, dx, dy,
                radius, 1, -1, 0, color);
}
}
