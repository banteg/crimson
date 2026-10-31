// RTX, the client's rendering mode beyond the original's look, after the Python
// port's src/crimson/render/rtx. The mode lives here, where the console's
// commands change it (rendermode, togglertx, registered by game/rtx/rtx.patch,
// beside rendersize for the host's render size);
// the host shows it, shades what the world's marks enclose and draws the beams
// sent in place of the original's stamped streaks. Nothing here reaches a run's
// state: only drawing reads the mode.
#include "crimsonland_console.h"
#include "crimsonland_types.h"
#include "grim2d_cpp.h"
#include "host_abi.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool platform_outputs();
extern IGrim2D_cpp *grim_interface_ptr;
extern "C" {
extern unsigned char grim_render_disabled, console_open_flag;
extern game_state_id_t game_state_id;
int console_cmd_argc_get(void);

int rtx_render_mode;
extern unsigned char run_active;
extern game_state_id_t game_state_id;
bool game_live_run();
__attribute__((export_name("game_render_mode_available"))) int game_render_mode_available() {
  return !game_live_run() && !run_active &&
         (game_state_id == GAME_STATE_MAIN_MENU || game_state_id == GAME_STATE_OPTIONS_MENU);
}
extern crimson_cfg_t config_blob;
extern int rtx_effects_active;
void rtx_effect_flush();
void rtx_glint_reset();
void rtx_debris_prepare();
void rtx_debris_reset();

static const char *rtx_mode_name(int mode) { return mode ? "rtx" : "classic"; }

void rtx_smoke_reset();
extern int rtx_smoke_on;

void rtx_reset();

static bool rtx_set_mode(int requested, bool launch = false) {
  static bool initialized;
  if (!(launch && !initialized) && !game_render_mode_available())
    return false;
  if (!initialized || requested != rtx_render_mode) {
    rtx_render_mode = platform_outputs() ? host_render_mode(requested) : 0;
    rtx_reset();
  }
  initialized = true;
  return true;
}

// The player's choice, kept in the game folder (the Python port's render/rtx/mode.py keeps the same file).
static const char rtx_choice_file[] = "render_mode.txt";

static int rtx_saved_mode() {
  char name[8] = {};
  if (FILE *fp = fopen(rtx_choice_file, "rb")) {
    fread(name, 1, sizeof name - 1, fp);
    fclose(fp);
  }
  return !strncmp(name, "rtx", 3);
}

// The player chooses a mode: the Options panel, the console, the page's switch. It is kept once drawn, so a host
// that only draws classic (WebGL2) leaves the choice for one that can.
void rtx_choose(int requested) {
  if (!rtx_set_mode(requested))
    return;
  if (!platform_outputs() || rtx_render_mode != requested)
    return;
  if (FILE *fp = fopen(rtx_choice_file, "wb")) {
    fprintf(fp, "%s\n", rtx_mode_name(rtx_render_mode));
    fclose(fp);
  }
}

// The mode the host's launch options ask for (--rtx, CRIMSON_RTX, the page's ?rtx=) for this launch only, or with
// none (-1) the player's choice.
__attribute__((export_name("game_render_mode"))) void game_render_mode(int mode) {
  rtx_set_mode(mode < 0 ? rtx_saved_mode() : mode, true);
}
__attribute__((export_name("game_render_choice"))) void game_render_choice(int mode) { rtx_choose(mode); }

static void rtx_report(int requested) {
  if (!game_render_mode_available()) {
    console_printf(&console_log_queue, "Change render mode from the main menu.\n");
    return;
  }
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
    rtx_choose(requested);
    rtx_report(requested);
  } else {
    console_printf(&console_log_queue, "rendermode <classic|rtx>\n");
  }
}

void console_cmd_toggle_rtx(void) {
  int requested = !rtx_render_mode;
  rtx_choose(requested);
  rtx_report(requested);
}

// rendersize <multiple|native>: the most the host draws, as a multiple of the
// game's resolution (at least 1), or every pixel of the display; the display
// scales the rest up.
void console_cmd_render_size(void) {
  char *name = console_cmd_argc_get() == 2 ? console_cmd_arg_get(1) : nullptr;
  if (name) {
    float limit = strcmp(name, "native") ? (float)atof(name) : 0;
    if (limit && limit < 1) {
      console_printf(&console_log_queue, "rendersize <multiple of the game's resolution, at least 1|native>\n");
      return;
    }
    host_render_size(limit);
  }
  float limit = host_render_size(-1);
  if (limit)
    console_printf(&console_log_queue, "Render size is at most %gx the game's resolution.\n", limit);
  else
    console_printf(&console_log_queue, "Render size is the display's.\n");
}

// rtxsmoke <on|off>: RTX's fluid smoke, on by default; off brings native puffs back.
void console_cmd_rtx_smoke(void) {
  char *name = console_cmd_argc_get() == 2 ? console_cmd_arg_get(1) : nullptr;
  if (name && (!strcmp(name, "on") || !strcmp(name, "off"))) {
    rtx_smoke_on = !strcmp(name, "on");
    rtx_smoke_reset();
  } else if (name) {
    console_printf(&console_log_queue, "rtxsmoke <on|off>\n");
    return;
  }
  console_printf(&console_log_queue, "RTX smoke is %s.\n", rtx_smoke_on ? "on" : "off");
}

bool rtx_drawing() { return rtx_render_mode && platform_outputs() && !grim_render_disabled; }

// RTX's diagnostic views (render/rtx/debug.py's RtxDebugView), presentation
// only: F6 steps to the next, Shift+F6 back, and the console's rtxdebug picks
// one. The host shows the ground's maps and the smoke's as they are, with
// nothing else of the world and no tonemap; no-direct only takes the ground's
// direct light away.
static const char *const rtx_debug_names[] = {
    "shaded",    "substrate-normal", "fluid-normal", "freshness",  "blood-depth",   "reflections",
    "direct",    "direct-unshadowed", "visibility",  "albedo",     "roughness",     "height",
    "materials", "ambient",          "no-direct",    "smoke-density", "smoke-heat", "smoke-flow",
    "smoke-light"};
static const char *const rtx_debug_help[] = {
    nullptr,
    "Diffuse normal: RGB = XYZ * 0.5 + 0.5",
    "Liquid normal: RGB = XYZ * 0.5 + 0.5",
    "Black = dry; white = fresh (45 s exponential decay)",
    "Exposed blood amount: black = none; white = deep",
    nullptr,
    nullptr,
    nullptr,
    "Direct-radiance weighted: white = visible; black = blocked; blue = no light",
    "Substrate color before blood absorption and lighting",
    "Black = smooth; white = rough",
    "Substrate height; blood never adds diffuse relief",
    "R = blood, G = corpse, B = brass; ice = cyan",
    nullptr,
    "Ground direct lighting removed; ordinary scene, reflections and display mapping",
    "Smoke opacity through the column: black = clear; white = opaque",
    "Smoke temperature: black = cold; red, yellow, white = hotter, taller columns",
    "Planar air velocity: hue = direction; brightness = speed",
    "Weapon and sight light scattered by smoke, no sky fill: c/(1+c), then gamma"};
enum { RTX_DEBUG_VIEWS = sizeof rtx_debug_names / sizeof *rtx_debug_names, RTX_DEBUG_NO_DIRECT = 14 };
static int rtx_debug_view;
// A view picked since the world last drew, which a paused replay draws again
// (host/watch.inc).
static bool rtx_debug_picked;

static void rtx_debug_pick(int view) {
  rtx_debug_view = view;
  rtx_debug_picked = true;
}
bool rtx_debug_redraw() { return rtx_drawing() && rtx_debug_picked; }

// Once a frame, outside the run's ticks, which read the replay's keys
// (game/frame.cpp).
void rtx_debug_keys() {
  if (!rtx_render_mode || console_open_flag || !grim_interface_ptr->grim_was_key_pressed(0x40)) // F6
    return;
  bool back = grim_interface_ptr->grim_is_key_down(0x2a) || grim_interface_ptr->grim_is_key_down(0x36); // Shift
  rtx_debug_pick((rtx_debug_view + (back ? RTX_DEBUG_VIEWS - 1 : 1)) % RTX_DEBUG_VIEWS);
}

void console_cmd_rtx_debug(void) {
  char *name = console_cmd_argc_get() == 2 ? console_cmd_arg_get(1) : nullptr;
  for (int view = 0; name && view < RTX_DEBUG_VIEWS; ++view)
    if (!strcmp(name, rtx_debug_names[view])) {
      rtx_debug_pick(view);
      console_printf(&console_log_queue, "RTX debug view is '%s'.\n", name);
      return;
    }
  char usage[320] = "rtxdebug <";
  for (int view = 0; view < RTX_DEBUG_VIEWS; ++view)
    snprintf(usage + strlen(usage), sizeof usage - strlen(usage), "%s%s", view ? "|" : "", rtx_debug_names[view]);
  console_printf(&console_log_queue, "%s>\n", usage);
}

// The view's name and how to read it, over the world's lower left.
static void rtx_debug_label() {
  if (!rtx_debug_view)
    return;
  char title[96];
  snprintf(title, sizeof title, "RTX / %s    F6 next / Shift+F6 previous", rtx_debug_names[rtx_debug_view]);
  const char *help = rtx_debug_help[rtx_debug_view] ? rtx_debug_help[rtx_debug_view]
                                                    : "Linear contribution mapped as c/(1+c), then gamma encoded";
  IGrim2D_cpp *grim = grim_interface_ptr;
  float y = fmaxf(8, (float)config_blob.screen_height - 104);
  float width = fminf((float)config_blob.screen_width - 16,
                      fmaxf(grim->grim_measure_text_width(title), grim->grim_measure_text_width((char *)help)) + 20);
  float pos[2] = {8, y}, back[4] = {0, 0, 0, 220 / 255.0f};
  grim->grim_draw_rect_filled(pos, width, 52, back);
  grim->grim_set_color(1, 1, 1, 1);
  grim->grim_draw_text_small(18, y + 8, title);
  grim->grim_set_color(200 / 255.0f, 200 / 255.0f, 200 / 255.0f, 1);
  grim->grim_draw_text_small(18, y + 28, (char *)help);
}

int rtx_collect_lights(float *out, int capacity);
extern const float rtx_beam_gain[2];
int rtx_collect_heat(float *out, int capacity);
int rtx_collect_fronts(float *out, int capacity);
void rtx_lights_reset();
extern float ui_transition_alpha;
const float *rtx_build_occlusion(const float *lights, int count, bool shadows, float *grid, int *value_count);
extern vec2f_t camera_offset;
extern int terrain_texture_width, terrain_texture_height;
extern int run_elapsed_ms;
float rtx_ground_ms = -1;

// The run's clock, which wet blood ages by: presentation time, slow motion
// included, paused with the run; or a logged bake's own time while a replay's
// seek bakes it again (host/keyframes.inc).
static float rtx_seconds() { return (rtx_ground_ms >= 0 ? rtx_ground_ms : (float)run_elapsed_ms) * 0.001f; }
// Results reuse run_elapsed_ms for the bonus-adjusted score. Frozen worlds and
// retained menu ground keep the last gameplay presentation time instead.
static float rtx_presentation_seconds;

// A restore can return a held frame straight to a menu without drawing gameplay.
void rtx_restore_clock() { rtx_presentation_seconds = (float)run_elapsed_ms * 0.001f; }

// The frame's lights, collected as the world begins.
static float rtx_lights[32 * RTX_LIGHT_FLOATS];
static int rtx_light_count;

// The world's bounds in the frame (game/rtx/rtx.patch): what Grim batched before
// a bound belongs to the side it was drawn on. The world's lights go first.
// Classic marks the bounds too, only so the host's timers can tell its drawing
// from the frame's simulation and HUD.
static void rtx_world_pass(int begin, bool menu) {
  if (begin && !menu) {
    if (game_state_id == GAME_STATE_GAMEPLAY || game_state_id == GAME_STATE_TYPO_GAMEPLAY)
      rtx_presentation_seconds = rtx_seconds();
    rtx_glint_reset();
    rtx_debris_prepare();
  }
  if (!platform_outputs() || grim_render_disabled)
    return;
  grim_interface_ptr->grim_flush_batch();
  if (!rtx_render_mode) {
    host_render_pass(begin ? HOST_PASS_WORLD_BEGIN : HOST_PASS_WORLD_END);
    return;
  }
  if (begin) {
    rtx_effects_active = !menu;
    int count = rtx_light_count = menu ? 0 : rtx_collect_lights(rtx_lights, 32);
    const float *lights = rtx_lights;
    const float view[8] = {camera_offset.x, camera_offset.y, rtx_presentation_seconds, (float)terrain_texture_width,
                           (float)terrain_texture_height, rtx_beam_gain[0], rtx_beam_gain[1], (float)(menu ? 0 : rtx_debug_view)};
    host_scene(view, lights, count);
    float grid[6];
    int value_count;
    bool shadows = config_blob.shadows_enabled;
    const float *values = rtx_build_occlusion(lights, count, shadows, grid, &value_count);
    grid[5] = shadows;
    host_occlusion(grid, values, value_count);
    static float footprints[385 * 4];
    host_heat(footprints, menu ? 0 : rtx_collect_heat(footprints, 385));
    static float fronts[16 * 4];
    // A diagnostic map shows its values where they are.
    bool map = rtx_debug_view && rtx_debug_view != RTX_DEBUG_NO_DIRECT;
    host_pressure(fronts, !menu && ui_transition_alpha > 1e-3f && !map ? rtx_collect_fronts(fronts, 16) : 0);
    rtx_debug_picked = false;
  }
  host_render_pass(begin ? HOST_PASS_WORLD_BEGIN : HOST_PASS_WORLD_END);
  if (!begin) {
    rtx_effects_active = 0;
    if (!menu)
      rtx_debug_label();
  }
}

void rtx_world(int begin) { rtx_world_pass(begin, false); }
void rtx_menu_world(int begin) { rtx_world_pass(begin, true); }

// The fluid smoke field after the world's sprites, at its transition `alpha`.
bool rtx_smoke_active();
void rtx_smoke_draw(const float *lights, int light_count, float alpha);
void rtx_smoke(float alpha) {
  if (!rtx_drawing() || !rtx_smoke_active())
    return;
  grim_interface_ptr->grim_flush_batch();
  rtx_smoke_draw(rtx_lights, rtx_light_count, alpha);
}

// What RTX keeps beside a run, cleared when a run starts or is restored and
// when the mode changes: the fluid smoke and the lights' explosions and fades.
void rtx_smoke_reset();
void rtx_reset() {
  // Effect history resets independently of the retained terrain's presentation time.
  rtx_effects_active = 0;
  rtx_effect_flush();
  rtx_smoke_reset();
  rtx_lights_reset();
  rtx_debris_reset();
}

// The batches the host lights (HOST_PASS_CREATURES, _PLAYERS), and the return to
// the device's own shading (HOST_PASS_SPRITES).
void rtx_material(int pass) {
  if (!rtx_drawing())
    return;
  grim_interface_ptr->grim_flush_batch();
  host_render_pass(pass);
}

// The terrain's decals by material (fx_queue_render): a mark only where the
// material changes, so a run of one material stays one batch.
void rtx_ground(int kind) {
  static int marked = HOST_GROUND_END;
  if (!rtx_drawing() || kind == marked)
    return;
  grim_interface_ptr->grim_flush_batch();
  host_ground(kind, rtx_seconds());
  marked = kind;
}

// A queued decal's material, by its effect (render/rtx/materials.py): blood
// splatters, casings, scorches (black), freeze shards and their shatter.
void rtx_ground_decal(int effect_id, float red) {
  rtx_ground(effect_id >= 3 && effect_id <= 7                       ? HOST_GROUND_BLOOD
             : effect_id == 0x12                                    ? HOST_GROUND_BRASS
             : effect_id == 0x10 && red <= 0.05f                    ? HOST_GROUND_SCORCH
             : (effect_id >= 8 && effect_id <= 10) || effect_id == 0xe ? HOST_GROUND_ICE
                                                                    : HOST_GROUND_DECAL);
}

// The freeze's ice among the effects (effects_render): the shatter's cubes and
// shards lit as ice, a mark only where the material changes, so the effects keep
// their order. -1 after the last returns to sprites.
void rtx_ice(int effect_id) {
  static int marked = HOST_PASS_SPRITES;
  int pass = effect_id == 0xe                       ? HOST_PASS_ICE_CUBES
             : effect_id >= 8 && effect_id <= 10 ? HOST_PASS_ICE_SHARDS
                                                 : HOST_PASS_SPRITES;
  if (!rtx_drawing() || pass == marked)
    return;
  rtx_material(pass);
  marked = pass;
}

// One bonus quad in its material (host_bonus): each carries its own shell center.
void rtx_bonus(int emblem, float grid_x, float grid_y, float center_x, float center_y) {
  if (!rtx_drawing())
    return;
  grim_interface_ptr->grim_flush_batch();
  host_bonus(emblem, grid_x, grid_y, center_x, center_y);
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
