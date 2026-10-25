#pragma once
// What the game module asks of its host. Presentation calls return nothing, so
// the host observes the game without feeding back into it. The queries are wall
// time and the rendering mode, which a simulation tick never reads; files arrive
// through WASI.
#define HOST_IMPORT(name) __attribute__((import_module("host"), import_name(#name)))
extern "C" {
// Textures hold A8R8G8B8 texels. Flags: 1, a render target the device draws
// into; 2, no alpha channel (X8R8G8B8), so alpha reads as one.
HOST_IMPORT(texture_create) void host_texture_create(int id, int width, int height, int flags);
HOST_IMPORT(texture_upload) void host_texture_upload(int id, const void *texels);
HOST_IMPORT(texture_release) void host_texture_release(int id);
// Direct3D 8 render and texture stage states, by their D3DRENDERSTATETYPE and
// D3DTEXTURESTAGESTATETYPE values.
HOST_IMPORT(render_state) void host_render_state(int state, unsigned value);
HOST_IMPORT(texture_stage_state) void host_texture_stage_state(int stage, int state, unsigned value);
HOST_IMPORT(set_texture) void host_set_texture(int stage, int id);
// The back buffer the device draws into, at device creation and reset.
HOST_IMPORT(back_buffer) void host_back_buffer(int width, int height);
// Texture id, or 0 for the back buffer.
HOST_IMPORT(set_render_target) void host_set_render_target(int id);
HOST_IMPORT(clear) void host_clear(unsigned color);
// Pre-transformed vertices (x, y, z, rhw, D3DCOLOR, u, v: 28 bytes each) as a
// D3DPRIMITIVETYPE; indices are 16-bit, or null for a non-indexed draw.
HOST_IMPORT(draw) void host_draw(int primitive, const void *vertices, int vertex_count, const unsigned short *indices,
                                 int primitive_count);
HOST_IMPORT(present) void host_present(void);
// RTX, the rendering mode beyond the original's look (game/rtx.cpp): the mode
// the host shows of the one asked for (0 classic, 1 RTX), and the world's bounds
// in the frame, which the host draws into its HDR target and then tonemaps onto
// the back buffer.
HOST_IMPORT(render_mode) int host_render_mode(int requested);
#include "render_passes.h"
HOST_IMPORT(render_pass) void host_render_pass(int pass);
// The world's light sources, sent before its begin mark (game/rtx_lights.cpp):
// the view (the camera offset, world to screen; the run's clock in seconds; the
// terrain's size in world units; the beam sections' gains) and
// `count` lights of RTX_LIGHT_FLOATS each.
HOST_IMPORT(scene) void host_scene(const float *view, const float *lights, int count);
// RTX fluid smoke (game/rtx_smoke.cpp): the solver's passes as SMOKE_* commands,
// run in order on the host's field targets.
HOST_IMPORT(smoke) void host_smoke(const float *commands, int count);
// The field drawn over the world, after its sprites (render/rtx/smoke.py): the
// view (the field's rect on the back buffer in logical pixels, its world origin
// and size, its opacity), SMOKE_LIGHT_FLOATS per light and four floats per
// Sharpshooter sight (its near and far ends).
HOST_IMPORT(smoke_draw) void host_smoke_draw(const float *view, const float *lights, int light_count,
                                              const float *sights, int sight_count);
// Monster Vision's heat trails (render/rtx/heat_vision.py), sent before the
// world's begin mark: `count` footprints as world x, y, radius and warmth,
// stamped into a world-space buffer that fades by the run's clock (host_scene).
HOST_IMPORT(heat) void host_heat(const float *footprints, int count);
// The trail buffer added to the ground in view, at the world's transition `alpha`.
HOST_IMPORT(heat_trails) void host_heat_trails(float alpha);
// The explosions' pressure fronts (render/rtx/shockwaves.py), sent before the
// world's begin mark: `count` fronts as screen center x, y, radius and strength,
// which displace the world before it is tonemapped.
HOST_IMPORT(pressure) void host_pressure(const float *fronts, int count);
// Draws into the terrain until the next mark are its decals of a HOST_GROUND_*
// material, deposited at `seconds` on the run's clock (render/rtx/materials.py).
HOST_IMPORT(ground) void host_ground(int kind, float seconds);
// Their shadows: the creature body grid (render/rtx/reflection_occlusion.py) as
// `grid` (origin x, y, columns, or 0 for none, rows, cell size, and whether the
// shadows setting is on) and `count` floats of RGBA32F texels, or none.
HOST_IMPORT(occlusion) void host_occlusion(const float *grid, const float *values, int count);
// A bonus draw's material (src/crimson/render/rtx/shaders/bonus.frag) until the
// next pass: the shell (emblem 0) or an icon on it, the atlas's cell grid and
// the bonus's world position, the shell's center.
HOST_IMPORT(bonus) void host_bonus(int emblem, float grid_x, float grid_y, float center_x, float center_y);
// An RTX analytic beam quad (src/crimson/render/rtx/shaders/beam.frag): four
// corners as x, y, u, v (u and v in beam radii), its length in radii (negative
// for a head) and stamp spacing, and its D3DCOLOR, drawn with the current blend
// into the current target.
HOST_IMPORT(beam) void host_beam(const float *corners, float length, float step, unsigned color);
// Analytic glow/shell/plasma/arc: four x,y,u,v corners, effect.frag's kind,
// three vec4 shape parameters, and the original D3DCOLOR. Uses the current blend state.
HOST_IMPORT(effect) void host_effect(const float *corners, int kind, const float *params, unsigned color);
// Consecutive radial sprites, as triangles of device-layout vertices (28 bytes each).
HOST_IMPORT(effect_sprites) void host_effect_sprites(const void *vertices, int kind, int vertex_count);
// The last drawn frame, kept and shown again under what a replay draws over it
// while no tick draws (host/watch.inc): save the back buffer, or show the saved one.
enum {
  HOST_FRAME_SAVE = 1, HOST_FRAME_SHOW = 2,
  HOST_FRAME_ANCHOR_SAVE = 3, HOST_FRAME_ANCHOR_RESTORE = 4, HOST_FRAME_ANCHOR_DROP = 5
};
HOST_IMPORT(frame_hold) void host_frame_hold(int op);
// A render target's pixels copied into another texture, made like it if it is
// new: a replay keeps its terrain at points along the run (host/keyframes.inc).
HOST_IMPORT(texture_copy) void host_texture_copy(int destination, int source);
HOST_IMPORT(gamma_ramp) void host_gamma_ramp(const unsigned short *red, const unsigned short *green,
                                             const unsigned short *blue);
[[noreturn]] HOST_IMPORT(fatal) void host_fatal(const char *message);
// A message box the original shows the player (startup failures, warnings).
HOST_IMPORT(message) void host_message(const char *text, const char *caption);
HOST_IMPORT(time_ms) unsigned host_time_ms(void);
// A steady clock in milliseconds finer than one, which times the game's own
// work for its telemetry (host/coop.inc); nothing the game plays reads it.
HOST_IMPORT(clock_ms) double host_clock_ms(void);
// The leaderboard (host/ranked.inc): open the player's profile, signed in
// (game_login_challenge), upload the runs waiting in leaderboard/outbox/,
// fetch a board's scores for the high score screen (game_scores_request), or
// fetch a board run's replay to watch (game_replay_download, host/watch.inc).
#include "leaderboard_requests.h"
HOST_IMPORT(leaderboard) void host_leaderboard(int request);
}
