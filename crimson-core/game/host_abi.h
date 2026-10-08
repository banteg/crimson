#pragma once
// What the game module asks of its host. Presentation calls return nothing, so
// the host observes the game without feeding back into it. The query is wall
// time, which a simulation tick never reads; files arrive through WASI.
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
HOST_IMPORT(gamma_ramp) void host_gamma_ramp(const unsigned short *red, const unsigned short *green,
                                             const unsigned short *blue);
HOST_IMPORT(fatal) [[noreturn]] void host_fatal(const char *message);
// A message box the original shows the player (startup failures, warnings).
HOST_IMPORT(message) void host_message(const char *text, const char *caption);
HOST_IMPORT(time_ms) unsigned host_time_ms(void);
// The leaderboard (host/ranked.inc): open the player's profile, signed in
// (game_login_challenge), or upload the runs waiting in leaderboard/outbox/.
enum { HOST_LEADERBOARD_PROFILE = 1, HOST_LEADERBOARD_UPLOAD = 2 };
HOST_IMPORT(leaderboard) void host_leaderboard(int request);
}
