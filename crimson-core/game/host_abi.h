#pragma once
// What the game module asks of its host. Presentation calls return nothing, so
// the host observes the game without feeding back into it; the queries are wall
// time and asset bytes, which a simulation tick never reads.
#define HOST_IMPORT(name) __attribute__((import_module("host"), import_name(#name)))
extern "C" {
// Textures hold A8R8G8B8 texels; a render target is a texture the host can draw into.
HOST_IMPORT(texture_create) void host_texture_create(int id, int width, int height, int render_target);
HOST_IMPORT(texture_upload) void host_texture_upload(int id, const void *texels);
HOST_IMPORT(texture_release) void host_texture_release(int id);
// Direct3D 8 render and texture stage states, by their D3DRENDERSTATETYPE and
// D3DTEXTURESTAGESTATETYPE values.
HOST_IMPORT(render_state) void host_render_state(int state, unsigned value);
HOST_IMPORT(texture_stage_state) void host_texture_stage_state(int stage, int state, unsigned value);
HOST_IMPORT(set_texture) void host_set_texture(int stage, int id);
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
HOST_IMPORT(time_ms) unsigned host_time_ms(void);
// An asset's size, or -1 when the host has none by that name; then its bytes.
HOST_IMPORT(file_size) int host_file_size(const char *name);
HOST_IMPORT(file_read) void host_file_read(const char *name, void *bytes);
}
