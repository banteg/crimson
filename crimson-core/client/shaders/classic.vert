#version 330
// The device's pre-transformed vertices (host_draw).
#include "common.glsl"
layout(location = 0) in vec4 position; // x, y, z, rhw in pixels
layout(location = 1) in vec4 diffuse;  // D3DCOLOR bytes: b, g, r, a
layout(location = 2) in vec2 uv;
uniform vec2 target_size;
LOC(0) out vec4 v_diffuse;
LOC(1) out vec2 v_uv;
void main() {
    gl_Position = target_position(position.xy, target_size);
    v_diffuse = diffuse.zyxw;
    v_uv = uv;
}
