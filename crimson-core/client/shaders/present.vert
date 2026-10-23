#version 330
// The back buffer to the window, whose row 0 is its bottom in OpenGL and its top in WebGPU.
#include "common.glsl"
LOC(0) out vec2 v_uv;
void main() {
    vec2 corner = corner_of(gl_VertexID);
    gl_Position = corner_position(corner);
#ifdef VULKAN
    v_uv = corner;
#else
    v_uv = vec2(corner.x, 1.0 - corner.y);
#endif
}
