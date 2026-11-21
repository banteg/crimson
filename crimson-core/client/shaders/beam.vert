#version 330
// An RTX analytic beam's quad (host_beam) for the Python port's beam.frag: corners in logical pixels with their
// beam uv, and per-vertex color, length and stamp spacing so consecutive beams batch into one draw.
#include "common.glsl"
layout(location = 0) in vec4 corner;      // x, y in pixels, u, v in beam radii
layout(location = 1) in vec4 beam_color;  // rgba
layout(location = 2) in vec2 beam_params; // length, step
uniform vec2 target_size;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
LOC(2) out float fragLen;
LOC(3) flat out float fragStep;
void main() {
    gl_Position = target_position(corner.xy, target_size);
    fragTexCoord = corner.zw;
    fragColor = beam_color;
    fragLen = beam_params.x;
    fragStep = beam_params.y;
}
