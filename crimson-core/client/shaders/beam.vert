#version 330
// An RTX analytic beam's quad (host_beam) for the Python port's beam.frag: corners in logical pixels with their
// beam uv, and the quad's length, stamp spacing and color.
#include "common.glsl"
layout(location = 0) in vec4 corner; // x, y in pixels, u, v in beam radii
uniform vec2 target_size;
uniform float beam_length, beam_step;
uniform vec4 beam_color;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
LOC(2) out float fragLen;
LOC(3) flat out float fragStep;
void main() {
    gl_Position = target_position(corner.xy, target_size);
    fragTexCoord = corner.zw;
    fragColor = beam_color;
    fragLen = beam_length;
    fragStep = beam_step;
}
