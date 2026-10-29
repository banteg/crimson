#version 330
#include "common.glsl"
LOC(0) in vec2 v_uv;
out vec4 color;
uniform sampler2D back_buffer, gamma;
// An RTX diagnostic map: its values go to the display as they are, past the device's gamma ramp.
uniform int map_view;
void main() {
    vec3 c = texture(back_buffer, v_uv).rgb;
    if (map_view != 0) {
        color = vec4(c, 1.0);
        return;
    }
    // The device's gamma ramp, one 256-entry table per channel, interpolated
    // between its levels: an 8-bit level lands on its own entry, and an RTX
    // back buffer keeps its finer steps. A highlight past white keeps its
    // excess over the ramp's white.
    vec3 sdr = min(c, 1.0);
    color = vec4(vec3(texture(gamma, vec2(sdr.r * 255.0 / 256.0 + 0.5 / 256.0, 0.5)).r,
                      texture(gamma, vec2(sdr.g * 255.0 / 256.0 + 0.5 / 256.0, 0.5)).g,
                      texture(gamma, vec2(sdr.b * 255.0 / 256.0 + 0.5 / 256.0, 0.5)).b) * max(c, 1.0), 1.0);
}
