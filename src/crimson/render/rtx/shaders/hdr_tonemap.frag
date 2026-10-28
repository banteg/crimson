#version 330

// The RTX world's linear light to the display: one hue-preserving shoulder toward the display's EDR headroom, then
// the gamma-2.2 encoding the display and the original's artwork share. Shared with the client
// (crimson-core/client/shaders.py).
#include "linear_light.glsl"

in vec2 fragTexCoord;
in vec4 fragColor;

uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform float u_edr_headroom;

out vec4 finalColor;

// Below the knee (the original's 0.85 once encoded) the world shows as drawn.
const float KNEE = 0.7;
const float WHITE_DRIFT = 0.6;
const float WHITE_STOPS = 4.4;

// A rational shoulder: its slope eases from 1 at the knee, so highlights keep their gradation many times past the
// limit instead of flattening into it.
float shoulder_to(float x, float knee, float limit) {
    float span = max(limit - knee, 1e-4);
    float t = (x - knee) / span;
    return x <= knee ? x : knee + span * t / (1.0 + t);
}

vec3 tonemap_hue_preserving(vec3 rgb, float headroom) {
    vec3 x = max(rgb, vec3(0.0));
    float peak = max(x.r, max(x.g, x.b));
    if (peak <= KNEE) {
        return x;
    }
    // NSScreen headroom is linear, as the world is: a display-relative limit, not a nit calibration. The same
    // shoulder works continuously down to headroom=1 (SDR).
    float mapped = shoulder_to(peak, KNEE, max(headroom, 1.0));
    vec3 out_rgb = x * (mapped / max(peak, 1e-6));
    // Highlights drift toward white over the stops past white, eased at both ends: a linear ramp's slope breaks
    // showed as contour lines wherever a glow's brightness passed through them.
    float heat = smoothstep(0.0, WHITE_STOPS, log2(peak)) * WHITE_DRIFT;
    return mix(out_rgb, vec3(mapped), heat);
}

void main() {
    vec4 texel = texture(texture0, fragTexCoord);
    float headroom = max(u_edr_headroom, 1.0);
    vec3 mapped = encodeDisplay(tonemap_hue_preserving(texel.rgb, headroom)) * fragColor.rgb * colDiffuse.rgb;
    finalColor = vec4(mapped, 1.0);
}
