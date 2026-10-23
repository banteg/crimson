#version 330

// The RTX world target to the display: hue-preserving shoulder toward the display's EDR headroom.
// Shared with the client (crimson-core/client/shaders.py).

in vec2 fragTexCoord;
in vec4 fragColor;

uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform float u_edr_headroom;

out vec4 finalColor;

const float KNEE = 0.85;
const float WHITE_DRIFT = 0.6;
const float WHITE_SPAN = 3.0;

float shoulder_to(float x, float knee, float limit) {
    float span = max(limit - knee, 1e-4);
    return (x <= knee) ? x : (knee + span * (1.0 - exp(-(x - knee) / span)));
}

vec3 tonemap_hue_preserving(vec3 rgb, float headroom) {
    vec3 x = max(rgb, vec3(0.0));
    float peak = max(x.r, max(x.g, x.b));
    if (peak <= KNEE) {
        return x;
    }
    // NSScreen headroom is linear; this legacy OpenGL pipeline is approximately
    // gamma-2.2 encoded. This is a display-relative limit, not a nit calibration.
    // The same shoulder works continuously down to headroom=1 (SDR).
    float limit = pow(max(headroom, 1.0), 1.0 / 2.2);
    float mapped = shoulder_to(peak, KNEE, limit);
    vec3 out_rgb = x * (mapped / max(peak, 1e-6));
    float heat = clamp((peak - 1.0) / WHITE_SPAN, 0.0, 1.0) * WHITE_DRIFT;
    return mix(out_rgb, vec3(mapped), heat);
}

void main() {
    vec4 texel = texture(texture0, fragTexCoord);
    float headroom = max(u_edr_headroom, 1.0);
    vec3 mapped = tonemap_hue_preserving(texel.rgb, headroom) * fragColor.rgb * colDiffuse.rgb;
    finalColor = vec4(mapped, 1.0);
}
