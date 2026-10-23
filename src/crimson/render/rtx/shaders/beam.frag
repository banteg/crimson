#version 330

// Analytic beam: the classic streak's repeated glow stamps summed in closed form along the quad.
// A head quad (negative length) is a single stamp. Shared with the client (crimson-core/client/shaders.py).

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;
flat in float fragStep;

uniform vec4 colDiffuse;

out vec4 finalColor;

// The stamp profile clamp(A * exp(-decay * d - quad * d^2) - offset, 0, 1), d in radius units.
const float STAMP_SCALE = 1.3;
const float STAMP_DECAY = 4.8;
const float STAMP_QUAD = 1.0;
const float STAMP_OFFSET = 0.01;
const float INTENSITY_GAIN = 0.92;
const float MAX_STAMPS = 128.0;

float stamp(float d) {
    return clamp(STAMP_SCALE * exp(-STAMP_DECAY * d - STAMP_QUAD * d * d) - STAMP_OFFSET, 0.0, 1.0);
}

void main() {
    if (fragLen < 0.0) {
        float intensity = stamp(length(fragTexCoord)) * fragColor.a * INTENSITY_GAIN;
        finalColor = vec4(fragColor.rgb * colDiffuse.rgb * intensity, 1.0);
        return;
    }

    float step_uv = max(0.001, fragStep);
    float len_uv = max(0.0, fragLen);
    float stamp_count = clamp(floor(len_uv / step_uv) + 1.0, 0.0, MAX_STAMPS);

    // Only stamps within the profile's support reach this fragment: where the profile falls to zero.
    float target = -log(STAMP_OFFSET / STAMP_SCALE);
    float reach_uv = (-STAMP_DECAY + sqrt(STAMP_DECAY * STAMP_DECAY + 4.0 * STAMP_QUAD * target)) / (2.0 * STAMP_QUAD);
    float center_index = floor(fragTexCoord.x / step_uv);
    float index_reach = ceil(reach_uv / step_uv);
    int start_i = max(0, int(center_index - index_reach));
    int end_i = min(int(stamp_count), int(center_index + index_reach + 1.0));

    float accum = 0.0;
    for (int i = start_i; i < end_i; i++) {
        float sx = float(i) * step_uv;
        if (sx >= len_uv) {
            break;
        }
        float t = clamp(sx / max(1e-6, len_uv), 0.0, 1.0);
        accum += t * stamp(length(vec2(fragTexCoord.x - sx, fragTexCoord.y)));
    }

    float intensity = accum * fragColor.a * INTENSITY_GAIN;
    finalColor = vec4(fragColor.rgb * colDiffuse.rgb * intensity, 1.0);
}
