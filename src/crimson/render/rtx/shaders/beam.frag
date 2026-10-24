#version 330

// Analytic beam: the classic streak's repeated glow stamps, integrated along the quad in closed form.
// A head quad (negative length) is a single stamp. Shared with the client (crimson-core/client/shaders.py).

in vec2 fragTexCoord;
in vec4 fragColor;
in float fragLen;
flat in float fragStep;

uniform vec4 colDiffuse;

out vec4 finalColor;

// The glow texel's alpha as two Gaussians, sum c * exp(-beta * r^2) with r in stamp radii:
// a narrow core and a broad halo.
const vec2 GLOW_C = vec2(0.47467, 0.3886);
const vec2 GLOW_BETA = vec2(49.18833, 5.9273);
const float SQRT_PI = 1.7724539;

float glow(float r2) {
    return dot(GLOW_C, exp(-GLOW_BETA * r2));
}

// The halo's Gaussian tail outlasts the texture's, which is spent by 0.9 radii; end it inside the quad.
float edge_fade(float r) {
    return smoothstep(1.0, 0.75, r);
}

// erf within 4e-4. erf is flat past 3; the clamp keeps tanh's own exp from overflowing to NaN.
vec2 erf2(vec2 z) {
    z = clamp(z, -3.0, 3.0);
    return tanh(1.1283792 * z * (1.0 + 0.08943 * z * z));
}

void main() {
    vec2 p = fragTexCoord;
    if (fragLen < 0.0) {
        float intensity = glow(dot(p, p)) * edge_fade(length(p)) * fragColor.a;
        finalColor = vec4(fragColor.rgb * colDiffuse.rgb * intensity, 1.0);
        return;
    }

    // Stamps every `step` along [0, len] weigh s / len. Their spacing taken to zero is
    // (1 / (step * len)) * integral_0^len s * glow((x - s)^2 + y^2) ds, which for a Gaussian splits
    // into an erf slab across the segment and exp terms at its two ends. Integrating up to the
    // head keeps the body from stepping behind it as the stamps would.
    float step_uv = max(0.001, fragStep);
    float len_uv = max(1e-4, fragLen);
    vec2 root = sqrt(GLOW_BETA);
    vec2 slab = p.x * exp(-GLOW_BETA * p.y * p.y) * (erf2(root * (len_uv - p.x)) + erf2(root * p.x)) * SQRT_PI / (2.0 * root);
    vec2 head = vec2(len_uv - p.x, p.y);
    vec2 ends = (exp(-GLOW_BETA * dot(p, p)) - exp(-GLOW_BETA * dot(head, head))) / (2.0 * GLOW_BETA);
    float accum = max(0.0, dot(GLOW_C, slab + ends)) / (step_uv * len_uv);
    accum *= edge_fade(length(vec2(p.x - clamp(p.x, 0.0, len_uv), p.y)));

    float intensity = accum * fragColor.a;
    finalColor = vec4(fragColor.rgb * colDiffuse.rgb * intensity, 1.0);
}
