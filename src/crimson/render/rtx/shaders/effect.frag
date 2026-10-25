#version 330
// Shared Python / OpenGL / WebGL / WebGPU effect primitives. Geometry is draw-only.
in vec2 fragTexCoord;
in vec4 fragColor;
in float fragShape; // an ion arc's length in strip scales, negative when its strips end in the native cut
uniform vec4 colDiffuse;
uniform int u_kind; // 0 warm glow, 1 white aura, 2 ring, 3 plasma, 4 ion arc, 5 pulse shot
uniform vec4 u_params[3];
out vec4 finalColor;
#include "effect_profiles.glsl"

float alphaTest(float alpha) {
    return floor(alpha * 255. + .5) >= 4. ? alpha : 0.;
}

vec3 plasmaGlow(vec2 p, float radius, float alpha) {
    if (radius <= 0. || alphaTest(alpha) == 0.) return vec3(0.);
    vec2 axis = u_params[2].xy;
    vec2 offset = vec2(dot(WARM_OFFSET, axis), dot(WARM_OFFSET, vec2(-axis.y, axis.x)));
    return warmProfile(p / radius - offset) * alpha;
}

vec3 plasmaTrail(vec2 p) {
    float radius = u_params[0].x, len = u_params[0].w, step_size = u_params[1].x;
    float alpha = alphaTest(u_params[1].y);
    if (len <= 0. || alpha == 0.) return vec3(0.);
    vec2 axis = u_params[2].xy;
    vec2 offset = vec2(dot(WARM_OFFSET, axis), dot(WARM_OFFSET, vec2(-axis.y, axis.x)));
    vec2 q = p / radius - offset;
    float cross2 = 1. - q.y*q.y;
    if (cross2 <= 0.) return vec3(0.);
    // Integrate the source disc only: Gaussian tails cannot leave a seam at the quad boundary.
    float reach = sqrt(cross2);
    float lo = max((-len + step_size*.5) / radius - q.x, -reach);
    float hi = min(step_size*.5 / radius - q.x, reach);
    if (hi <= lo) return vec3(0.);
    vec3 root = sqrt(WARM_BETA);
    vec3 slab = .88622692545 / root * (effectErf(root*hi) - effectErf(root*lo));
    return WARM_COLOR * (exp(-WARM_BETA*q.y*q.y) * slab) * (radius / step_size * alpha);
}

// projs.jaz cell 0 of 2x2, the Pulse Gun's shot: a dome with a circular front edge and a body fading behind it,
// thinning toward its straight sides, cut square at the sides and back. Fitted against the 62x62 cell in sprite
// units (x across, y back from the travel direction); `front` is the depth behind the front edge.
float pulseFront(vec2 p) {
    return 1.83 - length(p - vec2(0., 1.708));
}

float pulseProfile(vec2 p, float front, float aa) {
    float edge = smoothstep(-.035 - aa, .035 + aa, front);
    float body = exp(-pow(max(front - .06, 0.) / (.34 * (1. - .9 * p.x * p.x)), 1.4));
    float box = (1. - smoothstep(.84 - aa, .9 + aa, abs(p.x))) * (1. - smoothstep(.65 - aa, .71 + aa, p.y));
    return edge * body * box;
}

// The shot's HDR glow on top of the native artwork: a hot line just inside its front edge and a short halo around
// it, brightest in the middle and gone at the sides. A sub-pixel line dims instead of swelling.
const float PULSE_GAIN = 1.3, PULSE_GLOW = 1.6;
float pulseGlow(vec2 p, float front, float aa) {
    float width2 = .025 * .025 + aa * aa;
    float line = .025 * inversesqrt(width2) * exp(-(front - .03) * (front - .03) / width2);
    float halo = exp(-abs(front - .03) / .07);
    return (line + .3 * halo) * exp(-p.x * p.x / .3) * (1. - smoothstep(.84 - aa, .9 + aa, abs(p.x)));
}

void main() {
    vec2 p = fragTexCoord;
    vec4 tint = fragColor * colDiffuse;
    if (u_kind == 3) {
        vec3 value = plasmaTrail(p)
            + plasmaGlow(p, u_params[0].y, u_params[1].z)
            + plasmaGlow(p, u_params[0].z, u_params[1].w);
        finalColor = vec4(value * tint.rgb, 1.);
    } else if (u_kind == 5) {
        float front = pulseFront(p), aa = .5 * fwidth(front);
        vec3 glow = mix(tint.rgb, vec3(1.), .45);
        finalColor = vec4(tint.rgb * alphaTest(pulseProfile(p, front, aa) * tint.a) * PULSE_GAIN
                          + glow * pulseGlow(p, front, aa) * tint.a * PULSE_GLOW, 1.);
    } else if (u_kind == 4) {
        // Per vertex, so a run of arcs draws at once: p is in strip scales too.
        float len = abs(fragShape);
        vec2 nearest = vec2(p.x - clamp(p.x, 0., len), p.y);
        float body = alphaTest(ionProfile(nearest / 10.) * tint.a)
                   + alphaTest(ionProfile(nearest / 14.) * tint.a);
        if (fragShape < 0. && (p.x < 0. || p.x > len)) body = 0.;
        float head = alphaTest(ionProfile((p - vec2(len, 0.)) / 16.) * tint.a);
        finalColor = vec4(tint.rgb * (body + head), 1.);
    } else {
        float alpha;
        vec3 color;
        if (u_kind == 0) {
            if (length(p - WARM_OFFSET) >= 1.) discard;
            color = warmProfile(p - WARM_OFFSET) * tint.rgb;
            alpha = tint.a;
        } else {
            color = tint.rgb;
            alpha = (u_kind == 1 ? auraProfile(p) : ringProfile(p)) * tint.a;
        }
        alpha = alphaTest(alpha);
        if (alpha == 0.) discard;
        finalColor = vec4(color, alpha);
    }
}
