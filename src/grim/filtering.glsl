// Reconstruct straight-alpha artwork in associated color space. Sampling at
// texel centers preserves the sampler's clamp/repeat addressing without
// changing uploaded assets, render targets, or the existing blend equations.
vec4 associatedSample(sampler2D image, vec2 uv, bool linear_art) {
    vec4 s = textureLod(image, uv, 0.0);
    // Decode individual texels before interpolation. Alpha is coverage and
    // must stay linear; transparent RGB must never enter the reconstruction.
    if (linear_art) s.rgb = pow(max(s.rgb, vec3(0.)), vec3(2.2));
    return vec4(s.rgb * s.a, s.a);
}

vec4 unassociate(vec4 s) {
    float a = clamp(s.a, 0.0, 1.0);
    // Catmull-Rom's negative lobes can overshoot both color and coverage.
    return vec4(a > 0.0 ? clamp(s.rgb, vec3(0.0), vec3(a)) / a : vec3(0.0), a);
}

vec4 alphaBilinear(sampler2D image, vec2 uv, bool linear_art) {
    vec2 size = vec2(textureSize(image, 0));
    vec2 p = uv * size - 0.5;
    vec2 f = fract(p);
    vec2 b = (floor(p) + 0.5) / size;
    vec2 d = 1.0 / size;
    return unassociate(mix(
        mix(associatedSample(image, b, linear_art), associatedSample(image, b + vec2(d.x, 0.0), linear_art), f.x),
        mix(associatedSample(image, b + vec2(0.0, d.y), linear_art), associatedSample(image, b + d, linear_art), f.x), f.y));
}

vec4 alphaBilinear(sampler2D image, vec2 uv) { return alphaBilinear(image, uv, false); }

float catmullWeight(float x) {
    x = abs(x);
    return x < 1.0 ? 1.5*x*x*x - 2.5*x*x + 1.0 :
           x < 2.0 ? -0.5*x*x*x + 2.5*x*x - 4.0*x + 2.0 : 0.0;
}

vec4 alphaCatmullRom(sampler2D image, vec2 uv, bool linear_art) {
    vec2 size = vec2(textureSize(image, 0));
    vec2 p = uv * size - 0.5;
    vec2 b = floor(p);
    vec4 sum = vec4(0.0);
    for (int y = -1; y <= 2; ++y)
        for (int x = -1; x <= 2; ++x) {
            vec2 q = b + vec2(x, y);
            sum += associatedSample(image, (q + 0.5) / size, linear_art) *
                   catmullWeight(p.x - q.x) * catmullWeight(p.y - q.y);
        }
    return unassociate(sum);
}

vec4 alphaCatmullRom(sampler2D image, vec2 uv) { return alphaCatmullRom(image, uv, false); }
