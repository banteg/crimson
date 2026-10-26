#version 330
// The fixed-function texture stages, alpha test included: two stages, as the device has.
#include "common.glsl"
#include "filtering.glsl"
LOC(0) in vec4 v_diffuse;
LOC(1) in vec2 v_uv;
LOC(2) in vec2 v_pos;
out vec4 color;
uniform sampler2D texture0, texture1;
uniform ivec2 has_texture, color_op, color_arg1, color_arg2, alpha_op, alpha_arg1, alpha_arg2;
uniform ivec2 reconstruction; // 0 sampler state, 1 associated bilinear, 2 terrain cubic
uniform vec4 factor;
uniform int alpha_test, alpha_func;
uniform float alpha_ref;
// A circle the device shades itself (host_circle), else an outer radius of 0: its center and inner and outer radius
// in the vertices' pixels, then the texture's u and its v at the inner and outer edges.
uniform vec4 circle, circle_uv;
vec4 sampleColor(sampler2D image, int mode, vec2 uv) {
    if (mode == 2) return alphaCatmullRom(image, uv);
    if (mode == 1) return alphaBilinear(image, uv);
    return texture(image, uv);
}
vec4 argument(int a, vec4 current, vec4 texel) {
    int which = a & 7;
    vec4 v = which == 1 ? current : which == 2 ? texel : which == 3 ? factor : v_diffuse;
    if ((a & 0x10) != 0) v = 1.0 - v;
    if ((a & 0x20) != 0) v = vec4(v.a);
    return v;
}
vec4 operation(int op, vec4 a, vec4 b) {
    if (op == 2) return a;
    if (op == 3) return b;
    if (op == 4) return a * b;
    if (op == 5) return a * b * 2.0;
    if (op == 6) return a * b * 4.0;
    if (op == 7) return a + b;
    if (op == 8) return a + b - 0.5;
    if (op == 9) return (a + b - 0.5) * 2.0;
    if (op == 10) return a - b;
    if (op == 11) return a + b - a * b;
    if (op == 24) return vec4(clamp(4.0 * dot(a.rgb - 0.5, b.rgb - 0.5), 0.0, 1.0));
    return a;
}
bool passes(float a) {
    float r = alpha_ref;
    if (alpha_func == 1) return false;
    if (alpha_func == 2) return a < r;
    if (alpha_func == 3) return a == r;
    if (alpha_func == 4) return a <= r;
    if (alpha_func == 5) return a > r;
    if (alpha_func == 6) return a != r;
    if (alpha_func == 7) return a >= r;
    return true;
}
void main() {
    // A circle's coverage, a pixel's width of edge, and its texture across the band between its radii.
    float d = length(v_pos - circle.xy), edge = max(fwidth(d), 1e-4);
    float coverage = 1.0;
    vec2 uv = v_uv;
    if (circle.w > 0.0) {
        coverage = clamp((circle.w - d) / edge + 0.5, 0.0, 1.0);
        if (circle.z > 0.0) coverage *= clamp((d - circle.z) / edge + 0.5, 0.0, 1.0);
        uv = vec2(circle_uv.x, mix(circle_uv.y, circle_uv.z, clamp((d - circle.z) / (circle.w - circle.z), 0.0, 1.0)));
    }
    // Both stages sample before any stage decides, so texture lookups stay in uniform control flow.
    vec4 texels[2] = vec4[2](has_texture[0] != 0 ? sampleColor(texture0, reconstruction[0], uv) : vec4(1.0),
                             has_texture[1] != 0 ? sampleColor(texture1, reconstruction[1], uv) : vec4(1.0));
    vec4 current = v_diffuse;
    for (int s = 0; s < 2; ++s) {
        if (color_op[s] == 1) break;
        vec4 texel = texels[s];
        vec4 c = clamp(operation(color_op[s], argument(color_arg1[s], current, texel), argument(color_arg2[s], current, texel)), 0.0, 1.0);
        float a = alpha_op[s] == 1 ? current.a
            : clamp(operation(alpha_op[s], argument(alpha_arg1[s], current, texel), argument(alpha_arg2[s], current, texel)).a, 0.0, 1.0);
        current = vec4(c.rgb, a);
    }
    current.a *= coverage;
    // Direct3D compares the 8-bit alpha with the reference.
    if (alpha_test != 0 && !passes(floor(current.a * 255.0 + 0.5))) discard;
    color = current;
}
