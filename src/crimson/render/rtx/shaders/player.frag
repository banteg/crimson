#version 330
// Opaque player cloth lighting: painted relief and a directional inner rim.
#include "filtering.glsl"
#include "source_geometry.glsl"
in vec2 fragTexCoord;
in vec4 fragColor;
in vec2 world;
uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform int u_count;
uniform vec4 u_pos[32];
uniform vec4 u_rgb[32];
uniform vec4 u_dir[32];
uniform vec4 u_response[32]; // illumination; other channels reserved by shared light packing
out vec4 finalColor;
const float DOME_STRENGTH = 2.2;
const float RIM_STRENGTH = 0.8;
vec4 spriteSample(vec2 uv) {
    vec2 cell = floor(fragTexCoord * 8.0) / 8.0;
    vec2 half_texel = .5 / vec2(textureSize(texture0, 0));
    return textureLod(texture0, clamp(uv, cell + half_texel, cell + vec2(.125) - half_texel), 0.);
}
float spriteLuminance(vec2 uv) {
    return dot(spriteSample(uv).rgb, vec3(.299, .587, .114));
}
float spriteAlpha(vec2 uv) {
    vec2 cell = floor(fragTexCoord * 8.0) / 8.0;
    if (any(lessThan(uv, cell)) || any(greaterThanEqual(uv, cell + vec2(.125))))
        return 0.0;
    // Explicit LOD keeps alpha taps defined inside per-pixel light branches.
    return spriteSample(uv).a;
}
void main() {
    vec4 texel = alphaBilinear(texture0, fragTexCoord);
    vec4 base = texel * fragColor * colDiffuse;
    // Save derivatives before alpha discard makes neighboring lanes diverge.
    vec2 dxq = dFdx(fragTexCoord) * 16., dyq = dFdy(fragTexCoord) * 16.;
    vec2 dxw = dFdx(world), dyw = dFdy(world);
    if (floor(base.a * 255.0 + 0.5) < 4.0)
        discard;
    if (u_count == 0) {
        finalColor = vec4(base.rgb, base.a);
        return;
    }
    vec2 q = fract(fragTexCoord * 8.0) * 2.0 - 1.0;
    // Recover the rotated sprite basis from interpolated world/atlas coordinates.
    // No per-layer uniforms: rotated and differently sized quads can stay batched.
    float determinant = dxq.x * dyq.y - dxq.y * dyq.x;
    // Collapsed atlas coordinates have no recoverable orientation.
    mat2 rot = mat2(1.0);
    if (abs(determinant) > 1e-12) {
        mat2 basis = mat2(dxw * dyq.y - dyw * dxq.y, dyw * dxq.x - dxw * dyq.x) / determinant;
        rot = mat2(normalize(basis[0]), normalize(basis[1]));
    }
    vec2 wp = world;
    // Smooth body bulge plus painted texture relief.
    vec2 slope = rot * q * .85;
    // Central differences per atlas texel, independent of framebuffer scale.
    // Clamp taps to this animation cell, then rotate the gradient into world space.
    vec2 px = 1.0 / vec2(textureSize(texture0, 0));
    vec2 relief = .5 * vec2(
        spriteLuminance(fragTexCoord + vec2(px.x, 0)) - spriteLuminance(fragTexCoord - vec2(px.x, 0)),
        spriteLuminance(fragTexCoord + vec2(0, px.y)) - spriteLuminance(fragTexCoord - vec2(0, px.y)));
    // Brighter texels are raised: the height-field normal points downhill.
    slope -= rot * relief * 0.65;
    vec3 N = normalize(vec3(slope, sqrt(max(.12, 1.0 - dot(slope, slope)))));
    vec3 baseLin = pow(max(base.rgb, vec3(0)), vec3(2.2));
    vec3 added = vec3(0);
    for (int i = 0; i < u_count; i++) {
        vec2 axis = dot(u_dir[i].xy, u_dir[i].xy) > .0001 ? normalize(u_dir[i].xy) : vec2(0.);
        bool ring = u_rgb[i].w > 0.;
        vec2 source = ring ? nearestRingPoint(u_pos[i].xy, wp, u_rgb[i].w) :
                             illuminationSource(u_pos[i].xy, axis, u_dir[i].w, u_dir[i].z);
        vec2 delta = source - wp;
        float distance_to_light = length(delta);
        if (u_response[i].x <= 0. || distance_to_light >= u_pos[i].z) continue;
        float a = 1.0 - smoothstep(0.0, u_pos[i].z, distance_to_light);
        vec3 L = normalize(vec3(delta, max(8.0, u_pos[i].w - 8.0)));
        float facing = max(dot(N, L), 0.0);
        // An inner silhouette rim, only on the edge facing this emitter.
        // Atlas-local samples cannot reach neighboring animation frames.
        vec2 light_xy = normalize(delta + vec2(.0001));
        vec2 toward = transpose(rot) * light_xy;
        vec2 side = vec2(-toward.y, toward.x);
        float beyond = (spriteAlpha(fragTexCoord + toward * px * 1.5) +
                        spriteAlpha(fragTexCoord + (toward * 1.5 + side * .65) * px) +
                        spriteAlpha(fragTexCoord + (toward * 1.5 - side * .65) * px)) /
                       3.0;
        float edge = smoothstep(.04, .7, max(0.0, texel.a - beyond));
        float elevation = length(delta) / sqrt(dot(delta, delta) + pow(max(8.0, u_pos[i].w - 8.0), 2.0));
        // Both terms obey illumination gain; reflection-only tracers stay unlit.
        // The cell-center dome normal cannot describe individual limbs.
        vec3 diffuse = u_rgb[i].rgb * (
            u_response[i].x * a * a *
                ((baseLin + sqrt(baseLin) * .12) * (1.4 * DOME_STRENGTH + .12 * RIM_STRENGTH) * (.22 + .78 * facing) +
                 edge * (2.6 * RIM_STRENGTH) * elevation * (vec3(.06) + sqrt(baseLin) * .8)));
        added += diffuse;
    }
    // Stronger cloth response; no specular or transmission.
    // Bound aggregate illumination in dense fights without changing hue.
    float peak = max(added.r, max(added.g, added.b));
    added *= 1.0 / (1.0 + peak / 1.4);
    finalColor = peak > 0.0 ? vec4(pow(baseLin + added, vec3(1.0 / 2.2)), base.a) : base;
}
