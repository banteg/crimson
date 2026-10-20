"""Art-directed dome and silhouette lighting for the original 8x8 creature atlases."""

from grim.filtering import FILTERING_GLSL

CREATURE_VERTEX = r"""
#version 330
in vec3 vertexPosition;
in vec2 vertexTexCoord;
in vec4 vertexColor;
uniform mat4 mvp;
uniform vec2 u_camera;
uniform vec2 u_view_scale;
out vec2 fragTexCoord;
out vec4 fragColor;
out vec2 world;
void main() {
    fragTexCoord = vertexTexCoord;
    fragColor = vertexColor;
    world = vertexPosition.xy / u_view_scale - u_camera;
    gl_Position = mvp * vec4(vertexPosition, 1.0);
}
"""

CREATURE_FRAGMENT = "\n#version 330\n" + FILTERING_GLSL + r"""
in vec2 fragTexCoord;
in vec4 fragColor;
in vec2 world;
uniform sampler2D texture0;
uniform sampler2D u_thickness;
uniform vec4 colDiffuse;
uniform int u_count;
uniform vec4 u_pos[32];
uniform vec4 u_rgb[32];
uniform vec4 u_dir[32];
uniform vec4 u_response[32]; // illumination, reflection, reflection reach, source width
out vec4 finalColor;
const float DOME_STRENGTH = 0.65;
const float RIM_STRENGTH = 0.65;
const float TRANSMISSION_STRENGTH = 1.4;
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
        finalColor = base;
        return;
    }
    vec2 q = fract(fragTexCoord * 8.0) * 2.0 - 1.0;
    // Recover the rotated sprite basis from interpolated world/atlas coordinates.
    // No per-creature uniforms: rotated and differently sized quads can stay batched.
    float determinant = dxq.x * dyq.y - dxq.y * dyq.x;
    // Collapsed atlas coordinates have no recoverable orientation.
    mat2 rot = mat2(1.0);
    if (abs(determinant) > 1e-12) {
        mat2 basis = mat2(dxw * dyq.y - dyw * dxq.y, dyw * dxq.x - dxw * dyq.x) / determinant;
        rot = mat2(normalize(basis[0]), normalize(basis[1]));
    }
    vec2 wp = world;
    float lum = dot(texel.rgb, vec3(.299, .587, .114));
    // Smooth body bulge plus weak texture relief: no alpha-outline rim.
    vec2 slope = rot * q * .85;
    // Central differences per atlas texel, independent of framebuffer scale.
    // Clamp taps to this animation cell, then rotate the gradient into world space.
    vec2 px = 1.0 / vec2(textureSize(texture0, 0));
    vec2 relief = .5 * vec2(
        spriteLuminance(fragTexCoord + vec2(px.x, 0)) - spriteLuminance(fragTexCoord - vec2(px.x, 0)),
        spriteLuminance(fragTexCoord + vec2(0, px.y)) - spriteLuminance(fragTexCoord - vec2(0, px.y)));
    // Brighter texels are raised: the height-field normal points downhill.
    slope -= rot * relief * .8;
    vec3 N = normalize(vec3(slope, sqrt(max(.12, 1.0 - dot(slope, slope)))));
    vec3 V = normalize(vec3(0, .57735, 1));
    vec3 baseLin = pow(max(base.rgb, vec3(0)), vec3(2.2));
    // Per-cell morphological openings estimate part size, not anatomical depth.
    vec2 cell = floor(fragTexCoord * 8.0) / 8.0;
    vec2 half_texel = .5 / vec2(textureSize(u_thickness, 0));
    vec2 thickness_uv = clamp(fragTexCoord, cell + half_texel, cell + vec2(.125) - half_texel);
    float thickness = textureLod(u_thickness, thickness_uv, 0.).r * 16.0;
    float transmission = exp(-.48 * thickness);
    vec3 transmission_tint = mix(vec3(.15), baseLin, .85);
    vec3 added = vec3(0);
    for (int i = 0; i < u_count; i++) {
        vec2 dp = wp - u_pos[i].xy;
        float along = clamp(dot(dp, u_dir[i].xy), -u_dir[i].w * .5, u_dir[i].w * .5);
        vec2 source = u_pos[i].xy + u_dir[i].xy * along;
        vec2 delta = source - wp;
        float distance_to_light = length(delta);
        if (distance_to_light >= max(u_pos[i].z, u_response[i].z))
            continue;
        float a = 1.0 - smoothstep(0.0, u_pos[i].z, distance_to_light);
        float s = 1.0 - smoothstep(0.0, u_response[i].z, distance_to_light);
        // Taper emitted intensity once; only radial attenuation is squared.
        float axial_gain = u_dir[i].w > 0.0
            ? mix(.2, 1.0, clamp(along / max(u_dir[i].w, 1.0) + .5, 0.0, 1.0))
            : 1.0;
        vec3 L = normalize(vec3(delta, max(8.0, u_pos[i].w - 8.0)));
        float facing = max(dot(N, L), 0.0);
        vec3 H = normalize(L + V);
        float source_width = max(.1, u_response[i].w);
        float catchlight = pow(max(dot(N, H), 0.0), clamp(84.0 / source_width, 8.0, 100.0)) *
                           facing * min(1.0, source_width / 3.0);

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
        // Rim and lateral thin-part transmission follow illumination, never
        // bypassing a restrained tracer's gain. Specular catches stay independent.
        // The cell-center dome normal cannot describe individual limbs.
        added += u_rgb[i].rgb * axial_gain * (
            u_response[i].x * a * a *
                (baseLin * (1.4 * DOME_STRENGTH + .12 * RIM_STRENGTH) * facing +
                 edge * (2.6 * RIM_STRENGTH) * elevation * (.65 + .35 * lum) +
                 transmission_tint * transmission * elevation * TRANSMISSION_STRENGTH) +
            u_response[i].y * s * s *
                catchlight * (2.0 * DOME_STRENGTH + .20 * RIM_STRENGTH) * (.2 + .8 * lum));
    }
    // Bound aggregate illumination in dense fights without changing hue.
    float peak = max(added.r, max(added.g, added.b));
    added *= 1.0 / (1.0 + peak / 1.4);
    finalColor = peak > 0.0 ? vec4(pow(baseLin + added, vec3(1.0 / 2.2)), base.a) : base;
}
"""
