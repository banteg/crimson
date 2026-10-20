"""Art-directed dome and silhouette lighting for the original 8x8 creature atlases."""

from grim.filtering import FILTERING_GLSL

from .lighting_shaders import LIGHT_VISIBILITY_GLSL

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

CREATURE_FRAGMENT = "\n#version 330\n" + FILTERING_GLSL + LIGHT_VISIBILITY_GLSL + r"""
in vec2 fragTexCoord;
in vec4 fragColor;
in vec2 world;
uniform sampler2D texture0;
uniform sampler2D u_thickness;
uniform vec4 colDiffuse;
uniform int u_count;
uniform float u_ambient = 1.0;
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
        finalColor = vec4(base.rgb * pow(u_ambient, 1. / 2.2), base.a);
        return;
    }
    vec2 q = fract(fragTexCoord * 8.0) * 2.0 - 1.0;
    // Recover the rotated sprite basis from interpolated world/atlas coordinates.
    // No per-creature uniforms: rotated and differently sized quads can stay batched.
    float determinant = dxq.x * dyq.y - dxq.y * dyq.x;
    // Collapsed atlas coordinates have no recoverable orientation.
    mat2 rot = mat2(1.0);
    vec2 owner = vec2(1e19);
    if (abs(determinant) > 1e-12) {
        mat2 basis = mat2(dxw * dyq.y - dyw * dxq.y, dyw * dxq.x - dxw * dyq.x) / determinant;
        rot = mat2(normalize(basis[0]), normalize(basis[1]));
        owner = world - basis * q;
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
        vec2 axis = dot(u_dir[i].xy, u_dir[i].xy) > .0001 ? normalize(u_dir[i].xy) : vec2(0.);
        bool ring = u_rgb[i].w > 0.;
        bool beam = !ring && u_dir[i].w > 0. && dot(axis, axis) > 0.;
        float along = clamp(dot(dp, axis), -u_dir[i].w * .5, u_dir[i].w * .5);
        vec2 source = ring ? nearestRingPoint(u_pos[i].xy, wp, u_rgb[i].w) : u_pos[i].xy + axis * along;
        float spec_distance = length(source - wp);
        if (spec_distance >= max(u_pos[i].z, u_response[i].z)) continue;
        float source_width = max(.1, u_response[i].w);
        float point_visibility = -1.;
        if (u_response[i].y > 0. && spec_distance < u_response[i].z) {
            float s = 1.0 - smoothstep(0.0, u_response[i].z, spec_distance);
            float axial_gain = beam
                ? mix(.2, 1.0, clamp(along / max(u_dir[i].w, 1.0) + .5, 0.0, 1.0)) : 1.;
            vec3 spec_L = normalize(vec3(source - wp, max(8., u_pos[i].w - 8.)));
            vec3 H = normalize(spec_L + V);
            float catchlight = pow(max(dot(N, H), 0.0), clamp(84.0 / source_width, 8.0, 100.0)) *
                               max(dot(N, spec_L), 0.) * min(1.0, source_width / 3.0);
            float spec_amount = u_response[i].y * s * s * axial_gain * catchlight *
                                (2.0 * DOME_STRENGTH + .20 * RIM_STRENGTH) * (.2 + .8 * lum);
            if (spec_amount * max(u_rgb[i].r, max(u_rgb[i].g, u_rgb[i].b)) > .00001) {
                float visibility = illuminationVisibility(vec3(wp, 8.), vec3(source, u_pos[i].w), source_width, owner);
                if (!beam) point_visibility = visibility;
                added += u_rgb[i].rgb * spec_amount * visibility;
            }
        }
        if (u_response[i].x <= 0. || spec_distance >= u_pos[i].z) continue;
        vec2 light_source = ring ? source : illuminationSource(u_pos[i].xy, axis, u_dir[i].w);
        vec2 delta = light_source - wp;
        float distance_to_light = length(delta);
        if (distance_to_light >= u_pos[i].z) continue;
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
        // Rim and lateral thin-part transmission follow illumination, never
        // bypassing a restrained tracer's gain. Specular catches stay independent.
        // The cell-center dome normal cannot describe individual limbs.
        vec3 diffuse = u_rgb[i].rgb * (
            u_response[i].x * a * a *
                (baseLin * (1.4 * DOME_STRENGTH + .12 * RIM_STRENGTH) * facing +
                 edge * (2.6 * RIM_STRENGTH) * elevation * (.65 + .35 * lum) +
                 transmission_tint * transmission * elevation * TRANSMISSION_STRENGTH));
        if (max(diffuse.r, max(diffuse.g, diffuse.b)) > .00001) {
            float visibility = point_visibility >= 0. ? point_visibility :
                illuminationVisibility(vec3(wp, 8.), vec3(light_source, u_pos[i].w), source_width, owner);
            diffuse *= visibility;
        }
        added += diffuse;
    }
    // Bound aggregate illumination in dense fights without changing hue.
    float peak = max(added.r, max(added.g, added.b));
    added *= 1.0 / (1.0 + peak / 1.4);
    finalColor = peak > 0.0 || u_ambient != 1.0 ? vec4(pow(baseLin * u_ambient + added, vec3(1.0 / 2.2)), base.a) : base;
}
"""
