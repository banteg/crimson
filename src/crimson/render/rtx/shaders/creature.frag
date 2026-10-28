#version 330
// Art-directed dome and silhouette lighting for the original 8x8 creature atlases, and the freeze's ice lit as ice.
#include "filtering.glsl"
#include "source_geometry.glsl"
#include "linear_light.glsl"
in vec2 fragTexCoord;
in vec4 fragColor;
in vec2 world;
// Each light's visibility across the quad, four lights a vec4, from its corners (creature_visibility.glsl).
in vec4 lightVisibility0;
in vec4 lightVisibility1;
in vec4 lightVisibility2;
in vec4 lightVisibility3;
in vec4 lightVisibility4;
in vec4 lightVisibility5;
in vec4 lightVisibility6;
in vec4 lightVisibility7;
uniform sampler2D texture0;
uniform sampler2D u_thickness;
uniform vec4 colDiffuse;
uniform int u_count;
uniform float u_ambient = 1.0;
uniform vec4 u_pos[32];
uniform vec4 u_rgb[32];
uniform vec4 u_dir[32];
uniform vec4 u_response[32]; // illumination, reflection, reflection reach, source width
// The freeze's ice in the particles atlas (0 for a creature body): the grid of its cells, 4 for the cubes and 8 for
// the shatter's shards. Its surface takes the thickness map's place on u_thickness (tools/rtx/ice_surface.py), laid
// out like the atlas: RG the sprite-frame normal's x and y (x right, y down, z toward the viewer), B the ice's own
// mottling over 2.5.
uniform int u_ice;
// The cubes over frozen bodies: their darkest faces lose ICE_CLEAR of the ice's opacity, so the body shows through.
uniform int u_ice_frozen;
const float ICE_CLEAR = 0.32;
out vec4 finalColor;
const float DOME_STRENGTH = 0.65;
const float RIM_STRENGTH = 0.65;
const float TRANSMISSION_STRENGTH = 1.4;
float lightVisibility(int i) {
    vec4 group = i < 16 ? (i < 8 ? (i < 4 ? lightVisibility0 : lightVisibility1) : (i < 12 ? lightVisibility2 : lightVisibility3))
                        : (i < 24 ? (i < 20 ? lightVisibility4 : lightVisibility5) : (i < 28 ? lightVisibility6 : lightVisibility7));
    int lane = i - i / 4 * 4;
    return lane == 0 ? group.x : lane == 1 ? group.y : lane == 2 ? group.z : group.w;
}
float cellGrid() { return u_ice != 0 ? float(u_ice) : 8.0; }
vec4 spriteSample(vec2 uv) {
    vec2 cell = floor(fragTexCoord * cellGrid()) / cellGrid();
    vec2 half_texel = .5 / vec2(textureSize(texture0, 0));
    return alphaBilinear(texture0, clamp(uv, cell + half_texel, cell + vec2(1. / cellGrid()) - half_texel));
}
float spriteLuminance(vec2 uv) {
    return dot(spriteSample(uv).rgb, vec3(.299, .587, .114));
}
float spriteAlpha(vec2 uv) {
    vec2 cell = floor(fragTexCoord * cellGrid()) / cellGrid();
    if (any(lessThan(uv, cell)) || any(greaterThanEqual(uv, cell + vec2(1. / cellGrid()))))
        return 0.0;
    // Explicit LOD keeps alpha taps defined inside per-pixel light branches.
    return spriteSample(uv).a;
}
void main() {
    vec4 texel = alphaBilinear(texture0, fragTexCoord, true);
    vec4 tint = fragColor * colDiffuse;
    vec4 base = texel * vec4(decodeArt(tint.rgb), tint.a);
    // Save derivatives before alpha discard makes neighboring lanes diverge.
    vec2 dxq = dFdx(fragTexCoord) * 16., dyq = dFdy(fragTexCoord) * 16.;
    vec2 dxw = dFdx(world), dyw = dFdy(world);
    // Ice a little more solid than the original's overlay: its draws already carry its 0.7, or the shatter's fade.
    if (u_ice != 0)
        base.a = min(.95, base.a * 1.15);
    if (floor(base.a * 255.0 + 0.5) < 4.0)
        discard;
    if (u_count == 0 && u_ice == 0) {
        finalColor = vec4(base.rgb * u_ambient, base.a);
        return;
    }
    vec2 q = fract(fragTexCoord * cellGrid()) * 2.0 - 1.0;
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
    float lum = dot(encodeDisplay(texel.rgb), vec3(.299, .587, .114));
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
    vec3 baseLin = base.rgb;
    // Per-cell morphological openings estimate part size, not anatomical depth.
    vec2 cell = floor(fragTexCoord * 8.0) / 8.0;
    vec2 half_texel = .5 / vec2(textureSize(u_thickness, 0));
    vec2 thickness_uv = clamp(fragTexCoord, cell + half_texel, cell + vec2(.125) - half_texel);
    float thickness = textureLod(u_thickness, thickness_uv, 0.).r * 16.0;
    float transmission = exp(-.48 * thickness);
    vec3 transmission_tint = mix(vec3(.15), baseLin, .85);
    // What the lights shade, how they catch, how much the rim follows them, and how much colour the light the
    // surface scatters keeps; light that needs no emitter.
    vec3 albedo = baseLin;
    float spec_gain = 1., spec_sharp = 1., rim_gain = 1., light_desat = 0.;
    vec3 glow = vec3(0);
    if (u_ice != 0) {
        // The sprite's own model: a rounded, lumpy cube or a chunk of it, and its mottling.
        vec3 ice = textureLod(u_thickness, fragTexCoord, 0.).rgb;
        vec2 ice_xy = ice.xy * 2. - 1.;
        N = normalize(vec3(rot * ice_xy, sqrt(max(0., 1. - dot(ice_xy, ice_xy)))));
        // Unlit it keeps the original's look, a little colder; the lights shade an ice colour with the sprite's
        // mottling but not its baked light, so a fire on the dark side lights that side. Ice scatters little and
        // keeps its blue under fire: the lights mostly glint off it, at its edges rather than along its outline.
        albedo = vec3(.07, .12, .17) * ice.b * 2.5;
        baseLin *= vec3(.8, .92, 1.05);
        transmission = 0.;
        spec_gain = 5., spec_sharp = 3., rim_gain = .25, light_desat = .45;
        // The cold sky in the faces that turn toward it, and its hard glint, so the ice reads with no light near.
        float fresnel = .04 + .96 * pow(1. - max(dot(N, V), 0.), 5.);
        // The sprite's dark faces are a window into the ice; its bright frost and glancing edges stay solid.
        if (u_ice_frozen != 0)
            base.a *= mix(1. - ICE_CLEAR, 1., max(smoothstep(.06, .54, lum), .85 * fresnel));
        vec3 sky_dir = normalize(vec3(-.30, -.40, .86));
        float sky = dot(reflect(-V, N), sky_dir);
        glow = vec3(.05, .09, .13) * smoothstep(-.1, .9, sky) * (.35 + fresnel) +
               vec3(.6, .8, .95) * pow(max(sky, 0.), 80.) * .5;
    }
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
        if (u_response[i].y > 0. && spec_distance < u_response[i].z) {
            float s = 1.0 - smoothstep(0.0, u_response[i].z, spec_distance);
            float axial_gain = beam ? segmentRadiance(along / max(u_dir[i].w, 1.0) + .5, u_dir[i].z) : 1.;
            vec3 spec_L = normalize(vec3(source - wp, max(8., u_pos[i].w - 8.)));
            vec3 H = normalize(spec_L + V);
            float catchlight = pow(max(dot(N, H), 0.0), clamp(84.0 / source_width, 8.0, 100.0) * spec_sharp) *
                               max(dot(N, spec_L), 0.) * min(1.0, source_width / 3.0);
            float spec_amount = u_response[i].y * s * s * axial_gain * catchlight *
                                (2.0 * DOME_STRENGTH + .20 * RIM_STRENGTH) * (.2 + .8 * lum);
            added += u_rgb[i].rgb * spec_amount * spec_gain * lightVisibility(i);
        }
        if (u_response[i].x <= 0. || spec_distance >= u_pos[i].z) continue;
        vec2 light_source = ring ? source : illuminationSource(u_pos[i].xy, axis, u_dir[i].w, u_dir[i].z);
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
        vec3 diffuse = mix(u_rgb[i].rgb, vec3(dot(u_rgb[i].rgb, vec3(.2126, .7152, .0722))), light_desat) * (
            u_response[i].x * a * a *
                (albedo * (1.4 * DOME_STRENGTH + .12 * RIM_STRENGTH) * facing +
                 edge * (2.6 * RIM_STRENGTH) * rim_gain * elevation * (.65 + .35 * lum) +
                 transmission_tint * transmission * elevation * TRANSMISSION_STRENGTH));
        added += diffuse * lightVisibility(i);
    }
    // Dense fights add up as light; the tonemap alone compresses them.
    finalColor = vec4(baseLin * u_ambient + added + glow, base.a);
}
