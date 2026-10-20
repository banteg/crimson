"""Art-directed dome and silhouette lighting for the original 8x8 creature atlases."""

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

CREATURE_FRAGMENT = r"""
#version 330
in vec2 fragTexCoord;
in vec4 fragColor;
in vec2 world;
uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform int u_count;
uniform vec4 u_pos[16];
uniform vec4 u_rgb[16];
uniform vec4 u_dir[16];
out vec4 finalColor;
const float DOME_STRENGTH = 0.65;
const float RIM_STRENGTH = 0.65;
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
    vec4 texel = texture(texture0, fragTexCoord);
    vec4 base = texel * fragColor * colDiffuse;
    // Save derivatives before alpha discard makes neighboring lanes diverge.
    vec2 dxq = dFdx(fragTexCoord) * 16., dyq = dFdy(fragTexCoord) * 16.;
    vec2 dxw = dFdx(world), dyw = dFdy(world);
    if (base.a <= 4.0 / 255.0)
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
    vec3 added = vec3(0);
    for (int i = 0; i < u_count; i++) {
        vec2 dp = wp - u_pos[i].xy;
        float along = clamp(dot(dp, u_dir[i].xy), -u_dir[i].w * .5, u_dir[i].w * .5);
        vec2 source = u_pos[i].xy + u_dir[i].xy * along;
        vec2 delta = source - wp;
        float distance_to_light = length(delta);
        if (distance_to_light >= u_pos[i].z)
            continue;
        float a = 1.0 - smoothstep(0.0, u_pos[i].z, distance_to_light);
        // Taper emitted intensity once; only radial attenuation is squared.
        float axial_gain = u_dir[i].w > 0.0
            ? mix(.2, 1.0, clamp(along / max(u_dir[i].w, 1.0) + .5, 0.0, 1.0))
            : 1.0;
        vec3 L = normalize(vec3(delta, max(8.0, u_pos[i].w - 8.0)));
        float facing = max(dot(N, L), 0.0);
        vec3 H = normalize(L + V);
        float catchlight = pow(max(dot(N, H), 0.0), 28.0) * facing;

        // An inner silhouette rim, only on the edge facing this emitter.
        // Atlas-local samples cannot reach neighboring animation frames.
        vec2 toward = transpose(rot) * normalize(delta + vec2(.0001));
        vec2 side = vec2(-toward.y, toward.x);
        float beyond = (spriteAlpha(fragTexCoord + toward * px * 1.5) +
                        spriteAlpha(fragTexCoord + (toward * 1.5 + side * .65) * px) +
                        spriteAlpha(fragTexCoord + (toward * 1.5 - side * .65) * px)) /
                       3.0;
        float edge = smoothstep(.04, .7, max(0.0, texel.a - beyond));
        float elevation = length(delta) / sqrt(dot(delta, delta) + pow(max(8.0, u_pos[i].w - 8.0), 2.0));
        added += u_rgb[i].rgb * a * a * axial_gain *
                 (baseLin * (1.4 * DOME_STRENGTH + .12 * RIM_STRENGTH) * facing +
                  catchlight * (2.0 * DOME_STRENGTH + .20 * RIM_STRENGTH) * (.2 + .8 * lum) +
                  edge * (2.6 * RIM_STRENGTH) * elevation * (.65 + .35 * lum));
    }
    // Bound aggregate illumination in dense fights without changing hue.
    float peak = max(added.r, max(added.g, added.b));
    added *= 1.0 / (1.0 + peak / 1.4);
    finalColor = peak > 0.0 ? vec4(pow(baseLin + added, vec3(1.0 / 2.2)), base.a) : base;
}
"""
