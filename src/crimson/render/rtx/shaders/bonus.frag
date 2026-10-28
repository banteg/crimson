#version 330
// Analytical dark bonus shells and lit foil emblems, adapted from the Argon lookdev.
#include "filtering.glsl"
#include "source_geometry.glsl"
#include "linear_light.glsl"
in vec2 fragTexCoord;
in vec4 fragColor;
in vec2 world;
uniform sampler2D texture0;
uniform vec4 colDiffuse;
uniform vec2 u_shell_center;
uniform int u_pass;        // 0 = analytical obsidian-glass sphere, 1 = flat foil/enamel icon + cabochon clear-coat
uniform vec2 u_grid;       // (4, 4) for bonuses.jaz, (4, 8) for ui_wicons.jaz
uniform int u_count;
uniform vec4 u_pos[32];
uniform vec4 u_rgb[32];
uniform vec4 u_dir[32];
uniform vec4 u_response[32]; // illumination, reflection, reflection reach, source width
out vec4 finalColor;

vec4 cellSample(vec2 uv) {
    vec2 cell = floor(fragTexCoord * u_grid) / u_grid;
    vec2 step_uv = 1.0 / u_grid;
    vec2 half_texel = 0.5 / vec2(textureSize(texture0, 0));
    return textureLod(texture0, clamp(uv, cell + half_texel, cell + step_uv - half_texel), 0.0);
}

float cellAlpha(vec2 uv) {
    vec2 cell = floor(fragTexCoord * u_grid) / u_grid;
    vec2 step_uv = 1.0 / u_grid;
    if (any(lessThan(uv, cell)) || any(greaterThanEqual(uv, cell + step_uv)))
        return 0.0;
    return cellSample(uv).a;
}

float cellLum(vec2 uv) {
    return dot(cellSample(uv).rgb, vec3(0.299, 0.587, 0.114));
}

// Evaluate clear-coat spherical cabochon reflection & Fresnel rim for a sphere normal N:
vec3 sphereCoatLight(vec3 N, float r_norm, vec3 V, out vec3 rim_and_caustic) {
    vec3 R = reflect(-V, N);
    float NoV = clamp(dot(N, V), 0.0, 1.0);
    float fresnel = 0.04 + 0.96 * pow(1.0 - NoV, 4.0);
    vec3 spec_sum = vec3(0.0);
    vec3 rim_sum = vec3(0.0);

    for (int i = 0; i < u_count; i++) {
        vec2 dp = world - u_pos[i].xy;
        float along = clamp(dot(dp, u_dir[i].xy), -u_dir[i].w * 0.5, u_dir[i].w * 0.5);
        vec2 source = u_rgb[i].w > 0. ? nearestRingPoint(u_pos[i].xy, world, u_rgb[i].w) : u_pos[i].xy + u_dir[i].xy * along;
        vec2 delta = source - world;
        float dist = length(delta);
        if (dist >= max(u_pos[i].z, u_response[i].z))
            continue;
        float a = 1.0 - smoothstep(0.0, u_pos[i].z, dist);
        float s = 1.0 - smoothstep(0.0, u_response[i].z, dist);
        float axial = u_rgb[i].w <= 0. && u_dir[i].w > 0.0
            ? segmentRadiance(along / max(u_dir[i].w, 1.0) + 0.5, u_dir[i].z)
            : 1.0;
        float weight = s * s * axial * u_response[i].y;
        float illumination_weight = a * a * axial * u_response[i].x;
        float source_width = max(.1, u_response[i].w);

        vec3 L = normalize(vec3(delta, max(14.0, u_pos[i].w)));
        vec3 H = normalize(L + V);
        float ndl = max(dot(N, L), 0.0);
        float ndh = max(dot(N, H), 0.0);

        // 1. Curved convex-mirror reflection of finite 1D beam or point orb on the sphere:
        float coat_spec = (pow(ndh, 52.0) * 3.4 + pow(ndh, 12.0) * 0.55 * ndl) *
                          min(1.0, source_width / 3.0);
        if (R.z > 0.05) {
            vec2 hit = world + R.xy * max(16.0, u_pos[i].w) / R.z;
            float hit_along = clamp(dot(hit - u_pos[i].xy, u_dir[i].xy), -u_dir[i].w * 0.5, u_dir[i].w * 0.5);
            vec2 on_beam = u_rgb[i].w > 0. ? nearestRingPoint(u_pos[i].xy, hit, u_rgb[i].w) : u_pos[i].xy + u_dir[i].xy * hit_along;
            float d_beam = length(hit - on_beam);
            float reflected_width = source_width * (8.0 / 3.0);
            coat_spec += exp(-0.5 * pow(d_beam / reflected_width, 2.0)) * 2.2 * ndl;
        }

        // 2. Grazing Fresnel glass crescent around the sphere edge facing the emitter:
        vec2 dir2d = normalize(delta + vec2(1e-4));
        float rim_align = clamp(dot(N.xy, dir2d), 0.0, 1.0);
        float fresnel_crescent = pow(1.0 - N.z, 2.3) * pow(rim_align, 1.3) * 1.85;

        // 3. Art-directed opposite-wall glow suggesting internal refraction (not a traced caustic):
        float back_align = clamp(dot(-N.xy, dir2d), 0.0, 1.0);
        float back_caustic = smoothstep(0.32, 0.80, r_norm) * (1.0 - smoothstep(0.80, 0.98, r_norm))
            * pow(back_align, 2.6) * N.z * 0.36;

        spec_sum += u_rgb[i].rgb * weight * coat_spec * (0.38 + 0.62 * fresnel);
        rim_sum += u_rgb[i].rgb * (weight * fresnel_crescent * min(1.0, source_width / 3.0) +
                                   illumination_weight * back_caustic);
    }
    rim_and_caustic = rim_sum;
    return spec_sum;
}

void main() {
    vec4 texel = alphaBilinear(texture0, fragTexCoord);
    vec4 base = texel * fragColor * colDiffuse;
    vec2 dxq = dFdx(fragTexCoord * u_grid) * 2.0;
    vec2 dyq = dFdy(fragTexCoord * u_grid) * 2.0;
    vec2 dxw = dFdx(world);
    vec2 dyw = dFdy(world);

    vec2 q_cell = fract(fragTexCoord * u_grid) * 2.0 - 1.0;
    vec3 V = normalize(vec3(0.0, 0.35, 1.0));

    if (u_pass == 0) {
        // PASS 0: Analytical Jet-Black Obsidian / Clear-Coat Sphere
        float r = length(q_cell) / 0.885;
        float aa = max(fwidth(r), 0.035);
        float sphere_a = (1.0 - smoothstep(1.0 - aa, 1.0 + aa * 0.5, r)) * fragColor.a * colDiffuse.a;
        if (sphere_a <= 4.0 / 255.0)
            discard;

        vec2 p = q_cell / 0.885;
        float r_clamped = min(1.0, length(p));
        float nz = sqrt(max(0.015, 1.0 - r_clamped * r_clamped));
        vec3 N = normalize(vec3(p.x, p.y, nz));

        // Jet-black obsidian core (matches classic (5,5,5) center) + crisp top-right studio key highlight:
        vec3 L_key = normalize(vec3(0.45, -0.48, 0.75));
        vec3 H_key = normalize(L_key + V);
        float key_spec = pow(max(dot(N, H_key), 0.0), 34.0) * 0.16 + pow(max(dot(N, H_key), 0.0), 8.0) * 0.024;
        float rim_ambient = pow(1.0 - nz, 3.2) * 0.014;
        vec3 sphere_lin = vec3(0.00018, 0.00020, 0.00028) + vec3(0.94, 0.97, 1.0) * (key_spec + rim_ambient);

        vec3 rim_caustic = vec3(0.0);
        vec3 coat_spec = sphereCoatLight(N, r_clamped, V, rim_caustic);
        vec3 dyn_accum = coat_spec + rim_caustic;

        finalColor = vec4(max(sphere_lin + dyn_accum, vec3(0.0)), sphere_a);
        return;
    }

    // PASS 1: Flat Foil/Enamel Icon Slapped on Top of the Sphere + Clear-Coat Cabochon Glint
    if (floor(base.a * 255.0 + 0.5) < 4.0)
        discard;
    if (u_count == 0) {
        finalColor = vec4(decodeArt(base.rgb), base.a);
        return;
    }

    float det = dxq.x * dyq.y - dxq.y * dyq.x;
    mat2 rot = mat2(1.0);
    if (abs(det) > 1e-12) {
        mat2 basis = mat2(dxw * dyq.y - dyw * dxq.y, dyw * dxq.x - dxw * dyq.x) / det;
        rot = mat2(normalize(basis[0]), normalize(basis[1]));
    }

    // 1. Flat emblem normal with crisp 1-texel foil/enamel edge bevel:
    vec2 px = 1.0 / vec2(textureSize(texture0, 0));
    vec2 relief = 0.5 * vec2(
        cellLum(fragTexCoord + vec2(px.x, 0.0)) - cellLum(fragTexCoord - vec2(px.x, 0.0)),
        cellLum(fragTexCoord + vec2(0.0, px.y)) - cellLum(fragTexCoord - vec2(0.0, px.y))
    );
    // Brighter texels are raised: the height-field normal points downhill.
    vec2 slope_flat = rot * (q_cell * 0.22 - relief * 1.15);
    vec3 N_flat = normalize(vec3(slope_flat, sqrt(max(0.25, 1.0 - dot(slope_flat, slope_flat)))));

    // 2. Underlying spherical cabochon normal for clear-coat specular over the flat icon:
    // The icon may pulse, rotate, or overhang: the coating stays on the fixed 32-unit shell.
    vec2 p_dome = (world - u_shell_center) / (16.0 * 0.885);
    float r_dome = min(1.0, length(p_dome));
    vec3 N_dome = normalize(vec3(p_dome, sqrt(max(0.015, 1.0 - r_dome * r_dome))));

    float lum = dot(texel.rgb, vec3(0.299, 0.587, 0.114));
    vec3 base_lin = decodeArt(base.rgb);
    vec3 added = vec3(0.0);

    for (int i = 0; i < u_count; i++) {
        vec2 dp = world - u_pos[i].xy;
        float along = clamp(dot(dp, u_dir[i].xy), -u_dir[i].w * 0.5, u_dir[i].w * 0.5);
        vec2 source = u_rgb[i].w > 0. ? nearestRingPoint(u_pos[i].xy, world, u_rgb[i].w) : u_pos[i].xy + u_dir[i].xy * along;
        vec2 delta = source - world;
        float dist = length(delta);
        if (dist >= max(u_pos[i].z, u_response[i].z))
            continue;
        float a = 1.0 - smoothstep(0.0, u_pos[i].z, dist);
        float s = 1.0 - smoothstep(0.0, u_response[i].z, dist);
        float axial = u_rgb[i].w <= 0. && u_dir[i].w > 0.0
            ? segmentRadiance(along / max(u_dir[i].w, 1.0) + 0.5, u_dir[i].z)
            : 1.0;

        vec3 L = normalize(vec3(delta, max(12.0, u_pos[i].w - 4.0)));
        float facing_flat = max(dot(N_flat, L), 0.0);
        vec3 H = normalize(L + V);
        float foil_sheen = pow(max(dot(N_flat, H), 0.0), 18.0) * facing_flat;

        // 3-tap embossed foil/enamel edge catch-light on the icon contour facing the light:
        vec2 toward = transpose(rot) * normalize(delta + vec2(1e-4));
        vec2 side = vec2(-toward.y, toward.x);
        float beyond = (
            cellAlpha(fragTexCoord + toward * px * 1.4) +
            cellAlpha(fragTexCoord + (toward * 1.4 + side * 0.6) * px) +
            cellAlpha(fragTexCoord + (toward * 1.4 - side * 0.6) * px)
        ) / 3.0;
        float edge = smoothstep(0.04, 0.68, max(0.0, texel.a - beyond));

        added += u_rgb[i].rgb * axial * (
            u_response[i].x * a * a * (base_lin * 0.78 * facing_flat + edge * 1.85 * (0.55 + 0.45 * lum)) +
            u_response[i].y * s * s * min(1.0, u_response[i].w / 3.0) * foil_sheen * 1.15 * (0.25 + 0.75 * lum)
        );
    }

    // Share the shell's exact reflection and crescent over the emblem.
    // Weapon barrels outside its footprint retain foil lighting but have no spherical coat.
    float coat_gate = 1.0 - smoothstep(0.98, 1.0, length(p_dome));
    if (coat_gate > 0.0) {
        vec3 rim_caustic = vec3(0.0);
        vec3 coat = sphereCoatLight(N_dome, r_dome, V, rim_caustic);
        coat += rim_caustic;
        added += coat * coat_gate;
    }
    finalColor = vec4(base_lin + added, base.a);
}
