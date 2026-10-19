"""Ground material shaders adapted from the crimson-night-argon look development study."""

GROUND_FRAGMENT = r"""
#version 330

#define MAX_SPEC_LIGHTS 16

in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform sampler2D u_surface_tex;  // R=specularity, G=wet amount at epoch, B=volume, A=substrate height
uniform sampler2D u_substrate_tex; // Terrain and non-blood decals, without a second blood tint
uniform sampler2D u_material_tex; // Ordered RGBA coverage: blood, corpse, brass, ice

uniform vec2 u_ground_size;
uniform float u_time_s; // Seconds relative to the wetness epoch
uniform int u_debug; // 0 shaded, 1 substrate normal, 2 liquid normal, 3 freshness, 4 amount
uniform int u_spec_light_count;
uniform vec4 u_spec_pos[MAX_SPEC_LIGHTS];   // xy = world_pos, z = radius, w = z_height
uniform vec4 u_spec_color[MAX_SPEC_LIGHTS]; // rgb = hdr_color, w = shape (0=point/cone, 1=capsule)
uniform vec4 u_spec_dir[MAX_SPEC_LIGHTS];   // xy = out_dir, z = focus, w = capsule_h

float blood_below_ice(vec4 surface, vec4 coverage) {
    // Ice occludes the film; it does not thin it into a new red meniscus.
    // Both stored volume and blood coverage have been attenuated by the ice opacity.
    float exposed = max(1.0 - coverage.a, 0.001);
    return clamp(surface.b * coverage.r / (exposed * exposed), 0.0, 0.999);
}

void main() {
    vec2 ground_uv = fragTexCoord;
    vec2 world = vec2(ground_uv.x, 1.0 - ground_uv.y) * u_ground_size;
    // Source textures and the existing world compositor are approximately gamma-2.2 encoded.
    // Shade in linear RGB and encode exactly once when returning to that compositor.
    vec4 albedo_tex = texture(u_substrate_tex, ground_uv);
    albedo_tex.rgb = pow(max(albedo_tex.rgb, vec3(0.)), vec3(2.2));
    vec4 surf = texture(u_surface_tex, ground_uv);

    vec2 step_fine = vec2(1.2 / u_ground_size);
    vec2 step_med  = vec2(3.2 / u_ground_size);
    vec4 sL1 = texture(u_surface_tex, ground_uv + vec2(-step_fine.x, 0.0));
    vec4 sR1 = texture(u_surface_tex, ground_uv + vec2( step_fine.x, 0.0));
    vec4 sD1 = texture(u_surface_tex, ground_uv + vec2(0.0, -step_fine.y));
    vec4 sU1 = texture(u_surface_tex, ground_uv + vec2(0.0,  step_fine.y));
    vec4 sL2 = texture(u_surface_tex, ground_uv + vec2(-step_med.x, 0.0));
    vec4 sR2 = texture(u_surface_tex, ground_uv + vec2( step_med.x, 0.0));
    vec4 sD2 = texture(u_surface_tex, ground_uv + vec2(0.0, -step_med.y));
    vec4 sU2 = texture(u_surface_tex, ground_uv + vec2(0.0,  step_med.y));

    vec2 dH_fine  = vec2(sL1.a - sR1.a, sU1.a - sD1.a) * 1.35;
    vec2 dH_macro = vec2(sL2.a - sR2.a, sU2.a - sD2.a) * 1.15;

    // Explicit ordered material coverage, independent of the painted albedo hue.
    vec4 weights = texture(u_material_tex, ground_uv);
    float is_ice = weights.a;
    float amount_l1 = blood_below_ice(sL1, texture(u_material_tex, ground_uv + vec2(-step_fine.x, 0)));
    float amount_r1 = blood_below_ice(sR1, texture(u_material_tex, ground_uv + vec2( step_fine.x, 0)));
    float amount_d1 = blood_below_ice(sD1, texture(u_material_tex, ground_uv + vec2(0, -step_fine.y)));
    float amount_u1 = blood_below_ice(sU1, texture(u_material_tex, ground_uv + vec2(0,  step_fine.y)));
    float amount_l2 = blood_below_ice(sL2, texture(u_material_tex, ground_uv + vec2(-step_med.x, 0)));
    float amount_r2 = blood_below_ice(sR2, texture(u_material_tex, ground_uv + vec2( step_med.x, 0)));
    float amount_d2 = blood_below_ice(sD2, texture(u_material_tex, ground_uv + vec2(0, -step_med.y)));
    float amount_u2 = blood_below_ice(sU2, texture(u_material_tex, ground_uv + vec2(0,  step_med.y)));

    float blood_amount = blood_below_ice(surf, weights);
    float pool_amount = clamp(blood_amount * 1.65, 0.0, 1.0);
    float optical_depth = -log(1.0 - blood_amount) * 0.65;

    // - wet_film: any blood-wetted surface (thin spatter soaked into dirt or pool)
    // - deep_pool: thick coalesced pool where surface tension forms a smooth, continuous liquid sheet
    float wet_film  = smoothstep(0.04, 0.36, pool_amount);
    float deep_pool = smoothstep(0.42, 0.82, pool_amount);

    // DUAL-NORMAL LAYERED FLUID MODEL:
    // (A) Substrate Normal N_sub (drives DIFFUSE lighting ONLY):
    vec2 slope_sub = dH_fine + dH_macro * 0.85;
    vec3 N_sub = normalize(vec3(slope_sub.x, slope_sub.y, 1.0));

    // (B) Top-Surface Fluid Normal N_fluid (drives DIELECTRIC SPECULAR ONLY):
    float poolL = smoothstep(0.38, 0.80, 0.45 * amount_l1 + 0.55 * amount_l2);
    float poolR = smoothstep(0.38, 0.80, 0.45 * amount_r1 + 0.55 * amount_r2);
    float poolD = smoothstep(0.38, 0.80, 0.45 * amount_d1 + 0.55 * amount_d2);
    float poolU = smoothstep(0.38, 0.80, 0.45 * amount_u1 + 0.55 * amount_u2);
    vec2 dPool_smooth = vec2(poolL - poolR, poolU - poolD) * (1.0 - 0.65 * deep_pool);

    vec2 slope_fluid = dH_macro * mix(1.35, 0.24, deep_pool) + dH_fine * mix(0.45, 0.04, deep_pool) + dPool_smooth * 0.42;
    vec3 N_fluid = normalize(vec3(slope_fluid.x, slope_fluid.y, 1.0));

    // G and B are filtered with identical weights. Their ratio keeps bare thin spray fresh,
    // but only its contribution refreshes an older pool. Epoch rebasing prevents overflow.
    float freshness = surf.b > 1e-8 ? clamp(surf.g / surf.b * exp(-max(0., u_time_s) / 45.), 0., 1.) : 0.;
    if (u_debug == 1) { finalColor = vec4(N_sub * .5 + .5, 1.); return; }
    if (u_debug == 2) { finalColor = vec4(N_fluid * .5 + .5, 1.); return; }
    if (u_debug == 3) { finalColor = vec4(vec3(freshness), 1.); return; }
    if (u_debug == 4) { finalColor = vec4(vec3(blood_amount), 1.); return; }
    float is_metal = weights.b;
    float is_chitin = weights.g;
    float blood_smooth = mix(0.52, 0.91, freshness);
    float smoothness = max(0.12 * (1.0 - wet_film), mix(wet_film * 0.68 * freshness, blood_smooth, deep_pool));
    smoothness = mix(max(smoothness, max(is_metal * 0.88, is_chitin * 0.42)), .90, is_ice);
    vec3 N_spec = normalize(mix(N_fluid, N_sub, is_ice));
    float roughness = clamp(1.0 - smoothness, 0.09, 0.92);

    // Readable daylight floor: lighting adds to the scene, never blacks out its unlit regions.
    float daylight_ndl = clamp(dot(N_sub, normalize(vec3(-0.38, -0.48, 0.79))), 0.0, 1.0);
    vec3 ambient_term = vec3(0.94 + 0.08 * daylight_ndl);
    vec3 sky_reflection = pow(vec3(0.22, 0.25, 0.30), vec3(2.2));
    float soil_lum = dot(albedo_tex.rgb, vec3(0.299, 0.587, 0.114));
    vec3 base_substrate = mix(albedo_tex.rgb, vec3(soil_lum * 1.04, soil_lum * 0.98, soil_lum * 0.92), wet_film * 0.85);
    vec3 wetted_substrate = base_substrate * mix(1.0, 0.38, wet_film);

    // Beer-Lambert double-pass optical path through hemoglobin layer (older coagulated blood darkens further):
    float coag_darken = mix(1.25, 1.0, freshness);
    vec3 absorption = optical_depth * (0.85 + 1.15 * deep_pool) * coag_darken * vec3(1.35, 9.50, 12.50);
    // Ambient transmission never depends on the dynamic emitter list or its intensity.
    vec3 ambient_transmittance = exp(-absorption * (0.90 + 0.35 / 0.55));

    float ruby_shallows = sin(clamp(pool_amount, 0.0, 1.0) * 3.14159);
    vec3 erythrocyte_sss = vec3(0.08 * mix(0.65, 1.0, freshness), 0.00003, 0.00005) * (ruby_shallows * 0.78 + deep_pool * 0.22);

    // Exposed ice keeps its substrate/sprite color instead of passing through the blood pigment.
    vec3 diffuse_lit = mix(wetted_substrate * ambient_transmittance + erythrocyte_sss, albedo_tex.rgb, is_ice) * ambient_term;

    vec3 V = normalize(vec3(0.0, 0.0, 1.0));
    vec3 spec_accum = vec3(0.0);

    for (int i = 0; i < MAX_SPEC_LIGHTS; i++) {
        if (i >= u_spec_light_count) break;
        vec4 sp_pos = u_spec_pos[i];
        vec4 sp_col = u_spec_color[i];
        vec4 sp_dir = u_spec_dir[i];

        vec2 light_xy = sp_pos.xy;
        float capsule_axial_gain = 1.0;
        if (sp_col.w > 0.5 && dot(sp_dir.xy, sp_dir.xy) > 0.0001) {
            vec2 axis = normalize(sp_dir.xy);
            float h_len = max(1.0, sp_dir.w);
            float raw_proj = dot(world - sp_pos.xy, axis);
            float proj = clamp(raw_proj, -h_len * 0.5, h_len * 0.5);
            // Bias reflection point toward the blazing projectile head (+0.45 * h_len)
            float biased_proj = mix(proj, h_len * 0.45, 0.24);
            light_xy = sp_pos.xy + axis * biased_proj;
            // Steep head-to-tail intensity taper: blazing comet head -> fading tail!
            float axis_t = clamp((proj + h_len * 0.5) / h_len, 0.0, 1.0);
            float head_dist = length(world - (sp_pos.xy + axis * (h_len * 0.45)));
            float head_hotspot = exp(-head_dist / max(18.0, sp_pos.z * 0.28)) * 0.65;
            capsule_axial_gain = mix(0.12, 1.05, pow(axis_t, 1.85)) + head_hotspot;
        }

        vec2 to_l = light_xy - world;
        float d2d = length(to_l);
        float rad = max(1.0, sp_pos.z);
        if (d2d >= rad) continue;

        float x_att = clamp(1.0 - d2d / rad, 0.0, 1.0);
        float atten = x_att * x_att * capsule_axial_gain;

        vec3 L = normalize(vec3(to_l.x, to_l.y, max(12.0, sp_pos.w)));
        float ndl_sub = clamp(dot(N_sub, L), 0.0, 1.0);
        float flat_ndl = L.z;
        // Each light has its own optical path and relief; fading it cannot recolor other light.
        vec3 transmittance = exp(-absorption * (0.90 + 0.35 / clamp(flat_ndl, 0.22, 1.0)));
        vec3 direct_albedo = mix(wetted_substrate * transmittance + erythrocyte_sss, albedo_tex.rgb, is_ice);
        float relief = clamp((ndl_sub + 0.18) / (flat_ndl + 0.18), 0.64, 1.55);
        diffuse_lit += direct_albedo * sp_col.rgb * (atten * ndl_sub * 0.22 * relief);

        // Specular reflection uses N_fluid (smooth coalesced liquid sheet inside pools + wet rock facets):
        float z_refl = max(44.0, sp_pos.w * 3.2);
        vec3 L_refl = normalize(vec3(to_l.x, to_l.y, z_refl));
        vec3 H = normalize(L_refl + V);
        float ndh = max(0.0, dot(N_spec, H));

        // Dual-Lobe Wet GGX:
        // 1. Tight liquid mirror core (a2_core) on coalesced pools & light-facing meniscus
        float a = roughness * roughness;
        float a2 = max(0.0022, a * a);
        float denom = (ndh * ndh) * (a2 - 1.0) + 1.0;
        float D_core = a2 / (3.14159 * denom * denom);

        // 2. Smooth glossy liquid sheen (a2_sheen = 0.018) that gives continuous, non-sparkly wet body across pools
        float denom_sheen = (ndh * ndh) * (0.018 - 1.0) + 1.0;
        float D_sheen = 0.018 / (3.14159 * denom_sheen * denom_sheen);

        float fresnel = 0.03 + 0.97 * pow(clamp(1.0 - L_refl.z, 0.0, 1.0), 2.2);
        float fresh_spec_scale = mix(0.42, 1.0, freshness);
        float wet_response = clamp(wet_film * 0.45 + deep_pool * 0.78, 0.0, 1.0) * fresh_spec_scale * (1.0 - is_ice);
        float material_response = is_metal + is_chitin * 0.4 + is_ice * 0.75;
        float wet_gate = mix(0.012, 0.94, clamp(wet_response + material_response, 0.0, 1.0));
        float D_combined = min(5.5, D_core * 0.65 + D_sheen * (0.35 + 0.55 * deep_pool));
        float spec_brdf = D_combined * (0.30 + 0.70 * fresnel) * wet_gate * 0.46;

        vec3 spec_tint = mix(vec3(1.0), vec3(1.0, 0.85, 0.52), is_metal);
        spec_accum += sp_col.rgb * spec_tint * (spec_brdf * atten);
    }

    // Subtle cold moonlit sky reflection across smooth liquid pools (stronger on fresh blood)
    vec3 H_sky = normalize(vec3(-0.15, -0.20, 0.96));
    float ndh_sky = max(0.0, dot(N_spec, H_sky));
    vec3 sky_wet_spec = sky_reflection * pow(ndh_sky, 20.0) *
        ((wet_film * 0.12 + deep_pool * 0.30) * mix(0.45, 1.0, freshness) * (1.0 - is_ice) + is_ice * .30);

    // Visibility/shadows are a separate lighting follow-up. Never gate all lights with one mean shadow.
    vec3 reflected_light = spec_accum + sky_wet_spec;
    // HdrRenderer owns the only display shoulder; preserve highlights above 1 here.
    finalColor = vec4(pow(max(diffuse_lit + reflected_light, vec3(0.0)), vec3(1.0 / 2.2)), 1.0);
}
"""

STAMP_FRAGMENT = r"""
#version 330
in vec2 fragTexCoord;
in vec4 fragColor;
uniform sampler2D texture0;
uniform int u_kind; // 0 terrain, 1 blood, 2 corpse, 3 brass, 4 scorch, 5 ice
uniform int u_pass; // 0 coverage, 1 specularity/wetness/volume, 2 substrate height, 3 wetness rebase
uniform float u_wetness; // exp((deposit - epoch) / 45), or multiplicative rebase factor
out vec4 finalColor;
void main() {
    if (u_pass == 3) { finalColor = vec4(0., u_wetness, 0., 0.); return; }
    vec4 t = texture(texture0, fragTexCoord);
    float a = t.a * fragColor.a;
    if (a <= 4.0 / 255.0) discard;
    float lum = dot(t.rgb, vec3(.299, .587, .114));
    if (u_kind == 0) {
        finalColor = vec4(.04, 0., 0., clamp(.45 + (lum - .42) * .65, .05, .95));
        return;
    }
    if (u_pass == 0) {
        finalColor = vec4(float(u_kind == 1), float(u_kind == 2), float(u_kind == 3), a);
        return;
    }
    if (u_kind == 1) {
        // All five blood sprites occupy the atlas's 8x8 grid. Local UV needs no per-decal uniform.
        vec2 q = fract(fragTexCoord * 8.) * 2. - 1.;
        float radial = 1. - smoothstep(.10, 1., min(1., dot(q, q)));
        float volume = clamp(a * (.34 + .26 * radial), 0., .62);
        finalColor = vec4(0., volume * u_wetness, volume, volume);
        return;
    }
    float spec = u_kind == 2 ? .28 : (u_kind == 3 ? .96 : (u_kind == 5 ? .92 : .01));
    float height = u_kind == 2 ? (.045 + .075 * lum) : (u_kind == 3 || u_kind == 5 ? .14 : 0.);
    // Pass 2 accumulates relief: H' = H + (1-H)*height*a, rather than replacing terrain height.
    // Corpses/casings rise above the substrate while inheriting some of its texture; scorch adds no relief.
    finalColor = u_pass == 1 ? vec4(spec, 0., 0., a) : vec4(0., 0., 0., height * a);
}
"""
