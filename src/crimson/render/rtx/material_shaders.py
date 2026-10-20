"""Ground material shaders adapted from the crimson-night-argon look development study."""

GROUND_FRAGMENT = r"""
#version 330

#define MAX_SPEC_LIGHTS 32

in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform sampler2D u_surface_tex;  // R=specularity, G=wet amount at epoch, B=volume, A=substrate height
uniform sampler2D u_substrate_tex; // Terrain and non-blood decals, without a second blood tint
uniform sampler2D u_material_tex; // Ordered RGBA coverage: blood, corpse, brass, ice

uniform vec2 u_ground_size;
uniform float u_time_s; // Seconds relative to the wetness epoch
uniform int u_debug; // 0 shaded, 1 substrate normal, 2 liquid normal, 3 freshness, 4 amount, 5 dynamic specular
uniform int u_spec_light_count;
uniform vec4 u_spec_pos[MAX_SPEC_LIGHTS];   // xy = world_pos, z = radius, w = z_height
uniform vec4 u_spec_color[MAX_SPEC_LIGHTS]; // rgb = hdr_color, w = shape (0=point/cone, 1=capsule)
uniform vec4 u_spec_dir[MAX_SPEC_LIGHTS];   // xy = out_dir, z = focus, w = capsule_h
uniform vec4 u_spec_response[MAX_SPEC_LIGHTS]; // illumination, reflection, reflection reach, source width

// Packed float texture: cell headers, body transforms, then lossless cell lists.
uniform sampler2D u_occlusion_tex;
uniform vec4 u_occlusion_grid; // xy world origin, zw cell counts; z=0 disables
uniform float u_occlusion_cell_size;

vec4 occlusionData(int address) {
    int width = textureSize(u_occlusion_tex, 0).x;
    return texelFetch(u_occlusion_tex, ivec2(address % width, address / width), 0);
}

float bodyVisibility(int address, vec3 origin, vec3 ray, float source_width, float inverse_xy_length) {
    vec4 center = occlusionData(address);
    vec2 offset = origin.xy - center.xy;
    float along = clamp(-dot(offset, ray.xy) * inverse_xy_length, 0., 1.);
    vec2 nearest = offset + ray.xy * along;
    // Reject neighboring cell members with one fetch before loading transforms.
    // The bound already includes the largest selected source's soft margin.
    if (dot(nearest, nearest) > center.w * center.w) return 1.;
    vec3 inverse_radius = occlusionData(address + 1).xyz;
    vec4 orientation = occlusionData(address + 2);
    vec2 rotation = orientation.xy;
    mat2 local = mat2(rotation.x, -rotation.y, rotation.y, rotation.x);
    vec3 q = origin - center.xyz;
    q.xy = local * q.xy;
    ray.xy = local * ray.xy;
    q *= inverse_radius;
    ray *= inverse_radius;
    float t = clamp(-dot(q, ray) / max(dot(ray, ray), 1e-8), 0., 1.);
    float distance = length(q + ray * t);
    // Analytic finite-source penumbra. The cone grows from the receiver toward
    // the source; this is a smooth body proxy, not sampled silhouette tracing.
    float softness = max(.015, source_width * t * max(inverse_radius.x, inverse_radius.y));
    return 1. - orientation.z * (1. - smoothstep(1. - softness, 1. + softness, distance));
}

float reflectionVisibility(vec2 receiver, vec2 source, float height, float source_width) {
    if (u_occlusion_grid.z == 0.) return 1.;
    vec2 start = (receiver - u_occlusion_grid.xy) / u_occlusion_cell_size;
    vec2 delta = (source - receiver) / u_occlusion_cell_size;
    ivec2 cell = ivec2(floor(start));
    ivec2 step_cell = ivec2(sign(delta));
    vec2 next_edge = vec2(cell) + step(vec2(0.), delta);
    vec2 t_step = vec2(1e20);
    vec2 t_edge = vec2(1e20);
    if (abs(delta.x) > 1e-8) { t_step.x = abs(1. / delta.x); t_edge.x = (next_edge.x - start.x) / delta.x; }
    if (abs(delta.y) > 1e-8) { t_step.y = abs(1. / delta.y); t_edge.y = (next_edge.y - start.y) / delta.y; }
    vec3 ray = vec3(source - receiver, height);
    float visibility = 1.;
    float inverse_xy_length = 1. / max(dot(ray.xy, ray.xy), 1e-8);
    // Each step crosses one grid boundary. No nearest-body budget drops blockers.
    while (cell.x >= 0 && cell.y >= 0 && cell.x < int(u_occlusion_grid.z) && cell.y < int(u_occlusion_grid.w)) {
        vec4 header = occlusionData(cell.y * int(u_occlusion_grid.z) + cell.x);
        for (int j = 0; j < int(header.y); j++) {
            int address = int(occlusionData(int(header.x) + j).x);
            visibility = min(visibility, bodyVisibility(address, vec3(receiver, 0.), ray, source_width, inverse_xy_length));
            if (visibility < .001) return visibility;
        }
        if (min(t_edge.x, t_edge.y) >= 1.) break;
        if (t_edge.x < t_edge.y) { cell.x += step_cell.x; t_edge.x += t_step.x; }
        else { cell.y += step_cell.y; t_edge.y += t_step.y; }
    }
    return visibility;
}

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
    float optical_depth = -log(1.0 - blood_amount) * 0.65;

    // - wet_film: any blood-wetted surface (thin spatter soaked into dirt or pool)
    // - deep_pool: thick coalesced pool where surface tension forms a smooth, continuous liquid sheet
    float wet_film  = smoothstep(0.04, 0.36, clamp(blood_amount * 1.65, 0.0, 1.0));
    float deep_pool = smoothstep(0.12, 0.95, blood_amount);

    // DUAL-NORMAL LAYERED FLUID MODEL:
    // (A) Substrate Normal N_sub (drives DIFFUSE lighting ONLY):
    vec2 slope_sub = dH_fine + dH_macro * 0.85;
    vec3 N_sub = normalize(vec3(slope_sub.x, slope_sub.y, 1.0));

    // (B) Top-Surface Fluid Normal N_fluid (drives DIELECTRIC SPECULAR ONLY):
    float poolL = smoothstep(0.12, 0.95, 0.45 * amount_l1 + 0.55 * amount_l2);
    float poolR = smoothstep(0.12, 0.95, 0.45 * amount_r1 + 0.55 * amount_r2);
    float poolD = smoothstep(0.12, 0.95, 0.45 * amount_d1 + 0.55 * amount_d2);
    float poolU = smoothstep(0.12, 0.95, 0.45 * amount_u1 + 0.55 * amount_u2);
    vec2 dPool_smooth = vec2(poolL - poolR, poolU - poolD) * (1.0 - 0.65 * deep_pool);

    vec2 slope_fluid = dH_macro * mix(1.35, 0.24, deep_pool) + dH_fine * mix(0.45, 0.04, deep_pool) + dPool_smooth * 0.18;
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

    // Fresh pools keep a red body; age and depth are separate artistic controls.
    // A continuous transition avoids outlining pools with a bright shallow-water band.
    float body_weight = wet_film * mix(0.78, mix(0.22, 0.48, freshness), deep_pool);
    vec3 blood_body_color = vec3(mix(0.05, 0.16, freshness), 0.00003, 0.00005) * body_weight;

    // Exposed ice keeps its substrate/sprite color instead of passing through the blood pigment.
    vec3 diffuse_lit = mix(wetted_substrate * ambient_transmittance + blood_body_color, albedo_tex.rgb, is_ice) * ambient_term;

    // Fixed 30-degree backward virtual eye: reflections land below their emitters.
    // This affects specular only; neither the camera nor player positions steer it.
    vec3 V = normalize(vec3(0.0, 0.57735, 1.0));
    vec3 R = reflect(-V, N_spec);
    vec3 spec_accum = vec3(0.0);

    for (int i = 0; i < MAX_SPEC_LIGHTS; i++) {
        if (i >= u_spec_light_count) break;
        vec4 sp_pos = u_spec_pos[i];
        vec4 sp_col = u_spec_color[i];
        vec4 sp_dir = u_spec_dir[i];
        vec4 response = u_spec_response[i];

        vec2 light_xy = sp_pos.xy;
        vec2 reflection_xy = sp_pos.xy;
        float capsule_axial_gain = 1.0;
        if (sp_col.w > 0.5 && dot(sp_dir.xy, sp_dir.xy) > 0.0001) {
            vec2 axis = normalize(sp_dir.xy);
            float h_len = max(1.0, sp_dir.w);
            float raw_proj = dot(world - sp_pos.xy, axis);
            float proj = clamp(raw_proj, -h_len * 0.5, h_len * 0.5);
            reflection_xy += axis * proj;
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
        float reflection_distance = length(reflection_xy - world);
        float rad = max(1.0, sp_pos.z);
        if (d2d >= rad && reflection_distance >= response.z) continue;

        // Reflection-only tracers need no diffuse optical-path evaluation.
        if (response.x > 0.0 && d2d < rad) {
            float x_att = clamp(1.0 - d2d / rad, 0.0, 1.0);
            float atten = x_att * x_att * capsule_axial_gain;
            vec3 L = normalize(vec3(to_l.x, to_l.y, max(12.0, sp_pos.w)));
            float ndl_sub = clamp(dot(N_sub, L), 0.0, 1.0);
            float flat_ndl = L.z;
            // Each light has its own optical path and relief; fading it cannot recolor other light.
            vec3 transmittance = exp(-absorption * (0.90 + 0.35 / clamp(flat_ndl, 0.22, 1.0)));
            vec3 direct_albedo = mix(wetted_substrate * transmittance + blood_body_color, albedo_tex.rgb, is_ice);
            float relief = clamp((ndl_sub + 0.18) / (flat_ndl + 0.18), 0.64, 1.55);
            diffuse_lit += direct_albedo * sp_col.rgb * (response.x * atten * ndl_sub * 0.22 * relief);
        }

        // Reflect the virtual eye ray into a finite source at the emitter's height.
        // This is an artistic rough-reflection approximation, not a calibrated BRDF.
        if (response.y > 0.0 && R.z > 0.02) {
            float height = max(12., sp_pos.w);
            vec2 reflected_hit = world + R.xy * height / R.z;
            bool beam = sp_col.w > 0.5 && sp_dir.w > 0.0 && dot(sp_dir.xy, sp_dir.xy) > 0.0001;
            float source_gain = 1.0;
            vec2 on_source = sp_pos.xy;
            if (beam) {
                vec2 axis = normalize(sp_dir.xy);
                float along = clamp(dot(reflected_hit - sp_pos.xy, axis), -sp_dir.w * .5, sp_dir.w * .5);
                on_source += axis * along;
                float source_t = clamp(along / sp_dir.w + .5, 0.0, 1.0);
                source_gain = mix(.18, 1.0, source_t);
            }
            float source_distance = length(reflected_hit - on_source);
            float source_width = max(.1, response.w);
            float blur_width = source_width + roughness * roughness * height * 1.8 / R.z;
            float blur_gain = source_width / blur_width;
            // A point source spreads across two dimensions; a beam spreads mostly across its width.
            float footprint = exp(-.5 * pow(source_distance / blur_width, 2.0)) *
                (beam ? blur_gain : blur_gain * blur_gain);
            // Fade at finite light support rather than cutting off a displaced reflection.
            float support = 1.0 - smoothstep(response.z * .8, max(.01, response.z), reflection_distance);
            float NoV = clamp(dot(N_spec, V), 0.0, 1.0);
            float F = .03 + .97 * pow(1. - NoV, 5.);
            float blood_gate = clamp(wet_film*.45 + deep_pool*.78, 0., 1.) * mix(.25, 1., freshness) * (1.-is_ice);
            float material_gate = clamp(blood_gate + is_ice*.75 + is_metal + is_chitin*.25, 0., 1.);
            vec3 tint = mix(vec3(1.), vec3(1., .85, .52), is_metal);
            vec3 reflected = sp_col.rgb * tint * (response.y * F * 24. * footprint * source_gain * material_gate * support);
            // Only meaningful dynamic reflections trace bodies. Ambient, sky and
            // diffuse light are deliberately independent of this visibility.
            if (max(reflected.r, max(reflected.g, reflected.b)) > .00001)
                reflected *= reflectionVisibility(world, on_source, height, source_width);
            spec_accum += reflected;
        }
    }

    if (u_debug == 5) { finalColor = vec4(spec_accum, 1.0); return; }

    // Subtle cold moonlit sky reflection across smooth liquid pools (stronger on fresh blood)
    vec3 H_sky = normalize(normalize(vec3(-0.30, -0.40, 0.86)) + V);
    float ndh_sky = max(0.0, dot(N_spec, H_sky));
    vec3 sky_wet_spec = sky_reflection * pow(ndh_sky, 20.0) *
        ((wet_film * 0.12 + deep_pool * 0.30) * mix(0.45, 1.0, freshness) * (1.0 - is_ice) + is_ice * .30);

    // Each dynamic reflection has its own visibility; the sky stays unchanged.
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
    if (floor(a * 255.0 + 0.5) < 4.0) discard;
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
