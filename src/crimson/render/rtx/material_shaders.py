"""Ground material shaders adapted from the crimson-night-argon look development study."""

from .continuous_beam_shaders import CONTINUOUS_BEAM_GLSL
from .lighting_shaders import LIGHT_VISIBILITY_GLSL

GROUND_FRAGMENT = r"""
#version 330
#define CONTINUOUS_BEAM

#define MAX_SPEC_LIGHTS 32

in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform sampler2D u_surface_tex;  // R=specularity, G=wet amount at epoch, B=volume, A=substrate height
uniform sampler2D u_substrate_tex; // Terrain and non-blood decals, without a second blood tint
uniform sampler2D u_material_tex; // Ordered RGBA coverage: blood, corpse, brass, ice

uniform vec2 u_ground_size;
uniform float u_time_s; // Seconds relative to the wetness epoch
uniform int u_debug; // RtxDebugView: raw data maps bypass gamma and display tonemapping
uniform int u_debug_display; // Map radiance for live viewing; explicit diagnostic probes retain linear RGB.
uniform int u_spec_light_count;
uniform vec4 u_spec_pos[MAX_SPEC_LIGHTS];   // xy = world_pos, z = radius, w = z_height
uniform float u_spec_tail[MAX_SPEC_LIGHTS]; // Reflection radiance at the negative segment endpoint
uniform vec4 u_spec_color[MAX_SPEC_LIGHTS]; // rgb = hdr_color, w = annulus radius (0=disc/segment)
uniform vec4 u_spec_dir[MAX_SPEC_LIGHTS];   // xy = out_dir, z = broad illumination, w = capsule_h
uniform vec4 u_spec_response[MAX_SPEC_LIGHTS]; // illumination, reflection, reflection reach, source width

""" + LIGHT_VISIBILITY_GLSL + CONTINUOUS_BEAM_GLSL + r"""
float blood_below_ice(vec4 surface, vec4 coverage) {
    // Ice occludes the film; it does not thin it into a new red meniscus.
    // Both stored volume and blood coverage have been attenuated by the ice opacity.
    float exposed = max(1.0 - coverage.a, 0.001);
    return clamp(surface.b * coverage.r / (exposed * exposed), 0.0, 0.999);
}

vec3 debug_radiance(vec3 value) {
    if (u_debug_display == 0) return value;
    vec3 positive = max(value, vec3(0.));
    return pow(positive / (vec3(1.) + positive), vec3(1. / 2.2));
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
    if (u_debug == 9) { finalColor = vec4(pow(albedo_tex.rgb, vec3(1./2.2)), 1.); return; }
    if (u_debug == 11) { finalColor = vec4(vec3(surf.a), 1.); return; }
    if (u_debug == 12) { finalColor = vec4(mix(weights.rgb, vec3(0.,1.,1.), weights.a), 1.); return; }
    float is_metal = weights.b;
    float is_chitin = weights.g;
    float blood_smooth = mix(0.52, 0.91, freshness);
    float smoothness = max(0.12 * (1.0 - wet_film), mix(wet_film * 0.68 * freshness, blood_smooth, deep_pool));
    smoothness = mix(max(smoothness, max(is_metal * 0.88, is_chitin * 0.42)), .90, is_ice);
    vec3 N_spec = normalize(mix(N_fluid, N_sub, is_ice));
    float roughness = clamp(1.0 - smoothness, 0.09, 0.92);

    if (u_debug == 10) { finalColor = vec4(vec3(roughness), 1.); return; }

    // Readable daylight floor: lighting adds to the scene, never blacks out its unlit regions.
    float daylight_ndl = clamp(dot(N_sub, normalize(vec3(-0.38, -0.48, 0.79))), 0.0, 1.0);
    vec3 ambient_term = vec3(0.50 + 0.12 * daylight_ndl);
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
    // Beam contrast is local, bounded, and fades with the source.
    // Take the strongest local dip; overlapping sources never multiply to black.
    float beam_dip = 0.;
    if (u_has_beam_lights != 0) {
        for (int i=0;i<u_spec_light_count;i++) {
            if (u_line_cells[i * 3].x <= 0.) continue;
            vec2 axis=dot(u_spec_dir[i].xy, u_spec_dir[i].xy) > .0001?normalize(u_spec_dir[i].xy):vec2(1.,0.);
            vec2 delta=world-u_spec_pos[i].xy;
            float half_span=u_spec_dir[i].w * .5;
            float distance=length(delta-axis*clamp(dot(delta,axis),-half_span,half_span));
            float local=1.-smoothstep(40.,300.,distance);
            float power=clamp(max(u_spec_color[i].r,max(u_spec_color[i].g,u_spec_color[i].b))/1.65,0.,1.);
            float dip=u_line_cells[i * 3].w > .5 ? u_beam_tuning.y : u_beam_tuning.w;
            beam_dip=max(beam_dip,dip*local*power);
        }
    }
    ambient_term*=1.-beam_dip;
    vec3 diffuse_lit = mix(wetted_substrate * ambient_transmittance + blood_body_color, albedo_tex.rgb, is_ice) * ambient_term;

    // Fixed 30-degree backward virtual eye: reflections land below their emitters.
    // This affects specular only; neither the camera nor player positions steer it.
    vec3 V = normalize(vec3(0.0, 0.57735, 1.0));
    vec3 R = reflect(-V, N_spec);
    vec3 spec_accum = vec3(0.0);
    vec3 ambient_lit = diffuse_lit;
    vec3 direct_unshadowed = vec3(0.);
    vec3 direct_shadowed = vec3(0.);

    for (int i = 0; i < MAX_SPEC_LIGHTS; i++) {
        if (i >= u_spec_light_count) break;
        vec4 sp_pos = u_spec_pos[i];
        vec4 sp_col = u_spec_color[i];
        vec4 sp_dir = u_spec_dir[i];
        vec4 response = u_spec_response[i];

        vec2 axis = dot(sp_dir.xy, sp_dir.xy) > .0001 ? normalize(sp_dir.xy) : vec2(0.);
        vec2 light_xy = illuminationSource(sp_pos.xy, axis, sp_dir.w);
        vec2 reflection_xy = sp_pos.xy + axis * clamp(dot(world - sp_pos.xy, axis), -sp_dir.w*.5, sp_dir.w*.5);
        bool ring = sp_col.w > 0.0;
        if (ring) {
            light_xy = nearestRingPoint(sp_pos.xy, world, sp_col.w);
            reflection_xy = light_xy;
        }
        vec2 to_l = light_xy - world;
        float d2d = length(to_l);
        float reflection_distance = length(reflection_xy - world);
        float rad = max(1.0, sp_pos.z);
        bool continuous=u_has_beam_lights!=0 && u_line_cells[i * 3].x > 0. && response.x>0.;
        if (!continuous && reflection_distance >= max(rad, response.z)) continue;
        if (continuous) {
            vec2 source_axis=dot(sp_dir.xy, sp_dir.xy) > .0001?normalize(sp_dir.xy):vec2(1.,0.);
            vec2 delta=world-sp_pos.xy;
            float half_span=beamSampleExtent(i);
            float support_distance=length(delta-source_axis*clamp(dot(delta,source_axis),-half_span,half_span));
            if(support_distance<rad) {
                vec3 unshadowed;
                vec3 direct=continuousLight(i,sp_dir,world,N_sub,absorption,wetted_substrate,blood_body_color,albedo_tex.rgb,is_ice,sp_pos,sp_col,response,sp_dir.z,unshadowed);
                direct_unshadowed+=unshadowed;
                direct_shadowed+=direct;
                diffuse_lit+=direct;
            }
        } else if (response.x > 0.0 && d2d < rad) {
            float atten = pow(max(0., 1. - d2d / rad), 2.);
            vec3 L = normalize(vec3(to_l, max(.001, sp_pos.w)));
            float ndl_sub = max(dot(N_sub, L), 0.);
            vec3 transmittance = exp(-absorption * (.90 + .35 / clamp(L.z, .22, 1.)));
            vec3 direct_albedo = mix(wetted_substrate * transmittance + blood_body_color, albedo_tex.rgb, is_ice);
            // Weak sources retain their original angular response. Broad grazing
            // fill is an explicit energetic-source policy, not inferred from gain.
            float relief = sp_dir.z > .5 ? clamp((ndl_sub + .10) / (L.z + .10), .35, 2.5)
                                         : clamp((ndl_sub + .18) / (L.z + .18), .64, 1.55);
            float angular_response = sp_dir.z > .5 ? .22 + .78 * ndl_sub : .22 * ndl_sub;
            vec3 direct = direct_albedo * sp_col.rgb * (response.x * atten * angular_response * relief);
            direct_unshadowed += direct;
            // As with reflections, retain negligible radiance without tracing a
            // shadow whose maximum possible change is below 1e-5 linear RGB.
            if (max(direct.r, max(direct.g, direct.b)) > .00001)
                direct *= illuminationVisibility(vec3(world, 0.), vec3(light_xy, sp_pos.w), response.w, vec2(1e19));
            diffuse_lit += direct;
            direct_shadowed += direct;
        }

        // Reflect the virtual eye ray into a finite source at the emitter's height.
        // This is an artistic rough-reflection approximation, not a calibrated BRDF.
        if (response.y > 0.0 && R.z > 0.02) {
            float height = max(12., sp_pos.w);
            vec2 reflected_hit = world + R.xy * height / R.z;
            bool beam = !ring && sp_dir.w > 0.0 && dot(sp_dir.xy, sp_dir.xy) > 0.0001;
            float source_gain = 1.0;
            vec2 on_source = ring ? nearestRingPoint(sp_pos.xy, reflected_hit, sp_col.w) : sp_pos.xy;
            if (beam) {
                vec2 axis = normalize(sp_dir.xy);
                float along = clamp(dot(reflected_hit - sp_pos.xy, axis), -sp_dir.w * .5, sp_dir.w * .5);
                on_source += axis * along;
                float source_t = clamp(along / sp_dir.w + .5, 0.0, 1.0);
                source_gain = mix(u_spec_tail[i], 1.0, source_t);
            }
            float source_distance = length(reflected_hit - on_source);
            float source_width = max(.1, response.w);
            float blur_width = source_width + roughness * roughness * height * 1.8 / R.z;
            float blur_gain = source_width / blur_width;
            // A point source spreads across two dimensions; a beam spreads mostly across its width.
            float footprint = exp(-.5 * pow(source_distance / blur_width, 2.0)) *
                ((beam || ring) ? blur_gain : blur_gain * blur_gain);
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
                reflected *= sourceVisibility(vec3(world, 0.), vec3(on_source, height), source_width, vec2(1e19));
            spec_accum += reflected;
        }
    }

    if (u_debug == 5) { finalColor = vec4(debug_radiance(spec_accum), 1.); return; }
    if (u_debug == 6) { finalColor = vec4(debug_radiance(direct_shadowed), 1.); return; }
    if (u_debug == 7) { finalColor = vec4(debug_radiance(direct_unshadowed), 1.); return; }
    if (u_debug == 8) {
        vec3 luminance = vec3(.2126, .7152, .0722);
        float total = dot(direct_unshadowed, luminance);
        vec3 visibility = total > 1e-7 ? vec3(clamp(dot(direct_shadowed, luminance) / total, 0., 1.))
                                      : vec3(.12, .16, .22);
        finalColor = vec4(visibility, 1.); return;
    }
    if (u_debug == 13) { finalColor = vec4(debug_radiance(ambient_lit), 1.); return; }

    // Subtle cold moonlit sky reflection across smooth liquid pools (stronger on fresh blood)
    vec3 H_sky = normalize(normalize(vec3(-0.30, -0.40, 0.86)) + V);
    float ndh_sky = max(0.0, dot(N_spec, H_sky));
    vec3 sky_wet_spec = sky_reflection * pow(ndh_sky, 20.0) *
        ((wet_film * 0.12 + deep_pool * 0.30) * mix(0.45, 1.0, freshness) * (1.0 - is_ice) + is_ice * .30);

    // Each dynamic reflection has its own visibility; the sky stays unchanged.
    vec3 reflected_light = spec_accum + sky_wet_spec;
    if (u_debug == 14) diffuse_lit = ambient_lit;
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
