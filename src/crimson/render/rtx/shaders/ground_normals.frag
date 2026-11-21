#version 330
// Precomputed substrate and fluid normal slopes for ground.frag.
// Baked on initialization and whenever decals modify surface or coverage;
// wetness aging and epoch rebasing only touch surface.g and leave slopes exact.
#ifdef GROUND_V_DOWN
const float V_UP = -1.;
#else
const float V_UP = 1.;
#endif

in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;

uniform sampler2D u_surface_tex;  // R=specularity, G=wet amount at epoch, B=volume, A=substrate height
uniform sampler2D u_material_tex; // Ordered RGBA coverage: blood, corpse, brass, ice
uniform vec2 u_ground_size;

float blood_below_ice(vec4 surface, vec4 coverage) {
    float exposed = max(1.0 - coverage.a, 0.001);
    return clamp(surface.b * coverage.r / (exposed * exposed), 0.0, 0.999);
}

void main() {
    vec2 ground_uv = fragTexCoord;
    vec4 surf = texture(u_surface_tex, ground_uv);
    vec4 weights = texture(u_material_tex, ground_uv);

    // Samples named up (U) lie toward the world's top in either orientation.
    vec2 step_fine = vec2(1.2, 1.2 * V_UP) / u_ground_size;
    vec2 step_med  = vec2(3.2, 3.2 * V_UP) / u_ground_size;
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

    float amount_l1 = blood_below_ice(sL1, texture(u_material_tex, ground_uv + vec2(-step_fine.x, 0)));
    float amount_r1 = blood_below_ice(sR1, texture(u_material_tex, ground_uv + vec2( step_fine.x, 0)));
    float amount_d1 = blood_below_ice(sD1, texture(u_material_tex, ground_uv + vec2(0, -step_fine.y)));
    float amount_u1 = blood_below_ice(sU1, texture(u_material_tex, ground_uv + vec2(0,  step_fine.y)));
    float amount_l2 = blood_below_ice(sL2, texture(u_material_tex, ground_uv + vec2(-step_med.x, 0)));
    float amount_r2 = blood_below_ice(sR2, texture(u_material_tex, ground_uv + vec2( step_med.x, 0)));
    float amount_d2 = blood_below_ice(sD2, texture(u_material_tex, ground_uv + vec2(0, -step_med.y)));
    float amount_u2 = blood_below_ice(sU2, texture(u_material_tex, ground_uv + vec2(0,  step_med.y)));

    float blood_amount = blood_below_ice(surf, weights);
    float deep_pool = smoothstep(0.12, 0.95, blood_amount);

    vec2 slope_sub = dH_fine + dH_macro * 0.85;

    float poolL = smoothstep(0.12, 0.95, 0.45 * amount_l1 + 0.55 * amount_l2);
    float poolR = smoothstep(0.12, 0.95, 0.45 * amount_r1 + 0.55 * amount_r2);
    float poolD = smoothstep(0.12, 0.95, 0.45 * amount_d1 + 0.55 * amount_d2);
    float poolU = smoothstep(0.12, 0.95, 0.45 * amount_u1 + 0.55 * amount_u2);
    vec2 dPool_smooth = vec2(poolL - poolR, poolU - poolD) * (1.0 - 0.65 * deep_pool);

    vec2 slope_fluid = dH_macro * mix(1.35, 0.24, deep_pool) + dH_fine * mix(0.45, 0.04, deep_pool) + dPool_smooth * 0.18;

    finalColor = vec4(slope_sub, slope_fluid);
}
