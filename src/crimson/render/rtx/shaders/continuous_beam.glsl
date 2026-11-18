// Analytic beam lighting, attenuated by a supplied coarse visibility mask.
uniform int u_has_beam_lights;
uniform vec2 u_beam_gain; // ion, Fire Bullets direct gain
#include "beam_energy.glsl"

#ifdef BEAM_VISIBILITY_PASS
#include "beam_visibility.glsl"
#endif

vec3 continuousLight(int index, vec4 direction, vec2 world, vec3 N_sub, vec3 absorption,
                     vec3 wetted, vec3 blood, vec3 albedo, float ice, vec4 sp_pos,
                     vec4 sp_col, vec4 response, float broad, float visibility, out vec3 unshadowed) {
    unshadowed = vec3(0.);
    vec2 to_l;
    float irradiance;
    if (!beamAtReceiver(index, direction, world, sp_pos, to_l, irradiance))
        return vec3(0.);
    float gain = response.x * (u_beam_shape[index].z > .5 ? u_beam_gain.x : u_beam_gain.y);
    vec3 L = normalize(vec3(to_l, max(.001, sp_pos.w)));
    float ndl = max(dot(N_sub, L), 0.);
    vec3 transmittance = exp(-absorption * (.90 + .35 / clamp(L.z, .22, 1.)));
    vec3 direct_albedo = mix(wetted * transmittance + blood, albedo, ice);
    float relief = broad > .5 ? clamp((ndl + .10) / (L.z + .10), .35, 2.5)
                              : clamp((ndl + .18) / (L.z + .18), .64, 1.55);
    float angular = broad > .5 ? .22 + .78 * ndl : .22 * ndl;
    vec3 direct = direct_albedo * sp_col.rgb * (gain * irradiance * angular * relief);
    unshadowed = direct;
    return direct * visibility;
}
