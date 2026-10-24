// Three-section beam lighting with analytic finite-source visibility.
uniform int u_has_beam_lights;
uniform vec2 u_beam_gain; // ion, Fire Bullets direct gain
// Three energy-weighted sections per source: mass, world offset, halfspan, Ion.
// The shared occluder grid covers each section's complete longitudinal support.
uniform vec4 u_line_cells[MAX_SPEC_LIGHTS * 3];

float sectionVisibility(vec3 receiver, vec3 source, float width, vec2 axis, float halfspan, vec2 owner) {
    if (u_dynamic_shadows == 0) return 1.;
    beam_section_axis = axis;
    beam_section_halfspan = halfspan;
    float visibility = sourceVisibility(receiver, source, width, owner);
    // Reflection rays later in the same fragment retain standard visibility.
    beam_section_axis = vec2(0.);
    beam_section_halfspan = 0.;
    return visibility;
}

float beamSampleExtent(int index) {
    float extent = 0.;
    for (int cell = 0; cell < 3; cell++) {
        vec4 section = u_line_cells[index * 3 + cell];
        if (section.x > 0.) extent = max(extent, abs(section.y));
    }
    return extent;
}

vec3 continuousLight(int index, vec4 direction, vec2 world, vec3 N_sub, vec3 absorption,
                     vec3 wetted, vec3 blood, vec3 albedo, float ice, vec4 sp_pos,
                     vec4 sp_col, vec4 response, float broad, out vec3 unshadowed) {
    vec2 axis = dot(direction.xy, direction.xy) > .0001 ? normalize(direction.xy) : vec2(1., 0.);
    float gain = response.x * (u_line_cells[index * 3].w > .5 ? u_beam_gain.x : u_beam_gain.y);
    float radius = max(1., sp_pos.z);
    vec3 result = vec3(0.);
    unshadowed = vec3(0.);
    for (int cell = 0; cell < 3; cell++) {
        vec4 section = u_line_cells[index * 3 + cell];
        if (section.x <= 0.) continue;
        vec2 source = sp_pos.xy + axis * section.y;
        vec2 to_l = source - world;
        float distance_to_source = length(to_l);
        if (distance_to_source >= radius) continue;
        float attenuation = pow(max(0., 1. - distance_to_source / radius), 2.);
        vec3 L = normalize(vec3(to_l, max(.001, sp_pos.w)));
        float ndl = max(dot(N_sub, L), 0.);
        vec3 transmittance = exp(-absorption * (.90 + .35 / clamp(L.z, .22, 1.)));
        vec3 direct_albedo = mix(wetted * transmittance + blood, albedo, ice);
        float relief = broad > .5 ? clamp((ndl + .10) / (L.z + .10), .35, 2.5)
                                  : clamp((ndl + .18) / (L.z + .18), .64, 1.55);
        float angular = broad > .5 ? .22 + .78 * ndl : .22 * ndl;
        vec3 direct = direct_albedo * sp_col.rgb * (gain * section.x * attenuation * angular * relief);
        unshadowed += direct;
        if (max(direct.r, max(direct.g, direct.b)) > .00001)
            direct *= sectionVisibility(vec3(world, 0.), vec3(source, sp_pos.w), response.w,
                                        axis, section.z, vec2(1e19));
        result += direct;
    }
    return result;
}
