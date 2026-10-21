"""Bounded three-section beam lighting for Python RTX."""

CONTINUOUS_BEAM_GLSL = r"""
uniform int u_has_beam_lights;
uniform vec2 u_beam_tuning; // Ion direct gain, bounded local ambient dip
// Three energy-weighted sections per source: mass, world offset, halfspan, Ion.
// CPU caps longitudinal halfspans at four world units and expands the shared
// occluder grid by the same support. This is not exact finite-beam integration.
uniform vec4 u_line_cells[MAX_SPEC_LIGHTS * 3];

float sectionCoverage(vec3 miss, vec3 line, float softness) {
    float line2 = dot(line, line);
    if (line2 < 1e-10)
        return 1. - smoothstep(1. - softness, 1. + softness, length(miss));
    // Intersect a projected source line with the normalized rounded body.
    // Unlike miss-normal width projection, this stays continuous at miss=0.
    float chord_center = -dot(miss, line) / line2;
    float perpendicular2 = max(0., dot(miss, miss) - chord_center * chord_center * line2);
    float outer_radius = 1. + softness;
    float half_chord = sqrt(max(0., (outer_radius * outer_radius - perpendicular2) / line2));
    float coverage = .5 * max(0., min(1., chord_center + half_chord) - max(-1., chord_center - half_chord));
    // Artistic transverse feather; the zero-extent limit is the point source.
    vec3 nearest_miss = miss + line * clamp(chord_center, -1., 1.);
    return coverage * (1. - smoothstep(1. - softness, 1. + softness, length(nearest_miss)));
}

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
    float gain = response.x * (u_line_cells[index * 3].w > .5 ? u_beam_tuning.x : 1.);
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
"""
