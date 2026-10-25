// One-source beam lighting with analytic finite-source visibility.
uniform int u_has_beam_lights;
uniform vec2 u_beam_gain; // ion, Fire Bullets direct gain
// Per source (continuous_beam.py's beam_uniform): the head's share of the beam's energy, its half-width, Ion, and
// the support's half-extent past the midpoint (0: not a beam). The rest is a ramp from the tail to the head.
uniform vec4 u_beam_shape[MAX_SPEC_LIGHTS];

// Visibility through a section of a beam: the source stretch `axis` * [-halfspan, halfspan] around `source`. The
// walk leaves each eighth's own visibility in beam_bins (light_visibility.glsl); this returns their mean.
float sectionVisibility(vec3 receiver, vec3 source, float width, vec2 axis, float halfspan, vec2 owner) {
    beam_bins[0] = beam_bins[1] = vec4(1.);
    if (u_dynamic_shadows == 0) return 1.;
    beam_section_axis = axis;
    beam_section_halfspan = halfspan;
    // Bodies mark the eighths they block and crowd cells dim them all; the walk ends once all are dark.
    sourceVisibility(receiver, source, width, owner);
    // Reflection rays later in the same fragment retain standard visibility.
    beam_section_axis = vec2(0.);
    beam_section_halfspan = 0.;
    return dot(beam_bins[0] + beam_bins[1], vec4(.125));
}

// Antiderivatives in u of (1, u, u^2) * (1 - d/R)^2, d = sqrt(u^2 + b^2): the falloff along the beam's axis at
// perpendicular distance b, u from the receiver's foot on the axis.
vec3 beamFalloffIntegrals(float u, float b, float R) {
    float d = sqrt(u * u + b * b), b2 = b * b, arc = b2 * asinh(u / b);
    float d_line = .5 * (u * d + arc);                                 // ∫ d
    float d_moment = d * d * d / 3.;                                   // ∫ u d
    float d_second = .25 * u * d * d * d - .125 * b2 * (u * d + arc); // ∫ u^2 d
    float u2 = u * u;
    return vec3(u - 2. * d_line / R + (u2 * u / 3. + b2 * u) / (R * R),
                .5 * u2 - 2. * d_moment / R + (.25 * u2 * u2 + .5 * b2 * u2) / (R * R),
                u2 * u / 3. - 2. * d_second / R + (.2 * u2 * u2 * u + b2 * u2 * u / 3.) / (R * R));
}

// The energy and its first moment in u that a density a + c u over [lo, hi] (in u) delivers through the falloff.
vec2 beamPiece(float a, float c, float lo, float hi, float b, float R) {
    if (hi <= lo) return vec2(0.);
    vec3 delta = beamFalloffIntegrals(hi, b, R) - beamFalloffIntegrals(lo, b, R);
    return vec2(a * delta.x + c * delta.y, a * delta.y + c * delta.z);
}

vec3 continuousLight(int index, vec4 direction, vec2 world, vec3 N_sub, vec3 absorption,
                     vec3 wetted, vec3 blood, vec3 albedo, float ice, vec4 sp_pos,
                     vec4 sp_col, vec4 response, float broad, out vec3 unshadowed) {
    unshadowed = vec3(0.);
    vec4 shape = u_beam_shape[index];
    vec2 axis = dot(direction.xy, direction.xy) > .0001 ? normalize(direction.xy) : vec2(1., 0.);
    float gain = response.x * (shape.z > .5 ? u_beam_gain.x : u_beam_gain.y);
    float R = max(1., sp_pos.z), half_length = .5 * direction.w;
    vec2 delta = world - sp_pos.xy;
    float x0 = dot(delta, axis);
    float b = max(abs(delta.x * axis.y - delta.y * axis.x), 1e-3);
    if (b >= R) return vec3(0.);
    float reach = sqrt(R * R - b * b);
    // The beam in u = s - x0: a ramp over [-half_length, half_length] holding all but the head's share, rising to
    // the head, and the head's share spread over [half_length - h, half_length + h].
    float ramp = half_length > 0. ? (1. - shape.x) / (2. * half_length * half_length) : 0.;
    float head = shape.x / (2. * max(shape.y, 1e-3));
    vec2 ramp_window = clamp(vec2(-half_length, half_length) - x0, -reach, reach);
    vec2 head_window = clamp(half_length + vec2(-shape.y, shape.y) - x0, -reach, reach);
    vec2 energy = beamPiece(ramp * (x0 + half_length), ramp, ramp_window.x, ramp_window.y, b, R)
                + beamPiece(head, 0., head_window.x, head_window.y, b, R);
    if (energy.x <= 0.) return vec3(0.);
    // Shade toward the energy's centroid on the beam.
    vec2 to_l = sp_pos.xy + axis * (x0 + energy.y / energy.x) - world;
    vec3 L = normalize(vec3(to_l, max(.001, sp_pos.w)));
    float ndl = max(dot(N_sub, L), 0.);
    vec3 transmittance = exp(-absorption * (.90 + .35 / clamp(L.z, .22, 1.)));
    vec3 direct_albedo = mix(wetted * transmittance + blood, albedo, ice);
    float relief = broad > .5 ? clamp((ndl + .10) / (L.z + .10), .35, 2.5)
                              : clamp((ndl + .18) / (L.z + .18), .64, 1.55);
    float angular = broad > .5 ? .22 + .78 * ndl : .22 * ndl;
    vec3 direct = direct_albedo * sp_col.rgb * (gain * energy.x * angular * relief);
    unshadowed = direct;
    if (max(direct.r, max(direct.g, direct.b)) <= .00001) return direct;
    // One walk across the stretch that lights this receiver. Its eighths keep their own visibility, so bodies
    // blocking different parts of the beam add up; each eighth weighs the energy it delivers.
    vec2 lit = x0 + vec2(min(ramp_window.x, head_window.x), max(ramp_window.y, head_window.y));
    float center = .5 * (lit.x + lit.y), halfspan = max(.5 * (lit.y - lit.x), 1e-3);
    sectionVisibility(vec3(world, 0.), vec3(sp_pos.xy + axis * center, sp_pos.w), response.w, axis, halfspan,
                      vec2(1e19));
    float width = halfspan * .25;
    vec4 s0 = center - halfspan + width * (vec4(0., 1., 2., 3.) + .5);
    vec4 s1 = s0 + 4. * width;
    vec4 f0 = max(vec4(0.), 1. - sqrt((s0 - x0) * (s0 - x0) + b * b) / R);
    vec4 f1 = max(vec4(0.), 1. - sqrt((s1 - x0) * (s1 - x0) + b * b) / R);
    vec4 r0 = ramp * max(vec4(0.), s0 + half_length) * step(s0, vec4(half_length));
    vec4 r1 = ramp * max(vec4(0.), s1 + half_length) * step(s1, vec4(half_length));
    // The head's share lands in the eighths it overlaps.
    float head_falloff = pow(max(0., 1. - length(vec2(half_length - x0, b)) / R), 2.) * head;
    vec4 h0 = max(vec4(0.), min(s0 + .5 * width, vec4(half_length + shape.y)) - max(s0 - .5 * width, vec4(half_length - shape.y)));
    vec4 h1 = max(vec4(0.), min(s1 + .5 * width, vec4(half_length + shape.y)) - max(s1 - .5 * width, vec4(half_length - shape.y)));
    vec4 w0 = r0 * f0 * f0 * width + head_falloff * h0;
    vec4 w1 = r1 * f1 * f1 * width + head_falloff * h1;
    float total = dot(w0 + w1, vec4(1.));
    return total > 0. ? direct * (dot(w0, beam_bins[0]) + dot(w1, beam_bins[1])) / total : direct;
}
