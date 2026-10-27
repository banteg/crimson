// Analytic beam lighting, attenuated by a supplied coarse visibility mask.
uniform int u_has_beam_lights;
uniform vec2 u_beam_gain; // ion, Fire Bullets direct gain
// Per source (continuous_beam.py's beam_uniform): the head's share of the beam's energy, its half-width, Ion, and
// the support's half-extent past the midpoint (0: not a beam). The rest is a ramp from the tail to the head.
uniform vec4 u_beam_shape[MAX_SPEC_LIGHTS];

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

// Where a receiver sits against a beam: its foot on the axis (x0), its distance from it (b), the falloff's reach,
// the ramp's and the head's densities and the stretches of each (in u = s - x0) that reach it. False out of reach.
bool beamFrame(int index, vec4 direction, vec2 world, vec4 sp_pos, out vec2 axis, out float x0, out float b,
               out float R, out float half_length, out float ramp, out float head, out vec2 ramp_window,
               out vec2 head_window) {
    vec4 shape = u_beam_shape[index];
    axis = dot(direction.xy, direction.xy) > .0001 ? normalize(direction.xy) : vec2(1., 0.);
    R = max(1., sp_pos.z);
    half_length = .5 * direction.w;
    vec2 delta = world - sp_pos.xy;
    x0 = dot(delta, axis);
    b = max(abs(delta.x * axis.y - delta.y * axis.x), 1e-3);
    if (b >= R) return false;
    float reach = sqrt(R * R - b * b);
    // The beam in u = s - x0: a ramp over [-half_length, half_length] holding all but the head's share, rising to
    // the head, and the head's share spread over [half_length - h, half_length + h].
    ramp = half_length > 0. ? (1. - shape.x) / (2. * half_length * half_length) : 0.;
    head = shape.x / (2. * max(shape.y, 1e-3));
    ramp_window = clamp(vec2(-half_length, half_length) - x0, -reach, reach);
    head_window = clamp(half_length + vec2(-shape.y, shape.y) - x0, -reach, reach);
    return true;
}

#ifdef BEAM_VISIBILITY_PASS
#include "beam_visibility.glsl"
#endif

vec3 continuousLight(int index, vec4 direction, vec2 world, vec3 N_sub, vec3 absorption,
                     vec3 wetted, vec3 blood, vec3 albedo, float ice, vec4 sp_pos,
                     vec4 sp_col, vec4 response, float broad, float visibility, out vec3 unshadowed) {
    unshadowed = vec3(0.);
    vec2 axis, ramp_window, head_window;
    float x0, b, R, half_length, ramp, head;
    if (!beamFrame(index, direction, world, sp_pos, axis, x0, b, R, half_length, ramp, head, ramp_window, head_window))
        return vec3(0.);
    float gain = response.x * (u_beam_shape[index].z > .5 ? u_beam_gain.x : u_beam_gain.y);
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
    return direct * visibility;
}
