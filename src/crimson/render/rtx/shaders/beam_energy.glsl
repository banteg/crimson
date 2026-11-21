// Per source (continuous_beam.py's beam_uniform): the head's share of the beam's energy, its half-width, Ion, and
// the support's half-extent past the midpoint (0: not a beam). The rest is a ramp from the tail to the head.
uniform vec4 u_beam_shape[MAX_SPEC_LIGHTS];

// asinh, odd by construction: log(x + sqrt(x^2 + 1)) cancels to log(0) for large negative x in single precision, as
// on a receiver within hundredths of a unit of a beam's axis, where u / b reaches the thousands.
float oddAsinh(float x) {
    float a = abs(x);
    return sign(x) * log(a + sqrt(a * a + 1.));
}

// Antiderivatives in u of (1, u, u^2) * (1 - d/R)^2, d = sqrt(u^2 + b^2): the falloff along the beam's axis at
// perpendicular distance b, u from the receiver's foot on the axis.
vec3 beamFalloffIntegrals(float u, float b, float R) {
    float d = sqrt(u * u + b * b), b2 = b * b, arc = b2 * oddAsinh(u / b);
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

// Integrated falloff and its energy centroid at this receiver.
bool beamAtReceiver(int index, vec4 direction, vec2 world, vec4 source, out vec2 delta, out float irradiance) {
    vec2 axis, ramp_window, head_window;
    float x0, b, R, half_length, ramp, head;
    if (!beamFrame(index, direction, world, source, axis, x0, b, R, half_length, ramp, head, ramp_window, head_window))
        return false;
    bool has_ramp = ramp > 0. && ramp_window.y > ramp_window.x;
    bool has_head = head > 0. && head_window.y > head_window.x;
    if (!has_ramp && !has_head) return false;
    vec2 energy = (has_ramp ? beamPiece(ramp * (x0 + half_length), ramp, ramp_window.x, ramp_window.y, b, R) : vec2(0.))
                + (has_head ? beamPiece(head, 0., head_window.x, head_window.y, b, R) : vec2(0.));
    // Guard against float32 cancellation near the reach boundary producing tiny noise and out-of-span centroids.
    if (!(energy.x > 1e-6)) return false;
    float u_lo = has_ramp && has_head ? min(ramp_window.x, head_window.x) : (has_ramp ? ramp_window.x : head_window.x);
    float u_hi = has_ramp && has_head ? max(ramp_window.y, head_window.y) : (has_ramp ? ramp_window.y : head_window.y);
    float centroid_u = clamp(energy.y / energy.x, u_lo, u_hi);
    delta = source.xy + axis * (x0 + centroid_u) - world;
    irradiance = energy.x;
    return true;
}
