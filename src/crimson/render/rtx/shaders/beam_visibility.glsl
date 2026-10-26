// Analytic longitudinal beam occlusion, evaluated only in the coarse atlas.
// The interval solver and two transverse taps retain the beam's directional
// penumbra. Ordinary body lists are gathered from cells intersecting the fan;
// no CPU beam padding, second lists, or range metadata are needed.
vec2 beam_section_axis = vec2(0.);
float beam_section_halfspan = 0.;
// A section walk's visibility per eighth of the section, from its start (continuous_beam.glsl).
vec4 beam_bins[2];

// Interval where a*s^2 + b*s + c <= 0 for a > 0; hi <= lo when empty.
// The product form keeps the root nearest zero accurate when one is huge.
vec2 quadraticBelow(float a, float b, float c) {
    float radicand = b * b - 4. * a * c;
    if (radicand <= 0.) return vec2(1., -1.);
    float q = -.5 * (b + (b < 0. ? -sqrt(radicand) : sqrt(radicand)));
    vec2 roots = vec2(q / a, c / q);
    return vec2(min(roots.x, roots.y), max(roots.x, roots.y));
}

float edgeDistance2(vec2 a, vec2 b) {
    vec2 edge = b - a;
    vec2 nearest = a + edge * clamp(-dot(a, edge) / max(dot(edge, edge), 1e-8), 0., 1.);
    return dot(nearest, nearest);
}

float crossZ(vec2 a, vec2 b) {
    return a.x * b.y - a.y * b.x;
}

// Squared planar distance from the body center (the origin) to a section's ray
// fan: the triangle from the receiver to both ends of the section.
float fanDistance2(vec2 receiver, vec2 to_source, vec2 half_axis) {
    vec2 first = receiver + to_source - half_axis;
    vec2 second = receiver + to_source + half_axis;
    float a = crossZ(first - receiver, -receiver);
    float b = crossZ(second - first, -first);
    float c = crossZ(receiver - second, -second);
    if ((a >= 0. && b >= 0. && c >= 0.) || (a <= 0. && b <= 0. && c <= 0.)) return 0.;
    return min(edgeDistance2(receiver, first), min(edgeDistance2(first, second), edgeDistance2(second, receiver)));
}

// The source positions in [-halfspan, halfspan] whose rays from the receiver meet the body: up to two intervals
// (hi <= lo when empty), and `beyond`, those whose chord through the body lies past the light. False when the
// receiver is inside the body.
bool beamChordIntervals(vec3 relative, vec3 base_ray, vec3 axis_ray, float halfspan,
                        out vec2 first, out vec2 second, out vec2 beyond) {
    first = second = beyond = vec2(1., -1.);
    float quadratic_c = dot(relative, relative) - 1.;
    float quadratic_a = dot(base_ray, base_ray);
    float quadratic_b = dot(relative, base_ray);
    float linear_a = 2. * dot(base_ray, axis_ray);
    float linear_b = dot(relative, axis_ray);
    float constant_a = dot(axis_ray, axis_ray);
    if (quadratic_c <= 0.) return false;
    float lo = -halfspan;
    float hi = halfspan;
    if (abs(linear_b) < 1e-8) {
        if (quadratic_b > 0.) return true;
    } else {
        float bound = -quadratic_b / linear_b;
        if (linear_b > 0.) hi = min(hi, bound);
        else lo = max(lo, bound);
    }
    if (hi <= lo) return true;
    // Source positions whose infinite ray meets the body: one or two intervals.
    float a = linear_b * linear_b - constant_a * quadratic_c;
    float b = 2. * (quadratic_b * linear_b - .5 * linear_a * quadratic_c);
    float d = quadratic_b * quadratic_b - quadratic_a * quadratic_c;
    first = vec2(lo, hi);
    if (abs(a) < 1e-8) {
        if (abs(b) < 1e-8) {
            if (d < 0.) first = vec2(1., -1.);
        } else if (b > 0.) {
            first.x = max(lo, -d / b);
        } else {
            first.y = min(hi, -d / b);
        }
    } else if (a < 0.) {
        vec2 roots = quadraticBelow(-a, -b, -d);
        first = vec2(max(lo, roots.x), min(hi, roots.y));
    } else {
        vec2 roots = quadraticBelow(a, b, d);
        if (roots.y > roots.x) {
            first.y = min(hi, roots.x);
            second = vec2(max(lo, roots.y), hi);
        }
    }
    // The ray must reach the body before the light. Bodies taller than the
    // emitter otherwise shadow from beyond it.
    beyond = quadraticBelow(constant_a, linear_a + linear_b, quadratic_a + quadratic_b);
    return true;
}

// How much of each of four bins [lo, hi] an interval covers.
vec4 binOverlap(vec2 interval, vec4 lo, vec4 hi) {
    return max(vec4(0.), min(vec4(interval.y), hi) - max(vec4(interval.x), lo));
}

// One transverse tap's blocked share of each eighth of the section, from its chord's intervals (`outside` false:
// the receiver is in the body): those short of the light, less the stretch where the light sits in or against the
// body (`spared`, already per eighth).
void beamTapBlocked(bool outside, vec2 first, vec2 second, vec2 beyond, float halfspan, vec4 spared0, vec4 spared1,
                    inout vec4 blocked0, inout vec4 blocked1) {
    float width = .25 * halfspan;
    if (!outside) {
        blocked0 += .5 * clamp(1. - spared0 / width, 0., 1.);
        blocked1 += .5 * clamp(1. - spared1 / width, 0., 1.);
        return;
    }
    vec4 lo0 = -halfspan + width * vec4(0., 1., 2., 3.), lo1 = lo0 + 4. * width;
    vec2 first_beyond = vec2(max(first.x, beyond.x), min(first.y, beyond.y));
    vec2 second_beyond = vec2(max(second.x, beyond.x), min(second.y, beyond.y));
    blocked0 += .5 * clamp((binOverlap(first, lo0, lo0 + width) + binOverlap(second, lo0, lo0 + width)
        - binOverlap(first_beyond, lo0, lo0 + width) - binOverlap(second_beyond, lo0, lo0 + width) - spared0) / width, 0., 1.);
    blocked1 += .5 * clamp((binOverlap(first, lo1, lo1 + width) + binOverlap(second, lo1, lo1 + width)
        - binOverlap(first_beyond, lo1, lo1 + width) - binOverlap(second_beyond, lo1, lo1 + width) - spared1) / width, 0., 1.);
}

// The brightest eighth left: a section's walk stops once every eighth is dark.
float beamBrightest() {
    vec4 brightest = max(beam_bins[0], beam_bins[1]);
    return max(max(brightest.x, brightest.y), max(brightest.z, brightest.w));
}

void beamBodyVisibility(int address, vec3 receiver, vec3 emitter, float source_width) {
    vec4 center = occlusionData(address);
    vec3 ray = emitter - receiver;
    float bound = center.w + .57735027 * source_width;
    if (fanDistance2(receiver.xy - center.xy, ray.xy, beam_section_axis * beam_section_halfspan) > bound * bound)
        return;
    vec4 shape = occlusionData(address + 1), orientation = occlusionData(address + 2);
    mat2 local = mat2(orientation.x, -orientation.y, orientation.y, orientation.x);
    vec3 inverse_radius = shape.xyz;
    vec3 q = receiver - center.xyz;
    q.xy = local * q.xy;
    ray.xy = local * ray.xy;
    q *= inverse_radius;
    ray *= inverse_radius;
    // Marks the eighths of the section this body blocks (beam_bins).
    vec3 source_axis = vec3(local * beam_section_axis, 0.) * inverse_radius;
    vec2 transverse_axis = vec2(-beam_section_axis.y, beam_section_axis.x);
    vec3 transverse_ray = vec3(local * transverse_axis, 0.) * inverse_radius * (.57735027 * source_width);
    float halfspan = beam_section_halfspan, width = .25 * halfspan;
    vec2 first_a, second_a, beyond_a, first_b, second_b, beyond_b;
    bool outside_a = beamChordIntervals(q, ray - transverse_ray, source_axis, halfspan, first_a, second_a, beyond_a);
    bool outside_b = beamChordIntervals(q, ray + transverse_ray, source_axis, halfspan, first_b, second_b, beyond_b);
    // Most candidates hide none of the section.
    if (outside_a && outside_b && max(max(first_a.y - first_a.x, second_a.y - second_a.x),
                                      max(first_b.y - first_b.x, second_b.y - second_b.x)) <= 0.)
        return;
    vec4 lo0 = -halfspan + width * vec4(0., 1., 2., 3.), lo1 = lo0 + 4. * width;
    // A light in or against the body is spared over the last half radius before the body (the point
    // lights' fade below), taken at its two quarter points.
    vec3 source = q + ray;
    float a = dot(source_axis, source_axis), b = 2. * dot(source, source_axis), c = dot(source, source);
    vec2 near = quadraticBelow(a, b, c - 1.265625), far = quadraticBelow(a, b, c - 1.890625);
    vec4 spared0 = .5 * (binOverlap(near, lo0, lo0 + width) + binOverlap(far, lo0, lo0 + width));
    vec4 spared1 = .5 * (binOverlap(near, lo1, lo1 + width) + binOverlap(far, lo1, lo1 + width));
    vec4 blocked0 = vec4(0.), blocked1 = vec4(0.);
    beamTapBlocked(outside_a, first_a, second_a, beyond_a, halfspan, spared0, spared1, blocked0, blocked1);
    beamTapBlocked(outside_b, first_b, second_b, beyond_b, halfspan, spared0, spared1, blocked0, blocked1);
    beam_bins[0] = min(beam_bins[0], 1. - orientation.z * blocked0);
    beam_bins[1] = min(beam_bins[1], 1. - orientation.z * blocked1);
}

void beamFanVisibility(vec3 receiver, vec3 source, float source_width, vec2 axis, float halfspan) {
    beam_bins[0] = beam_bins[1] = vec4(1.);
    if (u_occlusion_grid.z <= 0.) return;
    beam_section_axis = axis;
    beam_section_halfspan = halfspan;
    vec2 half_axis = axis * halfspan;
    // A cell's circumscribed circle conservatively intersects the triangle,
    // enlarged by the transverse taps. The ordinary lists already include
    // each body's planar extent and finite-source penumbra padding.
    float transverse = .57735027 * source_width;
    vec2 lo = min(receiver.xy, min(source.xy - half_axis, source.xy + half_axis)) - transverse;
    vec2 hi = max(receiver.xy, max(source.xy - half_axis, source.xy + half_axis)) + transverse;
    ivec2 first = max(ivec2(0), ivec2(floor((lo - u_occlusion_grid.xy) / u_occlusion_cell_size)));
    ivec2 last = min(ivec2(u_occlusion_grid.zw) - 1,
                     ivec2(floor((hi - u_occlusion_grid.xy) / u_occlusion_cell_size)));
    float cell_bound = .70710679 * u_occlusion_cell_size + transverse;
    for (int y = first.y; y <= last.y; ++y) {
        for (int x = first.x; x <= last.x; ++x) {
            vec2 center = u_occlusion_grid.xy + (vec2(float(x), float(y)) + .5) * u_occlusion_cell_size;
            if (fanDistance2(receiver.xy - center, source.xy - receiver.xy, half_axis) > cell_bound * cell_bound)
                continue;
            vec4 cell = occlusionData(y * int(u_occlusion_grid.z) + x);
            // Crowds attenuate the center ray below. Repeating an ordinary
            // body from another cell is harmless: its per-bin minimum is idempotent.
            for (int j = 0; j < int(max(0., cell.y)); ++j) {
                beamBodyVisibility(int(occlusionData(int(cell.x) + j).x), receiver, source, source_width);
                if (beamBrightest() < .001) return;
            }
        }
    }
    // Preserve the previous beam model's center-ray crowd approximation. Keep
    // it separate from the idempotent per-body minima so list order is irrelevant.
    float crowd = sourceVisibility(receiver, source, source_width, vec2(1e19), false);
    beam_bins[0] *= crowd;
    beam_bins[1] *= crowd;
}

float beamAtlasVisibility(int index, vec4 direction, vec2 world, vec4 sp_pos, vec4 response) {
    sp_pos.z = max(max(1., sp_pos.z), response.z);
    vec2 axis, ramp_window, head_window;
    float x0, b, R, half_length, ramp, head;
    if (!beamFrame(index, direction, world, sp_pos, axis, x0, b, R, half_length, ramp, head, ramp_window, head_window))
        return 1.;
    float head_width = u_beam_shape[index].y;
    vec2 lit = x0 + vec2(min(ramp_window.x, head_window.x), max(ramp_window.y, head_window.y));
    float center = .5 * (lit.x + lit.y), halfspan = max(.5 * (lit.y - lit.x), 1e-3);
    beamFanVisibility(vec3(world, 0.), vec3(sp_pos.xy + axis * center, max(.001, sp_pos.w)),
                      max(.1, response.w), axis, halfspan);
    float width = halfspan * .25;
    vec4 s0 = center - halfspan + width * (vec4(0., 1., 2., 3.) + .5);
    vec4 s1 = s0 + 4. * width;
    vec4 f0 = max(vec4(0.), 1. - sqrt((s0 - x0) * (s0 - x0) + b * b) / R);
    vec4 f1 = max(vec4(0.), 1. - sqrt((s1 - x0) * (s1 - x0) + b * b) / R);
    vec4 r0 = ramp * max(vec4(0.), s0 + half_length) * step(s0, vec4(half_length));
    vec4 r1 = ramp * max(vec4(0.), s1 + half_length) * step(s1, vec4(half_length));
    // The head's share lands in the eighths it overlaps, through each eighth's own falloff.
    vec4 h0 = max(vec4(0.), min(s0 + .5 * width, vec4(half_length + head_width)) - max(s0 - .5 * width, vec4(half_length - head_width)));
    vec4 h1 = max(vec4(0.), min(s1 + .5 * width, vec4(half_length + head_width)) - max(s1 - .5 * width, vec4(half_length - head_width)));
    vec4 w0 = (r0 * width + head * h0) * f0 * f0;
    vec4 w1 = (r1 * width + head * h1) * f1 * f1;
    float total = dot(w0 + w1, vec4(1.));
    return total > 0. ? (dot(w0, beam_bins[0]) + dot(w1, beam_bins[1])) / total : 1.;
}

