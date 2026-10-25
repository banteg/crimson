// Finite-source visibility through the creature body grid, shared by ground and creature lighting.
#include "source_geometry.glsl"
uniform int u_dynamic_shadows;
// Packed float texture: cell headers, body transforms, then lossless cell lists.
uniform sampler2D u_occlusion_tex;
uniform vec4 u_occlusion_grid; // xy world origin, zw cell counts; z=0 disables
uniform float u_occlusion_cell_size;
// A crowd cell (header y < 0: minus its bodies' summed footprint over its area, x their top height) is crossed as an
// absorbing medium below that height (render/rtx/reflection_occlusion.py's CROWD_BODIES).
const float CROWD_EXTINCTION = 3.;
// The widest source a body shadow's penumbra follows (reflection_occlusion.py's PENUMBRA_WIDTH): the grid pads its
// lists for no wider.
const float PENUMBRA_WIDTH = 8.;

// The texture is 256 texels wide on every host (reflection_occlusion.py's TEXTURE_WIDTH).
vec4 occlusionData(int address) {
    return texelFetch(u_occlusion_tex, ivec2(address & 255, address >> 8), 0);
}

#ifdef CONTINUOUS_BEAM
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

float intervalOverlap(vec2 first, vec2 second) {
    return max(0., min(first.y, second.y) - max(first.x, second.x));
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

float beamChordCoverage(vec3 relative, vec3 base_ray, vec3 axis_ray, float halfspan) {
    vec2 first, second, beyond;
    if (!beamChordIntervals(relative, base_ray, axis_ray, halfspan, first, second, beyond)) return 1.;
    // Where the chord's midpoint lies past the light, only a light inside the body is still blocked.
    vec3 source_relative = relative + base_ray;
    vec2 inside = quadraticBelow(dot(axis_ray, axis_ray), 2. * dot(source_relative, axis_ray),
                                 dot(source_relative, source_relative) - 1.);
    inside = vec2(max(inside.x, -halfspan), min(inside.y, halfspan));
    float blocked = max(0., first.y - first.x) - intervalOverlap(first, beyond)
        + max(0., second.y - second.x) - intervalOverlap(second, beyond)
        + intervalOverlap(inside, beyond);
    return clamp(blocked / max(2. * halfspan, 1e-6), 0., 1.);
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
    if (!outside) {
        blocked0 += vec4(.5);
        blocked1 += vec4(.5);
        return;
    }
    float width = .25 * halfspan;
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

#endif

// Squared planar distance from the body center (the origin) to the ray.
float rayDistance2(vec2 receiver, vec2 to_source, float inverse_xy_length) {
    vec2 nearest = receiver + to_source * clamp(-dot(receiver, to_source) * inverse_xy_length, 0., 1.);
    return dot(nearest, nearest);
}

float bodyVisibility(int address, vec3 origin, vec3 ray, float source_width, float inverse_xy_length, vec2 owner) {
    vec4 center = occlusionData(address);
    vec2 offset = origin.xy - center.xy;
    #ifdef CONTINUOUS_BEAM
    float distance2 = beam_section_halfspan > 0.
        ? fanDistance2(offset, ray.xy, beam_section_axis * beam_section_halfspan)
        : rayDistance2(offset, ray.xy, inverse_xy_length);
    #else
    float distance2 = rayDistance2(offset, ray.xy, inverse_xy_length);
    #endif
    // Reject neighboring cell members with one fetch before loading transforms.
    // The bound includes the penumbra margin (for sources up to PENUMBRA_WIDTH);
    // a section's transverse taps reach 0.577 of its full width off the fan.
    float bound = center.w;
    #ifdef CONTINUOUS_BEAM
    if (beam_section_halfspan > 0.) bound += .57735027 * source_width;
    #endif
    if (distance2 > bound * bound) return 1.;
    vec4 shape = occlusionData(address + 1);
    vec3 inverse_radius = shape.xyz;
    vec4 orientation = occlusionData(address + 2);
    // Sprite center is recovered without changing the quad batch.
    // Exactly coincident owners share exclusion; nearby creatures still block.
    if (distance(vec2(shape.w, orientation.w), owner) < .02) return 1.;
    vec2 rotation = orientation.xy;
    mat2 local = mat2(rotation.x, -rotation.y, rotation.y, rotation.x);
    vec3 q = origin - center.xyz;
    q.xy = local * q.xy;
    ray.xy = local * ray.xy;
    q *= inverse_radius;
    ray *= inverse_radius;
    // A light inside a body, or against it (a muzzle in a packed crowd, a beam through a creature), is not shadowed
    // by that body: its occlusion fades out over the last half radius before the source, in the body's normalized
    // coordinates. Otherwise the body's near face cuts the light's pool along a straight line through the source.
    #ifdef CONTINUOUS_BEAM
    if (beam_section_halfspan > 0.) {
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
            return beamBrightest();
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
        return beamBrightest();
    }
    #endif
    float t = clamp(-dot(q, ray) / max(dot(ray, ray), 1e-8), 0., 1.);
    float distance = length(q + ray * t);
    // Analytic finite-source penumbra. The cone grows from the receiver toward
    // the source; this is a smooth body proxy, not sampled silhouette tracing.
    float softness = max(.015, min(source_width, PENUMBRA_WIDTH) * t * max(inverse_radius.x, inverse_radius.y));
    float embedded = smoothstep(1., 1.5, length(q + ray));
    return 1. - orientation.z * embedded * (1. - smoothstep(1. - softness, 1. + softness, distance));
}

float sourceVisibility(vec3 receiver, vec3 source, float source_width, vec2 owner) {
    if (u_occlusion_grid.z == 0.) return 1.;
    vec2 start = (receiver.xy - u_occlusion_grid.xy) / u_occlusion_cell_size;
    vec2 delta = (source.xy - receiver.xy) / u_occlusion_cell_size;
    ivec2 cell = ivec2(floor(start));
    ivec2 step_cell = ivec2(sign(delta));
    vec2 next_edge = vec2(cell) + step(vec2(0.), delta);
    vec2 t_step = vec2(1e20);
    vec2 t_edge = vec2(1e20);
    if (abs(delta.x) > 1e-8) { t_step.x = abs(1. / delta.x); t_edge.x = (next_edge.x - start.x) / delta.x; }
    if (abs(delta.y) > 1e-8) { t_step.y = abs(1. / delta.y); t_edge.y = (next_edge.y - start.y) / delta.y; }
    vec3 ray = source - receiver;
    float visibility = 1.;
    float inverse_xy_length = 1. / max(dot(ray.xy, ray.xy), 1e-8);
    bool beam = false;
    #ifdef CONTINUOUS_BEAM
    beam = beam_section_halfspan > 0.;
    #endif
    ivec2 previous = ivec2(-1);
    ivec2 first_cell = cell;
    float t_enter = 0.;
    float cells_crossed = length(delta);
    // Each step crosses one grid boundary. No nearest-body budget drops blockers.
    while (cell.x >= 0 && cell.y >= 0 && cell.x < int(u_occlusion_grid.z) && cell.y < int(u_occlusion_grid.w)) {
        vec4 header = occlusionData(cell.y * int(u_occlusion_grid.z) + cell.x);
        // Beam sections walk their own lists, padded by the largest half-span.
        if (beam) header.xy = header.zw;
        bool crowd = header.y < 0.;
        if (crowd) {
            // A crowd: absorb along the length crossed below the bodies' top height. A body's own cell does not
            // shade the body.
            float t_exit = min(min(t_edge.x, t_edge.y), 1.);
            float t_top = abs(ray.z) > 1e-6 ? (header.x - receiver.z) / ray.z : (receiver.z < header.x ? 1e20 : -1e20);
            vec2 below = ray.z >= 0. ? vec2(-1e20, t_top) : vec2(t_top, 1e20);
            float crossed = max(0., min(t_exit, below.y) - max(t_enter, below.x));
            if (crossed > 0. && !(cell == first_cell && owner.x < 1e18)) {
                float transmitted = exp(CROWD_EXTINCTION * header.y * crossed * cells_crossed);
                visibility *= transmitted;
                #ifdef CONTINUOUS_BEAM
                // A section's eighths all cross the medium.
                beam_bins[0] *= transmitted;
                beam_bins[1] *= transmitted;
                #endif
                if (visibility < .001) return visibility;
            }
            header.y = 0.;
        }
        for (int j = 0; j < int(header.y); j++) {
            vec4 entry = occlusionData(int(header.x) + j);
            // A padded beam entry spans a run of walked cells; test it in the first.
            if (beam && previous.x >= 0) {
                ivec2 cell_range = ivec2(entry.yz);
                if (all(greaterThanEqual(previous, cell_range & 4095)) && all(lessThanEqual(previous, cell_range >> 12))) continue;
            }
            visibility = min(visibility, bodyVisibility(int(entry.x), receiver, ray, source_width, inverse_xy_length, owner));
            if (visibility < .001) return visibility;
        }
        // A crowd tested none of its neighbors' padded entries: the next cell tests its whole list.
        previous = crowd ? ivec2(-1) : cell;
        if (min(t_edge.x, t_edge.y) >= 1.) break;
        t_enter = min(t_edge.x, t_edge.y);
        if (t_edge.x < t_edge.y) { cell.x += step_cell.x; t_edge.x += t_step.x; }
        else { cell.y += step_cell.y; t_edge.y += t_step.y; }
    }
    return visibility;
}

float illuminationVisibility(vec3 receiver, vec3 source, float width, vec2 owner) {
    return u_dynamic_shadows != 0 ? sourceVisibility(receiver, source, width, owner) : 1.;
}
