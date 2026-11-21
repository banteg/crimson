// A creature's light visibility at its quad's corners, which creature.frag interpolates across the body instead of
// walking the body grid per pixel: from the corner, at the height creature.frag lights from, toward the point each
// light shades the body from, the creature's own body spared (`owner`, its quad's center). The vertex stages (the
// client's creature_lit.vert, the Python port's CREATURE_VERTEX) pass it on as eight vec4s, four lights each.
#include "light_visibility.glsl"
#ifndef MAX_SPEC_LIGHTS
#define MAX_SPEC_LIGHTS 32
#endif
#include "beam_energy.glsl"
uniform int u_count;
uniform vec4 u_pos[32];
uniform vec4 u_rgb[32];
uniform vec4 u_dir[32];
uniform vec4 u_response[32]; // illumination, reflection, reflection reach, source width

// The point of light `i` (its disc's center, its segment or its ring) nearest `p`.
vec2 nearestOn(int i, vec2 axis, bool ring, float lo_span, float hi_span, vec2 p) {
    float along = clamp(dot(p - u_pos[i].xy, axis), lo_span, hi_span);
    return ring ? nearestRingPoint(u_pos[i].xy, p, u_rgb[i].w) : u_pos[i].xy + axis * along;
}

// Continuous-beam specular visibility at a quad corner toward that corner's nearest point on the bare segment
// (matching creature.frag's spec_L), so quad corners interpolate partial shadows and cell-boundary crossings.
float cornerSpecVisibility(int i, vec2 wp, vec2 owner) {
    if (i >= u_count || u_dynamic_shadows == 0 || u_response[i].y <= 0. || u_response[i].z <= 0.) return 1.;
    vec2 axis = dot(u_dir[i].xy, u_dir[i].xy) > .0001 ? normalize(u_dir[i].xy) : vec2(0.);
    float half_length = u_dir[i].w * .5;
    if (length(nearestOn(i, axis, false, -half_length, half_length, owner) - owner) - length(wp - owner) >= u_response[i].z)
        return 1.;
    vec2 nearest = nearestOn(i, axis, false, -half_length, half_length, wp);
    return illuminationVisibility(vec3(wp, 8.), vec3(nearest, u_pos[i].w), max(.1, u_response[i].w), owner);
}

bool needsSeparateSpecVis(int i) {
    return i < u_count && u_rgb[i].w <= 0. && u_beam_shape[i].w > 0. &&
           u_response[i].x > 0. && u_response[i].y > 0. && u_response[i].z > 0.;
}

float cornerVisibility(int i, vec2 wp, vec2 owner) {
    if (i >= u_count || u_dynamic_shadows == 0) return 1.;
    if (u_response[i].x <= 0. && u_response[i].y <= 0.) return 1.;
    bool ring = u_rgb[i].w > 0.;
    bool continuous = !ring && u_beam_shape[i].w > 0.;
    // Reflection-only continuous beams skip diffuse in creature.frag, so lightVisibility(i) carries their
    // corner-interpolated specular visibility directly (matching cornerSpecVisibility with zero pop on budget drop).
    if (continuous && u_response[i].x <= 0.) return cornerSpecVisibility(i, wp, owner);
    // Match beamFrame's +X fallback when a continuous beam has a zero or near-zero direction.
    vec2 axis = dot(u_dir[i].xy, u_dir[i].xy) > .0001 ? normalize(u_dir[i].xy) : (continuous ? vec2(1., 0.) : vec2(0.));
    float half_length = u_dir[i].w * .5;
    float lo_emit = continuous ? min(-half_length, half_length - u_beam_shape[i].y) : -half_length;
    float hi_emit = continuous ? half_length + u_beam_shape[i].y : half_length;
    // Past the light's active reach across the whole quad, every corner as far from its center as this one:
    // creature.frag shades none of it from the light. A corner past it alone still traces, since the pixels
    // inside its reach interpolate it.
    float reach = continuous ? u_pos[i].z : max(u_pos[i].z, u_response[i].z);
    if (length(nearestOn(i, axis, ring, lo_emit, hi_emit, owner) - owner) - length(wp - owner) >= reach) return 1.;
    vec2 nearest = nearestOn(i, axis, ring, lo_emit, hi_emit, wp);
    vec2 source = ring ? nearest : illuminationSource(u_pos[i].xy, axis, u_dir[i].w, u_dir[i].z);
    if (continuous) {
        vec2 delta;
        float irradiance;
        // Blend smoothly from the nearest emitting point to the integrated energy centroid across low
        // irradiance so float32 noise near the reach boundary cannot snap diffuse shadow rays.
        source = nearest;
        if (beamAtReceiver(i, u_dir[i], wp, u_pos[i], delta, irradiance))
            source = mix(nearest, wp + delta, smoothstep(1e-6, 1e-3, irradiance));
    }
    return illuminationVisibility(vec3(wp, 8.), vec3(source, u_pos[i].w), max(.1, u_response[i].w), owner);
}

// Pack corner-interpolated specular visibilities for the first 12 illuminating continuous beams; any overflow
// beam replays the exact same triangle-corner interpolation in creature.frag using quadCenterD00 and quadD01.
void fillSpecVisibilities(vec2 wp, vec2 owner, out vec4 s0, out vec4 s1, out vec4 s2) {
    s0 = vec4(1.);
    s1 = vec4(1.);
    s2 = vec4(1.);
    if (u_dynamic_shadows == 0) return;
    int slot = 0;
    for (int i = 0; i < MAX_SPEC_LIGHTS; i++) {
        if (i >= u_count || slot >= 12) break;
        if (!needsSeparateSpecVis(i)) continue;
        float vis = cornerSpecVisibility(i, wp, owner);
        int group = slot / 4;
        int lane = slot - group * 4;
        if (group == 0) {
            if (lane == 0) s0.x = vis; else if (lane == 1) s0.y = vis; else if (lane == 2) s0.z = vis; else s0.w = vis;
        } else if (group == 1) {
            if (lane == 0) s1.x = vis; else if (lane == 1) s1.y = vis; else if (lane == 2) s1.z = vis; else s1.w = vis;
        } else {
            if (lane == 0) s2.x = vis; else if (lane == 1) s2.y = vis; else if (lane == 2) s2.z = vis; else s2.w = vis;
        }
        slot++;
    }
}

vec4 cornerVisibilities(int group, vec2 wp, vec2 owner) {
    int first = group * 4;
    return vec4(cornerVisibility(first, wp, owner), cornerVisibility(first + 1, wp, owner),
                cornerVisibility(first + 2, wp, owner), cornerVisibility(first + 3, wp, owner));
}
