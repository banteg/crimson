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

float cornerVisibility(int i, vec2 wp, vec2 owner) {
    if (i >= u_count || u_dynamic_shadows == 0) return 1.;
    if (u_response[i].x <= 0. && u_response[i].y <= 0.) return 1.;
    bool ring = u_rgb[i].w > 0.;
    bool continuous = !ring && u_beam_shape[i].w > 0.;
    // Continuous beams evaluate specular visibility per pixel toward the nearest segment point in creature.frag,
    // so lightVisibility(i) only carries their diffuse visibility.
    if (continuous && u_response[i].x <= 0.) return 1.;
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

vec4 cornerVisibilities(int group, vec2 wp, vec2 owner) {
    int first = group * 4;
    return vec4(cornerVisibility(first, wp, owner), cornerVisibility(first + 1, wp, owner),
                cornerVisibility(first + 2, wp, owner), cornerVisibility(first + 3, wp, owner));
}
