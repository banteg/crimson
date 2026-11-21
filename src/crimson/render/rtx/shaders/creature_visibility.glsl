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

bool needsContinuousSpecVis(int i) {
    return i < u_count && u_rgb[i].w <= 0. && u_beam_shape[i].w > 0.
        && u_response[i].y > 0. && u_response[i].z > 0.;
}

float cornerVisibility(int i, vec2 wp, vec2 owner) {
    if (i >= u_count || u_dynamic_shadows == 0) return 1.;
    if (u_response[i].x <= 0. && u_response[i].y <= 0.) return 1.;
    bool ring = u_rgb[i].w > 0.;
    bool continuous = !ring && u_beam_shape[i].w > 0.;
    // Reflection-only continuous beams skip diffuse in creature.frag and read specular visibility from specVis0..3.
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

uint packQuad4(vec4 v) {
    uvec4 q = uvec4(clamp(v, 0., 1.) * 15. + .5);
    return q.x | (q.y << 4u) | (q.z << 8u) | (q.w << 12u);
}

// Compute corner-interpolated specular visibility for every reflective continuous beam strictly in the vertex stage
// (no fragment occlusion grid walks). Every light index 0..31 has its own fixed 16-bit halfword in specVis0..3
// (4 bits per corner: c00, c01, c11, c10), so precision never shifts when lights reorder or illumination fades to 0.
// `spec_role` names which triangles this vertex provokes (0 = none, 1 = T0 (c00,c01,c11), 2 = T1 (c00,c11,c10),
// 3 = both triangles or degenerate/arbitrary topology), so non-provoking vertices skip all specular shadow traces.
void fillSpecVisibilities(
    vec2 corner_wp, vec2 owner, vec2 d00, vec2 d01, bool has_quad, int spec_role,
    out uvec4 o0, out uvec4 o1, out uvec4 o2, out uvec4 o3
) {
    o0 = uvec4(0xFFFFFFFFu);
    o1 = uvec4(0xFFFFFFFFu);
    o2 = uvec4(0xFFFFFFFFu);
    o3 = uvec4(0xFFFFFFFFu);
    if (u_dynamic_shadows == 0 || spec_role == 0) return;
    o0 = uvec4(0u);
    o1 = uvec4(0u);
    o2 = uvec4(0u);
    o3 = uvec4(0u);
    float quad_radius = has_quad ? max(length(d00), length(d01)) : 1e20;
    bool need_c01 = (spec_role & 1) != 0;
    bool need_c10 = (spec_role & 2) != 0;
    int limit = min(u_count, MAX_SPEC_LIGHTS);
    for (int i = 0; i < limit; i++) {
        if (!needsContinuousSpecVis(i)) continue;
        vec2 axis = dot(u_dir[i].xy, u_dir[i].xy) > .0001 ? normalize(u_dir[i].xy) : vec2(0.);
        float half_length = u_dir[i].w * .5;
        vec2 near_owner = nearestOn(i, axis, false, -half_length, half_length, owner);
        uint spec_bits = 0xFFFFu;
        if (length(near_owner - owner) - quad_radius < u_response[i].z) {
            vec4 v = vec4(1.);
            if (!has_quad) {
                v = vec4(cornerSpecVisibility(i, corner_wp, owner));
            } else {
                for (int c = 0; c < 4; c++) {
                    if (c == 1 && !need_c01) continue;
                    if (c == 3 && !need_c10) continue;
                    vec2 p = owner + (c == 0 ? d00 : c == 1 ? d01 : c == 2 ? -d00 : -d01);
                    float vis = cornerSpecVisibility(i, p, owner);
                    if (c == 0) v.x = vis;
                    else if (c == 1) v.y = vis;
                    else if (c == 2) v.z = vis;
                    else v.w = vis;
                }
                if (!need_c01) v.y = v.x;
                if (!need_c10) v.w = v.x;
            }
            spec_bits = packQuad4(v);
        }
        uint shifted = spec_bits << ((i & 1) == 0 ? 0u : 16u);
        int word = i >> 1;
        if (word == 0) o0.x |= shifted;
        else if (word == 1) o0.y |= shifted;
        else if (word == 2) o0.z |= shifted;
        else if (word == 3) o0.w |= shifted;
        else if (word == 4) o1.x |= shifted;
        else if (word == 5) o1.y |= shifted;
        else if (word == 6) o1.z |= shifted;
        else if (word == 7) o1.w |= shifted;
        else if (word == 8) o2.x |= shifted;
        else if (word == 9) o2.y |= shifted;
        else if (word == 10) o2.z |= shifted;
        else if (word == 11) o2.w |= shifted;
        else if (word == 12) o3.x |= shifted;
        else if (word == 13) o3.y |= shifted;
        else if (word == 14) o3.z |= shifted;
        else o3.w |= shifted;
    }
}

void fillLightVisibilities(
    vec2 wp, vec2 owner,
    out vec4 v0, out vec4 v1, out vec4 v2, out vec4 v3,
    out vec4 v4, out vec4 v5, out vec4 v6, out vec4 v7
) {
    vec4 groups[8];
    for (int g = 0; g < 8; g++) groups[g] = vec4(1.);
    if (u_dynamic_shadows != 0) {
        int limit = min(u_count, MAX_SPEC_LIGHTS);
        for (int i = 0; i < limit; i++) {
            float vis = cornerVisibility(i, wp, owner);
            int g = i >> 2;
            int lane = i & 3;
            if (lane == 0) groups[g].x = vis;
            else if (lane == 1) groups[g].y = vis;
            else if (lane == 2) groups[g].z = vis;
            else groups[g].w = vis;
        }
    }
    v0 = groups[0]; v1 = groups[1]; v2 = groups[2]; v3 = groups[3];
    v4 = groups[4]; v5 = groups[5]; v6 = groups[6]; v7 = groups[7];
}
