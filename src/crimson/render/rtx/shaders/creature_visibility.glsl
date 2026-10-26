// A creature's light visibility at its quad's corners, which creature.frag interpolates across the body instead of
// walking the body grid per pixel: from the corner, at the height creature.frag lights from, toward the point each
// light shades the body from, the creature's own body spared (`owner`, its quad's center). The vertex stages (the
// client's creature_lit.vert, the Python port's CREATURE_VERTEX) pass it on as eight vec4s, four lights each.
#include "light_visibility.glsl"
uniform int u_count;
uniform vec4 u_pos[32];
uniform vec4 u_rgb[32];
uniform vec4 u_dir[32];
uniform vec4 u_response[32]; // illumination, reflection, reflection reach, source width

// The point of light `i` (its disc's center, its segment or its ring) nearest `p`.
vec2 nearestOn(int i, vec2 axis, bool ring, vec2 p) {
    float along = clamp(dot(p - u_pos[i].xy, axis), -u_dir[i].w * .5, u_dir[i].w * .5);
    return ring ? nearestRingPoint(u_pos[i].xy, p, u_rgb[i].w) : u_pos[i].xy + axis * along;
}

float cornerVisibility(int i, vec2 wp, vec2 owner) {
    if (i >= u_count || u_dynamic_shadows == 0) return 1.;
    vec2 axis = dot(u_dir[i].xy, u_dir[i].xy) > .0001 ? normalize(u_dir[i].xy) : vec2(0.);
    bool ring = u_rgb[i].w > 0.;
    // Past both of the light's reaches across the whole quad, every corner as far from its center as this one:
    // creature.frag shades none of it from the light. A corner past them alone still traces, since the pixels
    // inside its reach interpolate it.
    float reach = max(u_pos[i].z, u_response[i].z);
    if (length(nearestOn(i, axis, ring, owner) - owner) - length(wp - owner) >= reach) return 1.;
    vec2 nearest = nearestOn(i, axis, ring, wp);
    vec2 source = ring ? nearest : illuminationSource(u_pos[i].xy, axis, u_dir[i].w, u_dir[i].z);
    return illuminationVisibility(vec3(wp, 8.), vec3(source, u_pos[i].w), max(.1, u_response[i].w), owner);
}

vec4 cornerVisibilities(int group, vec2 wp, vec2 owner) {
    int first = group * 4;
    return vec4(cornerVisibility(first, wp, owner), cornerVisibility(first + 1, wp, owner),
                cornerVisibility(first + 2, wp, owner), cornerVisibility(first + 3, wp, owner));
}
