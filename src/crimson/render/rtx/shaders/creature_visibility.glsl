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

float cornerVisibility(int i, vec2 wp, vec2 owner) {
    if (i >= u_count) return 1.;
    vec2 axis = dot(u_dir[i].xy, u_dir[i].xy) > .0001 ? normalize(u_dir[i].xy) : vec2(0.);
    bool ring = u_rgb[i].w > 0.;
    float along = clamp(dot(wp - u_pos[i].xy, axis), -u_dir[i].w * .5, u_dir[i].w * .5);
    vec2 nearest = ring ? nearestRingPoint(u_pos[i].xy, wp, u_rgb[i].w) : u_pos[i].xy + axis * along;
    // Past both of the light's reaches: creature.frag never shades this corner from it.
    if (length(nearest - wp) >= max(u_pos[i].z, u_response[i].z)) return 1.;
    vec2 source = ring ? nearest : illuminationSource(u_pos[i].xy, axis, u_dir[i].w, u_dir[i].z);
    return illuminationVisibility(vec3(wp, 8.), vec3(source, u_pos[i].w), max(.1, u_response[i].w), owner);
}

vec4 cornerVisibilities(int group, vec2 wp, vec2 owner) {
    int first = group * 4;
    return vec4(cornerVisibility(first, wp, owner), cornerVisibility(first + 1, wp, owner),
                cornerVisibility(first + 2, wp, owner), cornerVisibility(first + 3, wp, owner));
}
