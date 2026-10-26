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

// Squared planar distance from the body center (the origin) to the ray.
float rayDistance2(vec2 receiver, vec2 to_source, float inverse_xy_length) {
    vec2 nearest = receiver + to_source * clamp(-dot(receiver, to_source) * inverse_xy_length, 0., 1.);
    return dot(nearest, nearest);
}

float bodyVisibility(int address, vec3 origin, vec3 ray, float source_width, float inverse_xy_length, vec2 owner) {
    vec4 center = occlusionData(address);
    vec2 offset = origin.xy - center.xy;
    float distance2 = rayDistance2(offset, ray.xy, inverse_xy_length);
    // Reject neighboring cell members with one fetch before loading transforms.
    // The bound includes the penumbra margin for sources up to PENUMBRA_WIDTH.
    float bound = center.w;
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
    ivec2 first_cell = cell;
    float t_enter = 0.;
    float cells_crossed = length(delta);
    // Each step crosses one grid boundary. No nearest-body budget drops blockers.
    while (cell.x >= 0 && cell.y >= 0 && cell.x < int(u_occlusion_grid.z) && cell.y < int(u_occlusion_grid.w)) {
        vec4 header = occlusionData(cell.y * int(u_occlusion_grid.z) + cell.x);
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
                if (visibility < .001) return visibility;
            }
            header.y = 0.;
        }
        for (int j = 0; j < int(header.y); j++) {
            vec4 entry = occlusionData(int(header.x) + j);
            visibility = min(visibility, bodyVisibility(int(entry.x), receiver, ray, source_width, inverse_xy_length, owner));
            if (visibility < .001) return visibility;
        }
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
