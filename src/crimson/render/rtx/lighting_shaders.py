"""Shared finite-source visibility for ground and creature lighting."""

SOURCE_GEOMETRY_GLSL = r"""
// Nearest point approximation to a continuous annulus, not angular integration.
vec2 nearestRingPoint(vec2 center, vec2 receiver, float radius) {
    vec2 delta = receiver - center;
    float distance = length(delta);
    return center + (distance > 1e-6 ? delta / distance : vec2(1., 0.)) * radius;
}
// Energy centroid of (.015 + f^8), f in [0,1], measured from tail to head.
// Fixed source placement avoids receiver-dependent shadow sliding. Source width
// supplies analytic softness; this is not full finite-beam integration.
vec2 illuminationSource(vec2 center, vec2 direction, float length) {
    return center + direction * length * .35242291;
}

"""

LIGHT_VISIBILITY_GLSL = SOURCE_GEOMETRY_GLSL + r"""
uniform int u_dynamic_shadows;
// Packed float texture: cell headers, body transforms, then lossless cell lists.
uniform sampler2D u_occlusion_tex;
uniform vec4 u_occlusion_grid; // xy world origin, zw cell counts; z=0 disables
uniform float u_occlusion_cell_size;

vec4 occlusionData(int address) {
    int width = textureSize(u_occlusion_tex, 0).x;
    return texelFetch(u_occlusion_tex, ivec2(address % width, address / width), 0);
}

#ifdef CONTINUOUS_BEAM
vec2 beam_section_axis = vec2(0.);
float beam_section_halfspan = 0.;
float sectionCoverage(vec3 miss, vec3 line, float softness);
#endif

float bodyVisibility(int address, vec3 origin, vec3 ray, float source_width, float inverse_xy_length, vec2 owner) {
    vec4 center = occlusionData(address);
    vec2 offset = origin.xy - center.xy;
    float along = clamp(-dot(offset, ray.xy) * inverse_xy_length, 0., 1.);
    vec2 nearest = offset + ray.xy * along;
    // Reject neighboring cell members with one fetch before loading transforms.
    // The bound already includes the largest selected source's soft margin.
    if (dot(nearest, nearest) > center.w * center.w) return 1.;
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
    float t = clamp(-dot(q, ray) / max(dot(ray, ray), 1e-8), 0., 1.);
    float distance = length(q + ray * t);
    // Analytic finite-source penumbra. The cone grows from the receiver toward
    // the source; this is a smooth body proxy, not sampled silhouette tracing.
    float softness = max(.015, source_width * t * max(inverse_radius.x, inverse_radius.y));
    #ifdef CONTINUOUS_BEAM
    if (beam_section_halfspan > 0.) {
        vec3 source_axis = vec3(local * beam_section_axis, 0.) * inverse_radius;
        vec3 projected = source_axis - ray * (dot(source_axis, ray) / max(dot(ray, ray), 1e-8));
        vec3 line = projected * (beam_section_halfspan * t);
        return 1. - orientation.z * sectionCoverage(q + ray * t, line, softness);
    }
    #endif
    return 1. - orientation.z * (1. - smoothstep(1. - softness, 1. + softness, distance));
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
    // Each step crosses one grid boundary. No nearest-body budget drops blockers.
    while (cell.x >= 0 && cell.y >= 0 && cell.x < int(u_occlusion_grid.z) && cell.y < int(u_occlusion_grid.w)) {
        vec4 header = occlusionData(cell.y * int(u_occlusion_grid.z) + cell.x);
        for (int j = 0; j < int(header.y); j++) {
            int address = int(occlusionData(int(header.x) + j).x);
            visibility = min(visibility, bodyVisibility(address, receiver, ray, source_width, inverse_xy_length, owner));
            if (visibility < .001) return visibility;
        }
        if (min(t_edge.x, t_edge.y) >= 1.) break;
        if (t_edge.x < t_edge.y) { cell.x += step_cell.x; t_edge.x += t_step.x; }
        else { cell.y += step_cell.y; t_edge.y += t_step.y; }
    }
    return visibility;
}

float illuminationVisibility(vec3 receiver, vec3 source, float width, vec2 owner) {
    return u_dynamic_shadows != 0 ? sourceVisibility(receiver, source, width, owner) : 1.;
}
"""
