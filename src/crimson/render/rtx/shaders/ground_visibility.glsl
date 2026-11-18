// A bounded, color-independent visibility field. Every four selected sources
// share one RGBA group; the same coarse mask shades diffuse and reflection.
// Beam masks preserve analytic directional penumbrae; other sources use a
// nearest-source ray. Reflection reuses the mask rather than tracing its own ray.
uniform vec4 u_visibility_world; // snapped world origin and extent
uniform vec2 u_visibility_size;  // one group's texels
const int VISIBILITY_ROWS = MAX_SPEC_LIGHTS / 16;
#ifndef BEAM_VISIBILITY_PASS
uniform sampler2D u_visibility_tex;
uniform vec4 u_coarse_visibility_world;
uniform vec2 u_coarse_visibility_size;
uniform int u_coarse_visibility_mask;

vec4 visibilityAt(int group, vec2 world, vec4 rect, vec2 size, float first_row) {
    if (rect.z <= 0. || rect.w <= 0.) return vec4(1.);
    vec2 uv = (world - rect.xy) / rect.zw;
    if (any(lessThan(uv, vec2(0.))) || any(greaterThan(uv, vec2(1.)))) return vec4(1.);
    // A group's half-texel border prevents its neighbours bleeding into it.
    vec2 inset = .5 / size;
    uv = clamp(uv, inset, 1. - inset);
    if (V_UP > 0.) uv.y = 1. - uv.y;
    vec2 corner = vec2(float(group % 4), float(group / 4));
    if (u_coarse_visibility_size.y <= 0.)
        return textureLod(u_visibility_tex, (corner + uv) / vec2(4., float(VISIBILITY_ROWS)), 0.);
    vec2 atlas_size = vec2(4. * u_visibility_size.x,
                           float(VISIBILITY_ROWS) * (u_visibility_size.y + u_coarse_visibility_size.y));
    return textureLod(u_visibility_tex, ((corner + uv) * size + vec2(0., first_row)) / atlas_size, 0.);
}

vec4 groundVisibility(int group, vec2 world) {
    uint lanes = (uint(u_coarse_visibility_mask) >> uint(group * 4)) & 15u;
    if (lanes == 0u)
        return visibilityAt(group, world, u_visibility_world, u_visibility_size, 0.);
    vec4 coarse = visibilityAt(group, world, u_coarse_visibility_world, u_coarse_visibility_size,
                               u_visibility_size.y * float(VISIBILITY_ROWS));
    uint active_lanes = (1u << uint(min(4, u_spec_light_count - group * 4))) - 1u;
    if (lanes == active_lanes) return coarse;
    vec4 fine = visibilityAt(group, world, u_visibility_world, u_visibility_size, 0.);
    return vec4((lanes & 1u) != 0u ? coarse.x : fine.x,
                (lanes & 2u) != 0u ? coarse.y : fine.y,
                (lanes & 4u) != 0u ? coarse.z : fine.z,
                (lanes & 8u) != 0u ? coarse.w : fine.w);
}
#endif
