// A bounded, color-independent visibility field. Every four selected sources
// share one RGBA group; the same coarse mask shades diffuse and reflection.
// This is intentionally one nearest-source ray, not an exact reflected ray.
uniform vec4 u_visibility_world; // snapped world origin and extent
uniform vec2 u_visibility_size;  // one group's texels
const int VISIBILITY_ROWS = MAX_SPEC_LIGHTS / 16;
#ifndef BEAM_VISIBILITY_PASS
uniform sampler2D u_visibility_tex;
vec4 groundVisibility(int group, vec2 world) {
    if (u_visibility_world.z <= 0. || u_visibility_world.w <= 0.) return vec4(1.);
    vec2 uv = (world - u_visibility_world.xy) / u_visibility_world.zw;
    if (any(lessThan(uv, vec2(0.))) || any(greaterThan(uv, vec2(1.)))) return vec4(1.);
    // A group's half-texel border prevents its neighbours bleeding into it.
    vec2 inset = .5 / u_visibility_size;
    uv = clamp(uv, inset, 1. - inset);
    if (V_UP > 0.) uv.y = 1. - uv.y;
    vec2 corner = vec2(float(group % 4), float(group / 4));
    return textureLod(u_visibility_tex, (corner + uv) / vec2(4., float(VISIBILITY_ROWS)), 0.);
}
#endif
