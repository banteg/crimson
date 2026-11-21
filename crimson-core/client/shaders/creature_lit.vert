#version 330
// The device's vertices for the RTX creature lighting (creature.frag), as creature.vert gives them, with each light's
// visibility at the quad's corners (creature_visibility.glsl). `center` is the quad's center, which the host adds:
// the creature whose body its corners spare.
#include "common.glsl"
#include "creature_visibility.glsl"
layout(location = 0) in vec4 position; // x, y, z, rhw in pixels
layout(location = 1) in vec4 diffuse;  // D3DCOLOR bytes: b, g, r, a
layout(location = 2) in vec2 uv;
layout(location = 3) in vec4 center;   // xy quad center, zw v0 - center in pixels
layout(location = 4) in vec2 corner1;  // v3 - center in pixels
uniform vec2 target_size;
uniform vec2 camera;
uniform int u_spec_topology;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
LOC(2) out vec2 world;
LOC(3) out vec4 lightVisibility0;
LOC(4) out vec4 lightVisibility1;
LOC(5) out vec4 lightVisibility2;
LOC(6) out vec4 lightVisibility3;
LOC(7) out vec4 lightVisibility4;
LOC(8) out vec4 lightVisibility5;
LOC(9) out vec4 lightVisibility6;
LOC(10) out vec4 lightVisibility7;
LOC(11) out vec2 quadCoord;
LOC(12) flat out uvec4 specVis0;
LOC(13) flat out uvec4 specVis1;
LOC(14) flat out uvec4 specVis2;
LOC(15) flat out uvec4 specVis3;
void main() {
    gl_Position = target_position(position.xy, target_size);
    fragTexCoord = uv;
    fragColor = diffuse.zyxw;
    world = position.xy - camera;
    vec2 owner = center.xy - camera;
    vec2 d00 = center.zw;
    vec2 d01 = corner1;
    vec2 corner_wp = world;
    vec2 quad_coord = vec2(0., 0.);
    int corner_id = 0;
    bool has_quad = dot(d00, d00) > 1e-12 && dot(d01, d01) > 1e-12;
    if (has_quad) {
        vec2 c00 = owner + d00, c01 = owner + d01, c11 = owner - d00, c10 = owner - d01;
        corner_wp = c00;
        quad_coord = vec2(0., 0.);
        corner_id = 0;
        float best = dot(world - c00, world - c00);
        float dist = dot(world - c01, world - c01);
        if (dist < best) { best = dist; corner_wp = c01; quad_coord = vec2(0., 1.); corner_id = 1; }
        dist = dot(world - c11, world - c11);
        if (dist < best) { best = dist; corner_wp = c11; quad_coord = vec2(1., 1.); corner_id = 2; }
        dist = dot(world - c10, world - c10);
        if (dist < best) { corner_wp = c10; quad_coord = vec2(1., 0.); corner_id = 3; }
    }
    quadCoord = quad_coord;
    fillLightVisibilities(
        world, owner,
        lightVisibility0, lightVisibility1, lightVisibility2, lightVisibility3,
        lightVisibility4, lightVisibility5, lightVisibility6, lightVisibility7
    );
    int spec_role = 3;
    if (has_quad) {
#ifdef VULKAN
        if (u_spec_topology == 0)
            spec_role = corner_id == 0 ? 1 : corner_id == 2 ? 2 : 0;
        else if (u_spec_topology == 1)
            spec_role = corner_id == 1 ? 1 : corner_id == 0 ? 2 : 0;
        else if (u_spec_topology == 2)
            spec_role = corner_id == 0 ? 3 : 0;
#else
        if (u_spec_topology == 0)
            spec_role = corner_id == 2 ? 1 : corner_id == 0 ? 2 : 0;
        else if (u_spec_topology == 1 || u_spec_topology == 2)
            spec_role = corner_id == 2 ? 1 : corner_id == 3 ? 2 : 0;
#endif
    }
    fillSpecVisibilities(corner_wp, owner, d00, d01, has_quad, spec_role, specVis0, specVis1, specVis2, specVis3);
}
