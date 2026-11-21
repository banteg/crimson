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
LOC(11) out vec4 specVisibility0;
LOC(12) out vec4 specVis45Quad;
LOC(13) flat out uvec4 specOverflow0;
LOC(14) flat out uvec4 specOverflow1;
LOC(15) flat out uvec4 specOverflow2;
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
    bool has_quad = dot(d00, d00) > 1e-12 && dot(d01, d01) > 1e-12;
    if (has_quad) {
        vec2 c00 = owner + d00, c01 = owner + d01, c11 = owner - d00, c10 = owner - d01;
        corner_wp = c00;
        quad_coord = vec2(0., 0.);
        float best = dot(world - c00, world - c00);
        float dist = dot(world - c01, world - c01);
        if (dist < best) { best = dist; corner_wp = c01; quad_coord = vec2(0., 1.); }
        dist = dot(world - c11, world - c11);
        if (dist < best) { best = dist; corner_wp = c11; quad_coord = vec2(1., 1.); }
        dist = dot(world - c10, world - c10);
        if (dist < best) { corner_wp = c10; quad_coord = vec2(1., 0.); }
    }
    fillLightVisibilities(
        world, corner_wp, owner,
        lightVisibility0, lightVisibility1, lightVisibility2, lightVisibility3,
        lightVisibility4, lightVisibility5, lightVisibility6, lightVisibility7
    );
    vec2 spec45;
    fillSpecVisibilities(
        corner_wp, owner, d00, d01, has_quad,
        specVisibility0, spec45, specOverflow0, specOverflow1, specOverflow2
    );
    specVis45Quad = vec4(spec45, quad_coord);
}
