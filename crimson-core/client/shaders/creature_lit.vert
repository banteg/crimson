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
LOC(12) out vec4 specVisibility1;
LOC(13) out vec4 specVisibility2;
LOC(14) flat out vec4 quadCenterD00;
LOC(15) flat out vec2 quadD01;
void main() {
    gl_Position = target_position(position.xy, target_size);
    fragTexCoord = uv;
    fragColor = diffuse.zyxw;
    world = position.xy - camera;
    vec2 owner = center.xy - camera;
    vec2 d00 = center.zw;
    vec2 d01 = corner1;
    quadCenterD00 = vec4(owner, d00);
    quadD01 = d01;
    int vid = gl_VertexID & 3;
    vec2 corner_wp = (dot(d00, d00) > 1e-12 && dot(d01, d01) > 1e-12)
        ? owner + (vid == 0 ? d00 : vid == 1 ? -d01 : vid == 2 ? -d00 : d01)
        : world;
    lightVisibility0 = cornerVisibilities(0, corner_wp, owner);
    lightVisibility1 = cornerVisibilities(1, corner_wp, owner);
    lightVisibility2 = cornerVisibilities(2, corner_wp, owner);
    lightVisibility3 = cornerVisibilities(3, corner_wp, owner);
    lightVisibility4 = cornerVisibilities(4, corner_wp, owner);
    lightVisibility5 = cornerVisibilities(5, corner_wp, owner);
    lightVisibility6 = cornerVisibilities(6, corner_wp, owner);
    lightVisibility7 = cornerVisibilities(7, corner_wp, owner);
    fillSpecVisibilities(corner_wp, owner, quadRadius(d00, d01), specVisibility0, specVisibility1, specVisibility2);
}
