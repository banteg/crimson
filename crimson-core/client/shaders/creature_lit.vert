#version 330
// The device's vertices for the RTX creature lighting (creature.frag), as creature.vert gives them, with each light's
// visibility at the quad's corners (creature_visibility.glsl). `center` is the quad's center, which the host adds:
// the creature whose body its corners spare.
#include "common.glsl"
#include "creature_visibility.glsl"
layout(location = 0) in vec4 position; // x, y, z, rhw in pixels
layout(location = 1) in vec4 diffuse;  // D3DCOLOR bytes: b, g, r, a
layout(location = 2) in vec2 uv;
layout(location = 3) in vec2 center;   // in pixels
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
void main() {
    gl_Position = target_position(position.xy, target_size);
    fragTexCoord = uv;
    fragColor = diffuse.zyxw;
    world = position.xy - camera;
    vec2 owner = center - camera;
    lightVisibility0 = cornerVisibilities(0, world, owner);
    lightVisibility1 = cornerVisibilities(1, world, owner);
    lightVisibility2 = cornerVisibilities(2, world, owner);
    lightVisibility3 = cornerVisibilities(3, world, owner);
    lightVisibility4 = cornerVisibilities(4, world, owner);
    lightVisibility5 = cornerVisibilities(5, world, owner);
    lightVisibility6 = cornerVisibilities(6, world, owner);
    lightVisibility7 = cornerVisibilities(7, world, owner);
}
