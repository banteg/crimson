#version 330
// The device's vertices for the Python port's RTX creature and player lighting (creature.frag, player.frag): their
// atlas coordinates and tint, and the world position each lights in (the screen less the camera offset).
#include "common.glsl"
layout(location = 0) in vec4 position; // x, y, z, rhw in pixels
layout(location = 1) in vec4 diffuse;  // D3DCOLOR bytes: b, g, r, a
layout(location = 2) in vec2 uv;
uniform vec2 target_size;
uniform vec2 camera;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
LOC(2) out vec2 world;
void main() {
    gl_Position = target_position(position.xy, target_size);
    fragTexCoord = uv;
    fragColor = diffuse.zyxw;
    world = position.xy - camera;
}
