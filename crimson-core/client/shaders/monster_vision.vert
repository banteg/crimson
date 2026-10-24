#version 330
// Monster Vision's source quads (render/rtx/perk_lighting.py's MONSTER_VISION_VERTEX): device vertices whose texture
// coordinates carry their aura's world center and whose alpha its fade; the ground's coordinates come from the world.
#include "common.glsl"
layout(location = 0) in vec4 position; // x, y, z, rhw in pixels
layout(location = 1) in vec4 diffuse;  // D3DCOLOR bytes: b, g, r, a
layout(location = 2) in vec2 uv;
uniform vec2 target_size;
uniform vec2 camera;
uniform vec2 u_ground_size;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
LOC(2) out vec3 perk_source;
void main() {
    gl_Position = target_position(position.xy, target_size);
    fragTexCoord = (position.xy - camera) / u_ground_size;
    fragColor = diffuse.zyxw;
    perk_source = vec3(uv, fragColor.a);
}
