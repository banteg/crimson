#version 330
#include "common.glsl"
layout(location = 0) in vec4 position;
layout(location = 1) in vec4 diffuse;
layout(location = 2) in vec2 uv;
uniform vec2 target_size;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
void main() {
    gl_Position = target_position(position.xy, target_size);
    fragTexCoord = uv;
    fragColor = diffuse.zyxw;
}
