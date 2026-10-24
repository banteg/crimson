#version 330
#include "common.glsl"
layout(location = 0) in vec4 corner;
uniform vec2 target_size;
uniform vec4 effect_color;
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
void main() {
    gl_Position = target_position(corner.xy, target_size);
    fragTexCoord = corner.zw;
    fragColor = effect_color;
}
