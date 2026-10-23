#version 330
// A copy between targets of other sizes or formats (WebGPU copies only like for like).
#include "common.glsl"
LOC(0) in vec2 fragTexCoord;
LOC(1) in vec4 fragColor;
out vec4 color;
uniform sampler2D source;
void main() { color = texture(source, fragTexCoord); }
