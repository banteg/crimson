#version 330
// A target-filling quad over a source of the same orientation (the RTX tonemap, scaled copies), with the varyings
// the Python port's fragment shaders take (raylib's).
#include "common.glsl"
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
void main() {
    vec2 corner = corner_of(gl_VertexID);
    gl_Position = corner_position(corner);
    fragTexCoord = corner;
    fragColor = vec4(1.0);
}
