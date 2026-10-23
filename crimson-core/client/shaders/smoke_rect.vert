#version 330
// A rectangle of a fluid smoke solver target (src/crimson/render/rtx/shaders/smoke_*.frag), in the solver's uv: the
// Python port draws its passes in raylib's top-down target coordinates, so uv.y = 1 is the target's row 0, which the
// solver's gl_FragCoord reads as its first row in either API.
#include "common.glsl"
uniform vec4 rect; // uv origin and size
LOC(0) out vec2 fragTexCoord;
LOC(1) out vec4 fragColor;
void main() {
    vec2 corner = corner_of(gl_VertexID);
    vec2 uv = rect.xy + corner * rect.zw;
    gl_Position = corner_position(vec2(uv.x, 1.0 - uv.y));
    fragTexCoord = uv;
    fragColor = vec4(1.0);
}
